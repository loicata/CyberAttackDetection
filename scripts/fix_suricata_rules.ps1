#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enables compatible Emerging Threats rules in Suricata and restarts it.
    Excludes rule files known to be incompatible with Suricata 8.0.x Windows.
#>

$ErrorActionPreference = "Stop"
$SuricataYaml = "C:\Program Files\Suricata\suricata.yaml"
$RulesDir = "C:\Program Files\Suricata\rules"
$SuricataExe = "C:\Program Files\Suricata\suricata.exe"
$SuricataLog = "C:\Program Files\Suricata\log"

# Rule files to SKIP — incompatible with Suricata 8.0.x Windows build
# (missing protocol parsers or unsupported keywords)
$excludeRules = @(
    "dnp3-events.rules",          # dnp3 protocol not compiled in Windows build
    "modbus-events.rules",        # modbus protocol not compiled in Windows build
    "emerging-icmp_info.rules",   # file does not exist in ET Open
    "emerging-policy.rules"        # file does not exist in ET Open
)

Write-Host ""
Write-Host "Fixing Suricata rules configuration..." -ForegroundColor Cyan

# Get all existing .rules files, excluding incompatible ones
$allRules = Get-ChildItem "$RulesDir\*.rules" -Name | Sort-Object
$validRules = @()
$skippedRules = @()

foreach ($file in $allRules) {
    if ($excludeRules -contains $file) {
        $skippedRules += $file
    } else {
        $validRules += $file
    }
}

Write-Host "  Found $($allRules.Count) rule files" -ForegroundColor White
Write-Host "  Skipping $($skippedRules.Count) incompatible: $($skippedRules -join ', ')" -ForegroundColor Yellow
Write-Host "  Loading $($validRules.Count) compatible rule files" -ForegroundColor Green

# Build the rule-files YAML block
$rulesBlock = "rule-files:`r`n"
foreach ($file in $validRules) {
    $rulesBlock += " - $file`r`n"
}

# Read yaml
$yaml = Get-Content $SuricataYaml -Raw

# Replace existing rule-files block
$pattern = '(?m)^rule-files:\r?\n(^ - [^\r\n]+\r?\n)+'
$yaml = [regex]::Replace($yaml, $pattern, $rulesBlock)

# Write WITHOUT BOM — Suricata chokes on UTF-8 BOM
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($SuricataYaml, $yaml, $utf8NoBom)
Write-Host "  Updated $SuricataYaml" -ForegroundColor Green

# Kill existing Suricata
Write-Host ""
Write-Host "Restarting Suricata..." -ForegroundColor Cyan
$suricataProc = Get-Process -Name "suricata" -ErrorAction SilentlyContinue
if ($suricataProc) {
    Stop-Process -Name "suricata" -Force
    Start-Sleep -Seconds 3
    Write-Host "  Suricata stopped" -ForegroundColor Yellow
}

# Detect network interface
$adapter = Get-NetAdapter | Where-Object {
    $_.Status -eq "Up" -and
    $_.InterfaceDescription -notmatch "Loopback|Virtual|Hyper-V|vEthernet|WireGuard|ProtonVPN|NordVPN|OpenVPN|TAP-Windows"
} | Select-Object -First 1

if (-not $adapter) {
    Write-Host "[ERROR] No active network adapter found" -ForegroundColor Red
    exit 1
}

$dev = "\Device\NPF_$($adapter.InterfaceGuid)"
Write-Host "  Interface: $($adapter.Name) ($dev)" -ForegroundColor Green

# Clear old eve.json for clean test
$eveJson = "$SuricataLog\eve.json"
if (Test-Path $eveJson) {
    Remove-Item $eveJson -Force
    Write-Host "  Cleared old eve.json" -ForegroundColor Yellow
}

# Set PATH so Suricata can find Npcap DLLs
$env:PATH = "C:\Windows\System32\Npcap;$env:PATH"

# Start Suricata directly (not via Start-Process which may lose PATH)
Write-Host "  Starting Suricata (loading ~40000 rules, please wait)..." -ForegroundColor Yellow
$pinfo = New-Object System.Diagnostics.ProcessStartInfo
$pinfo.FileName = $SuricataExe
$pinfo.Arguments = "-c `"$SuricataYaml`" -i `"$dev`" -l `"$SuricataLog`""
$pinfo.UseShellExecute = $false
$pinfo.CreateNoWindow = $true
$pinfo.EnvironmentVariables["PATH"] = "C:\Windows\System32\Npcap;$($pinfo.EnvironmentVariables["PATH"])"

$process = [System.Diagnostics.Process]::Start($pinfo)
Write-Host "  PID: $($process.Id)" -ForegroundColor Gray

# Wait for eve.json to appear (means engine started successfully)
$waited = 0
$maxWait = 120
while ($waited -lt $maxWait) {
    Start-Sleep -Seconds 5
    $waited += 5

    # Check if process died
    if ($process.HasExited) {
        Write-Host "[ERROR] Suricata exited with code $($process.ExitCode)" -ForegroundColor Red
        Write-Host "  Check: $SuricataLog\suricata.log" -ForegroundColor Yellow
        # Show last error from log
        if (Test-Path "$SuricataLog\suricata.log") {
            Get-Content "$SuricataLog\suricata.log" -Tail 5 | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        }
        exit 1
    }

    # Check if eve.json exists
    if (Test-Path $eveJson) {
        Write-Host "  Suricata engine started after ${waited}s" -ForegroundColor Green
        break
    }

    Write-Host "  Loading rules... (${waited}s)" -ForegroundColor Gray
}

# Final verification
$proc = Get-Process -Name "suricata" -ErrorAction SilentlyContinue
if ($proc) {
    # Count alerts capability
    Start-Sleep -Seconds 2
    $logContent = Get-Content "$SuricataLog\suricata.log" -Tail 10 -ErrorAction SilentlyContinue
    $rulesLoaded = ($logContent | Select-String "rules successfully loaded" | Select-Object -Last 1)

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  [OK] Suricata is running!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    if ($rulesLoaded) {
        Write-Host "  $rulesLoaded" -ForegroundColor White
    }
    Write-Host "  PID:      $($proc.Id)" -ForegroundColor White
    Write-Host "  Eve.json: $eveJson" -ForegroundColor White
    Write-Host ""
    Write-Host "  Next steps:" -ForegroundColor White
    Write-Host "    1. Launch Cyber Attack Detection" -ForegroundColor Yellow
    Write-Host "    2. Run: python scripts\simulate_attack.py" -ForegroundColor Yellow
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "[ERROR] Suricata failed to start" -ForegroundColor Red
    Write-Host "  Check: $SuricataLog\suricata.log" -ForegroundColor Yellow
}
