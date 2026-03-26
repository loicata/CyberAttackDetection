#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Downloads and installs Npcap + Suricata + ET rules, configures eve.json,
    creates a Windows service, and enables Suricata in Cyber Attack Detection.

.NOTES
    Must be run as Administrator.
    Run: Right-click PowerShell -> Run as Administrator
    Then: .\scripts\install_suricata.ps1
#>

$ErrorActionPreference = "Stop"

# ---- Configuration ----
$NpcapUrl      = "https://npcap.com/dist/npcap-1.80.exe"
$SuricataUrl   = "https://www.openinfosecfoundation.org/download/windows/Suricata-8.0.4-1-64bit.msi"
$SuricataDir   = "C:\Program Files\Suricata"
$SuricataExe   = "$SuricataDir\suricata.exe"
$SuricataYaml  = "$SuricataDir\suricata.yaml"
$SuricataLog   = "$SuricataDir\log"
$EveJsonPath   = "$SuricataLog\eve.json"
$TempDir       = "$env:TEMP\CAD_Install"
$ProjectRoot   = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$LocalToml     = Join-Path $ProjectRoot "config\local.toml"

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Suricata + Npcap Installer for Cyber Attack Detection" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

# Create temp dir
if (-not (Test-Path $TempDir)) {
    New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ============================================================
# STEP 1: Install Npcap
# ============================================================

$npcapInstalled = Test-Path "C:\Program Files\Npcap\NPFInstall.exe"
if ($npcapInstalled) {
    Write-Host "[OK] Npcap is already installed." -ForegroundColor Green
}
else {
    Write-Host "[1/6] Downloading Npcap..." -ForegroundColor White
    $npcapExe = "$TempDir\npcap-installer.exe"
    try {
        Invoke-WebRequest -Uri $NpcapUrl -OutFile $npcapExe -UseBasicParsing
        Write-Host "      Downloaded: $npcapExe" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Failed to download Npcap. Please download manually from https://npcap.com" -ForegroundColor Red
        Write-Host "        Install with: WinPcap API-compatible mode ENABLED" -ForegroundColor Yellow
        Read-Host "Press Enter after installing Npcap manually..."
        $npcapExe = $null
    }

    if ($npcapExe -and (Test-Path $npcapExe)) {
        Write-Host "[1/6] Installing Npcap (silent)..." -ForegroundColor White
        # /winpcap_mode=yes enables WinPcap API compatibility
        $proc = Start-Process -FilePath $npcapExe -ArgumentList "/S","/winpcap_mode=yes" -Wait -PassThru
        if ($proc.ExitCode -eq 0) {
            Write-Host "      Npcap installed successfully." -ForegroundColor Green
        }
        else {
            Write-Host "[WARNING] Npcap installer exited with code $($proc.ExitCode)." -ForegroundColor Yellow
            Write-Host "          If Npcap was already installed, this is normal." -ForegroundColor Yellow
        }
    }
}

# ============================================================
# STEP 1b: Add Npcap to system PATH (required for Suricata)
# ============================================================

$npcapSysPath = "C:\Windows\System32\Npcap"
$currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($currentPath -notlike "*$npcapSysPath*") {
    Write-Host "      Adding Npcap to system PATH..." -ForegroundColor White
    [Environment]::SetEnvironmentVariable("PATH", "$npcapSysPath;$currentPath", "Machine")
    Write-Host "      [OK] Npcap added to system PATH" -ForegroundColor Green
}
# Also set for current session
$env:PATH = "$npcapSysPath;C:\Program Files\Suricata;$env:PATH"

# ============================================================
# STEP 2: Install Suricata
# ============================================================

$suricataInstalled = Test-Path $SuricataExe
if ($suricataInstalled) {
    Write-Host "[OK] Suricata is already installed at $SuricataDir" -ForegroundColor Green
}
else {
    Write-Host "[2/6] Downloading Suricata MSI..." -ForegroundColor White
    $suricataMsi = "$TempDir\suricata.msi"
    try {
        Invoke-WebRequest -Uri $SuricataUrl -OutFile $suricataMsi -UseBasicParsing
        Write-Host "      Downloaded: $suricataMsi" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Failed to download Suricata MSI." -ForegroundColor Red
        Write-Host "        Please download manually from https://suricata.io/download/" -ForegroundColor Yellow
        Write-Host "        Install to: $SuricataDir" -ForegroundColor Yellow
        Read-Host "Press Enter after installing Suricata manually..."
    }

    if (Test-Path $suricataMsi) {
        Write-Host "[2/6] Installing Suricata (this may take a minute)..." -ForegroundColor White
        $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i","$suricataMsi","/quiet","/norestart" -Wait -PassThru
        if ($proc.ExitCode -eq 0) {
            Write-Host "      Suricata installed successfully." -ForegroundColor Green
        }
        else {
            Write-Host "[WARNING] Suricata MSI exited with code $($proc.ExitCode)." -ForegroundColor Yellow
        }
    }
}

# Verify Suricata is present
if (-not (Test-Path $SuricataExe)) {
    Write-Host "[ERROR] Suricata not found at $SuricataExe" -ForegroundColor Red
    Write-Host "        Please install manually and re-run this script." -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "      Suricata version:" -ForegroundColor White
& $SuricataExe --build-info 2>&1 | Select-String "Suricata version" | ForEach-Object { Write-Host "      $_" -ForegroundColor Cyan }

# ============================================================
# STEP 3: Detect network interface
# ============================================================

Write-Host ""
Write-Host "[3/6] Detecting network interface..." -ForegroundColor White

# Get the active network adapter with an IP
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.InterfaceDescription -notmatch "Loopback|Virtual|Hyper-V|vEthernet|WireGuard|ProtonVPN|NordVPN|Windscribe|Mullvad|OpenVPN|TAP-Windows" } | Select-Object -First 1
if (-not $adapter) {
    Write-Host "[ERROR] No active network adapter found." -ForegroundColor Red
    exit 1
}

$adapterName = $adapter.Name
$adapterDesc = $adapter.InterfaceDescription
$ipAddress = (Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress | Select-Object -First 1

Write-Host "      Adapter: $adapterName ($adapterDesc)" -ForegroundColor Green
Write-Host "      IP:      $ipAddress" -ForegroundColor Green

# Get Npcap device name for this adapter
$npcapDevice = $null
$pcapList = & $SuricataExe --pcap=list 2>&1
foreach ($line in $pcapList) {
    if ($line -match "\\\\Device\\\\NPF_\{[0-9a-fA-F-]+\}") {
        $currentDevice = $Matches[0]
    }
    if ($line -match [regex]::Escape($adapterDesc)) {
        $npcapDevice = $currentDevice
    }
    # Also try matching by adapter name
    if ($line -match [regex]::Escape($adapterName)) {
        if (-not $npcapDevice) {
            $npcapDevice = $currentDevice
        }
    }
}

if (-not $npcapDevice) {
    # Fallback: use first device from list
    $firstMatch = $pcapList | Select-String "\\\\Device\\\\NPF_\{" | Select-Object -First 1
    if ($firstMatch) {
        $npcapDevice = ($firstMatch -match "\\\\Device\\\\NPF_\{[0-9a-fA-F-]+\}") | Out-Null
        $npcapDevice = $Matches[0]
    }
}

if (-not $npcapDevice) {
    Write-Host "[ERROR] Could not detect Npcap device. Listing available:" -ForegroundColor Red
    $pcapList | ForEach-Object { Write-Host "  $_" }
    $npcapDevice = Read-Host "Paste the \Device\NPF_{...} device name"
}

Write-Host "      Npcap Device: $npcapDevice" -ForegroundColor Green

# ============================================================
# STEP 4: Configure suricata.yaml
# ============================================================

Write-Host ""
Write-Host "[4/6] Configuring Suricata..." -ForegroundColor White

# Determine HOME_NET from IP
$networkParts = $ipAddress.Split(".")
$homeNet = "$($networkParts[0]).$($networkParts[1]).$($networkParts[2]).0/24"

# Read existing yaml
$yamlContent = Get-Content $SuricataYaml -Raw -ErrorAction SilentlyContinue

if ($yamlContent) {
    # Update HOME_NET
    $yamlContent = $yamlContent -replace 'HOME_NET:\s*"\[.*?\]"', "HOME_NET: ""[$homeNet]"""

    # Ensure eve-log is enabled
    # The default config usually has eve-log enabled, but let's make sure
    if ($yamlContent -notmatch "eve-log") {
        Write-Host "      [WARNING] eve-log section not found in yaml. Using default config." -ForegroundColor Yellow
    }

    # Write updated config
    Set-Content -Path $SuricataYaml -Value $yamlContent -Encoding UTF8
    Write-Host "      HOME_NET set to: [$homeNet]" -ForegroundColor Green
    Write-Host "      Config: $SuricataYaml" -ForegroundColor Green
}
else {
    Write-Host "      [WARNING] Could not read suricata.yaml. Skipping config update." -ForegroundColor Yellow
}

# Create log directory
if (-not (Test-Path $SuricataLog)) {
    New-Item -ItemType Directory -Path $SuricataLog -Force | Out-Null
}
Write-Host "      Log dir: $SuricataLog" -ForegroundColor Green

# ============================================================
# STEP 5: Download rules
# ============================================================

Write-Host ""
Write-Host "[5/6] Downloading Emerging Threats rules..." -ForegroundColor White

# Try suricata-update first, fallback to direct ET rules download
$suricataUpdate = "$SuricataDir\suricata-update.exe"
if (Test-Path $suricataUpdate) {
    $proc = Start-Process -FilePath $suricataUpdate -ArgumentList "--suricata","$SuricataExe","--suricata-conf","$SuricataYaml" -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -eq 0) {
        Write-Host "      Rules downloaded via suricata-update." -ForegroundColor Green
    }
    else {
        Write-Host "      [WARNING] suricata-update failed, trying direct download." -ForegroundColor Yellow
    }
}

# Fallback: download ET Open rules directly
$rulesDir = "$SuricataDir\rules"
if (-not (Test-Path "$rulesDir\suricata.rules") -or (Get-ChildItem "$rulesDir\*.rules" -ErrorAction SilentlyContinue).Count -eq 0) {
    Write-Host "      Downloading Emerging Threats Open rules..." -ForegroundColor White
    $etUrl = "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.zip"
    $etZip = "$TempDir\emerging.rules.zip"
    try {
        Invoke-WebRequest -Uri $etUrl -OutFile $etZip -UseBasicParsing
        if (-not (Test-Path $rulesDir)) { New-Item -ItemType Directory -Path $rulesDir -Force | Out-Null }
        Expand-Archive -Path $etZip -DestinationPath "$TempDir\rules_extract" -Force
        # Move rule files to Suricata rules directory
        $extractedRules = Get-ChildItem "$TempDir\rules_extract" -Recurse -Filter "*.rules"
        foreach ($ruleFile in $extractedRules) {
            Copy-Item $ruleFile.FullName -Destination $rulesDir -Force
        }
        $ruleCount = (Get-ChildItem "$rulesDir\*.rules").Count
        Write-Host "      [OK] Downloaded $ruleCount rule files." -ForegroundColor Green
    }
    catch {
        Write-Host "      [WARNING] Failed to download ET rules: $_" -ForegroundColor Yellow
    }
}
else {
    $ruleCount = (Get-ChildItem "$rulesDir\*.rules").Count
    Write-Host "      [OK] Rules already present: $ruleCount files." -ForegroundColor Green
}

# ============================================================
# STEP 6: Create Windows service
# ============================================================

Write-Host ""
Write-Host "[6/6] Creating Suricata Windows service..." -ForegroundColor White

$serviceName = "Suricata"
$existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

if ($existingService) {
    Write-Host "      Service already exists (Status: $($existingService.Status))" -ForegroundColor Green
    if ($existingService.Status -ne "Running") {
        Write-Host "      Starting service..." -ForegroundColor White
        Start-Service -Name $serviceName -ErrorAction SilentlyContinue
    }
}
else {
    # Create a batch wrapper that sets PATH before launching Suricata
    $batchWrapper = "$SuricataDir\run_suricata.bat"
    $batchContent = "@echo off`r`nset PATH=C:\Windows\System32\Npcap;%PATH%`r`n`"$SuricataExe`" -c `"$SuricataYaml`" -i `"$npcapDevice`" -l `"$SuricataLog`""
    Set-Content -Path $batchWrapper -Value $batchContent -Encoding ASCII
    Write-Host "      Created service wrapper: $batchWrapper" -ForegroundColor Green

    $binPath = "`"$batchWrapper`""

    # Use sc.exe to create the service
    $scResult = & sc.exe create $serviceName binPath= $binPath start= auto DisplayName= "Suricata IDS"
    Write-Host "      $scResult" -ForegroundColor White

    # Start it
    Start-Sleep -Seconds 1
    $startResult = & sc.exe start $serviceName 2>&1
    Write-Host "      $startResult" -ForegroundColor White
}

# ============================================================
# STEP 7: Configure Cyber Attack Detection
# ============================================================

Write-Host ""
Write-Host "Configuring Cyber Attack Detection for Suricata..." -ForegroundColor White

$suricataToml = @"

# Suricata configuration — generated by install_suricata.ps1
[detection.suricata]
enabled = true
eve_json_path = "$($EveJsonPath -replace '\\', '\\')"
syslog_listen_port = 0
syslog_listen_host = "127.0.0.1"
"@

$configDir = Split-Path -Parent $LocalToml
if (-not (Test-Path $configDir)) {
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
}

if (Test-Path $LocalToml) {
    $existing = Get-Content $LocalToml -Raw
    if ($existing -match "detection\.suricata") {
        Write-Host "[OK] Suricata already configured in local.toml" -ForegroundColor Green
    }
    else {
        Add-Content -Path $LocalToml -Value $suricataToml
        Write-Host "[OK] Suricata config appended to $LocalToml" -ForegroundColor Green
    }
}
else {
    Set-Content -Path $LocalToml -Value $suricataToml
    Write-Host "[OK] Created $LocalToml with Suricata config" -ForegroundColor Green
}

# ============================================================
# Summary
# ============================================================

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Installation complete!" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Npcap          : Installed" -ForegroundColor White
Write-Host "  Suricata        : $SuricataDir" -ForegroundColor White
Write-Host "  Config          : $SuricataYaml" -ForegroundColor White
Write-Host "  Eve.json        : $EveJsonPath" -ForegroundColor White
Write-Host "  HOME_NET        : [$homeNet]" -ForegroundColor White
Write-Host "  Interface       : $npcapDevice" -ForegroundColor White
Write-Host "  Service         : Suricata (auto-start)" -ForegroundColor White
Write-Host "  CAD config      : $LocalToml" -ForegroundColor White
Write-Host ""
Write-Host "  Restart Cyber Attack Detection to start ingesting Suricata alerts." -ForegroundColor White
Write-Host ""

# Quick test
Write-Host "Verifying Suricata is logging..." -ForegroundColor White
Start-Sleep -Seconds 3
if (Test-Path $EveJsonPath) {
    $lineCount = (Get-Content $EveJsonPath | Measure-Object -Line).Lines
    Write-Host "[OK] eve.json exists with $lineCount lines." -ForegroundColor Green
}
else {
    Write-Host "[INFO] eve.json not yet created. Suricata may need a few seconds to start." -ForegroundColor Yellow
    Write-Host "       Check: sc query Suricata" -ForegroundColor Yellow
}

# Cleanup
Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
