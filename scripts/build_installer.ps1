#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Builds the Cyber Attack Detection installer:
    1. Builds the .exe with PyInstaller
    2. Compiles the Inno Setup installer

.NOTES
    Prerequisites:
    - Python 3.13 with pip
    - Inno Setup 6 (default location)
    - PyInstaller (pip install pyinstaller)

    Run: .\scripts\build_installer.ps1
#>

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $ProjectRoot

$InnoSetup = "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
$IssFile   = "$ProjectRoot\installer\setup.iss"
$SpecFile  = "$ProjectRoot\cyberattackdetection.spec"
$DistExe   = "$ProjectRoot\dist\CyberAttackDetection.exe"

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Cyber Attack Detection Installer Builder" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# ---- Step 1: Check prerequisites ----
Write-Host "[1/3] Checking prerequisites..." -ForegroundColor White

if (-not (Test-Path $InnoSetup)) {
    Write-Host "[ERROR] Inno Setup 6 not found at $InnoSetup" -ForegroundColor Red
    Write-Host "        Download from: https://jrsoftware.org/isinfo.php" -ForegroundColor Yellow
    exit 1
}
Write-Host "      Inno Setup: OK" -ForegroundColor Green

$pyinstaller = & python -m PyInstaller --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "      Installing PyInstaller..." -ForegroundColor Yellow
    & pip install pyinstaller
}
Write-Host "      PyInstaller: OK" -ForegroundColor Green

# Check dependencies
Write-Host "      Installing dependencies..." -ForegroundColor Yellow
& pip install -r requirements.txt --quiet
Write-Host "      Dependencies: OK" -ForegroundColor Green

# ---- Step 2: Build .exe with PyInstaller ----
Write-Host ""
Write-Host "[2/3] Building Cyber Attack Detection with PyInstaller..." -ForegroundColor White

# Clean previous build
if (Test-Path "$ProjectRoot\build") { Remove-Item "$ProjectRoot\build" -Recurse -Force }
if (Test-Path $DistExe) { Remove-Item $DistExe -Force }

& python -m PyInstaller $SpecFile --noconfirm --clean 2>&1 | ForEach-Object {
    if ($_ -match "ERROR|error|Error") {
        Write-Host "  $_" -ForegroundColor Red
    }
    elseif ($_ -match "WARNING|warning") {
        # Suppress most warnings, only show critical ones
    }
    elseif ($_ -match "Building|Appending|Compiling") {
        Write-Host "  $_" -ForegroundColor Gray
    }
}

if (-not (Test-Path $DistExe)) {
    Write-Host "[ERROR] PyInstaller build failed — $DistExe not found." -ForegroundColor Red
    exit 1
}

$exeSize = [math]::Round((Get-Item $DistExe).Length / 1MB, 1)
Write-Host "      Built: $DistExe ($exeSize MB)" -ForegroundColor Green

# ---- Step 3: Compile Inno Setup installer ----
Write-Host ""
Write-Host "[3/3] Compiling installer with Inno Setup..." -ForegroundColor White

& $InnoSetup $IssFile 2>&1 | ForEach-Object {
    if ($_ -match "Error") {
        Write-Host "  $_" -ForegroundColor Red
    }
    elseif ($_ -match "Successful") {
        Write-Host "  $_" -ForegroundColor Green
    }
    else {
        Write-Host "  $_" -ForegroundColor Gray
    }
}

$installer = Get-ChildItem "$ProjectRoot\dist\CyberAttackDetection-Setup-*.exe" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1

if ($installer) {
    $installerSize = [math]::Round($installer.Length / 1MB, 1)
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "  BUILD SUCCESSFUL" -ForegroundColor Green
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Installer: $($installer.FullName)" -ForegroundColor White
    Write-Host "  Size:      $installerSize MB" -ForegroundColor White
    Write-Host ""
    Write-Host "  The installer will:" -ForegroundColor White
    Write-Host "    [x] Install Cyber Attack Detection" -ForegroundColor Green
    Write-Host "    [x] Optionally install Sysmon" -ForegroundColor Green
    Write-Host "    [x] Optionally install Suricata + Npcap" -ForegroundColor Green
    Write-Host "    [x] Auto-download or ask user to browse for Suricata MSI" -ForegroundColor Green
    Write-Host "    [x] Configure all components automatically" -ForegroundColor Green
    Write-Host ""
}
else {
    Write-Host "[ERROR] Inno Setup compilation failed." -ForegroundColor Red
    exit 1
}
