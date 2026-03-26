#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Master installer: Sysmon + Suricata + Cyber Attack Detection configuration.
    Run this script once to set up the complete detection stack.

.NOTES
    Must be run as Administrator.
    Usage: .\scripts\install_all.ps1
#>

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Cyber Attack Detection — Complete Stack Installer" -ForegroundColor Cyan
Write-Host "  Sysmon + Suricata + Configuration" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# ---- Step 1: Install Sysmon ----
Write-Host "=== PHASE 1: SYSMON ===" -ForegroundColor Yellow
Write-Host ""
& "$ScriptDir\install_sysmon.ps1"

Write-Host ""
Write-Host "=== PHASE 2: SURICATA ===" -ForegroundColor Yellow
Write-Host ""
& "$ScriptDir\install_suricata.ps1"

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  ALL COMPONENTS INSTALLED" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Installed:" -ForegroundColor White
Write-Host "    [x] Sysmon     — 16 event types monitored" -ForegroundColor Green
Write-Host "    [x] Suricata   — IDS with Emerging Threats rules" -ForegroundColor Green
Write-Host "    [x] Config     — local.toml updated" -ForegroundColor Green
Write-Host ""
Write-Host "  Next: Launch CyberAttackDetection.exe" -ForegroundColor White
Write-Host ""
