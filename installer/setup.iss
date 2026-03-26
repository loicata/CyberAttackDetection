; Cyber Attack Detection Inno Setup Installer Script
; All dependencies bundled — no internet required during installation
; (ET rules still downloaded at first Suricata launch for freshness)

#define MyAppName "Cyber Attack Detection"
#define MyAppVersion "1.0.1"
#define MyAppPublisher "Loic Ader"
#define MyAppExeName "CyberAttackDetection.exe"

[Setup]
AppId={{E3A5F2C1-B7D4-4F8E-9A3C-6D2E1F0B8C7A}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppCopyright=Copyright (c) 2026 Loic Ader — MIT License
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
OutputDir=..\dist
OutputBaseFilename=CyberAttackDetection{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
SetupLogging=yes
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
UninstallDisplayIcon={app}\{#MyAppExeName}
SetupIconFile=..\assets\icon.ico
MinVersion=10.0.17763

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "french"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "install_sysmon"; Description: "Install Sysmon (Microsoft Sysinternals — process/network monitoring)"; GroupDescription: "Security Components:"; Flags: checkedonce
Name: "install_suricata"; Description: "Install Suricata IDS (network intrusion detection)"; GroupDescription: "Security Components:"; Flags: checkedonce
Name: "autostart"; Description: "Start Cyber Attack Detection automatically at Windows startup"; GroupDescription: "System Integration:"; Flags: checkedonce

[Files]
; Main application
Source: "..\dist\CyberAttackDetection.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\config\default.toml"; DestDir: "{app}\config"; Flags: ignoreversion
Source: "..\config\local.toml"; DestDir: "{app}\config"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "..\.env.example"; DestDir: "{app}"; DestName: ".env.example"; Flags: ignoreversion

; Icon
Source: "..\assets\icon.ico"; DestDir: "{app}"; Flags: ignoreversion

; Installation scripts (kept for manual re-install if needed)
Source: "..\scripts\install_sysmon.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "..\scripts\install_suricata.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion

; ========== BUNDLED DEPENDENCIES (no internet needed) ==========
; VC++ Redistributable 2015-2022 x64
Source: "deps\vc_redist.x64.exe"; DestDir: "{tmp}"; Flags: ignoreversion deleteafterinstall

; Sysmon (extracted during install if selected)
Source: "deps\Sysmon.zip"; DestDir: "{tmp}"; Flags: ignoreversion deleteafterinstall; Tasks: install_sysmon
Source: "deps\sysmonconfig-export.xml"; DestDir: "{tmp}"; Flags: ignoreversion deleteafterinstall; Tasks: install_sysmon

; Npcap + Suricata (installed if Suricata selected)
Source: "deps\npcap-installer.exe"; DestDir: "{tmp}"; Flags: ignoreversion deleteafterinstall; Tasks: install_suricata
Source: "deps\suricata.msi"; DestDir: "{tmp}"; Flags: ignoreversion deleteafterinstall; Tasks: install_suricata

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "CyberAttackDetection"; ValueData: """{app}\{#MyAppExeName}"""; Flags: uninsdeletevalue; Tasks: autostart

[Run]
; Launch after install
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Cyber Attack Detection"; Flags: nowait postinstall skipifsilent

[Code]
// ============================================================
// Helper: Run PowerShell silently
// ============================================================
function RunPowerShell(const Script: String): Integer;
var
  ResultCode: Integer;
begin
  Exec('powershell.exe',
    '-NoProfile -ExecutionPolicy Bypass -Command "' + Script + '"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := ResultCode;
end;

// ============================================================
// Helper: Check if a service exists
// ============================================================
function ServiceExists(const ServiceName: String): Boolean;
var
  ResultCode: Integer;
begin
  Exec('sc.exe', 'query ' + ServiceName, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := (ResultCode = 0);
end;

// ============================================================
// Check if VC++ Redistributable is already installed
// ============================================================
function IsVCRedistInstalled: Boolean;
var
  Version: String;
begin
  Result := RegQueryStringValue(HKLM,
    'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64',
    'Version', Version);
  if Result then
    Log('VC++ Redistributable found: ' + Version)
  else
    Log('VC++ Redistributable NOT found');
end;

// ============================================================
// Install Visual C++ Redistributable (bundled)
// ============================================================
procedure InstallVCRedist;
var
  VCExe: String;
  ResultCode: Integer;
begin
  if IsVCRedistInstalled then
  begin
    Log('VC++ Redistributable already installed, skipping');
    Exit;
  end;

  VCExe := ExpandConstant('{tmp}\vc_redist.x64.exe');
  if not FileExists(VCExe) then
  begin
    Log('vc_redist.x64.exe not found in temp — skipping');
    Exit;
  end;

  WizardForm.StatusLabel.Caption := 'Installing Visual C++ 2015-2022 Runtime...';
  Exec(VCExe, '/install /quiet /norestart', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('VC++ Redistributable install exit code: ' + IntToStr(ResultCode));
end;

// ============================================================
// Install Sysmon (bundled)
// ============================================================
procedure InstallSysmon;
var
  SysmonDir, SysmonZip, SysmonExe, ConfigFile: String;
  ResultCode: Integer;
  Ps: String;
begin
  if ServiceExists('Sysmon64') then
  begin
    Log('Sysmon64 already installed, skipping');
    Exit;
  end;

  SysmonDir := 'C:\Sysmon';
  SysmonZip := ExpandConstant('{tmp}\Sysmon.zip');
  SysmonExe := SysmonDir + '\Sysmon64.exe';
  ConfigFile := SysmonDir + '\sysmonconfig-export.xml';

  ForceDirectories(SysmonDir);

  // Extract bundled Sysmon.zip
  WizardForm.StatusLabel.Caption := 'Extracting Sysmon...';
  Ps := 'Expand-Archive -Path \"' + SysmonZip + '\" -DestinationPath \"' + SysmonDir + '\" -Force';
  RunPowerShell(Ps);

  if not FileExists(SysmonExe) then
  begin
    Log('Sysmon64.exe not found after extraction');
    MsgBox('Sysmon extraction failed. You can install manually later.', mbInformation, MB_OK);
    Exit;
  end;

  // Copy bundled config
  CopyFile(ExpandConstant('{tmp}\sysmonconfig-export.xml'), ConfigFile, False);

  // Install service
  WizardForm.StatusLabel.Caption := 'Installing Sysmon service...';
  Exec(SysmonExe, '-accepteula -i ' + ConfigFile, SysmonDir,
    SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('Sysmon install exit code: ' + IntToStr(ResultCode));

  // Write sysmon config to local.toml
  WizardForm.StatusLabel.Caption := 'Configuring Sysmon for Cyber Attack Detection...';
  Ps := '$toml = @\"' + #13#10 +
    '[detection.eventlog]' + #13#10 +
    'sysmon_enabled = true' + #13#10 +
    'channels = [\"Security\", \"System\", \"Application\", \"Microsoft-Windows-Sysmon/Operational\"]' + #13#10 +
    '\"@; ' +
    '$p = \"' + ExpandConstant('{app}\config\local.toml') + '\"; ' +
    'if (Test-Path $p) { $c = Get-Content $p -Raw; if ($c -notmatch \"sysmon_enabled\") { Add-Content $p $toml } } ' +
    'else { Set-Content $p $toml }';
  RunPowerShell(Ps);
end;

// ============================================================
// Install Npcap (bundled)
// ============================================================
procedure InstallNpcap;
var
  NpcapExe: String;
  ResultCode: Integer;
begin
  if FileExists('C:\Program Files\Npcap\NPFInstall.exe') then
  begin
    Log('Npcap already installed, skipping');
    Exit;
  end;

  NpcapExe := ExpandConstant('{tmp}\npcap-installer.exe');
  if not FileExists(NpcapExe) then
  begin
    Log('npcap-installer.exe not found in temp');
    Exit;
  end;

  WizardForm.StatusLabel.Caption := 'Installing Npcap (packet capture)...';
  Exec(NpcapExe, '/S /winpcap_mode=yes', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('Npcap install exit code: ' + IntToStr(ResultCode));
end;

// ============================================================
// Install Suricata (bundled MSI)
// ============================================================
procedure InstallSuricata;
var
  ResultCode: Integer;
  MsiPath: String;
  Ps: String;
  SuricataExe, SuricataYaml, SuricataLog: String;
begin
  SuricataExe := ExpandConstant('{pf}\Suricata\suricata.exe');

  if FileExists(SuricataExe) then
  begin
    Log('Suricata already installed, skipping MSI');
  end
  else
  begin
    // Install Npcap first (required dependency)
    InstallNpcap;

    MsiPath := ExpandConstant('{tmp}\suricata.msi');
    if not FileExists(MsiPath) then
    begin
      Log('suricata.msi not found in temp');
      MsgBox('Suricata MSI not found. You can install manually later.', mbInformation, MB_OK);
      Exit;
    end;

    WizardForm.StatusLabel.Caption := 'Installing Suricata IDS...';
    Exec('msiexec.exe', '/i "' + MsiPath + '" /quiet /norestart', '',
      SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Log('Suricata MSI exit code: ' + IntToStr(ResultCode));

    if not FileExists(SuricataExe) then
    begin
      MsgBox('Suricata installation may have failed. You can install manually later.',
        mbInformation, MB_OK);
      Exit;
    end;
  end;

  // Configure suricata.yaml (HOME_NET + interface detection)
  WizardForm.StatusLabel.Caption := 'Configuring Suricata...';
  SuricataYaml := ExpandConstant('{pf}\Suricata\suricata.yaml');
  SuricataLog := ExpandConstant('{pf}\Suricata\log');

  // Set HOME_NET based on active adapter
  Ps :=
    '$adapter = Get-NetAdapter | Where-Object { $_.Status -eq \"Up\" -and $_.InterfaceDescription -notmatch \"Loopback|Virtual|Hyper-V|vEthernet|WireGuard|ProtonVPN|NordVPN|OpenVPN|TAP-Windows\" } | Select-Object -First 1; ' +
    'if ($adapter) { ' +
    '  $ip = (Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress | Select-Object -First 1; ' +
    '  if ($ip) { ' +
    '    $parts = $ip.Split(\".\"); ' +
    '    $net = \"$($parts[0]).$($parts[1]).$($parts[2]).0/24\"; ' +
    '    $yaml = Get-Content \"' + SuricataYaml + '\" -Raw -ErrorAction SilentlyContinue; ' +
    '    if ($yaml) { ' +
    '      $yaml = $yaml -replace \"HOME_NET:\s*\"\"\[.*?\]\"\"\", (\"HOME_NET: \"\"[$net]\"\"\"); ' +
    '      Set-Content \"' + SuricataYaml + '\" $yaml -Encoding UTF8 ' +
    '    } ' +
    '  } ' +
    '}';
  RunPowerShell(Ps);

  // Ensure log dir
  ForceDirectories(SuricataLog);

  // Add Npcap to PATH
  Ps := '$npcap = \"C:\Windows\System32\Npcap\"; ' +
    '$p = [Environment]::GetEnvironmentVariable(\"PATH\", \"Machine\"); ' +
    'if ($p -notlike \"*$npcap*\") { [Environment]::SetEnvironmentVariable(\"PATH\", \"$npcap;$p\", \"Machine\") }';
  RunPowerShell(Ps);

  // Detect network interface and start Suricata
  WizardForm.StatusLabel.Caption := 'Starting Suricata...';
  Ps :=
    '$adapter = Get-NetAdapter | Where-Object { $_.Status -eq \"Up\" -and $_.InterfaceDescription -notmatch \"Loopback|Virtual|Hyper-V|vEthernet|WireGuard|ProtonVPN|NordVPN|OpenVPN|TAP-Windows\" } | Select-Object -First 1; ' +
    'if ($adapter) { ' +
    '  $guid = $adapter.InterfaceGuid; ' +
    '  $dev = \"\\Device\\NPF_$guid\"; ' +
    '  Start-Process -FilePath \"' + SuricataExe + '\" -ArgumentList \"-c\",\"' + SuricataYaml + '\",\"-i\",$dev,\"-l\",\"' + SuricataLog + '\" -WindowStyle Hidden ' +
    '}';
  RunPowerShell(Ps);

  // Download ET rules in background (only thing needing internet)
  WizardForm.StatusLabel.Caption := 'Downloading Suricata threat rules (background)...';
  Ps := 'try { ' +
    '$suricataUpdate = \"' + ExpandConstant('{pf}') + '\Suricata\suricata-update.exe\"; ' +
    'if (Test-Path $suricataUpdate) { ' +
    '  Start-Process -FilePath $suricataUpdate -ArgumentList \"--suricata\",\"' + SuricataExe + '\",\"--suricata-conf\",\"' + SuricataYaml + '\" -WindowStyle Hidden ' +
    '} } catch {}';
  RunPowerShell(Ps);

  // Create daily scheduled task for ET rules update
  WizardForm.StatusLabel.Caption := 'Creating daily rules update task...';
  Ps := '$action = New-ScheduledTaskAction -Execute \"' + ExpandConstant('{pf}') + '\Suricata\suricata-update.exe\" ' +
    '-Argument \"--suricata \\\"\"' + SuricataExe + '\\\"\" --suricata-conf \\\"\"' + SuricataYaml + '\\\"\"\"; ' +
    '$trigger = New-ScheduledTaskTrigger -Daily -At 4:00AM; ' +
    '$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable; ' +
    '$principal = New-ScheduledTaskPrincipal -UserId \"SYSTEM\" -RunLevel Highest; ' +
    '$existing = Get-ScheduledTask -TaskName \"SuricataRulesUpdate\" -ErrorAction SilentlyContinue; ' +
    'if ($existing) { Unregister-ScheduledTask -TaskName \"SuricataRulesUpdate\" -Confirm:$false }; ' +
    'Register-ScheduledTask -TaskName \"SuricataRulesUpdate\" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description \"Daily Emerging Threats rules update for Suricata IDS\"';
  RunPowerShell(Ps);
  Log('Created daily ET rules update scheduled task at 4:00 AM');

  // Write suricata config to local.toml
  WizardForm.StatusLabel.Caption := 'Configuring Cyber Attack Detection for Suricata...';
  Ps := '$toml = @\"' + #13#10 +
    '[detection.suricata]' + #13#10 +
    'enabled = true' + #13#10 +
    'eve_json_path = \"C:\\\\Program Files\\\\Suricata\\\\log\\\\eve.json\"' + #13#10 +
    'syslog_listen_port = 0' + #13#10 +
    'syslog_listen_host = \"127.0.0.1\"' + #13#10 +
    '\"@; ' +
    '$p = \"' + ExpandConstant('{app}\config\local.toml') + '\"; ' +
    'if (Test-Path $p) { $c = Get-Content $p -Raw; if ($c -notmatch \"detection\.suricata\") { Add-Content $p $toml } } ' +
    'else { Set-Content $p $toml }';
  RunPowerShell(Ps);
end;

// ============================================================
// Main install procedure
// ============================================================
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    // Step 0: Always install VC++ Runtime if missing
    InstallVCRedist;

    // Step 1: Sysmon (optional)
    if WizardIsTaskSelected('install_sysmon') then
      InstallSysmon;

    // Step 2: Suricata + Npcap (optional)
    if WizardIsTaskSelected('install_suricata') then
      InstallSuricata;

    WizardForm.StatusLabel.Caption := 'Installation complete!';
  end;
end;

// ============================================================
// Uninstall: clean up but keep Sysmon and Suricata (system-wide)
// ============================================================
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    // Remove the daily rules update task
    Exec('schtasks.exe', '/Delete /TN "SuricataRulesUpdate" /F',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Log('Cyber Attack Detection uninstalled. Sysmon and Suricata are preserved.');
  end;
end;
