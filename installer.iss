; ZainWolf Tunnel — Inno Setup installer script
; Builds ZainWolfTunnel-Setup-1.0.1.exe from the PyInstaller output.
; Run on Windows after build_windows_exe.bat, or via the GitHub Actions
; workflow (.github/workflows/build-windows.yml), which installs Inno Setup
; and compiles this script automatically.
; The user only ever receives this setup EXE, never the raw portable EXE.

#define AppName "ZainWolf Tunnel"
#define AppVersion "1.0.1"
#define AppPublisher "ZainWolf"
#define AppExe "ZainWolfTunnel.exe"

[Setup]
AppId={{4E76A74D-7ADE-43CF-A1CE-49FBB471652A}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\ZainWolf Tunnel
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=Output
OutputBaseFilename=ZainWolfTunnel-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupIconFile=
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
VersionInfoVersion={#AppVersion}
VersionInfoProductName={#AppName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "dist\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "tools\THIRD_PARTY_NOTICES.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "tools\licenses\*"; DestDir: "{app}\licenses"; Flags: ignoreversion recursesubdirs
Source: "restore_network_routes.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "restore_network_routes.bat"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Remove any temporary Full Traffic routes left behind by the app, silently.
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\restore_network_routes.ps1"" -NonInteractive"; Flags: runhidden; RunOnceId: "RestoreRoutes"
