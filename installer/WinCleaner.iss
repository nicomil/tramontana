; Classic setup.exe for WinCleaner, built with Inno Setup 6.
; Built by scripts\publish.ps1 -Setup, which passes the defines below:
;   ISCC /DAppVersion=0.2.0 /DArch=x64 /DSourceDir=<published folder> /DOutputDir=<artifacts> installer\WinCleaner.iss

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef Arch
  #define Arch "x64"
#endif
#ifndef SourceDir
  #define SourceDir "..\artifacts\WinCleaner-" + Arch
#endif
#ifndef OutputDir
  #define OutputDir "..\artifacts"
#endif
; publish.ps1 -SignThumbprint passes /SSignTool=... and /DSignTool=signtool: setup and uninstaller get Authenticode-signed.

[Setup]
; Never change AppId: Windows uses it to recognise upgrades of the same app.
AppId={{6F2A9C1E-4B7D-4E8A-9C35-0D1B7E5A2F64}
AppName=WinCleaner
AppVersion={#AppVersion}
AppVerName=WinCleaner {#AppVersion}
AppPublisher=Nicola Milella
VersionInfoVersion={#AppVersion}
DefaultDirName={autopf}\WinCleaner
; The folder is fixed: the app must live in Program Files so the helper can run
; without copies, and the upgrade step below empties it safely.
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
MinVersion=10.0.19041
#if Arch == "arm64"
ArchitecturesAllowed=arm64
ArchitecturesInstallIn64BitMode=arm64
#else
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
#endif
SetupIconFile=..\src\WinCleaner.App\Assets\AppIcon.ico
UninstallDisplayIcon={app}\WinCleaner.exe
UninstallDisplayName=WinCleaner
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
OutputDir={#OutputDir}
OutputBaseFilename=WinCleaner-Setup-{#AppVersion}-{#Arch}
; Closing the app is handled in PrepareToInstall, without the Restart Manager prompt.
CloseApplications=no
#ifdef SignTool
SignTool={#SignTool}
SignedUninstaller=yes
#endif

[Languages]
Name: "it"; MessagesFile: "compiler:Languages\Italian.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[InstallDelete]
; Upgrades start from an empty folder, so files from the previous version never linger.
Type: filesandordirs; Name: "{app}\*"

[UninstallDelete]
; The folder may predate this setup (older script installs), so remove it explicitly once empty.
Type: dirifempty; Name: "{app}"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\WinCleaner"; Filename: "{app}\WinCleaner.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\WinCleaner"; Filename: "{app}\WinCleaner.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\WinCleaner.exe"; Description: "{cm:LaunchProgram,WinCleaner}"; Flags: nowait postinstall skipifsilent

[Code]
procedure StopWinCleaner();
var
  Code: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM WinCleaner.exe', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM wchelper.exe', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Sleep(500);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopWinCleaner();
  // Older versions were installed by scripts\install.ps1 with their own entry in
  // Settings > Apps: remove it so the app is not listed twice.
  RegDeleteKeyIncludingSubkeys(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinCleaner');
  Result := '';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Code: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    StopWinCleaner();
    // Things the app itself creates: the scheduled scan and "start with Windows".
    // User data in %LOCALAPPDATA%\WinCleaner (log, settings, backups) is kept.
    Exec(ExpandConstant('{sys}\schtasks.exe'), '/Delete /TN "WinCleaner - analisi pianificata" /F', '', SW_HIDE, ewWaitUntilTerminated, Code);
    RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'WinCleaner');
  end;
end;
