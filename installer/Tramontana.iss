; Classic setup.exe for Tramontana, built with Inno Setup 6.
; Built by scripts\publish.ps1 -Setup, which passes the defines below:
;   ISCC /DAppVersion=0.2.0 /DArch=x64 /DSourceDir=<published folder> /DOutputDir=<artifacts> installer\Tramontana.iss

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef Arch
  #define Arch "x64"
#endif
#ifndef SourceDir
  #define SourceDir "..\artifacts\Tramontana-" + Arch
#endif
#ifndef OutputDir
  #define OutputDir "..\artifacts"
#endif
; publish.ps1 -SignThumbprint passes /SSignTool=... and /DSignTool=signtool: setup and uninstaller get Authenticode-signed.

[Setup]
; Never change AppId: Windows uses it to recognise upgrades of the same app.
; (Up to 0.2 the app was WinCleaner, AppId 6F2A9C1E-4B7D-4E8A-9C35-0D1B7E5A2F64: PrepareToInstall removes it.)
AppId={{9F2EC35D-04E8-4328-BC77-C6B7CA4EB35C}
AppName=Tramontana
AppVersion={#AppVersion}
AppVerName=Tramontana {#AppVersion}
AppPublisher=Nicola Milella
VersionInfoVersion={#AppVersion}
DefaultDirName={autopf}\Tramontana
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
SetupIconFile=..\src\Tramontana.App\Assets\AppIcon.ico
UninstallDisplayIcon={app}\Tramontana.exe
UninstallDisplayName=Tramontana
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
OutputDir={#OutputDir}
OutputBaseFilename=Tramontana-Setup-{#AppVersion}-{#Arch}
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
Name: "{autoprograms}\Tramontana"; Filename: "{app}\Tramontana.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\Tramontana"; Filename: "{app}\Tramontana.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\Tramontana.exe"; Description: "{cm:LaunchProgram,Tramontana}"; Flags: nowait postinstall skipifsilent

[Code]
procedure StopTramontana();
var
  Code: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM Tramontana.exe', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM trhelper.exe', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM WinCleaner.exe', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM wchelper.exe', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Sleep(500);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  OldUninstaller: String;
  Code: Integer;
begin
  StopTramontana();
  // Up to 0.2 the app was WinCleaner, with its own setup: run its uninstaller first, so
  // Settings > Apps lists one app and Program Files has one folder. The user's data in
  // %LOCALAPPDATA%\WinCleaner is kept, and the app moves it to its new folder at first start.
  if RegQueryStringValue(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{6F2A9C1E-4B7D-4E8A-9C35-0D1B7E5A2F64}_is1', 'UninstallString', OldUninstaller) then
  begin
    OldUninstaller := RemoveQuotes(OldUninstaller);
    if FileExists(OldUninstaller) then
      Exec(OldUninstaller, '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART', '', SW_HIDE, ewWaitUntilTerminated, Code);
  end;
  // Older versions were installed by scripts\install.ps1 with their own entry in
  // Settings > Apps: remove it so the app is not listed twice.
  RegDeleteKeyIncludingSubkeys(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinCleaner');
  RegDeleteKeyIncludingSubkeys(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Tramontana');
  Result := '';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Code: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    StopTramontana();
    // Things the app itself creates: the scheduled scan and "start with Windows".
    // User data in %LOCALAPPDATA%\Tramontana (log, settings, backups) is kept.
    Exec(ExpandConstant('{sys}\schtasks.exe'), '/Delete /TN "Tramontana - analisi pianificata" /F', '', SW_HIDE, ewWaitUntilTerminated, Code);
    RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'Tramontana');
  end;
end;
