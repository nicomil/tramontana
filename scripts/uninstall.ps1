# Removes Tramontana from Program Files, its shortcut, its Settings > Apps entry,
# the scheduled scan and the "start with Windows" value. User data in
# %LOCALAPPDATA%\Tramontana (log, settings, registry backups) is kept.
$ErrorActionPreference = "Stop"
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}
Get-Process Tramontana, trhelper -ErrorAction SilentlyContinue | Stop-Process -Force
Unregister-ScheduledTask -TaskName "Tramontana - analisi pianificata" -Confirm:$false -ErrorAction SilentlyContinue
Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name Tramontana -ErrorAction SilentlyContinue
Remove-Item -Force (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Tramontana.lnk") -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Tramontana" -ErrorAction SilentlyContinue
$target = Join-Path $env:ProgramFiles "Tramontana"
# The script itself lives in the folder: remove it from a temporary copy of cmd.
Start-Process cmd.exe -ArgumentList "/c timeout /t 2 >nul & rmdir /s /q `"$target`"" -WindowStyle Hidden
"Tramontana disinstallato. I dati in $env:LOCALAPPDATA\Tramontana restano."
