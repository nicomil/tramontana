# Installs a published WinCleaner folder into Program Files (only administrators
# can change it there, so the helper runs directly), adds a Start menu shortcut
# and an entry in Settings > Apps.
#   powershell -ExecutionPolicy Bypass -File scripts\install.ps1 [-Source artifacts\WinCleaner-x64]
param([string]$Source = (Join-Path (Split-Path -Parent $PSScriptRoot) "artifacts\WinCleaner-x64"))
$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Source `"$((Resolve-Path $Source).Path)`""
    exit
}

$target = Join-Path $env:ProgramFiles "WinCleaner"
if (-not (Test-Path (Join-Path $Source "WinCleaner.exe"))) { throw "WinCleaner.exe non trovato in $Source: esegui prima scripts\publish.ps1" }
Get-Process WinCleaner -ErrorAction SilentlyContinue | Stop-Process -Force
if (Test-Path $target) { Remove-Item -Recurse -Force $target }
Copy-Item -Recurse $Source $target
Copy-Item (Join-Path $PSScriptRoot "uninstall.ps1") (Join-Path $target "uninstall.ps1")

$shell = New-Object -ComObject WScript.Shell
$link = $shell.CreateShortcut((Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\WinCleaner.lnk"))
$link.TargetPath = Join-Path $target "WinCleaner.exe"
$link.WorkingDirectory = $target
$link.IconLocation = (Join-Path $target "Assets\AppIcon.ico")
$link.Save()

$key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinCleaner"
New-Item -Force $key | Out-Null
$version = (Get-Item (Join-Path $target "WinCleaner.exe")).VersionInfo.ProductVersion
$size = [int]((Get-ChildItem $target -Recurse | Measure-Object Length -Sum).Sum / 1KB)
Set-ItemProperty $key DisplayName "WinCleaner"
Set-ItemProperty $key DisplayVersion $version
Set-ItemProperty $key Publisher "Nicola Milella"
Set-ItemProperty $key InstallLocation $target
Set-ItemProperty $key DisplayIcon (Join-Path $target "WinCleaner.exe")
Set-ItemProperty $key UninstallString "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$target\uninstall.ps1`""
Set-ItemProperty $key EstimatedSize $size -Type DWord
Set-ItemProperty $key NoModify 1 -Type DWord
Set-ItemProperty $key NoRepair 1 -Type DWord
"WinCleaner installato in $target"
