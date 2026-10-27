# Installs a published WinCleaner folder into Program Files (only administrators
# can change it there, so the helper runs directly), adds a Start menu shortcut
# and an entry in Settings > Apps.
#   powershell -ExecutionPolicy Bypass -File scripts\install.ps1 [-Source artifacts\WinCleaner-x64]
param([string]$Source, [switch]$AllowUnsigned)
# In a release package the app sits in .\app next to this script; in the repository, in artifacts\.
if (-not $Source) {
    $Source = if (Test-Path (Join-Path $PSScriptRoot "app\WinCleaner.exe")) { Join-Path $PSScriptRoot "app" }
              else { Join-Path (Split-Path -Parent $PSScriptRoot) "artifacts\WinCleaner-x64" }
}
$Source = $Source.TrimEnd('\')
$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $unsigned = if ($AllowUnsigned) { " -AllowUnsigned" } else { "" }
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Source `"$((Resolve-Path $Source).Path)`"$unsigned"
    exit
}

$target = Join-Path $env:ProgramFiles "WinCleaner"
if (-not (Test-Path (Join-Path $Source "WinCleaner.exe"))) { throw "WinCleaner.exe non trovato in ${Source}: esegui prima scripts\publish.ps1" }

# Nothing altered gets copied into Program Files: the app's binaries must carry intact signatures from one and the same publisher.
$own = @((Join-Path $Source "WinCleaner.exe"), (Join-Path $Source "wchelper.exe")) + (Get-ChildItem $Source -Filter "WinCleaner*.dll" | ForEach-Object FullName)
$signers = @()
foreach ($file in $own) {
    $sig = Get-AuthenticodeSignature -LiteralPath $file
    if ($sig.Status -eq "HashMismatch") { throw "$file è stato modificato dopo la firma: installazione annullata" }
    if ($sig.Status -eq "NotSigned") {
        if (-not $AllowUnsigned) { throw "$file non è firmato. Pubblica con scripts\publish.ps1 (firma automatica) oppure usa -AllowUnsigned per una build di prova" }
        Write-Warning "$file non è firmato (build di prova)"
    }
    elseif (-not $sig.SignerCertificate) { throw "$file ha una firma illeggibile ($($sig.Status)): installazione annullata" }
    else { $signers += $sig.SignerCertificate.Thumbprint }
}
if (($signers | Sort-Object -Unique).Count -gt 1) { throw "I file sono firmati da certificati diversi: installazione annullata" }
Get-Process WinCleaner -ErrorAction SilentlyContinue | Stop-Process -Force
if (Test-Path $target) { Remove-Item -Recurse -Force $target }
Copy-Item -Recurse $Source $target
Copy-Item (Join-Path $PSScriptRoot "uninstall.ps1") (Join-Path $target "uninstall.ps1")
# Files from a downloaded zip carry the "from the internet" mark: SmartScreen would block the helper.
Get-ChildItem $target -Recurse -File | Unblock-File

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
