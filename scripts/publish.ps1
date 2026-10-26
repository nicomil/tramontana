# Builds a ready-to-run WinCleaner folder: the app (self-contained, with the
# Windows App SDK) and wchelper.exe as a single file next to it.
#   powershell -ExecutionPolicy Bypass -File scripts\publish.ps1 [-Arch x64|arm64] [-Out artifacts\WinCleaner]
param(
    [ValidateSet("x64", "arm64")] [string]$Arch = "x64",
    [string]$Out = "artifacts\WinCleaner-$Arch"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$platform = if ($Arch -eq "arm64") { "ARM64" } else { "x64" }
$rid = "win-$Arch"

if (Test-Path $Out) { Remove-Item -Recurse -Force $Out }
dotnet publish src\WinCleaner.App -c Release -r $rid -p:Platform=$platform --self-contained -o $Out -nologo -v q
if ($LASTEXITCODE -ne 0) { throw "app publish failed" }
dotnet publish src\WinCleaner.Helper -c Release -r $rid -p:Platform=$platform --self-contained -p:PublishSingleFile=true -o "$Out\helper-tmp" -nologo -v q
if ($LASTEXITCODE -ne 0) { throw "helper publish failed" }
Move-Item -Force "$Out\helper-tmp\wchelper.exe" "$Out\wchelper.exe"
Remove-Item -Recurse -Force "$Out\helper-tmp"
Get-ChildItem $Out -Filter *.pdb | Remove-Item
$size = (Get-ChildItem $Out -Recurse | Measure-Object Length -Sum).Sum / 1MB
"Pubblicato in $Out ({0:N0} MB)" -f $size
