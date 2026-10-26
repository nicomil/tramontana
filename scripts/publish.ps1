# Builds a ready-to-run WinCleaner folder: the app (self-contained, with the
# Windows App SDK) and wchelper.exe as a single file next to it.
#   powershell -ExecutionPolicy Bypass -File scripts\publish.ps1 [-Arch x64|arm64] [-Out artifacts\WinCleaner]
param(
    [ValidateSet("x64", "arm64")] [string]$Arch = "x64",
    [string]$Out = "artifacts\WinCleaner-$Arch",
    # Also build artifacts\WinCleaner-<version>-<arch>.zip: extract on another PC and run Installa.cmd.
    [switch]$Zip
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$platform = if ($Arch -eq "arm64") { "ARM64" } else { "x64" }
$rid = "win-$Arch"

if (Test-Path $Out) {
    # A copy started from this folder keeps its files locked: close it first.
    $full = (Resolve-Path $Out).Path
    Get-Process WinCleaner, wchelper -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and $_.Path.StartsWith($full, [StringComparison]::OrdinalIgnoreCase) } |
        Stop-Process -Force
    Start-Sleep -Milliseconds 500
    # Empty it rather than delete it: an Explorer window may have the folder open.
    Get-ChildItem $Out -Force | Remove-Item -Recurse -Force
}
dotnet publish src\WinCleaner.App -c Release -r $rid -p:Platform=$platform --self-contained -o $Out -nologo -v q
if ($LASTEXITCODE -ne 0) { throw "app publish failed" }
dotnet publish src\WinCleaner.Helper -c Release -r $rid -p:Platform=$platform --self-contained -p:PublishSingleFile=true -o "$Out\helper-tmp" -nologo -v q
if ($LASTEXITCODE -ne 0) { throw "helper publish failed" }
Move-Item -Force "$Out\helper-tmp\wchelper.exe" "$Out\wchelper.exe"
Remove-Item -Recurse -Force "$Out\helper-tmp"
Get-ChildItem $Out -Filter *.pdb | Remove-Item
$size = (Get-ChildItem $Out -Recurse | Measure-Object Length -Sum).Sum / 1MB
"Pubblicato in $Out ({0:N0} MB)" -f $size

if ($Zip) {
    $version = (Get-Item "$Out\WinCleaner.exe").VersionInfo.ProductVersion -replace '\+.*$', ''
    $name = "WinCleaner-$version-$Arch"
    $stage = "artifacts\package\$name"
    if (Test-Path "artifacts\package") { Remove-Item -Recurse -Force "artifacts\package" }
    New-Item -ItemType Directory -Force $stage | Out-Null
    Copy-Item -Recurse $Out "$stage\app"
    Copy-Item scripts\install.ps1, scripts\uninstall.ps1, scripts\Installa.cmd $stage
    $zipPath = "artifacts\$name.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath }
    Compress-Archive -Path $stage -DestinationPath $zipPath -CompressionLevel Optimal
    Remove-Item -Recurse -Force "artifacts\package"
    "Pacchetto: $zipPath ({0:N0} MB)" -f ((Get-Item $zipPath).Length / 1MB)
}
