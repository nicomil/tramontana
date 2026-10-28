# Builds a ready-to-run WinCleaner folder: the app (self-contained, with the
# Windows App SDK) and wchelper.exe as a single file next to it.
#   powershell -ExecutionPolicy Bypass -File scripts\publish.ps1 [-Arch x64|arm64] [-Out artifacts\WinCleaner]
#       [-Zip] [-Setup] [-SignThumbprint <sha1 of a code-signing certificate in the user store>] [-TimestampUrl <url>]
#
# Security notes (docs/security-review.md):
#  - packages are restored in locked mode (packages.lock.json) and checked for known vulnerabilities;
#  - the SHA-256 of WinCleaner.dll is compiled into wchelper.exe, which then only serves that app;
#  - every executable, the DLLs of the project and the setup are Authenticode-signed with the "WinCleaner Code Signing"
#    certificate of this PC (scripts\new-signing-cert.ps1), or the one in -SignThumbprint; -NoSign only for throwaway builds.
param(
    [ValidateSet("x64", "arm64")] [string]$Arch = "x64",
    [string]$Out = "artifacts\WinCleaner-$Arch",
    # Also build artifacts\WinCleaner-<version>-<arch>.zip: extract on another PC and run Installa.cmd.
    [switch]$Zip,
    # Also build artifacts\WinCleaner-Setup-<version>-<arch>.exe, a classic installer (needs Inno Setup 6).
    [switch]$Setup,
    # Thumbprint of a code-signing certificate (CurrentUser\My or LocalMachine\My). Without it the certificate
    # named "WinCleaner Code Signing" is used (scripts\new-signing-cert.ps1 creates one); -NoSign skips signing.
    [string]$SignThumbprint,
    [switch]$NoSign,
    # CI: the files are signed later by SignPath (docs/code-signing-policy.md). Nothing is signed here, but the
    # helper is compiled with the thumbprint of the certificate the signed WinCleaner.exe will carry.
    [string]$ExpectedSigner,
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    # Skip the vulnerability audit (offline builds).
    [switch]$NoAudit,
    # Only build the installer from an existing -Out folder (CI: after SignPath returned the signed files).
    [switch]$SetupOnly
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$platform = if ($Arch -eq "arm64") { "ARM64" } else { "x64" }
$rid = "win-$Arch"

if (-not $NoSign -and -not $SignThumbprint) {
    $cert = @(Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.FriendlyName -eq "WinCleaner Code Signing" -and $_.NotAfter -gt (Get-Date) -and $_.HasPrivateKey } |
        Sort-Object NotAfter -Descending)
    if ($cert.Count -gt 0) { $SignThumbprint = $cert[0].Thumbprint }
    else { throw "Nessun certificato di firma: esegui scripts\new-signing-cert.ps1 (o passa -SignThumbprint, o -NoSign per una build di prova non firmata)" }
}
if ($NoSign) { $SignThumbprint = "" }
if ($ExpectedSigner -and -not $NoSign) { throw "-ExpectedSigner va con -NoSign: la firma la mette SignPath dopo la build" }
if ($SetupOnly -and -not $Setup) { $Setup = $true }

$signScript = Join-Path $PSScriptRoot "sign-file.ps1"
function Sign-Files([string[]]$files) {
    if (-not $SignThumbprint) { return }
    foreach ($file in $files) {
        & $signScript -Thumbprint $SignThumbprint -File $file -TimestampUrl $TimestampUrl
    }
}

if ($SetupOnly) {
    if (-not (Test-Path "$Out\WinCleaner.exe")) { throw "$Out non contiene una build: esegui prima publish.ps1 senza -SetupOnly" }
}
else {
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

# Dependencies exactly as locked, and none with a known advisory.
dotnet restore WinCleaner.slnx -p:Platform=$platform --locked-mode -nologo -v q
if ($LASTEXITCODE -ne 0) { throw "restore failed (packages.lock.json out of date? run dotnet restore without --locked-mode and commit the lock files)" }
if (-not $NoAudit) {
    $audit = dotnet list WinCleaner.slnx package --vulnerable --include-transitive 2>&1 | Out-String
    if ($audit -match "has the following vulnerable packages" -or $audit -match ">\s+\S+\s+\S+\s+\S+\s+(Critical|High|Moderate|Low)") {
        Write-Host $audit
        throw "vulnerable packages: update Directory.Packages.props"
    }
}

dotnet publish src\WinCleaner.App -c Release -r $rid -p:Platform=$platform --self-contained --no-restore -o $Out -nologo -v q
if ($LASTEXITCODE -ne 0) { throw "app publish failed" }
Get-ChildItem $Out -Filter *.pdb | Remove-Item

# The app's own binaries are signed first (the runtime and SDK files are Microsoft's), so the hash below is of the signed dll.
$own = @("$Out\WinCleaner.exe") + (Get-ChildItem $Out -Filter "WinCleaner*.dll" | ForEach-Object FullName)
Sign-Files $own

# The helper is bound to this very build of the app (hash of WinCleaner.dll, signer of WinCleaner.exe): it refuses any other caller.
$appHash = (Get-FileHash -Algorithm SHA256 -LiteralPath "$Out\WinCleaner.dll").Hash
$signer = if ($SignThumbprint) { $SignThumbprint } else { $ExpectedSigner }
dotnet publish src\WinCleaner.Helper -c Release -r $rid -p:Platform=$platform --self-contained -p:PublishSingleFile=true "-p:WcAppSha256=$appHash" "-p:WcSignerThumbprint=$signer" --no-restore -o "$Out\helper-tmp" -nologo -v q
if ($LASTEXITCODE -ne 0) { throw "helper publish failed" }
Move-Item -Force "$Out\helper-tmp\wchelper.exe" "$Out\wchelper.exe"
Remove-Item -Recurse -Force "$Out\helper-tmp"
Sign-Files @("$Out\wchelper.exe")
$reported = (& "$Out\wchelper.exe" --identity | Out-String).Trim()
if ($reported -ne "$appHash|$signer") { throw "wchelper.exe non riporta l'identità dell'app ($reported invece di $appHash|$signer)" }
"Helper legato a WinCleaner.dll $($appHash.Substring(0, 16))... firmata da $(if ($signer) { $signer } else { 'nessuno (build di prova)' })"

if ($SignThumbprint) {
    foreach ($file in $own + @("$Out\wchelper.exe")) {
        $sig = Get-AuthenticodeSignature -LiteralPath $file
        if ($sig.Status -eq "HashMismatch" -or $sig.Status -eq "NotSigned" -or $sig.SignerCertificate.Thumbprint -ne $SignThumbprint) { throw "firma non valida: $file ($($sig.Status))" }
    }
    "Firmati $($own.Count + 1) file con il certificato $SignThumbprint"
}
$size = (Get-ChildItem $Out -Recurse | Measure-Object Length -Sum).Sum / 1MB
"Pubblicato in $Out ({0:N0} MB)" -f $size
}

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

if ($Setup) {
    $iscc = (Get-Command ISCC.exe -ErrorAction SilentlyContinue).Source
    if (-not $iscc) {
        $iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
                  "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
    }
    if (-not $iscc) { throw "Inno Setup 6 non trovato: winget install JRSoftware.InnoSetup" }
    $version = (Get-Item "$Out\WinCleaner.exe").VersionInfo.ProductVersion -replace '\+.*$', ''
    $signArgs = @()
    if ($SignThumbprint) {
        # Inno runs "$f" through the SignTool definition: setup.exe and the uninstaller get signed too.
        $signArgs = @("/Ssigntool=powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$signScript`" -Thumbprint $SignThumbprint -TimestampUrl $TimestampUrl -File `$f", "/DSignTool=signtool")
    }
    & $iscc /Q "/DAppVersion=$version" "/DArch=$Arch" "/DSourceDir=$((Resolve-Path $Out).Path)" `
        "/DOutputDir=$((Resolve-Path artifacts).Path)" @signArgs installer\WinCleaner.iss
    if ($LASTEXITCODE -ne 0) { throw "setup build failed" }
    $exe = "artifacts\WinCleaner-Setup-$version-$Arch.exe"
    "Setup: $exe ({0:N0} MB)" -f ((Get-Item $exe).Length / 1MB)
}
