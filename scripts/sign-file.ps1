# Signs one file with the certificate publish.ps1 chose, using Windows's own
# Set-AuthenticodeSignature (no Windows SDK needed). Inno Setup calls this for
# setup.exe and the uninstaller; publish.ps1 for the app's binaries.
#   powershell -ExecutionPolicy Bypass -File scripts\sign-file.ps1 -Thumbprint <sha1> -File <path> [-TimestampUrl <url>]
param(
    [Parameter(Mandatory)] [string]$Thumbprint,
    [Parameter(Mandatory)] [string]$File,
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)
$ErrorActionPreference = "Stop"
$cert = @(Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $Thumbprint -and $_.HasPrivateKey })
if ($cert.Count -eq 0) { throw "certificato $Thumbprint non trovato (con chiave privata) in CurrentUser\My o LocalMachine\My" }
# With a timestamp when the server answers (the signature outlives the certificate), without it otherwise.
$result = $null
if ($TimestampUrl) {
    try { $result = Set-AuthenticodeSignature -LiteralPath $File -Certificate $cert[0] -HashAlgorithm SHA256 -TimestampServer $TimestampUrl -ErrorAction Stop } catch { $result = $null }
}
if (-not $result -or $result.Status -eq "UnknownError" -and -not $result.SignerCertificate) {
    $result = Set-AuthenticodeSignature -LiteralPath $File -Certificate $cert[0] -HashAlgorithm SHA256
}
if ($result.Status -eq "HashMismatch" -or $result.Status -eq "NotSigned" -or -not $result.SignerCertificate) { throw "firma non riuscita: $File ($($result.Status) $($result.StatusMessage))" }
if ($result.SignerCertificate.Thumbprint -ne $Thumbprint) { throw "firma con il certificato sbagliato: $File" }
