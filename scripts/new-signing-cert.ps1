# Creates the code-signing certificate publish.ps1 signs with, in the current
# user's certificate store with a non-exportable private key, and prints its
# thumbprint. publish.ps1 finds it by friendly name, so this is needed once per
# build machine.
#
# A self-signed certificate gives Tramontana what matters for its own security:
# every binary is tamper-evident and the helper only serves an app signed with
# this very certificate (the thumbprint is compiled into trhelper.exe). What it
# does not give is SmartScreen reputation: for that, replace it with a
# certificate from a public CA or Azure Trusted Signing (same friendly name, or
# pass -SignThumbprint to publish.ps1).
#   powershell -ExecutionPolicy Bypass -File scripts\new-signing-cert.ps1 [-Subject "CN=..."] [-Years 5]
param(
    [string]$Subject = "CN=Tramontana Code Signing, O=Tramontana",
    [int]$Years = 5
)
$ErrorActionPreference = "Stop"
$friendly = "Tramontana Code Signing"
$existing = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.FriendlyName -eq $friendly -and $_.NotAfter -gt (Get-Date) }
if ($existing) {
    "Certificato già presente: $($existing[0].Thumbprint) (scade il $($existing[0].NotAfter.ToShortDateString()))"
    exit 0
}
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $Subject -FriendlyName $friendly `
    -CertStoreLocation Cert:\CurrentUser\My -KeyExportPolicy NonExportable -KeyAlgorithm RSA -KeyLength 3072 `
    -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears($Years)
"Certificato creato: $($cert.Thumbprint) (scade il $($cert.NotAfter.ToShortDateString()))"
