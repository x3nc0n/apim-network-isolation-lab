#requires -Version 7.4
[CmdletBinding()]
param(
    [string] $FrontendHostname = 'api.lab.example',
    [Parameter(Mandatory)]
    [string] $PublisherEmail,
    [System.Security.SecureString] $PfxPassword,
    [string] $OutputDirectory = (Join-Path (Get-Location) '.lab-secrets')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([uri]::CheckHostName($FrontendHostname) -ne [System.UriHostNameType]::Dns -or
    $FrontendHostname -match '[\s:*,]' -or $FrontendHostname.EndsWith('.')) {
    throw 'FrontendHostname must be a plain DNS hostname.'
}
if (Test-Path -LiteralPath $OutputDirectory) {
    throw 'OutputDirectory already exists; choose a fresh directory to avoid overwriting secrets.'
}
if (-not $PfxPassword) {
    $PfxPassword = Read-Host 'New lab-only PFX password (not saved in shell history)' -AsSecureString
}
if ($PfxPassword.Length -lt 12) { throw 'Use a lab-only password of at least 12 characters.' }
$directory = New-Item -ItemType Directory -Path $OutputDirectory
if ($IsWindows) {
    $acl = Get-Acl -LiteralPath $directory.FullName
    $acl.SetAccessRuleProtection($true, $false)
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.SetAccessRule($rule)
    Set-Acl -LiteralPath $directory.FullName -AclObject $acl
} else {
    [System.IO.File]::SetUnixFileMode($directory.FullName,
        [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite -bor
        [System.IO.UnixFileMode]::UserExecute)
}
$leafKey = [System.Security.Cryptography.RSA]::Create(2048)
$leaf = $null
try {
    $hash = [System.Security.Cryptography.HashAlgorithmName]::SHA256
    $padding = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    $start = [datetimeoffset]::UtcNow.AddMinutes(-5)
    $end = $start.AddDays(7)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        "CN=$FrontendHostname", $leafKey, $hash, $padding)
    $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $san.AddDnsName($FrontendHostname)
    $request.CertificateExtensions.Add($san.Build())
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true))
    $usages = [System.Security.Cryptography.OidCollection]::new()
    $null = $usages.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($usages, $true))
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment, $true))
    $leaf = $request.CreateSelfSigned($start, $end)
    $plainPassword = ConvertFrom-SecureString $PfxPassword -AsPlainText
    $pfx = $leaf.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $plainPassword)
    $parameters = @{
        '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
        contentVersion = '1.0.0.0'
        parameters = @{
            frontendHostname = @{ value = $FrontendHostname }
            frontendPfxBase64 = @{ value = [Convert]::ToBase64String($pfx) }
            frontendPfxPassword = @{ value = $plainPassword }
            publisherEmail = @{ value = $PublisherEmail }
        }
    }
    $parameters | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (
        Join-Path $directory.FullName 'lab.secure.parameters.json') -Encoding utf8NoBOM
    $pem = "-----BEGIN CERTIFICATE-----`n" +
        [Convert]::ToBase64String($leaf.RawData, [Base64FormattingOptions]::InsertLineBreaks) +
        "`n-----END CERTIFICATE-----`n"
    Set-Content -LiteralPath (Join-Path $directory.FullName 'lab-root.pem') -Value $pem -Encoding ascii
    Write-Host "Created protected lab parameters and public lab-root.pem in $($directory.FullName)"
    Write-Warning 'Parameters contain a private key and plaintext PFX password. Never commit, upload to issues, or print them. Certificate expires in 7 days.'
} finally {
    $plainPassword = $null
    $pfx = $null
    if ($leaf) { $leaf.Dispose() }
    $leafKey.Dispose()
}
