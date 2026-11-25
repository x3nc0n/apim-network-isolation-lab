#requires -Version 7.2
<#
.SYNOPSIS
Tests HTTPS frontend hostname filtering using independent HTTP Host and TLS SNI values.
.DESCRIPTION
Run only against frontends you are authorized to test. Requires curl.exe (or curl).
No redirects are followed, proxies and curl configuration files are bypassed, and
HTTP/1.1 is forced so Host and SNI can be varied independently.

PASS means the observed responses match the supplied response contract, not that
the frontend's configuration, historical isolation, or exploit resistance is certified.
Confirm negative requests were not forwarded using complete edge/backend telemetry.
Use a unique, verified edge-denial response marker, not a generic Server header.

Timeouts, connection failures, and TLS failures are INCONCLUSIVE, never PASS.
Negative probes ignore certificate verification to avoid mistaking a client-side
certificate error for hostname enforcement. The approved control verifies TLS.

Exit codes: 0 = PASS; 1 = FAIL; 2 = INCONCLUSIVE. Invalid input/runtime errors
terminate with an error. JSON contains metadata and hashes, not response bodies.

This tests one IP/approved-hostname pair. Repeat for every frontend and approved
hostname. It does not test direct-backend bypasses or protocols other than HTTP/1.1.
.EXAMPLE
.\Test-FrontendHostnameFilter.ps1 `
    -FrontendIp '203.0.113.10' `
    -GatewayHostname 'api.example.com' `
    -UnapprovedHostname 'instance.management.azure-api.net' `
    -Path '/health' `
    -ApprovedBodyPattern '"service"\s*:\s*"orders-api"' `
    -RejectionStatusCode 403 `
    -RejectionBodyPattern 'EDGE-HOSTNAME-DENIED' `
    -OutputPath '.\frontend-result.json'

The denial marker above is an example, not a built-in Application Gateway response.
Omit rejection patterns for discovery; ambiguous denial responses cannot earn PASS.
.EXAMPLE
.\Test-FrontendHostnameFilter.ps1 `
    -FrontendIp '203.0.113.10' `
    -GatewayHostname 'api.example.com' `
    -UnapprovedHostname 'instance.management.azure-api.net' `
    -Path '/health' -ApprovedBodyPattern 'orders-api-healthy' `
    -RejectionHeaderPattern '(?im)^X-Edge-Denial:\s*hostname\s*$' `
    -RequireSniMatch

RequireSniMatch additionally requires rejection when only SNI is unapproved or
absent. Without it, those cases are informational, not pass/fail requirements.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [System.Net.IPAddress] $FrontendIp,

    [Parameter(Mandatory)]
    [string] $GatewayHostname,

    [string[]] $UnapprovedHostname = @(),

    [Parameter(Mandatory)]
    [ValidatePattern('^/[^#\r\n]*$')]
    [string] $Path,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $ApprovedBodyPattern,

    [ValidateNotNullOrEmpty()]
    [ValidateRange(100, 599)]
    [int[]] $ApprovedStatusCode = @(200),

    [ValidateNotNullOrEmpty()]
    [ValidateRange(400, 599)]
    [int[]] $RejectionStatusCode = @(403, 421),

    [string] $RejectionBodyPattern,
    [string] $RejectionHeaderPattern,
    [switch] $RequireSniMatch,

    [ValidateRange(1, 65535)]
    [int] $Port = 443,

    [ValidateRange(1, 300)]
    [int] $ConnectTimeoutSeconds = 10,

    [ValidateRange(1, 600)]
    [int] $TimeoutSeconds = 30,

    [string] $CertificateAuthorityFile,

    [string] $OutputPath = (
        Join-Path (Get-Location) (
            'FrontendHostnameValidation-{0}-{1}.json' -f
            (Get-Date -Format 'yyyyMMdd-HHmmss'), ([guid]::NewGuid().ToString('N').Substring(0, 8))
        )
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

foreach ($hostname in @($GatewayHostname) + $UnapprovedHostname) {
    if ([uri]::CheckHostName($hostname) -ne [System.UriHostNameType]::Dns -or
        $hostname -match '[\s:*]' -or $hostname.EndsWith('.')) {
        throw "Specify a plain DNS hostname without port, wildcard, or trailing dot: '$hostname'."
    }
}
$GatewayHostname = $GatewayHostname.ToLowerInvariant()
$invalidHostname = 'probe-{0}.invalid' -f [guid]::NewGuid().ToString('N')
$otherHostnames = @(@($UnapprovedHostname) + $invalidHostname |
    ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
if ($otherHostnames -contains $GatewayHostname) {
    throw 'The approved gateway hostname cannot also be an unapproved hostname.'
}
if ($CertificateAuthorityFile) {
    $CertificateAuthorityFile = (Resolve-Path -LiteralPath $CertificateAuthorityFile).ProviderPath
}
$OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
if (Test-Path -LiteralPath $OutputPath) {
    throw "Output already exists; choose a new OutputPath: $OutputPath"
}
if (-not (Test-Path -LiteralPath (Split-Path -Parent $OutputPath) -PathType Container)) {
    throw 'The output directory must already exist.'
}

$regexTimeout = [timespan]::FromSeconds(2)
$approvedRegex = [regex]::new($ApprovedBodyPattern, 'None', $regexTimeout)
$denialBodyRegex = if ($RejectionBodyPattern) {
    [regex]::new($RejectionBodyPattern, 'None', $regexTimeout)
}
$denialHeaderRegex = if ($RejectionHeaderPattern) {
    [regex]::new($RejectionHeaderPattern, 'None', $regexTimeout)
}
$hasDenialMarker = [bool]($denialBodyRegex -or $denialHeaderRegex)
$curlCommand = Get-Command curl.exe -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
if (-not $curlCommand) {
    $curlCommand = Get-Command curl -CommandType Application -ErrorAction Stop |
        Select-Object -First 1
}
$curlPath = $curlCommand.Source
$ipText = $FrontendIp.ToString()
$address = if ($FrontendIp.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
    "[$ipText]"
} else {
    $ipText
}
$ipAuthority = if ($Port -eq 443) { $address } else { "${address}:$Port" }
$runId = [guid]::NewGuid().ToString('N')
$tempDirectory = Join-Path ([System.IO.Path]::GetTempPath()) "frontend-validation-$runId"
$null = New-Item -ItemType Directory -Path $tempDirectory
$results = [System.Collections.Generic.List[object]]::new()

function Invoke-Probe {
    param(
        [string] $Name,
        [string] $SniHostname,
        [string] $HttpHost,
        [bool] $Required,
        [bool] $Positive = $false
    )

    $requestId = [guid]::NewGuid().ToString('N')
    $started = [datetime]::UtcNow
    $bodyFile = Join-Path $tempDirectory "$requestId.body"
    $headerFile = Join-Path $tempDirectory "$requestId.headers"
    $errorFile = Join-Path $tempDirectory "$requestId.stderr"
    $urlAuthority = if ($SniHostname) { "${SniHostname}:$Port" } else { $ipAuthority }
    $arguments = @(
        '--silent', '--show-error',
        '--http1.1', '--proto', '=https', '--retry', '0',
        '--connect-timeout', "$ConnectTimeoutSeconds", '--max-time', "$TimeoutSeconds",
        '--max-filesize', '1048576', '--output', $bodyFile, '--dump-header', $headerFile,
        '--write-out', '%{http_code}', '--header', "Host: $HttpHost",
        '--header', "X-Frontend-Validation-Id: $requestId"
    )
    if ($SniHostname) {
        $arguments += @('--resolve', "${SniHostname}:${Port}:$address")
    }
    if ($Positive) {
        if ($CertificateAuthorityFile) {
            $arguments += @('--cacert', $CertificateAuthorityFile)
        }
    } else {
        $arguments += '--insecure'
    }
    $arguments += @('--url', "https://${urlAuthority}${Path}")
    # Unix PowerShell expands wildcard arguments in splatted arrays; keep this literal quoted.
    $statusText = & $curlPath --disable --noproxy '*' @arguments 2> $errorFile
    $curlExitCode = $LASTEXITCODE
    $status = 0
    $null = [int]::TryParse(($statusText -join '').Trim(), [ref] $status)
    [byte[]] $bodyBytes = [byte[]]::new(0)
    if (Test-Path -LiteralPath $bodyFile) {
        $bodyBytes = [System.IO.File]::ReadAllBytes($bodyFile)
    }
    $body = [System.Text.Encoding]::UTF8.GetString([byte[]] $bodyBytes)
    $headers = if (Test-Path -LiteralPath $headerFile) {
        [System.IO.File]::ReadAllText($headerFile)
    } else { '' }
    $errorText = if (Test-Path -LiteralPath $errorFile) {
        [System.IO.File]::ReadAllText($errorFile).Trim()
    } else { '' }
    $approvedMatch = $approvedRegex.IsMatch($body)
    $denialMatch = $hasDenialMarker -and
        (-not $denialBodyRegex -or $denialBodyRegex.IsMatch($body)) -and
        (-not $denialHeaderRegex -or $denialHeaderRegex.IsMatch($headers))

    $verdict = 'INCONCLUSIVE'
    $reason = ''
    if ($curlExitCode -ne 0 -or $status -eq 0) {
        $reason = "Transport/client failure (curl $curlExitCode); not proven to be an edge rejection."
    } elseif ($Positive) {
        if ($status -in $ApprovedStatusCode -and $approvedMatch) {
            $verdict = 'PASS'
            $reason = 'Approved-host control matched the configured status and application marker.'
        } else {
            $verdict = 'FAIL'
            $reason = 'Approved-host control did not match the configured status and application marker.'
        }
    } elseif (-not $Required) {
        $verdict = 'INFO'
        $reason = 'SNI-only mismatch/no-SNI observation; not required unless RequireSniMatch is set.'
    } elseif ($approvedMatch) {
        $verdict = 'FAIL'
        $reason = 'Unapproved request returned the approved application marker.'
    } elseif ($status -notin $RejectionStatusCode) {
        $verdict = 'FAIL'
        $reason = 'Response did not have a configured rejection status; blocking was not demonstrated.'
    } elseif (-not $denialMatch) {
        $reason = 'Rejection status without the configured edge-denial marker; origin is unverified.'
    } elseif ($results[0].Verdict -ne 'PASS') {
        $reason = 'Cannot validate a negative result without a passing approved-host control.'
    } else {
        $verdict = 'PASS'
        $reason = 'Response matched the configured rejection status and edge-denial marker.'
    }
    [pscustomobject][ordered]@{
        Name = $Name
        Required = $Required
        RequestId = $requestId
        StartedUtc = $started.ToString('o')
        CompletedUtc = [datetime]::UtcNow.ToString('o')
        Sni = if ($SniHostname) { $SniHostname } else { '(none; IP URL)' }
        HttpHost = $HttpHost
        CertificateVerification = $Positive
        HttpStatus = $status
        CurlExitCode = $curlExitCode
        BodyBytes = ([byte[]] $bodyBytes).Length
        BodySha256 = [Convert]::ToHexString(
            [System.Security.Cryptography.SHA256]::HashData([byte[]] $bodyBytes)
        ).ToLowerInvariant()
        ApprovedMarkerMatched = $approvedMatch
        EdgeDenialMarkerMatched = [bool] $denialMatch
        Verdict = $verdict
        Reason = $reason
        CurlError = $errorText
    }
}

try {
    $results.Add((Invoke-Probe -Name 'Approved control' -SniHostname $GatewayHostname `
        -HttpHost $GatewayHostname -Required $true -Positive $true))
    foreach ($otherHostname in $otherHostnames) {
        $results.Add((Invoke-Probe -Name 'Unapproved Host; approved SNI' `
            -SniHostname $GatewayHostname -HttpHost $otherHostname -Required $true))
        $results.Add((Invoke-Probe -Name 'Unapproved Host and SNI' `
            -SniHostname $otherHostname -HttpHost $otherHostname -Required $true))
        $results.Add((Invoke-Probe -Name 'Approved Host; unapproved SNI' `
            -SniHostname $otherHostname -HttpHost $GatewayHostname -Required ([bool] $RequireSniMatch)))
    }
    $results.Add((Invoke-Probe -Name 'IP Host; approved SNI' `
        -SniHostname $GatewayHostname -HttpHost $ipAuthority -Required $true))
    $results.Add((Invoke-Probe -Name 'IP Host; no DNS SNI' `
        -SniHostname '' -HttpHost $ipAuthority -Required $true))
    $results.Add((Invoke-Probe -Name 'Approved Host; no DNS SNI' `
        -SniHostname '' -HttpHost $GatewayHostname -Required ([bool] $RequireSniMatch)))

    $requiredResults = @($results | Where-Object Required)
    $overall = if ($requiredResults.Verdict -contains 'FAIL') { 'FAIL' }
        elseif ($requiredResults.Verdict -contains 'INCONCLUSIVE') { 'INCONCLUSIVE' }
        else { 'PASS' }
    $report = [ordered]@{
        RunId = $runId
        GeneratedUtc = [datetime]::UtcNow.ToString('o')
        FrontendIp = $ipText
        Port = $Port
        GatewayHostname = $GatewayHostname
        Path = $Path
        RequireSniMatch = [bool] $RequireSniMatch
        ApprovedStatusCode = $ApprovedStatusCode
        ApprovedBodyPattern = $ApprovedBodyPattern
        RejectionStatusCode = $RejectionStatusCode
        RejectionBodyPattern = $RejectionBodyPattern
        RejectionHeaderPattern = $RejectionHeaderPattern
        Overall = $overall
        Scope = 'Observed HTTP/1.1 response contract only; verify no forwarding with edge/backend telemetry.'
        Results = @($results.ToArray())
    }
    $report | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $OutputPath -Encoding utf8 -NoClobber
    $results | Format-Table Name, Sni, HttpHost, HttpStatus, Verdict -AutoSize | Out-Host
    Write-Host "`nOverall: $overall"
    Write-Host "JSON: $OutputPath"
    Write-Host 'PASS is not a historical-isolation or vulnerability certification. Verify telemetry.'
    if (-not $hasDenialMarker) {
        Write-Warning 'No edge-denial marker supplied. Rejection status codes alone cannot earn PASS.'
    }
    $exitCode = switch ($overall) { 'PASS' { 0 } 'FAIL' { 1 } default { 2 } }
} finally {
    Get-ChildItem -LiteralPath $tempDirectory -File | Remove-Item -Force
    Remove-Item -LiteralPath $tempDirectory -Force
}
exit $exitCode
