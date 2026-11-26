# APIM network isolation lab

A disposable Azure lab comparing **network reachability, backend Host rewriting, and incoming HTTP Host filtering** across API Management Classic SKUs. Every APIM exposes a harmless `GET /lab/health` operation returning `APIM-NETWORK-LAB-OK`; no exploit payloads or real backend data are used.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fx3nc0n%2Fapim-network-isolation-lab%2Fmain%2Fazuredeploy.json)

**Cost warning:** the default deployment creates **two APIM instances (Basic + Developer), two independent WAF_v2 Application Gateways with public IPs, and Log Analytics**. This is not a free-tier deployment. Standard, Premium (high cost), and a third Developer instance are separate opt-ins. Review [costs and cleanup](docs/setup.md#costs-and-cleanup) before deploying; provision only in a dedicated disposable resource group.

**Validation boundary:** local Bicep compilation, generated ARM parity, static/mutation contracts, and real localhost HTTPS validator scenarios can be checked without Azure credentials. **No live Azure deployment, ARM service-side validation, what-if, backend health, or runtime WAF behavior is certified by these tests.** Regional capacity, quotas, subscription policy, and runtime behavior require an explicitly authorized Azure deployment.

The default topology was also tested in an operator-authorized Azure deployment: see [recorded live validation](docs/testing.md#recorded-live-validation). Optional variants were not deployed.

## Patterns

| Pattern | Default? | Intended inbound path |
| --- | --- | --- |
| Basic Classic, public | Yes | Internet directly to APIM default gateway hostname |
| Developer Classic, internal VNet | Yes | Private APIM IP; client TCP 443 allowed only from the two gateway subnets, plus platform probes |
| Rewrite frontend, WAF_v2 | Yes | Any incoming Host forwarded using the internal APIM's correct backend Host/TLS name, unless managed WAF rules intervene |
| Strict frontend, WAF_v2 | Yes | Global Prevention WAF blocks unapproved incoming Host with a unique lab denial body |
| Standard Classic, public | `deployStandard=true` | Like Basic, with a different Classic SKU |
| Premium Classic, internal VNet | `deployPremium=true` | Separate private comparison instance; **not** a frontend backend |
| Developer Classic, external VNet | `deployExternalRestricted=true` | Public APIM TCP 443 allowed only from an operator-supplied source CIDR |

Basic/Standard Classic are **never** VNet-injected. Premium Classic is not Premium v2. Internal mode still requires APIM platform management connectivity; it does not mean every service/control-plane address is private.

Resource names end in scenario hints: `public-basic`, `private-developer`, `appgwnofilter`, and `appgwhostfilter`; opt-ins use `public-standard`, `private-premium`, and `public-iprestricted`. The prefix and unique suffix keep names globally distinct, and `scenario` tags describe each path. **`appgwnofilter` means no incoming-Host custom filter**, not disabled managed WAF inspection.

## Start here

1. Try the [deployed public lab](#try-the-deployed-public-lab) without an Azure account, or follow [certificate preparation and deployment](docs/setup.md) to create your own billable lab. Generate a seven-day lab-only self-signed certificate with `scripts/New-LabCertificate.ps1`, then use the deploy button or the CLI instructions. Secure certificate parameters have no defaults and no secrets appear in template outputs.
2. Follow [DNS-free testing and the expected-result matrix](docs/testing.md). Run the supplied validator per frontend IP using the same approved synthetic hostname and your local PEM trust file.
3. Use [architecture and telemetry](docs/architecture.md) to distinguish a response from evidence of forwarding, and read [security scope](SECURITY.md) before interpreting results.

## Try the deployed public lab

These endpoints are intentionally published for the harmless `GET /lab/health` checks below and were checked live on **2026-11-26 UTC**. They require no Azure login or API subscription key. Do not send exploit payloads, scan other paths, or load-test this shared lab. It is disposable: addresses, certificate and availability may change.

| Deployed scenario | Public endpoint / frontend IP | What it demonstrates |
| --- | --- | --- |
| `public-basic` | [Direct APIM health endpoint](https://apimlab-ozpteryhevtbi-public-basic.azure-api.net/lab/health) | Public APIM returns HTTP 200 and `APIM-NETWORK-LAB-OK`, without the lab WAF |
| `appgwnofilter` | `20.119.175.69`, HTTPS port 443 | Approved and unapproved incoming Host can reach the same private APIM because backend Host is rewritten |
| `appgwhostfilter` | `52.242.120.181`, HTTPS port 443 | Approved Host reaches APIM; unapproved Host is blocked with HTTP 403 and `APIM-LAB-EDGE-DENIED` |

Both gateway frontends use **`api.lab.example`**, a synthetic hostname with no public DNS record. Select the IP with `--resolve`; opening a bare gateway IP in a browser causes a certificate-name/trust error, not an isolation verdict. The internal Developer APIM has no direct public gateway URL; both gateways forward to its private IP.

The gateway certificate is self-signed. [The published PEM](certificates/public-lab-leaf.pem) contains **only the public certificate**, not its private key or password. Trust it only for these commands with `--cacert`; do not install it globally or use it for your own deployment. It expires **2026-12-02 at 21:53:42 UTC**. After expiry or rotation, fix the certificate/endpoint configuration rather than disabling positive-control TLS verification.

Install PowerShell **7.2+**, git and curl, then clone the repository:

```powershell
git clone https://github.com/x3nc0n/apim-network-isolation-lab.git
Set-Location .\apim-network-isolation-lab
```

Run these exact checks from the repository root:

```powershell
# Public lab quick check
$curl = if ($IsWindows) { 'curl.exe' } else { 'curl' }
$approved = 'api.lab.example'
$ca = '.\certificates\public-lab-leaf.pem'
$targets = @(
    @{ Name = 'appgwnofilter'; Ip = '20.119.175.69' }
    @{ Name = 'appgwhostfilter'; Ip = '52.242.120.181' }
)

& $curl --disable --noproxy '*' --silent --show-error --max-time 30 `
    --write-out '\nHTTP %{http_code}\n' `
    'https://apimlab-ozpteryhevtbi-public-basic.azure-api.net/lab/health'
# APIM-NETWORK-LAB-OK / HTTP 200; provider-managed certificate verified.

foreach ($target in $targets) {
    Write-Host "$($target.Name): approved Host"
    & $curl --disable --noproxy '*' --silent --show-error --max-time 30 `
        --cacert $ca --http1.1 --resolve "${approved}:443:$($target.Ip)" `
        --write-out '\nHTTP %{http_code}\n' "https://${approved}/lab/health"
    Write-Host "$($target.Name): unapproved Host, same approved TLS SNI"
    & $curl --disable --noproxy '*' --silent --show-error --max-time 30 `
        --cacert $ca --http1.1 --resolve "${approved}:443:$($target.Ip)" `
        --header 'Host: unapproved.lab.example' `
        --write-out '\nHTTP %{http_code}\n' "https://${approved}/lab/health"
}
```

| Request | `appgwnofilter` | `appgwhostfilter` |
| --- | --- | --- |
| Approved Host | HTTP 200 / `APIM-NETWORK-LAB-OK` | HTTP 200 / `APIM-NETWORK-LAB-OK` |
| DNS-shaped unapproved Host, approved TLS SNI | HTTP 200 / `APIM-NETWORK-LAB-OK` | HTTP 403 / `APIM-LAB-EDGE-DENIED` |
| Full validator's required negative probes | Expected **FAIL / exit 1**: unapproved Hosts reach the mock API | Expected **PASS / exit 0** for the Host response contract |

**Why the difference?** Both gateways have managed WAF inspection and the same correct backend Host/TLS settings. Only `appgwhostfilter` checks the **incoming** Host before rewriting it. Managed WAF rules can independently block some negative probes, so the no-filter path does not promise every possible request succeeds. Host filtering does not filter TLS SNI, and neither response proves exploitation or historical immunity.

Run the full script against each explicitly selected live frontend:

```powershell
# Validate the deployed lab
$PSNativeCommandUseErrorActionPreference = $false # Expected exit 1 is a filtering result.
$targets = @(
    @{ Name = 'appgwnofilter'; Ip = '20.119.175.69' }
    @{ Name = 'appgwhostfilter'; Ip = '52.242.120.181' }
)
foreach ($target in $targets) {
    $output = ".\FrontendHostnameValidation-live-$($target.Name)-$([guid]::NewGuid().ToString('N')).json"
    pwsh -NoProfile -File .\scripts\Test-FrontendHostnameFilter.ps1 `
        -FrontendIp $target.Ip -GatewayHostname 'api.lab.example' `
        -UnapprovedHostname 'unapproved.lab.example' -Path '/lab/health' `
        -ApprovedBodyPattern '^APIM-NETWORK-LAB-OK$' `
        -RejectionStatusCode 403 -RejectionBodyPattern '^APIM-LAB-EDGE-DENIED$' `
        -CertificateAuthorityFile '.\certificates\public-lab-leaf.pem' -OutputPath $output
    $resultCode = $LASTEXITCODE
    Write-Host "$($target.Name): exit $resultCode; report $output"
}
```

In the recorded live run, all six required rewrite negatives arrived at APIM; all six strict negatives matched custom Host blocks with no corresponding APIM arrival. Positive controls were correlated across gateway and APIM logs. See [the verified results and limits](docs/testing.md#recorded-live-validation).

## Test your own setup

Use **`scripts/Test-FrontendHostnameFilter.ps1`** against endpoints you own or have permission to test. It has **no default target**: `-FrontendIp`, `-GatewayHostname`, `-Path`, and `-ApprovedBodyPattern` are mandatory. An omitted target prompts in an interactive shell and fails in a noninteractive run; it never falls back to this public lab. Supply an IP address, a plain approved DNS hostname (no `https://`, port or path), and an actual harmless HTTPS operation that returns a known positive marker.

The following addresses and markers are **placeholders**, not endpoints to scan. Replace all of them with your own configuration:

```powershell
pwsh -NoProfile -File .\scripts\Test-FrontendHostnameFilter.ps1 `
    -FrontendIp '203.0.113.10' -GatewayHostname 'api.example.com' `
    -UnapprovedHostname 'unapproved.example.com' -Path '/health' `
    -ApprovedBodyPattern '^MY-APPLICATION-HEALTHY$' `
    -RejectionStatusCode 403 -RejectionBodyPattern '^MY-VERIFIED-EDGE-DENIAL$'
```

Use `-Port` for a non-default HTTPS port. For a private/self-signed CA, add `-CertificateAuthorityFile` pointing to **your own public trust certificate**; omit it for a publicly trusted certificate. Configure and verify the real edge-denial body/header first; `-RejectionHeaderPattern` can instead match a unique denial header. Generic 403/404 responses, resets and timeouts are not proof of isolation. Without a verified denial marker, ambiguous negatives are **INCONCLUSIVE / exit 2**, not PASS.

Repeat the command for **every frontend IP and approved hostname**, including alternate listeners/routes, and test authorized direct-backend paths separately. Do not infer that one passing frontend protects another. Add `-RequireSniMatch` only if your own edge intentionally enforces SNI; this lab is Host-only and is not expected to pass that stronger requirement. Keep the JSON reports private (default report names are git-ignored), and use [edge/APIM telemetry](docs/architecture.md#telemetry-and-correlation) to distinguish rejection from forwarding.

## Local checks (no Azure login or deployment)

Requires PowerShell **7.4+** for the certificate/test helpers, Node.js **24+**, curl, Azure CLI, and Bicep **0.49.2**. The standalone validator itself requires PowerShell 7.2+.

```powershell
az bicep install --version v0.49.2
pwsh -NoProfile -File .\scripts\Test-Lab.ps1
```

The checks compile/lint `main.bicep`, compare its full JSON output to committed `azuredeploy.json`, check deployment/SKU/WAF/NSG/telemetry contracts, mutation-test critical gates, and exercise the real validator against a localhost HTTPS fixture using the **helper-generated PFX/PEM**. CI runs the same command without Azure credentials or live resources.

`scripts/Test-FrontendHostnameFilter.ps1` is adapted from [APIM-Analyzer commit a9acbeb](https://github.com/x3nc0n/APIM-Analyzer/commit/a9acbeb81b31385877e3b5b605ed6d138e71ed7d), original SHA256 `d4f499d59ca5dd68c37cee382aff9e3440ee86758c7e4d996f33ba920b8109f1`. The only functional change passes curl's `--noproxy '*'` as an explicitly quoted literal, fixing [Unix PowerShell wildcard expansion during array splatting](https://github.com/PowerShell/PowerShell/issues/24178); verdict semantics are retained. The lab copy's SHA256 is `256fe76fbce945e34201cfed852b6055a06b7b9a0a6f09ab387a4b3450b8d25c`. APIM-Analyzer is not modified.

The validator reports JSON and exits **0 PASS / 1 FAIL / 2 INCONCLUSIVE**. PASS is a response-contract result, **not vulnerability immunity or a historical isolation attestation**.
