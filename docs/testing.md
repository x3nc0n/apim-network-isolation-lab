# Test procedure and interpretation

## Expected results, not exploit verdicts

| Path | Expected observation with healthy deployment | Interpretation |
| --- | --- | --- |
| Public Basic / opt-in Standard, default gateway hostname | `/lab/health` returns the positive marker over verified HTTPS | Public gateway reachability, not an exploit |
| Internal Developer direct from internet | No usable public gateway route; DNS/transport may fail | Private network design; a failed connection alone is not a validator PASS |
| Rewrite WAF frontend | Approved request succeeds; at least DNS-shaped unapproved Host requests can return the same positive marker | **FAIL** for incoming Host filtering despite WAF and correct backend TLS |
| Strict WAF frontend | Approved request succeeds; unapproved Host requests return 403 with `APIM-LAB-EDGE-DENIED` | Expected **PASS** for the supplied HTTP Host response contract, subject to runtime verification |
| Strict frontend, approved Host but different/absent SNI | Can still return positive marker | Host control is not SNI control; normally INFO, **FAIL** if `-RequireSniMatch` is requested |
| Opt-in external APIM, allowed source | Default gateway HTTPS returns positive marker | Source allowlist permits a legitimate path, not Host filtering |
| Opt-in external APIM, untrusted source | NSG can drop/timeout | **INCONCLUSIVE**, not PASS; verify effective NSG rules/traffic separately |
| Opt-in Premium internal | No direct internet data-plane route; not routed by either gateway | Separate SKU/network comparison, not another public frontend |

Managed OWASP rules can independently block some requests on **both** gateways (for example IP-shaped Host or protocol anomalies). Thus the rewrite case does not promise every negative row succeeds. A generic 403, 404, WAF product name, timeout or failed TLS handshake is not evidence that the hostname rule blocked the request. Identify the actual WAF rule in logs. The strict custom response body applies to **all blocks by that policy**, so the body identifies the policy, not uniquely the custom Host rule.

## Establish positive controls first

After an operator-authorized deployment, wait for provisioning to finish and inspect **each Application Gateway's Backend health**. Both must show a healthy private APIM backend. If unhealthy, check subnet NSGs, APIM operation/policy provisioning, private IP, backend Host, probe hostname/path, and backend TLS trust. A 502 is not isolation.

Use deployment outputs for `frontendIps`, `approvedFrontendHostname`, `publicBasicUrl` and `internalDeveloperHostname`. Do not guess IPs. The following placeholder addresses are reserved documentation addresses; replace them with **your own lab outputs**.

```powershell
$rewriteIp = '203.0.113.10'
$strictIp = '203.0.113.11'
$approved = 'api.lab.example'
$ca = '.\.lab-secrets\lab-root.pem'

curl --disable --noproxy '*' --cacert $ca --http1.1 `
  --resolve "${approved}:443:${strictIp}" "https://${approved}/lab/health"
# Expect APIM-NETWORK-LAB-OK. This sends approved SNI and approved Host without public DNS.
```

On Windows, use `curl.exe` if `curl` is an alias in your shell. The validator resolves the actual executable itself. Do not use `-k` for the positive control. A Schannel revocation/trust error, expired certificate or hostname mismatch is a client/TLS failure to fix, not a successful block; the helper's explicit self-signed trust anchor is exercised by local tests without changing global certificate trust.

## Run the unchanged validator

```powershell
.\scripts\Test-FrontendHostnameFilter.ps1 `
  -FrontendIp $rewriteIp -GatewayHostname $approved `
  -UnapprovedHostname 'unapproved.lab.example' `
  -Path '/lab/health' -ApprovedBodyPattern 'APIM-NETWORK-LAB-OK' `
  -RejectionStatusCode 403 -RejectionBodyPattern '^APIM-LAB-EDGE-DENIED$' `
  -CertificateAuthorityFile $ca -OutputPath '.\rewrite-result.json'
# Expected exit 1 / FAIL; inspect which rows actually returned the positive marker.

.\scripts\Test-FrontendHostnameFilter.ps1 `
  -FrontendIp $strictIp -GatewayHostname $approved `
  -UnapprovedHostname 'unapproved.lab.example' `
  -Path '/lab/health' -ApprovedBodyPattern 'APIM-NETWORK-LAB-OK' `
  -RejectionStatusCode 403 -RejectionBodyPattern '^APIM-LAB-EDGE-DENIED$' `
  -CertificateAuthorityFile $ca -OutputPath '.\strict-result.json'
# Expected exit 0 / PASS only if the positive and all required negative response contracts pass.
```

Do not overwrite existing result JSON files; choose fresh output names on repeat runs. Capture `$LASTEXITCODE` immediately after each invocation if automating. Never treat a nonzero exit as a generic "safe" result. The validator uses HTTP/1.1, no redirects/proxies/curl config, unique per-probe IDs, a generated `.invalid` hostname in addition to your supplied hostname, independent HTTP Host/SNI variation, IP/no-SNI cases, timeouts, and response hashes. Negative probes intentionally skip certificate verification so a client-side name/trust error cannot masquerade as edge enforcement.

`-RequireSniMatch` additionally requires rejection when only SNI is unapproved or absent. **This lab does not implement SNI matching**, so that stronger requirement is not expected to pass. HTTP Host WAF rules do not inspect TLS SNI. A basic/catch-all HTTPS listener is intentional on both independent gateways; the strict gateway has no alternative unprotected listener.

## Inspect direct APIM paths separately

For public Basic/Standard, request the output URL without the lab trust file: the APIM default hostname uses its provider-managed certificate. These APIMs are intentionally not behind the lab WAF. Do not expect a unique edge-denial marker from direct APIM, or equate APIM's unknown-Host 404 with network isolation. APIM may reject unrecognized Host while still offering its legitimate public default hostname.

For the optional external instance, run the positive control from the configured source CIDR and again from an authorized client outside it. A drop observed from one client cannot certify historical policy or all network routes. Proxy/NAT changes can invalidate the configured source-IP assumption.

Internal Developer/Premium NSGs allow TCP 443 only from the two gateway subnets, so an arbitrary VM in the VNet is **not** an allowed direct test client. No jump host, VPN, Bastion, private endpoint or peering is created. If you deliberately add a temporary private test client/rule, narrowly scope it, record the change, and remove it afterward; the rule changes the original boundary under test. Never expose 3443 to Internet to make a test pass.

## Verdict meanings and local contracts

**PASS / exit 0:** required observed responses matched a working positive control plus the configured rejection status and marker. It does not attest non-forwarding or vulnerability immunity.

**FAIL / exit 1:** at least one required application/rejection contract failed, such as a rewritten unapproved Host receiving the application marker. This is a failed filtering requirement, not proof of code execution or an unpatched provider vulnerability.

**INCONCLUSIVE / exit 2:** ambiguous denial, missing marker, timeout, reset, TLS/client error, or inability to validate negatives against the positive control. Failures are not silently converted to safety.

Offline tests cover 10 HTTPS modes/requirements: permissive rewriting, strict Host filtering, Host-only filtering with SNI required, empty-body/header-marked rejection, ambiguous 403, missing marker, dropped connections, generic 404, failed positive control, and positive-marker content in a denial. Template contracts check default/optional SKUs, secure parameter propagation, distinct frontend resources, WAF Prevention/Host rule/custom marker, private routing/TLS probes, management/data-plane NSG ordering, mock policy and header telemetry. Mutation checks demonstrate rejection of injected Basic SKU, an Allow-rule substitution, and deletion of the management deny. None simulates the Azure control plane or proves actual Azure enforcement.
