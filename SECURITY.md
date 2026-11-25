# Security scope

This is an intentionally internet-accessible, **synthetic-data-only** network-control lab, not a production reference deployment. Public Basic/Standard APIM and the permissive WAF frontend are deliberately reachable. Never connect them to customer APIs, private datasets, real secrets or production networks. Use only a disposable group/subscription boundary you control and test only your own authorized frontend IPs.

## What the lab explains

A public reverse proxy/WAF can make an internal API reachable even when direct internet-to-API routing is unavailable. Rewriting the backend HTTP Host/TLS name fixes routing; it does not reject the original incoming Host. Conversely, an explicitly enforced incoming Host rule can narrow which HTTP requests are forwarded, and private networking/source-IP rules constrain who can establish a path. These are different trust boundaries, not interchangeable controls.

Exposure also depends on every alternate path: the public APIM default hostname, other gateways/listeners, allowed source NATs, private routes, management endpoints and future configuration changes. A Key Vault secret reference improves secret handling but does **not** impose network isolation. Generic WAF presence, a 404, or failure of a client certificate check is not a proven network block.

## What it cannot prove

This lab contains **no working exploit**, does not reconstruct undisclosed provider implementation details, and cannot determine whether a provider-managed service was historically vulnerable. The response validator is not an RCE scanner, patch detector or attestation of historical immunity. Follow provider incident guidance and account-specific notifications; do not infer CVE identity or exploit prerequisites from network results.

The November 2026 APIM Classic incident identified as **MZK9-GH0** and the separate July issue **CVE-2026-35425** must not be conflated. No CVE is asserted here for MZK9-GH0. Public descriptions do not establish all technical exploitation prerequisites, so this repository makes **no claim that its strict/private patterns prevented that historical incident**, nor that a failed Host-filter contract proves exploitability.

[Public reporting on November 23](https://www.bleepingcomputer.com/news/security/microsoft-azure-flaw-exploited-to-steal-customers-api-credentials/), quoting Microsoft, describes the Classic incident as provider-mitigated on **November 19, 2026**. The article explicitly does not independently verify the alleged technical mechanism. [Secondary analysis](https://labs.cloudsecurityalliance.org/research/csa-research-note-azure-apim-classic-secret-theft-20261124-c/) distinguishes the November incident from July's CVE and notes the lack of a verified public root cause/CVE. These are public context, not sufficient specifications for reproducing the incident. For actual remediation, use Microsoft's [credential rotation guidance](https://techcommunity.microsoft.com/blog/integrationsonazureblog/rotating-credentials-in-azure-api-management/4575478) and your own service notifications.

Local tests exercise response interpretation and template configuration only. A successful build, a PASSED fixture, or a marker-bearing 403 is not proof of Azure runtime enforcement or of non-forwarding. Use the documented positive controls, effective network configuration and complete edge/APIM telemetry. HTTP/2, request smuggling, arbitrary malformed HTTP, all possible host normalization variants, and exhaustive alternate paths are outside the validator's scope.

## Handling lab materials

Secure-string parameters prevent ordinary template output disclosure, but generated parameter files contain the private certificate/password in plaintext. Keep them out of source control, logs, screenshots and issues. Result JSON contains no bodies but does contain hostnames, IPs, paths, errors and correlation metadata: review before sharing. Publish synthetic examples only. Do not include private incident notices, customer hostnames, subscription/tenant identifiers or credentials.

Delete the dedicated Azure resource group after testing and verify deletion. Report repository defects without attaching private keys or confidential incident material. For actual Azure service vulnerabilities, use the [Microsoft Security Response Center](https://www.microsoft.com/msrc).
