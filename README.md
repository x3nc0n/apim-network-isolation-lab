# APIM network isolation lab

A disposable Azure lab comparing **network reachability, backend Host rewriting, and incoming HTTP Host filtering** across API Management Classic SKUs. Every APIM exposes a harmless `GET /lab/health` operation returning `APIM-NETWORK-LAB-OK`; no exploit payloads or real backend data are used.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fx3nc0n%2Fapim-network-isolation-lab%2Fmain%2Fazuredeploy.json)

**Cost warning:** the default deployment creates **two APIM instances (Basic + Developer), two independent WAF_v2 Application Gateways with public IPs, and Log Analytics**. This is not a free-tier deployment. Standard, Premium (high cost), and a third Developer instance are separate opt-ins. Review [costs and cleanup](docs/setup.md#costs-and-cleanup) before deploying; provision only in a dedicated disposable resource group.

**Validation boundary:** local Bicep compilation, generated ARM parity, static/mutation contracts, and real localhost HTTPS validator scenarios can be checked without Azure credentials. **No live Azure deployment, ARM service-side validation, what-if, backend health, or runtime WAF behavior is certified by these tests.** Regional capacity, quotas, subscription policy, and runtime behavior require an explicitly authorized Azure deployment.

## Patterns

| Pattern | Default? | Intended inbound path |
| --- | --- | --- |
| Basic Classic, public | Yes | Internet directly to APIM default gateway hostname |
| Developer Classic, internal VNet | Yes | Private APIM IP; TCP 443 allowed only from the two gateway subnets |
| Rewrite frontend, WAF_v2 | Yes | Any incoming Host forwarded using the internal APIM's correct backend Host/TLS name, unless managed WAF rules intervene |
| Strict frontend, WAF_v2 | Yes | Global Prevention WAF blocks unapproved incoming Host with a unique lab denial body |
| Standard Classic, public | `deployStandard=true` | Like Basic, with a different Classic SKU |
| Premium Classic, internal VNet | `deployPremium=true` | Separate private comparison instance; **not** a frontend backend |
| Developer Classic, external VNet | `deployExternalRestricted=true` | Public APIM TCP 443 allowed only from an operator-supplied source CIDR |

Basic/Standard Classic are **never** VNet-injected. Premium Classic is not Premium v2. Internal mode still requires APIM platform management connectivity; it does not mean every service/control-plane address is private.

## Start here

1. Follow [certificate preparation and deployment](docs/setup.md). Generate a seven-day lab-only self-signed certificate with `scripts/New-LabCertificate.ps1`, then use the deploy button or the CLI instructions. Secure certificate parameters have no defaults and no secrets appear in template outputs.
2. Follow [DNS-free testing and the expected-result matrix](docs/testing.md). Run the supplied validator per frontend IP using the same approved synthetic hostname and your local PEM trust file.
3. Use [architecture and telemetry](docs/architecture.md) to distinguish a response from evidence of forwarding, and read [security scope](SECURITY.md) before interpreting results.

## Local checks (no Azure login or deployment)

Requires PowerShell **7.4+** for the certificate/test helpers, Node.js **24+**, curl, Azure CLI, and Bicep **0.49.2**. The unchanged standalone validator itself requires PowerShell 7.2+.

```powershell
az bicep install --version v0.49.2
pwsh -NoProfile -File .\scripts\Test-Lab.ps1
```

The checks compile/lint `main.bicep`, compare its full JSON output to committed `azuredeploy.json`, check deployment/SKU/WAF/NSG/telemetry contracts, mutation-test critical gates, and exercise the real validator against a localhost HTTPS fixture using the **helper-generated PFX/PEM**. CI runs the same command without Azure credentials or live resources.

`scripts/Test-FrontendHostnameFilter.ps1` is reused byte-for-byte from [APIM-Analyzer commit a9acbeb](https://github.com/x3nc0n/APIM-Analyzer/commit/a9acbeb81b31385877e3b5b605ed6d138e71ed7d), SHA256 `d4f499d59ca5dd68c37cee382aff9e3440ee86758c7e4d996f33ba920b8109f1`. It reports JSON and exits **0 PASS / 1 FAIL / 2 INCONCLUSIVE**. PASS is a response-contract result, **not vulnerability immunity or a historical isolation attestation**.
