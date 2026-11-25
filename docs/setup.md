# Setup, deployment, cost and cleanup

## Before deploying

Use an Azure **public cloud** subscription and a new resource group containing only this lab. Choose a region supporting Classic Basic/Developer APIM and WAF_v2; opt-in Standard/Premium availability and APIM/gateway quotas vary. Subscription Azure Policy, provider registrations (`Microsoft.ApiManagement`, `Microsoft.Network`, `Microsoft.OperationalInsights`, `Microsoft.Insights`) and deployment permissions can prevent creation. Deployments can take an hour or more; do not assume a successful template build means a deployable subscription.

No Azure provisioning is part of the repository's automated checks. The commands below are **operator-run examples that create billable resources**. Review them and the template before running.

## Prepare a lab-only certificate

Use PowerShell 7.4+:

```powershell
.\scripts\New-LabCertificate.ps1 -PublisherEmail 'you@example.com'
```

The helper prompts securely for a new lab-only PFX password of at least 12 characters. It creates a **new**, current-user-protected `.lab-secrets` directory (Unix mode 700 or a Windows ACL restricted to the current identity) containing:

| File | Content |
| --- | --- |
| `lab.secure.parameters.json` | Base64 PFX with private key, plaintext PFX password, hostname and publisher email |
| `lab-root.pem` | Public self-signed server certificate, used as an explicit trust anchor with curl `--cacert`; despite the filename, no separate root CA is created |

The seven-day RSA certificate has a DNS SAN for `api.lab.example` and server-auth usage. It is not for production, is never installed into your operating system's trust store, and has no external revocation service. The helper does not print private keys/passwords or export a separate private-key file. Supply `-FrontendHostname` if you want another plain hostname. Public DNS ownership is unnecessary when using `--resolve`.

The parameter JSON is a **secret file**, not a safe artifact to attach to an issue. Keep it on your own machine, do not enable shell transcripts/debug logging while handling it, do not dump it to a terminal, and never commit it. The ignored directory and file extensions are guardrails, not a substitute for checking staged content. If keys are exposed, delete/recreate the lab certificate.

The helper refuses to overwrite an existing directory. To retain an existing lab, use a fresh `-OutputDirectory`; to rebuild it, first remove only the known old secret files/directory when no longer needed.

## Deploy using the button

Click **Deploy to Azure** in the README. The portal anonymously fetches the committed `azuredeploy.json` from public `main`; the JSON includes all nested templates, with no external module registry dependency.

Select your subscription and a **new** resource group, then choose its region. In the template deployment's parameter editor, load your local `lab.secure.parameters.json` or enter its values into the corresponding secure input fields. Retain the default optional switches unless you explicitly accept their added cost. Do not copy secret values into issue comments, command arguments, screenshots or shell output. Review **Review + create** before confirming.

`frontendPfxBase64` and `frontendPfxPassword` are secure strings at **both** top-level and nested frontend deployment boundaries. Never include secret values in template outputs. ARM/deployment credentials and the portal still need to handle these secrets; a secure-string declaration does not make a plaintext local parameter file safe to publish.

## Equivalent CLI deployment

After you explicitly choose to provision the lab:

```powershell
az login
# Select your intended subscription through your normal local account workflow.
az group create --name rg-apim-network-lab --location eastus

# These are Azure service-side operations, not the offline repository tests.
az deployment group validate --resource-group rg-apim-network-lab `
  --template-file .\azuredeploy.json --parameters '@.lab-secrets\lab.secure.parameters.json'
az deployment group what-if --resource-group rg-apim-network-lab `
  --template-file .\azuredeploy.json --parameters '@.lab-secrets\lab.secure.parameters.json'
az deployment group create --resource-group rg-apim-network-lab --name apim-network-lab `
  --template-file .\azuredeploy.json --parameters '@.lab-secrets\lab.secure.parameters.json'

az deployment group show --resource-group rg-apim-network-lab --name apim-network-lab `
  --query properties.outputs --output json
```

Use your platform's native path separators if adapting commands. No account IDs, tenant IDs, or subscription IDs need to be committed to use the lab. What-if is informative, not a runtime connectivity test.

## Parameters and opt-ins

| Parameter | Default / requirement |
| --- | --- |
| `location` | Resource group location; public cloud only |
| `namePrefix` | `apimlab`; use 3-15 lowercase alphanumeric characters, starting with a letter |
| `frontendHostname` | `api.lab.example`; must match certificate SAN |
| `publisherEmail` | Required; supply a contact address you control |
| `frontendPfxBase64`, `frontendPfxPassword` | Required secure strings; use helper or your own valid PFX |
| `deployStandard` | `false`; adds public Standard Classic APIM |
| `deployPremium` | `false`; adds internal Premium Classic APIM, significant extra cost |
| `deployExternalRestricted` | `false`; adds external VNet Developer APIM |
| `externalAllowedCidr` | `192.0.2.1/32`, a documentation-only address, **not your real client** |

For the optional source-IP scenario, change `externalAllowedCidr` to the actual IPv4 NAT egress CIDR of an authorized test client, ideally a `/32`. The template passes this string to an NSG; **it does not validate that the CIDR is suitably narrow**. `0.0.0.0/0`, overly broad networks, proxies or shared NAT invalidate an isolation claim. This is an operator-supplied trust boundary, not a guaranteed protection against malicious configuration. NSG evaluation uses packet source addresses, not `X-Forwarded-For`.

To opt in with CLI, append, for example:

```powershell
# Additional BILLABLE instances. Replace the documentation CIDR before use.
# --parameters deployStandard=true
# --parameters deployPremium=true
# --parameters deployExternalRestricted=true externalAllowedCidr='192.0.2.1/32'
```

Resource names use `<prefix>-<resource-group-derived-unique-part>-<scenario>`. Default scenario suffixes are `public-basic`, `private-developer`, `appgwnofilter`, and `appgwhostfilter`; optional APIM suffixes are `public-standard`, `private-premium`, and `public-iprestricted`. Scenario tags reinforce the distinction. The nofilter gateway still has managed WAF inspection; only its incoming-Host custom filter is absent.

Repeat deployment to the same group targets the same lab. Internal private IPs may change after network/service changes. Redeploy/update both gateway backends if that happens. Do not swap an APIM SKU without reviewing its networking capabilities. Changing an existing resource's name creates a new resource rather than renaming it; remove an old disposable lab deliberately instead of leaving duplicate billable instances.

## Costs and cleanup

Estimate with the [Azure pricing calculator](https://azure.microsoft.com/pricing/calculator/), [APIM pricing](https://azure.microsoft.com/pricing/details/api-management/) and [Application Gateway pricing](https://azure.microsoft.com/pricing/details/application-gateway/). No universal price is quoted because currency, region and agreements differ.

Default billable inventory: **one Basic APIM, one Developer APIM, two fixed-capacity-one WAF_v2 gateways, two Standard public IPs, plus Log Analytics ingestion/retention and data transfer**. WAF_v2 can be a large fraction of the cost even at idle. Each opt-in adds its own APIM instance; Premium is especially expensive. Developer is a non-production tier with no production SLA.

The workspace has a 1 GB/day ingestion cap and 30-day retention; that is **not a hard total spending cap**, nor does it limit gateway/APIM runtime costs. Reaching the log cap also makes no-forwarding evidence incomplete. Configure a subscription budget separately. The lab has no automatic expiry or unattended cleanup.

When finished, inspect the dedicated group's inventory and delete **that lab group only**:

```powershell
az resource list --resource-group rg-apim-network-lab --output table
az group delete --name rg-apim-network-lab
# Confirm the prompt only after verifying the group contains no unrelated resources.
az group exists --name rg-apim-network-lab
```

Keep the deletion confirmation prompt. Verify group deletion completes; do not assume requesting deletion immediately stops all charges. Remove the local secret file and public trust file when no longer needed. No certificate was installed globally by the helper.
