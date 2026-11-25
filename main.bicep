targetScope = 'resourceGroup'

@description('Azure public cloud region supporting Classic APIM and WAF_v2. Check regional availability and quotas first.')
param location string = resourceGroup().location

@minLength(3)
@maxLength(15)
@description('Lowercase alphanumeric resource prefix, starting with a letter.')
param namePrefix string = 'apimlab'

@description('Synthetic approved frontend hostname. No public DNS registration is needed with curl --resolve.')
param frontendHostname string = 'api.lab.example'

@secure()
@description('Base64-encoded PFX with private key for frontendHostname. See scripts/New-LabCertificate.ps1.')
param frontendPfxBase64 string

@secure()
@description('Password protecting the frontend PFX.')
param frontendPfxPassword string

@description('APIM publisher contact. Supply an address you control when deploying.')
param publisherEmail string

@description('Adds a public Standard Classic APIM. Additional hourly cost.')
param deployStandard bool = false

@description('Adds an internal Premium Classic APIM. HIGH COST; check quotas and pricing before enabling.')
param deployPremium bool = false

@description('Adds an external VNet-injected Developer APIM restricted on TCP 443 to externalAllowedCidr.')
param deployExternalRestricted bool = false

@description('IPv4 source CIDR for optional external APIM. Default is documentation-only, not a usable client. Never use 0.0.0.0/0.')
param externalAllowedCidr string = '192.0.2.1/32'

var stem = '${namePrefix}-${uniqueString(resourceGroup().id)}'
var tags = {
  purpose: 'disposable-network-control-lab'
  data: 'synthetic-only'
}

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${stem}-logs'
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
    workspaceCapping: { dailyQuotaGb: 1 }
  }
}

module network 'modules/network.bicep' = {
  name: 'network'
  params: {
    stem: stem
    location: location
    tags: tags
    externalAllowedCidr: externalAllowedCidr
  }
}

module publicBasic 'modules/apim.bicep' = {
  name: 'public-basic'
  params: {
    name: '${stem}-basic'
    location: location
    tags: tags
    sku: 'Basic'
    publisherEmail: publisherEmail
    workspaceId: workspace.id
  }
}

module internalDeveloper 'modules/apim.bicep' = {
  name: 'internal-developer'
  params: {
    name: '${stem}-internal'
    location: location
    tags: tags
    sku: 'Developer'
    networkMode: 'Internal'
    subnetId: network.outputs.internalSubnetId
    publisherEmail: publisherEmail
    workspaceId: workspace.id
  }
}

module publicStandard 'modules/apim.bicep' = if (deployStandard) {
  name: 'public-standard'
  params: {
    name: '${stem}-standard'
    location: location
    tags: tags
    sku: 'Standard'
    publisherEmail: publisherEmail
    workspaceId: workspace.id
  }
}

module internalPremium 'modules/apim.bicep' = if (deployPremium) {
  name: 'internal-premium'
  params: {
    name: '${stem}-premium'
    location: location
    tags: tags
    sku: 'Premium'
    networkMode: 'Internal'
    subnetId: network.outputs.premiumSubnetId
    publisherEmail: publisherEmail
    workspaceId: workspace.id
  }
}

module externalRestricted 'modules/apim.bicep' = if (deployExternalRestricted) {
  name: 'external-restricted'
  params: {
    name: '${stem}-external'
    location: location
    tags: tags
    sku: 'Developer'
    networkMode: 'External'
    subnetId: network.outputs.externalSubnetId
    publisherEmail: publisherEmail
    workspaceId: workspace.id
  }
}

module frontends 'modules/frontend.bicep' = [for (mode, index) in ['rewrite', 'strict']: {
  name: 'frontend-${mode}'
  params: {
    name: '${stem}-${mode}'
    location: location
    tags: tags
    strictHostFiltering: mode == 'strict'
    frontendHostname: frontendHostname
    frontendPfxBase64: frontendPfxBase64
    frontendPfxPassword: frontendPfxPassword
    subnetId: network.outputs.gatewaySubnetIds[index]
    backendIp: internalDeveloper.outputs.privateIp
    backendHostname: internalDeveloper.outputs.gatewayHostname
    workspaceId: workspace.id
  }
}]

output publicBasicUrl string = 'https://${publicBasic.outputs.gatewayHostname}/lab/health'
output internalDeveloperHostname string = internalDeveloper.outputs.gatewayHostname
output internalDeveloperPrivateIp string = internalDeveloper.outputs.privateIp
output publicStandardUrl string = deployStandard ? 'https://${publicStandard!.outputs.gatewayHostname}/lab/health' : 'not deployed'
output internalPremiumHostname string = deployPremium ? internalPremium!.outputs.gatewayHostname : 'not deployed'
output externalRestrictedUrl string = deployExternalRestricted ? 'https://${externalRestricted!.outputs.gatewayHostname}/lab/health' : 'not deployed'
output frontendIps array = [for index in range(0, 2): {
  mode: index == 0 ? 'rewrite' : 'strict'
  ip: frontends[index].outputs.publicIp
}]
output approvedFrontendHostname string = frontendHostname
output workspaceName string = workspace.name
output positiveMarker string = 'APIM-NETWORK-LAB-OK'
output strictDenialMarker string = 'APIM-LAB-EDGE-DENIED'
