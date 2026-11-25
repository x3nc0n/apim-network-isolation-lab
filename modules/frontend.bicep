param name string
param location string
param tags object
param strictHostFiltering bool
param frontendHostname string
@secure()
param frontendPfxBase64 string
@secure()
param frontendPfxPassword string
param subnetId string
param backendIp string
param backendHostname string
param workspaceId string

resource publicIp 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: '${name}-pip'
  location: location
  tags: tags
  sku: { name: 'Standard' }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource waf 'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies@2024-05-01' = {
  name: '${name}-waf'
  location: location
  tags: tags
  properties: {
    policySettings: {
      state: 'Enabled'
      mode: 'Prevention'
      requestBodyCheck: true
      customBlockResponseStatusCode: 403
      customBlockResponseBody: base64(strictHostFiltering ? 'APIM-LAB-EDGE-DENIED' : 'APIM-LAB-MANAGED-WAF-DENIED')
    }
    customRules: strictHostFiltering ? [
      {
        name: 'BlockUnapprovedIncomingHost'
        priority: 1
        ruleType: 'MatchRule'
        action: 'Block'
        matchConditions: [
          {
            matchVariables: [
              { variableName: 'RequestHeaders', selector: 'Host' }
            ]
            operator: 'Equal'
            negationConditon: true
            matchValues: [toLower(frontendHostname), '${toLower(frontendHostname)}:443']
            transforms: ['Lowercase']
          }
        ]
      }
    ] : []
    managedRules: {
      managedRuleSets: [
        { ruleSetType: 'OWASP', ruleSetVersion: '3.2' }
      ]
    }
  }
}

var gatewayId = resourceId('Microsoft.Network/applicationGateways', name)

resource gateway 'Microsoft.Network/applicationGateways@2024-05-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    sku: { name: 'WAF_v2', tier: 'WAF_v2', capacity: 1 }
    enableHttp2: false
    firewallPolicy: { id: waf.id }
    sslPolicy: { policyType: 'Predefined', policyName: 'AppGwSslPolicy20220101S' }
    gatewayIPConfigurations: [
      { name: 'gateway', properties: { subnet: { id: subnetId } } }
    ]
    frontendIPConfigurations: [
      { name: 'public', properties: { publicIPAddress: { id: publicIp.id } } }
    ]
    frontendPorts: [
      { name: 'https', properties: { port: 443 } }
    ]
    sslCertificates: [
      {
        name: 'lab'
        properties: { data: frontendPfxBase64, password: frontendPfxPassword }
      }
    ]
    // Both basic listeners accept any SNI; the strict gateway's global WAF checks incoming Host.
    httpListeners: [
      {
        name: 'https'
        properties: {
          frontendIPConfiguration: { id: '${gatewayId}/frontendIPConfigurations/public' }
          frontendPort: { id: '${gatewayId}/frontendPorts/https' }
          protocol: 'Https'
          requireServerNameIndication: false
          sslCertificate: { id: '${gatewayId}/sslCertificates/lab' }
        }
      }
    ]
    backendAddressPools: [
      { name: 'apim', properties: { backendAddresses: [{ ipAddress: backendIp }] } }
    ]
    backendHttpSettingsCollection: [
      {
        name: 'apim-https'
        properties: {
          port: 443
          protocol: 'Https'
          cookieBasedAffinity: 'Disabled'
          requestTimeout: 30
          hostName: backendHostname
          pickHostNameFromBackendAddress: false
          probe: { id: '${gatewayId}/probes/apim-health' }
        }
      }
    ]
    probes: [
      {
        name: 'apim-health'
        properties: {
          protocol: 'Https'
          host: backendHostname
          path: '/lab/health'
          interval: 30
          timeout: 30
          unhealthyThreshold: 3
          pickHostNameFromBackendHttpSettings: false
          match: { statusCodes: ['200'], body: 'APIM-NETWORK-LAB-OK' }
        }
      }
    ]
    requestRoutingRules: [
      {
        name: 'only-route'
        properties: {
          priority: 100
          ruleType: 'Basic'
          httpListener: { id: '${gatewayId}/httpListeners/https' }
          backendAddressPool: { id: '${gatewayId}/backendAddressPools/apim' }
          backendHttpSettings: { id: '${gatewayId}/backendHttpSettingsCollection/apim-https' }
        }
      }
    ]
  }
}

resource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'lab-logs'
  scope: gateway
  properties: {
    workspaceId: workspaceId
    logAnalyticsDestinationType: 'Dedicated'
    logs: [
      { category: 'ApplicationGatewayAccessLog', enabled: true }
      { category: 'ApplicationGatewayFirewallLog', enabled: true }
    ]
    metrics: [
      { category: 'AllMetrics', enabled: true }
    ]
  }
}

output publicIp string = publicIp.properties.ipAddress
