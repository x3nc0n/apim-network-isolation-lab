param name string
param location string
param tags object

@allowed(['Developer', 'Basic', 'Standard', 'Premium'])
param sku string

@allowed(['None', 'Internal', 'External'])
param networkMode string = 'None'

param subnetId string = ''
param publisherEmail string
param workspaceId string

resource apim 'Microsoft.ApiManagement/service@2024-05-01' = {
  name: name
  location: location
  tags: tags
  sku: {
    name: sku
    capacity: 1
  }
  properties: {
    publisherEmail: publisherEmail
    publisherName: 'Synthetic APIM network lab'
    virtualNetworkType: networkMode
    virtualNetworkConfiguration: networkMode == 'None' ? null : { subnetResourceId: subnetId }
    publicNetworkAccess: 'Enabled'
  }
}

resource api 'Microsoft.ApiManagement/service/apis@2024-05-01' = {
  parent: apim
  name: 'network-lab'
  properties: {
    displayName: 'Harmless synthetic network control'
    path: 'lab'
    protocols: ['https']
    subscriptionRequired: false
    apiRevision: '1'
  }
}

resource health 'Microsoft.ApiManagement/service/apis/operations@2024-05-01' = {
  parent: api
  name: 'health'
  properties: {
    displayName: 'Synthetic health marker'
    method: 'GET'
    urlTemplate: '/health'
    responses: [
      { statusCode: 200 }
    ]
  }
}

resource policy 'Microsoft.ApiManagement/service/apis/policies@2024-05-01' = {
  parent: api
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: '''
      <policies>
        <inbound>
          <base />
          <return-response>
            <set-status code="200" reason="OK" />
            <set-header name="Content-Type" exists-action="override"><value>text/plain</value></set-header>
            <set-header name="X-Lab-Request-Id" exists-action="override"><value>@(context.Request.Headers.GetValueOrDefault("X-Frontend-Validation-Id", "none"))</value></set-header>
            <set-body>APIM-NETWORK-LAB-OK</set-body>
          </return-response>
        </inbound>
        <backend><base /></backend>
        <outbound><base /></outbound>
        <on-error><base /></on-error>
      </policies>
      '''
  }
  dependsOn: [health]
}

resource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'lab-logs'
  scope: apim
  properties: {
    workspaceId: workspaceId
    logAnalyticsDestinationType: 'Dedicated'
    logs: [
      { category: 'GatewayLogs', enabled: true }
    ]
    metrics: [
      { category: 'AllMetrics', enabled: true }
    ]
  }
}

resource apiDiagnostics 'Microsoft.ApiManagement/service/apis/diagnostics@2024-05-01' = {
  parent: api
  name: 'azuremonitor'
  properties: {
    loggerId: '/loggers/azuremonitor'
    alwaysLog: 'allErrors'
    sampling: { samplingType: 'fixed', percentage: 100 }
    logClientIp: true
    verbosity: 'information'
    frontend: {
      request: {
        headers: ['X-Frontend-Validation-Id', 'x-appgw-trace-id', 'x-original-host']
        body: { bytes: 0 }
      }
      response: {
        headers: ['X-Lab-Request-Id']
        body: { bytes: 0 }
      }
    }
  }
}

output gatewayHostname string = replace(apim.properties.gatewayUrl, 'https://', '')
output privateIp string = networkMode == 'None' ? '' : apim.properties.privateIPAddresses[0]
