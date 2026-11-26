param stem string
param location string
param tags object
param externalAllowedCidr string

var gatewayPrefixes = ['10.42.0.0/24', '10.42.1.0/24']
var apimNames = ['internal', 'premium', 'external']
var apimPrefixes = ['10.42.2.0/24', '10.42.3.0/24', '10.42.4.0/24']

resource gatewayNsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: '${stem}-gateway-nsg'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'InternetHttps'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: 'Internet'
          destinationAddressPrefix: '*'
        }
      }
      {
        name: 'GatewayManager'
        properties: {
          priority: 110
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '65200-65535'
          sourceAddressPrefix: 'GatewayManager'
          destinationAddressPrefix: '*'
        }
      }
      {
        name: 'LoadBalancer'
        properties: {
          priority: 120
          direction: 'Inbound'
          access: 'Allow'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: 'AzureLoadBalancer'
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}

resource apimNsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = [for (mode, index) in apimNames: {
  name: '${stem}-${mode}-nsg'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'ApimControlPlane'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '3443'
          sourceAddressPrefix: 'ApiManagement'
          destinationAddressPrefix: apimPrefixes[index]
        }
      }
      {
        name: 'ApimPlatformProbes'
        properties: {
          priority: 103
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRanges: ['443', '3443']
          sourceAddressPrefix: 'AzureLoadBalancer'
          destinationAddressPrefix: '*'
        }
      }
      {
        name: 'DenyOtherManagement'
        properties: {
          priority: 105
          direction: 'Inbound'
          access: 'Deny'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '3443'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: apimPrefixes[index]
        }
      }
      {
        name: 'ApimLoadBalancer'
        properties: {
          priority: 110
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '6390'
          sourceAddressPrefix: 'AzureLoadBalancer'
          destinationAddressPrefix: apimPrefixes[index]
        }
      }
      {
        name: 'ApprovedHttpsSources'
        properties: {
          priority: 120
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefixes: mode == 'external' ? [externalAllowedCidr] : gatewayPrefixes
          destinationAddressPrefix: apimPrefixes[index]
        }
      }
      {
        name: 'DenyOtherHttps'
        properties: {
          priority: 130
          direction: 'Inbound'
          access: 'Deny'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: apimPrefixes[index]
        }
      }
      {
        name: 'DenyPublicHttp'
        properties: {
          priority: 140
          direction: 'Inbound'
          access: 'Deny'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '80'
          sourceAddressPrefix: 'Internet'
          destinationAddressPrefix: apimPrefixes[index]
        }
      }
    ]
  }
}]

var gatewaySubnets = [for (prefix, index) in gatewayPrefixes: {
  name: 'gateway-${index}'
  properties: {
    addressPrefix: prefix
    networkSecurityGroup: { id: gatewayNsg.id }
  }
}]
var apimSubnets = [for (mode, index) in apimNames: {
  name: mode
  properties: {
    addressPrefix: apimPrefixes[index]
    networkSecurityGroup: { id: apimNsg[index].id }
    serviceEndpoints: [
      { service: 'Microsoft.Storage' }
    ]
  }
}]

// Default outbound NSG rules are retained for APIM/AppGw dependencies, DNS and certificate validation.
resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: '${stem}-vnet'
  location: location
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: ['10.42.0.0/16'] }
    subnets: concat(gatewaySubnets, apimSubnets)
  }
}

output gatewaySubnetIds array = [for index in range(0, 2): resourceId('Microsoft.Network/virtualNetworks/subnets', vnet.name, 'gateway-${index}')]
output internalSubnetId string = resourceId('Microsoft.Network/virtualNetworks/subnets', vnet.name, 'internal')
output premiumSubnetId string = resourceId('Microsoft.Network/virtualNetworks/subnets', vnet.name, 'premium')
output externalSubnetId string = resourceId('Microsoft.Network/virtualNetworks/subnets', vnet.name, 'external')
