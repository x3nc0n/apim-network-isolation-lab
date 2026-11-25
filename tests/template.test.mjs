import assert from 'node:assert/strict';
import { readFile, access, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = fileURLToPath(new URL('../', import.meta.url));
const template = JSON.parse(await readFile(path.join(root, 'azuredeploy.json'), 'utf8'));
const deployment = (t, name) => {
  const found = t.resources.find(r => r.type === 'Microsoft.Resources/deployments' && r.name === name);
  assert.ok(found, `Missing nested deployment ${name}`);
  return found;
};
const resource = (t, type) => {
  const found = t.resources.find(r => r.type === type);
  assert.ok(found, `Missing ${type}`);
  return found;
};
const frontend = t => t.resources.find(r => r.copy?.name === 'frontends');

function assertSkuNetwork(t) {
  for (const name of ['public-basic', 'internal-developer', 'public-standard', 'internal-premium', 'external-restricted']) {
    const d = deployment(t, name);
    const params = d.properties.parameters;
    const sku = params.sku.value;
    const mode = params.networkMode?.value ?? d.properties.template.parameters.networkMode.defaultValue;
    assert.ok(['Developer', 'Basic', 'Standard', 'Premium'].includes(sku), `${name}: unknown SKU ${sku}`);
    if (mode !== 'None') {
      assert.ok(['Developer', 'Premium'].includes(sku), `${name}: ${sku} cannot use VNet injection`);
      assert.ok(params.subnetId?.value, `${name}: missing injected subnet`);
    } else {
      assert.equal(params.subnetId, undefined, `${name}: public Classic must not specify a subnet`);
    }
    const service = resource(d.properties.template, 'Microsoft.ApiManagement/service');
    assert.equal(service.properties.virtualNetworkType, "[parameters('networkMode')]");
  }
}

function assertStrictGate(t) {
  const f = frontend(t);
  assert.ok(f, 'Missing frontend loop');
  assert.equal(f.copy.count, "[length(createArray('rewrite', 'strict'))]", 'Two independent gateways are required');
  assert.match(f.name, /createArray\('rewrite', 'strict'\)/);
  assert.equal(f.properties.parameters.strictHostFiltering.value,
    "[equals(createArray('rewrite', 'strict')[copyIndex()], 'strict')]");
  assert.match(f.properties.parameters.backendIp.value, /internal-developer.*outputs\.privateIp/);
  const nested = f.properties.template;
  const waf = resource(nested, 'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies');
  assert.equal(waf.properties.policySettings.mode, 'Prevention');
  assert.equal(waf.properties.policySettings.state, 'Enabled');
  assert.equal(waf.properties.policySettings.customBlockResponseStatusCode, 403);
  assert.equal(waf.properties.policySettings.customBlockResponseBody,
    "[base64(if(parameters('strictHostFiltering'), 'APIM-LAB-EDGE-DENIED', 'APIM-LAB-MANAGED-WAF-DENIED'))]");
  const rules = waf.properties.customRules;
  assert.match(rules, /^\[if\(parameters\('strictHostFiltering'\)/, 'Gate must be strict-only');
  for (const clause of ["'priority', 1", "'action', 'Block'", "'selector', 'Host'",
    "'variableName', 'RequestHeaders'", "'operator', 'Equal'", "'negationConditon', true()",
    "'transforms', createArray('Lowercase')", "toLower(parameters('frontendHostname'))"]) {
    assert.ok(rules.includes(clause), `Strict WAF is missing ${clause}`);
  }
  assert.doesNotMatch(rules, /'action', 'Allow'/, 'Allow rules can short-circuit the block');
  assert.ok(rules.endsWith(', createArray())]'), 'Permissive path must have no Host custom rules');
  const gateway = resource(nested, 'Microsoft.Network/applicationGateways');
  assert.match(gateway.properties.firewallPolicy.id, /ApplicationGatewayWebApplicationFirewallPolicies/);
  assert.equal(gateway.properties.httpListeners.length, 1, 'No alternative listener may bypass the global WAF');
  assert.equal(gateway.properties.requestRoutingRules.length, 1);
  const settings = gateway.properties.backendHttpSettingsCollection[0].properties;
  assert.equal(settings.hostName, "[parameters('backendHostname')]", 'Backend Host rewrite is required on both paths');
  assert.equal(settings.protocol, 'Https');
  assert.equal(settings.pickHostNameFromBackendAddress, false);
  const probe = gateway.properties.probes[0].properties;
  assert.equal(probe.host, "[parameters('backendHostname')]");
  assert.equal(probe.path, '/lab/health');
  assert.deepEqual(probe.match, { statusCodes: ['200'], body: 'APIM-NETWORK-LAB-OK' });
}

function assertNsgBoundaries(t) {
  const network = deployment(t, 'network').properties.template;
  const nsg = network.resources.find(r => r.copy?.name === 'apimNsg');
  assert.ok(nsg, 'Missing per-APIM subnet NSGs');
  const rules = Object.fromEntries(nsg.properties.securityRules.map(r => [r.name, r.properties]));
  for (const [allow, deny, port] of [
    ['ApimControlPlane', 'DenyOtherManagement', '3443'],
    ['ApprovedHttpsSources', 'DenyOtherHttps', '443'],
  ]) {
    assert.ok(rules[allow] && rules[deny], `Missing ${allow}/${deny} boundary`);
    assert.equal(rules[allow].access, 'Allow');
    assert.equal(rules[deny].access, 'Deny');
    assert.equal(rules[allow].destinationPortRange, port);
    assert.equal(rules[deny].destinationPortRange, port);
    assert.equal(rules[deny].sourceAddressPrefix, '*');
    assert.ok(rules[allow].priority < rules[deny].priority && rules[deny].priority < 65000,
      `${deny} must precede default VNet allow`);
  }
  assert.equal(rules.ApimControlPlane.sourceAddressPrefix, 'ApiManagement');
  assert.equal(rules.ApimLoadBalancer.sourceAddressPrefix, 'AzureLoadBalancer');
  assert.equal(rules.ApimLoadBalancer.destinationPortRange, '6390');
  assert.equal(rules.DenyPublicHttp.destinationPortRange, '80');
  assert.match(rules.ApprovedHttpsSources.sourceAddressPrefixes, /externalAllowedCidr/);
  assert.match(rules.ApprovedHttpsSources.sourceAddressPrefixes, /gatewayPrefixes/);
  assert.deepEqual(network.variables.gatewayPrefixes, ['10.42.0.0/24', '10.42.1.0/24']);
  const gatewayNsg = network.resources.find(r => r.type === 'Microsoft.Network/networkSecurityGroups' && !r.copy);
  assert.ok(gatewayNsg.properties.securityRules.some(r =>
    r.properties.sourceAddressPrefix === 'GatewayManager' && r.properties.destinationPortRange === '65200-65535'));
}

test('fresh compiler output exactly matches committed standalone ARM', { skip: !process.env.APIM_LAB_COMPILED_FILE }, async () => {
  const fresh = JSON.parse(await readFile(process.env.APIM_LAB_COMPILED_FILE, 'utf8'));
  assert.deepEqual(fresh, template, 'Regenerate azuredeploy.json with the pinned compiler');
});

test('ARM schema, secure parameters, default inventory, opt-ins and output shapes', () => {
  function checkNested(t) {
    assert.equal(t.$schema, 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#');
    assert.equal(t.contentVersion, '1.0.0.0');
    for (const r of t.resources) {
      assert.ok(r.type && r.apiVersion && r.name, 'ARM resources need type, apiVersion and name');
      if (r.properties?.template) checkNested(r.properties.template);
    }
  }
  checkNested(template);
  for (const name of ['frontendPfxBase64', 'frontendPfxPassword']) {
    assert.equal(template.parameters[name].type, 'securestring');
    assert.equal(template.parameters[name].defaultValue, undefined);
    assert.equal(frontend(template).properties.template.parameters[name].type, 'securestring');
  }
  assert.ok(!JSON.stringify(template.outputs).match(/Pfx|Password|privateKey/i));
  assert.equal(template.outputs.frontendIps.type, 'array');
  for (const name of ['publicBasicUrl', 'internalDeveloperHostname', 'internalDeveloperPrivateIp',
    'publicStandardUrl', 'internalPremiumHostname', 'externalRestrictedUrl', 'approvedFrontendHostname']) {
    assert.equal(template.outputs[name].type, 'string', name);
  }
  assert.equal(deployment(template, 'public-basic').condition, undefined);
  assert.equal(deployment(template, 'internal-developer').condition, undefined);
  for (const [name, suffix] of [
    ['public-basic', 'public-basic'], ['internal-developer', 'private-developer'],
    ['public-standard', 'public-standard'], ['internal-premium', 'private-premium'],
    ['external-restricted', 'public-iprestricted'],
  ]) {
    assert.ok(deployment(template, name).properties.parameters.name.value.includes(`-${suffix}`),
      `${name}: missing scenario-readable resource name`);
    assert.ok(deployment(template, name).properties.parameters.tags.value.includes('scenario'),
      `${name}: missing scenario tag`);
  }
  assert.ok(frontend(template).properties.parameters.name.value.includes('appgwnofilter'));
  assert.ok(frontend(template).properties.parameters.name.value.includes('appgwhostfilter'));
  for (const [name, flag] of [['public-standard', 'deployStandard'], ['internal-premium', 'deployPremium'],
    ['external-restricted', 'deployExternalRestricted']]) {
    assert.equal(template.parameters[flag].defaultValue, false);
    assert.equal(deployment(template, name).condition, `[parameters('${flag}')]`);
  }
  assertSkuNetwork(template);
});

test('WAF Host gate, marker, routing, backend TLS and NSG boundaries', () => {
  assertStrictGate(template);
  assertNsgBoundaries(template);
});

test('mock operation and complete minimal APIM telemetry contract', () => {
  const nested = deployment(template, 'internal-developer').properties.template;
  const api = resource(nested, 'Microsoft.ApiManagement/service/apis');
  assert.equal(api.properties.path, 'lab');
  assert.equal(api.properties.subscriptionRequired, false);
  const operation = resource(nested, 'Microsoft.ApiManagement/service/apis/operations');
  assert.equal(operation.properties.urlTemplate, '/health');
  assert.equal(operation.properties.method, 'GET');
  const policy = resource(nested, 'Microsoft.ApiManagement/service/apis/policies').properties.value;
  assert.ok(policy.includes('<set-body>APIM-NETWORK-LAB-OK</set-body>'));
  assert.ok(policy.includes('X-Frontend-Validation-Id'));
  const diagnostic = resource(nested, 'Microsoft.ApiManagement/service/apis/diagnostics');
  assert.equal(diagnostic.properties.loggerId, '/loggers/azuremonitor');
  assert.deepEqual(diagnostic.properties.sampling, { samplingType: 'fixed', percentage: 100 });
  assert.deepEqual(diagnostic.properties.frontend.request.headers,
    ['X-Frontend-Validation-Id', 'x-appgw-trace-id', 'x-original-host']);
  assert.equal(diagnostic.properties.frontend.request.body.bytes, 0);
  const edgeLogs = resource(frontend(template).properties.template, 'Microsoft.Insights/diagnosticSettings');
  assert.equal(edgeLogs.properties.logAnalyticsDestinationType, 'Dedicated');
  assert.deepEqual(edgeLogs.properties.logs.map(l => l.category),
    ['ApplicationGatewayAccessLog', 'ApplicationGatewayFirewallLog']);
});

test('critical assertions reject mutated real ARM artifacts', () => {
  const invalidSku = structuredClone(template);
  deployment(invalidSku, 'internal-developer').properties.parameters.sku.value = 'Basic';
  assert.throws(() => assertSkuNetwork(invalidSku), /cannot use VNet injection/);
  const allowBypass = structuredClone(template);
  const waf = resource(frontend(allowBypass).properties.template,
    'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies');
  waf.properties.customRules = waf.properties.customRules.replace("'action', 'Block'", "'action', 'Allow'");
  assert.throws(() => assertStrictGate(allowBypass), /action.*Block/);
  const managementBypass = structuredClone(template);
  const nsg = deployment(managementBypass, 'network').properties.template.resources.find(r => r.copy?.name === 'apimNsg');
  nsg.properties.securityRules = nsg.properties.securityRules.filter(r => r.name !== 'DenyOtherManagement');
  assert.throws(() => assertNsgBoundaries(managementBypass), /boundary/);
});

test('Deploy to Azure URL decodes to an existing public main template', async () => {
  const readme = await readFile(path.join(root, 'README.md'), 'utf8');
  const links = [...readme.matchAll(/https:\/\/portal\.azure\.com\/#create\/Microsoft\.Template\/uri\/([^\s)]+)/g)];
  assert.equal(links.length, 1, 'Keep a single working Deploy to Azure entry point');
  const target = new URL(decodeURIComponent(links[0][1]));
  assert.equal(target.origin, 'https://raw.githubusercontent.com');
  const prefix = '/x3nc0n/apim-network-isolation-lab/main/';
  assert.ok(target.pathname.startsWith(prefix), 'Portal must fetch default main, not a feature branch');
  await access(path.join(root, target.pathname.slice(prefix.length)));
  assert.deepEqual(JSON.parse(await readFile(path.join(root, target.pathname.slice(prefix.length)), 'utf8')), template);
});

test('documentation file links resolve within the published repository', async () => {
  const markdownFiles = ['README.md', 'SECURITY.md',
    ...(await readdir(path.join(root, 'docs'))).filter(name => name.endsWith('.md')).map(name => path.join('docs', name))];
  for (const file of markdownFiles) {
    const markdown = await readFile(path.join(root, file), 'utf8');
    for (const match of markdown.matchAll(/\]\(([^)]+)\)/g)) {
      const target = match[1];
      if (/^(https?:|#)/.test(target)) continue;
      const destination = path.resolve(root, path.dirname(file), target.split('#')[0]);
      assert.ok(destination.startsWith(root), `${file}: link escapes repository: ${target}`);
      await assert.doesNotReject(access(destination), `${file}: broken local link ${target}`);
    }
  }
});
