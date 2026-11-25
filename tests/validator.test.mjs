import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import https from 'node:https';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = fileURLToPath(new URL('../', import.meta.url));
const approvedHost = 'api.lab.example';
const positive = 'APIM-NETWORK-LAB-OK';
const denial = 'APIM-LAB-EDGE-DENIED';
const validator = path.join(root, 'scripts', 'Test-FrontendHostnameFilter.ps1');

function runPowerShell(args) {
  return new Promise((resolve, reject) => {
    const child = spawn('pwsh', ['-NoLogo', '-NoProfile', ...args], { windowsHide: true });
    let output = '';
    child.stdout.on('data', data => { output += data; });
    child.stderr.on('data', data => { output += data; });
    child.on('error', reject);
    child.on('close', code => resolve({ code, output }));
  });
}

test('supplied validator remains byte-for-byte unchanged', async () => {
  const hash = createHash('sha256').update(await readFile(validator)).digest('hex');
  assert.equal(hash, 'd4f499d59ca5dd68c37cee382aff9e3440ee86758c7e4d996f33ba920b8109f1');
});

test('real HTTPS response contracts, certificate helper and exit codes', { timeout: 240_000 }, async t => {
  const temp = await mkdtemp(path.join(tmpdir(), 'apim-lab-contract-'));
  let server;
  try {
    const certDirectory = path.join(temp, 'certificates');
    const escaped = value => value.replaceAll("'", "''");
    const certificate = await runPowerShell(['-Command',
      `& '${escaped(path.join(root, 'scripts', 'New-LabCertificate.ps1'))}' ` +
      `-PublisherEmail 'lab@example.invalid' -OutputDirectory '${escaped(certDirectory)}' ` +
      "-PfxPassword (ConvertTo-SecureString 'Disposable-test-only-945!' -AsPlainText -Force)"]);
    assert.equal(certificate.code, 0, certificate.output);
    assert.doesNotMatch(certificate.output, /Disposable-test-only-945!/);
    const parameters = JSON.parse(await readFile(path.join(certDirectory, 'lab.secure.parameters.json'), 'utf8'));
    assert.equal(parameters.parameters.frontendHostname.value, approvedHost);
    let mode = 'strict';
    const requests = [];
    server = https.createServer({
      pfx: Buffer.from(parameters.parameters.frontendPfxBase64.value, 'base64'),
      passphrase: parameters.parameters.frontendPfxPassword.value,
    }, (request, response) => {
      requests.push({
        host: request.headers.host,
        sni: request.socket.servername,
        id: request.headers['x-frontend-validation-id'],
      });
      const allowed = [approvedHost, `${approvedHost}:443`].includes(request.headers.host?.toLowerCase());
      if (mode === 'bad-control' && allowed) {
        response.writeHead(503).end('not the application');
      } else if (mode === 'rewrite' || allowed) {
        response.writeHead(200).end(positive);
      } else if (mode === 'transport') {
        request.socket.destroy();
      } else if (mode === 'empty-header') {
        response.writeHead(403, { 'X-Edge-Denial': 'hostname' }).end();
      } else if (mode === 'ambiguous') {
        response.writeHead(403).end('generic forbidden');
      } else if (mode === 'not-found') {
        response.writeHead(404).end('not found');
      } else if (mode === 'positive-in-denial') {
        response.writeHead(403).end(`${denial} ${positive}`);
      } else {
        response.writeHead(403).end(denial);
      }
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const cases = [
      { mode: 'rewrite', overall: 'FAIL', exit: 1, check: r => {
        assert.ok(r.Results.some(p => p.Required && p.Name !== 'Approved control' && p.ApprovedMarkerMatched));
      } },
      { mode: 'strict', overall: 'PASS', exit: 0, check: r => {
        assert.ok(r.Results.filter(p => p.Required && p.Name !== 'Approved control')
          .every(p => p.HttpStatus === 403 && p.EdgeDenialMarkerMatched));
        assert.ok(r.Results.some(p => p.Verdict === 'INFO' && p.ApprovedMarkerMatched));
      } },
      { mode: 'strict', sni: true, overall: 'FAIL', exit: 1, check: r => {
        assert.ok(r.Results.some(p => p.Name === 'Approved Host; unapproved SNI' && p.Verdict === 'FAIL'));
      } },
      { mode: 'empty-header', header: true, overall: 'PASS', exit: 0, check: r => {
        assert.ok(r.Results.filter(p => p.Required && p.Name !== 'Approved control')
          .every(p => p.BodyBytes === 0 && p.EdgeDenialMarkerMatched));
      } },
      { mode: 'ambiguous', overall: 'INCONCLUSIVE', exit: 2 },
      { mode: 'strict', noMarker: true, overall: 'INCONCLUSIVE', exit: 2 },
      { mode: 'transport', overall: 'INCONCLUSIVE', exit: 2, check: r => {
        assert.ok(r.Results.some(p => p.Required && p.CurlExitCode !== 0 && p.Verdict === 'INCONCLUSIVE'));
      } },
      { mode: 'not-found', overall: 'FAIL', exit: 1 },
      { mode: 'bad-control', overall: 'FAIL', exit: 1, check: r => {
        assert.equal(r.Results[0].Verdict, 'FAIL');
        assert.ok(!r.Results.some(p => p.Required && p.Verdict === 'PASS'));
      } },
      { mode: 'positive-in-denial', overall: 'FAIL', exit: 1 },
    ];
    for (const [index, scenario] of cases.entries()) {
      await t.test(`${scenario.mode}${scenario.sni ? ' with SNI required' : ''}${scenario.noMarker ? ' without marker' : ''}`, async () => {
        mode = scenario.mode;
        const outputPath = path.join(temp, `result-${index}.json`);
        const args = ['-File', validator, '-FrontendIp', '127.0.0.1',
          '-GatewayHostname', approvedHost, '-UnapprovedHostname', 'other.lab.example',
          '-Path', '/lab/health', '-ApprovedBodyPattern', positive,
          '-RejectionStatusCode', '403', '-Port', String(server.address().port),
          '-CertificateAuthorityFile', path.join(certDirectory, 'lab-root.pem'),
          '-OutputPath', outputPath, '-ConnectTimeoutSeconds', '2', '-TimeoutSeconds', '3'];
        if (scenario.header) args.push('-RejectionHeaderPattern', '(?im)^X-Edge-Denial:\\s*hostname\\s*$');
        else if (!scenario.noMarker) args.push('-RejectionBodyPattern', denial);
        if (scenario.sni) args.push('-RequireSniMatch');
        const result = await runPowerShell(args);
        const report = JSON.parse((await readFile(outputPath, 'utf8')).replace(/^\uFEFF/, ''));
        assert.equal(result.code, scenario.exit, JSON.stringify(report.Results, null, 2));
        assert.equal(report.Overall, scenario.overall, result.output);
        assert.equal(report.Results.length, 10);
        assert.equal(report.Results[0].CertificateVerification, true);
        assert.ok(report.Results.slice(1).every(p => !p.CertificateVerification));
        assert.ok(report.Results.every(p => /^[a-f0-9]{64}$/.test(p.BodySha256)));
        assert.ok(!JSON.stringify(report).includes('"Body":'), 'Report must not retain response bodies');
        scenario.check?.(report);
      });
    }
    assert.ok(requests.some(r => r.sni === approvedHost && r.host === 'other.lab.example'));
    assert.ok(requests.some(r => r.sni === 'other.lab.example' && r.host === approvedHost));
    assert.ok(requests.some(r => !r.sni && r.host === approvedHost));
    assert.ok(requests.every(r => /^[a-f0-9]{32}$/.test(r.id)));
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    await rm(temp, { recursive: true, force: true });
  }
});
