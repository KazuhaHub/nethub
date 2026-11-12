import assert from 'node:assert/strict';
import { readFileSync, lstatSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { connect, isIP } from 'node:net';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
const require = createRequire(new URL('../../../server/web/package.json', import.meta.url));
const { chromium } = require('playwright');

assert.equal(process.platform, 'linux');
assert.equal(process.getuid(), 0);
assert.equal(process.env.GITHUB_ACTIONS, 'true');
assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted');
function privateText(path, maximum) {
  const info = lstatSync(path);
  assert.ok(info.isFile() && info.nlink === 1 && (info.mode & 0o077) === 0 && info.size <= maximum);
  return readFileSync(path, 'utf8').trimEnd();
}
const config = JSON.parse(privateText(process.argv[2], 8192));
assert.ok(Number.isInteger(config.console_port) && config.console_port > 0 && config.console_port < 65536);
assert.match(config.device_id, /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/);
assert.ok(typeof config.device_name === 'string' && config.device_name.length > 0 && config.device_name.length <= 253);
assert.equal(isIP(config.gateway), 4);
const octets = config.gateway.split('.').map(Number);
assert.ok(octets[0] === 10 || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) || (octets[0] === 192 && octets[1] === 168));
const password = privateText(config.password_file, 1024);
assert.ok(password.length >= 15);
const admin = privateText(join(config.frps_secrets, 'frps_admin_user'), 1024);
const adminPassword = privateText(join(config.frps_secrets, 'frps_admin_password'), 1024);
const authorization = 'Basic ' + Buffer.from(admin + ':' + adminPassword).toString('base64');
const origin = 'https://console.example.com';
const proxyName = 'nethub-' + config.device_id + '-web';
const sockets = new Set();
let refused = 0;
const proxy = createServer((_request, response) => { refused++; response.writeHead(403).end(); });
proxy.on('connect', (request, client, head) => {
  if (request.url !== 'console.example.com:443') { refused++; client.destroy(); return; }
  const upstream = connect({ host: '127.0.0.1', port: config.console_port });
  for (const socket of [client, upstream]) {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  }
  client.on('error', () => upstream.destroy());
  upstream.on('error', () => client.destroy());
  upstream.once('connect', () => {
    client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head.length) upstream.write(head);
    client.pipe(upstream); upstream.pipe(client);
  });
});
await new Promise((resolve, reject) => { proxy.once('error', reject); proxy.listen(0, '127.0.0.1', resolve); });

const result = {
  version: 1, passed: false, phase: 'login', deadline_ms: 5000,
  clock_start: 'before normal console confirmation click',
  isolated_console_CA_exception: true, public_network_acceptance: false,
  full_W5_acceptance: false, samples: [],
};
let browser;
let csp = 0, errors = 0, external = 0;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function online() {
  const response = await fetch(`http://${config.gateway}:7500/api/proxy/https`, {
    headers: { Authorization: authorization, Accept: 'application/json' },
    redirect: 'error', signal: AbortSignal.timeout(1000),
  });
  assert.equal(response.status, 200);
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > 1024 * 1024) { await reader.cancel(); throw new Error('bounded admin response required'); }
    chunks.push(Buffer.from(value));
  }
  const bytes = Buffer.concat(chunks, total);
  const value = JSON.parse(bytes.toString('utf8'));
  assert.ok(value.proxies === null || Array.isArray(value.proxies));
  const matches = (value.proxies ?? []).filter(row => row.name === proxyName);
  assert.ok(matches.length <= 1);
  return matches.some(row => row.status === 'online');
}
try {
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox'], proxy: { server: `http://127.0.0.1:${proxy.address().port}` } });
  // This isolated console uses its generated internal CA. Native-route TLS is
  // separately verified by the parent; public certificate acceptance is separate.
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 1000 } });
  await context.exposeBinding('recordNativeRevokeCSP', () => csp++);
  await context.addInitScript(() => document.addEventListener('securitypolicyviolation', () => window.recordNativeRevokeCSP()));
  const page = await context.newPage();
  page.setDefaultTimeout(15000);
  page.on('pageerror', () => errors++);
  page.on('request', request => { if (!request.url().startsWith(origin + '/')) external++; });
  const providers = ['oidc', 'saml'].map(protocol => page.waitForResponse(response =>
    new URL(response.url()).pathname === `/api/v1/console/${protocol}/providers` && response.status() === 200));
  await page.goto(origin);
  await page.getByRole('heading', { name: 'Sign in to NetHub' }).waitFor();
  for (const pending of providers) assert.equal(await (await pending).finished(), null);
  await page.getByLabel('Email address').fill('compose-admin@example.com');
  await page.getByLabel('Password', { exact: true }).fill(password);
  const inventory = page.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/console/devices' && response.status() === 200);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  const inventoryResponse = await inventory;
  assert.equal(await inventoryResponse.finished(), null);
  const items = (await inventoryResponse.json()).items;
  assert.equal(items.filter(item => item.id === config.device_id && item.revoked === false).length, 1);
  const row = page.getByRole('row').filter({ has: page.getByText(config.device_name, { exact: true }) });
  assert.equal(await row.count(), 1);
  await row.getByRole('button', { name: 'Revoke', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Revoke device?' });
  await dialog.waitFor();
  assert.equal(await online(), true);
  const confirmation = dialog.getByRole('button', { name: 'Permanently revoke', exact: true });
  assert.equal(await confirmation.isEnabled(), true);
  result.phase = 'confirmation_and_cutoff';
  const started = performance.now();
  result.confirmation_dispatch_utc = new Date().toISOString();
  // Establish live control after the conservative clock start, before clicking.
  assert.equal(await online(), true);
  result.samples.push({ elapsed_ms: Math.ceil(performance.now() - started), proxy_online: true });
  let responseMs;
  const decision = page.waitForResponse(response =>
    new URL(response.url()).pathname === `/api/v1/console/devices/${config.device_id}/revoke` && response.request().method() === 'POST')
    .then(response => { responseMs = Math.ceil(performance.now() - started); return response; });
  const cutoff = (async () => {
    while (true) {
      const active = await online();
      const elapsed = performance.now() - started;
      result.samples.push({ elapsed_ms: Math.ceil(elapsed), proxy_online: active });
      assert.ok(elapsed <= 5000, 'native proxy cutoff exceeded five seconds');
      if (!active) return Math.ceil(elapsed);
      await delay(100);
    }
  })();
  const [, response, cutoffMs] = await Promise.all([confirmation.click(), decision, cutoff]);
  assert.equal(response.status(), 200);
  assert.equal(await response.finished(), null);
  assert.equal(await response.request().headerValue('origin'), origin);
  assert.ok((await response.request().headerValue('x-csrf-token'))?.length > 0);
  const body = await response.json();
  assert.equal(body.revoked, true);
  assert.ok(typeof body.revoked_at === 'string' && Number.isFinite(Date.parse(body.revoked_at)));
  result.console_response_ms = responseMs;
  result.server_revoked_at_utc = body.revoked_at;
  result.native_proxy_offline_ms = cutoffMs;
  result.normal_browser_CSRF_protected_revoke = true;
  result.phase = 'no_reconnect';
  const observationStarted = performance.now();
  do {
    assert.equal(await online(), false);
    await delay(500);
  } while (performance.now() - observationStarted < 30000);
  result.no_reconnect_observation_ms = Math.floor(performance.now() - observationStarted);
  await row.getByText('Revoked', { exact: true }).waitFor();
  await page.screenshot({ path: join(config.evidence, 'installed-console-revoke.png'), fullPage: true });
  assert.equal(csp, 0); assert.equal(errors, 0); assert.equal(external, 0); assert.equal(refused, 0);
  result.csp_violations = csp; result.browser_errors = errors; result.external_requests = external;
  result.phase = 'completed'; result.passed = true;
} catch {
  // Never print Playwright call logs: failed password fills can contain secrets.
  console.error('Installed console Revoke failed at ' + result.phase);
  process.exitCode = 1;
} finally {
  writeFileSync(join(config.evidence, 'installed-console-revoke.json'), JSON.stringify(result, null, 2) + '\n', { mode: 0o600 });
  if (browser) await browser.close();
  for (const socket of sockets) socket.destroy();
  await new Promise(resolve => proxy.close(resolve));
}
