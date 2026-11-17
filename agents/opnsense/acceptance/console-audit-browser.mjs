import assert from 'node:assert/strict';
import { readFileSync, lstatSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { connect } from 'node:net';
import { createRequire } from 'node:module';
import { join } from 'node:path';
const require = createRequire(new URL('../../../server/web/package.json', import.meta.url));
const { chromium } = require('playwright');

assert.equal(process.platform, 'linux');
assert.equal(process.getuid(), 0);
assert.equal(process.env.GITHUB_ACTIONS, 'true');
assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted');
function privateText(path, maximum) {
  const info = lstatSync(path);
  assert.ok(info.isFile() && info.uid === 0 && info.nlink === 1 && (info.mode & 0o077) === 0 && info.size <= maximum);
  return readFileSync(path, 'utf8').trimEnd();
}
const config = JSON.parse(privateText(process.argv[2], 8192));
assert.deepEqual(Object.keys(config).sort(), ['console_port', 'details', 'device_id', 'evidence', 'password_file']);
assert.ok(Number.isInteger(config.console_port) && config.console_port > 0 && config.console_port < 65536);
assert.match(config.device_id, /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/);
assert.deepEqual(Object.keys(config.details).sort(), ['device_reported', 'failure_count', 'first_reported_at', 'last_reported_at']);
assert.equal(config.details.failure_count, '1');
assert.equal(config.details.device_reported, true);
const password = privateText(config.password_file, 1024);
assert.ok(password.length >= 15);
const origin = 'https://console.example.com';
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

const result = { version: 1, passed: false, phase: 'login', normal_login: false,
  filtered_original_device_reported_row: false, typed_count_and_interval_visible: false,
  browser_integrity: false, isolated_console_CA_exception: true, public_network_acceptance: false };
let browser;
let csp = 0, errors = 0, external = 0;
try {
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox'], proxy: { server: `http://127.0.0.1:${proxy.address().port}` } });
  // Only the isolated console's generated CA is excepted. The parent verifies
  // the native route independently; this is not public certificate acceptance.
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 1000 } });
  await context.exposeBinding('recordNativeAuditCSP', () => csp++);
  await context.addInitScript(() => document.addEventListener('securitypolicyviolation', () => window.recordNativeAuditCSP()));
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
  assert.equal(await (await inventory).finished(), null);
  result.normal_login = true;
  result.phase = 'audit';
  await page.getByRole('link', { name: 'Audit log', exact: true }).click();
  await page.getByRole('heading', { name: 'Audit log', exact: true }).waitFor();
  const filters = page.getByRole('form', { name: 'Audit filters' });
  await filters.getByLabel('Action', { exact: true }).fill('device.reconcile_failed');
  await filters.getByLabel('Device ID', { exact: true }).fill(config.device_id);
  const filtered = page.waitForResponse(response => {
    const url = new URL(response.url());
    return url.pathname === '/api/v1/console/audit' && url.searchParams.get('action') === 'device.reconcile_failed'
      && url.searchParams.get('device_id') === config.device_id && response.status() === 200;
  });
  await filters.getByRole('button', { name: 'Apply filters', exact: true }).click();
  const response = await filtered;
  assert.equal(await response.finished(), null);
  const body = await response.json();
  assert.ok(Array.isArray(body.items) && body.items.length > 0 && body.items.length <= 200);
  const matches = body.items.filter(item => item.details?.first_reported_at === config.details.first_reported_at);
  assert.equal(matches.length, 1);
  const item = matches[0];
  assert.equal(item.action, 'device.reconcile_failed');
  assert.equal(item.actor_type, 'device');
  assert.equal(item.target_device_id, config.device_id);
  assert.deepEqual(item.details, config.details);
  const events = page.getByRole('region', { name: 'Audit events' });
  assert.match(item.created_at, /^[0-9T:.Z+-]+$/);
  const row = events.getByRole('row')
    .filter({ has: page.getByRole('cell', { name: 'device.reconcile_failed', exact: true }) })
    .filter({ has: page.locator(`time[datetime="${item.created_at}"]`) });
  await row.waitFor();
  assert.equal(await row.count(), 1);
  assert.equal(await row.getByRole('cell', { name: config.device_id, exact: true }).count(), 1);
  result.filtered_original_device_reported_row = true;
  for (const [label, expected] of [['failure count', '1'], ['device reported', 'true']]) {
    const pair = row.locator('dl > div').filter({ has: page.locator('dt').filter({ hasText: new RegExp(`^${label}$`) }) });
    assert.equal(await pair.locator('dd').innerText(), expected);
  }
  for (const label of ['first reported at', 'last reported at']) {
    const pair = row.locator('dl > div').filter({ has: page.locator('dt').filter({ hasText: new RegExp(`^${label}$`) }) });
    assert.ok((await pair.locator('dd').innerText()).trim().length > 0);
  }
  result.typed_count_and_interval_visible = true;
  await page.screenshot({ path: join(config.evidence, 'installed-reconcile-audit.png'), fullPage: true,
    mask: [events.locator('tbody td:nth-child(3), tbody td:nth-child(4), tbody td:nth-child(5)'), filters.getByLabel('Device ID', { exact: true })] });
  result.phase = 'integrity';
  assert.equal(csp, 0); assert.equal(errors, 0); assert.equal(external, 0); assert.equal(refused, 0);
  result.browser_integrity = true;
  result.phase = 'completed'; result.passed = true;
} catch {
  // Child call logs can contain entered passwords. Export only a fixed phase.
  console.error('Installed audit browser failed at ' + result.phase);
  process.exitCode = 1;
} finally {
  writeFileSync(join(config.evidence, 'installed-reconcile-audit-browser.json'), JSON.stringify(result, null, 2) + '\n', { mode: 0o600 });
  if (browser) await browser.close();
  for (const socket of sockets) socket.destroy();
  await new Promise(resolve => proxy.close(resolve));
}
