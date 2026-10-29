import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';

const require = createRequire(new URL('../../../server/web/package.json', import.meta.url));
const { chromium } = require('playwright');
const config = JSON.parse(readFileSync(process.argv[2], 'utf8'));
assert.match(config.origin, /^https:\/\/127\.0\.0\.1:[0-9]+$/);
assert.match(config.console, /^https:\/\/console\.example\.com:[0-9]+$/);
assert.ok(['enroll', 'rotate'].includes(config.action));
const expectedSuccess = config.expected_success ?? true;
assert.equal(typeof expectedSuccess, 'boolean');
assert.ok(config.action === 'rotate' || expectedSuccess);
const label = config.label ?? config.action;
assert.ok(['enroll', 'rotate', 'rotate-lost', 'rotate-recovered',
  'rotate-save-failed', 'rotate-save-recovered'].includes(label));
assert.equal(label === 'enroll', config.action === 'enroll');
assert.equal(expectedSuccess, !['rotate-lost', 'rotate-save-failed'].includes(label));
let browser;
let phase = 'private_gui_login';
try {
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
  // Direct fixture management is separate from the verified same-route TLS probe.
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  await page.goto(config.origin, { waitUntil: 'domcontentloaded' });
  await page.locator('[name=usernamefld]').fill('root');
  await page.locator('[name=passwordfld]').fill('opnsense');
  await page.locator('button[type=submit], input[type=submit]').first().click();
  await page.locator('a[href*=logout]').first().waitFor();
  phase = 'native_' + config.action;
  await page.goto(config.origin + '/ui/nethubagent/', { waitUntil: 'domcontentloaded' });
  const endpoint = config.action === 'enroll' ? '/api/nethubagent/enroll/enroll' : '/api/nethubagent/service/rotate';
  const pending = page.waitForResponse(response => new URL(response.url()).pathname === endpoint, { timeout: 100000 });
  if (config.action === 'enroll') {
    await page.locator('#nethubEnrollmentInfo').filter({ hasText: 'Not enrolled' }).waitFor();
    await page.locator('#nethubConsoleUrl').fill(config.console);
    await page.locator('#nethubEnrollToken').fill(config.token);
    await page.locator('#enrollNetHub').click();
  } else {
    await page.locator('#nethubEnrollmentInfo').filter({ hasText: 'Enrolled device' }).waitFor();
    await page.waitForFunction(() => !document.querySelector('#rotateNetHub').disabled);
    page.once('dialog', dialog => dialog.accept());
    await page.locator('#rotateNetHub').click();
  }
  const response = await pending;
  assert.equal(response.status(), 200);
  const result = await response.json();
  assert.equal(result.success, expectedSuccess);
  if (config.action === 'enroll') {
    assert.equal(result.enrolled, true);
    await page.locator('#nethubEnrollmentInfo').filter({ hasText: 'Enrolled device' }).waitFor();
  } else if (expectedSuccess) {
    assert.equal(result.phase, 'applied');
    await page.locator('#nethubRotationResult').filter({ hasText: 'Credentials rotated' }).waitFor();
  } else {
    assert.equal(result.phase, 'error');
    await page.locator('#nethubRotationResult').filter({ hasText: 'Rotation response unavailable' }).waitFor();
  }
  assert.equal(await page.locator('#nethubEnrollToken').inputValue(), '');
  await page.locator('#rotateNetHub').scrollIntoViewIfNeeded();
  const screenshot = 'installed-' + label + '.png';
  await page.screenshot({ path: join(config.evidence, screenshot), mask: [page.locator('#nethubStatus')] });
  writeFileSync(join(config.evidence, 'installed-' + label + '-page.json'),
    JSON.stringify({ passed: true, action: config.action, expected_success: expectedSuccess,
      actual_native_write_API: true,
      screenshots: { [screenshot]: createHash('sha256').update(readFileSync(join(config.evidence, screenshot))).digest('hex') } }, null, 2));
  await context.close();
} catch {
  writeFileSync(join(config.evidence, 'installed-' + label + '-page.json'),
    JSON.stringify({ passed: false, phase }, null, 2));
  throw new Error('Installed device browser check failed at ' + phase);
} finally {
  if (browser) await browser.close();
}
