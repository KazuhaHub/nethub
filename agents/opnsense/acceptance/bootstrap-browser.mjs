import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';

const require = createRequire(new URL('../../../server/web/package.json', import.meta.url));
const { chromium } = require('playwright');
const config = JSON.parse(readFileSync(process.argv[2], 'utf8'));
assert.match(config.origin, /^https:\/\/127\.0\.0\.1:[0-9]+$/);
const browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
try {
  // The untouched signed image initially serves its factory self-signed GUI.
  // Public/relay TLS acceptance must use separate verified certificate checks.
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 1000 } });
  const page = await context.newPage();
  await page.goto(config.origin, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.locator('[name=usernamefld]').fill('root');
  await page.locator('[name=passwordfld]').fill('opnsense');
  await page.locator('button[type=submit], input[type=submit]').first().click();
  await page.locator('a[href*=logout]').first().waitFor({ timeout: 30000 });
  const errors = [];
  page.on('pageerror', () => errors.push('native_page_error'));
  const enrollment = page.waitForResponse(response =>
    new URL(response.url()).pathname === '/api/nethubagent/enroll/get');
  await page.goto(config.origin + '/ui/nethubagent/', { waitUntil: 'domcontentloaded' });
  const response = await enrollment;
  assert.equal(response.status(), 200);
  assert.equal((await response.json()).enrolled, false);
  await page.locator('#enrollNetHub').waitFor();
  await page.locator('#nethubEnrollmentInfo').filter({ hasText: 'Not enrolled' }).waitFor();
  assert.equal(await page.locator('#enrollNetHub').isEnabled(), true);
  assert.equal(await page.locator('#rotateNetHub').isDisabled(), true);
  assert.equal(await page.locator('#nethubEnrollToken').inputValue(), '');
  assert.deepEqual(errors, []);
  await page.screenshot({ path: join(config.evidence, 'native-page.png'), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  assert.ok(await page.locator('#rotateNetHub').isVisible());
  await page.screenshot({ path: join(config.evidence, 'native-mobile.png'), fullPage: true });
  const screenshots = Object.fromEntries(['native-page.png', 'native-mobile.png'].map(name =>
    [name, createHash('sha256').update(readFileSync(join(config.evidence, name))).digest('hex')]));
  writeFileSync(join(config.evidence, 'page.json'), JSON.stringify({ passed: true, screenshots,
    actual_installed_OPNsense_page: true, unconfigured_rotation_disabled: true,
    factory_self_signed_GUI_only: true, public_TLS_or_enrolled_rotation_acceptance: false }, null, 2));
  await context.close();
} finally {
  await browser.close();
}
