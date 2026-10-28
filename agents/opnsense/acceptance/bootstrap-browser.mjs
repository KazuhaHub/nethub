import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';

const require = createRequire(new URL('../../../server/web/package.json', import.meta.url));
const { chromium } = require('playwright');
const config = JSON.parse(readFileSync(process.argv[2], 'utf8'));
assert.match(config.origin, /^https:\/\/127\.0\.0\.1:[0-9]+$/);
let browser;
let phase = 'browser_launch';
const mobileChecks = {};
try {
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
  phase = 'private_gui_login';
  // The untouched signed image initially serves its factory self-signed GUI.
  // Public/relay TLS acceptance must use separate verified certificate checks.
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 1000 } });
  const page = await context.newPage();
  await page.goto(config.origin, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.locator('[name=usernamefld]').fill('root');
  await page.locator('[name=passwordfld]').fill('opnsense');
  await page.locator('button[type=submit], input[type=submit]').first().click();
  await page.locator('a[href*=logout]').first().waitFor({ timeout: 30000 });
  phase = 'native_page_status';
  const errors = [];
  page.on('pageerror', () => errors.push('native_page_error'));
  const enrollment = page.waitForResponse(response =>
    new URL(response.url()).pathname === '/api/nethubagent/enroll/get');
  const status = page.waitForResponse(response =>
    new URL(response.url()).pathname === '/api/nethubagent/service/status');
  await page.goto(config.origin + '/ui/nethubagent/', { waitUntil: 'domcontentloaded' });
  const response = await enrollment;
  assert.equal(response.status(), 200);
  assert.equal((await response.json()).enrolled, false);
  const statusResponse = await status;
  assert.equal(statusResponse.status(), 200);
  assert.equal((await statusResponse.json()).status, 'stopped');
  await page.waitForFunction(() => {
    try { return JSON.parse(document.querySelector('#nethubStatus').textContent).status === 'stopped'; }
    catch { return false; }
  });
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
  for (const [selector, name] of [['#nethubConsoleUrl', 'native-mobile-enrollment.png'],
                                 ['#rotateNetHub', 'native-mobile-rotation.png']]) {
    const target = page.locator(selector);
    phase = selector === '#rotateNetHub' ? 'mobile_rotation' : 'mobile_enrollment';
    await target.evaluate(element => element.scrollIntoView({ block: 'center', behavior: 'instant' }));
    const visibility = await target.evaluate(element => {
      const bounds = element.getBoundingClientRect();
      const x = bounds.x + bounds.width / 2, y = bounds.y + bounds.height / 2;
      const hit = document.elementFromPoint(x, y);
      const disabled = element.disabled === true;
      const pointerEventsNone = getComputedStyle(element).pointerEvents === 'none';
      const hitTarget = hit !== null && element.contains(hit);
      const hitAncestor = hit !== null && hit.contains(element);
      return { disabled, pointer_events_none: pointerEventsNone, hit_target: hitTarget,
        hit_ancestor: hitAncestor,
        within_viewport: bounds.width > 0 && bounds.height > 0 && bounds.left >= 0 &&
          bounds.top >= 0 && bounds.right <= innerWidth && bounds.bottom <= innerHeight,
        // Bootstrap excludes disabled buttons from hit testing. Only their
        // painted ancestor may replace them; an unrelated overlay still fails.
        unobscured: hitTarget || disabled && pointerEventsNone && hitAncestor };
    });
    mobileChecks[phase] = visibility;
    assert.equal(visibility.within_viewport && visibility.unobscured, true);
    await page.screenshot({ path: join(config.evidence, name) });
  }
  const screenshots = Object.fromEntries(['native-page.png', 'native-mobile.png',
    'native-mobile-enrollment.png', 'native-mobile-rotation.png'].map(name =>
    [name, createHash('sha256').update(readFileSync(join(config.evidence, name))).digest('hex')]));
  writeFileSync(join(config.evidence, 'page.json'), JSON.stringify({ passed: true, screenshots,
    mobile_checks: mobileChecks,
    actual_installed_OPNsense_page: true, unconfigured_rotation_disabled: true,
    factory_self_signed_GUI_only: true, public_TLS_or_enrolled_rotation_acceptance: false }, null, 2));
  await context.close();
} catch {
  writeFileSync(join(config.evidence, 'page.json'), JSON.stringify({ passed: false, phase,
    mobile_checks: mobileChecks }, null, 2));
  throw new Error('Installed native page check failed at ' + phase);
} finally {
  if (browser) await browser.close();
}
