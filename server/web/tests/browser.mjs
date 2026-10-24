import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve, join, dirname, basename } from "node:path";
import { createInterface } from "node:readline";
import { chromium } from "playwright";

const root = resolve(import.meta.dirname, "../..");
const stage = mkdtempSync(join(tmpdir(), "nethub-ui-"));
const evidence = process.env.NETHUB_UI_EVIDENCE
  ? resolve(process.env.NETHUB_UI_EVIDENCE)
  : join(stage, "evidence");
mkdirSync(evidence, { recursive: true });
const executable = join(
  stage,
  process.platform === "win32" ? "fixture.exe" : "fixture",
);
const build = spawnSync(
  process.env.GO_BINARY || "go",
  ["build", "-o", executable, "./web/tests/fixture"],
  {
    cwd: root,
    env: { ...process.env, GOWORK: "off", CGO_ENABLED: "0" },
    encoding: "utf8",
  },
);
assert.equal(build.status, 0, build.stderr);
const child = spawn(executable, [], {
  env: { ...process.env, NETHUB_UI_FIXTURE: "1" },
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true,
});
let browser;
let serverLog = "";
child.stderr.on("data", (chunk) => {
  serverLog += chunk;
});
try {
  const origin = await new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(Error("Fixture startup timed out")),
      20000,
    );
    const lines = createInterface({ input: child.stdout });
    lines.once("line", (line) => {
      clearTimeout(timer);
      lines.close();
      try {
        resolve(JSON.parse(line).origin);
      } catch (error) {
        reject(error);
      }
    });
    child.once("exit", () => {
      clearTimeout(timer);
      reject(Error("Fixture exited before readiness"));
    });
  });
  browser = await chromium.launch({
    headless: true,
    channel: process.env.PLAYWRIGHT_CHANNEL || undefined,
  });
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    viewport: { width: 1440, height: 1000 },
    colorScheme: "light",
  });
  await context.grantPermissions(["clipboard-read", "clipboard-write"], {
    origin,
  });
  const page = await context.newPage();
  const violations = [];
  const failures = [];
  const external = [];
  let inventoryRequests = 0;
  let activeInventoryRefreshes = 0;
  await context.exposeBinding("recordCSP", (_, value) =>
    violations.push(value),
  );
  await context.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (event) =>
      window.recordCSP({
        directive: event.violatedDirective,
        blocked: event.blockedURI,
      }),
    );
  });
  page.on("pageerror", (error) => failures.push(error.message));
  page.on("request", (request) => {
    if (!request.url().startsWith(origin + "/")) external.push(request.url());
    if (new URL(request.url()).pathname === "/api/v1/console/devices") {
      inventoryRequests++;
      if (request.headers()["x-nethub-background"] === undefined) {
        activeInventoryRefreshes++;
      }
    }
  });
  await page.goto(origin);
  await page.getByRole("heading", { name: "Sign in to NetHub" }).waitFor();
  await page.screenshot({
    path: join(evidence, "login-light.png"),
    fullPage: true,
  });
  async function login() {
    await page.getByLabel("Email address").fill("ui-test@example.com");
    await page
      .getByLabel("Password", { exact: true })
      .fill("isolated UI fixture passphrase");
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page.getByRole("heading", { name: "Devices", exact: true }).waitFor();
  }
  await login();
  await page
    .getByRole("heading", { name: "Your network starts here" })
    .waitFor();
  await page.screenshot({
    path: join(evidence, "devices-empty.png"),
    fullPage: true,
  });
  const cookies = await context.cookies();
  const session = cookies.find(
    (cookie) => cookie.name === "__Host-nethub_session",
  );
  assert.ok(session?.httpOnly && session.secure && session.path === "/");
  assert.ok(
    !(await page.evaluate(() => document.cookie)).includes(
      "__Host-nethub_session",
    ),
  );
  await page.reload();
  await page.getByRole("heading", { name: "Devices", exact: true }).waitFor();
  const opener = page.getByRole("button", { name: "Add device", exact: true });
  await opener.click();
  const dialog = page.getByRole("dialog", { name: "Add a device" });
  async function closeDialogOnce(action) {
    const before = activeInventoryRefreshes;
    await action();
    await dialog.waitFor({ state: "hidden" });
    await page.waitForTimeout(200);
    await page.waitForFunction(
      () =>
        !document.querySelector('button[aria-label="Refresh devices"]')
          ?.disabled,
    );
    assert.equal(
      activeInventoryRefreshes - before,
      1,
      "One dialog dismissal must trigger exactly one active inventory refresh",
    );
  }
  await dialog.waitFor();
  await page
    .getByRole("button", { name: "Generate token", exact: true })
    .click();
  const tokenField = page.getByLabel("Enrollment token", { exact: true });
  await tokenField.waitFor();
  const token = await tokenField.inputValue();
  assert.equal(token.length, 43);
  const consoleField = page.getByLabel("Console HTTPS address", {
    exact: true,
  });
  assert.equal(await consoleField.inputValue(), origin);
  assert.equal(await consoleField.getAttribute("readonly"), "");
  await page
    .getByRole("button", { name: "Copy console address", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Copied address", exact: true })
    .waitFor();
  assert.equal(
    await page.evaluate(() => navigator.clipboard.readText()),
    origin,
  );
  await page.getByRole("button", { name: "Copy token", exact: true }).click();
  await page.getByRole("button", { name: "Copied", exact: true }).waitFor();
  for (let step = 0; step < 12; step++) {
    await page.keyboard.press(step < 6 ? "Tab" : "Shift+Tab");
    assert.ok(
      await page.evaluate(() =>
        document
          .querySelector("dialog[open]")
          ?.contains(document.activeElement),
      ),
    );
  }
  await closeDialogOnce(() => page.keyboard.press("Escape"));
  await dialog.waitFor({ state: "hidden" });
  assert.equal(await tokenField.count(), 0);
  assert.ok(
    await opener.evaluate((element) => element === document.activeElement),
  );
  const storage = await page.evaluate(() =>
    JSON.stringify({
      local: { ...localStorage },
      session: { ...sessionStorage },
    }),
  );
  assert.ok(!storage.includes(token) && !storage.includes(session.value));
  await page.request.post(origin + "/test/short-token");
  await opener.click();
  await page
    .getByRole("button", { name: "Generate token", exact: true })
    .click();
  await tokenField.waitFor();
  await page
    .getByText("This token expired. Generate a new one when you are ready.")
    .waitFor();
  assert.equal(await tokenField.count(), 0);
  await closeDialogOnce(() =>
    page.getByRole("button", { name: "Close dialog" }).click(),
  );
  console.log(
    "Dialog Escape and close button each triggered exactly one active inventory refresh.",
  );
  await page.request.post(origin + "/test/devices");
  await page
    .getByText("Branch office", { exact: true })
    .waitFor({ timeout: 8000 });
  let activeInventoryRequests = 0;
  const branch = page.getByRole("row").filter({ hasText: "Branch office" });
  const lab = page.getByRole("row").filter({ hasText: "Lab gateway" });
  assert.equal(
    await lab.getByRole("button", { name: "Open", exact: true }).isDisabled(),
    true,
  );
  let opens = 0;
  page.on("request", (request) => {
    if (request.url().endsWith("/open")) opens++;
  });
  const routerURL = "https://branch.router.example.com:8443/";
  await context.route(routerURL, async (route) => {
    const headers = await route.request().allHeaders();
    assert.equal(headers.cookie, undefined, "Console cookie reached router");
    assert.equal(headers.referer, undefined, "Console referrer reached router");
    await route.fulfill({
      contentType: "text/html",
      body: "<!doctype html><title>Isolated router</title><p>Router login</p>",
    });
  });
  for (let attempt = 1; attempt <= 2; attempt++) {
    const popupEvent = context.waitForEvent("page");
    await branch.getByRole("button", { name: "Open", exact: true }).click();
    const popup = await popupEvent;
    await popup.waitForURL(routerURL);
    assert.equal(await popup.evaluate(() => window.opener), null);
    assert.equal(await popup.evaluate(() => document.referrer), "");
    assert.equal(opens, attempt, "Only explicit clicks renew access");
    await popup.close();
  }
  await page.evaluate(() => {
    window.fixtureOpen = window.open;
    window.open = () => null;
  });
  await branch.getByRole("button", { name: "Open", exact: true }).click();
  const fallback = branch.getByRole("link", { name: "Continue to router" });
  await fallback.waitFor();
  assert.equal(await fallback.getAttribute("href"), routerURL);
  assert.equal(await fallback.getAttribute("rel"), "noopener noreferrer");
  assert.equal(opens, 3);
  await page.evaluate(() => {
    window.open = window.fixtureOpen;
    delete window.fixtureOpen;
  });
  await page.route("**/api/v1/console/devices/*/open", (route) =>
    route.fulfill({
      status: 409,
      contentType: "application/json",
      body: JSON.stringify({
        error: {
          code: "device_revoked",
          message: "This device has been revoked",
        },
      }),
    }),
  );
  const rejectedPopup = context.waitForEvent("page");
  await branch.getByRole("button", { name: "Open", exact: true }).click();
  const rejected = await rejectedPopup;
  if (!rejected.isClosed()) await rejected.waitForEvent("close");
  await branch.getByRole("alert").waitFor();
  await page.unroute("**/api/v1/console/devices/*/open");
  const explicitOpens = opens;
  console.log(
    "Explicit Open and renewal passed with disabled pending certificate, detached opener, no referrer/cookie leakage and rejected-popup cleanup.",
  );
  let maximumInventoryRequests = 0;
  let finishSlowInventory;
  const slowInventory = new Promise((resolve) => {
    finishSlowInventory = resolve;
  });
  const inventoryRoute = /\/api\/v1\/console\/devices(?:\?|$)/;
  await page.route(inventoryRoute, async (route) => {
    assert.equal(route.request().headers()["x-nethub-background"], "1");
    activeInventoryRequests++;
    maximumInventoryRequests = Math.max(
      maximumInventoryRequests,
      activeInventoryRequests,
    );
    try {
      const response = await route.fetch();
      await new Promise((resolve) => setTimeout(resolve, 6500));
      await route.fulfill({ response });
    } finally {
      activeInventoryRequests--;
      finishSlowInventory();
    }
  });
  await Promise.race([
    slowInventory,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Inventory polling timed out")), 13000),
    ),
  ]);
  assert.equal(maximumInventoryRequests, 1);
  await page.unroute(inventoryRoute);
  await page.waitForFunction(
    () =>
      document
        .querySelector('[aria-label="Device inventory"]')
        .getAttribute("aria-busy") === "false",
  );
  await page.evaluate(() => {
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      get: () => "hidden",
    });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  const hiddenInventoryRequests = inventoryRequests;
  await page.waitForTimeout(6500);
  assert.equal(inventoryRequests, hiddenInventoryRequests);
  const resumedInventory = page.waitForRequest(
    (request) => new URL(request.url()).pathname === "/api/v1/console/devices",
    { timeout: 2000 },
  );
  await page.evaluate(() => {
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      get: () => "visible",
    });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await resumedInventory;
  await page.getByLabel("Search this page").fill("home");
  assert.equal(await page.getByRole("row").count(), 2);
  await page.getByLabel("Search this page").fill("");
  await page.screenshot({
    path: join(evidence, "devices-light.png"),
    fullPage: true,
  });
  await page.getByRole("button", { name: "Use dark theme" }).click();
  await page.screenshot({
    path: join(evidence, "devices-dark.png"),
    fullPage: true,
  });
  await page.setViewportSize({ width: 390, height: 844 });
  assert.ok(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  );
  await page.screenshot({
    path: join(evidence, "devices-mobile.png"),
    fullPage: true,
  });
  await page.setViewportSize({ width: 1440, height: 1000 });
  let revocations = 0;
  page.on("request", (request) => {
    if (request.url().endsWith("/revoke")) revocations++;
  });
  const revokeButton = branch.getByRole("button", {
    name: "Revoke",
    exact: true,
  });
  const revokeDialog = page.getByRole("dialog", {
    name: "Revoke device?",
    exact: true,
  });
  await revokeButton.click();
  await revokeDialog.waitFor();
  await page.screenshot({
    path: join(evidence, "revoke-confirmation.png"),
    fullPage: true,
  });
  await revokeDialog
    .getByRole("button", { name: "Cancel", exact: true })
    .click();
  await revokeDialog.waitFor({ state: "hidden" });
  await revokeButton.click();
  await page.keyboard.press("Escape");
  await revokeDialog.waitFor({ state: "hidden" });
  assert.equal(revocations, 0, "Dismissal must not revoke a device");
  await page.route("**/api/v1/console/devices/*/revoke", (route) =>
    route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({
        error: {
          code: "internal",
          message: "The request could not be completed",
        },
      }),
    }),
  );
  await revokeButton.click();
  await revokeDialog
    .getByRole("button", { name: "Permanently revoke", exact: true })
    .click();
  await revokeDialog.getByRole("alert").waitFor();
  assert.equal(await revokeDialog.isVisible(), true);
  assert.equal(
    await branch
      .getByRole("button", { name: "Open", exact: true })
      .isDisabled(),
    false,
  );
  await page.unroute("**/api/v1/console/devices/*/revoke");
  await revokeDialog
    .getByRole("button", { name: "Permanently revoke", exact: true })
    .click();
  await revokeDialog.waitFor({ state: "hidden" });
  await branch.getByText("Revoked", { exact: true }).first().waitFor();
  assert.equal(
    await branch
      .getByRole("button", { name: "Open", exact: true })
      .isDisabled(),
    true,
  );
  assert.equal(await revokeButton.isDisabled(), true);
  assert.equal(
    await branch.getByRole("link", { name: "Continue to router" }).count(),
    0,
  );
  assert.equal(revocations, 2, "Only explicit confirmation may call revoke");
  await page.screenshot({
    path: join(evidence, "revoked-inventory.png"),
    fullPage: true,
  });
  console.log(
    "Console revoke passed native confirmation, Cancel/Escape without mutation, retained error retry, disabled Open and cleared continuation after success.",
  );
  await opener.click();
  await page.request.post(origin + "/test/expire");
  await page
    .getByRole("button", { name: "Generate token", exact: true })
    .click();
  await page.getByRole("heading", { name: "Sign in to NetHub" }).waitFor();
  assert.equal(await tokenField.count(), 0);
  await login();
  await page.getByRole("button", { name: "Sign out" }).click();
  await page.getByRole("heading", { name: "Sign in to NetHub" }).waitFor();
  assert.deepEqual(violations, []);
  assert.deepEqual(failures, []);
  assert.deepEqual(external, []);
  assert.equal(opens, explicitOpens, "Polling must never renew access");
  assert.ok(!serverLog.includes(token) && !serverLog.includes(session.value));
  writeFileSync(
    join(evidence, "results.json"),
    JSON.stringify(
      {
        passed: true,
        cspViolations: violations.length,
        browserErrors: failures.length,
        externalRequests: external.length,
        checked: [
          "login",
          "reload",
          "empty inventory",
          "automatic inventory updates",
          "explicit Open and renewal",
          "certificate readiness gating",
          "router opener and credential isolation",
          "failed Open popup cleanup",
          "explicit permanent revocation confirmation and failure retry",
          "non-overlapping inventory requests",
          "hidden inventory polling pause and resume",
          "enrollment",
          "copy",
          "modal focus",
          "Escape",
          "token clearing",
          "expiry",
          "search",
          "light/dark",
          "mobile",
          "401 redirect",
          "logout",
        ],
        backend:
          "isolated in-memory fixture using production authentication and HTTP handlers; PostgreSQL boundaries are tested separately",
      },
      null,
      2,
    ),
  );
  console.log(
    "Browser flows passed: zero CSP violations, browser errors, or external requests.",
  );
  console.log(
    "Automatic inventory refresh passed without reload, with non-overlapping requests and hidden-page pause/resume.",
  );
} finally {
  await browser?.close();
  if (child.exitCode === null) {
    const exited = new Promise((resolve) => child.once("exit", resolve));
    child.kill();
    await exited;
  }
  if (
    dirname(stage) === resolve(tmpdir()) &&
    basename(stage).startsWith("nethub-ui-") &&
    !evidence.startsWith(stage)
  )
    rmSync(stage, { recursive: true, force: true });
}
