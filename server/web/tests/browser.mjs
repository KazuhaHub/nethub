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
  await page.keyboard.press("Escape");
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
  await page.getByRole("button", { name: "Close dialog" }).click();
  await page.request.post(origin + "/test/devices");
  await page
    .getByText("Branch office", { exact: true })
    .waitFor({ timeout: 8000 });
  let activeInventoryRequests = 0;
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
