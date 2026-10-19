import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, statSync, mkdirSync, writeFileSync } from "node:fs";
import { isIP } from "node:net";
import { join, resolve } from "node:path";
import { chromium } from "playwright";
import { probePublicTLS } from "./public-tls.mjs";

const configFile = process.argv[2] ? resolve(process.argv[2]) : null;
let browser;
try {
  assert.ok(
    configFile && process.argv.length === 3,
    "Pass one private configuration file",
  );
  assert.ok(statSync(configFile).isFile() && statSync(configFile).size < 8192);
  const config = JSON.parse(readFileSync(configFile, "utf8"));
  const url = new URL(config.origin);
  assert.ok(url.protocol === "https:" && !url.username && !url.password);
  assert.ok(
    url.port === "" && isIP(url.hostname) === 0 && url.hostname.includes("."),
  );
  assert.ok(url.href === url.origin + "/");
  const origin = url.origin;
  const secretInfo = statSync(config.passwordFile);
  assert.ok(secretInfo.isFile() && secretInfo.size < 1024);
  if (process.platform !== "win32")
    assert.equal(secretInfo.mode & 0o777, 0o600);
  const password = readFileSync(config.passwordFile, "utf8").replace(
    /\r?\n$/,
    "",
  );
  assert.ok(password.length >= 15 && password.length <= 1024);
  const evidence = resolve(config.evidenceDirectory);
  mkdirSync(evidence, { recursive: true, mode: 0o700 });
  const certificate = await probePublicTLS(origin);
  assert.ok(
    certificate.status === 200 &&
      certificate.authorized &&
      certificate.fingerprint256,
  );
  const health = await probePublicTLS(origin, "/healthz");
  assert.equal(health.status, 404);
  browser = await chromium.launch({
    headless: true,
    channel: process.env.PLAYWRIGHT_CHANNEL || undefined,
    args: ["--no-proxy-server"],
  });
  const context = await browser.newContext({
    ignoreHTTPSErrors: false,
    viewport: { width: 1440, height: 1000 },
  });
  const page = await context.newPage();
  page.setDefaultTimeout(15000);
  let violations = 0;
  let errors = 0;
  let external = 0;
  await context.exposeBinding("recordPublicCSP", () => violations++);
  await context.addInitScript(() =>
    document.addEventListener("securitypolicyviolation", () =>
      window.recordPublicCSP(),
    ),
  );
  page.on("pageerror", () => errors++);
  page.on("request", (req) => {
    if (!req.url().startsWith(origin + "/")) external++;
  });
  await page.goto(origin);
  await page.getByRole("heading", { name: "Sign in to NetHub" }).waitFor();
  await page.screenshot({
    path: join(evidence, "public-login.png"),
    fullPage: true,
  });
  await page.getByLabel("Email address").fill(config.email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page
    .getByRole("heading", { name: "Your network starts here" })
    .waitFor();
  const session = (await context.cookies()).find(
    (cookie) => cookie.name === "__Host-nethub_session",
  );
  assert.ok(
    session?.secure && session.httpOnly && session.domain === url.hostname,
  );
  await page.reload();
  await page
    .getByRole("heading", { name: "Your network starts here" })
    .waitFor();
  await page.screenshot({
    path: join(evidence, "public-empty.png"),
    fullPage: true,
  });
  await page.getByRole("button", { name: "Add device", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Add a device" });
  await dialog.waitFor();
  await page
    .getByRole("button", { name: "Generate token", exact: true })
    .click();
  const tokenField = page.getByLabel("Enrollment token", { exact: true });
  await tokenField.waitFor();
  const token = await tokenField.inputValue();
  assert.equal(token.length, 43);
  await page.screenshot({
    path: join(evidence, "public-enrollment-masked.png"),
    mask: [tokenField],
    fullPage: true,
  });
  await page.keyboard.press("Escape");
  await dialog.waitFor({ state: "hidden" });
  assert.equal(await tokenField.count(), 0);
  const storage = await page.evaluate(() =>
    JSON.stringify({
      local: { ...localStorage },
      session: { ...sessionStorage },
    }),
  );
  assert.ok(
    ![password, token, session.value].some((secret) =>
      storage.includes(secret),
    ),
  );
  await page.setViewportSize({ width: 390, height: 844 });
  assert.ok(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  );
  await page.screenshot({
    path: join(evidence, "public-mobile.png"),
    fullPage: true,
  });
  await page.getByRole("button", { name: "Sign out" }).click();
  await page.getByRole("heading", { name: "Sign in to NetHub" }).waitFor();
  assert.ok(
    !(await context.cookies()).some(
      (cookie) => cookie.name === "__Host-nethub_session",
    ),
  );
  const protectedStatus = await page.evaluate(async () => {
    const response = await fetch("/api/v1/console/devices", {
      credentials: "same-origin",
    });
    await response.text();
    return response.status;
  });
  assert.equal(protectedStatus, 401);
  assert.equal(violations, 0);
  assert.equal(errors, 0);
  assert.equal(external, 0);
  writeFileSync(
    configFile + ".secret-hashes.json",
    JSON.stringify(
      [token, session.value].map((value) =>
        createHash("sha256").update(value).digest("hex"),
      ),
    ),
    { mode: 0o600 },
  );
  writeFileSync(
    join(evidence, "public-results.json"),
    JSON.stringify(
      {
        passed: true,
        tlsVerified: true,
        certificate,
        publicHealthStatus: health.status,
        cspViolations: violations,
        browserErrors: errors,
        externalRequests: external,
        checked: [
          "public CA and hostname",
          "private health denial",
          "administrator login",
          "session cookie and reload",
          "empty inventory",
          "enrollment and clearing",
          "storage exclusion",
          "mobile",
          "logout and protected 401",
        ],
        scope:
          "real public endpoint; clean-host provenance must be established separately",
      },
      null,
      2,
    ),
    { mode: 0o600 },
  );
  console.log("Public console HTTPS and browser acceptance passed.");
} catch (error) {
  if (configFile)
    writeFileSync(configFile + ".error.txt", String(error?.stack || error), {
      mode: 0o600,
    });
  console.error(
    "Public console acceptance failed; diagnostics remain beside the private configuration file.",
  );
  process.exitCode = 1;
} finally {
  await browser?.close();
}
