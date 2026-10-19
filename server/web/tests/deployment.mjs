import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, statSync, mkdirSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { connect } from "node:net";
import { join } from "node:path";
import { chromium } from "playwright";

const [portText, passwordFile, evidence, databaseContainer, webContainer] =
  process.argv.slice(2);
const port = Number(portText);
assert.ok(Number.isInteger(port) && port > 0 && port < 65536);
assert.ok(passwordFile && evidence && databaseContainer && webContainer);
function docker(args) {
  const result = spawnSync("docker", args, {
    encoding: "utf8",
    maxBuffer: 4 * 1024 * 1024,
  });
  assert.ok(result.status === 0, "Isolated Docker check failed");
  return result.stdout + result.stderr;
}
const info = statSync(passwordFile);
assert.ok(info.isFile() && info.size < 1024);
if (process.platform !== "win32") assert.equal(info.mode & 0o777, 0o600);
const password = readFileSync(passwordFile, "utf8").replace(/\n$/, "");
assert.ok(password.length >= 15 && password.length <= 1024);
mkdirSync(evidence, { recursive: true });
const origin = "https://console.example.com";
const sockets = new Set();
let refusedConnections = 0;
const proxy = createServer((_request, response) => {
  refusedConnections++;
  response.writeHead(403).end();
});
// Preserve the production HTTPS origin while forwarding only this test host.
// CONNECT passes TLS through unchanged to Caddy's private loopback listener.
proxy.on("connect", (request, client, head) => {
  if (request.url !== "console.example.com:443") {
    refusedConnections++;
    client.destroy();
    return;
  }
  const upstream = connect({ host: "127.0.0.1", port });
  for (const socket of [client, upstream]) {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  }
  client.on("error", () => upstream.destroy());
  upstream.on("error", () => client.destroy());
  upstream.once("connect", () => {
    client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (head.length) upstream.write(head);
    client.pipe(upstream);
    upstream.pipe(client);
  });
});
await new Promise((resolve, reject) => {
  proxy.once("error", reject);
  proxy.listen(0, "127.0.0.1", resolve);
});

let browser;
try {
  browser = await chromium.launch({
    headless: true,
    channel: process.env.PLAYWRIGHT_CHANNEL || undefined,
    proxy: { server: `http://127.0.0.1:${proxy.address().port}` },
  });
  const context = await browser.newContext({
    // Only this isolated test's internal Caddy CA is untrusted by Chromium.
    // Public ACME acceptance must use a separate certificate-verifying run.
    ignoreHTTPSErrors: true,
    viewport: { width: 1440, height: 1000 },
  });
  await context.grantPermissions(["clipboard-read", "clipboard-write"], {
    origin,
  });
  const page = await context.newPage();
  page.setDefaultTimeout(15000);
  let cspViolations = 0;
  let browserErrors = 0;
  let externalRequests = 0;
  let failedRequests = 0;
  await context.exposeBinding("recordDeploymentCSP", () => cspViolations++);
  await context.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", () =>
      window.recordDeploymentCSP(),
    );
  });
  page.on("pageerror", () => browserErrors++);
  page.on("requestfailed", () => failedRequests++);
  page.on("request", (request) => {
    if (!request.url().startsWith(origin + "/")) externalRequests++;
  });
  await page.goto(origin);
  await page.getByRole("heading", { name: "Sign in to NetHub" }).waitFor();
  await page.screenshot({ path: join(evidence, "login.png"), fullPage: true });
  const login = async () => {
    await page.getByLabel("Email address").fill("compose-admin@example.com");
    await page.getByLabel("Password", { exact: true }).fill(password);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page.getByRole("heading", { name: "Devices", exact: true }).waitFor();
    await page
      .getByRole("heading", { name: "Your network starts here" })
      .waitFor();
  };
  await login();
  const session = (await context.cookies()).find(
    (cookie) => cookie.name === "__Host-nethub_session",
  );
  assert.ok(session?.secure && session.httpOnly && session.path === "/");
  assert.ok(
    session.sameSite === "Lax" && session.domain === "console.example.com",
  );
  assert.ok(
    !(await page.evaluate(() => document.cookie)).includes(session.value),
  );
  await page.reload();
  await page
    .getByRole("heading", { name: "Your network starts here" })
    .waitFor();
  await page.screenshot({
    path: join(evidence, "empty-inventory.png"),
    fullPage: true,
  });
  const opener = page.getByRole("button", { name: "Add device", exact: true });
  const dialog = page.getByRole("dialog", { name: "Add a device" });
  const tokenField = page.getByLabel("Enrollment token", { exact: true });
  const tokens = [];
  for (let attempt = 0; attempt < 2; attempt++) {
    await opener.click();
    await dialog.waitFor();
    await page
      .getByRole("button", { name: "Generate token", exact: true })
      .click();
    await tokenField.waitFor();
    const token = await tokenField.inputValue();
    assert.equal(token.length, 43);
    assert.ok(
      !tokens.includes(token),
      "Enrollment tokens must be freshly generated",
    );
    tokens.push(token);
    await page.getByRole("button", { name: "Copy token", exact: true }).click();
    await page.getByRole("button", { name: "Copied", exact: true }).waitFor();
    assert.ok(
      (await page.evaluate(() => navigator.clipboard.readText())) === token,
    );
    await page.evaluate(() => navigator.clipboard.writeText(""));
    if (attempt === 0) {
      await page.screenshot({
        path: join(evidence, "enrollment-masked.png"),
        mask: [tokenField],
        fullPage: true,
      });
    }
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
  }
  const stored = await page.evaluate(() =>
    JSON.stringify({
      local: { ...localStorage },
      session: { ...sessionStorage },
    }),
  );
  for (const secret of [...tokens, session.value, password]) {
    assert.ok(
      !stored.includes(secret),
      "Secrets must not enter browser storage",
    );
  }
  await page.setViewportSize({ width: 390, height: 844 });
  assert.ok(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  );
  await page.screenshot({ path: join(evidence, "mobile.png"), fullPage: true });
  await opener.click();
  await dialog.waitFor();
  // Expire real database sessions without adding any production test endpoint.
  docker([
    "exec",
    "-u",
    "postgres",
    databaseContainer,
    "psql",
    "-X",
    "-v",
    "ON_ERROR_STOP=1",
    "-d",
    "nethub",
    "-c",
    "UPDATE sessions SET expires_at = clock_timestamp() - interval '1 second'",
  ]);
  await page
    .getByRole("button", { name: "Generate token", exact: true })
    .click();
  await page.getByRole("heading", { name: "Sign in to NetHub" }).waitFor();
  assert.equal(await tokenField.count(), 0);
  await login();
  const renewed = (await context.cookies()).find(
    (cookie) => cookie.name === "__Host-nethub_session",
  );
  assert.ok(renewed && renewed.value !== session.value);
  await page.getByRole("button", { name: "Sign out" }).click();
  await page.getByRole("heading", { name: "Sign in to NetHub" }).waitFor();
  assert.ok(
    !(await context.cookies()).some(
      (cookie) => cookie.name === "__Host-nethub_session",
    ),
  );
  await page.reload();
  await page.getByRole("heading", { name: "Sign in to NetHub" }).waitFor();
  assert.equal(cspViolations, 0, "CSP violations occurred");
  assert.equal(browserErrors, 0, "Browser script errors occurred");
  assert.equal(externalRequests, 0, "Unexpected external requests occurred");
  assert.equal(failedRequests, 0, "Network requests failed");
  assert.equal(refusedConnections, 0, "Unexpected proxy destinations occurred");
  const runtimeLog = docker(["logs", webContainer]);
  for (const secret of [...tokens, session.value, renewed.value, password]) {
    assert.ok(
      !runtimeLog.includes(secret),
      "A secret appeared in runtime logs",
    );
  }
  writeFileSync(
    join(evidence, "results.json"),
    JSON.stringify(
      {
        passed: true,
        backend:
          "fresh Compose project: Caddy, embedded web assets, actual PostgreSQL roles and sessions",
        tls: "internal test CA; public ACME is not covered",
        cspViolations,
        browserErrors,
        externalRequests,
        failedRequests,
        checked: [
          "initial administrator login",
          "session cookie",
          "reload",
          "empty inventory",
          "fresh enrollment tokens",
          "clipboard",
          "dialog focus and Escape",
          "secret storage exclusion",
          "mobile",
          "database session expiry",
          "logout",
        ],
      },
      null,
      2,
    ),
  );
  console.log(
    "Deployed browser flows passed against Caddy/PostgreSQL: zero CSP violations, browser errors, external requests, or network failures.",
  );
} finally {
  await browser?.close();
  for (const socket of sockets) socket.destroy();
  await new Promise((resolve) => proxy.close(resolve));
}
