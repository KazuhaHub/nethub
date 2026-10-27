import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { connect } from "node:net";
import { join } from "node:path";
import { chromium } from "playwright";

const [portText, passwordFile, evidence] = process.argv.slice(2);
const port = Number(portText),
  origin = "https://console.example.com";
assert.ok(
  Number.isInteger(port) &&
    port > 0 &&
    port < 65536 &&
    passwordFile &&
    evidence,
);
const password = readFileSync(passwordFile, "utf8").trimEnd();
const sockets = new Set();
let refused = 0,
  violations = 0,
  errors = 0,
  browser;
const proxy = createServer((_request, response) => {
  refused++;
  response.writeHead(403).end();
});
proxy.on("connect", (request, client, head) => {
  if (request.url !== "console.example.com:443") {
    refused++;
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
try {
  browser = await chromium.launch({
    headless: true,
    channel: process.env.PLAYWRIGHT_CHANNEL || undefined,
    proxy: { server: `http://127.0.0.1:${proxy.address().port}` },
  });
  // Only the isolated deployment's private Caddy CA is bypassed in this browser.
  // The companion real relay transfer independently verifies its backend TLS CA.
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    viewport: { width: 1440, height: 1000 },
  });
  await context.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", () => {
      window.__trafficCSP = (window.__trafficCSP || 0) + 1;
    });
  });
  const page = await context.newPage();
  page.setDefaultTimeout(15000);
  page.on("pageerror", () => errors++);
  await page.goto(origin + "/traffic");
  await page.getByLabel("Email address").fill("compose-admin@example.com");
  for (let attempt = 0; attempt < 2; attempt++) {
    await page.getByLabel("Password", { exact: true }).fill(password);
    const reply = page.waitForResponse(
      (response) =>
        new URL(response.url()).pathname === "/api/v1/console/login" &&
        response.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    const response = await reply;
    if (response.status() === 429 && attempt === 0) {
      const delay = Number(response.headers()["retry-after"]);
      assert.ok(Number.isInteger(delay) && delay >= 1 && delay <= 60);
      await page.waitForTimeout(delay * 1000 + 100);
      continue;
    }
    assert.equal(
      response.status(),
      200,
      "Isolated traffic browser login failed",
    );
    break;
  }
  await page.getByRole("heading", { name: "Traffic", exact: true }).waitFor();
  await page.getByText(/Monthly warning exceeded/).waitFor();
  assert.ok((await page.locator("tbody tr").count()) >= 2);
  const next = page.waitForResponse(
    (response) =>
      new URL(response.url()).pathname === "/api/v1/console/traffic" &&
      response.request().headers()["x-nethub-background"] === "1",
  );
  const response = await next;
  assert.equal(response.status(), 200);
  const report = await response.json();
  assert.ok(
    BigInt(report.total_bytes) >= 131072n &&
      report.warning &&
      report.warning_bytes === "1",
  );
  assert.equal(
    report.items.reduce((sum, item) => sum + BigInt(item.total_bytes), 0n),
    BigInt(report.total_bytes),
  );
  violations = await page.evaluate(() => window.__trafficCSP || 0);
  assert.equal(violations, 0);
  assert.equal(errors, 0);
  assert.equal(refused, 0);
  const name = "deployed-traffic.png";
  await page.screenshot({
    path: join(evidence, name),
    animations: "disabled",
    mask: [page.locator(".account-email"), page.locator(".traffic-device-id")],
  });
  writeFileSync(
    join(evidence, "traffic-deployment-results.json"),
    JSON.stringify(
      {
        passed: true,
        genuine_deployed_console: true,
        actual_relay_totals_positive: true,
        warning_only: true,
        cspViolations: violations,
        browserErrors: errors,
        unexpectedProxyConnections: refused,
        public_TLS_or_native_appliance_claimed: false,
        screenshots: [
          {
            name,
            sha256: createHash("sha256")
              .update(readFileSync(join(evidence, name)))
              .digest("hex"),
          },
        ],
      },
      null,
      2,
    ),
  );
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await page
    .getByRole("heading", { name: "Sign in to NetHub", exact: true })
    .waitFor();
  console.log(
    "Deployed traffic console rendered actual persisted relay totals and warning under strict CSP; isolated private-CA browser scope only.",
  );
} finally {
  await browser?.close();
  for (const socket of sockets) socket.destroy();
  await new Promise((resolve) => proxy.close(resolve));
}
