import assert from "node:assert/strict";
import { createServer } from "node:http";
import { chromium } from "playwright";
import { captureCallback } from "./oidc-callback.mjs";

const callbacks = [];
const server = createServer((request, response) => {
  const url = new URL(request.url, "http://localhost");
  if (url.pathname === "/login" && request.method === "POST") {
    response
      .writeHead(302, { Location: "/callback?code=demo-code&state=demo-state" })
      .end();
  } else if (url.pathname === "/callback") {
    callbacks.push({
      state: url.searchParams.get("state"),
      parked: request.headers["x-nethub-test-capture"] === "1",
    });
    response
      .writeHead(200, { "Content-Type": "text/plain" })
      .end("Callback captured");
  } else {
    response
      .writeHead(200, { "Content-Type": "text/html" })
      .end(
        '<form method="post" action="/login"><button>Submit</button></form>',
      );
  }
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
let browser;
try {
  browser = await chromium.launch({
    headless: true,
    ...(process.env.NETHUB_BROWSER_CHANNEL
      ? { channel: process.env.NETHUB_BROWSER_CHANNEL }
      : {}),
  });
  const page = await browser.newPage();
  page.setDefaultTimeout(5000);
  const origin = `http://127.0.0.1:${server.address().port}`;
  await page.goto(origin);
  await page.context().setExtraHTTPHeaders({ "X-Nethub-Test-Capture": "1" });
  const captured = await captureCallback(
    page,
    origin,
    "/callback",
    () => page.getByRole("button", { name: "Submit" }).click(),
    "Callback captured",
  );
  assert.equal(captured.searchParams.get("code"), "demo-code");
  assert.equal(captured.searchParams.get("state"), "demo-state");
  assert.deepEqual(callbacks, [{ state: "demo-state", parked: true }]);
  await page.context().setExtraHTTPHeaders({});
  captured.searchParams.set("state", "changed-state");
  await page.goto(captured.toString());
  assert.deepEqual(callbacks[1], { state: "changed-state", parked: false });
  console.log(
    "Actual browser POST/302 callback capture and removal of the test-only parking header passed.",
  );
} finally {
  await browser?.close();
  await new Promise((resolve) => server.close(resolve));
}
