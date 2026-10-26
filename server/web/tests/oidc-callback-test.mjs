import assert from "node:assert/strict";
import { createServer } from "node:http";
import { chromium } from "playwright";
import { captureCallback, observeAuthorization } from "./oidc-callback.mjs";
import { observeSAMLAuthorization } from "./saml-callback.mjs";

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
  } else if (url.pathname === "/start") {
    response.writeHead(200, { "Content-Type": "application/json" }).end(
      JSON.stringify({
        redirect_url: `http://localhost:${server.address().port}/auth?client_id=demo-client&state=demo-state&nonce=demo-nonce&code_challenge=demo-challenge`,
      }),
    );
  } else if (url.pathname === "/sso") {
    response
      .writeHead(200, { "Content-Type": "text/html" })
      .end(
        '<button id="sso">Start SSO</button><script>document.querySelector("#sso").onclick = async () => { const data = await (await fetch("/start")).json(); location.assign(data.redirect_url); };</script>',
      );
  } else if (url.pathname === "/saml-start") {
    response
      .writeHead(200, { "Content-Type": "application/json" })
      .end(
        JSON.stringify({
          redirect_url: `http://localhost:${server.address().port}/saml-auth?SAMLRequest=request-bytes&RelayState=relay-bytes&Signature=signature-bytes&SigAlg=rsa-sha256`,
        }),
      );
  } else if (url.pathname === "/saml-sso") {
    response
      .writeHead(200, { "Content-Type": "text/html" })
      .end(
        '<button id="saml">Start SAML</button><script>document.querySelector("#saml").onclick = async () => { const data = await (await fetch("/saml-start")).json(); location.assign(data.redirect_url); };</script>',
      );
  } else if (url.pathname === "/auth" || url.pathname === "/saml-auth") {
    response.writeHead(200, { "Content-Type": "text/plain" }).end("IdP login");
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
  await page.goto(origin + "/sso");
  const idpOrigin = `http://localhost:${server.address().port}`;
  const authorization = observeAuthorization(page, idpOrigin, "demo-client");
  try {
    await page.getByRole("button", { name: "Start SSO", exact: true }).click();
    await page.waitForURL((url) => url.origin === idpOrigin);
    await page.getByText("IdP login", { exact: true }).waitFor();
    const outgoing = new URL(authorization.url);
    assert.equal(outgoing.searchParams.get("state"), "demo-state");
    assert.equal(outgoing.searchParams.get("nonce"), "demo-nonce");
    assert.equal(outgoing.searchParams.get("code_challenge"), "demo-challenge");
  } finally {
    authorization.close();
  }
  await page.goto(origin + "/saml-sso");
  const saml = observeSAMLAuthorization(page, idpOrigin, "/saml-auth");
  try {
    await page.getByRole("button", { name: "Start SAML", exact: true }).click();
    await page.waitForURL(
      (url) => url.origin === idpOrigin && url.pathname === "/saml-auth",
    );
    const outgoing = new URL(saml.url);
    assert.equal(outgoing.searchParams.get("SAMLRequest"), "request-bytes");
    assert.equal(outgoing.searchParams.get("RelayState"), "relay-bytes");
    assert.equal(outgoing.searchParams.get("Signature"), "signature-bytes");
    assert.equal(outgoing.searchParams.get("SigAlg"), "rsa-sha256");
  } finally {
    saml.close();
  }
  console.log(
    "Actual browser asynchronous SAML navigation preserved request, relay and signature fields after leaving its response document.",
  );
  console.log(
    "Actual browser POST/302 callback capture and removal of the test-only parking header passed.",
  );
  console.log(
    "Actual browser asynchronous SSO navigation preserved state, nonce and PKCE after leaving its response document.",
  );
} finally {
  await browser?.close();
  await new Promise((resolve) => server.close(resolve));
}
