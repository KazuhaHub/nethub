import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { request as httpsRequest } from "node:https";
import { connect } from "node:net";
import { join } from "node:path";
import { chromium } from "playwright";
import { observeSAMLAuthorization } from "./saml-callback.mjs";

const [
  portText,
  adminPasswordFile,
  fixture,
  browserHome,
  evidence,
  databaseContainer,
  webContainer,
] = process.argv.slice(2);
const port = Number(portText),
  origin = "https://console.example.com",
  idpOrigin = "https://saml.test";
assert.ok(Number.isInteger(port) && port > 0 && port < 65536);
assert.ok(
  adminPasswordFile &&
    fixture &&
    browserHome &&
    evidence &&
    databaseContainer &&
    webContainer,
);
const secrets = JSON.parse(
  readFileSync(join(fixture, "credentials.json"), "utf8"),
);
const adminPassword = readFileSync(adminPasswordFile, "utf8").trimEnd();
const ca = readFileSync(join(fixture, "root.crt"));
const privateValues = [
  adminPassword,
  secrets.password,
  ...Object.values(secrets.clients),
];
const checks = [],
  screenshots = [],
  contexts = [],
  sockets = new Set(),
  headerChecks = [];
const allowed = new Set(["console.example.com:443", "saml.test:443"]);
const attemptTimes = { start: [], callback: [] };
async function reserveAttempt(kind) {
  // Respect the production five-per-provider minute budget without changing it.
  const times = attemptTimes[kind];
  while (times.length && Date.now() - times[0] >= 60100) times.shift();
  if (times.length >= 5)
    await new Promise((resolve) =>
      setTimeout(resolve, 60100 - (Date.now() - times[0])),
    );
  while (times.length && Date.now() - times[0] >= 60100) times.shift();
  times.push(Date.now());
}
let browser,
  proxy,
  phase = "startup",
  unexpectedRequests = 0,
  cspViolations = 0,
  browserErrors = 0,
  cookieLeaks = 0;
mkdirSync(evidence, { recursive: true });
function command(args) {
  const result = spawnSync("docker", args, {
    encoding: "utf8",
    timeout: 20000,
    maxBuffer: 4 * 1024 * 1024,
  });
  assert.equal(result.status, 0, "Owned command failed");
  return result.stdout.trim();
}
function sql(query) {
  return command([
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
    "-Atqc",
    query,
  ]);
}
function quote(value) {
  assert.equal(typeof value, "string");
  assert.ok(!value.includes("\0"));
  return "'" + value.replaceAll("'", "''") + "'";
}
function count(table, where = "true") {
  assert.ok(
    ["users", "user_identities", "sessions", "invites", "saml_flows"].includes(
      table,
    ),
  );
  return Number(sql(`SELECT count(*) FROM ${table} WHERE ${where}`));
}
async function api(page, path, method = "GET", body, csrf) {
  return page.evaluate(
    async ({ path, method, body, csrf }) => {
      const headers = { Accept: "application/json" };
      if (body !== undefined) headers["Content-Type"] = "application/json";
      if (csrf) headers["X-CSRF-Token"] = csrf;
      const reply = await fetch("/api/v1/console" + path, {
        method,
        headers,
        cache: "no-store",
        credentials: "same-origin",
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      return {
        status: reply.status,
        data: await reply.json().catch(() => null),
      };
    },
    { path, method, body, csrf },
  );
}
function idp(path, { method = "GET", body, token, form = false } = {}) {
  assert.ok(path.startsWith("/") && !path.startsWith("//"));
  const bytes =
    body === undefined
      ? undefined
      : Buffer.from(
          form ? new URLSearchParams(body).toString() : JSON.stringify(body),
        );
  return new Promise((resolve, reject) => {
    const request = httpsRequest(
      {
        hostname: "127.0.0.1",
        port,
        servername: "saml.test",
        ca,
        rejectUnauthorized: true,
        method,
        path,
        headers: {
          Host: "saml.test",
          ...(token ? { Authorization: "Bearer " + token } : {}),
          ...(bytes
            ? {
                "Content-Type": form
                  ? "application/x-www-form-urlencoded"
                  : "application/json",
                "Content-Length": bytes.length,
              }
            : {}),
        },
      },
      (response) => {
        let size = 0;
        const chunks = [];
        response.on("data", (chunk) => {
          size += chunk.length;
          if (size > 2 * 1024 * 1024)
            response.destroy(new Error("Bounded IdP response exceeded limit"));
          else chunks.push(chunk);
        });
        response.on("error", reject);
        response.on("end", () =>
          resolve({
            status: response.statusCode,
            text: Buffer.concat(chunks).toString("utf8"),
          }),
        );
      },
    );
    request.setTimeout(15000, () =>
      request.destroy(new Error("Bounded IdP request timed out")),
    );
    request.on("error", reject);
    request.end(bytes);
  });
}
async function anonymous() {
  const context = await browser.newContext({
    ignoreHTTPSErrors: false,
    viewport: { width: 1440, height: 1000 },
  });
  contexts.push(context);
  await context.exposeBinding("recordSAMLCSP", ({ frame }) => {
    if (new URL(frame.url()).origin === origin) cspViolations++;
  });
  await context.addInitScript(() =>
    document.addEventListener("securitypolicyviolation", () =>
      window.recordSAMLCSP(),
    ),
  );
  const page = await context.newPage();
  page.setDefaultTimeout(15000);
  page.on("pageerror", () => browserErrors++);
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (
      url.protocol !== "data:" &&
      !allowed.has(url.hostname + ":" + (url.port || "443"))
    )
      unexpectedRequests++;
    if (url.origin === idpOrigin)
      headerChecks.push(
        request.allHeaders().then((headers) => {
          if (/__Host-nethub_(?:session|saml|oidc)=/.test(headers.cookie || ""))
            cookieLeaks++;
        }),
      );
  });
  await page.goto(origin);
  await page
    .getByRole("heading", { name: "Sign in to NetHub", exact: true })
    .waitFor();
  return { context, page };
}
async function localAdmin() {
  const client = await anonymous();
  await client.page
    .getByLabel("Email address", { exact: true })
    .fill("compose-admin@example.com");
  await client.page.getByLabel("Password", { exact: true }).fill(adminPassword);
  const response = client.page.waitForResponse(
    (reply) => new URL(reply.url()).pathname === "/api/v1/console/login",
  );
  await client.page
    .getByRole("button", { name: "Sign in", exact: true })
    .click();
  assert.equal((await response).status(), 200);
  const data = await (await response).json();
  assert.equal(data.user.role, "admin");
  privateValues.push(data.csrf_token);
  client.csrf = data.csrf_token;
  await client.page
    .getByRole("heading", { name: "Devices", exact: true })
    .waitFor();
  return client;
}
const callbackPath = "/api/v1/console/saml/keycloak/callback";
async function begin(client, grant) {
  await reserveAttempt("start");
  if (grant) {
    await client.page.goto(origin + "/invite#" + grant);
    await client.page
      .getByRole("button", {
        name: "Continue with Keycloak acceptance",
        exact: true,
      })
      .waitFor();
    assert.equal(new URL(client.page.url()).hash, "");
  }
  const response = client.page.waitForResponse(
    (reply) =>
      new URL(reply.url()).pathname === "/api/v1/console/saml/keycloak/start",
  );
  const authorization = observeSAMLAuthorization(
    client.page,
    idpOrigin,
    "/realms/nethub-saml/protocol/saml",
  );
  let redirect;
  try {
    await client.page
      .getByRole("button", {
        name: "Continue with Keycloak acceptance",
        exact: true,
      })
      .click();
    assert.equal((await response).status(), 200);
    await client.page.waitForURL((url) => url.origin === idpOrigin);
    assert.ok(authorization.url, "Signed SAML navigation was not observed");
    redirect = new URL(authorization.url);
  } finally {
    authorization.close();
  }
  assert.equal(redirect.origin, idpOrigin);
  for (const field of ["SAMLRequest", "RelayState", "Signature"]) {
    assert.ok(redirect.searchParams.get(field));
    privateValues.push(redirect.searchParams.get(field));
  }
  assert.equal(
    redirect.searchParams.get("SigAlg"),
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  );
  await client.page.waitForURL((url) => url.origin === idpOrigin);
  const cookies = (await client.context.cookies(origin)).filter(
    (cookie) => cookie.name === "__Host-nethub_saml",
  );
  assert.equal(cookies.length, 1);
  assert.ok(
    cookies[0].secure && cookies[0].httpOnly && cookies[0].sameSite === "None",
  );
  privateValues.push(cookies[0].value);
  return cookies;
}
async function keycloakLogin(client, username) {
  await client.page.locator("#username").fill(username);
  await client.page.locator("#password").fill(secrets.password);
  await client.page.locator("#kc-login").click();
}
async function outcome(client, email) {
  await client.page.waitForURL(
    (url) => url.origin === origin && !url.pathname.startsWith("/api/"),
  );
  if (!email) {
    assert.equal(new URL(client.page.url()).pathname, "/login");
    assert.equal(new URL(client.page.url()).search, "?error=sso_failed");
    assert.equal((await api(client.page, "/session")).data.signed_in, false);
    return;
  }
  await client.page
    .getByRole("heading", { name: "Devices", exact: true })
    .waitFor();
  const response = await api(client.page, "/session");
  assert.equal(response.status, 200);
  assert.equal(response.data.user.email, email);
  assert.equal(response.data.user.role, "member");
  assert.equal((await api(client.page, "/users")).status, 403);
  const session = (await client.context.cookies(origin)).find(
    (cookie) => cookie.name === "__Host-nethub_session",
  );
  assert.ok(session?.secure && session.httpOnly && session.sameSite === "Lax");
  privateValues.push(session.value, response.data.csrf_token);
  client.user = response.data.user;
}
async function signIn(username, grant, email = username + "@example.com") {
  const client = await anonymous();
  const packets = [];
  client.page.on("request", (request) => {
    if (
      new URL(request.url()).pathname === callbackPath &&
      request.method() === "POST"
    )
      packets.push(request.postData());
  });
  client.startCookies = await begin(client, grant);
  await reserveAttempt("callback");
  await keycloakLogin(client, username);
  await outcome(client, email);
  assert.equal(packets.length, 1);
  client.packet = packets[0];
  privateValues.push(
    client.packet,
    new URLSearchParams(client.packet).get("SAMLResponse"),
  );
  return client;
}
async function submit(client, packet, success = false) {
  await reserveAttempt("callback");
  const form = new URLSearchParams(packet);
  assert.deepEqual([...form.keys()].sort(), ["RelayState", "SAMLResponse"]);
  await client.page.goto(origin + "/login");
  const navigation = client.page.waitForURL(
    (url) =>
      url.origin === origin &&
      (success
        ? url.pathname === "/"
        : url.pathname === "/login" && url.search === "?error=sso_failed"),
  );
  await client.page.evaluate(
    ({ path, fields }) => {
      const form = document.createElement("form");
      form.method = "POST";
      form.action = path;
      for (const [name, value] of fields) {
        const input = document.createElement("input");
        input.type = "hidden";
        input.name = name;
        input.value = value;
        form.append(input);
      }
      document.body.append(form);
      form.submit();
    },
    { path: callbackPath, fields: [...form] },
  );
  return navigation;
}
async function capturedLogin(username) {
  const client = await anonymous();
  client.startCookies = await begin(client);
  await client.context.setExtraHTTPHeaders({ "X-Nethub-Test-Capture": "1" });
  const packet = client.page.waitForRequest(
    (request) =>
      new URL(request.url()).pathname === callbackPath &&
      request.method() === "POST",
  );
  await keycloakLogin(client, username);
  client.packet = (await packet).postData();
  await client.page
    .getByText("SAML callback captured", { exact: true })
    .waitFor();
  await client.context.setExtraHTTPHeaders({});
  privateValues.push(
    client.packet,
    new URLSearchParams(client.packet).get("SAMLResponse"),
  );
  return client;
}
async function screenshot(page, name) {
  await page.screenshot({ path: join(evidence, name), animations: "disabled" });
  screenshots.push({
    name,
    sha256: createHash("sha256")
      .update(readFileSync(join(evidence, name)))
      .digest("hex"),
  });
}
try {
  proxy = createServer((_request, response) => {
    unexpectedRequests++;
    response.writeHead(403).end();
  });
  proxy.on("connect", (request, client, head) => {
    if (!allowed.has(request.url)) {
      unexpectedRequests++;
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
  await new Promise((resolve) => proxy.listen(0, "127.0.0.1", resolve));
  browser = await chromium.launch({
    headless: true,
    env: { ...process.env, HOME: browserHome },
    proxy: { server: `http://127.0.0.1:${proxy.address().port}` },
  });
  phase = "admin_login";
  const admin = await localAdmin();
  assert.equal(count("users"), 1);
  phase = "provider_registration";
  const metadataReply = await idp(
    "/realms/nethub-saml/protocol/saml/descriptor",
  );
  assert.equal(metadataReply.status, 200);
  const entityID = idpOrigin + "/realms/nethub-saml";
  await admin.page.goto(origin + "/saml-providers");
  await admin.page
    .getByRole("button", { name: "Add SAML provider", exact: true })
    .click();
  const dialog = admin.page.getByRole("dialog");
  for (const [name, value] of [
    ["Display name", "Keycloak acceptance"],
    ["Slug", "keycloak"],
    ["IdP entity ID", entityID],
    ["Email attribute name", "mail"],
    ["IdP metadata XML", metadataReply.text],
  ])
    await dialog.getByLabel(name, { exact: true }).fill(value);
  const created = admin.page.waitForResponse(
    (reply) =>
      new URL(reply.url()).pathname === "/api/v1/console/saml-providers" &&
      reply.request().method() === "POST",
  );
  await dialog
    .getByRole("button", { name: "Save provider", exact: true })
    .click();
  assert.equal((await created).status(), 201);
  const provider = await (await created).json();
  assert.equal(provider.enabled, false);
  await dialog.waitFor({ state: "hidden" });
  const sp = await admin.page.evaluate(async () => {
    const response = await fetch("/api/v1/console/saml/keycloak/metadata");
    if (!response.ok) throw new Error("SP metadata unavailable");
    const xml = new DOMParser().parseFromString(
      await response.text(),
      "application/xml",
    );
    return {
      entity: xml.documentElement.getAttribute("entityID"),
      acs: xml
        .getElementsByTagNameNS(
          "urn:oasis:names:tc:SAML:2.0:metadata",
          "AssertionConsumerService",
        )[0]
        ?.getAttribute("Location"),
      cert: xml
        .getElementsByTagNameNS(
          "http://www.w3.org/2000/09/xmldsig#",
          "X509Certificate",
        )[0]
        ?.textContent.replace(/\s/g, ""),
    };
  });
  assert.equal(sp.entity, origin + "/api/v1/console/saml/keycloak/metadata");
  assert.equal(sp.acs, origin + callbackPath);
  assert.ok(sp.cert && Buffer.from(sp.cert, "base64").length > 500);
  const tokenReply = await idp("/realms/master/protocol/openid-connect/token", {
    method: "POST",
    form: true,
    body: {
      client_id: "admin-cli",
      grant_type: "password",
      username: "fixture-admin",
      password: secrets.clients.one,
    },
  });
  assert.equal(tokenReply.status, 200);
  const token = JSON.parse(tokenReply.text).access_token;
  assert.ok(token);
  privateValues.push(token);
  const registered = await idp("/admin/realms/nethub-saml/clients", {
    method: "POST",
    token,
    body: {
      clientId: sp.entity,
      name: "NetHub acceptance",
      protocol: "saml",
      enabled: true,
      redirectUris: [sp.acs],
      baseUrl: origin,
      frontchannelLogout: false,
      attributes: {
        "saml.signature.algorithm": "RSA_SHA256",
        saml_name_id_format: "persistent",
        saml_force_name_id_format: "true",
        "saml.authnstatement": "true",
        "saml.server.signature": "true",
        "saml.assertion.signature": "true",
        "saml.client.signature": "true",
        "saml.force.post.binding": "true",
        "saml.signing.certificate": sp.cert,
      },
      protocolMappers: [
        {
          name: "Signed email",
          protocol: "saml",
          protocolMapper: "saml-user-property-mapper",
          consentRequired: false,
          config: {
            "user.attribute": "email",
            "attribute.name": "mail",
            "attribute.nameformat": "Basic",
          },
        },
      ],
    },
  });
  assert.equal(registered.status, 201);
  await admin.page
    .getByRole("button", { name: "Edit Keycloak acceptance", exact: true })
    .click();
  await dialog.getByLabel("Enable console sign-in", { exact: true }).check();
  const enabled = admin.page.waitForResponse(
    (reply) =>
      new URL(reply.url()).pathname.endsWith(
        "/saml-providers/" + provider.id,
      ) && reply.request().method() === "PATCH",
  );
  await dialog
    .getByRole("button", { name: "Save provider", exact: true })
    .click();
  assert.equal((await enabled).status(), 200);
  await dialog.waitFor({ state: "hidden" });
  checks.push(
    "actual provider UI metadata import and actual SP public certificate registered with required signed requests",
  );
  async function invite(email) {
    const response = await api(
      admin.page,
      "/invites",
      "POST",
      { email, role: "member", provider_id: provider.id },
      admin.csrf,
    );
    assert.equal(response.status, 201);
    const url = new URL(response.data.invite_url);
    assert.equal(url.origin, origin);
    assert.equal(url.search, "");
    assert.match(url.hash.slice(1), /^[A-Za-z0-9_-]{43}$/);
    privateValues.push(url.hash.slice(1));
    return url.hash.slice(1);
  }
  phase = "alice_invitation";
  const alice = await signIn("alice", await invite("alice@example.com"));
  assert.equal(count("user_identities"), 1);
  assert.equal(
    count("users", "email='alice@example.com' AND password_hash IS NULL"),
    1,
  );
  assert.equal(
    count("invites", "email='alice@example.com' AND used_at IS NOT NULL"),
    1,
  );
  checks.push(
    "actual Keycloak signed email admits invited SAML member even when its OIDC emailVerified flag is false",
  );
  phase = "web_restart";
  command(["restart", "--time", "10", webContainer]);
  let healthy = false;
  for (let attempt = 0; attempt < 30; attempt++) {
    if (
      JSON.parse(
        command([
          "inspect",
          "--format",
          "{{json .State.Health.Status}}",
          webContainer,
        ]),
      ) === "healthy"
    ) {
      healthy = true;
      break;
    }
    await alice.page.waitForTimeout(1000);
  }
  assert.ok(healthy);
  assert.equal((await api(alice.page, "/session")).data.user.id, alice.user.id);
  checks.push(
    "actual Web restart preserves the database-backed SAML member session",
  );
  phase = "callback_replay";
  const replay = await anonymous(),
    sessionsBefore = count("sessions");
  await replay.context.addCookies(alice.startCookies);
  await submit(replay, alice.packet);
  await outcome(replay);
  assert.equal(count("sessions"), sessionsBefore);
  await replay.context.close();
  checks.push(
    "actual signed response replay with original browser cookie creates no new session",
  );
  phase = "bound_login";
  const bound = await signIn("alice");
  assert.equal(bound.user.id, alice.user.id);
  assert.equal(count("user_identities"), 1);
  await bound.context.close();
  checks.push(
    "fresh Keycloak session preserves persistent NameID binding without another invitation",
  );
  phase = "browser_binding";
  const captured = await capturedLogin("alice"),
    stranger = await anonymous();
  const beforeWrongBrowser = count("sessions");
  await stranger.context.addCookies(
    captured.startCookies.map((cookie) => ({
      ...cookie,
      value: Buffer.alloc(32, 7).toString("base64url"),
    })),
  );
  await submit(stranger, captured.packet);
  await outcome(stranger);
  assert.equal(count("sessions"), beforeWrongBrowser);
  const relay = new URLSearchParams(captured.packet).get("RelayState");
  const relayHash = createHash("sha256")
    .update(Buffer.from(relay, "base64url"))
    .digest("hex");
  assert.equal(
    count(
      "saml_flows",
      `state_hash=decode(${quote(relayHash)},'hex') AND consumed_at IS NULL`,
    ),
    1,
  );
  await stranger.context.close();
  await submit(captured, captured.packet, true);
  await outcome(captured, "alice@example.com");
  assert.equal(captured.user.id, alice.user.id);
  await captured.context.close();
  checks.push(
    "genuine parked IdP POST rejects a wrong browser without consuming its flow, then admits its original binding after the parking header is removed",
  );
  phase = "signature_tamper";
  const tampered = await capturedLogin("alice"),
    tamperedForm = new URLSearchParams(tampered.packet);
  const originalXML = Buffer.from(
    tamperedForm.get("SAMLResponse"),
    "base64",
  ).toString("utf8");
  assert.ok(originalXML.includes("alice@example.com"));
  const changedXML = originalXML.replaceAll(
    "alice@example.com",
    "other@example.com",
  );
  assert.notEqual(changedXML, originalXML);
  tamperedForm.set("SAMLResponse", Buffer.from(changedXML).toString("base64"));
  privateValues.push(originalXML, changedXML, tamperedForm.get("SAMLResponse"));
  const beforeTamper = count("sessions");
  await submit(tampered, tamperedForm.toString());
  await outcome(tampered);
  assert.equal(count("sessions"), beforeTamper);
  assert.equal(count("users", "email='other@example.com'"), 0);
  await tampered.context.close();
  checks.push(
    "modifying signed email in the actual Keycloak response is refused without another account or session",
  );
  phase = "bob_invitation";
  const bob = await signIn("bob", await invite("bob@example.com"));
  assert.notEqual(bob.user.id, alice.user.id);
  assert.equal(count("user_identities"), 2);
  phase = "member_ownership";
  for (const [client, label, slug] of [
    [alice, "Alice owned fixture", "saml-alice"],
    [bob, "Bob owned fixture", "saml-bob"],
  ])
    sql(
      `INSERT INTO devices(tenant_id,owner_user_id,hostname,label,platform,device_secret_hash,subdomain,agent_protocol_version) SELECT tenant_id,id,'SAML inventory fixture',${quote(label)},'opnsense','unusable SAML inventory fixture',${quote(slug)},'1.0.0' FROM users WHERE id=${quote(client.user.id)}`,
    );
  for (const [client, own, other, file] of [
    [
      alice,
      "Alice owned fixture",
      "Bob owned fixture",
      "keycloak-alice-login.png",
    ],
    [bob, "Bob owned fixture", "Alice owned fixture", "keycloak-bob-login.png"],
  ]) {
    await client.page.reload();
    await client.page.getByText(own, { exact: true }).waitFor();
    assert.equal(
      await client.page.getByText(other, { exact: true }).count(),
      0,
    );
    assert.equal((await api(client.page, "/devices")).data.items.length, 1);
    await screenshot(client.page, file);
  }
  checks.push(
    "two actual SAML members see separate deliberate inventory fixtures, not agent or tunnel acceptance",
  );
  phase = "existing_mailbox";
  const usersBefore = count("users"),
    identitiesBefore = count("user_identities");
  await (await signIn("mailbox", undefined, null)).context.close();
  assert.equal(count("users"), usersBefore);
  assert.equal(count("user_identities"), identitiesBefore);
  checks.push(
    "valid signed existing administrator mailbox cannot attach or sign in without invitation",
  );
  phase = "live_disable";
  const retainedAliceCookie = (await alice.context.cookies(origin)).find(
    (cookie) => cookie.name === "__Host-nethub_session",
  );
  assert.ok(retainedAliceCookie);
  const disabled = await api(
    admin.page,
    `/users/${alice.user.id}`,
    "PATCH",
    { disabled: true },
    admin.csrf,
  );
  assert.equal(disabled.status, 200);
  assert.equal(count("sessions", `user_id=${quote(alice.user.id)}`), 0);
  const revoked = await anonymous();
  await revoked.context.addCookies([retainedAliceCookie]);
  const sent = revoked.page.waitForRequest(
    (request) =>
      new URL(request.url()).pathname === "/api/v1/console/session" &&
      request.headers()["x-nethub-background"] === undefined,
  );
  const [refused, request] = await Promise.all([
    api(revoked.page, "/session"),
    sent,
  ]);
  assert.ok(
    (await request.allHeaders()).cookie?.includes(retainedAliceCookie.value),
  );
  assert.equal(refused.data.signed_in, false);
  await revoked.context.close();
  await (await signIn("alice", undefined, null)).context.close();
  await (await localAdmin()).context.close();
  checks.push(
    "live account disable rejects existing session and new valid SAML login while local administrator recovery works",
  );
  await Promise.all(headerChecks);
  assert.equal(unexpectedRequests, 0);
  assert.equal(cspViolations, 0);
  assert.equal(browserErrors, 0);
  assert.equal(cookieLeaks, 0);
  for (const context of contexts)
    for (const cookie of await context.cookies().catch(() => []))
      privateValues.push(cookie.value);
  writeFileSync(
    join(evidence, "privacy-values.json"),
    JSON.stringify(
      privateValues.filter(
        (value) => typeof value === "string" && value.length >= 16,
      ),
    ),
    { mode: 0o600 },
  );
  writeFileSync(
    join(evidence, "results.json"),
    JSON.stringify(
      {
        passed: true,
        checks,
        screenshots,
        normal_TLS_verification: true,
        required_signed_AuthnRequests: true,
        genuine_Keycloak_signed_responses: true,
        unexpectedRequests,
        cspViolations,
        browserErrors,
        cookieLeaks,
        full_W6_acceptance_claimed: false,
      },
      null,
      2,
    ),
  );
  console.log(
    "Actual Keycloak signed SAML requests/responses passed invitation, stable identity, replay refusal, Web restart, member isolation and live disable with normal TLS verification.",
  );
} catch (error) {
  let lastReason;
  try {
    const reason = sql(
      "SELECT payload->>'reason' FROM audit_log WHERE action='auth.sso_failed' ORDER BY sequence DESC LIMIT 1",
    );
    if (
      [
        "callback",
        "state_invalid",
        "state_unavailable",
        "token_invalid",
        "admission_denied",
        "admission_unavailable",
        "provider_unavailable",
      ].includes(reason)
    )
      lastReason = reason;
  } catch {}
  writeFileSync(
    join(evidence, "private-diagnostic.log"),
    String(error.stack || error),
    { mode: 0o600 },
  );
  writeFileSync(
    join(evidence, "results.json"),
    JSON.stringify(
      {
        passed: false,
        phase,
        last_sso_reason: lastReason,
        assertion_actual:
          error instanceof assert.AssertionError &&
          (typeof error.actual === "boolean" ||
            (Number.isInteger(error.actual) && Math.abs(error.actual) <= 10000))
            ? error.actual
            : null,
        assertion_expected:
          error instanceof assert.AssertionError &&
          (typeof error.expected === "boolean" ||
            (Number.isInteger(error.expected) &&
              Math.abs(error.expected) <= 10000))
            ? error.expected
            : null,
        failure_line:
          Number(
            /saml-deployment\.mjs:(\d+):\d+/.exec(String(error.stack))?.[1],
          ) || null,
        category:
          error.name === "TimeoutError"
            ? "timeout"
            : error instanceof assert.AssertionError
              ? "assertion"
              : "runtime",
        full_W6_acceptance_claimed: false,
      },
      null,
      2,
    ),
  );
  console.error(`Actual Keycloak SAML acceptance failed during ${phase}.`);
  process.exitCode = 1;
} finally {
  for (const context of contexts) await context.close().catch(() => {});
  await browser?.close();
  for (const socket of sockets) socket.destroy();
  if (proxy) await new Promise((resolve) => proxy.close(resolve));
}
