import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { connect } from "node:net";
import { join } from "node:path";
import { chromium } from "playwright";
import { captureCallback, observeAuthorization } from "./oidc-callback.mjs";

const [
  portText,
  adminPasswordFile,
  fixture,
  helper,
  browserHome,
  evidence,
  databaseContainer,
  webContainer,
] = process.argv.slice(2);
const port = Number(portText),
  origin = "https://console.example.com";
assert.ok(Number.isInteger(port) && port > 0 && port < 65536);
assert.ok(
  fixture &&
    helper &&
    browserHome &&
    evidence &&
    databaseContainer &&
    webContainer,
);
const secrets = JSON.parse(
  readFileSync(join(fixture, "credentials.json"), "utf8"),
);
const adminPassword = readFileSync(adminPasswordFile, "utf8").trimEnd();
const privateValues = [
  secrets.password,
  adminPassword,
  ...Object.values(secrets.clients),
];
mkdirSync(evidence, { recursive: true });
let phase = "startup",
  browser,
  proxy;
const sockets = new Set(),
  contexts = [];
const allowed = new Set([
  "console.example.com:443",
  "dex-one.test:443",
  "dex-two.test:443",
]);
const checks = [],
  images = [];
const headerChecks = [];
const failureContext = {};
let unexpectedRequests = 0,
  cspViolations = 0,
  browserErrors = 0,
  cookieLeaks = 0;
function command(executable, args, input) {
  const result = spawnSync(executable, args, {
    encoding: "utf8",
    input,
    timeout: 20000,
    maxBuffer: 4 * 1024 * 1024,
  });
  assert.equal(result.status, 0, "An isolated command failed");
  return result.stdout;
}
function sql(query) {
  return command("docker", [
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
  ]).trim();
}
function quote(value) {
  assert.ok(!value.includes("\0"));
  return "'" + value.replaceAll("'", "''") + "'";
}
function count(table, where = "true") {
  assert.ok(
    [
      "users",
      "user_identities",
      "invites",
      "sessions",
      "oidc_flows",
      "audit_log",
    ].includes(table),
  );
  return Number(sql(`SELECT count(*) FROM ${table} WHERE ${where}`));
}
async function api(page, path, method = "GET", body, csrf) {
  return page.evaluate(
    async ({ path, method, body, csrf }) => {
      const headers = { Accept: "application/json" };
      if (body !== undefined) headers["Content-Type"] = "application/json";
      if (csrf) headers["X-CSRF-Token"] = csrf;
      const response = await fetch("/api/v1/console" + path, {
        method,
        headers,
        credentials: "same-origin",
        cache: "no-store",
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      return {
        status: response.status,
        retry: response.headers.get("Retry-After"),
        data: await response.json().catch(() => null),
      };
    },
    { path, method, body, csrf },
  );
}
async function newClient() {
  const context = await browser.newContext({
    ignoreHTTPSErrors: false,
    viewport: { width: 1440, height: 1000 },
  });
  contexts.push(context);
  await context.exposeBinding("recordSSOCSP", ({ frame }) => {
    if (new URL(frame.url()).origin === origin) cspViolations++;
  });
  await context.addInitScript(() =>
    document.addEventListener("securitypolicyviolation", () =>
      window.recordSSOCSP(),
    ),
  );
  const page = await context.newPage();
  page.setDefaultTimeout(15000);
  page.on("pageerror", () => browserErrors++);
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (
      !allowed.has(
        url.hostname +
          ":" +
          (url.port || (url.protocol === "https:" ? "443" : "80")),
      ) &&
      url.protocol !== "data:"
    )
      unexpectedRequests++;
    if (url.hostname.startsWith("dex-"))
      headerChecks.push(
        request.allHeaders().then((headers) => {
          if (/__Host-nethub_(?:session|oidc)/.test(headers.cookie || ""))
            cookieLeaks++;
        }),
      );
  });
  return { context, page };
}
async function anonymous() {
  const client = await newClient();
  await client.page.goto(origin);
  await client.page
    .getByRole("heading", { name: "Sign in to NetHub", exact: true })
    .waitFor();
  return client;
}
async function start(client, slug, grant) {
  for (let attempt = 0; attempt < 2; attempt++) {
    const response = await api(
      client.page,
      `/oidc/${slug}/start`,
      "POST",
      grant ? { invite_token: grant } : {},
    );
    if (response.status === 429 && attempt === 0) {
      const seconds = Number(response.retry);
      assert.ok(Number.isInteger(seconds) && seconds >= 1 && seconds <= 60);
      await client.page.waitForTimeout(seconds * 1000 + 100);
      continue;
    }
    if (response.status === 200) {
      const url = new URL(response.data.redirect_url);
      assert.equal(url.origin, `https://dex-${slug}.test`);
      assert.equal(url.searchParams.get("code_challenge_method"), "S256");
      assert.ok(url.searchParams.get("code_challenge"));
      for (const key of ["state", "nonce"])
        privateValues.push(url.searchParams.get(key));
    }
    return response;
  }
  assert.fail("SSO start did not recover after its published rate limit");
}
async function dexLogin(page, email) {
  await page.locator('input[name="login"]').fill(email);
  await page.locator('input[name="password"]').fill(secrets.password);
  await page.locator("#submit-login").click();
}
async function startFromUI(client, slug, grant) {
  if (grant) {
    await client.page.goto(origin + "/invite#" + grant);
    await client.page
      .getByRole("button", { name: `Continue with Dex ${slug}`, exact: true })
      .waitFor();
    assert.equal(new URL(client.page.url()).hash, "");
    assert.ok(
      !(
        await client.page.evaluate(() =>
          JSON.stringify({
            local: { ...localStorage },
            session: { ...sessionStorage },
          }),
        )
      ).includes(grant),
    );
  }
  const authorization = observeAuthorization(
    client.page,
    `https://dex-${slug}.test`,
    `nethub-${slug}`,
  );
  try {
    for (let attempt = 0; attempt < 2; attempt++) {
      const received = client.page.waitForResponse(
        (response) =>
          new URL(response.url()).pathname ===
          `/api/v1/console/oidc/${slug}/start`,
      );
      await client.page
        .getByRole("button", { name: `Continue with Dex ${slug}`, exact: true })
        .click();
      const response = await received;
      if (response.status() === 429 && attempt === 0) {
        const seconds = Number(response.headers()["retry-after"]);
        assert.ok(Number.isInteger(seconds) && seconds >= 1 && seconds <= 60);
        await client.page.waitForTimeout(seconds * 1000 + 100);
        continue;
      }
      assert.equal(
        response.status(),
        200,
        "UI SSO start refused a valid test flow",
      );
      await client.page.waitForURL(
        (url) => url.origin === `https://dex-${slug}.test`,
      );
      assert.ok(
        authorization.url,
        "UI did not navigate to its IdP authorization endpoint",
      );
      const url = new URL(authorization.url);
      assert.equal(url.origin, `https://dex-${slug}.test`);
      assert.equal(url.searchParams.get("code_challenge_method"), "S256");
      assert.ok(url.searchParams.get("code_challenge"));
      for (const key of ["state", "nonce"])
        privateValues.push(url.searchParams.get(key));
      return { redirect_url: authorization.url };
    }
    assert.fail("UI SSO start did not recover after Retry-After");
  } finally {
    authorization.close();
  }
}
async function signIn(
  slug,
  email,
  grant,
  { success = true, tamper = false } = {},
) {
  const client = await anonymous();
  const callbackPath = `/api/v1/console/oidc/${slug}/callback`;
  let callback;
  client.page.on("response", (reply) => {
    const url = new URL(reply.url());
    if (url.origin === origin && url.pathname === callbackPath) {
      callback = reply.url();
      privateValues.push(url.searchParams.get("code"));
    }
  });
  let untampered;
  const begun = await startFromUI(client, slug, grant);
  const startCookies = (await client.context.cookies(origin)).filter(
    (cookie) => cookie.name === "__Host-nethub_oidc",
  );
  assert.equal(startCookies.length, 1);
  privateValues.push(startCookies[0].value);
  if (tamper) {
    // The disposable Caddy route parks this one callback before Web can consume
    // its valid state. Remove the marker before sending the tampered callback.
    await client.context.setExtraHTTPHeaders({ "X-Nethub-Test-Capture": "1" });
    untampered = (
      await captureCallback(
        client.page,
        origin,
        callbackPath,
        () => dexLogin(client.page, email),
        "Callback captured",
      )
    ).toString();
    await client.context.setExtraHTTPHeaders({});
    const changed = new URL(untampered);
    changed.searchParams.set("state", "a".repeat(43));
    await client.page.goto(changed.toString());
  } else {
    await dexLogin(client.page, email);
  }
  await client.page.waitForURL(
    (url) => url.origin === origin && !url.pathname.startsWith("/api/"),
  );
  if (success) {
    await client.page
      .getByRole("heading", { name: "Devices", exact: true })
      .waitFor();
    const session = await api(client.page, "/session");
    assert.equal(session.status, 200);
    assert.equal(session.data.user.email, email);
    assert.equal(session.data.user.role, "member");
    assert.equal(
      await client.page
        .getByRole("link", { name: "Users", exact: true })
        .count(),
      0,
    );
    assert.equal((await api(client.page, "/users")).status, 403);
    const cookie = (await client.context.cookies()).find(
      (value) => value.name === "__Host-nethub_session",
    );
    assert.ok(
      cookie?.secure &&
        cookie.httpOnly &&
        cookie.sameSite === "Lax" &&
        cookie.domain === "console.example.com",
    );
    privateValues.push(cookie.value);
    client.user = session.data.user;
  } else {
    assert.equal(new URL(client.page.url()).pathname, "/login");
    assert.equal(new URL(client.page.url()).search, "?error=sso_failed");
    await client.page
      .getByRole("heading", { name: "Sign in to NetHub", exact: true })
      .waitFor();
    assert.equal((await api(client.page, "/session")).data.signed_in, false);
  }
  return {
    ...client,
    callback,
    untampered,
    startCookies,
    startState: new URL(begun.redirect_url).searchParams.get("state"),
  };
}
async function screenshot(page, name) {
  await page.screenshot({ path: join(evidence, name), animations: "disabled" });
  images.push({
    name,
    sha256: createHash("sha256")
      .update(readFileSync(join(evidence, name)))
      .digest("hex"),
  });
}
async function signedClaimProbe(slug, email) {
  const begun = JSON.parse(
    command(helper, ["probe-begin", fixture, portText, slug]),
  );
  const probeState = JSON.parse(
    readFileSync(join(fixture, `probe-${slug}.json`), "utf8"),
  );
  privateValues.push(probeState.Value, probeState.Nonce, probeState.Verifier);
  const client = await newClient();
  await client.page.goto(begun.redirect_url);
  const returned = await captureCallback(
    client.page,
    origin,
    "/claim-probe",
    () => dexLogin(client.page, email),
    "Signed claim captured",
  );
  for (const key of ["state", "code"])
    privateValues.push(returned.searchParams.get(key));
  const verified = JSON.parse(
    command(
      helper,
      ["probe-finish", fixture, portText, slug],
      JSON.stringify({
        state: returned.searchParams.get("state"),
        code: returned.searchParams.get("code"),
      }),
    ),
  );
  assert.equal(verified.issuer, `https://dex-${slug}.test`);
  assert.equal(verified.email, email);
  assert.equal(verified.signature_nonce_and_PKCE_verified, true);
  await client.context.close();
  return verified;
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
  await new Promise((resolve, reject) => {
    proxy.once("error", reject);
    proxy.listen(0, "127.0.0.1", resolve);
  });
  browser = await chromium.launch({
    headless: true,
    env: { ...process.env, HOME: browserHome },
    proxy: { server: `http://127.0.0.1:${proxy.address().port}` },
  });
  phase = "admin_login";
  const admin = await anonymous();
  await admin.page
    .getByLabel("Email address", { exact: true })
    .fill("compose-admin@example.com");
  await admin.page.getByLabel("Password", { exact: true }).fill(adminPassword);
  const loginReply = admin.page.waitForResponse(
    (reply) => new URL(reply.url()).pathname === "/api/v1/console/login",
  );
  await admin.page
    .getByRole("button", { name: "Sign in", exact: true })
    .click();
  const login = await (await loginReply).json();
  assert.equal(login.user.role, "admin");
  const csrf = login.csrf_token;
  privateValues.push(csrf);
  privateValues.push(
    (await admin.context.cookies(origin)).find(
      (cookie) => cookie.name === "__Host-nethub_session",
    ).value,
  );
  await admin.page
    .getByRole("heading", { name: "Devices", exact: true })
    .waitFor();
  phase = "provider_creation";
  assert.equal(count("users"), 1);
  assert.equal(count("user_identities"), 0);
  await admin.page
    .getByRole("link", { name: "Identity providers", exact: true })
    .click();
  const dialog = admin.page.getByRole("dialog"),
    providers = {};
  for (const slug of ["one", "two"]) {
    await admin.page
      .getByRole("button", { name: "Add provider", exact: true })
      .click();
    for (const [label, value] of [
      ["Display name", `Dex ${slug}`],
      ["Slug", slug],
      ["Issuer URL", `https://dex-${slug}.test`],
      ["Client ID", `nethub-${slug}`],
      ["Client secret", secrets.clients[slug]],
    ])
      await dialog.getByLabel(label, { exact: true }).fill(value);
    await dialog.getByLabel("Enable sign-in", { exact: true }).check();
    const created = admin.page.waitForResponse(
      (reply) =>
        new URL(reply.url()).pathname === "/api/v1/console/oidc-providers" &&
        reply.request().method() === "POST",
    );
    await dialog
      .getByRole("button", { name: "Save provider", exact: true })
      .click();
    const response = await created;
    failureContext.provider_status = response.status();
    const provider = await response.json();
    if (
      [
        "invalid_request",
        "oidc_discovery_failed",
        "forbidden",
        "unauthenticated",
        "internal_error",
        "slug_taken",
      ].includes(provider?.error?.code)
    )
      failureContext.provider_error = provider.error.code;
    assert.equal(response.status(), 201);
    assert.ok(provider.has_client_secret);
    assert.equal(
      provider.redirect_uri,
      `${origin}/api/v1/console/oidc/${slug}/callback`,
    );
    assert.ok(!JSON.stringify(provider).includes(secrets.clients[slug]));
    providers[slug] = provider.id;
    await dialog.waitFor({ state: "hidden" });
  }
  const rows = JSON.parse(
    sql(
      "SELECT json_agg(json_build_object('issuer',issuer_url,'cipher',encode(client_secret_enc,'hex'))) FROM oidc_providers",
    ),
  );
  assert.equal(rows.length, 2);
  for (const row of rows) {
    assert.ok(row.cipher.length > 80);
    for (const secret of Object.values(secrets.clients))
      assert.ok(!row.cipher.includes(Buffer.from(secret).toString("hex")));
  }
  checks.push("real provider UI discovery and encrypted client credentials");
  async function invite(email, slug) {
    const response = await api(
      admin.page,
      "/invites",
      "POST",
      {
        email,
        role: "member",
        ...(slug ? { provider_id: providers[slug] } : {}),
      },
      csrf,
    );
    assert.equal(response.status, 201);
    privateValues.push(response.data.token);
    return response.data.token;
  }
  phase = "signed_false_probe";
  const falseClaim = await signedClaimProbe("one", "unverified@example.com");
  assert.equal(falseClaim.email_verified, false);
  checks.push(
    "actual signed Dex email_verified false verified independently through authcore",
  );
  phase = "first_provider_claim";
  const aliceGrant = await invite("alice@example.com");
  const alice = await signIn("one", "alice@example.com", aliceGrant);
  assert.equal(count("user_identities", "issuer='https://dex-one.test'"), 1);
  assert.equal(
    count("users", "email='alice@example.com' AND password_hash IS NULL"),
    1,
  );
  assert.equal(
    count("invites", "email='alice@example.com' AND used_at IS NOT NULL"),
    1,
  );
  await alice.page
    .getByRole("button", { name: "Sign out", exact: true })
    .click();
  await alice.page
    .getByRole("heading", { name: "Sign in to NetHub", exact: true })
    .waitFor();
  await alice.context.close();
  const boundAlice = await signIn("one", "alice@example.com");
  assert.equal(boundAlice.user.id, alice.user.id);
  assert.equal(count("users", "email='alice@example.com'"), 1);
  checks.push(
    "first issuer invitation claim and subsequent issuer-subject login",
  );
  phase = "web_restart";
  command("docker", ["restart", "--time", "10", webContainer]);
  let healthy = false;
  for (let attempt = 0; attempt < 30; attempt++) {
    if (
      JSON.parse(
        command("docker", [
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
    await boundAlice.page.waitForTimeout(1000);
  }
  assert.ok(healthy, "Restarted Web did not become healthy");
  assert.equal(
    (await api(boundAlice.page, "/session")).data.user.id,
    alice.user.id,
  );
  checks.push(
    "actual Web restart preserves the existing database-backed SSO session and one-use flow receipt",
  );
  phase = "callback_replay";
  assert.ok(boundAlice.callback);
  const replay = await anonymous();
  await replay.context.addCookies(boundAlice.startCookies);
  const sessionsBeforeReplay = count("sessions");
  await replay.page.goto(boundAlice.callback);
  await replay.page
    .getByRole("heading", { name: "Sign in to NetHub", exact: true })
    .waitFor();
  assert.equal(new URL(replay.page.url()).search, "?error=sso_failed");
  assert.equal((await api(replay.page, "/session")).data.signed_in, false);
  await replay.context.close();
  assert.equal(count("sessions"), sessionsBeforeReplay);
  assert.equal(
    sql(
      "SELECT payload->>'reason' FROM audit_log WHERE action='auth.sso_failed' ORDER BY sequence DESC LIMIT 1",
    ),
    "state_invalid",
  );
  checks.push(
    "actual consumed callback replay with the original browser binding refused without another session",
  );
  phase = "second_provider_claim";
  const bobGrant = await invite("bob@example.com", "two"),
    bob = await signIn("two", "bob@example.com", bobGrant);
  assert.notEqual(bob.user.id, alice.user.id);
  assert.equal(count("user_identities", "issuer='https://dex-two.test'"), 1);
  checks.push(
    "second independent issuer restricted invitation claim and member session",
  );
  phase = "member_ownership";
  // Device rows are deliberate inventory fixtures, not real enrollments/tunnels.
  const deviceFor = (user, label, subdomain) =>
    sql(
      `INSERT INTO devices(tenant_id,owner_user_id,hostname,label,platform,device_secret_hash,subdomain,agent_protocol_version) SELECT tenant_id,id,'SSO inventory fixture',${quote(label)},'opnsense','unusable SSO inventory fixture',${quote(subdomain)},'1.0.0' FROM users WHERE id=${quote(user.id)} RETURNING id`,
    );
  const aliceDevice = deviceFor(
      boundAlice.user,
      "Alice owned fixture",
      "oidc-alice",
    ),
    bobDevice = deviceFor(bob.user, "Bob owned fixture", "oidc-bob");
  for (const [client, own, other, name, otherName] of [
    [
      boundAlice,
      aliceDevice,
      bobDevice,
      "Alice owned fixture",
      "Bob owned fixture",
    ],
    [bob, bobDevice, aliceDevice, "Bob owned fixture", "Alice owned fixture"],
  ]) {
    const inventory = await api(client.page, "/devices");
    assert.equal(inventory.status, 200);
    assert.deepEqual(
      inventory.data.items.map((item) => item.id),
      [own],
    );
    const session = (await api(client.page, "/session")).data;
    privateValues.push(session.csrf_token);
    assert.equal(
      (
        await api(
          client.page,
          `/devices/${other}/revoke`,
          "POST",
          {},
          session.csrf_token,
        )
      ).status,
      404,
    );
    const refreshed = client.page.waitForResponse(
      (response) =>
        new URL(response.url()).pathname === "/api/v1/console/devices" &&
        response.request().headers()["x-nethub-background"] === undefined,
    );
    await client.page
      .getByRole("button", { name: "Refresh devices", exact: true })
      .click();
    await refreshed;
    await client.page.getByText(name, { exact: true }).waitFor();
    assert.equal(
      await client.page.getByText(otherName, { exact: true }).count(),
      0,
    );
  }
  assert.equal(Number(sql("SELECT count(*) FROM devices WHERE revoked")), 0);
  await screenshot(boundAlice.page, "dex-one-login.png");
  await screenshot(bob.page, "dex-two-login.png");
  await bob.context.close();
  checks.push(
    "two real SSO members see only their owned fixture devices and cannot revoke the other's row with a valid CSRF token",
  );
  phase = "email_confusion";
  const sameSubject = await signedClaimProbe("two", "alice@example.com");
  assert.equal(sameSubject.email_verified, true);
  assert.equal(
    sameSubject.subject,
    sql(
      `SELECT subject FROM user_identities WHERE issuer='https://dex-one.test' AND user_id=${quote(alice.user.id)}`,
    ),
  );
  const before = count("users");
  await (
    await signIn("two", "alice@example.com", undefined, { success: false })
  ).context.close();
  await (
    await signIn("one", "compose-admin@example.com", undefined, {
      success: false,
    })
  ).context.close();
  assert.equal(count("users"), before);
  assert.equal(count("user_identities", "issuer='https://dex-two.test'"), 1);
  checks.push(
    "existing mailbox and another issuer's equal email and subject cannot sign in without an invitation",
  );
  phase = "restricted_invitation";
  const crossGrant = await invite("cross@example.com", "two"),
    cross = await anonymous();
  assert.equal((await start(cross, "one", crossGrant)).status, 401);
  assert.equal(
    count("invites", "email='cross@example.com' AND used_at IS NULL"),
    1,
  );
  assert.equal(count("users", "email='cross@example.com'"), 0);
  await cross.context.close();
  checks.push("wrong issuer cannot start or consume a restricted invitation");
  phase = "unverified_claim";
  const unverified = await invite("unverified@example.com", "one");
  await (
    await signIn("one", "unverified@example.com", unverified, {
      success: false,
    })
  ).context.close();
  assert.equal(count("users", "email='unverified@example.com'"), 0);
  assert.equal(
    count("invites", "email='unverified@example.com' AND used_at IS NULL"),
    1,
  );
  checks.push(
    "real signed false email claim cannot consume its matching invitation",
  );
  phase = "tampered_state";
  const tampered = await signIn("one", "alice@example.com", undefined, {
    success: false,
    tamper: true,
  });
  assert.ok(tampered.untampered);
  const originalHash = createHash("sha256")
    .update(Buffer.from(tampered.startState, "base64url"))
    .digest("hex");
  assert.equal(
    count(
      "oidc_flows",
      `state_hash=decode('${originalHash}','hex') AND consumed_at IS NULL`,
    ),
    1,
  );
  await tampered.context.close();
  checks.push(
    "actual signed authorization response with tampered state refused without consuming its valid flow",
  );
  phase = "disabled_account";
  assert.equal(
    (
      await api(
        admin.page,
        `/users/${alice.user.id}`,
        "PATCH",
        { disabled: true },
        csrf,
      )
    ).status,
    200,
  );
  assert.equal((await api(boundAlice.page, "/session")).status, 401);
  await (
    await signIn("one", "alice@example.com", undefined, { success: false })
  ).context.close();
  assert.equal(count("sessions", `user_id=${quote(alice.user.id)}`), 0);
  assert.equal(count("sessions", `user_id=${quote(bob.user.id)}`), 1);
  checks.push(
    "live account disable invalidates its existing session and refuses valid IdP login",
  );
  phase = "local_admin_recovery";
  const recovery = await anonymous();
  await recovery.page
    .getByLabel("Email address", { exact: true })
    .fill("compose-admin@example.com");
  await recovery.page
    .getByLabel("Password", { exact: true })
    .fill(adminPassword);
  const recovered = recovery.page.waitForResponse(
    (response) => new URL(response.url()).pathname === "/api/v1/console/login",
  );
  await recovery.page
    .getByRole("button", { name: "Sign in", exact: true })
    .click();
  assert.equal((await recovered).status(), 200);
  await recovery.page
    .getByRole("heading", { name: "Devices", exact: true })
    .waitFor();
  const recoveredSession = (await api(recovery.page, "/session")).data;
  assert.equal(recoveredSession.user.role, "admin");
  privateValues.push(
    recoveredSession.csrf_token,
    (await recovery.context.cookies(origin)).find(
      (cookie) => cookie.name === "__Host-nethub_session",
    ).value,
  );
  checks.push(
    "fresh local-password emergency administrator login remains usable after SSO and member disable",
  );
  phase = "audit_and_privacy";
  for (const action of [
    "auth.login",
    "auth.sso_failed",
    "invite.created",
    "invite.accepted",
    "oidc_provider.created",
    "user.updated",
    "auth.sessions_revoked",
  ]) {
    assert.ok(
      count("audit_log", `action=${quote(action)}`) > 0,
      "Required authentication audit event is absent",
    );
  }
  const webLog = spawnSync("docker", ["logs", webContainer], {
    encoding: "utf8",
    timeout: 15000,
    maxBuffer: 4 * 1024 * 1024,
  });
  assert.equal(webLog.status, 0);
  const logs =
    webLog.stdout +
    webLog.stderr +
    sql("SELECT coalesce(string_agg(payload::text,''),'') FROM audit_log");
  for (const value of privateValues.filter(
    (value) => typeof value === "string" && value.length >= 20,
  ))
    assert.ok(
      !logs.includes(value),
      "Authentication material appeared in Web/audit logs",
    );
  await Promise.all(headerChecks);
  assert.equal(cspViolations, 0);
  assert.equal(browserErrors, 0);
  assert.equal(unexpectedRequests, 0);
  assert.equal(cookieLeaks, 0);
  writeFileSync(
    join(evidence, "privacy-values.json"),
    JSON.stringify(
      privateValues.filter(
        (value) => typeof value === "string" && value.length >= 20,
      ),
    ),
    { mode: 0o600 },
  );
  writeFileSync(
    join(evidence, "results.json"),
    JSON.stringify(
      {
        passed: true,
        real_Dex_providers: 2,
        genuine_PostgreSQL: true,
        device_inventory_rows_are_fixture_records: true,
        browser_TLS_verification_enabled: true,
        backend_TLS_verification_enabled: true,
        independent_signed_false_claim_verified: true,
        identical_subject_issuer_fence_verified: true,
        actual_Web_restart_and_replay_checked: true,
        checks,
        cspViolations,
        browserErrors,
        unexpectedRequests,
        cookieLeaks,
        screenshots: images,
        public_IdP_or_SAML_acceptance_claimed: false,
      },
      null,
      2,
    ),
  );
  console.log(
    "Two actual Dex issuers passed UI configuration, invitation and bound login, strict signed-false rejection, mailbox/issuer isolation, state/replay refusal, live account disable, audit privacy and normal TLS verification.",
  );
} catch (error) {
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
        failure_line:
          Number(
            /oidc-deployment\.mjs:(\d+):\d+/.exec(String(error.stack))?.[1],
          ) || null,
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
        ...failureContext,
        category: String(error.message).includes("ERR_CERT_")
          ? "certificate_trust"
          : error.name === "TimeoutError"
            ? "timeout"
            : error instanceof assert.AssertionError
              ? "assertion"
              : "runtime",
        public_IdP_or_SAML_acceptance_claimed: false,
      },
      null,
      2,
    ),
  );
  console.error(`Real Dex browser acceptance failed during ${phase}.`);
  process.exitCode = 1;
} finally {
  for (const context of contexts) await context.close().catch(() => {});
  await browser?.close();
  for (const socket of sockets) socket.destroy();
  if (proxy) await new Promise((resolve) => proxy.close(resolve));
}
