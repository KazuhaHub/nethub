import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";

const source = readFileSync(new URL("../src/api.ts", import.meta.url), "utf8");
const compiled = stripTypeScriptTypes(source, { mode: "transform" });
const { api, clearSession, onUnauthorized, validRelayAlerts } = await import(
  `data:text/javascript;base64,${Buffer.from(compiled).toString("base64")}`
);

test("invitation administration uses CSRF on bodyless DELETE and secret POST bodies", async () => {
  const previous = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    if (url.endsWith("/login"))
      return Response.json({ csrf_token: "admin-csrf" });
    if (url.endsWith("/accept"))
      return Response.json({ csrf_token: "accepted-csrf" });
    if (init.method === "DELETE") return new Response(null, { status: 204 });
    return Response.json({ items: [], next_cursor: null });
  };
  try {
    await api.login("admin@example.com", "fixture password");
    await api.invitations("next-page");
    assert.equal(calls.at(-1).init.method, "GET");
    assert.equal(calls.at(-1).init.headers["X-NetHub-Background"], undefined);
    await api.issueInvitation("new@example.com", "member");
    assert.deepEqual(JSON.parse(calls.at(-1).init.body), {
      email: "new@example.com",
      role: "member",
    });
    await api.withdrawInvitation("canonical-id");
    assert.equal(calls.at(-1).init.method, "DELETE");
    assert.equal(calls.at(-1).init.headers["X-CSRF-Token"], "admin-csrf");
    assert.equal(calls.at(-1).init.headers["Content-Type"], undefined);
    assert.equal(calls.at(-1).init.body, undefined);
    await api.inspectInvitation("private-bearer");
    assert.equal(calls.at(-1).init.method, "POST");
    assert.equal(calls.at(-1).url, "/api/v1/console/invites/inspect");
    assert.deepEqual(JSON.parse(calls.at(-1).init.body), {
      token: "private-bearer",
    });
    await api.acceptInvitation("private-bearer", "new invitation password");
    assert.deepEqual(JSON.parse(calls.at(-1).init.body), {
      token: "private-bearer",
      password: "new invitation password",
    });
    await api.withdrawInvitation("canonical-id");
    assert.equal(calls.at(-1).init.headers["X-CSRF-Token"], "accepted-csrf");
    assert.ok(calls.every(({ url }) => !url.includes("private-bearer")));
  } finally {
    globalThis.fetch = previous;
    clearSession();
  }
});

test("invitation mutations report uncertain delivery without automatic replay", async () => {
  const previous = globalThis.fetch;
  const timeout = AbortSignal.timeout;
  try {
    for (const failure of ["connection", "server", "deadline"]) {
      let attempts = 0;
      AbortSignal.timeout = () => timeout(1);
      globalThis.fetch = async (_, init) => {
        attempts++;
        if (failure === "connection") throw new TypeError("connection lost");
        if (failure === "server")
          return Response.json(
            { error: { code: "internal", message: "Unavailable" } },
            { status: 500 },
          );
        return new Promise((_, reject) =>
          init.signal.addEventListener(
            "abort",
            () => reject(init.signal.reason),
            { once: true },
          ),
        );
      };
      // Keep the event loop alive while the unref'd deadline expires.
      const keepAlive = setTimeout(() => {}, 1000);
      try {
        await assert.rejects(
          api.acceptInvitation("private-bearer", "new invitation password"),
          (error) => error.code === "invitation_unconfirmed",
        );
      } finally {
        clearTimeout(keepAlive);
      }
      assert.equal(attempts, 1);
    }
  } finally {
    globalThis.fetch = previous;
    AbortSignal.timeout = timeout;
    clearSession();
  }
});

test("relay alerts reject ambiguous identities, unsafe modes and duplicate receipts", () => {
  const alert = {
    id: "11111111-1111-4111-8111-111111111111",
    device_id: null,
    kind: "unknown_proxy",
    response: "alarm_only",
    confirmed_at: "2026-10-24T00:00:00Z",
  };
  assert.equal(validRelayAlerts([alert]), true);
  const known = {
    ...alert,
    device_id: "22222222-2222-4222-8222-222222222222",
    kind: "domain_mismatch",
    response: "revoked",
  };
  assert.equal(validRelayAlerts([known]), true);
  for (const invalid of [
    null,
    {},
    [alert, alert],
    Array(101).fill(alert),
    [{ ...alert, device_id: known.device_id }],
    [{ ...alert, response: "revoked" }],
    [{ ...known, response: "already_revoked" }],
    [{ ...alert, confirmed_at: "not-a-date" }],
    [{ ...alert, id: { toString: "invalid" } }],
  ]) {
    assert.equal(validRelayAlerts(invalid), false);
  }
});

test("user updates use PATCH and CSRF while passive user pages stay read-only", async () => {
  const previous = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    if (url.endsWith("/login"))
      return Response.json({
        csrf_token: "fixture-csrf",
        user: { id: "fixture" },
      });
    if (url.endsWith("/session"))
      return Response.json({
        signed_in: true,
        csrf_token: "fixture-csrf",
        user: { id: "fixture" },
      });
    return Response.json({ items: [], next_cursor: null });
  };
  try {
    await api.login("member@example.com", "fixture-password");
    await api.session(undefined, true);
    assert.equal(calls.at(-1).init.method, "GET");
    assert.equal(calls.at(-1).init.headers["X-NetHub-Background"], "1");
    await api.users("opaque-cursor", undefined, true);
    assert.equal(calls.at(-1).init.method, "GET");
    assert.equal(calls.at(-1).init.headers["X-NetHub-Background"], "1");
    assert.equal(calls.at(-1).init.body, undefined);
    assert.ok(calls.at(-1).url.includes("cursor=opaque-cursor"));
    await api.users(null);
    assert.equal(calls.at(-1).init.method, "GET");
    assert.equal(calls.at(-1).init.headers["X-NetHub-Background"], undefined);
    await api.updateUser("00000000-0000-4000-8000-000000000099", {
      disabled: true,
    });
    const call = calls.at(-1);
    assert.equal(call.init.method, "PATCH");
    assert.equal(call.init.headers["X-CSRF-Token"], "fixture-csrf");
    assert.equal(call.init.headers["X-NetHub-Background"], undefined);
    assert.equal(call.init.credentials, "same-origin");
    assert.equal(call.init.cache, "no-store");
    assert.equal(call.init.body, '{"disabled":true}');
  } finally {
    globalThis.fetch = previous;
    clearSession();
  }
});

test("a user-change deadline reports an unconfirmed result without replay", async () => {
  const previous = globalThis.fetch,
    timeout = AbortSignal.timeout;
  const controller = new AbortController();
  let calls = 0;
  AbortSignal.timeout = () => controller.signal;
  globalThis.fetch = (_url, init) => {
    calls++;
    return new Promise((_resolve, reject) =>
      init.signal.addEventListener(
        "abort",
        () => reject(controller.signal.reason),
        { once: true },
      ),
    );
  };
  try {
    const pending = api.updateUser("00000000-0000-4000-8000-000000000099", {
      disabled: true,
    });
    controller.abort(new DOMException("deadline", "TimeoutError"));
    await assert.rejects(
      pending,
      (error) =>
        error.code === "change_unconfirmed" &&
        error.message.includes("Refresh"),
    );
    assert.equal(calls, 1);
  } finally {
    globalThis.fetch = previous;
    AbortSignal.timeout = timeout;
  }
});

test("the request wrapper attaches CSRF, clears it on 401, and never puts credentials in URLs", async () => {
  const previous = globalThis.fetch;
  const calls = [];
  let denied = false;
  let signedOut = 0;
  const unsubscribe = onUnauthorized(() => signedOut++);
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    if (denied)
      return Response.json(
        { error: { code: "unauthenticated", message: "Sign in to continue" } },
        { status: 401 },
      );
    if (url.endsWith("/login"))
      return Response.json({
        csrf_token: "fixture-csrf",
        user: { id: "fixture" },
      });
    return Response.json({ token: "fixture-once" });
  };
  try {
    await api.login("member@example.com", "fixture-password");
    await api.enroll();
    assert.equal(calls[1].init.headers["X-CSRF-Token"], "fixture-csrf");
    assert.equal(calls[1].init.credentials, "same-origin");
    assert.equal(calls[1].init.cache, "no-store");
    await api.openDevice("00000000-0000-4000-8000-000000000001");
    assert.equal(calls.at(-1).init.method, "POST");
    assert.equal(calls.at(-1).init.body, "{}");
    assert.equal(calls.at(-1).init.headers["X-CSRF-Token"], "fixture-csrf");
    await api.revokeDevice("00000000-0000-4000-8000-000000000001");
    assert.equal(calls.at(-1).init.method, "POST");
    assert.equal(calls.at(-1).init.body, "{}");
    await api.requestDisconnect("00000000-0000-4000-8000-000000000001");
    assert.equal(calls.at(-1).init.method, "POST");
    assert.equal(calls.at(-1).init.body, "{}");
    assert.equal(calls.at(-1).init.headers["X-CSRF-Token"], "fixture-csrf");
    await api.devices(null, "all", undefined, true);
    assert.equal(calls.at(-1).init.headers["X-NetHub-Background"], "1");
    assert.equal(calls.at(-1).init.method, "GET");
    await api.devices(null, "all");
    assert.equal(calls.at(-1).init.headers["X-NetHub-Background"], undefined);
    assert.ok(
      calls.every(
        (call) =>
          !call.url.includes("fixture-password") &&
          !call.url.includes("fixture-csrf"),
      ),
    );

    denied = true;
    await assert.rejects(api.enroll(), (error) => error.status === 401);
    assert.equal(signedOut, 1);
    denied = false;
    await api.enroll();
    assert.equal(calls.at(-1).init.headers["X-CSRF-Token"], undefined);
  } finally {
    globalThis.fetch = previous;
    clearSession();
    unsubscribe();
  }
});

test("network and retry failures have bounded, safe messages", async () => {
  const previous = globalThis.fetch;
  try {
    globalThis.fetch = async () => {
      throw Error("private network detail");
    };
    await assert.rejects(
      api.enroll(),
      (error) =>
        error.code === "connection_failed" &&
        !error.message.includes("private network"),
    );
    globalThis.fetch = async () =>
      new Response("", { status: 429, headers: { "Retry-After": "9999999" } });
    await assert.rejects(
      api.enroll(),
      (error) => error.status === 429 && error.message.includes("3600"),
    );
  } finally {
    globalThis.fetch = previous;
  }
});

const accessSource = readFileSync(
  new URL("../src/device-access.ts", import.meta.url),
  "utf8",
);
const { canOpenDevice, deviceDestination } = await import(
  `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(accessSource, { mode: "transform" })).toString("base64")}`
);
test("Open requires a live matching installation report and a strict router destination", () => {
  const now = Date.now();
  const device = {
    online: true,
    revoked: false,
    url: "https://branch.router.example.com:8443",
    gui_certificate: {
      state: "applied",
      assigned_host: "branch.router.example.com",
      confirmed_at: new Date(now - 1000).toISOString(),
      valid_until: new Date(now + 60000).toISOString(),
    },
  };
  assert.equal(canOpenDevice(device, now), true);
  for (const change of [
    { online: false },
    { revoked: true },
    { gui_certificate: undefined },
  ])
    assert.equal(canOpenDevice({ ...device, ...change }, now), false);
  for (const change of [
    { state: "pending" },
    { state: "failed" },
    { state: "expired" },
    { assigned_host: "other.router.example.com" },
    { confirmed_at: null },
    { valid_until: new Date(now).toISOString() },
  ])
    assert.equal(
      canOpenDevice(
        {
          ...device,
          gui_certificate: { ...device.gui_certificate, ...change },
        },
        now,
      ),
      false,
    );
  for (const url of [
    "javascript:alert(1)",
    "http://branch.router.example.com:8443",
    "https://branch.router.example.com",
    "https://user@branch.router.example.com:8443",
    "https://branch.router.example.com:8443/path",
    "https://branch.router.example.com:8443/?token=x",
    "https://branch.router.example.com:8443/#x",
  ])
    assert.equal(deviceDestination({ ...device, url }), null);
});
