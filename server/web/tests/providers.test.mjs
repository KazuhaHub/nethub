import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";

async function load(path) {
  const source = readFileSync(new URL(path, import.meta.url), "utf8");
  return import(
    `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`
  );
}
const { providerDraft, providerChanges, providerProjection } = await load(
  "../src/provider-form.ts",
);
const { api, clearSession, validSSODestination } = await load("../src/api.ts");
const provider = {
  id: "00000000-0000-4000-8000-000000003000",
  slug: "corporate",
  display_name: "Corporate",
  issuer_url: "https://idp.example.com",
  client_id: "console",
  scopes: ["openid", "email", "profile"],
  enabled: true,
  has_client_secret: true,
  redirect_uri:
    "https://console.example.com/api/v1/console/oidc/corporate/callback",
  created_at: "2026-10-25T00:00:00Z",
};

test("provider edits distinguish unchanged, replacement and explicit removal", () => {
  const draft = providerDraft(provider);
  assert.equal(draft.secret, "");
  assert.deepEqual(providerChanges(draft), {});
  assert.deepEqual(providerChanges({ ...draft, name: "Renamed" }), {
    display_name: "Renamed",
  });
  assert.deepEqual(providerChanges({ ...draft, secret: "replacement" }), {
    client_secret: "replacement",
  });
  assert.deepEqual(providerChanges({ ...draft, removeSecret: true }), {
    client_secret: "",
  });
  assert.throws(() =>
    providerChanges({ ...draft, removeSecret: true, secret: "replacement" }),
  );
  for (const scopes of [
    "email",
    "openid openid",
    'openid invalid"scope',
    "openid \\bad",
  ])
    assert.throws(() => providerChanges({ ...draft, scopes }));
  assert.equal(providerDraft(null).enabled, false);
  assert.equal("client_secret" in providerChanges(providerDraft(null)), false);
  assert.ok(providerProjection(provider));
  assert.equal(
    providerProjection({ ...provider, client_secret: "leaked" }),
    false,
  );
  assert.equal(
    providerProjection({ ...provider, client_secret_enc: "leaked" }),
    false,
  );
});

test("provider CRUD uses changed bodies and CSRF, SSO grants stay in POST bodies", async () => {
  const previous = globalThis.fetch,
    calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    if (url.endsWith("/login"))
      return Response.json({ csrf_token: "fixture-csrf" });
    if (url.endsWith("/start"))
      return Response.json({
        redirect_url: "https://idp.example.com/authorize?state=opaque",
      });
    if (init.method === "DELETE") return new Response(null, { status: 204 });
    return Response.json({ items: [] });
  };
  try {
    await api.login("admin@example.com", "fixture password");
    await api.updateOIDCProvider(provider.id, { display_name: "Renamed" });
    assert.equal(calls.at(-1).init.method, "PATCH");
    assert.deepEqual(JSON.parse(calls.at(-1).init.body), {
      display_name: "Renamed",
    });
    await api.deleteOIDCProvider(provider.id);
    assert.equal(calls.at(-1).init.headers["X-CSRF-Token"], "fixture-csrf");
    assert.equal(calls.at(-1).init.body, undefined);
    await api.oidcProviders(null, undefined, true);
    assert.equal(calls.at(-1).init.headers["X-NetHub-Background"], "1");
    await api.startOIDC("corporate", "private-invite");
    assert.deepEqual(JSON.parse(calls.at(-1).init.body), {
      invite_token: "private-invite",
    });
    assert.ok(calls.every(({ url }) => !url.includes("private-invite")));
    await api.issueInvitation("new@example.com", "member", provider.id);
    assert.equal(JSON.parse(calls.at(-1).init.body).provider_id, provider.id);
  } finally {
    globalThis.fetch = previous;
    clearSession();
  }
});

test("unconfirmed provider writes never replay", async () => {
  const previous = globalThis.fetch;
  try {
    for (const mode of ["network", "server"]) {
      let attempts = 0;
      globalThis.fetch = async () => {
        attempts++;
        if (mode === "network") throw Error("lost");
        return new Response(null, { status: 503 });
      };
      await assert.rejects(
        api.createOIDCProvider({}),
        (error) => error.code === "provider_unconfirmed",
      );
      assert.equal(attempts, 1);
    }
  } finally {
    globalThis.fetch = previous;
  }
});

test("catalog and SSO destinations reject malformed data", async () => {
  assert.ok(
    validSSODestination("https://idp.example.com/authorize?state=opaque"),
  );
  for (const value of [
    null,
    "/authorize",
    "http://idp.example.com",
    "javascript:alert(1)",
    "https://user:secret@idp.example.com",
    "https://idp.example.com/#secret",
  ])
    assert.equal(validSSODestination(value), false);
  const previous = globalThis.fetch;
  try {
    globalThis.fetch = async () =>
      Response.json({ items: [{ slug: "../callback", display_name: "bad" }] });
    await assert.rejects(api.loginProviders());
    globalThis.fetch = async () =>
      Response.json({ redirect_url: "http://idp.example.com" });
    await assert.rejects(api.startOIDC("corporate"));
  } finally {
    globalThis.fetch = previous;
  }
});
