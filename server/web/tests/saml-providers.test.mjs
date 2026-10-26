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
const { samlDraft, samlChanges, samlProjection, verifiedSAMLAddresses } =
  await load("../src/saml-provider-form.ts");
const { api, clearSession } = await load("../src/api.ts");
const provider = {
  id: "00000000-0000-4000-8000-000000004000",
  slug: "company",
  display_name: "Company SAML",
  entity_id: "urn:company",
  email_attribute: "mail",
  enabled: false,
  has_signing_key: true,
  created_at: "2026-10-26T00:00:00Z",
  metadata_uri:
    "https://console.example.com/api/v1/console/saml/company/metadata",
  acs_uri: "https://console.example.com/api/v1/console/saml/company/callback",
};

test("SAML edits retain omitted metadata and distinguish deliberate replacements", () => {
  const draft = samlDraft(provider);
  assert.equal(draft.metadata, "");
  assert.deepEqual(samlChanges(draft), {});
  assert.deepEqual(samlChanges({ ...draft, name: "Renamed" }), {
    display_name: "Renamed",
  });
  assert.deepEqual(samlChanges({ ...draft, metadata: "<new-metadata/>" }), {
    metadata_xml: "<new-metadata/>",
  });
  assert.throws(
    () => samlChanges({ ...draft, entity: "urn:other" }),
    /matching metadata/,
  );
  assert.throws(
    () => samlChanges({ ...draft, metadata: "🙂".repeat(262145) }),
    /1 MiB/,
  );
  assert.throws(() => samlChanges(samlDraft(null)), /trusted IdP/);
});
test("SAML projections reject private fields and origin substitution", () => {
  assert.equal(samlProjection(provider), true);
  for (const field of [
    "sp_key_enc",
    "signing_key",
    "private_key",
    "metadata_xml",
  ])
    assert.equal(samlProjection({ ...provider, [field]: "not-public" }), false);
  assert.deepEqual(
    verifiedSAMLAddresses(provider, "https://console.example.com"),
    { metadata: provider.metadata_uri, acs: provider.acs_uri },
  );
  assert.equal(
    verifiedSAMLAddresses(
      { ...provider, metadata_uri: "https://other.example.com/metadata" },
      "https://console.example.com",
    ),
    null,
  );
});
test("SAML mutations carry CSRF and metadata in bodies without replay", async () => {
  const previous = globalThis.fetch,
    calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    if (url.endsWith("/login"))
      return Response.json({ csrf_token: "fixture-csrf" });
    if (init.method === "DELETE") return new Response(null, { status: 204 });
    if (url.endsWith("/start"))
      return Response.json({
        redirect_url: "https://identity.example.com/sso",
      });
    return Response.json(provider);
  };
  try {
    await api.login("member@example.com", "fixture-password");
    await api.createSAMLProvider({
      slug: "company",
      display_name: "Company SAML",
      entity_id: "urn:company",
      email_attribute: "mail",
      metadata_xml: "<private-upload/>",
      enabled: false,
    });
    assert.equal(calls.at(-1).init.headers["X-CSRF-Token"], "fixture-csrf");
    assert.equal(
      JSON.parse(calls.at(-1).init.body).metadata_xml,
      "<private-upload/>",
    );
    assert.ok(!calls.at(-1).url.includes("private-upload"));
    await api.startSAML("company", "fixture-invitation");
    assert.equal(
      JSON.parse(calls.at(-1).init.body).invite_token,
      "fixture-invitation",
    );
    assert.ok(!calls.at(-1).url.includes("fixture-invitation"));
    await api.deleteSAMLProvider(provider.id);
    assert.equal(calls.at(-1).init.method, "DELETE");
    assert.equal(calls.at(-1).init.body, undefined);
    let attempts = 0;
    globalThis.fetch = async () => {
      attempts++;
      throw new Error("offline");
    };
    await assert.rejects(
      api.updateSAMLProvider(provider.id, { enabled: true }),
      (error) => error.code === "provider_unconfirmed",
    );
    assert.equal(attempts, 1);
  } finally {
    globalThis.fetch = previous;
    clearSession();
  }
});
test("SSO catalogs retain an available protocol when the other is down", async () => {
  const previous = globalThis.fetch;
  try {
    globalThis.fetch = async (url) =>
      url.includes("/saml/")
        ? Response.json({
            items: [
              {
                slug: "company",
                display_name: "Company SAML",
                protocol: "saml",
              },
            ],
          })
        : new Response("unavailable", { status: 503 });
    let result = await api.ssoProviders();
    assert.equal(result.partial, true);
    assert.equal(result.items[0].protocol, "saml");
    globalThis.fetch = async (url) =>
      url.includes("/saml/")
        ? Response.json({ items: [] })
        : new Response("unavailable", { status: 503 });
    await assert.rejects(api.ssoProviders(), /unavailable/);
    globalThis.fetch = async (url) =>
      Response.json({
        items: url.includes("/saml/")
          ? [{ slug: "wrong", display_name: "Wrong", protocol: "oidc" }]
          : [{ slug: "company", display_name: "Company OIDC" }],
      });
    result = await api.ssoProviders();
    assert.equal(result.items.length, 1);
    assert.equal(result.items[0].protocol, "oidc");
  } finally {
    globalThis.fetch = previous;
  }
});
