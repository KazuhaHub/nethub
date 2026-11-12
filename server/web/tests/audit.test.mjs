import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
const source = readFileSync(new URL("../src/api.ts", import.meta.url), "utf8");
const { api, validAuditPage } = await import(
  `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`
);
const id = "11111111-1111-4111-8111-111111111111";
const page = {
  items: [
    {
      id,
      created_at: "2026-11-12T00:00:00Z",
      actor_type: "user",
      actor: id,
      action: "user.updated",
      target_device_id: null,
      details: { disabled: false, sessions_revoked: 0 },
    },
  ],
  next_cursor: null,
};

test("audit projection refuses raw payloads, unknown details and inconsistent entries", () => {
  assert.equal(validAuditPage(page), true);
  for (const patch of [
    { payload: {} },
    { details: { token: "fixture-secret" } },
    { actor: "invalid" },
    { actor_type: "unknown" },
    { actor_type: ["system"] },
    { created_at: "invalid" },
    { details: { sessions_revoked: -1 } },
    { client_ip: "https://example.com" },
    { target_device_id: 123 },
  ]) {
    assert.equal(
      validAuditPage({ ...page, items: [{ ...page.items[0], ...patch }] }),
      false,
    );
  }
  assert.equal(
    validAuditPage({ ...page, items: [page.items[0], page.items[0]] }),
    false,
  );
  assert.equal(
    validAuditPage({ ...page, next_cursor: "private value" }),
    false,
  );
  assert.equal(validAuditPage({ ...page, raw: {} }), false);
  assert.equal(validAuditPage({ items: [], next_cursor: null }), true);
});

test("audit filter reads preserve explicit timezone, opaque cursor and encoded filters without retry", async () => {
  const original = globalThis.fetch;
  const calls = [];
  try {
    globalThis.fetch = async (url, options) => {
      calls.push({ url, ...options });
      return Response.json(page);
    };
    await api.audit(
      {
        action: "device.access_granted",
        device_id: id,
        user_id: "",
        since: "2026-11-12T08:00:00+08:00",
        until: "",
      },
      "opaque_cursor",
    );
    const url = new URL(calls[0].url, "https://console.example.com");
    assert.equal(url.searchParams.get("since"), "2026-11-12T00:00:00.000Z");
    assert.equal(url.searchParams.get("cursor"), "opaque_cursor");
    assert.equal(url.searchParams.get("device_id"), id);
    assert.equal(url.searchParams.get("user_id"), null);
    assert.equal(calls[0].method, "GET");
    assert.equal(calls.length, 1);
    globalThis.fetch = async () =>
      Response.json({ ...page, payload: "private" });
    await assert.rejects(
      api.audit(
        { action: "", device_id: "", user_id: "", since: "", until: "" },
        null,
      ),
      /could not be verified/,
    );
  } finally {
    globalThis.fetch = original;
  }
});
