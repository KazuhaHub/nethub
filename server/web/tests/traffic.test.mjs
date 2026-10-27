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
const { trafficProjection, formatBytes, validWarning, validMonth } = await load(
  "../src/traffic-values.ts",
);
const { api, clearSession } = await load("../src/api.ts");
const page = {
  month: "2026-10",
  in_bytes: "9223372036854775807",
  out_bytes: "9223372036854775807",
  total_bytes: "18446744073709551614",
  reset_events: "2",
  first_observed_at: "2026-10-26T00:00:00Z",
  last_observed_at: "2026-10-26T00:01:00Z",
  warning_bytes: "18446744073709551613",
  warning: true,
  warning_revision: 2,
  items: [],
  next_cursor: null,
};

test("traffic projections preserve wide exact counts and reject inconsistent or private data", () => {
  assert.equal(trafficProjection(page), true);
  for (const patch of [
    { total_bytes: "18446744073709551615" },
    { total_bytes: 18446744073709551614n },
    { warning: false },
    { warning_bytes: "01" },
    { warning_revision: 9007199254740992 },
    { reset_events: "-1" },
    { first_observed_at: null },
    { last_observed_at: "2025-01-01T00:00:00Z" },
    { baseline: "private" },
    { month: "0000-10" },
  ])
    assert.equal(trafficProjection({ ...page, ...patch }), false);
  const item = {
    device_id: "00000000-0000-4000-8000-000000006000",
    label: "Removed appliance",
    hostname: "",
    removed: true,
    in_bytes: page.in_bytes,
    out_bytes: page.out_bytes,
    total_bytes: page.total_bytes,
    reset_events: "2",
    first_observed_at: page.first_observed_at,
    last_observed_at: page.last_observed_at,
  };
  assert.equal(trafficProjection({ ...page, items: [item] }), true);
  assert.equal(trafficProjection({ ...page, items: [item, item] }), false);
  assert.equal(
    trafficProjection({
      ...page,
      items: [{ ...item, device_secret_hash: "private" }],
    }),
    false,
  );
  assert.equal(
    trafficProjection({
      ...page,
      total_bytes: "0",
      in_bytes: "0",
      out_bytes: "0",
      warning: false,
      warning_bytes: null,
      first_observed_at: null,
      last_observed_at: null,
    }),
    true,
  );
});
test("byte formatting never rounds through JavaScript Number", () => {
  assert.equal(formatBytes("1023"), "1023 B");
  assert.equal(formatBytes("1024"), "1.0 KiB");
  assert.equal(formatBytes("18446744073709551614"), "15.9 EiB");
  assert.throws(() => formatBytes("1e10"));
  for (const value of ["0", "1", "9".repeat(30)])
    assert.equal(validWarning(value), true);
  for (const value of ["", "01", "-1", "9".repeat(31), "1.5"])
    assert.equal(validWarning(value), false);
  assert.equal(validMonth("0001-01"), true);
  assert.equal(validMonth("2026-13"), false);
});
test("traffic reads are passive only when requested and warning PATCH is explicit CSRF with no replay", async () => {
  const original = globalThis.fetch,
    requests = [];
  try {
    globalThis.fetch = async (url, options) => {
      requests.push({ url, ...options });
      return Response.json({
        signed_in: true,
        user: { id: "admin", email: "admin@example.com", role: "admin" },
        csrf_token: "fixture-csrf",
        session_expires_at: "2026-10-27T00:00:00Z",
      });
    };
    await api.session();
    globalThis.fetch = async (url, options) => {
      requests.push({ url, ...options });
      return Response.json(page);
    };
    await api.traffic("2026-10", "cursor", undefined, true);
    assert.equal(requests.at(-1).headers["X-NetHub-Background"], "1");
    assert.equal(
      new URL(
        requests.at(-1).url,
        "https://console.example.com",
      ).searchParams.get("month"),
      "2026-10",
    );
    await api.setTrafficWarning("18446744073709551613", 2);
    assert.equal(requests.at(-1).method, "PATCH");
    assert.equal(requests.at(-1).headers["X-CSRF-Token"], "fixture-csrf");
    assert.equal(requests.at(-1).headers["X-NetHub-Background"], undefined);
    assert.deepEqual(JSON.parse(requests.at(-1).body), {
      warning_bytes: "18446744073709551613",
      expected_revision: 2,
    });
    const before = requests.length;
    globalThis.fetch = async (url, options) => {
      requests.push({ url, ...options });
      throw Error("response lost");
    };
    await assert.rejects(api.setTrafficWarning("0", 3), /Could not reach/);
    assert.equal(requests.length, before + 1);
  } finally {
    globalThis.fetch = original;
    clearSession();
  }
});
