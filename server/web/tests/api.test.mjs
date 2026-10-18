import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";

const source = readFileSync(new URL("../src/api.ts", import.meta.url), "utf8");
const compiled = stripTypeScriptTypes(source, { mode: "transform" });
const { api, clearSession, onUnauthorized } = await import(
  `data:text/javascript;base64,${Buffer.from(compiled).toString("base64")}`
);

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
