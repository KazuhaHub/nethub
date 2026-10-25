import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";

const source = readFileSync(
  new URL("../src/invitation-safety.ts", import.meta.url),
  "utf8",
);
const { takeInvitation, validInvitationLink, validInvitationPassword } =
  await import(
    `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source, { mode: "transform" })).toString("base64")}`
  );
const token = Buffer.alloc(32, 12).toString("base64url");

test("invitation extraction clears the fragment before any caller can use it", () => {
  for (const [hash, search, expected] of [
    [`#${token}`, "", token],
    ["#bad", "", null],
    [`#${token.slice(0, -1)}B`, "", null],
    [`#${token}`, "?token=ignored", null],
    ["", "", null],
  ]) {
    const calls = [];
    assert.equal(
      takeInvitation(
        { pathname: "/invite", hash, search },
        { replaceState: (...args) => calls.push(args) },
      ),
      expected,
    );
    assert.deepEqual(calls, [[null, "", "/invite"]]);
  }
  assert.equal(
    takeInvitation(
      { pathname: "/invite", hash: `#${token}`, search: "" },
      {
        replaceState: () => {
          throw Error("history unavailable");
        },
      },
    ),
    null,
  );
  let touched = false;
  assert.equal(
    takeInvitation(
      { pathname: "/", hash: `#${token}`, search: "" },
      {
        replaceState: () => {
          touched = true;
        },
      },
    ),
    null,
  );
  assert.equal(touched, false);
});

test("generated invitations require the current HTTPS origin and a canonical fragment", () => {
  const origin = "https://console.example.com";
  const expiry = new Date(Date.now() + 60000).toISOString();
  assert.equal(
    validInvitationLink(`${origin}/invite#${token}`, origin, expiry),
    true,
  );
  for (const url of [
    `https://attacker.example/invite#${token}`,
    `http://console.example.com/invite#${token}`,
    `${origin}/invite?token=${token}`,
    `${origin}/invite#${token.slice(1)}`,
    `${origin}/other#${token}`,
    `https://name:pass@console.example.com/invite#${token}`,
    "javascript:alert(1)",
  ])
    assert.equal(validInvitationLink(url, origin, expiry), false);
  assert.equal(
    validInvitationLink(`${origin}/invite#${token}`, origin, "invalid"),
    false,
  );
  assert.equal(
    validInvitationLink(
      `${origin}/invite#${token}`,
      origin,
      new Date(0).toISOString(),
    ),
    false,
  );
});

test("invitation passwords use Unicode characters and UTF-8 bytes without trimming", () => {
  for (const value of [
    "a".repeat(15),
    "😀".repeat(15),
    "a".repeat(1024),
    "a".repeat(14) + " ",
  ])
    assert.equal(validInvitationPassword(value), true);
  for (const value of [
    "a".repeat(14),
    "😀".repeat(14),
    "a".repeat(1025),
    "😀".repeat(257),
    "a".repeat(15) + "\n",
    "a".repeat(15) + "\r",
    "a".repeat(15) + "\0",
    "a".repeat(15) + "\ud800",
  ])
    assert.equal(validInvitationPassword(value), false);
});
