import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:https";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import test from "node:test";
import { probePublicTLS } from "./public-tls.mjs";

test("public acceptance refuses an untrusted certificate before HTTP", async () => {
  const stage = mkdtempSync(join(tmpdir(), "nethub-public-tls-"));
  let server;
  let requests = 0;
  try {
    const key = join(stage, "test.key");
    const cert = join(stage, "test.crt");
    const created = spawnSync(
      process.env.NETHUB_OPENSSL_BINARY || "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-keyout",
        key,
        "-out",
        cert,
      ],
      { stdio: "pipe" },
    );
    assert.ok(created.status === 0, "Ephemeral certificate creation failed");
    chmodSync(key, 0o600);
    server = createServer(
      { key: readFileSync(key), cert: readFileSync(cert) },
      (_req, res) => {
        requests++;
        res.end("ok");
      },
    );
    server.on("tlsClientError", () => {});
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    await assert.rejects(
      probePublicTLS(`https://127.0.0.1:${server.address().port}`),
      (error) =>
        ["DEPTH_ZERO_SELF_SIGNED_CERT", "SELF_SIGNED_CERT_IN_CHAIN"].includes(
          error.code,
        ),
    );
    assert.equal(requests, 0);
  } finally {
    if (server) await new Promise((resolve) => server.close(resolve));
    assert.ok(
      dirname(resolve(stage)) === resolve(tmpdir()) &&
        basename(stage).startsWith("nethub-public-tls-"),
    );
    rmSync(stage, { recursive: true, force: true });
  }
});

test("public acceptance refuses plaintext and credential-bearing targets", async () => {
  await assert.rejects(probePublicTLS("http://127.0.0.1"));
  await assert.rejects(probePublicTLS("https://user:secret@example.com"));
});
