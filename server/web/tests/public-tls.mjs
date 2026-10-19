import assert from "node:assert/strict";
import { Agent, request } from "node:https";
import { rootCertificates } from "node:tls";

// Use the bundled public CA set, independent of browser test-CA exceptions.
export async function probePublicTLS(origin, path = "/") {
  const target = new URL(origin);
  assert.ok(
    target.protocol === "https:" && !target.username && !target.password,
  );
  assert.ok(!target.search && !target.hash && ["/", "/healthz"].includes(path));
  target.pathname = path;
  const agent = new Agent({
    ca: rootCertificates,
    rejectUnauthorized: true,
    proxyEnv: {},
    keepAlive: false,
  });
  try {
    return await new Promise((resolve, reject) => {
      const req = request(
        target,
        {
          agent,
          method: "HEAD",
          signal: AbortSignal.timeout(10000),
        },
        (response) => {
          const certificate = response.socket.getPeerCertificate();
          const result = {
            status: response.statusCode,
            authorized: response.socket.authorized,
            issuer: certificate.issuer?.CN,
            fingerprint256: certificate.fingerprint256,
            validTo: certificate.valid_to,
          };
          response.on("error", reject);
          response.on("end", () => resolve(result));
          response.resume();
        },
      );
      req.on("error", reject);
      req.end();
    });
  } finally {
    agent.destroy();
  }
}
