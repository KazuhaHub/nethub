import assert from "node:assert/strict";
import { schema, trafficFailure } from "./traffic-failure.mjs";

const privateText =
  "private-host.invalid credential-fixture request-and-session";
const error = Object.assign(new Error(privateText), {
  name: "TimeoutError",
  actual: { secret: privateText },
});
const projection = trafficFailure(error, "background_poll", {
  lastHTTPStatus: 200,
  browserErrors: 0,
  refused: 2,
  visibleRows: 2,
  privateText,
});
assert.equal(projection.phase, "background_poll");
assert.equal(projection.failure_kind, "timeout");
assert.equal(projection.unexpected_proxy_connections, 2);
assert.equal(projection.csp_violations, null);
assert.ok(!JSON.stringify(projection).includes(privateText));
assert.ok(schema.phases.every((phase) => /^[a-z_]{1,40}$/.test(phase)));
assert.equal(new Set(schema.phases).size, schema.phases.length);
assert.deepEqual(
  trafficFailure({ message: privateText }, privateText, {
    browserErrors: privateText,
    refused: Infinity,
    visibleRows: -1,
    cspViolations: 1_000_001,
    lastHTTPStatus: privateText,
  }),
  {
    version: 1,
    phase: "unclassified",
    failure_kind: "other",
    last_http_status: 0,
    browser_errors: -1,
    unexpected_proxy_connections: -1,
    csp_violations: null,
    visible_rows: null,
  },
);
assert.equal(
  trafficFailure({ code: "ERR_ASSERTION" }, "rows").failure_kind,
  "assertion",
);
console.log(
  "Traffic failure projection retains bounded phases/counters and excludes private error data",
);
