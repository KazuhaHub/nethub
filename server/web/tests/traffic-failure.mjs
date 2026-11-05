import { readFileSync } from "node:fs";

export const schema = JSON.parse(
  readFileSync(
    new URL("./traffic-failure-schema.json", import.meta.url),
    "utf8",
  ),
);
const count = (value) =>
  Number.isInteger(value) && value >= 0 && value <= 1_000_000 ? value : -1;
const optionalCount = (value) => (count(value) >= 0 ? value : null);

// Error messages, stacks, requests and assertion values stay in private logs.
export function trafficFailure(error, phase, observed = {}) {
  return {
    version: 1,
    phase: schema.phases.includes(phase) ? phase : "unclassified",
    failure_kind:
      error?.name === "TimeoutError"
        ? "timeout"
        : error?.code === "ERR_ASSERTION"
          ? "assertion"
          : "other",
    last_http_status:
      Number.isInteger(observed.lastHTTPStatus) &&
      observed.lastHTTPStatus >= 100 &&
      observed.lastHTTPStatus <= 599
        ? observed.lastHTTPStatus
        : 0,
    browser_errors: count(observed.browserErrors),
    unexpected_proxy_connections: count(observed.refused),
    csp_violations: optionalCount(observed.cspViolations),
    visible_rows: optionalCount(observed.visibleRows),
  };
}
