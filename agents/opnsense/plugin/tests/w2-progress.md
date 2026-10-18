# W2 integration evidence in progress

This is not W2 acceptance. The implementation is under review in draft PR #23.

Validated on the isolated OPNsense 26.7.7 / FreeBSD 15 amd64 guest on 2026-10-18,
using the owner-approved 1 GiB resource exception:

- Eleven controlled reconcile tests passed on native FreeBSD: verified replacement,
  rejection without restart, unchanged configuration with running/stopped service,
  kill switch, disabled settings, persistent operator stop, required CA/name,
  concurrency exclusion, and safe log-event reporting.
- The unsigned 0.0.2 development package built and installed successfully. Native
  PHP syntax checks passed; `pkg check -s os-nethub-agent` returned success.
- `configctl nethub-agent status` returned valid JSON. With incomplete relay trust
  configuration, the service remained stopped and reported a safe error.
- An authenticated browser session loaded the page without JavaScript or HTTP
  errors. The status rendered, the debug GET returned blank token/claim values,
  and the actual debug-save endpoint rejected an invalid device ID containing a
  quote. No tunnel or WAN operation was attempted in this browser check.
- Three template cases and eight artifact cases passed locally. PR CI passed all
  three jobs at `b1f78d7` (run `39119451937`).

The native guest now has the development 0.0.2 integration installed. It retains
the separately installed os-frp 1.0.2. No NetHub tunnel is running. Logs, stage
paths, configuration backups, and browser evidence remain outside Git.

Outstanding: confirm the W2-7 scheduler, implement and test the independent
one-attempt watchdog, provision the isolated authenticated relay, reject incorrect
CA/name, exercise live tunnel coexistence, verify lifecycle and reboot behavior,
and measure WAN-address recovery under D21. The temporary debug form must be
removed or made read-only in W4.
