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

Further native evidence from 2026-10-18:

- Correct CA/name allowed a real frpc login and proxy registration. An unrelated
  CA and incorrect name blocked login with the default mux transport. A separate
  non-mux diagnostic exposed explicit unknown-authority and name-mismatch errors;
  its valid baseline did not log in, so it is diagnostic evidence only, not an
  additional successful transport profile.
- The installed service started through the actual GUI/debug API. A request from
  the relay through its loopback-only HTTPS vhost reached the device login form
  over the public control connection. No public browser-vhost port was opened.
- An unknown candidate key failed native strict verification without changing
  the live file or PID. Candidate/live permissions were 0600. Restoring the
  template produced an unchanged result. The kill switch stopped the process
  without changing config.xml; removing it allowed service start.
- Nine watchdog branch tests passed natively, including the actual FreeBSD lockf
  contention check, one-attempt persistence, quarantine release, abandoned-service
  suppression, and local revocation suppression. The package scheduler shape tests
  passed locally. The rc startup guard also rejects abandoned or malformed recovery
  state; only the watchdog's budgeted attempt supplies a one-time start override.

Cron lifecycle evidence:

- The cron file was listed by pkg and installed as a package-owned file. A fresh
  reinstall produced scheduled output after 3.558 seconds without changing the
  cron master PID. The scheduler log was mode 0600.
- Uninstall stopped an actual running NetHub frpc, removed the cron file, and
  retained model settings. No scheduled output appeared during the following
  65-second observation. Reinstall restored scheduling.
- The first reboot exposed a missing scheduler log directory: the cron entry
  persisted but redirection failed before Python ran. The boot hook now recreates
  protected logging paths before redirecting output. A second native reboot
  verified the cron file persisted and subsequent scheduled output appeared during
  a 7.016-second observation. The operator stop marker remained effective.
- The stock SSH host key and password authentication passed after reboot. The
  private observation helper switched to password authentication because its
  runtime-added public key did not authenticate after boot; no SSH settings were
  changed by the plugin or this workaround.

The os-frp baseline has a separate boot defect: OPNsense rc.freebsd sources every
file under rc.conf.d, and this guest's frpc.sample is read after the live frpc
fragment, overriding YES with NO. The server started, but the client did not.
Both live TOML files and both rc fragments retained their baseline hashes. A
manual start restored the baseline tunnel without changing those hashes. This
does not prove legacy-plugin automatic startup; do not attribute that failure to
NetHub or claim it passed. No packaging-repository changes for this defect are
included in this PR.

Kazuha confirmed W2-7 cron scheduling with shared lockf, package ownership,
persistent rejected hashes/attempt budgets, and revoked-device suppression.
The temporary relay and probe were stopped after the TLS/service checks; NetHub
was explicitly stopped. Test configuration and the CA certificate remain on the
guest for the next bounded test window. CA private keys remain on the workstation,
outside the relay container.

Remaining acceptance work is NetHub automatic tunnel rejoin after reboot, final
package/CI verification, and test cleanup. The temporary debug form must be
removed or made read-only in W4. Further evidence below completes the other
previously outstanding checks.

Additional native acceptance evidence:

- os-frp and NetHub ran concurrently with distinct frpc PIDs. The legacy tunnel
  remained usable; both legacy TOML files and both rc fragments matched the
  baseline hashes. NetHub had no admin listener, its live configuration was 0600,
  and the sample recorded zero swap-out pages.
- The relayed browser authenticated, loaded eleven Dashboard widgets with populated
  data/charts, observed repeated clock/API refresh, navigated to administration,
  and returned successfully with no JavaScript, HTTP, or request failures. DNS
  rebinding and referrer checks stayed enabled. Browser ingress used a temporary
  SSH forward to the relay's loopback vhost; the device control connection crossed
  the public network. This is not a new carrier/public-8443 reachability sample.
- A kernel WAN-address replacement with a valid default route reconnected without
  manual reconcile: registration/source-address recovery was observed at 17.072s
  and the relayed login page at 21.375s. The frpc PID stayed unchanged; the original
  address and default route were restored. An earlier 115s trial had accidentally
  removed the default route and produced network-unreachable retries; it is an
  invalid network-preparation trial, not evidence that a WAN hook is required.
  D21 remains automatic reconnect with periodic reconcile for this tested profile.
- A deliberate valid-but-unreachable candidate stopped the real process. The
  independent watchdog restored the previous configuration and persisted the
  rejected hash/attempt budget. A scheduled reconcile left that recovered file
  and PID intact. After another controlled stop, watchdog refused a second
  attempt, reconcile remained quarantined, and the real rc entry rejected startup
  of the abandoned service. Restoring a different desired template released the
  quarantine and started the service through normal reconcile.
- These tests exposed and fixed two integration details: configd must retain
  structured failure output, and service(8) requires an explicit `-E KEY=value`
  assignment for the one-time recovery flag. The watchdog cron entry now has a
  ten-second offset to avoid systematic minute-boundary contention.
