# W2 native integration validation

Validated on 2026-10-18 using the isolated OPNsense 26.7.7 / FreeBSD 15 amd64
NAT guest, two vCPUs, and Kazuha's approved 1 GiB memory exception. NetHub's
independent frpc, legacy os-frp, and the isolated relay use frp 0.71.1.
Packages used here are unsigned development artifacts.

| Requirement | Observed result |
|---|---|
| Reconcile branches | Eleven native tests passed, including invalid-candidate preservation, unchanged/running and unchanged/stopped cases, kill switch, operator stop, CA/name requirements, and concurrency exclusion. |
| Independent watchdog | Nine native tests passed, including actual FreeBSD lockf contention, persistent one-attempt budget, rejected-hash quarantine, changed-desired release, abandoned startup refusal, and revoked/disabled suppression. |
| Live rollback | A valid but unreachable candidate stopped the real process. Watchdog restored last-good once; scheduled reconcile preserved the recovered file and PID. Another stop exhausted the budget; both reconcile and rc startup refused restart. A different validated desired configuration released quarantine. |
| Package integration | Native build, PHP syntax, pkg installation/checksum, configd structured JSON, and model validation passed. Candidate and live configurations were mode 0600. |
| GUI debug settings | The real save endpoint rejected a quoted device ID. GET returned blank credentials; blank secret writes retained stored values. |
| TLS | Correct CA/name allowed real login and registration; unrelated CA and wrong server name blocked default-mux login. Separate non-mux diagnostics exposed explicit X.509 errors, but their valid baseline did not register, so they are diagnostic evidence only. |
| Bad candidate | An unknown key failed strict verification without changing the live file or PID. The API retained a safe structured error. |
| Kill switch | Stopped the actual process without changing config.xml; removing the marker allowed recovery. |
| Coexistence | Legacy client/server and NetHub ran simultaneously with distinct client PIDs. The legacy tunnel worked, both legacy TOML files and rc fragments retained baseline hashes, and NetHub exposed no admin listener. Recorded swap-out pages were zero. |
| Browser | Authenticated through the relay, loaded eleven populated Dashboard widgets, observed repeated clock/API refresh, navigated to administration and back, with zero JavaScript/HTTP/request errors. Exact alternate hostname and both security checks remained enabled. Repeated successfully after NetHub's automatic reboot recovery. |
| WAN recovery | With a valid default route, kernel WAN-address replacement produced registration/source-address recovery at 17.072s and relayed login at 21.375s. PID unchanged; no manual reconcile. Original address and route restored. |
| Active reboot | New kernel boot time verified; NetHub started and the relayed login page returned without manual start or reconcile. Observation was 142.844s from reboot request, including guest boot. |
| Cron install | Package-owned system cron entry executed after 3.558s without restarting the cron master. Shared persistent nonblocking lockf lock, root fields, absolute paths, and protected plugin logging were verified. |
| Cron reboot | File persisted and subsequent scheduled output appeared during a 7.016s observation. Operator stop survived reboot. |
| Uninstall | Running NetHub process stopped; pkg removed the cron file. No new scheduled output during 65s observation. Reinstall restored scheduling. |

The live tests exposed and fixed missing boot-time log directories, configd's
handling of structured failures, and service(8)'s explicit `-E KEY=value` syntax
for the single watchdog recovery attempt. Watchdog has a ten-second phase offset
to avoid systematic contention with minute reconcile.

Legacy os-frp also exposed a boot defect: rc.freebsd sources all rc.conf.d files,
so disabled *.sample defaults can override live YES settings. Packaging PR #50
moves these samples to the shared data directory. Upgrade removes only unchanged
obsolete samples, preserving local edits with a warning. Native upgrade preserved
all four live configuration hashes; its regression and install-hook tests passed.
After a genuine reboot, all three services started automatically, the legacy
GUI tunnel worked, and all four baseline hashes remained unchanged. No manual
start was used. Packaging PR #50 merged as `fcaf6fe`.

Limits:

- Browser ingress used an SSH forward to the relay's loopback vhost; the device
  control connection crossed the public network. This is not another carrier or
  public browser-port reachability sample; W0's accepted measurements cover those.
- WAN measurement changed the guest's kernel IPv4 address behind the local NAT,
  preserving a valid default route. It does not establish multi-WAN, public-IP,
  or carrier migration behavior. D21 retains automatic reconnect for this profile.
- An earlier 115s WAN trial accidentally removed the default route and logged
  network-unreachable retries. It is invalid network preparation, not a failed
  automatic-reconnect acceptance trial.
- Initial cron reboot failed because log redirection preceded directory creation;
  the corrected hook and subsequent reboot passed. Failed observations were retained.
- Locally known revocation is enforced; receiving verified remote revocation is W5.
- The temporary debug form must be removed or made read-only during W4 enrollment.
- CA private keys stayed on the workstation, outside the relay container. Raw
  addresses, credentials, logs, backups, and browser payloads remain outside Git.
- Stock pinned SSH host key and password authentication were retained. The plugin
  does not alter SSH policy. No signing or release publication was performed.

Final cleanup restored the original legacy files and both plugin model subtrees,
stopped all test services, removed the test CA/live tunnel configuration, and
retained an operator stop marker. Relay stages were archived before removal;
owned test listeners are closed, and the original relay listeners remain active.
Private evidence archives remain outside Git. The development packages remain
installed, ready for subsequent isolated tests.

Selected native harness results (deployment identifiers omitted):

```json
{
  "bad_candidate": {
    "rejected": true,
    "pid_unchanged": true,
    "live_unchanged": true,
    "candidate_mode": "0o600",
    "message": "frpc rejected the candidate configuration; live configuration was retained"
  },
  "kill_switch": {
    "success": true,
    "service_stopped": true,
    "config_xml_unchanged": true
  },
  "live_mode": "0o600",
  "wan_recovery": {
    "login": true,
    "proxy": true,
    "pid_unchanged": true,
    "source_changed": true,
    "elapsed_seconds": 17.072,
    "gui_recovered": true,
    "gui_observation_seconds": 21.375,
    "original_address_restored": true,
    "manual_reconcile_invoked": false
  },
  "watchdog_recovery": {
    "success": true,
    "action": "rollback"
  },
  "second_watchdog": {
    "success": false,
    "action": "already_attempted"
  },
  "rc_start_rejected_abandoned": true,
  "coexistence_after_reboot": {
    "services": {
      "frpc": true,
      "frps": true,
      "nethub_agent_frpc": true
    },
    "legacy_gui": true,
    "old_samples_absent": true,
    "new_boot_verified": true,
    "baseline_unchanged": true,
    "observation_seconds": 193.093,
    "manual_start_after_boot": false
  }
}
```
