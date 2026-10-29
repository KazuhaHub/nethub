# Shared relay token replacement

This host operation is under isolated acceptance testing. It changes the two
deployment token files, the setup manifest and the bound authz/frps services.
The existing per-device **Rotate credentials** operation then obtains the new
assignment using that device's current authenticated console connection.

Before the window, arrange independent local, console or SSH management for every
online router being refreshed. Restarting frps interrupts NetHub tunnels, so the
NetHub route alone cannot carry the following device action. Keep the control
plane reachable over its normal verified HTTPS address. Router GUI keys, login
settings, exact Alternate Hostnames and source-IP grants remain unchanged.

## Start and verify the server operation

Run the matching host CLI as Linux root against the existing confirmed deployment.
Its original backup must verify, the bound services must be healthy, and at least
one nonrevoked enrolled identity must exist for actual token admission checks.
The command refuses before publication when that preflight is unavailable.

Choose a separate successor path outside the deployment and original backup.
Its parent must already be root-owned with mode 0700. This copy includes current
runtime keys and maintenance state as well as the generated deployment secrets.
Protect it through the deployment's independent backup/custody process; local
copy verification does not establish off-host durability.

```sh
sudo nethub relay-token rotate \
  --directory /srv/nethub \
  --project-name nethub \
  --successor-backup /srv/nethub-backups/token-successor-001
```

Supply `--compose-file` when the existing binding uses an additional protected
override. Retain the returned operation UUID. A supplied `--operation-id` permits
an automation to retain that UUID before its first invocation.

The command preserves original input before preparation and holds the shared
relay lease. It verifies an independent successor before publishing, records the
phase before each effect, and re-creates only authz/frps with the original image
and configuration binding. Completion requires the served relay certificate and
actual candidate/previous/candidate Login outcomes over verified local TLS.
The probe requests no proxy and changes no device row or grant.

`verified: true` with `phase: complete` confirms the server operation.
`device_rotation_required: true` means the device steps below still belong to the
incident. `inspect` reads historical state and reports `verified: false`; it does
not perform a fresh runtime check.

## Refresh the online devices

Through the independent management path arranged before cutover, use each native
plugin's **Rotate credentials** action, or run:

```sh
sudo /usr/local/opnsense/scripts/nethub-agent/agentctl.py rotate
```

This uses the saved device bearer and a private recoverable candidate; it does
not need a newly delivered enrollment token. Confirm a successful native model
save and the same assigned HTTPS route, then check its GUI login and refresh.
Retain local disabled, stopped and circuit-breaker policy. The action does not
grant a new source IP; use the console's normal explicit Open action when needed.

Schedule these steps for devices participating in the controlled window. Handle
offline devices through the accepted manual re-enrollment procedure. Shared
token replacement itself does not expire their stored device bearer or provide
automatic fleet delivery. Record which devices recovered and which need manual
work; server completion alone is not a fleet recovery receipt.

## Inspect and resume

```sh
sudo nethub relay-token inspect --directory /srv/nethub
nethub_operation_id='paste-the-retained-operation-uuid'
sudo nethub relay-token inspect --directory /srv/nethub --operation-id "$nethub_operation_id"
sudo nethub relay-token resume --directory /srv/nethub --operation-id "$nethub_operation_id"
```

Resume reads the original protected options, service binding, backup path and
baseline. It retains the same candidate across partial publication or ambiguous
reload replies. A completed retry verifies current state without reloading; it
refuses to reapply an older token after a newer operation changed the deployment.
Other unfinished token/authority work and ordinary maintenance remain fenced even
when the process lease has been released, including the gap before initialization.

Keep retained command, candidate, snapshot, journal and backup files private.
Changed input, unknown live bytes, links, damaged partial output or conflicting
backup content require local review. Preserve that evidence and resolve the
original operation; deleting its journal or restoring the compromised token is
not a recovery procedure. No signing or formal package publication is involved.
