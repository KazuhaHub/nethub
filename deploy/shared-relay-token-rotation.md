# Shared relay token replacement

This host operation is under isolated acceptance testing. It changes the two
deployment token files, the setup manifest and the bound authz/frps services.
The existing per-device **Rotate credentials** operation then obtains the new
assignment using that device's saved bearer over verified console HTTPS.

Before the window, arrange independent local, console or SSH management for every
online router being refreshed. Restarting frps interrupts NetHub tunnels, so the
NetHub route alone cannot carry the following device action. Keep the control
plane reachable over its normal verified HTTPS address. Router GUI keys, login
settings, exact Alternate Hostnames and source-IP grants remain unchanged.

Before cutover, record which devices will participate through independent
management and which are offline. Do not count an unavailable device as recovered.
For offline devices requiring manual re-enrollment, revoke their old console
inventory entries before returning them to service. Keep at least one participating
nonrevoked device available for the host command's admission preflight.

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

Schedule these steps for devices participating in the controlled window. Shared
token replacement itself does not expire a stored device bearer or provide
automatic fleet delivery. Record each device's verified route recovery and any
remaining manual work; server completion alone is not a fleet recovery receipt.

## Return an offline device through manual enrollment

Use independent local, console or SSH management when the device returns:

1. Confirm its old console inventory entry has been revoked. This explicit
   action disables the old device authority; changing only the shared token does
   not revoke its device bearer.
2. Use the plugin's **Remove enrollment** action and confirm completion. It stops
   the tunnel, confirms server revocation and clears saved enrollment. If a
   rotation response was lost, this removal action can retry revocation with the
   retained candidate; finish its confirmed cleanup before enrolling again.
   Preserve conflicts for local review rather than deleting its journal.
3. Create a new one-use enrollment token in the console and use the normal
   console-address/token inputs on the plugin page. Keep that token private.
4. Record the new device identity and assigned hostname. Manual enrollment is a
   new onboarding operation; it does not preserve the old identity or transfer
   the old device's source-IP grants. Review the native enabled flag and local
   stop/circuit policy before allowing the new tunnel to run.
5. Complete the normal GUI certificate and exact Alternate Hostname checks for
   the new assignment. Keep DNS-rebinding and HTTP_REFERER checks enabled. From
   an authorized browser, explicitly **Open** the new device and verify normal
   HTTPS trust, GUI login and page refresh before recording recovery.

The old revoked inventory entry remains historical evidence. Its old hostname
and a successful server operation are not proof that this newly enrolled device
is usable. Offline re-enrollment and public/mobile operator checks have separate
acceptance boundaries from the isolated online incident fixture.

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
