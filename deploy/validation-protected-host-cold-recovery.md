# Isolated protected-host cold recovery

Source `a2bb4efd9b6c364ef63463fe18bc05724a3d8d09` passed
[cold recovery run 42538171102](https://github.com/KazuhaHub/nethub/actions/runs/42538171102)
using the successful six-job [CI producer 42538171113](https://github.com/KazuhaHub/nethub/actions/runs/42538171113).
PR #223 merged as `16c4f458f80dbeae7752984f62f978d26dda25b5` with a tree
identical to the tested source. All 48 branch commits carry human DCO sign-offs.

This extends the earlier [six-service recovery](validation-clean-host-restore.md)
to the separately configured issuer installation. It is an isolated hosted
Linux/KVM experiment with a genuine native OPNsense client and independent private
Pebble CA. It is not a public VPS/operator drill or a production restore command.

## Executed sequence

1. Initialize the source deployment and independent backup, enroll through the
   genuine native page, and retain the device's key, original CSR and assignment.
   Open the original route through the normal console action and verify its TLS.
2. Configure the protected issuer, register its private test-CA account, and
   retain the original initial issuance request. Capture the full database,
   matching deployment keys, account/publisher state, policies, helper and stock
   service/timer installation at the guarded checkpoint.
3. Stop and reap the original source guest before creating a distinct empty
   target. Restore the checkpoint there; the source cannot keep serving requests.
4. Verify the retained console actor, original request and unchanged normal Open
   grant. Recover the same assigned TLS route without another enrollment, Rotate,
   requested client restart or SQL-created/renewed source grant.
5. Resume the stock cleanup and issuer timers. Require generation one of the
   same initial request to issue through its retained account, key and CSR;
   confirm native application, its authenticated database acknowledgement and
   the exact served leaf through the original route.
6. Use the genuine native Remove action. Verify server revocation and route
   closure, then reap the source, target, appliance and independent witness.
   The outer guard independently confirms removal of owned disks, keys and logs.

The original identity, native process, GUI key, assignment, security checks and
exact Alternate Hostname remain fenced throughout. The fixture uses private CA
trust and controlled forwarding; it does not establish public DNS, public CA
trust or independent external reachability.

## Measurements and evidence

| Observation                                                                      | Measured interval                |
| -------------------------------------------------------------------------------- | -------------------------------- |
| Original baseline TLS route recovered                                            | 120.047 seconds from source stop |
| Original-request issuance, native acknowledgement and issued-leaf route verified | 179.847 seconds from source stop |
| Checkpoint start through that verified issuance/application                      | 194.383 seconds                  |

These include target boot and restoration work. They are observations from one
hosted run, not an outage SLO or a renewal-clock measurement. The existing
120-second issuance wait starts after restoration and timer resumption; its
deadline was not enlarged to obtain this result.

Both complete official job logs, the official artifact ZIP digest and every
extracted byte, all eight closed operation proofs and the independent cleanup
receipt were checked. Both native image hashes and actual views were reviewed.
Enrollment and removal are visible; the fixed native footer clips lower Remove
content. Separate native/model/SQL/service/route checks establish removal.
Private accounts, keys, transfers, raw child logs and disks remain outside Git
and public artifacts.

The same exact source also passed:

- All six CI jobs, actual SQL/authority/OpenSSL controls, five final assembled
  image scans without advisory suppression, ten Keycloak and thirteen two-Dex
  cases, cleanup and nine reviewed browser views.
- [Installed run 42538171156](https://github.com/KazuhaHub/nethub/actions/runs/42538171156):
  normal rotation, both interrupted recoveries, trust conflict, committed replay
  after later publication, shared-token recovery, six-service restoration,
  Remove and the complete tail. Replay recovered in 5.426 seconds; six-service
  restoration recovered both routes in 62.222 seconds. Thirteen image hashes and
  eleven unique views, exact source/archive/logs and cleanup were checked.
- Fresh-target recovery with three genuine systemd controls, recovery-database
  negative controls, 214 FreeBSD cases against all 248 source blobs, and fresh
  unsigned appliance preparation with four image hashes/three unique views.

## Retained failures and limits

Source `f08585d` failed a later independent
[cold run 43549725074](https://github.com/KazuhaHub/nethub/actions/runs/43549725074)
at `native_baseline`, before checkpoint or target restoration. Its closed trace
ends in the native fixture's `install-bound-key` SSH call. The exported category
was only `other`; it does not distinguish transport failure from fixture refusal.
Both full job logs, the exact official result archive and source-bound closed
failure/cleanup validation were retained. The operation cgroup, owned guests,
private material and witness were removed. This failed run does not supersede
earlier successful evidence or establish a new recovery result.

The follow-up retains the SSH probe's existing fixed failure category as a typed
optional field in the closed cold-failure result. It validates the category again
before export, including the bounded fixture phase/context vocabulary. Labels,
arguments, child text, addresses and credentials are excluded. This diagnostic
does not establish the original failed run's cause.

Separately, private input staging now checks the fixed read-only root boundary
before its first upload. It shares the existing four-event inspection-recovery
budget and preserves pinned host-key/authentication refusals. Only the owned
guest's existing private listener may be recovered before staging. A failed or
timed-out upload is not retried; native actions, deadlines and timed measurements
are unchanged.

Earlier cold attempts remain failed records. The prior source reached initial
validation but retained a terminal policy failure. Its private CA response was
not exported. The pinned Pebble validator constructs an explicit HTTP port 80;
the witness had admitted only the bare hostname. Actual HTTP round trips
reproduced the rejection before correction and passed afterward. The witness
now admits the bare assigned name or exactly `name:80`; alternate authorities,
peers, methods and unrelated paths remain refused. Product timers, retry policy
and success criteria did not change. This proves the fixture defect and the
later successful run, not a retrospective explanation of every earlier failure.

Complete W7 still needs a fresh public-VPS/operator recovery drill, independently
durable encrypted off-host custody, the remaining public/mobile/provider and
external-port checks, published-package agreement, documentation/disclosure
review and formal release/canary acceptance. Renewal clocks and earlier
intermittent native failure causes remain separate. Authcore's official-SAML
candidate PR #37 retains its called advisory failure and is not adopted here.
