# Isolated clean-host control-plane recovery

Source `dcbb83d71f3da77b733a4ba6afcf551ef77043bd` passed the complete installed
[run 41984680901](https://github.com/KazuhaHub/nethub/actions/runs/41984680901).
The exact archive, both full job logs, eight image hashes/actual views, guest
exit zero, owned-image cleanup and complete original Compose tail were checked.
All 26 commits carry human DCO sign-offs. This is a tested checkpoint in
[PR #194](https://github.com/KazuhaHub/nethub/pull/194), not a merged release or
acceptance of later source changes.

## Restored state and retained clients

The source had already completed genuine shared-token replacement and native
credential rotation. The drill retained its current matching keys, independent
successor backup, authority/operation history and a newly verified restricted
PostgreSQL archive. It used a distinct, initially empty Ubuntu 24.04 hosted guest
with a new database cluster, Docker 29.1.3 and Compose 2.40.3.

The saved and reloaded images matched configuration digests and every uncompressed
layer. The restored database matched all table/sequence contents, ownership,
object/column/default grants, role state, definitions, constraints, indexes and
RLS metadata. Current-key/file readiness, audit and service separation checks
passed after starting six new services. The original six services stayed stopped
through the recovered-host proof.

The original administrator logged in and read inventory from the source host
over verified HTTPS. Normal authenticated Open calls admitted an owned private
target-interface source outside the Docker subnet. Each response expiry matched
the exact actor/source grant; the browser forward used that same owned source.
No SQL grant insertion, forwarding-header forgery or admission-policy change was
used. Both original source-host TLS routes recovered automatically with the same
native assignment and independent witness. The driver issued no client restart,
Rotate or new enrollment command during host recovery. The native GUI key, checks and
exact alias were unchanged.

Source stop to verified recovery of both routes measured **56.425 seconds**.
This includes restoring and starting the new control plane; it is not a general
reconnect-time guarantee or an Internet/mobile measurement. The existing
90-second route-check deadline was unchanged.

The drill removed its target stack and guest, recovered the original fixture and
verified both routes again before genuine native Remove. Removal's database,
XML/model, service and route checks passed, as did the complete remaining tail.
The Remove screenshot clips the lower rotation section at the native footer;
its functional cleanup has independent checks. Positive and interrupted rotation
views retain the fixture's status mask and blank enrollment token field.

## Independent prerequisites and retained failures

All six jobs in [CI 41984680910](https://github.com/KazuhaHub/nethub/actions/runs/41984680910)
passed with complete official logs and actual SQL/storage/custom-restore/authority
regression markers checked. Separate Linux execution passed all 44 recovery
methods without skips and seven genuine database-authority negative controls.
FreeBSD passed 214 actual cases and all 243 source blobs with its exact receipt
validator. Fresh unsigned preparation passed installation/configd/page checks on
OPNsense 26.7.8_2 with frpc 0.71.1 built by Go 1.26.10; all four preparation
image hashes/views were checked. The accepted 1 GiB appliance deviation remains.

Earlier failed runs remain failed. Source22's two clients/proxies were online,
but all 163 actual NewUserConn refusals were source-access denials; all 163
recorded peers differed from the address chosen from Open grants. The corrected
fixture selects its owned source from routing metadata, then binds normal Open
and the browser forward to that source and verifies the fresh persisted grant.
An online proxy, authorized different address or target-local probe did not
substitute for the two original source-host routes.

## Remaining W7 requirements

This hosted guest is an isolated fixture, not a fresh public VPS/operator drill
or a general production restore command. Its private transfers are not durable
off-host encrypted custody. It does not restore the separately configured GUI
issuer's account, HTTP-01/publisher state, helper or systemd installation, or
prove resumed certificate automation after cold-host loss. Public/mobile checks,
external port witnesses, published-package agreement and formal release remain
separate. W7-5 and the full project goal are incomplete.

See the [drill sequence](../server/tests/recovery/README.md),
[custody inventory](database-backups.md#custody-and-restoration) and
[account namespace procedure](../server/internal/guiacme/PROVISIONING.md).
