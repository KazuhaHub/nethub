# Shared relay token transition

The Linux host command coordinates deployment-wide token replacement; the
[incident procedure](../../../deploy/shared-relay-token-rotation.md) covers
independent router management, online Rotate and manual offline recovery.

## Ordering and recovery

One protected command record retains the original operation UUID, deployment,
service binding, successor-backup path and baseline before initialization. The
host holds the shared relay lease through the transition. Retained input also
fences ordinary maintenance before an operation directory exists; other pending
token or authority operations remain excluded after a process exits.

Preparation retains one candidate, complete original/candidate snapshots and an
independent current-key successor backup. The manifest planner permits only the
two token digests and successor-backup path to change. Publication accepts known
original/candidate live bytes and preserves unrelated credentials and authority.
Every active effect follows a durable phase: prepared, publishing, published,
reloading, verifying and complete. Ambiguous effects resume the same candidate.
Unknown temporary files or conflicting material remain for local review; this
is not a promise of automatic recovery after every hard kill or power loss.

The runtime host re-creates only the original bound authz/frps services. It
checks the served relay certificate and actual candidate/previous/candidate
Login over verified local TLS. A read-only existing device identity and the
existing claim key supply the probe; it requests no proxy. New operations
require an eligible enrolled identity before retaining a command or publishing.

Inspect reads historical state. A completed retry performs current verification
without publication or reload, and an older operation must refuse once newer
material supersedes it. Credentials belong in protected files and private
memory; command arguments and public receipts carry only fixed operation data.

## Checked evidence and remaining boundaries

Source `19bfce2` passed all six CI jobs in
[run 40841093567](https://github.com/KazuhaHub/nethub/actions/runs/40841093567).
Complete official logs and the compiled command's actual SIGTERM during durable
reload, same-candidate resume, two-service reload and no-reload completed retry
were independently checked. Four unrelated services and the original backup
survived. Both online official reference clients used their original bearers for
Rotate/replay, rejected old bearers and recovered their original verified HTTPS
routes in 876 ms with stable identity and source grants. This reference run has
no earlier completed operation, so superseded-operation refusal belongs to the
second/native cutover case.

The same source passed all 92 required protected Linux root identities in
[run 40841093548](https://github.com/KazuhaHub/nethub/actions/runs/40841093548),
with exact-source validator, complete log and bounded receipt checked. Those
cases use synthetic protected material. FreeBSD execution passed 214 cases and
all 242 source blobs were verified; fresh unsigned OPNsense preparation passed
installation/configd/page checks with four reviewed image hashes and visuals.

Complete installed run `40841093577` is executing the second server cutover,
older-operation refusal, genuine native Rotate and independent witness recovery.
Its actual outcomes and eight page images remain pending. A new pre-enrollment
Compose case requires the real command to refuse an empty device table while
preserving material, backup and all six services, without candidate/operation
records. That additional case has compilation/vet/shell checks only so far.

Logical coordinator tests cover lost effect/journal acknowledgements, changed
requests/snapshots, orphaned state and failed readback. They complement the
actual file, service and native evidence rather than establish those boundaries.
Earlier protected-parent fixture and cutoff-wait failures remain retained.
W7-4, public/mobile/operator checks, complete restoration, off-host custody and
formal release remain open.
