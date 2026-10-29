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

Source `e3dfef5` passed all six jobs in
[CI 40845857458](https://github.com/KazuhaHub/nethub/actions/runs/40845857458),
including the actual empty-device-table refusal with unchanged material/backup,
all six service IDs and no candidate/operation records. Actual SIGTERM during
reload resumed the same candidate; only authz/frps changed, and completed retry
verified without reload. Both online reference routes recovered through their
saved bearers in 693 ms with stable identity and source grants.

The same source passed 92 protected Linux root identities and 214 actual
FreeBSD cases with all 242 source blobs verified. Fresh unsigned OPNsense
preparation passed installation/configd and four reviewed page images.
[Complete installed run 40845857496](https://github.com/KazuhaHub/nethub/actions/runs/40845857496)
performed a second cutover, refused the superseded first operation and recovered
the genuine native assigned HTTPS route in 2617 ms through the normal Rotate
page. Policy, identity/grants, GUI key/checks/alias and the independent witness
survived. Exact archive, both logs, full tail/cleanup, standalone incident JSON
and all eight image hashes/corresponding visuals were checked.

Source13's functional success had two missing artifact exports. Its nested
outcome and seven PNGs remain retained separately; complete acceptance was
withheld until the corrected run exported every required file. The upload list
now has a cross-file contract regression.

See the [validation record](../../../deploy/validation-shared-token.md) for exact
runs, measurements and image limitations. Logical coordinator/file fixtures and
actual host/native execution cover different boundaries. Public/mobile/operator
checks, offline fleet recovery, the installed trust-publication-conflict scenario,
complete restoration, off-host custody and formal release remain open. This
operation's isolated acceptance does not complete the full HANDOFF goal.
