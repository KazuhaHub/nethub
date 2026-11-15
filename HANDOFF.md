# NetHub handoff for Ubuntu

Updated: 2026-11-15 UTC. Work stopped at the owner's request after reviewing the
current validation runs. The project is **pre-alpha and incomplete**. No pending
product PR was merged, and no release was tagged, signed or published.

## Start here

```sh
git clone --branch docs/ubuntu-handoff https://github.com/KazuhaHub/nethub.git
cd nethub
python3 tools/handoff/verify.py
```

This branch contains the latest native-test transport correction, these handoff
documents, portable checks and durable validation evidence. It does not require
the previous workstation, its files, credentials, Hyper-V guests or private
orchestration scripts. Provision your own disposable lab and operator secrets.

Read these in order:

1. [Current results and the first unresolved failure](docs/handoff/validation.md).
2. [Ubuntu setup, tests and hosted native reproduction](docs/handoff/ubuntu.md).
3. [All 29 requirements and their remaining acceptance work](docs/handoff/remaining-work.md).
4. [Confirmed decisions and external repository work](docs/handoff/decisions-and-repositories.md).

The original [PLAN](docs/PLAN.md) and [DESIGN](docs/DESIGN.md) remain the scope
references. Older chronological notes describe their original source and must
not override this dated snapshot. The [evidence index](docs/handoff/evidence/index.json)
records source commits, runs, original artifact digests and committed file hashes.

## Branches and changes

| Work | Exact source | State at handoff |
| --- | --- | --- |
| `main` | `c9e74abb1fb1c060ab32ee880d20f32d8d7a653b` | Last merged baseline |
| [PR #231](https://github.com/KazuhaHub/nethub/pull/231), `feat/revocation-deadline` | `a29fbfe52a1a7774a538a33081277be2a253ab97` | Draft; CI and isolated cold recovery passed; installed upgrade failed |
| [PR #242](https://github.com/KazuhaHub/nethub/pull/242), `feat/external-tcp-doctor` | `a4d8a1c456464bb3a5707ad8b5c4fa6071ea592e` | Draft, stacked on #231; external TCP mode and tests implemented; native run failed before package migration |
| `docs/ubuntu-handoff` | Parent is `a29fbfe52a1a7774a538a33081277be2a253ab97` | Documentation/evidence delivery; no new product behavior |

PR #242 diverged before the transport correction. Do not assume its source
contains that correction merely because its target branch advanced. A copy of
its implementation patch is included under [patches](docs/handoff/patches/README.md).

## Resume with the native upgrade failure

The newest installed run is
[43698475533](https://github.com/KazuhaHub/nethub/actions/runs/43698475533).
It passed enrollment, WAN recovery, the initial migration baseline, relay
widening, the first planned outage, installation/recovery of unsigned 0.0.18,
the legacy steady window and the second planned outage. It failed during the
upgrade attempt with:

```text
Package migration changed enrollment, GUI, trust or witness process
```

The aggregate check did not record which comparison failed. The cause is
**unknown**; do not weaken that invariant or call the migration successful.
Start at `invariants()` and `install()` in
[package_migration.py](agents/opnsense/acceptance/package_migration.py), and the
fingerprints in [package_probe.py](agents/opnsense/acceptance/package_probe.py).
Add a closed diagnostic identifying only the differing category, then reproduce
on a fresh hosted guest. Never publish model values, credentials, GUI keys or
raw private configuration. A package mutation or ambiguous SQL operation must
not be replayed to make a run pass.

The earlier upload timeout remains a separate retained failure. Staging the
observer before enrollment/WAN changes allowed the latest run to progress to
real package operations; it did not prove the underlying timeout's cause.

After fixing the native failure, integrate the external doctor change, collect
new exact-source evidence, and continue the remaining requirements. A green
unit suite or isolated twelve-client test is not full W5, public-network,
formal-package or release acceptance.
