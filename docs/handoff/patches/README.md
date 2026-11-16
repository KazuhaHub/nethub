# Pending implementation patches

These are exact source diffs, not releases or instructions to apply everything.
They use one line of context and omit optional hunk-section labels; actual
added/removed lines are preserved, including changed dependency checksums.
The project source and tests are already on this handoff branch. Copies of the
other pending changes avoid a dependency on a local worktree or mutable PR page.

| File | Repository | Base | Head |
| --- | --- | --- | --- |
| `external-tcp-doctor.patch` | KazuhaHub/nethub | `e22ae9c3c7851519e97a7a53705ea948feb37868` | `a4d8a1c456464bb3a5707ad8b5c4fa6071ea592e` |
| `dependency-refresh-pr241.patch` | KazuhaHub/nethub | `c9e74abb1fb1c060ab32ee880d20f32d8d7a653b` | `5a4ccf3c1f952c497126454a5d1a8b9b4139abbb` |
| `packaging-pr52.patch` | KKazuhaK/OPNsense-repo | `fcaf6fe67c1bd296ebb7e5652183512fcf2983fa` | `85c5c522735a723ebb07a324283a7be62da6255c` |
| `authcore-pr37.patch` | KazuhaHub/authcore | `f3886de2dcef2fc09536b97b4ec4c93dcf5df1cb` | `e3e8cc05330fcff6cbd21c6f38e10320a165c0e1` |

Verify the hashes with `python3 tools/handoff/verify.py`. Read each PR's status
and remaining gate before applying. No dependency-refresh, authcore or formal
packaging acceptance is implied.

After the native package rollback/upgrade actually passes, select that exact
validated fix commit and retain its installed run and accepted image-producer
references. Use it as the doctor integration base; do not reset to the historical
`a29` source and discard later fixes. No Ubuntu continuation source is qualified
merely by passing CI, preparation or isolated recovery. Until the installed
upgrade has passed, do not apply the patch.

Replace the placeholder with the validated commit before running this example:

```sh
HANDOFF_ROOT="$PWD"
VALIDATED_NATIVE_SOURCE=replace_with_exact_validated_fix_commit
git rev-parse --verify "$VALIDATED_NATIVE_SOURCE^{commit}"
git worktree add -b feat/doctor-integration ../nethub-doctor \
  "$VALIDATED_NATIVE_SOURCE"
cd ../nethub-doctor
git apply --check "$HANDOFF_ROOT/docs/handoff/patches/external-tcp-doctor.patch"
git apply "$HANDOFF_ROOT/docs/handoff/patches/external-tcp-doctor.patch"
git diff --check
bash "$HANDOFF_ROOT/tools/handoff/ubuntu-checks.sh" "$PWD"
```

This combined tree has not been tested by the historical a4/a29 runs. Commit
your integration with your own sign-off, open a PR, and collect new exact-source
CI/native evidence. Do not reuse a historical green check for a changed tree.
