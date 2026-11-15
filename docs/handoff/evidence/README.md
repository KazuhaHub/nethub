# Durable result evidence

`index.json` records the original source, attempt, run/job IDs, decoded-log
checksums and official artifact digests. The original small native, cold,
preparation, source-contract and diagnostic ZIPs are included byte-for-byte.
Selected closed browser reports and the thirteen required images per source
are included directly. Whole CI logs and large OCI image payloads are not part
of this package. Regenerate actual runtime evidence for changed code or expired
downloads; the committed hashes do not themselves authenticate a new deployment.

Run `python3 tools/handoff/verify.py` from a full Git clone. The verifier checks
all retained file hashes, original ZIP digests, the expected failed native and
passed cold outcomes, patch hashes and all 29 requirement rows. It performs no
network requests, does not start a VM, and does not require private files.

A deep generic-key scanner flags eighteen entries inside the two source-contract
manifests because their filenames contain words such as `certificate_key` or
`token`. Their values are SHA256 hashes of public source files. The verifier
checks those exact entries against `git show <recorded-source>:<path>`; it does
not broadly suppress new values, credentials or other paths. Ordinary text and
patch scanning passed without adding a credential exception. Pending patches
use one context line and omit optional hunk-section labels so unrelated module
checksum context is not copied into the transfer.

All retained screenshots are from isolated fixture identities/reserved example
domains, with the browser masks supplied by the original tests. Native footer
clipping and mobile preformatted horizontal overflow are recorded in
`../validation.md`. The checks do not imply full native/package/public-provider,
operator, canary or release acceptance.

## First Ubuntu diagnostic checkpoint

The separate [Ubuntu index](ubuntu-870eb57/index.json) retains 33 closed files
for source `870eb575cec13f4869e7848aac2cdc9b7c93307a`: five original run/job
records, four original small artifact ZIPs, selected closed reports and the
thirteen reviewed console images. CI, FreeBSD contracts, appliance preparation
and isolated cold recovery passed. Installed run `43723295382` failed at the
dedicated heartbeat client's verified-TLS preparation before native migration;
there is no new package-upgrade diagnosis or acceptance from that run.

Run both checks from a complete clone:

```sh
python3 tools/handoff/verify.py
python3 tools/handoff/verify_continuation.py
```

The continuation verifier checks official ZIP digests, recorded source/attempt
identities, the original source archive, 256 Git blobs, screenshot hashes and
the distinct failed/native versus passed/isolated outcomes. Raw logs remain
private; only their hashes are retained. These records do not qualify a changed
source, an operator network, formal packaging or release.

## Later Ubuntu preflight evidence

[`ubuntu-native-preflight/index.json`](ubuntu-native-preflight/index.json)
separates sources `38bec4d` and `b2bfb50`, each with its own successful six-job CI,
failed installed-native run and successful isolated cold-recovery run. The
installed runs failed before any package migration step; they do not diagnose
the earlier upgrade invariant. Original small closed artifact ZIPs and run
origins are retained. `python3 tools/handoff/verify_continuation.py` verifies
these records as well as the first Ubuntu checkpoint. No failed run is relabeled
and no public, mobile, formal-package or release scope is accepted.

## Local SQL snapshot load

[`ubuntu-52e3362-local/index.json`](ubuntu-52e3362-local/index.json) retains the
closed local actual-SQL record at source `52e3362`, including the explicitly
enabled row/tenant-bound load and overflow refusal. Its source, compiler and
binary/log hashes are distinct from hosted CI images. The continuation verifier
checks the retained metrics and original harness source hashes; it does not
re-execute the database, attest an online fleet or accept native/public cutoff.
Raw SQL logs and ephemeral credentials remain outside Git.

## Post-WAN preflight checkpoint

[`ubuntu-52e3362/index.json`](ubuntu-52e3362/index.json) retains 33 closed files
for five exact-source runs. Six-job CI, appliance preparation, FreeBSD contracts
and isolated cold recovery passed. Installed-native execution failed its console
probe after WAN recovery, before any package migration step. The reported old
`tls` / `http_failure` classification is preserved without claiming which socket
operation failed. Original small ZIPs and all 13 required console images are
retained; the continuation verifier checks run identities, archive and image
hashes, source archive and all 257 contract source blobs. Raw logs and credentials
remain outside Git. The later diagnostic source requires its own evidence.

## Authz log checkpoint and local framing reproduction

[`ubuntu-359bf94/index.json`](ubuntu-359bf94/index.json) retains five exact-source
runs and 33 closed files. Installed execution failed before guest creation at
authz log decoding; CI, preparation, FreeBSD contracts and isolated recovery
passed separately. The verifier checks all 258 original source blobs and keeps
that failure failed.

[`local-relay-log-framing/index.json`](local-relay-log-framing/index.json) records
a distinct local Docker mechanism reproduction using the pinned source helper.
Run `python3 tools/handoff/reproduce_relay_log.py` with local Docker and its
cached pinned image to repeat it. This demonstrates an incomplete log tail and
its bounded, byte-preserving read; it does not attribute the prior native failure
or qualify installed upgrades. The verifier checks the source/helper/reproducer
hashes and the retained closed result, without executing Docker.
