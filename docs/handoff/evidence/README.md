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
