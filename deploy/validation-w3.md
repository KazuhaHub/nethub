# W3 initialization and Compose validation (2026-10-18)

Native Linux checks used the designated development LXC without stopping its
existing services or publishing test listeners on public interfaces. The pinned
three-stage image built successfully with Node, static Go, and distroless nonroot.
Base-image digests were read from the official registries at implementation time;
the existing tested PostgreSQL digest was retained. Its postgres UID is 999.

The initializer generated ten independent logical values in seventeen intended
service-bound copies, with mode 0600 files and private directories. Backup copy
coverage/checksums and exact acknowledgement passed. Runtime directories/files
were UID 65532 and PostgreSQL UID 999. Doctor's scoped file checks passed. A
deliberately unacknowledged setup exited unsuccessfully; explicit resume verified
the existing backup, completed setup, and preserved the claim key unchanged.

The actual Compose configuration contained the expected default services and an
opt-in admin profile. Only Caddy published a port; tests replaced public mappings
with one loopback HTTPS listener and used an internal test CA. Web mounted only
its service directory and waited for successful migration. The first attempt
exposed an address allocation conflict: web automatically received Caddy's static
.2 address before Caddy started. Both edge addresses are now explicit (.2/.3),
with unit and real-Compose regressions for distinct assignments. Failed evidence
is retained privately alongside the corrected run.

The corrected complete script passed on new volumes: database initialization,
owner migration exit, web database health, Caddy TLS/reverse proxy, separate
one-shot administrator creation, repeat-admin rejection, administrator login,
empty inventory, one-time token issuance, and public-path health denial. Raw
admin passwords and enrollment plaintext were absent from runtime logs. A second
fresh-volume startup deliberately failed migration and did not start web.
The harness removes its owned containers, networks, volumes, and test image.

Local Go tests/vet, template parity, shell syntax, workflow lint, and pre-push
privacy checks accompany the native run. CI adds Deployment checks, running the
same fresh-project script on an ephemeral Linux runner. The script's evidence
archive includes disposable credentials and must remain private.

This is not public ACME, external-network, or full deployed-browser acceptance.
The LXC is an existing host, while the Compose project/volumes are fresh; the CI
runner supplies the clean-host reproduction. Public certificate issuance and
browser flows against the real deployment, the remaining W3 security scan gate,
and complete doctor coverage remain outstanding. W3 is not complete. Deployment
CA/certificate handling and device/authz/frps integration follow in W4; scheduled
database backups and final operational checks follow in W7.

## Patched helper image follow-up

PR #36 replaces the initial Debian PostgreSQL/Caddy binaries with derived,
checksum-pinned builds described in [image notes](images/README.md). Fresh
setup now uses manifest v2 and PostgreSQL UID 70. Native PostgreSQL boundary
checks passed all thirteen groups in 3.87 seconds, including actual HTTP tests
and read-only dump; repeated bootstrap passed. On the ephemeral Linux runner,
CI run 39183393699 passed assembled-image HIGH/CRITICAL scans for runtime,
PostgreSQL, and Caddy without exclusions, then repeated all fresh Compose and
failed-migration checks. The original UID 999 evidence above remains historical;
old bundles/volumes are not silently migrated. Public ACME and deployed-browser
acceptance remain outstanding.

## Deployed browser acceptance

The new deployment script drives Chromium through the real Compose stack and
production assets, using the one-shot-created administrator. It checks session
cookies/reload, empty inventory, independent token generation/copy, native-dialog
focus/Escape, secret storage/log exclusion, mobile layout, real database session
expiry, reauthentication, and logout. No production test routes are added.
Screenshots mask the token field; raw credentials/session state/traces are not
uploaded. CI run 39185680803 on 646a1f2 passed all six jobs. The deployed
browser report records eleven checked flow groups, zero CSP violations, browser
errors, external requests, or unexpected network failures, and one expected
logout cancellation. All four exported screenshots were downloaded and visually
reviewed: desktop/mobile layout is intact and the entire token value is masked.
The artifact contains exactly those PNGs and results.json, with no raw credentials.
The final PR head must retain passing checks before merge.
The loopback test accepts Caddy's internal CA and does not prove public ACME.

The first deployed run completed the UI flow but its blanket network assertion
counted one cancellation. A local instrumented run reproduced Chromium reporting
`net::ERR_ABORTED` after receiving logout HTTP 204. The test now distinguishes
only that exact path/status/error combination, permits at most one, and separately
verifies cookie removal plus a protected endpoint returning 401. All other failed
requests remain fatal and receive sanitized path/status diagnostics. The expected
logout cancellation count is included in the summary; it is not hidden as zero.

## Public certificate and browser acceptance

A new Compose project, new database/certificate volumes, and new independent
secret backups were prepared on the designated existing LXC. Runtime and helper
images were built from pinned sources with separate temporary builders to bound
disk use. The initializer's real DNS/backup/UID checks passed, migration exited
successfully, and the one-shot administrator was created before public exposure.
The Docker-only initializer was also tested with source mounted read-only and
only the selected state/backup parents writable; scoped doctor checks passed.

A ten-minute independent restoration timer was armed before releasing the
original occupied ports. Caddy obtained a public certificate. A separate Windows
client completed nine public flow groups: public CA/hostname validation with
Node's bundled roots and Chromium certificate checking enabled, health-path
404, administrator login, session cookie/reload, empty inventory, enrollment
and clearing, storage exclusion, mobile layout, and logout/protected 401. There
were zero CSP violations, script errors, or external resource requests. All four
screenshots were visually reviewed; the complete enrollment value is masked.
No internal CA exception or insecure request option was used for this run.

Private runtime-log checks found no tested password/session/enrollment plaintext.
The public window lasted 86.726 seconds. Original OpenResty/x-ui services and
80/443/8443 listeners were independently verified restored; owned containers,
networks, and volumes were all absent, and the restoration timer was inactive.
Evidence and disposable key backups were archived privately; local test password
material and temporary server stages were removed. Built images are retained for
follow-up development, with identities recorded outside Git.

CI run 39188227924 on 54a53bc passed all six jobs, including the self-signed
certificate rejection test and the existing deployed-browser/image gates.
The final PR head must retain passing checks before merge. This public run used
an existing LXC, not a freshly installed OS. Clean-host CI currently proves the
internal-CA stack; a clean-host public deployment run remains required. W3 is
not complete. Real endpoints, credentials, certificate identifiers, and raw
private evidence are deliberately excluded from this repository.
