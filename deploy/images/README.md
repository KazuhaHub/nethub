# Deployment image builds

The initial container scan found vulnerabilities in the official Caddy binary
and in the gosu binary bundled with PostgreSQL. The derived builds pin their
upstream inputs and rebuild affected Go binaries with the compiler pinned in
`server/.go-version`. Caddy also uses the bounded source adaptations described
in its [JOSE migration note](caddy/README.md); its upstream sources are not
claimed to be unchanged.

- Caddy 2.11.7 uses the standard module set and embedded time zones, with
  `golang.org/x/net` upgraded to 0.60.0. Its version identifies the NetHub build.
  Its pinned Alpine base also receives the `brotli-libs` 1.2.1-r0 security patch
  for CVE-2026-111497, as recorded in the
  [Alpine 3.23 security database](https://secdb.alpinelinux.org/v3.23/main.json).
  This updates the inherited OS libraries without changing the Caddy module set.
  Its inherited curl and libcurl packages are upgraded to 8.23.0-r0 for
  [CVE-2026-92392](https://curl.se/docs/CVE-2026-92392.html), matching the Alpine
  3.23 security database. The assembled-image HIGH/CRITICAL scan remains required.
  Its crypto dependency uses a pre-release pin and prepared JOSE v4 adaptations;
  the migration note records the exact changes and upstream test limitation.
- Caddy, PostgreSQL and the backup tools stage install zlib 1.4-r0 from their
  existing Alpine repositories. The previous assembled-image scan reported
  CVE-2026-85091 against 1.3.2-r0. The initial 1.3.2-r1 pin passed source
  `326d444` deployment checks before Alpine superseded that package revision.
  [Alpine's package index](https://pkgs.alpinelinux.org/package/v3.23/main/x86_64/zlib)
  records 1.4-r0; [upstream 1.4](https://github.com/madler/zlib/releases/tag/v1.4)
  includes the security fix and changes stream error/reset behavior. Exact pins
  fail the build when a repository no longer supplies them; there is no fallback
  to an unreviewed version. The new assembled-image scans, PostgreSQL restore
  and backup/deployment checks must pass, including the libraries copied into
  backup. No scanner exclusion is added.
- PostgreSQL and backup tools also pin musl and musl-utils 1.2.6-r3 from their
  Alpine 3.24 repositories. The scan at source `1fdfbcf` reported HIGH
  CVE-2026-107891 against musl-utils 1.2.6-r2 and identified r3 as fixed.
  The [official Alpine index](https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/)
  supplies both r3 packages. Digest-verified upstream root layers identify the
  PostgreSQL base as Alpine 3.24.2 and Caddy as Alpine 3.23.6; package pins follow
  those existing branches. Fresh scans and database/backup acceptance remain
  required for the changed libc and utility packages.
- PostgreSQL uses the pinned official 16 Alpine image. Its gosu binary is replaced,
  rebuilt from the upstream 1.19 commit (`6456aaa0f3c8`); Go records that tag as
  a pseudo-version because the upstream tag does not use a `v` prefix. The
  PostgreSQL entrypoint still drops from root to the postgres account (UID 70).
- frps builds the unmodified upstream 0.71.1 command from Go's checksummed module,
  with `golang.org/x/net` 0.60.0 and `golang.org/x/crypto` 0.58.0. The `noweb`
  build tag omits the separate frps dashboard assets; its authenticated admin API
  remains available for NetHub observations. The final image runs as UID 65532.
  Symbols are retained for binary vulnerability analysis. A stripped binary makes
  govulncheck fall back to module-level findings, including the unused OpenPGP
  package (GO-2026-5932); no advisory is suppressed. See the
  [scanner's documented limitations](https://github.com/golang/vuln/blob/master/cmd/govulncheck/doc.go).
- Module versions/checksums are committed and Dependabot watches these modules.
  Builds copy the linked modules' license/notice files plus the Go license into
  the final images. Missing license files fail the helper build.

Build from the repository root:

```sh
docker build -f deploy/images/postgres/Dockerfile -t nethub-postgres-local:dev .
docker build -f deploy/images/caddy/Dockerfile -t nethub-caddy-local:dev .
docker build -f deploy/images/frps/Dockerfile -t nethub-frps-local:dev .
docker build -f deploy/Dockerfile -t nethub-local:dev .
docker build --target backup -f deploy/Dockerfile -t nethub-backup-local:dev .
```

The runtime image serves Web/authz and the migration/bootstrap commands. The
separate nonroot backup target includes PostgreSQL client tools, private storage
and system TLS roots; it has no shell, database server or Docker socket. See
[backup operation and custody](../database-backups.md). These are local development
builds, not formally published or signed release images.

`server/tests/postgres.sh` builds the same PostgreSQL image before testing actual
database-role boundaries. `server/tests/compose.sh` builds all five images:
runtime, PostgreSQL, Caddy, frps and backup. It tests a fresh six-service project,
successful login/token issuance, failed migration gating and the subsequent
relay, certificate and backup boundaries. With `NETHUB_SCAN_IMAGES=1`, it saves each assembled image to a
tar and scans that tar with pinned Trivy, rejecting every HIGH/CRITICAL finding.
It mounts only the scan directory, never the Docker socket or host credentials.
No ignore rules or unfixed-vulnerability exclusions apply. Native orchestration
may supply all five owned prebuilt images through `NETHUB_*_TEST_IMAGE`; those
images remain the caller's cleanup responsibility.

The frps smoke test checks its actual version, nonroot startup and authenticated
empty-route admin response on a temporary loopback-only published port. The
generated Compose deployment also runs this frps image with host networking for
the relay's source-IP gate. That smoke test alone does not prove device admission
or TLS routes. The [relay integration](../validation-w4.md) and subsequent
[native public-certificate checkpoint](../validation-native-public-certificate.md)
record their distinct runtime scope. Public/operator W5-W7 checks, external port
witnesses and agreement with a formally published appliance remain open.

## Existing development data

This is a base-distribution and UID change, not an in-place volume upgrade.
Fresh setup manifests use version 3 and PostgreSQL secret UID 70. Earlier
manifest versions are rejected; the initializer does not silently chown or
rewrite an existing deployment. Keep the original checkout/image and verified
logical database/secret backups when inspecting an earlier development bundle.
Use a separate new bundle and fresh database volume for the new stack. Data
transfer requires a reviewed logical dump/restore and validation, including
locale/collation behavior. Do not attach an old Debian data directory to this
Alpine image or delete the original volume as part of this change.
