# Patched deployment helpers

The initial container scan found vulnerabilities in the official Caddy binary
and in the gosu binary bundled with PostgreSQL. These small derived builds keep
the upstream service sources and runtime layouts, and rebuild the affected Go
binaries with the compiler pinned in `server/.go-version`.

- Caddy 2.11.7 uses the standard module set and embedded time zones, with
  `golang.org/x/net` upgraded to 0.60.0. Its version identifies the NetHub build.
- PostgreSQL uses the pinned official 16 Alpine image. Only gosu is replaced,
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
```

`server/tests/postgres.sh` builds the same PostgreSQL image before testing actual
database-role boundaries. `server/tests/compose.sh` builds the three deployed
images plus the frps candidate and tests a fresh project, successful login/token issuance, and failed
migration gating. With `NETHUB_SCAN_IMAGES=1`, it saves each assembled image to a
tar and scans that tar with pinned Trivy, rejecting every HIGH/CRITICAL finding.
It mounts only the scan directory, never the Docker socket or host credentials.
No ignore rules or unfixed-vulnerability exclusions apply. Native orchestration
may supply four owned prebuilt images through `NETHUB_*_TEST_IMAGE`; those
images remain the caller's cleanup responsibility.

The frps smoke test checks its actual version, nonroot startup and authenticated
empty-route admin response on a temporary loopback-only published port. This image
is not yet wired into the generated production Compose bundle. Actual multi-device
registration, TLS passthrough, public source-address preservation and automated
certificate application remain W4 deployment acceptance.

## Existing development data

This is a base-distribution and UID change, not an in-place volume upgrade.
Fresh setup manifests use version 2 and PostgreSQL secret UID 70. Version 1
manifests with UID 999 are rejected; the initializer does not silently chown or
rewrite an existing deployment. Keep the original checkout/image and verified
logical database/secret backups when inspecting an earlier development bundle.
Use a separate new bundle and fresh database volume for the new stack. Data
transfer requires a reviewed logical dump/restore and validation, including
locale/collation behavior. Do not attach an old Debian data directory to this
Alpine image or delete the original volume as part of this change.
