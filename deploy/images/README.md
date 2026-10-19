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
- Module versions/checksums are committed and Dependabot watches both modules.
  Builds copy the linked modules' license/notice files plus the Go license into
  the final images. Missing license files fail the helper build.

Build from the repository root:

```sh
docker build -f deploy/images/postgres/Dockerfile -t nethub-postgres-local:dev .
docker build -f deploy/images/caddy/Dockerfile -t nethub-caddy-local:dev .
```

`server/tests/postgres.sh` builds the same PostgreSQL image before testing actual
database-role boundaries. `server/tests/compose.sh` builds all three deployment
images and tests a fresh project, successful login/token issuance, and failed
migration gating. With `NETHUB_SCAN_IMAGES=1`, it saves each assembled image to a
tar and scans that tar with pinned Trivy, rejecting every HIGH/CRITICAL finding.
It mounts only the scan directory, never the Docker socket or host credentials.
No ignore rules or unfixed-vulnerability exclusions apply. Native orchestration
may supply three owned prebuilt images through `NETHUB_*_TEST_IMAGE`; those
images remain the caller's cleanup responsibility.

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
