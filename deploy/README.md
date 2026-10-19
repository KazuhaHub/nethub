# Deploying NetHub

The W3 console stack includes PostgreSQL, one-shot migration, the nonroot web
service, Caddy, and an opt-in initial-administrator service. Use the
[deployment workflow](QUICKSTART.md) for the current commands and limits.

The initializer generates service-separated files, verifies an independent backup,
requires an exact acknowledgement, and assigns Linux container UIDs. It refuses
overwrite; explicit resume preserves an interrupted setup's keys. The generated
Compose override contains deployment names and network/build configuration, never
secret values. Host secrets and backup data stay outside Git and build layers.

Only Caddy publishes ports. PostgreSQL stays on an internal network. Web waits for
successful migration and mounts only its own secret directory. The initial admin
runs separately with owner credentials; web never receives those credentials,
the claim key, or relay credentials. The database initialization exception allows
PostgreSQL to receive all database role passwords, as confirmed in W3 D11.

The pinned three-stage Dockerfile builds React, then a static Go binary, then uses
distroless nonroot. Caddy's public certificate state persists in its own volumes.
The initializer's secret manifest covers generated deployment keys; W4 will add
CA/certificate material and update backup coverage when enrollment TLS is wired.

Use `sudo sh server/tests/compose.sh` to exercise an isolated fresh project with
new volumes and private-loopback test TLS. It verifies first start, admin login,
empty inventory, enrollment-token issuance, health isolation, secret ownership,
log exclusion, and failed-migration startup gating. This does not prove public
ACME issuance or complete deployed browser acceptance. See the stage-specific
validation records before treating any feature as accepted.

Device/authz/frps integration is W4; Open/revocation UI is W5; invitation and full
OIDC/SAML flows are W6; scheduled backups and final operational acceptance are W7.
The design authority remains [DESIGN](../docs/DESIGN.md), with confirmed deployment
decisions in [the W3 record](../docs/w3-decisions.md). W3 is not complete yet.
