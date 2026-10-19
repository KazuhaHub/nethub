# Deploying NetHub

The stack includes PostgreSQL, one-shot migration, the nonroot web/authz
services, frps, Caddy, and an opt-in initial-administrator service. Use the
[deployment workflow](QUICKSTART.md) for the current commands and limits.

The initializer generates service-separated files, verifies an independent backup,
requires an exact acknowledgement, and assigns Linux container UIDs. It refuses
overwrite; explicit resume preserves an interrupted setup's keys. The generated
Compose override contains deployment names and network/build configuration, never
secret values. Host secrets and backup data stay outside Git and build layers.

Only Caddy uses Docker port publishing (80/443). The Linux host-network frps
listener uses TCP 7000/8443 directly; its authenticated admin API binds only the
private edge gateway, and callbacks bind only the private authz address.
PostgreSQL stays on an internal network. Web and authz wait for
successful migration and mounts only its own secret directory. The initial admin
runs separately with owner credentials; web never receives those credentials,
the claim key, or relay credentials. The database initialization exception allows
PostgreSQL to receive all database role passwords, as confirmed in W3 D11.

The pinned three-stage Dockerfile builds React, then a static Go binary, then uses
distroless nonroot. Caddy's public certificate state persists in its own volumes.
The version-3 initializer also backs up the private deployment CA, initial leaf
snapshot and rendered private frps config. Mutable runtime leaf/trust directories
are separate. A renewed leaf under the same authority does not invalidate the
immutable backup acknowledgement. CA signing state is not mounted into runtime
services. Automated issuance/application and trust rotation still need lifecycle
implementation; creating an initial certificate does not complete those features.

Use `sudo sh server/tests/compose.sh` to exercise an isolated fresh project with
new volumes and private-loopback test TLS. It verifies first start, admin login,
empty inventory, enrollment-token issuance, health isolation, secret ownership,
log exclusion, official frps configuration verification, two actual frpc clients,
verified TLS passthrough, claim rejection, observed online status and
failed-migration startup gating. TCP 7000/8443 must be unused on this isolated
Linux host; the script does not stop existing services. This does not prove public
ACME issuance or complete deployed browser acceptance. See the stage-specific
validation records before treating any feature as accepted.

The deployment CI job additionally runs Chromium against the actual Caddy/web/
PostgreSQL project with `NETHUB_BROWSER_TEST=1`. Install `server/web` dependencies
and Playwright Chromium first; `NETHUB_NODE_BINARY` can select an absolute Node
path when invoking the harness through sudo. The test uses a destination-limited
loopback CONNECT proxy to preserve the configured HTTPS origin. It accepts only
the isolated internal test CA; public certificate verification remains separate.
Successful runs may copy masked screenshots and a nonsecret result summary to
`NETHUB_BROWSER_EVIDENCE`. The full Compose evidence archive contains disposable
credentials and must stay private; CI uploads only the selected browser files.

CI also retains the four tested immutable images for one day as
`deployment-images`, with a SHA256 checksum and image-ID manifest. This lets native
acceptance use the exact tested images without rebuilding on a constrained relay.
No container snapshots, runtime mounts, configuration bundles or test credentials
are included. Authenticate the workflow run/head, verify the checksum and each
loaded image ID before use. This artifact is not a release or a state backup.

For a bounded test deployment with a real public certificate, run
`node server/web/tests/public-browser.mjs /private/public-console.json` from a
separate client with Node 24 and `server/web` dependencies/Playwright installed.
The private JSON config supplies `origin`, `email`, `passwordFile`, and
`evidenceDirectory`; keep it, credentials, and output outside the checkout. Use a
disposable test account. The script validates the public CA/hostname with Node's
bundled roots and Chromium with certificate checking enabled. It checks public
health denial, login/reload, inventory, token masking/clearing, mobile layout,
and logout. Private failure diagnostics and token/session hashes remain beside
the config; neither belongs in published evidence. Public reachability and
clean-host provenance are separate claims; this script proves the former flows.

Appliance enrollment and public relay acceptance remain W4; Open/revocation UI is W5; invitation and full
OIDC/SAML flows are W6; scheduled backups and final operational acceptance are W7.
The design authority remains [DESIGN](../docs/DESIGN.md), with confirmed deployment
decisions in [the W3 record](../docs/w3-decisions.md). Existing W3 evidence is in
[the validation record](validation-w3.md); it does not substitute for W4 acceptance.
