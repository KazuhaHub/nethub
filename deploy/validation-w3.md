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
