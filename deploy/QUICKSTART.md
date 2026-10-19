# W3 deployment workflow

This is the console stack: PostgreSQL, migration, web, Caddy, and an opt-in initial
administrator service. Device/authz/frps integration belongs to W4. Public TLS,
external reachability, and complete deployed browser acceptance must be verified
before calling the deployment ready. The isolated acceptance script uses an
internal test CA, not a public certificate.

Use a Linux Docker host with Docker Engine and Compose supporting `!override`
([Compose 2.24.4 or later](https://docs.docker.com/reference/compose-file/merge/#replace-value)). Keep the source checkout available for image builds.
Build the console with Node 24.14.0, then the CLI with Go 1.26.9, or use the pinned
three-stage deploy/Dockerfile. Runtime is static distroless nonroot (UID 65532).
Run host initialization/file checks as root because local Compose bind mounts
preserve host ownership. The PostgreSQL 16 Alpine image uses UID 70; runtime secrets remain UID 65532.
Docker's [file-based service secret model](https://docs.docker.com/compose/how-tos/use-secrets/)
is the reference for the explicit read-only mounts and ownership checks.

1. Arrange the console DNS hostname outside the device wildcard, wildcard DNS,
   and inbound TCP 80/443 for Caddy's certificate issuance. W4 adds 7000/8443.
   Select an unused RFC1918 /24 for the edge network. Caddy uses its .2 address
   and web its .3 address, both explicit; the web trust list contains only Caddy.
2. Choose a new deployment directory and a separate protected backup directory.
   Their parents must already exist. A local checksum-verified copy does not prove
   off-host durability; use protected external storage and retain a separate copy.
3. From the source checkout, run the built CLI as root:

   ```sh
   nethub init --directory /opt/nethub \
     --backup-directory /protected-backups/nethub \
     --source-directory "$PWD" \
     --console-host console.example.com --device-domain router.example.com \
     --expected-address YOUR_PUBLIC_RELAY_ADDRESS
   ```

   Replace the sample DNS names/address and choose a real protected backup parent.
   Missing DNS names and backup location are prompted. The command probes random
   wildcard names plus the console against the expected address, generates keys,
   copies and verifies every secret, then requires the exact printed acknowledgement.
   It does not start services, alter firewall rules, or change existing listeners.
4. After confirmation, change into the generated deployment directory:

   ```sh
   docker compose build migrate postgres caddy
   docker compose up -d
   docker compose run --rm admin-bootstrap --email YOUR_EMAIL
   nethub doctor --directory . --expected-address YOUR_PUBLIC_RELAY_ADDRESS
   ```

   Enter the administrator password in the hidden prompt. Migrate must exit zero
   before web starts; Caddy waits for web health. Admin-bootstrap is a separate
   opt-in one-shot service with owner credentials, and cannot reset an existing
   account. Web never gets owner, claim-signing, or relay credentials.
5. Check the public certificate and sign in through the configured HTTPS origin.
   Verify empty inventory, token generation, logout, session expiry, and browser CSP.
   `/healthz` is private to the Docker network; Caddy returns 404 publicly.

`init --offline` is for isolated preparation/tests. It still verifies backup and
ownership but explicitly leaves DNS/public readiness unverified. If interrupted
before acknowledgement, preserve the unconfirmed bundle and run `init --resume`
with the same directory and backup location. Resume verifies existing files and
never generates or rotates keys. A confirmed directory is never reinitialized.
Do not use Compose until initialization succeeds. Existing volumes do not rerun
PostgreSQL initialization; role-secret rotation is a separate operator procedure.

The generated bundle and backup each contain an ignore-all .gitignore. Secret files
are mode 0600 in private directories; do not force-add them to Git or change modes
to make a container start. Files are duplicated only for services explicitly
sharing a value. PostgreSQL bootstrap alone receives all database role passwords;
it receives no signing, relay, or OIDC encryption keys. Web gets pg_nethub_web and
secrets_key, migrate/admin get pg_nethub_owner, and future authz/backup/frps copies
are prepared separately. Session synchronizer derivation needs no global key.
Deployment CA/certificate generation and rotation details are W4 work; those keys
must be included in the backup when implemented.

The source tree includes reviewed base Compose/Caddy/bootstrap templates. The
initializer embeds identical copies; unit tests fail if they drift. The generated
override holds nonsecret DNS/build/network configuration only. The Docker context
allowlist excludes host secrets, local dependencies, and generated assets.

`doctor --directory` checks exact secret coverage/checksums, private file modes,
UIDs, acknowledgement, and the independent backup copy. Optional expected-address
checking probes DNS. `doctor --health-url` accepts only an exact loopback HTTP
/healthz endpoint and is used inside the web container. The command explicitly
lists checks it has not performed: it does not claim public connectivity, runtime
mount/grant correctness, relay/authz health, or scheduled database backup.

Run `sudo sh server/tests/compose.sh` for a new temporary project/image/volumes,
private loopback test TLS, real first-admin creation/login, empty inventory, token
issuance, health isolation, secret/log checks, and migration-failure startup gating.
The script removes only its own resources. Optional NETHUB_COMPOSE_EVIDENCE retains
private evidence including disposable credentials; never publish that archive.
