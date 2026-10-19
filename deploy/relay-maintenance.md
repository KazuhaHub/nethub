# Automatic relay leaf maintenance

The Linux host command renews the relay certificate under the deployment's
existing private CA. It keeps the signer outside web/authz/frps containers,
persists an issued generation before changing runtime files, recreates only frps,
and verifies its actual served TLS fingerprint. This interrupts tunnels; frpc must
reconnect. A failed apply restores and verifies a still-valid last-good pair.
An expired prior leaf cannot provide valid rollback.

Run on the local rootful Docker host, with a protected local filesystem:

```sh
sudo /usr/local/libexec/nethub certificates maintain-relay \
  --directory /srv/nethub-deployment --project-name nethub
```

Use the exact project name already used for deployment. If the stack uses an
additional Compose override, pass its absolute path with `--compose-file`.
Compose files must be root-owned regular files without group/world write access.
The tool uses the local `/var/run/docker.sock`, ignores Docker context/environment
overrides, and never pulls an uninstalled image. It does not start an intentionally
stopped service on an ordinary timer scan. Interrupted applying/rollback work can
complete its previously authorized recovery.

The command can be installed from the exact trusted runtime image without a Go
toolchain or an always-running issuer container:

```sh
task_container=$(docker create nethub-local:dev)
docker cp "$task_container:/nethub" ./nethub-maintenance
docker rm "$task_container"
sudo install -o root -g root -m 0755 ./nethub-maintenance /usr/local/libexec/nethub
```

Create `/usr/local/libexec` first if absent. Use the tested deployment image and
replace the binary when upgrading that deployment. The signer runs on the host;
no application gets a signing-key mount or Docker socket.

Review the paths/project in the [service](systemd/nethub-relay-maintenance.service)
and install both it and the [timer](systemd/nethub-relay-maintenance.timer) as
root-owned mode 0644 files under `/etc/systemd/system`. Then:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now nethub-relay-maintenance.timer
sudo systemctl start nethub-relay-maintenance.service
sudo journalctl -u nethub-relay-maintenance.service
```

Renewal uses at most 30 days of lead, bounded by one third of the actual leaf
lifetime. A near-expiry authority is reported separately. The timer cannot
extend a CA-clamped leaf indefinitely: authority rotation requires a separate
trust transition and remains unfinished.

Private state and complete generation snapshots live under
`secrets/issuer/maintenance` with root ownership. The journal is machine-written;
manual JSON edits, duplicate fields, corrupt material and linked paths are
rejected. It records separate issued/applying/rollback/waiting/exhausted phases,
fixed diagnostics, public fingerprints, expiry and attempt timing. It contains
no PEM or private key. The PEM snapshots beside it remain private.

Three automatic attempts reuse the same issued generation, with durable backoff.
After investigating a failed deployment, an explicit root retry can bypass the
pending wait or reset an exhausted budget:

```sh
sudo /usr/local/libexec/nethub certificates maintain-relay \
  --directory /srv/nethub-deployment --project-name nethub --retry
```

This reuses valid issued material and can restart that explicitly requested
pending generation. It does not silently reissue an expired candidate or replace
an expired CA. Preserve the private journal/generations for investigation before
operator recovery. Automated CA rotation/recovery and a first-class expired-job
replacement operation remain pending; do not claim those from same-root renewal.

On success the recorded fingerprint was seen in a fresh verified connection.
`recovery_milliseconds` measures the command's recreation/verification interval
only when `recovery_known` is true. Recovery after an already-served interrupted
application cannot reconstruct the earlier outage. Genuine deployment acceptance
also measures both real frpc tunnels becoming usable again; neither measure is a
guarantee for another network or a claim of seamless renewal.

Authenticated trust distribution/ACK and OPNsense GUI ACME installation/renewal
remain separate required work. Console certificates stay with the selected
reverse proxy.
