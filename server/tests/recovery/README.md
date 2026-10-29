# Clean-host recovery drill

This harness is being built for W7-5. Target preparation has passed actual hosted
boot, empty-state and cleanup checks. The combined restoration flow below is
under validation; preparation alone does not accept it or establish off-host
backup custody.

The dated Canonical image is pinned by SHA256 and checked against its signed
checksum list. The signing fingerprint comes from Canonical's
[cloud image verification guide](https://ubuntu.com/docs/public-images/public-images-how-to/verify-image-checksum/).
The [NoCloud seed procedure](https://ubuntu.com/docs/public-images/public-images-how-to/use-local-cloud-init-ds/)
supplies per-run client and host keys; SSH checks the prebound host key and
accepts no passwords. Only the SSH forward binds to host loopback. No source
filesystem or Docker socket is shared with the guest.

`Fresh recovery target` is a manual hosted-only workflow. It checks a new
machine/boot identity, empty deployment/database paths, and an empty Docker
daemon before returning closed decisions and runtime versions. Apt installs
the distribution's signed Docker packages. The harness stops only its owned
QEMU process on success or failure. Raw disks, seeds, keys, console output and
machine identifiers are private and are never uploaded. Only
`target-result.json` is eligible for publication. Temporary hosted storage is
not an independently retained recovery copy.

Run the source refusal checks without launching a guest:

```sh
python3 -m unittest discover -s server/tests/recovery -p 'test_*.py'
```

## Combined installed-device drill

The installed-native workflow calls `restore.py` after the real shared-token
cutover and native Rotate. It leaves the OPNsense guest and independent client
running. The source must have exactly the six owned services and a current
post-rotation independent backup. This is an isolated fixture driver, not a
general production restore CLI.

1. Prepare a distinct empty Linux guest and privately transfer the same tested
   images. Create only new empty target volumes.
2. Acquire the same host operation lease used by relay maintenance. Stop source
   writers, create and hash a new restricted custom archive, and compare all
   public tables, sequences, owners, ACLs and role metadata before/after the dump.
   Stop the original PostgreSQL service as well.
3. Transfer current deployment files, the original and successor secret backups,
   complete retained operation history and stopped Caddy/backup volumes over
   pinned SSH. A bounded private archive refuses links, traversal, foreign owners,
   duplicate paths and existing data. Restore exact bytes and numeric ownership;
   never run initialization to generate replacement credentials.
4. Bootstrap approved roles on a new PostgreSQL cluster, verify its distinct
   system identifier and schema-empty database, then restore in one transaction
   with ownership and ACLs. Compare the complete private database fingerprint
   before application startup. Start the normal services and run database role,
   audit-chain, current-file and service separation checks.
5. Forward the unchanged logical endpoints to the recovered host. Log in with
   the original administrator credentials and use normal Open to admit the
   private forwarding source. Both original assigned routes must recover with
   verified TLS. Native model and GUI identity/security checks must be unchanged;
   no native restart, Rotate or new enrollment is performed by this driver.
6. Remove the owned target stack and stop its guest. Recover the original fixture
   services, wait for both clients to reconnect again, then continue genuine
   native Remove and the complete existing Compose cleanup tail.

Only the closed `installed-host-restore.json` is added to public exports. The
restricted dump, file inventory/hashes, SQL rows, transferred images, console
state and key material stay private. The original control connections are
necessarily replaced by the planned host outage; later removal uses the
reconnected control as its baseline. Independent encrypted, durable custody and
public/operator checks remain separate requirements, even after this drill passes.
