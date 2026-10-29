# Clean-host recovery drill

This harness is being built for W7-5. The first checkpoint prepares a distinct
empty Ubuntu 24.04 guest on a fresh hosted Linux runner. It does not restore a
deployment, reconnect a native device or establish off-host backup custody.

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

The next stage must restore retained current keys, role ownership/ACLs and a
matching full database archive into this target before starting application
writers. Actual original-device reconnection, ordinary administrator use,
complete cleanup and independent encrypted custody remain required. A passing
target preparation job must not be presented as W7-5 acceptance.
