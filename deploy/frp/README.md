# Relay binary prerequisite

The selected relay version is 0.71.1, matching the OPNsense agent and the pinned
os-frp source revision in `agents/opnsense/plugin/frp-artifacts.json`.

From the repository root, stage the official Linux amd64 executable with:

```sh
python3 deploy/frp/check_versions.py
python3 deploy/frp/fetch.py /path/to/staging/frps
/path/to/staging/frps --version
```

The downloader verifies the fixed SHA256 before reading the archive member and
checks that it contains the expected amd64 ELF executable. Only the executable
is staged. A failed download, checksum, or ELF check leaves an existing output
untouched. CI compares all three version pins and checks both archive digests
against the pinned official checksum manifest.

This is binary preparation, not a deployment stack. W2 uses an isolated test
relay. W4 will supply the product configuration and deployment CA lifecycle.
The CA private key must stay outside runtime containers; devices must verify the
relay certificate with `trustedCaFile` and `serverName` (D22).
