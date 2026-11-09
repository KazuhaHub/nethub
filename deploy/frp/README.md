# Relay binary and interoperability fixtures

The selected relay version is 0.71.1, matching the OPNsense agent and the pinned
os-frp source revision in `agents/opnsense/plugin/frp-artifacts.json`.

The deployment image builds frps from locked source and dependencies with the
compiler pinned in `server/.go-version`; see
[`deploy/images/frps/Dockerfile`](../images/frps/Dockerfile) and the
[image build and scan policy](../images/README.md). The appliance separately
rebuilds frpc with the same compiler. An upstream version match alone does not
prove that two binaries have the same dependencies or security status.

For an isolated interoperability fixture, stage the checksum-pinned official
Linux amd64 executable from the repository root with:

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

That official prebuilt is retained as a versioned test fixture, not the current
rebuilt deployment executable. Its checksum establishes artifact identity;
it does not establish a clean vulnerability scan.

Use the [quickstart](../QUICKSTART.md) for deployment and the
[protected authority procedure](../relay-authority-operations.md) for certificate
and trust operations. The CA private key stays outside runtime containers;
devices verify the relay certificate with `trustedCaFile` and `serverName` (D22).
