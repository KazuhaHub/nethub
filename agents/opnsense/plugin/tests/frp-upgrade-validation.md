# frp 0.71.1 preparation

Validated on 2026-10-18 before W2 service integration. The selected test guest is
OPNsense 26.7.7 / FreeBSD 15 amd64, with the owner-approved 1 GiB resource
exception. No production router or formal package release was used.

- Official FreeBSD amd64 and Linux amd64 archives matched the upstream checksum
  manifest and repository pins. The manifest itself is pinned by SHA256.
- The os-frp 1.0.2 unsigned native package built successfully; 70 backend tests
  passed on the guest. Packaging repository PR #49 merged as
  `3684a2ec81738bdd36022194ceab2b664bb2ce8b`; its complete CI passed.
- The NetHub unsigned native package built from the official download and
  installed successfully. Its independent frpc reported `0.71.1`; the installed
  os-frp frpc also reported `0.71.1`. The upstream license was installed alongside
  the NetHub binary.
- The isolated relay downloaded and validated the Linux executable, which
  reported `0.71.1`; its upstream license was present. This step started no
  listener and did not replace the relay's existing services.
- Eight artifact tests passed, including checksum, OS, CPU, duplicate-member,
  symlink, and missing-member rejection with the previous binary preserved.
  Version and official checksum agreement checks passed against merged os-frp.

The final native NetHub development package SHA256 was
`c72711d05a5a83d4eb52b8826c6994b27c264141b82d4659c0f0d2ab0ab1115a`.
Raw build/install logs and machine details remain in the private W2 runtime.

These checks establish binary preparation only. They do not establish a working
NetHub service, TLS rejection, os-frp tunnel coexistence, reconnect behavior, or
WAN-address recovery. W0 observations remain versioned as 0.71.0. Complete W2
acceptance must measure automatic registration and GUI recovery after a WAN
address change; failure requires the debounced newwanip fallback and a repeated
test under D21.
