# Native W4 deployment evidence

## Public console and relay source address

The Linux LXC loaded the four images exported by CI run 39231661494 from
19c29f07bcea97c74180980e72c30ee99a974451 (PR #51). Archive checksums, exact image
configuration bytes, ordered rootfs diff IDs and platform matched before fresh
version-3 initialization, DNS checks, private backup acknowledgement and doctor.
PR #52 records portable image identities; its six final-head checks passed in
39234383994 before merging as c6ec379.

The public console passed public-CA/hostname verification and nine browser groups:
private health denial, administrator login, session/reload, empty inventory,
one-time enrollment-token creation/clearing, storage exclusion, mobile layout,
and logout/protected 401, in addition to certificate verification. CSP violations,
browser errors and unexpected external requests were zero. The four desktop/mobile
screenshots were inspected. Console certificates were obtained by Caddy, not by
the application.

The final source-only test used three fresh external IPv4 TLS connections through
host-network frps on 8443. Each verified the backend fixture certificate and
hostname and returned the expected backend response. All three NewUserConn
remote addresses matched both independent direct HTTP requests from the same
client and the host's established TCP socket peers. Five HTTP samples were
recorded, including readiness retries; there were three proxy samples and zero
invalid callbacks. No SSH or reverse-proxy-forwarded source address was used as
the independent comparison.

Two earlier attempts are retained as failed evidence. The first collector
incorrectly assumed callbacks to the host's bridge listener originate from that
same bridge address. It rejected real callbacks. The second passed external TLS
and independent HTTP comparison, but its socket parser did not normalize
IPv4-mapped IPv6 addresses. The corrected collector accepts only enumerated local
host interface addresses on its private callback listener, retains nonce and
assigned-proxy checks, and normalizes mapped addresses before socket comparison.
A separate loopback-only reproduction passed before reopening the public window.
These are private test-harness changes, not relaxed product hook authorization.

Every window armed an independent nine-minute restoration timer before stopping
the original services. The three windows lasted 69.104, 24.681 and 24.256 seconds.
After each, original services/listeners on 80/443/8443 were independently verified,
test control port 7000 was closed, and owned collectors/clients were stopped
before cancelling the timer. Private database, issuance authority, backup and
Caddy certificate state were retained; no authority was regenerated between tests.

## Limits and remaining acceptance

The source-only backend is an explicitly enrolled lab fixture. This establishes
the current LXC host-network deployment's source-address behavior; it does not
establish another host's firewall/NAT behavior, native OPNsense enrollment or GUI
certificate installation. Raw requests, source addresses, hostnames, passwords,
generated deployment files, certificate keys and screenshots stay outside Git.

External reverse-proxy acceptance is recorded below. Durable relay renewal/application/rollback,
authenticated trust generation acknowledgement, and OPNsense GUI ACME
issuance/installation/renewal remain required. Initial material generation and a
successful public relay are not certificate lifecycle acceptance.

## Existing host HTTPS proxy

PR #54 passed six checks on 55daa202665e0c67ff6bc14aeb6153d2140fe8aa
(run 39239990731), then merged as cd863d9. The genuine Compose log confirms an
external-mode bundle without bundled Caddy, two loopback-only HTTP origins,
verified TLS through a separate host proxy, console login/device enrollment,
secure cookies, ignored forged source headers and non-loopback origin isolation.
Existing bundled deployment/browser, official frp configuration, two real clients,
failed-migration and four-image HIGH/CRITICAL vulnerability checks also passed.

The first attempt failed because the fixture proxy tried to create an automatic
port-80 redirect despite having no low-port capability. A loopback-only native
reproduction confirmed the cause. Disabling fixture redirects fixed it; production
certificate ownership and proxy routing were not weakened.

A supplementary native LXC run used the cross-built PR #54 initializer with the
previously verified PR #51 application images. It passed external-mode creation,
operator-owned fixture TLS, console/device routing, secure session, spoofed-source
rejection and origin isolation. It used another private subnet and high loopback
ports; the original public services were never stopped. All owned test containers,
network and proxy were removed, and original services/listeners were checked.
This supplements the assembled-image CI evidence; it is not a public NGINX or
arbitrary third-party proxy configuration acceptance.

## Device-owned router certificate requests

PR #55 passed six checks on cf9224cdd4d7b5479045183d63281e47c66b73e9
(run 39240210910), then merged as da3fa29. Linux race tests include signed
P-256/SHA-256 requests, tampered signatures, wrong-device/wildcard/extra SANs,
unapproved extensions and subject fields, malformed encodings and key limits.
An additional five-second malformed-input fuzz run completed 43,986 executions
without a failure. That bounded run does not establish exhaustive parser coverage.

The validator supports a device-generated GUI key and public CSR/chain exchange.
It does not authorize a tenant/device, contact an ACME issuer, deliver/install
certificates or implement renewal. Those components remain open.
