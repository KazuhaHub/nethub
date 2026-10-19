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

External reverse-proxy deployment, durable relay renewal/application/rollback,
authenticated trust generation acknowledgement, and OPNsense GUI ACME
issuance/installation/renewal remain required. Initial material generation and a
successful public relay are not certificate lifecycle acceptance.
