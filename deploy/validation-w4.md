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

External reverse-proxy and durable same-root relay maintenance acceptance are
recorded below. Authenticated trust generation acknowledgement and OPNsense GUI
ACME issuance/installation/renewal remain required. Initial material generation
and a successful public relay are not complete certificate lifecycle acceptance.

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

## Same-root relay leaf maintenance

PR #56 merged as 689e8e9 after all six checks passed on
d099ee803df258c5948b57aef0848169578ff473, run 39248588114. Inspected deployment
logs confirm a genuine due leaf, injected recreation failure, verified rollback,
reuse of the persisted issued generation, fresh served fingerprint, two official
frpc clients, unchanged-scan suppression, an actual host timer and production unit
verification. Retry to both working tunnels measured 690 ms in that isolated CI
environment. All four image scans and existing deployment regressions passed.

The native LXC public run used the exact verified host binary from that CI image,
the original retained deployment authority/backup and earlier PR #51 application
images. It loaded a currently valid due fixture under the same authority, enrolled
two labelled Linux fixture clients through verified console HTTPS, then invoked
the normal root maintenance command. Fresh external IPv4 TLS checked the control
leaf against the independent CA/hostname and confirmed the new fingerprint.
Both 8443 routes verified their fixture certificates/hostnames and expected bodies.

Trigger to fresh external confirmation of both routes measured 4.0 seconds. After
the trigger, 17 fresh control/HTTP probes failed and 62 succeeded; renewal is not
seamless. This includes sampling and command-trigger latency, not an exact outage
measurement or a bound for other networks. The CA key and unrelated container IDs
were unchanged, ownership/modes and doctor passed, and a second scan did not
restart frps. The verified renewed generation and its journal were retained.

An independent nine-minute restoration timer was armed before listener changes.
The public window lasted 25.699 seconds. All certificate writers and descendants
were stopped, owned public containers removed, original 80/443/8443 listeners
restored, and 7000 closed before cancelling the timer. A subsequent independent
check confirmed restoration and timer inactivity. Disposable cleanup tests covered
baseline restoration, retained successful generations, corrupt baseline recovery
and a child process that ignored termination; no original services were touched
by those cleanup tests. Secrets and raw evidence remain outside Git.

This accepts same-root relay leaf maintenance with Linux fixture clients. It does
not establish native OPNsense enrollment, GUI certificates, authenticated trust
acknowledgements or CA rotation. Expired-candidate replacement remains open.

## Returned router certificate chains

Local tests validate the returned current server chain against the original signed
P-256 CSR, exact assigned name and independently supplied roots. They reject a
response-supplied untrusted root, another device key, missing intermediates,
reordered/duplicate/unrelated certificates, malformed/mixed PEM, altered
signatures, expanded identities and incorrect usage. Effective chain expiry is
reported separately from the leaf's own dates. PR #57 merged as 8f3bf2c after six
checks on 58d429e7faf5951f8668df53617c77380a316e37 (run 39254303439), with race
and complete deployment logs inspected. No live ACME issuance or appliance
installation is established by these parser/trust tests.

## Native enrollment and lifecycle

PR #58 merged as a3bc4da after all six d1c8f34 checks (run 39264535841) and actual
fresh public-console/native-OPNsense enrollment acceptance. The installed 0.0.3
package's source/build inputs matched that revision. Click to online inventory
measured 3.642 seconds. Public console TLS and pinned local GUI TLS, native model
persistence, private CA reconstruction, running frpc, idempotency and checked
assignment-secret log absence passed. The 103.551-second window closed with
original public services and the appliance baseline restored.

PR #59 merged as b22c168 after six d68212e checks (run 39270567927). Genuine
database tests accept authenticated health/removal boundaries, atomic audit and
revocation, concurrency, routing-name reuse with old-claim denial and stale-hash
rechecks under the write lock. Health receipt does not update relay online state.

PR #60 merged as 25c17e8 after six b0f544c checks (run 39272484598), actual logs
inspected and native/public acceptance. Plugin CI passed 199 tests with the
existing FreeBSD-only lock check skipped on Linux. Exact 0.0.4 package upgrade,
checksums and the twelve-field native model passed. A fresh isolated authority and
database with all four exact CI images passed enrollment, manual and genuine cron
reporting, model/runtime removal, console revocation and closed former route.
Online inventory measured 14.102 seconds in this run; removal took 1.501 seconds.
A separate bounded official frpc with retained old credentials was explicitly
denied while verified control TLS remained available. There was one removal audit
event. Actual token/secret/frp-token/claim log scans and repeated removal passed.

The 109.279-second window closed with original listeners restored, test control
port closed, both authorities unchanged and doctor passing. Native field values,
thirteen owned files, stopped intent and system/unrelated configuration hashes
were restored and the watcher exited. Root credentials, password SSH and GUI
security checks stayed unchanged. The 0.0.4 development package remains installed
under the owner-approved 1 GiB lab exception. Public router TLS pinned the existing
self-signed GUI leaf; these results do not accept formal GUI ACME certificates,
trust generation acknowledgements/root rotation or all W4 requirements.
