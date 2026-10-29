# Fresh installed appliance preparation

`native-appliance.yml` owns a new hosted Linux/KVM guest. It verifies the pinned
official Nano image checksum, independently published release key and raw-image
signature, updates the guest's signed OPNsense packages, and builds the current
unsigned plugin with the pinned FreeBSD Go SDK and dependency locks. SSH host
trust is obtained through the verified guest's serial console. Both management
forwards bind to host loopback; no local workstation VM or existing relay is used.
The first emulated NIC is the restricted LAN and the second is the outbound WAN,
matching the signed image's factory `em0` LAN and `em1` WAN assignments. Factory
interface and firewall configuration remain enabled.

The installed frpc receipt, package registration, configd status and native page
are checked. The unconfigured device must show enrollment and keep rotation
disabled. This preparation does **not** accept enrolled rotation, real relay
cutoff/recovery, public TLS/network access, restoration or W7. Those checks still
need the same current package joined to the controlled deployment.

The factory GUI's self-signed certificate is allowed only for its initial private
page check. It cannot establish verified public/relay TLS. The guest receives
3072 MiB. Its disk, serial transcript, temporary SSH keys, build output and native
configuration remain private to the disposable runner. Only the closed result
and logged-in, unenrolled page images are uploaded. Scrolled mobile images also
check that the enrollment field and rotation control are unobscured in the native
shell's scroll container. No package is signed or published.

Source `548571f` passed the [current preparation run](https://github.com/KazuhaHub/nethub/actions/runs/40798049846):
the unsigned package, rebuilt frpc 0.71.1 with Go 1.26.10, agent stopped status reported through configd
and unenrolled native page were checked on fresh OPNsense 26.7.7. The exact source
archive, official log and four image hashes/visuals were independently verified;
the owned guest terminated with exit status zero. Supplementary mobile viewports
confirmed unobscured enrollment and disabled rotation controls. The earlier
cropped capture and disabled-button foreground failure remain retained. Bootstrap's
disabled hit testing now has actual runtime evidence. Enrollment, rotation and
relay recovery remain separate acceptance work.

## Combined installed-device acceptance

`native-enrolled.yml` waits for a successful six-job CI run for its exact PR source
before allocating a fresh guest. A separate image-gate job bounds that wait;
the existing CI deadline remains unchanged. Manual dispatch can also name the
exact-source producer. `with_images.py` verifies the producer, every required job,
artifact lifetime/checksum, image IDs and layers before loading the existing
tested images. It reuses `server/tests/compose.sh`; ordinary CI does not start a
guest. The optional native hook exercises the actual enrollment and rotation
page actions, configd, PHP model readback and verified assigned-route TLS.

The disposable guest imports only the fixture's public console CA through native
configuration/trust handling. A public CSR uses its existing GUI private key;
that key stays inside the guest. An owned test CA signs the CSR, and a fixture
helper applies the certificate and exact Alternate Hostname through Core Config.
Both native GUI security checks must remain enabled. This precondition is not
acceptance of production certificate issuance. Direct private management browser
TLS exceptions do not count as relay TLS verification.

The fixture checks retained identity/source grants/GUI key, native credential and
claim replacement, old-credential HTTP refusal, a genuine official-frpc stale
Login refusal, and verified TLS recovery at the same assigned route. It also
keeps an independent enrolled official client alive and checks its original
control socket and verified TLS before/after the native rotation. Recovery
after an interrupted installed operation still needs additional installed
coverage; Linux relay and FreeBSD
contracts remain separate evidence. The new combined fixture is unaccepted until
an actual exact-source run and its retained outcomes/images are reviewed.

Only closed outcomes and selected native page images are made readable to the
artifact uploader. Tokens, snapshots, CSRs, fixture keys, raw child output and
service logs stay in root-only ephemeral storage. The runner discards them after
the test. No existing workstation VM, relay, production configuration or formal
package is used.

The first combined run at `02b2313` passed its image gate and installed the native
package, then failed during fixture system-trust preparation before enrollment.
Its owned guest exited with status zero and image cleanup passed. The helper now
uses `toArray(listtags())` to retain the legacy list representation required by
native trust handling ([native configuration adapter](https://raw.githubusercontent.com/opnsense/core/master/src/etc/inc/config.inc)).
Closed fixture-phase diagnostics retain the next failure location without private
exception text. This correction still needs an actual successful combined run;
the earlier failed result remains retained.

The next combined run at `3b9b38a` failed at the fixture's PHP host boundary,
before CA import. Root identity now uses FreeBSD's base `id` command instead of
assuming the optional PHP POSIX extension. The helper still requires one CLI
argument, FreeBSD and effective UID zero; the caller explicitly enables CLI
argument registration. A closed boolean runtime-condition receipt distinguishes
these prerequisites on the actual guest. Run `40798049843` at `548571f` confirmed
all host prerequisites and the absence of the POSIX extension, then failed during
native trust-store regeneration before enrollment. Exact source, both official
logs, closed runtime conditions and owned cleanup were independently retained.
The helper now loads `util.inc` and `legacy_bindings.inc`, checks required native
functions and respects deliberately suppressed native warnings. Unsuppressed
failures still stop the fixture. A bounded context can expose only an allowlisted
error class, source category and line number, never exception text or full paths.
These corrections still need a successful actual run; no installed rotation is
accepted from the failed trust preparation.

The additional unknown-commit fixture loses both real rotation responses after
the upstream returns, using the owned edge's
[response interception](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#intercepting-responses)
and [abort handler](https://caddyserver.com/docs/caddyfile/directives/abort).
It keeps console HTTPS unchanged and restores the original edge configuration
in `finally`. A failed page action must leave the original native model and a
prepared journal while exactly one candidate-bound operation/audit is committed.
The same page action then retries that retained operation, removes the completed
journal and restores verified TLS without changing identity, source grants or
the independent original control. This fixture still requires actual execution.

A second owned helper waits for the real prepared journal, then holds the native
Core Config lock beyond the existing PHP save timeout. It never saves configuration
and has an external deadline. The fixture requires acknowledged lock ownership,
a received assignment, unchanged native model and one committed operation/audit.
After releasing the lock, the page must recover with the rotation endpoint serving
503, apply that same candidate, remove its journal and recover verified TLS.
The original edge configuration is restored in `finally`. A missed lock race
fails the fixture. Both interruption cases still require actual hosted execution;
source and unit tests alone do not establish installed recovery.

Serial bootstrap sends short encoded heredoc lines within FreeBSD's canonical
terminal input bound. Failure results retain only the waiting stage, selected
prompt flags, byte count and image-verification receipt; raw transcripts remain
private. A serial timeout does not establish that the package was installed.

Pinned upstream sources:

- [OPNsense 26.7 announcement and image checksums](https://raw.githubusercontent.com/opnsense/changelog/fd539a8f722f56354e117faa5ab1495a4ad14d5b/community/26.7/26.7)
- [Go release archive checksums](https://go.dev/dl/?mode=json&include=all)
- [OPNsense factory interface assignments](https://docs.opnsense.org/manual/interfaces.html)
- [FreeBSD canonical terminal limits](https://raw.githubusercontent.com/freebsd/freebsd-src/releng/15.1/sys/sys/syslimits.h)
