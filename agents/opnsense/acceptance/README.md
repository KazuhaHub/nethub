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

Source `b148325` passed the [initial preparation run](https://github.com/KazuhaHub/nethub/actions/runs/40781008446):
the current unsigned package, rebuilt frpc 0.71.1, configd stopped status and
unenrolled native desktop page were checked on a fresh OPNsense 26.7.7 guest.
The exact source archive, official log and both original image hashes were
independently verified; the owned guest terminated with exit status zero.
The original mobile image cropped lower controls in the native scroll container.
The supplementary mobile captures above still require execution and review.
Enrollment, rotation and relay recovery remain separate acceptance work.

Source `c2b91a9` installed the package and captured enrollment plus the visible
disabled rotation control, but its foreground assertion failed. The check now
accounts for Bootstrap's disabled-button hit testing and records closed boolean
geometry/hit results and a fixed failure phase. This correction needs a real run;
the earlier failed overall preparation result remains retained.

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
Login refusal, and verified TLS recovery at the same assigned route. Recovery
after an interrupted installed operation and concurrent independent-device
survival still need additional installed coverage; Linux relay and FreeBSD
contracts remain separate evidence. The new combined fixture is unaccepted until
an actual exact-source run and its retained outcomes/images are reviewed.

Only closed outcomes and selected native page images are made readable to the
artifact uploader. Tokens, snapshots, CSRs, fixture keys, raw child output and
service logs stay in root-only ephemeral storage. The runner discards them after
the test. No existing workstation VM, relay, production configuration or formal
package is used.

Serial bootstrap sends short encoded heredoc lines within FreeBSD's canonical
terminal input bound. Failure results retain only the waiting stage, selected
prompt flags, byte count and image-verification receipt; raw transcripts remain
private. A serial timeout does not establish that the package was installed.

Pinned upstream sources:

- [OPNsense 26.7 announcement and image checksums](https://raw.githubusercontent.com/opnsense/changelog/fd539a8f722f56354e117faa5ab1495a4ad14d5b/community/26.7/26.7)
- [Go release archive checksums](https://go.dev/dl/?mode=json&include=all)
- [OPNsense factory interface assignments](https://docs.opnsense.org/manual/interfaces.html)
- [FreeBSD canonical terminal limits](https://raw.githubusercontent.com/freebsd/freebsd-src/releng/15.1/sys/sys/syslimits.h)
