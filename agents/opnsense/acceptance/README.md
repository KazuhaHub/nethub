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
and two logged-in, unenrolled page images are uploaded. No package is signed or
published. This new preparation path is unaccepted until its real run succeeds.

Serial bootstrap sends short encoded heredoc lines within FreeBSD's canonical
terminal input bound. Failure results retain only the waiting stage, selected
prompt flags, byte count and image-verification receipt; raw transcripts remain
private. A serial timeout does not establish that the package was installed.

Pinned upstream sources:

- [OPNsense 26.7 announcement and image checksums](https://raw.githubusercontent.com/opnsense/changelog/fd539a8f722f56354e117faa5ab1495a4ad14d5b/community/26.7/26.7)
- [Go release archive checksums](https://go.dev/dl/?mode=json&include=all)
- [OPNsense factory interface assignments](https://docs.opnsense.org/manual/interfaces.html)
- [FreeBSD canonical terminal limits](https://raw.githubusercontent.com/freebsd/freebsd-src/releng/15.1/sys/sys/syslimits.h)
