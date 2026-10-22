# Native trust admission and offline recovery

This record follows the [native overlap and lost-response test](validation-relay-trust-overlap.md).
The retained lab deployment contains three genuine enrollments. One had
confirmed generation 2; two had not. One of the unconfirmed identities has a
recoverable generation-1 native model. The other comes from an earlier aborted
enrollment whose returned credentials were not retained.

## Admission refusal

The actual protected host CLI verified the successor backup and its explicit
custody acknowledgement, obtained a healthy service binding, and received all
seven original options with the six required transition request fields. The
request named the current two-root generation, both original/successor roots
and leaves, and a new operation ID and independent successor backup path.

Activation refused with two active devices lacking the current application.
The command retained its original input, prepared snapshot, backups and
maintenance exclusion. No pending database switch was admitted. The operator
then explicitly aborted that prepared operation. An exact abort retry returned
the original terminal receipt, including its cancellation.

Checks before refusal, after refusal and after abort confirmed unchanged active
files, running service container identities and the actual original TLS leaf
on the relay control listener. Device/application state was unchanged. The
current publication and healthy service binding also matched after abort.
This establishes refusal with unconfirmed native identities, rather than a
successful switch or proof that either identity alone caused the refusal.

The successor and its separate backup were also copied off the relay before
this test. The private archive was flushed, reread and checked against both
source inventories, including file contents, modes and numeric ownership.
The protected acknowledgement and its exact retry preserved the first
acknowledgement timestamp. This is lab backup evidence, not release custody
acceptance or public CA account consent.

## Offline overlap recovery

A second bounded window restored the recoverable identity's exported
generation-1 model through native PHP validation after installing the same
unsigned package. Its enrollment credentials matched the original returned
assignment and the hashed export. No new enrollment or application report was
seeded. Before restoration, PostgreSQL had its original application and no
generation-2 application.

New scheduler output after a recorded inode/offset confirmed generation 2.
The native model selected the exact published generation and bundle identity;
the installed CA file matched the model and contained both roots. The common
reconcile lock was free and frpc was running. PostgreSQL held one matching
generation-2 application and one audit event, while the separately enrolled
live identity retained its generation-2 application. frps reported the
recovering identity's assigned HTTPS proxy online.

Two subsequent actual configd trust calls completed in 1.274 and 1.270 seconds.
The native PID and CA bytes, application/audit counts and first acceptance
timestamp remained unchanged. These calls polled an already-applied model;
they do not resolve the earlier cold-sync timeout or measure first-application
configd latency.

Owned logs and the native model were exported before independent relay closure
and appliance checkpoint restoration. The three device records remained
active. The unrecoverable earlier enrollment still lacks an application; no
identity was revoked or removed to satisfy admission.

## Environment and limits

Runtime inputs, unsigned package and resource deviations match the preceding
overlap record: frp 0.71.1 built with Go 1.26.10, the accepted four server images,
unsigned plugin 0.0.12, a 1 GiB OPNsense VM and a 4 GiB Linux LXC. Console HTTPS
uses an independent private fixture CA with hostname verification.

The refusal window did not modify the native appliance. The independent relay
guard closed the window. Follow-up checks confirmed the original fourteen
running containers, original 443/8443 owners and configurations, stopped test
services and retained database/authority storage.

The recovery window also restored the original 0.0.6 package, exact native
configuration and stopped intent. The 1 GiB appliance and its original cold
checkpoint remained present.

Signer activation, old-root retirement, authenticated manual recovery after
retirement and the complete browser/GUI certificate pipeline remain separate
acceptance. Initial cold-sync configd latency also remains unresolved. W5-W7
are not completed by these measurements. Private assignments, operation IDs,
hostnames, addresses, signing material and logs remain outside Git.

The later [authority and deadline record](validation-relay-authority-native.md)
documents explicit backed-up lab administration, the actual signer switch and
root retirement, and corrected manual/scheduled native recovery. The state
described above is the earlier measurement, before that administration.
