# Native offline certificate renewal

## Tested inputs

The unsigned 0.0.15 plugin was built from `4965310`, accepted in PR #141
(`85af224`) after all six jobs in CI run 40039202976 and actual log inspection.
The package archive, installed package checksums, product/model versions and
archived PHP source were independently matched to that revision.

The test used OPNsense 26.7.7 behind host NAT, with the owner-approved 1 GiB
allocation below the documented 3 GiB VM minimum. The retained deployment used
runtime `ab20628` and patched Caddy `6614ab6`, from their accepted, verified image
archives. Console and GUI trust used independent private roots and explicit lab
DNS. GUI leaves lived for 299 seconds; this was not public CA acceptance.

## Observed lifecycle

The actual browser enrolled a new device and displayed it online in **7.788
seconds**, without a console reload or manual inventory refresh. Genuine package
cron installed generation 1 and reported its application. Independent public
TLS checks verified the chain, assigned hostname and served leaf fingerprint.

The same guest was shut down. Natural renewal issued generation 2 while host
observations confirmed it was off; its database application record remained
absent. A single guarded start booted the unchanged 1 GiB guest. Early boot
receipts retained its key, selected reference, generation-1 leaf and journal.
Both fixture roots and the explicit DNS configuration survived boot.

Genuine cron then installed and confirmed generation 2. Its relayed connection
passed the same independent TLS checks. The exported native snapshot retained
the original native UUID, reference and private key while replacing the leaf.
This exercises the model serialization that caused the earlier last-good
identity rejection.

| Measurement | Observed |
| --- | --- |
| Generation 1: issuance to server-confirmed native application | 47.995 s |
| Generation 2: issuance to server-confirmed native application, including offline/boot time | 200.967 s |
| Boot DNS readiness to generation-2 confirmation | 77.521 s |
| Generation-2 validity remaining at confirmation | 95.703 s |
| Renewal issuance after the first leaf's renewal threshold | 15.489 s |

The CA recorded exactly two real orders and two finalizations from the original
key/CSR. Both generation records and their first application receipts remained
unchanged through subsequent observations and removal. No clock or immutable
database record was edited. All ten exported applied-material files passed their
retained hashes.

## Removal and restoration

Native UI removal completed cleanup. A fresh console login displayed Revoked;
the old subdomain could no longer complete TLS against the live TCP listener.
Independent guards removed the temporary issuer, keys and units, restored the
original native checkpoint/configuration/package 0.0.6/stopped intent, and left
the original guest running. The original managed trust bundle, all 14 original
relay containers, service bindings and listener owners were independently checked.

Before this experiment, recovering the original VM from the package-build
checkpoint required reclaiming idle pages from the host execution processes.
No application was closed and no VM or system setting changed. The experiment's
own offline start passed the recorded memory preflight without another
reclamation. Its lightweight host observer completed one asynchronous start job
with no error. Earlier failed starts and lifecycle results remain archived.

## Remaining acceptance

This closes the corrected-package offline renewal and reboot-persistence check
within the private-CA, lab-DNS and 1 GiB scope. A separate
[restart-failure experiment](validation-native-certificate-rollback.md) verified
rollback and delayed same-generation retry. Wrong-host/key rejection, public CA
and the remaining W4-W7 acceptance remain open. The earlier
[failed lifecycle](validation-native-offline-recovery.md) and
[its diagnosis](validation-native-certificate-normalization.md) retain their
original outcomes. Private payloads, deployment details, keys and screenshots
remain outside Git.
