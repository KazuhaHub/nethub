# Native GUI certificate rollback and retry

## Setup and fault

The experiment used the accepted unsigned 0.0.15 package from `4965310` on
OPNsense 26.7.7, behind host NAT at the owner-approved 1 GiB allocation. Package
checksums and source identity matched the earlier
[offline-renewal validation](validation-native-offline-renewal.md).

The device first completed genuine scheduled relay-trust application and its
authenticated generation-1 confirmation. Its model, managed CA and receipt agreed;
two consecutive running-PID samples established the fault baseline. An earlier
attempt stopped before fault injection when its PID sample overlapped this
bootstrap transition; that attempt remains failed.

A device-bound wrapper around the stock GUI restart command returned exit 1
exactly once, after the production store selected the new certificate. Later
rollback and retry calls delegated to the retained, hash-checked stock script.
Production plugin modules stayed unchanged. Five temporary-file/stub rehearsals
on FreeBSD had verified the wrapper's failure, rollback and retry branches plus
wrong-key and wrong-phase refusals without touching real native configuration.

The private CA used a 600-second profile to cover the product's unchanged
300-second retry delay. The issuer timer stopped after generation 1, so recovering
the application could not depend on another issuance. Native and relay deadline
guards remained in force throughout.

## Observed recovery

The actual transaction rolled back to the previous GUI selection after the
restart failure. Independent comparison of complete native XML found no changed
settings apart from revision/formatting metadata. A public connection matched
the original leaf's exact pin and returned a usable GUI response. This pin check
did not claim public-CA hostname validation for the original certificate.

Genuine package cron observed the retry delay and installed the same candidate
on attempt 2. The generation ID, staged-candidate digest and issued-material
digest were unchanged. Its new public connection passed independent CA-chain,
assigned-hostname and leaf-fingerprint checks. The tunnel PID and device-held
GUI key remained identical throughout the fault and retry observations.

| Measurement | Observed |
| --- | --- |
| Failure to retry's native restart delegation | 359.777 s |
| Stored retry deadline to that delegation | 58.623 s |
| Issuance to server-confirmed native application | 390.135 s |
| Leaf lifetime | 599 s |
| Validity remaining at confirmation | 207.365 s |

The CA recorded one real order and one finalization. PostgreSQL retained one
request, job, generation and first application receipt. Generation/application
records remained unchanged in later observations and after removal. No clock,
retry deadline or immutable database record was edited. Rollback and applied
material exports passed their retained hashes; the successful native config
changed only the owned certificate entry and GUI selection.

## Cleanup and limits

The stock restart script was restored before normal native UI removal. A fresh
console login showed Revoked, and the old subdomain could not complete TLS.
Independent guards removed the temporary issuer, keys and units and restored
the original running appliance, configuration, package 0.0.6 and stopped intent.
The stock script's bytes/owner/mode and the original managed trust were checked
again. All 14 original relay containers, bindings and listener owners were
restored, with the owned stack stopped.

This verifies one native restart failure with rollback and delayed same-generation
recovery. Private CA trust and the 1 GiB resource deviation remain part of its
scope. Wrong-host/key rejection, public CA and the remaining W4-W7 acceptance
are open. Process-death and hang recovery remain separate checks. Private XML,
keys, credentials, payloads and screenshots stay outside Git.
