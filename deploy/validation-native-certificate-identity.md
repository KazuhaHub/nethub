# Native GUI certificate identity validation

The unsigned OPNsense 0.0.15 package from accepted source `4965310` rejected
wrong-host and wrong-key certificates at both installed verification boundaries.
A correct certificate passed both controls. A subsequent genuine private-CA
issuance completed installation and confirmation through the package cron task.
This is a private-CA, lab-DNS validation on the accepted 1 GiB appliance.

## Boundary controls

The newly enrolled device submitted its real CSR. After genuine initial relay
trust confirmation and two stable tunnel PID samples, an authenticated settings
request recovered that same CSR over verified HTTPS. The test retained the
original device, assigned host, key fingerprint and request in all three payloads.

A temporary independent CA signed three otherwise valid server certificates:

| Certificate | Installed Python verifier | Native PHP shadow preparation |
| --- | --- | --- |
| Original CSR, assigned DNS SAN | Accepted | Accepted |
| Original CSR, different DNS SAN | Rejected | Rejected |
| Different key, assigned DNS SAN | Rejected | Rejected |

Every payload passed the production wire parser, and every leaf passed native
OpenSSL chain verification against the independently provisioned temporary root.
Separate hostname and public-key checks established each intended difference.
The negative PHP controls returned the precise native key/host refusal before
creating a snapshot. The positive control created a protected shadow snapshot.
The Core configuration proxy refused saves; no control installed a certificate
or restarted the GUI. The shared reconcile lock covered the complete probe.

The installed Python and PHP source hashes matched `4965310`. Before/after
hashes and metadata covered the native configuration, key files, relay CA, system
CA bundle and tunnel PID file. Those files remained identical. Temporary keys
and shadow snapshots were removed. Off-host independent parsing checked the CA
and leaf signatures, CSR signature, exact SANs and leaf public keys against the
protected exported original key. No key, credential, operational address or
raw configuration is included in this report.

## Subsequent genuine application

After the controls, authenticated certificate records remained unchanged. The
real issuer then created one order and one finalize request, producing one
generation and one immutable first application. Genuine cron installed and
confirmed it; a public relayed request verified its chain, hostname and exact
leaf fingerprint. The tunnel PID and original GUI key remained unchanged.

| Measurement | Observed |
| --- | ---: |
| Enrollment click to automatic online display | 7.995 s |
| Issuance to native confirmation | 30.015 s |
| Certificate validity remaining at confirmation | 267.504 s |

Normal native UI removal revoked the device, removed its runtime state, rendered
Revoked in a fresh console session and made the former TLS route unavailable.
Independent checks verified the original native checkpoint, managed trust,
stock GUI restart script, all 14 original relay services and listener ownership.
The issuer resources, temporary keys and independent guards were closed.

## Limits and retained failures

These are controlled delivery inputs to the actual installed verification and
native preparation boundaries. They do not represent a malicious public CA or
an invalid certificate delivered by the real authenticated HTTP endpoint. The
subsequent successful issuance used a separate genuine private-CA flow.

Three earlier fixture runs remain failed and are excluded from this result.
The corrected fixture uses Core-declared configuration ownership and the native
hostname command's actual exit convention. A separate FreeBSD lock rehearsal
proved that exit 75 with empty output skips the child while the lock is held;
the coordinator waits for initialization and only retries that bounded case.
Every earlier fixture was retired and the original baseline restored.

Public CA acceptance, combined W4 certificate acceptance, W5-W7 and release
validation remain incomplete. This report changes no product code or package.
