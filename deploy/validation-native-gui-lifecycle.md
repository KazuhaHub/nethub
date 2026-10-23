# Native GUI certificate issuance, renewal and removal

On 2026-10-23, an actual OPNsense 26.7.7 NAT guest completed GUI certificate
issuance, scheduled installation, natural renewal and native UI removal through
the isolated public relay. Both served generations passed independent TLS chain,
hostname and exact leaf-fingerprint verification. The result uses a private
test CA; public CA trust and registration are not claimed.

## Inputs and boundaries

- Unsigned plugin 0.0.14, built from `aaf0dbe`; official frp 0.71.1.
- Previously accepted relay images from `9ffcb2d`, run 39828844165. Device and
  issuer handlers used here are unchanged by the deployment-generator fix.
- The production host initializer and issuer command built from `0ab6753`, with
  the shipped issuer service restrictions adapted to exact private fixture paths.
- A private Pebble 2.10.1 CA and an internal HTTP challenge proxy. Their API and
  issuing roots were independently verified. Account initialization, independent
  backup verification, registration with private test terms and account lookup
  completed before issuance. No public CA account or terms were used.
- The owner-approved 1 GiB native guest remains below the documented 3 GiB VM
  minimum. The private issuer ran every 10 seconds and used approximately
  five-minute certificates to exercise natural renewal within the guarded window.
  The installed appliance cron schedule was unchanged.

The retained deployment predates [the admission fix](validation-certificate-admission.md).
An explicit temporary Compose override supplied only its missing authorization
device-domain argument. Protected deployment files, original device identities
and their histories were retained. This is not an existing-bundle migration test.

The actual browser flow minted a token and enrolled a new native fixture. Its
PHP-saved model and native-generated key were exported before certificate work.
The test operator provisioned only the private issuing root and exact Alternate
Hostname; all other native System settings were compared unchanged. Both GUI
security checks remained enabled.

## Observed sequence

The package's bounded, shared-lock command submitted the original CSR while the
issuer was stopped and returned `pending`. The real issuer timer was then
started. Subsequent appliance observations were read-only: genuine package cron
performed installation and authenticated application reporting.

| Generation | Leaf lifetime | Issued to native confirmation | Public TLS and GUI GET |
| --- | --- | --- | --- |
| 1 | 299 s | 35.617 s | Passed |
| 2 | 299 s | 24.530 s | Passed |

Generation 2 was issued 6.392 seconds after generation 1's stored renewal
threshold. No clock or database timestamps were changed. Both generations used
the same native private key and original CSR. Repeated database observations
preserved the immutable generations and first application receipts. Actual CA
logs contained exactly two new-order POSTs, two finalize POSTs and order counts
of one, then two. The issuer timer was stopped after the second issuance.

Both public probes verified the configured private root, assigned hostname and
database leaf fingerprint before making a bounded GUI request. Both returned an
accepted HTTP response. The complete applied profile's ten exported files were
independently checked against their recorded hashes.

The native page's **Remove enrollment** button then returned success,
`enrolled: false` and `cleanup_complete: true`. A fresh console login displayed
the same device as **Revoked**, also confirmed in PostgreSQL. A new connection
to its original subdomain reached the public TCP listener but could no longer
complete TLS. This checks the route while the relay window is still open,
before infrastructure cleanup.

## Restoration and remaining acceptance

The private CA/proxy, timers, units and temporary keys were removed first while
preserving the live relay's container identities. The relay guard then restored
all 14 original running containers, their service configurations and original
443/8443 listener owners. The native cold checkpoint restored package 0.0.6,
exact configuration and stopped intent. Its system trust bundle independently
matched the original path, permissions and SHA256. No host reboot was requested.

Earlier attempts remain recorded separately: a nonexistent configd action in
the harness, the missing admission argument and a Windows export path exceeding
260 characters. A preceding run independently passed both certificate generations
but stopped during that export, so it did not establish UI removal. The accepted
run used a short export location and retained complete raw material before file
extraction. Failed records were not replaced with the successful result.

Private keys, credentials, raw responses, operational addresses and screenshots
remain outside Git. Wrong-host/key rejection, application failure/rollback,
offline recovery, reboot persistence and public CA operation still require
separate evidence. This record does not complete W4 or the remaining W5–W7 work.
