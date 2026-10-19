# Certificate automation scope and design

Kazuha requested automatic renewal, distribution and configuration on 2026-10-18,
with PSP as a reference. He then selected console/relay scope for v1 and kept
router Web UI certificates in v1.1. Console HTTPS belongs to the reverse proxy:
Caddy in the bundled deployment, or the administrator's external reverse proxy.
NetHub must not create a competing ACME manager for that same hostname.

This records the confirmed product scope and a proposed implementation. Certificate
automation is not implemented by the protocol foundation. The earlier private
manual-renewal proposal is superseded; it is not an accepted operational design.

## PSP findings

Inspected Passwall-Sub-Panel main at
`acde1f3da692aef1209a2358e075fd3c4ff8e4fc`:

- [Renewal scanning](https://github.com/KazuhaHub/Passwall-Sub-Panel/blob/acde1f3da692aef1209a2358e075fd3c4ff8e4fc/internal/service/cert/renewal.go)
  schedules due and failed certificates. Its threshold adapts to short lifetimes.
- [Certificate tasks](https://github.com/KazuhaHub/Passwall-Sub-Panel/blob/acde1f3da692aef1209a2358e075fd3c4ff8e4fc/internal/service/cert/cert.go)
  separate issuance from deployment, deduplicate active work and retry transient
  failures with a bounded budget. A deployment retry can reuse issued material.
- [Deployment](https://github.com/KazuhaHub/Passwall-Sub-Panel/blob/acde1f3da692aef1209a2358e075fd3c4ff8e4fc/internal/service/cert/deploy.go)
  binds certificates to targets and skips unchanged certificate content before
  scheduling node configuration pushes.
- [The ACME adapter](https://github.com/KazuhaHub/Passwall-Sub-Panel/blob/acde1f3da692aef1209a2358e075fd3c4ff8e4fc/internal/adapters/acme/lego.go)
  contains lego and DNS-provider integration behind an issuer interface.
  [Storage](https://github.com/KazuhaHub/Passwall-Sub-Panel/blob/acde1f3da692aef1209a2358e075fd3c4ff8e4fc/internal/adapters/sqlstore/certificate_repo.go)
  encrypts persisted certificate/key values.

These are source/test inspections, not a fresh PSP deployment or live ACME test.
PSP is AGPL-3.0; no PSP code is copied into NetHub's Apache-2.0 implementation.
Its internal service is not an importable shared module. Reuse an appropriate
independently licensed library if needed, rather than copying the service.

## NetHub ownership

| Material | Owner and v1 behavior |
|---|---|
| Console public HTTPS certificate | Reverse proxy obtains, renews and applies it; NetHub checks the configured HTTPS origin |
| Deployment CA private key | Protected issuance state, outside web/authz/frps runtime containers and ordinary API responses |
| Relay leaf certificate/key | Automated isolated issuance job renews it; frps receives only its leaf/key and applies a changed generation |
| Public relay trust bundle | Authz distributes it over verified console HTTPS; agents validate, apply and acknowledge a generation |
| Router GUI certificate/key | v1.1; no new GUI certificate installation/configuration authority is granted in v1 |

Renewing a relay leaf under the existing CA needs no device trust replacement.
CA rotation is a separate staged operation. The server-authentication design
does not introduce device client certificates or put trustedCaFile on frps.

## Proposed execution boundary

Keep signing authority out of the application services. An operator-installed
host timer runs a one-shot certificate maintenance command against private
issuance state. A Docker-only installation may use a short-lived, isolated issuer
invocation; it is not a web/authz/frps mount or an always-running application
service. The host applies validated output and controls the frps process. No
application container receives the Docker socket or CA signing key.

The issuance job accepts only the deployment's protected relay identity and
configured policy. A console retry button may request the existing authorized
operation; it must not submit arbitrary subjects, SANs, shell commands or paths
to a privileged signer. Public status may expose expiry, fingerprint, generation,
next attempt, last result and per-device acknowledgement, never private material.

Implement durable issue/apply states and a single-operation lease. Persist newly
issued material before applying it. A failed apply retries that same generation,
not a fresh issuance. Bound transient retries, distinguish invalid configuration,
and retain a useful expiry/failure alert after the attempt budget is exhausted.
Do not mark a scheduled or delivered generation as applied without verification.

## Proposed renewal and application

Suggested initial policy remains a ten-year root and one-year relay leaf, with
renewal before expiry and a lifetime-relative bound for shorter certificates.
Use the actual certificate dates; renewal must not repeatedly issue because a
fixed lead time exceeds the whole lifetime. Expiry checking is mandatory even
when an existing tunnel is still connected.

Validate key/certificate agreement, issuer, validity and exact relay SAN before
publishing a generation. Retain the last known-good generation and private backup.
Use service-specific read-only certificate directories: authz receives public
trust/metadata only, while frps receives its leaf/key. Never place the issuer key
inside either directory.

Account for Docker bind-mount inode behavior when replacing files. Atomic rename
of a host file does not prove that a single-file bind mount sees the replacement.
Use an explicit generation/mount/application procedure and test it in Compose.
Stock frps loads certificate material into memory, so applying new files requires
a controlled restart/recreation unless a verified reload mechanism is available.
Gate it by the applied fingerprint to avoid repeated tunnel interruption.

After application, make a fresh verified TLS connection to the relay and record
the presented leaf fingerprint and recovery duration. On failure, restore the
previous valid generation and retry the bounded recovery action; surface a
terminal failure if recovery fails. This is automatic application with measured
interruption, not a claim of seamless renewal.

## Proposed trust distribution

The device obtains authenticated desired trust over its configured, verified
console HTTPS origin. Validate PEM, CA constraints, dates and bounded generation
metadata before atomically installing it through the plugin's approved local
writer. Reconcile should apply changed content and report the applied generation;
it must not repeatedly restart an already-correct tunnel.

For planned CA rotation: publish old-plus-new trust, collect authenticated applied
generation acknowledgements, then switch the relay issuer. Keep the old trust
until all nonrevoked devices acknowledge, or an administrator explicitly chooses
quarantine/manual recovery for remaining offline devices. Delivery alone is not
an acknowledgement. A compromised CA requires an emergency replacement procedure;
ordinary overlap would retain trust in the compromised key.

## Acceptance before claiming automation

- A time-controlled expiry test automatically issues and applies exactly one new
  leaf; subsequent scans do not issue or restart again for unchanged material.
- A short-lived certificate does not cause a renewal loop. Invalid configuration,
  transient failures, exhausted retries and restart/crash recovery are exercised.
- Apply failure reuses the issued generation, preserves/restores last-good state
  and reports separate issuance/application outcomes.
- A fresh external relay handshake observes the new certificate. Measure the
  actual tunnel interruption and automatic client recovery in Compose.
- Trust changes reach an online device, are validated/applied once, and have an
  authenticated acknowledgement. Exercise an offline device and staged root
  transition without silently stranding it.
- Invalid/expired material is rejected. Root private keys remain outside runtime
  mounts, browser responses and logs; restore issuance state from private backup.
- Console TLS renewal remains owned by the selected reverse proxy. No v1 action
  modifies the router GUI certificate or its configuration.
