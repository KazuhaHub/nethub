# Certificate automation scope and design

Kazuha requested automatic renewal, distribution and configuration on 2026-10-18,
with PSP as a reference. His selection of option 2 brings router Web UI
certificate issuance, installation and renewal into v1 as well. Console HTTPS belongs to the reverse proxy:
Caddy in the bundled deployment, or the administrator's external reverse proxy.
NetHub must not create a competing ACME manager for that same hostname.

This records the confirmed product scope and a proposed implementation. Certificate
automation is not established by the protocol foundation. Same-root relay
renewal/application is implemented and tested; authenticated trust transitions
and the full router GUI lifecycle remain open. The earlier private
manual-renewal proposal is superseded; it is not an accepted operational design.

The HTTP-01 publication foundation now has an issuer-owned public file store and
an optional HTTP-only Caddy route accepted by genuine proxy tests. It does not
enable routing in existing deployments. Durable initial jobs, current-assignment
lease checks, immutable progress/issued generations and the CA coordinator now
pass combined private PostgreSQL/host-runner/Pebble/Caddy recovery tests. Two lost
committed replies recover the same order/CSR; expired leases cannot regain work,
and one generation/audit/finalize POST is retained. The fixture deliberately
advances lease/retry clocks and seeds public device metadata; it does not measure
production recovery time or replace enrollment acceptance. Protected host
configuration/scheduling and independent proof expiry cleanup now have guarded
native evidence. Authenticated original-request delivery is implemented in
protocol 1.3; the combined host fixture now enrolls a fresh logical device through
compiled HTTP, submits its client-held-key CSR, issues through genuine private
ACME/Caddy and downloads the exact certificate, then verifies removal denial.
Only initial admin/token authority is seeded in that fixture. This is private
HTTP transport with a logical client, not native GUI installation or public
HTTPS acceptance. Renewal jobs, native installation/rollback and trust transitions
remain required. No public
CA account or order has been created. See the issuer and HTTP-01 contracts.

The account client foundation directly reuses `golang.org/x/crypto/acme` and
constrains every request to operator-approved HTTPS origins, verified TLS and
bounded responses. It looks up the caller's previously persisted key before
considering explicit registration with current terms consent. TLS protocol
fixtures cover actual JWS signing and ambiguous-response recovery. The separate
AccountStore now persists the private key before network use, binds immutable CA
policy and recovers account identity without replacing the key. Local and focused
Linux filesystem tests passed; current-head CI and deployment wiring remain gates.
See server/internal/guiacme/README.md and STORE.md. No public account has been created.

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
| Router GUI certificate/key | v1 automatically obtains, renews and installs a certificate for the device's assigned remote hostname through a platform-specific adapter |

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
- Console TLS renewal remains owned by the selected reverse proxy.
- Router certificate issuance, renewal and installation succeed on OPNsense,
  including a fresh browser connection through the TLS passthrough relay.
  Reject a wrong hostname, mismatched key, expired material and another device's
  assignment. Failed installation preserves or restores the prior working GUI.
- Exercise renewal retries, unchanged-content suppression, device offline/rejoin,
  and configuration persistence across reboot. Record the GUI interruption and
  verify that local management and both GUI security checks remain available.

## Router GUI certificates in v1

This corrects the earlier scope record, which read option 2 as console/relay-only.
The owner's answer includes router GUI certificates in v1. Implementation and
native acceptance remain pending; the existing self-signed test certificate is
not evidence of this feature.

Prefer central HTTP-01 when the assigned device DNS reaches the relay and its
public port 80 can serve validation requests. The router can remain behind NAT:
the relay serves the validation resource while the device retains its private
key and terminates its own GUI TLS through frps. HTTP-01 validates a resource on
the requested domain's port 80; it does not require that resource to live on the
router. This follows [RFC 8555 section 8.3](https://www.rfc-editor.org/rfc/rfc8555.html#section-8.3)
and corrects the earlier DNS-01-only assumption. DNS-01 remains an optional
provider-specific fallback; keep provider credentials at the issuance boundary.

Publish only bounded, exact host/token/key-authorization records from the isolated
issuer into a public-only directory outside the private deployment tree. Mount
it read-only in the selected proxy; do not give web/authz write access or serve
arbitrary application-provided validation responses. Keep account keys, PEM and
private metadata outside that directory. Explicit HTTP routing must return 404
for unmatched hosts/paths, prevent traversal and remove expired records, without
causing the proxy to request device GUI certificates itself. Existing host
proxies need an equivalent reviewed port-80 route. This routing and a local
ACME integration are still unimplemented; protocol inspection is not issuance
evidence.

The control plane must authorize the current device, tenant and hostname assignment
before issuance or deployment; neither a pasted hostname nor a signed claim
alone grants that authority. Public certificate issuance exposes names in
Certificate Transparency logs, so the accepted source-IP gate remains required.

Separate issuer, distribution and installation interfaces. The shared protocol
describes certificate generations and verified installation status; only the
OPNsense adapter writes the OPNsense certificate store and selects the GUI
certificate under the native configuration lock. Future router systems provide
their own adapters. Use a device-generated P-256 key and signed CSR for the
assigned name. The issuer returns the public chain; the GUI private key stays on
that device. The CSR validator checks proof of key possession, exact DNS identity
and a restricted request profile; it does not establish tenant/device
authorization. The API must authorize the current assignment before submitting a
job and bind the accepted public key to that enrolled device. Ordinary web/authz
writes cannot replace this binding; rotations need proof from the previous key.
CSR validation alone does not establish that binding. The chain validator now
checks the returned leaf against the exact signed CSR and independently supplied
roots, including identity, server usage, ordered chain and current validity.
Authenticated CSR/chain transport, device key persistence and installation
remain pending; never send keys through command
arguments, logs, ordinary console status or audit payloads.

Persist issued material separately from deployment state, retry deployment
without reissuing, and require a verified applied generation. Validate SAN,
chain, validity and key agreement before changing GUI configuration. Retain
last-good state and use a bounded service-specific apply/rollback operation.
Spread renewal schedules and retain actionable expiry/failure status for offline
devices. Provider support and key custody details are still design work, not
implemented or owner-approved defaults.
