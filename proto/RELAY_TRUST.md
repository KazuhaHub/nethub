# Relay trust protocol 1.5

The verified console HTTPS origin serves two authenticated POST operations:
`/api/v1/devices/relay-trust/settings` and `/api/v1/devices/relay-trust/applied`.
They require major 1, minor 5 or later. Older major-1 agents keep their existing
enrollment/status/certificate behavior; the new operations explicitly refuse old
minors. A response advertises the server's current version, not an echo of the
request's minor. Native source version 0.0.12 includes the wire builders; it does
not yet automatically apply or report these trust generations.

Settings takes protocol/device identity and returns `desired: null` before host
publication, or the exact current generation ID/number, expected server name,
canonical CA PEM, bundle fingerprint, publication timestamp and effective validity
window. Fingerprints follow `server/internal/relaytrust/README.md`: sorted DER
root identities, LF PEM and domain-separated SHA256. Delivery is not application
and does not create a receipt. The server reparses public material independently
of database metadata; the receiving adapter must independently validate it too.

Applied takes only protocol/device identity, generation ID/number and bundle
fingerprint. It does not carry PEM, private material or a client timestamp. The
repository rechecks the current credential, tenant, live device, exact current
head and validity under the head/device locks. A repeated current report retains
the first server timestamp and one audit; receipt/audit commit atomically.

An authenticated report for a changed/non-current identity returns 409 with the
fixed `relay_trust_changed` code. Fetch desired trust again before reporting.
Authentication/revocation failure returns 401; the agent must still use the
existing status path to learn revocation and stop. A trust fetch failure must not
short-circuit that lifecycle handling. Missing or malformed protocol input has
the existing fixed validation errors. Origin, host, body/header limits, trusted
forwarding resolution, Argon2 pool and lifecycle rate budgets are shared with the
existing device API. No diagnostic includes a submitted secret or CA response.

Go/Python request builders and JSON Schema examples cover this additive contract.
Python builders construct public identity messages. The native verification
helper independently checks the assigned identity, monotonic snapshot, canonical
content, effective dates, CA constraints and each root's self-signature using
isolated native OpenSSL trust. It rejects unknown critical extensions and strips
bounded future response fields. Verification uses disposable public scratch files;
it installs no trust, sends no request and does not assert that a native writer ran.
Receipt parsing correlates the exact report while allowing a newer server minor.
A native adapter must
persist and verify the actual managed trust before calling the applied operation.
It must correlate the exact response, retry a lost receipt without reinstalling,
preserve monotonic generations, and keep the tunnel/source-IP/lifecycle safeguards.

This API does not publish trust, switch relay signing authority, solve bootstrap
expiry/startup migration, quarantine an offline device or implement native
reconciliation. Those remain separate rollout gates. Application reports are
authenticated device assertions, not an independent server observation of the
device filesystem. No new signing key or device client certificate is introduced.

The native model boundary separately supports compare-and-swap of public CA and
generation metadata under the Core configuration lock. It fences enrollment
identity, exact before/after nodes, activation intent and immutable generations;
reads back the saved XML and preserves unrelated fields and Core file ownership.
Exact retries also flush the saved configuration. This boundary alone does not
update the managed CA file, reload frpc or record application. Its root caller
must independently verify a candidate and retain a durable recovery journal
before requesting a model change. Ordinary settings cannot edit trust metadata.

Once metadata is present, ordinary reconciliation independently validates stored
trust and includes its public CA byte fingerprint in the desired configuration
hash. A CA change therefore requires a reload even when the template text stays
the same; an identical CA under a new generation does not restart a good tunnel.
The independent watchdog checks the persisted effective window/content and refuses
a last-good backup bound to another CA, including a legacy unbound backup after a
managed generation. Invalid/expired managed trust stops the tunnel without marking
it revoked. These checks do not replace the pending transaction's crash recovery,
which must be installed before automatic trust application is enabled.

The application component journals public before/after nodes and managed CA bytes
before its first mutation. It quiesces a changed-CA tunnel, uses the native model
CAS boundary, replaces only exact owned CA bytes, records the written phase and
requires a confirmed reconcile before recording application. Pending recovery
restores only the exact owned model/file values and leaves a changed-CA tunnel
stopped. Unknown local changes require review. Recovery never requires network or
claims expired old trust has restored connectivity. Retries retain the highest
desired epoch, wait five minutes after rollback and stop after three attempts for
the same snapshot; a new valid generation gets a fresh budget.

The separate synchronizer always fetches authenticated desired state before a
report retry. It binds the fetch to the native enrollment identity, and reports
only after local application. A rejected/stale/lost report reply preserves good
local trust and retries after a fresh fetch. Confirmed retries retain the original
server receipt timestamp; a compatible server version change does not reinstall.
Both components remain disconnected from production scheduling until boot/direct
startup/watchdog pending-state fencing and removal recovery are integrated.

The shared HTTPS transport permits only the exact lifecycle, GUI certificate and
relay trust paths. Real TLS tests exercise those paths through the transport,
including GUI settings and trust application/stale-report retry; helper mocks
alone cannot prove a route is reachable.
