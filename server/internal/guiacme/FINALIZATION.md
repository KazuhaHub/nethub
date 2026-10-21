# Bounded finalization and issued-material recovery

`FinalizeOrder` uses an existing durable account, exact saved order identity and
signed request matching the enrolled device key. The caller must persist its
finalizing intent and reauthorize the live tenant/device/assignment before calling,
and again before storing/delivering the result. This component is not that job
journal or authorization transaction.

Pending/processing orders return a fixed not-ready result without submitting a
CSR. A ready order submits the original DER through the SDK under the shared
45-second account lease. An already valid order fetches its existing certificate
without submitting again. Lost finalize/download replies can therefore recover
the same known order. If an ambiguous operation is still ready, a future durable
attempt policy must bound another submission; exactly-once HTTP is not claimed.

After download, the client rechecks the original order, hostname, CSR fingerprint,
profile, authorization/finalize URLs and returned certificate URL. A previously
known certificate URL cannot be replaced. The original bounded PEM response is
retained privately for validation: re-encoding the SDK's DER output would otherwise
hide ignored PEM headers or trailing junk. Each operation has at most 32 captured
HTTP responses, with the existing verified-origin/size/deadline constraints.

Certificate MIME, canonical PEM, exact CSR key/SAN/profile, ordered chain, server
usage and current validity are checked against an independently provided root pool
snapshot. That pool is separate from trust in the CA's HTTPS API and never comes
from the downloaded chain. Missing roots, changed identity, wrong key/name,
expired/untrusted material and malformed wire data return fixed errors with no
installation material. Issued metadata/chain are excluded from ordinary JSON.

Local fixtures verify actual SDK KID signatures/nonces and trusted signed chains.
They cover successful/reopened recovery, lost finalize and certificate responses,
unready orders, missing/wrong roots, raw PEM headers/trailing data, wrong MIME,
reordered or wrong-key/name/expired chains and post-finalize identity changes.
The complete local Go tests and vet passed.

The genuine Pebble/Caddy fixture passed in 5.57 seconds: real HTTP-01 validation,
independent root verification, issuance of the exact CSR/key chain and recovery
after reopening the account store with the old ready-order identity. The isolated
CA recorded one order and one finalize POST. Its logger identifies the registered
route prefix rather than the opaque order suffix; the first counter assertion
used the latter and its failed rehearsal was retained.

For this test only, the management interface serves the public issuing root on
the private internal bridge. It is retrieved before any order through the
independently pinned API TLS channel; no private-key endpoint is requested and
no system trust store changes. This test CA and its roots are never production
trust. Independent cleanup removed both containers, network and all temporary
keys before cancelling the guard. Original public services remained running.

No native GUI certificate was installed. Durable jobs, live assignment/API wiring,
authenticated delivery, renewal scheduling and native application/rollback remain
open. Local proof does not replace the six required exact-head hosted checks
and inspection of their actual logs.
