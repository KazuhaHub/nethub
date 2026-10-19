# Bound order creation and observation

`AccountStore.CreateOrder` accepts a signed CSR, exact assigned DNS name and
immutable enrolled public key. It validates the restricted request/key profile
before network work, takes the existing account OS lease and requires a durably
registered account identity. It cannot initialize, register, adopt or replace an
account. Every operation checks that the CA still returns that exact active
account, then signs the SDK order request using its persisted account KID/key.

Creation requests only that single DNS identifier, without profile or validity
overrides. A CA-selected default profile is accepted only when advertised in the
fresh authenticated directory and bounded to a short identifier; it remains
private job metadata and does not replace certificate-chain/profile validation.
Responses must retain the exact name/type, one approved authorization
URL, approved order/finalize URLs and a known status. Pending/ready/processing
orders need a future expiry and cannot contain a certificate or CA error. Valid
orders need an approved certificate URL; invalid orders expose only their fixed
status, never the CA's error detail. Observation must return the exact persisted
order URI. This metadata is excluded from ordinary JSON serialization. Durable
jobs must also retain and compare their selected profile and authorization/finalize
URLs before advancing a recovered order to challenge acceptance or finalization.

`InspectOrder` makes one signed POST-as-GET observation of the stored URL. It never
creates another order or loops waiting for progress. The shared bounded verified
HTTPS transport, approved origins, disabled redirects/proxy and fixed errors also
apply here; each operation has a 45-second deadline including account lookup.

The future issuer must authorize the current tenant/device/assignment before
creation and delivery. A valid CSR alone is not permission to issue. It must
durably save the returned order URI and request fingerprint before challenge
publication/acceptance/finalization. Losing the new-order response can leave an
unvalidated orphan order; creation is not exactly once and must have a bounded
durable attempt policy. Recover a known order with `InspectOrder`, never by blindly
creating a replacement on each scheduler poll.

No challenge acceptance, finalization, certificate download, job database,
production issuer command/mount/timer, application endpoint or public CA account
is introduced here. Real CA validation and native GUI issuance/application remain
unaccepted. TLS fixtures verify real SDK ES256 KID signatures and single-use
nonces, exact request identifiers, response-origin/identity/status rejection,
unchanged account state, lost response behavior, terminal states and shared lease.

The full local Go test/vet run and the complete account package on actual Linux
passed. Linux additionally repeated order creation/observation and lost-response
recovery twenty times, removed all temporary keys and verified that original
public services remained running. Current-head race/CI and genuine CA order
validation remain required; these loopback protocol fixtures do not issue a GUI
certificate or change an operator account.
