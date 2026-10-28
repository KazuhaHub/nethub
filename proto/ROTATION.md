# Recoverable credential rotation contract

Protocol 1.6 specifies an operation-bound rotation request. The HTTP endpoint and
atomic server mutation are under validation. The private candidate journal is
implemented with recovery tests. Native model persistence, command wiring and
the explicit page action are now under combined validation. The shared-token
incident operation remains unimplemented. These contracts do not establish
operational W7-4 acceptance. See [device operation and limits](../deploy/device-rotation.md).

The request contains `agent_protocol_version`, `device_id`, `operation_id` and
`replacement_secret` and `expected_relay_ca_sha256`. The trust digest is lowercase
SHA-256 of the exact public PEM bundle retained in the native model. The operation ID is a canonical lowercase UUIDv4; the
candidate is 32 random bytes encoded as unpadded canonical base64url. The client
must durably journal both before requesting rotation over verified console HTTPS.
The current device secret authenticates the first request in the single Bearer
header. Neither an operation ID nor knowledge of a candidate authenticates a
previously uncommitted operation. Older minor versions must refuse this workflow.

The response retains the assigned identity, relay credentials/address/trust and
the exact operation ID. Its `device_secret` must equal the journaled candidate.
The native caller must validate that binding before saving. Device ID, owner,
tenant, subdomain and GUI key identity remain stable. A signed claim's issuance
timestamp must advance atomically with the credential hash and audit record;
the previous credential and claim then cease to authorize fresh admission.

A lost response must not strand the device or create a second rotation. A retry
can authenticate with the candidate only after the server has committed it,
and must match the retained operation. New mutations compare the expected trust
digest with the current bundle under the publication fence. A mismatch returns
an authenticated `409 rotation_trust_changed` before credential/audit mutation.
The committed operation retains its public bundle so candidate replay remains
identical across later publication. Server-side persistence must not retain
the plaintext candidate. Conflicting/reused operation IDs, revoked devices,
stale authenticated hashes and tenant mismatches must fail without partial
mutation. Genuine transaction/race tests are required before exposing the route.

PHP continues to save native settings through the OPNsense model under the
shared exclusion and configuration locks. Python requests and validates the
assignment. The native journal survives response loss, failed model saves and
restarts until the saved assignment is independently confirmed. Only a committed
configuration may trigger reconcile. Rotation must preserve local disabled,
revoked and circuit-breaker state; it must not silently enroll or re-enable a
device. Installed/public recovery remains a separate acceptance requirement.

The request and response schemas bound shape and transport size; they cannot
establish entropy, credential possession, durable persistence or authorization.
Credentials belong only in private request/journal storage and verified HTTPS,
never in URLs, process arguments, browser output or diagnostic messages.


The heartbeat cache also retains a monotonically increasing claim issuance floor
for each rotated device. A fresh database Login/proxy check rejects the old claim
immediately after commit. Existing controls learn the floor on the bounded
five-second snapshot refresh and are denied on a later heartbeat. A failed refresh
retains the last good snapshot, so this is not an instantaneous cutoff guarantee.
Rotation is separate from one-way device revocation; a stale claim must not make
a disconnect request appear to have completed device revocation.

A native prepared journal may be discarded only after that exact precommit
conflict from its previous-credential request. A candidate-attempt conflict or
ambiguous network/body failure retains recovery state. Received assignments do
not contact the server again. Periodic trust synchronization waits while any
validated journal remains; malformed state blocks it. After a definitive
precommit conflict, ordinary verified trust synchronization can complete before
a fresh candidate is created. These paths still require combined acceptance.
