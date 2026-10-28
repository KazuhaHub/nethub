# Recoverable credential rotation contract

Protocol 1.6 specifies an operation-bound rotation request. The HTTP endpoint,
durable server mutation, native journal/model transaction and page action are
still being implemented. These contracts do not establish operational W7-4
acceptance or make the existing placeholder command usable.

The request contains `agent_protocol_version`, `device_id`, `operation_id` and
`replacement_secret`. The operation ID is a canonical lowercase UUIDv4; the
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
and must match the retained operation. Server-side persistence must not retain
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
