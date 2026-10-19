# Domain claims

This package implements W4-2's HMAC-SHA256 domain claim. It does not serve device
endpoints or authorize relay hooks. A verified signature must still be matched
against the device's tenant, subdomain, current issued_at and nonrevoked database
record before a hook can allow access.

The signed value is unpadded canonical base64url of the five-field JSON payload,
followed by a dot and unpadded base64url HMAC-SHA256 over the encoded payload.
Field order is device_id, subdomain, tenant_id, issued_at, key_id. The independent
Python known-answer vector and shared protocol example guard the representation.

Verification requires the exact canonical encoding: duplicate/unknown/case-folded
fields, reordered or escaped JSON, whitespace, trailing data, padded/noncanonical
base64 and invalid timestamps are rejected even with a correct signature. Tokens
are bounded before decoding; errors contain no input and failed verification
returns no partial identity. HMAC comparison uses the standard constant-time
primitive. The keyring snapshots 32-byte keys and selects an explicit active ID;
retained verification keys support planned signing-key rotation.

`NextIssuedAt` truncates the current time to PostgreSQL microseconds and advances
past the previous value, including same-second rotations and clock rollback. The
device handler must call it while holding the device row lock, save that exact
timestamp, and issue the response within the transaction. This package alone
does not supply the lock or prove transactional rotation; that remains W4-3/W7.
`Issue` rejects a timestamp with finer precision instead of signing a value the
database would round differently.

Tests cover independent encoding, tampering of every field/signature, malformed
and correctly signed noncanonical inputs, key rotation/copy isolation, timestamp
precision/overflow, concurrent use, and fuzz seeds. Full tenant/revocation/hook
checks and live device acceptance belong to the subsequent integration work.
