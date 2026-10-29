# Recoverable device rotation backend

`POST /api/v1/devices/rotate` requires protocol 1.6, the existing single canonical
Bearer credential and an operation-bound candidate. It shares the lifecycle
source and Argon2 admission budgets. A candidate is hashed only after successful
authentication; recovery with an already committed candidate does not hash it
again. All dependency failures use fixed diagnostics and responses are `no-store`.

The store fences published relay trust before taking the tenant-scoped device
lock, rechecks the authenticated hash and rejects revoked devices. A new operation
updates only the credential hash and monotonically advancing claim timestamp,
then inserts immutable hash/commitment metadata and the audit in one transaction.
Signing or audit failure rolls everything back. No plaintext candidate is stored.
Existing device, tenant, owner, routing name and GUI key/history remain unchanged.

A retry must authenticate the committed candidate, match the same operation and
commitment, and still match the current device hash and issuance timestamp. An
old bearer, conflicting candidate, unrecorded equal-to-current candidate or
superseded operation cannot recover or initiate another rotation.

Fresh relay admission checks the current timestamp in PostgreSQL. The heartbeat
snapshot also tracks monotonic issuance floors for rotated devices, separately
from revoked IDs. Older reads and failed refreshes cannot lower a known floor.
Ping stays memory-only. A rotated claim is not evidence that device revocation
completed; disconnect processing still requires membership in the revoked set.
The existing five-second refresh, bounded reads and last-good failure behavior
mean this is not an instantaneous control-channel cutoff guarantee.

This backend is under genuine PostgreSQL and deployed relay validation. Shared
schema and local fake-repository tests do not prove those runtime boundaries.
The native durable journal/model transaction and command/page action are under
combined validation. The coordinated shared-token incident operation remains
W7-4 work. See the [wire contract](../../../proto/ROTATION.md) and
[device operation](../../../deploy/device-rotation.md).
