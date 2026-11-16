# Authenticated reconcile failure events

Protocol 1.7 adds POST `/api/v1/devices/reconcile-events`. It carries a device
identity and one to eight retained failure events over the existing verified
console HTTPS/bearer path. Existing major-1 enrollment, status, rotation and
removal messages keep their required fields and meanings. Minor versions below
1.7 cannot acknowledge this endpoint. A new agent retains pending events when
an older console answers status, and reports the pending condition locally.
An older agent can continue its existing operations; it has no durable event
outbox. A newer server cannot reconstruct its missed failures.

Each event has a random v4 UUID, fixed `reconcile_failed` or
`reconcile_failure_overflow` kind, positive signed-64-bit count and canonical
microsecond-UTC first/last observation times. Ordinary events count one and have
identical times. No raw error, configuration, key, command output or path is sent.
The device clock and report are untrusted statements. Server audit append time
is independent; these records do not prove truthful local execution.

The root-private local outbox is bound to one enrollment. Callers hold the same
mutation lock as reconcile, reporting and removal. It retains up to 64 individual
events. At capacity, later failures increment a bounded overflow summary without
evicting the original events. The summary explicitly discloses lost individual
ordering/details; it is not evidence that every failure has its own record.
A frozen overflow event keeps its original UUID/count on retry. Later failures
use a separate pending summary. A saturated counter or unsafe storage fails
explicitly, preserving existing bytes; it cannot justify a success or silently
release local stop policy.

Reporting sends at most one batch per ordinary report. Only an exact accepted
ordered-ID acknowledgement permits local deletion. Unavailable replies retain
the original records. The server rechecks the current credential under the
device lock, enforces tenant RLS, retains immutable original event content and
appends each new event/audit atomically. Concurrent exact replay returns the
same IDs without another audit; conflicting content fails. Audit failure rolls
the event insert back. Web cannot insert, update or delete the event history. Authz readiness refuses missing/disabled event guards or widened write authority.
The backup identity can read it. New distinct events are limited to 2048 per
device per server UTC day; exact replay does not consume another slot. This
bounds ingestion, not historical retention or online fleet capacity.

A revoked identity may drain its authenticated retained history without changing
revocation, source grants, claims, online status or tunnel admission. Removal
stops and confirms server revocation first. Pending event delivery then precedes
native model clearing; each explicit retry drains at most one batch. An older
console may need upgrading before that history can be acknowledged. Removal
never silently erases pending events to appear successful. Restore the matching
private outbox with an enrolled device's local state; conflicting old-enrollment
history requires local review rather than rebinding or discarding it.

This implementation is under validation. Unit/filesystem, actual PostgreSQL and
compiled-HTTP results have distinct scopes. Native package migration, offline
recovery, current-source public/mobile operation and formal release require their
own actual evidence. Earlier sources' audit-chain integrity results do not prove
this new event-delivery path.
