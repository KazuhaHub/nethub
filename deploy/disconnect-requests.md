# Explicit disconnect requests

After revoking an enrollment, its owner or a tenant administrator can request
disconnection from the inventory row. The action records a request for authz;
web never receives frps administration credentials. The request does not undo
revocation or renew an access grant.

The same session, origin, CSRF and resolved-source checks protect
`POST /api/v1/console/devices/{canonical-uuid}/disconnect`. Only an empty JSON
object is accepted, with a separate per-actor/source attempt limit. An active
enrollment returns a conflict; foreign and missing devices share an unavailable
response. The enabled actor and device are locked before request insertion.

Migration 20 corrects the old active-only disconnect helper without changing
Open's authorization. Requests require an already revoked device. Retries preserve
the first request ID, requester and timestamps, with one request audit. The console
reads a narrow owner/tenant-scoped status projection, without raw queue access.
Web can neither mark a request processed nor change its identity.

Authz checks pending requests after its five-second revocation refresh. It marks
a request armed only when the corresponding tenant/device is already denied in
the published memory snapshot. Pending devices and requests use skip-locked reads;
each pass processes at most 128 requests with the existing two-second budget.
An unresponsive processor has the same cancellation grace and process-exit path
as an unresponsive refresh. Database or audit errors leave the request pending
and preserve the memory denial. Processing status and its audit commit together;
retries preserve the first armed timestamp. Known revocations reload before hooks
open after a restart.

The UI distinguishes Pending from Heartbeat rejection ready. Armed means the
Ping rejection mechanism is ready; it does not prove an existing control socket
or browser stream closed. The action bypasses anomaly confirmation, not heartbeat
scheduling, callback delays or network failure. See
[heartbeat availability](revocation-and-heartbeats.md).

Source tests cover publication-before-ack and stalled processing. PostgreSQL cases
cover explicit request scope, concurrent retries, stable receipts, audit rollback,
runtime grants and inventory metadata. A compiled authz case exercises genuine
web-role request creation and scheduled processing. Browser fixtures check pending
retry and polled armed status. These fixtures do not replace combined native/public
W5 acceptance, anomaly detection or measured established-stream behavior.
