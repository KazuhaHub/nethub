# Authenticated device lifecycle

Status and unenroll use the existing 1.0.0 messages and an exact canonical device
secret in a single Authorization bearer header. The server validates bounded JSON
and compatibility before credential work. A separate 120-request-per-minute
source-IP budget, a bounded 10,000-source map and the shared two-worker Argon2
budget limit admission; health traffic does not consume enrollment's ten-request
budget. Unknown identities perform dummy verification. Credentials, headers,
dependency errors and submitted bodies are absent from responses and logs.

The authz-only credential lookup derives tenant scope from the database. Every
mutation rereads the hash under a device row lock so a credential replaced after
verification cannot mutate state. Runtime web roles cannot execute that lookup or
read credential hashes. The existing forced RLS and one-way revocation remain.

Health reports store only platform/agent versions, the service state and bounded
reconcile outcome/timestamp. Server receipt time is separate from device time;
reports never update relay-observed last_seen_at and cannot make a device online.
Reports from already revoked devices return a revoked acknowledgement without
changing their metadata.

Unenroll revokes the identity and appends its device audit event atomically. A
repeat confirms the existing revocation without another event. Audit failure
rolls back revocation. A partial unique index releases revoked routing names while
retaining identity/history; authenticated hooks still check device ID and claim.
Previously issued access grants cannot authorize a revoked identity. Existing
connections close through heartbeat denial rather than this HTTP response.

This server increment does not implement the native PHP clearing workflow,
periodic agent reports, authenticated CA generation acknowledgements or GUI
certificates. Full W4 acceptance still requires those separate components.
