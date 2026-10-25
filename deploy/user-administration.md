# Console user administration

W6 adds administrator-only user listing and role/disable mutations. These are
backend endpoints; the management interface, invitations and provider login
remain unfinished. W6 acceptance is not complete.

`GET /api/v1/console/users` returns a tenant-scoped cursor page without password
hashes, provider secrets or identity subjects. The projection includes only
identity provider slugs and link timestamps. Anonymous and member requests cannot
list accounts.

`PATCH /api/v1/console/users/{id}` accepts role and/or disabled state. It requires
the normal session, exact-origin and CSRF policies. Unknown, repeated, null and
malformed fields are rejected; neither account email nor credentials can be
changed through this operation.

The transaction serializes account administration per tenant, locks actor/target
rows in ID order, and rechecks the current actor. This prevents an administrator
demoted while waiting from retaining old authority. The existing database trigger
also preserves an enabled local-password administrator for writes outside the
HTTP path. Last-admin and last-local-password-admin refusals return separate 409
codes.

Disabling an account deletes its sessions and appends account/session audit
events in the same transaction. Audit failure rolls everything back. Enabling the
account again requires a fresh login; it cannot revive deleted cookies. Existing
sessions reload the current role on each request. Device enrollment is not
revoked by a user-management operation.

The SQL suite exercises real web-role tenant isolation, pagination, role lookup,
disable/re-enable, both audit failure positions, competing local-admin changes
and a positively observed actor-row wait. HTTP tests cover admin/member/anonymous
access, origin/CSRF, input validation and error mapping. Hosted execution results
must pass before merging; source tests alone do not establish deployment or UI
acceptance.
