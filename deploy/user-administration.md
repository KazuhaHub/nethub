# Console user administration

W6 adds administrator-only user listing and role/disable mutations, with a
management page at `/users`. Invitations and provider login remain unfinished.
W6 acceptance is not complete.

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

## Management page

The administrator navigation opens cursor-paginated accounts. The native edit
dialog submits only changed role/disable fields. It preserves a last-admin error
for review, supports Cancel/Escape without a mutation, and refuses dismissal
while a save is pending. Desktop light/dark and mobile layouts use the existing
console components and CSP; no inline-style exception is needed.
Table hover transitions animate the background only. Tests switch the theme
within one rendering frame and require account-text contrast of at least 4.5:1;
screenshots capture completed animations. This prevents inherited text from
briefly retaining its previous theme color against the new background.

The save request has a fifteen-second client deadline. A timeout reports an
unconfirmed change and never replays the mutation automatically; it does not
claim the server rolled back. The dialog becomes dismissible again after failure.

Visible pages refresh every fifteen seconds without overlapping requests;
hidden pages pause refresh. Both user reads and automatic authority confirmation
use passive session checks, preserving idle expiry. An explicit edit or manual
refresh remains active. A 403 clears loaded account data before reconfirming
authority. Self-demotion returns to devices with the current role; self-disable
returns to sign-in. A member opening `/users` directly does not fetch account data.

The backend was accepted in PR [168](https://github.com/KazuhaHub/nethub/pull/168)
after six checks in run
[40179871352](https://github.com/KazuhaHub/nethub/actions/runs/40179871352), actual
logs and DCO inspection. The management browser fixture uses production HTTP and
authentication with stateful synthetic accounts; PostgreSQL boundaries are tested
separately. It checks pagination, changed-field PATCH, pending dialog behavior,
last-admin refusal, member isolation, external demotion and both self-access
changes. This is not combined deployed UI/database or provider-login acceptance.
CI retains only the three synthetic user-management screenshots and its boolean
result receipt from this fixture, excluding credential dialogs and raw requests.
