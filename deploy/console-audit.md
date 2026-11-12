# Console audit log

The console's **Audit log** page lists recorded events in descending append order.
Administrators can view this instance's tenant events. Members can view their own
account activity, events targeting their account and events associated with their
devices. Tenant RLS remains in effect; the query also checks the actor's current
enabled account and role. Deleted devices retain visibility only when their
enrollment history establishes unique ownership. Conflicting ownership records
do not establish member access.

Filter by exact action or device UUID, and by an inclusive start and exclusive end
time. Administrators can also filter by the acting user's UUID. The browser
converts local time inputs to UTC; displayed event times use the browser timezone.
The API does not filter by a user's email address. User filters select acting
users, rather than accounts mentioned in an event's details.

`GET /api/v1/console/audit` accepts `action`, `device_id`, `user_id`, `since`,
`until`, `limit` and `cursor`. The default limit is 50 and the maximum is 200.
Times must use RFC 3339. Unknown, duplicate, empty and invalid parameters fail
closed. Pagination cursors bind the tenant, actor and filters; changing a filter
requires restarting pagination. Event IDs remain UUID strings; cursor positions
use exact signed 64-bit database sequence values without JavaScript rounding.
New events can appear after refreshing the first page. No total count or stable
cross-request database snapshot is promised.

Responses expose a fixed event envelope and selected typed details. Raw audit
payloads, credential hashes, claims and tokens are excluded. Source IP addresses
are visible to administrators and to the acting user for that user's own events;
member access to a device's other events does not reveal another actor's IP.
An absent detail or IP is not evidence that the underlying event never had one.
The page does not poll, change grants or perform mutations.

Browsing events does not verify the hash chain and cannot establish protection
against privileged database rewriting. Use the separate
[audit consistency checker](audit-chain.md) for its documented scope and limits.
The console view does not introduce an external audit anchor.

Validation must include genuine PostgreSQL role/tenant/member boundaries and
populated browser checks. Synthetic browser fixtures exercise presentation and
interaction only. Implementation and local unit tests do not complete those
deployment acceptance requirements.
