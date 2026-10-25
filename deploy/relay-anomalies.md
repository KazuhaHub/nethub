# Relay anomaly confirmation

The implementation was accepted in PR #161 at `a69fa27` after all six checks in
run `40145347040`, actual log inspection and thirteen signed commits. This is
backend and browser acceptance; installed/public W5 acceptance remains open.

Authz checks relay anomalies separately from the five-second online display. Its
own private admin HTTP connection pool prevents a stalled check from consuming the
display connection. Checks start after fifteen seconds and wait at least fifteen
seconds after each completed attempt; three successful consistent observations
are required. Missing, changed, failed or widely separated observations break the
confirmation streak. There is no catch-up sampling.

The three categories are revoked-but-online devices, canonical device proxies
whose assigned subdomain differs from the database, and proxies with no matching
database identity. Candidate names establish no identity or tenant. Classification
uses current device rows under explicit tenant RLS; admission continues to use
signed claims and current SQL, with memory-only Ping checks.

`nethub authz --anomaly-action-limit 3` is the default. Valid limits are 1 through
1024. Set the same option on `nethub init` for a new managed bundle; it is retained
in the protected setup configuration and generated authz command, including its
authority binding. An older bundle with the option omitted retains the default of 3.
Resuming initialization preserves that bundle's existing configuration.
More confirmed anomalies than this limit make the whole batch alarm-only.
Cluster-tagged devices also require manual review. Unknown proxies have no trusted
device to revoke and always produce alarms. In the single-tenant v1 console these
are deployment-wide summaries; authz stores the same private summary within each
existing tenant rather than guessing a device owner.

A confirmed ordinary domain mismatch sets one-way revocation and records its
decision atomically with the incident. The existing refresh/heartbeat path then
denies the identity. An already revoked device remains revoked; no administrator
identity is invented to enqueue a manual request, and frps is not restarted.
Manual Revoke and Request disconnect retain their independent authorization and
skip anomaly confirmation. Existing streams are not promised to close immediately.

Only relevant known anomaly targets are locked, with NOWAIT; ordinary matching
online devices are not locked. The transaction rechecks current classification
before any mutation. A changed classification rolls back and requires fresh
confirmation. Receipt, revocation and a bounded tenant audit commit together.
Failed persistence leaves confirmation pending for retry. Unknown audit entries
contain counts without names or digest keys.

The first incident response is immutable. Restarting the worker, retrying a lost
response or increasing the action allowance cannot turn a persisted alarm into
automatic revocation. A successful clean observation resolves the incident; a
later recurrence needs a new three-sample confirmation.

HTTP has a three-second budget, classification and persistence two seconds each,
within an eight-second attempt. Failures log fixed unavailable/resumed transitions.
Admin alert projection is scoped to an enabled current admin and excludes internal
keys. Inventory displays its latest 100 active entries, including honest decision
state and confirmation time; members receive none.

The accepted run exercised all five PostgreSQL anomaly cases: scoped classification
and locked recheck, immutable mass alarms after restart, unknown/admin/member and
cluster projections, busy-target/concurrent retries, and audit-failure rollback.
The compiled authz process used three real fifteen-second observations on an
independent admin connection before one atomic revocation and audit. Its admin
snapshot came from an HTTP fixture; this does not prove anomaly injection on an
installed appliance. Strict-CSP browser checks covered admin polling, member alert
removal, mobile layout and absence of automatic UI mutations.

The same run retained the official-frp heartbeat regression: original sockets
closed in 9.106 seconds, proxies disappeared in 9.119 seconds after stop dispatch,
recovery took 1.269 seconds after the start command returned, and the revoked
device disappeared in 9.843 seconds. These measurements are hosted regression
evidence. The earlier nullable cluster-label failure and formatting failure remain
recorded with their corrections.
