# Revocation and authz availability

The generated frps callback list includes Login, NewProxy, NewUserConn and Ping.
The agent retains a 10-second heartbeat interval and 30-second timeout. Existing
bundles need a reviewed configuration migration; replacing the web/authz binary
alone does not enable the added operations. Preserve the immutable setup backup
and rollback material rather than rerunning initialization over an existing stack.

Scheduling or restarting authz interrupts connected tunnels. Ping now depends on
authz: a refused or failed callback enters frp's heartbeat failure path. Clients
reconnect when authz returns, unless their identity was revoked. Keep access to
the host and router that does not depend on NetHub before deploying this change.
The private frps admin API must remain private; it is not a console endpoint.

Generated deployments publish the hook port only on host loopback
(`127.0.0.1:9000`), which host-network frps uses. Authz still binds its exact
private bridge address and accepts only the configured bridge gateway peer.
Use Docker Engine 28 or newer with default NAT bridge behavior; older engines
have a [documented localhost-publication isolation issue](https://docs.docker.com/engine/network/port-publishing/).
When authz stops, the removed loopback publication refuses new callbacks instead
of leaving frps dialing a removed bridge endpoint. Existing deployments need a
reviewed Compose and frps configuration migration together; the external HTTPS
origin ports and proxy trust remain separate. This does not impose a total
transport deadline on upstream frp or make a suspended process responsive.

Authz loads revocations and rotated-claim issuance floors before serving callbacks
and refreshes them every five seconds. Ping checks this memory state after
signature and peer validation; a claim issued before its device's retained floor
is denied. Login, NewProxy and NewUserConn continue to check current SQL state.
Known revocations remain denied and known issuance floors never decrease when
later reads omit them or return older values. Ordinary database errors retain
the previous state, so new revocations or floors may wait for database recovery;
new connection admissions already fail closed.

Revocations and floors use separate read-only repeatable-read scans within one
shared two-second refresh budget; they are not one atomic database snapshot.
Each scan caps at 1,024 tenants, with independent limits of 100,000 revoked IDs
and 100,000 rotated-device floors. Migration 19 adds the revoked-device index.

An unresponsive refresh dependency or failed self-check stops both authz APIs and
exits unsuccessfully for container restart. Database requests have a two-second
budget and 250 ms cancellation grace. HTTP drain is bounded at ten seconds;
observation and database cleanup each have a one-second limit. A suspended process
can still delay callbacks; these bounds do not make a frozen host responsive.

Revocation waits for a successful refresh and the next heartbeat. Existing browser
streams are not promised to close immediately. Explicit source-IP grants still
expire after 30 minutes and only Open renews them; they do not replace revocation
or router authentication.

The deployment fixture measures actual frps proxy control states on authz outage,
restart recovery and revocation, rather than inferring control loss from failed
TLS alone. It also checks Ping rejection, fresh Login rejection and an unaffected
device's verified TLS. SQL integration tests cover two tenants and real lock-wait
failure; memory tests cover last-good retention and refresh/self-check liveness.
[Console Revoke](console-revocation.md), [disconnect requests](disconnect-requests.md)
and the [installed heartbeat measurement](validation-native-w5-heartbeat.md)
have separate evidence. The installed record retains its unresolved W0 timing
comparison; these fixtures do not complete public/mobile W5 acceptance.
See [callback details](../server/internal/relayhook/README.md).
