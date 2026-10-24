# Internal relay callbacks

W4 implements `Login` and `NewProxy`, and W5 adds `NewUserConn` and `Ping` on
`POST /api/v1/frp/hooks`. The public
device listener does not serve this route. Enable the separate listener with
`--hook-listen` and repeatable `--hook-peer` flags. The bind must be an exact
private or loopback IP; peers are exact socket addresses without CIDRs or DNS.
Do not publish this port or proxy public requests to it. Forwarding headers do
not establish relay authority.

The adapter follows frp 0.71.1's [request types](https://github.com/fatedier/frp/blob/v0.71.1/pkg/plugin/server/types.go)
and [HTTP caller](https://github.com/fatedier/frp/blob/v0.71.1/pkg/plugin/server/http.go).
Both the envelope and query must identify the same operation and callback API
version `0.1.0`; this is separate from NetHub's device protocol version. The
caller has no configured timeout in that source path, so the handler enforces a
500 ms read/authorization budget, a one-second response deadline and at most 64
active callbacks. The listener separately bounds header reads and idle sockets.

Read at most 64 KiB, reject duplicate keys at every depth, and extract identity
from exact field names: Login's `metas` or other operations' `user.metas`. Verify the
deployment signature and metadata device ID before admission. For Login,
NewProxy and NewUserConn, storage
sets tenant RLS from that verified identity and requires the current device ID,
tenant, subdomain and microsecond issuance timestamp, with `revoked=false`. A
row share lock serializes that check with revocation or claim replacement. A
valid signature alone does not authorize a callback.

NewProxy additionally requires HTTPS, the assigned subdomain, the canonical
`nethub-<device_id>-web` proxy name and no custom domains. frps has a
[global proxy-name registry](https://github.com/fatedier/frp/blob/v0.71.1/server/proxy/proxy.go),
so the old constant name prevented a second device from registering. The agent
now renders the per-device name; the hook prevents another device from claiming
it. Pre-v1 test clients must update their rendered configuration. Shared proxy
groups/group keys are rejected because the current agent
has a single device route. The [upstream message fields](https://github.com/fatedier/frp/blob/v0.71.1/pkg/msg/msg.go)
are serialized by frps before this check. The response never changes that
content: allow uses `reject=false, unchange=true`; all failures deny. Invalid
identity and revoked/missing assignments share a fixed rejection. Log only a
known operation and decision code, never raw metadata, claims, credentials, query
values or dependency errors.

Both listeners stop if either fails. SIGTERM drains both; a hook bind failure
does not leave the public API running alone. With no hook flags, enrollment-only
startup remains available and explicitly reports hooks disabled.

`NewUserConn` verifies the same signed/current assignment, the canonical HTTPS
proxy name and the relay-reported exact TCP source. IPv4-mapped addresses normalize
to IPv4; hostnames, ranges, scoped addresses, unspecified/multicast addresses and
invalid ports are refused. HTTP forwarding headers never select this source.
The request requires an unexpired exact grant from explicit console Open. Its
actor must still be enabled and either the current owner or an administrator.
The narrow `device_source_access` function locks the grant/actor and rechecks the
database clock after waits; it exposes only a boolean to authz, with no user-table
read grant. Traffic does not extend access. Router GUI authentication remains
required, and an already established stream can outlive its source grant.

Generated frps configurations include `NewUserConn` and `Ping`. Existing bundles must update
their callback operation list before source gating can be claimed; updating the
web binary alone does not enable it. The Open UI is implemented; real native source-gate
acceptance remains separate W5 work. Missing/expired grants and storage errors
deny within the existing hook budget.

`Ping` uses only an initialized in-memory revocation set, keyed by tenant and
device. It still verifies the signed login metadata and trusted socket peer.
Authz loads the initial set before serving hooks and refreshes it every five
seconds using a read-only, repeatable-read transaction with tenant-local RLS.
The existing database grants suffice. Database failures retain the last good set;
known one-way revocations never disappear after an incomplete read. Login and
proxy admission continue to query current database state. Successful Ping decisions
log at debug level; denials keep the fixed operation/decision log.

Refresh has a two-second database budget and a 250 ms cancellation grace. An
unresponsive loader or a failed in-memory self-check stops both authz listeners
and exits unsuccessfully, allowing the container restart policy to act. There
is at most one refresh request in flight. Normal database errors do not trigger
this exit. HTTP draining retains its ten-second bound; observation cleanup and
database cleanup each wait at most one additional second so an unresponsive
dependency cannot trap process exit.
Snapshot reads are limited to 1,024 tenants and 100,000 revoked device
IDs; exceeding a limit refuses the refresh instead of discarding existing denials.

Clients retain the explicit 10-second heartbeat interval and 30-second timeout.
frp's [Ping handler](https://github.com/fatedier/frp/blob/v0.71.1/server/control.go)
processes plugin refusal through its heartbeat error path. Authz restart or outage
therefore affects every connected tunnel. Deploy authz changes with that
interruption in mind; clients reconnect after service recovery. A suspended
process can delay callbacks, and refusing a heartbeat does not promise immediate
closure of every established browser stream. Newly revoked IDs wait for a
successful refresh and their next heartbeat. Database outage can delay that
refresh while new Login/proxy/user connections already fail closed.

The official-client deployment fixture checks actual frps proxy control states
through its private admin API, not only TLS failures (which could instead be
NewUserConn rejection). It separately exercises authz outage/recovery, cached Ping
revocation, fresh Login denial and an unaffected device's verified TLS route.
These isolated checks do not replace the native/public-network W5 acceptance.

Local tests cover signature/identity/routing rejection, peer spoofing, bounded
input, saturation, database deadlines and a real slow-body TCP connection. The
native PostgreSQL harness adds valid signed-but-stale/wrong assignments,
revocation/claim changes during observed row-lock waits, and compiled-process
callbacks, a real 500 ms database lock timeout, recovery, listener separation and
shutdown. These native cases passed in run 39219581415 on 3c24e5e. Real frps registration and
tunnel traffic still require W4 deployment acceptance; these tests send callback
HTTP directly. The additional W5 suite exercises current source grants, role
isolation, expiry during an unchanged row-lock wait, and two actual official
clients through generated frps. Ping-based interruption and the remaining native
W5 acceptance are still pending.

The host-local Compose fixture measures a nonce-bound TCP peer independently of
its socket bind address. When Docker applies different source translations to
console ingress and local relay probes, the fixture records the console Open and
adds the measured local source through the same narrow web-role grant/audit
transaction. This compensation is confined to the isolated fixture. Each denial
requires an actual NewUserConn decision; public/native source preservation and
the complete console-to-router flow remain separate acceptance.
