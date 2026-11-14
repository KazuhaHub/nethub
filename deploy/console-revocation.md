# Console revocation

Each active inventory row has a Revoke action. Its native confirmation dialog
explains that revocation permanently retires the enrollment: restoring access
requires enrolling again. Dismissing the dialog makes no mutation. On failure,
the dialog retains the error and permits an explicit retry; successful revocation
immediately disables Open and removes any saved continuation link.

`POST /api/v1/console/devices/{canonical-uuid}/revoke` accepts only an empty JSON
object. It uses the existing session, origin, CSRF, trusted-proxy source resolver
and a separate per-actor/source attempt budget. The tenant is selected at startup,
never by the browser. Enabled owners and tenant administrators may revoke a
device; foreign and missing devices return the same unavailable response.

The transaction locks the enabled actor before the device, then sets the one-way
revocation flag and first timestamp/actor and appends a normalized-source audit.
Concurrent retries preserve the first timestamp and produce one revocation audit.
An audit failure rolls back the device update. A committed actor demotion wins over
a request waiting for the actor lock. Existing Open grants cannot bypass revocation.

Login, NewProxy and NewUserConn refuse the revoked identity through current SQL.
Once a successful cache refresh observes the revocation, Ping refuses it. Refresh
is scheduled every second. Heartbeat
disconnection can take time, and established browser streams are not promised to
close immediately. A snapshot older than 2.5 seconds cannot admit Ping, even if a
database outage prevents publication. The one/three-second heartbeat candidate
still needs end-to-end five-second acceptance; see [the availability limits](revocation-and-heartbeats.md).

The [disconnect request](disconnect-requests.md) and
[anomaly confirmation](relay-anomalies.md) have separate implementations and
fixture evidence. The [installed Revoke measurement](validation-native-w5-heartbeat.md)
records actual cutoff and recovery scope, including the unresolved W0 timing
comparison. Combined public/mobile W5 acceptance remains open; browser and
SQL fixtures establish only their tested UI and authorization scope.
