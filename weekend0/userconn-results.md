# W0 experiment ⑤: NewUserConn behavior

The HTTPS-vhost hook can reject new user connections without interrupting the
registered stock-client tunnel. This establishes a technical attachment point
for Q7 gating; D7 remains an owner decision.

The owner used mobile data, logged in, and reported normal Dashboard behavior.
An independent HTTP listener recorded the mobile IPv4 peer; it differed from the
desktop self-test peer and matched the IP in the mobile NewUserConn remote_addr.
Hook proxy_type was https. Proxy name, device metadata, and server-assigned run ID
matched NewProxy registration. Addresses and raw payloads remain outside Git.

With only NewUserConn changed to deny, the owner reported that the existing
Dashboard tab A remained usable while a fresh private window B could not open the
same entry. The observation was collected about 112 seconds after the mode change;
the time until A eventually stopped working was not observed. Desktop fresh
connection checks also failed. Login and NewProxy each remained at one request,
all observed heartbeats stayed allow, and the admin API showed the proxy online.

An additional desktop check changed only NewUserConn to HTTP 500. Fresh public
connections failed while the registered proxy stayed online. Restoring allow
returned the public login form without client re-registration. The probe was not
restarted during mode changes. NewUserConn hang was not tested in this experiment.

The mobile login and Dashboard baseline produced seven NewUserConn requests after
the desktop readiness snapshot. The login-page and authenticated stages were not
counted separately, so this is a combined observation rather than a per-stage
cost estimate. Browser connection reuse and later requests affect these counts.

Existing connections can outlive a NewUserConn authorization change; this hook
alone does not provide immediate revocation. Backend errors prevent new GUI
connections when gating is enabled. Both behaviors remain design considerations
for D7 and the revocation tests in experiment ⑥.

The NAT guest used native Hyper-V, two vCPUs, and the owner-approved 1 GiB resource
exception. Cleanup stopped the owned client and relay test processes. Original
relay services and listeners were independently verified restored, test listeners
closed, and the restoration timer cancelled. Full W0 acceptance remains pending.
