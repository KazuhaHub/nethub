# Relay rejection probe

The doctor sends one deliberately invalid Login through the loopback relay TLS
listener and the pinned Yamux transport. It submits no frp token, device secret,
signed claim, run ID or proxy. The random UUID is not enrolled. A verified TLS
connection alone is insufficient: only a bounded LoginResp with an empty run ID,
a canonical version and the exact `not_authorized` rejection passes. Unavailable
plugins, successful admission, token failures, malformed/duplicate/unknown fields
and oversized responses fail. Dependencies and response text are never exposed.

The framing follows the pinned frp 0.71.1 Login protocol. Its server invokes the
Login plugin before control admission. NetHub's invalid-claim path rejects before
database authorization; transport/plugin failures have distinct responses. The
source version check prevents the doctor protocol pin from silently diverging
from relay/appliance pins. The probe has a five-second total budget, one stream,
bounded messages, no keepalive and no automatic retry.

The unmodified `github.com/fatedier/yamux v0.2.0` dependency matches frp 0.71.1.
The runtime image includes its upstream license and module version alongside
the existing dependency notices. Upstream source is available at
<https://github.com/fatedier/yamux/tree/v0.2.0>.

Synthetic TLS/mux tests validate protocol and refusal behavior. Genuine deployed
frps/authz and the compiled doctor must separately pass the existing service
acceptance suite, including an unavailable-hook check and unchanged
device/grant/audit counts. This does not prove successful agent admission,
external-network reachability or agreement with a formally published appliance
package. The CLI compares the reported running version with this binary's pin.
