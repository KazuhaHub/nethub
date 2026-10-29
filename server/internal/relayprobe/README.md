# Relay admission probes

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


## Host token Login verification

`LoginToken` uses the same bounded loopback TLS/Yamux exchange with a valid
existing-device claim and a private shared token. It creates a fresh unique user,
leaves run/client IDs empty, requests no proxy and closes the new control after
one Login response. Only a pinned-version successful run ID or the exact token
authentication rejection produces a closed result; policy, plugin, transport,
unknown-version and malformed responses remain errors. Credential JSON/formatting
is redacted and raw server data never leaves the helper.

The legacy wire digest and reply shape follow the pinned upstream
[token authentication](https://github.com/fatedier/frp/blob/v0.71.1/pkg/auth/token.go),
[wire messages](https://github.com/fatedier/frp/blob/v0.71.1/pkg/msg/msg.go) and
[control admission](https://github.com/fatedier/frp/blob/v0.71.1/server/service.go).
The existing doctor's credential-free invalid-claim behavior remains separate.

TLS/mux unit fixtures check success/refusal separation, fresh identities, no raw
token or extra messages, strict replies, redaction, hostname verification and
cancellation. The owned Compose relay harness now requires a compiled valid/wrong/
valid token Login test against official frps/authz, then checks both original
official-client controls and verified HTTPS routes. That actual test still needs
execution. No production token-incident caller exists yet; this does not accept
shared-token replacement, service recovery or fleet recovery.
