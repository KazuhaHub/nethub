# Device protocol walkthrough

This guide describes the current major-1 device contract. The protocol version is
[`proto/VERSION`](../proto/VERSION), currently `1.6.0`; the authoritative wire
shapes are the [schemas](../proto/v1/) and shared
[example manifest](../proto/examples/manifest.json). Protocol compatibility does
not establish a supported platform, native installation or a stable release.

Console OIDC/SAML sessions are a separate protocol. A router authenticates with
its own device secret, not a console cookie or an identity-provider assertion.

## Transport and parsing

Agents call the administrator-selected HTTPS console origin. The public proxy
routes `/api/v1/devices/` to authz. Verify console TLS and the exact hostname
before sending a token or accepting credentials. Do not follow an arbitrary
redirect with a device bearer. The server accepts its configured console host;
device endpoints use POST with JSON bodies, not URL parameters.

Messages are UTF-8 JSON objects bounded to 64 KiB. Required fields have explicit
types; null does not mean absent. Duplicate keys, including escaped duplicates,
are invalid. Optional extensions are bounded and ignored rather than persisted
as device configuration. Schema validity alone does not authenticate a message,
verify a signature or authorize a side effect. Runtime checks and transactional
admission are required as well.

`agent_protocol_version` uses SemVer for the complete device protocol. Both sides
reject malformed versions and incompatible majors. Enrollment compatibility is
checked before consuming its one-use token. Minor extensions keep existing
required fields and meanings; use an endpoint only when its minimum minor is
supported. Do not treat an old peer ignoring a field as acknowledging it.

## Enrollment and the tunnel

1. An administrator issues a one-use enrollment token. The agent sends it in the
   enrollment JSON body with its version, platform, bounded capabilities,
   hostname and cluster hint. Never put it in a URL, command argument or log.
2. Authz consumes the token in the device-creation transaction and returns the
   assigned identity, device secret, subdomain, signed domain claim, relay token,
   relay address/port, TLS server name and public relay CA bundle. The token
   cannot be used to create another device.
3. Before persisting or activating the response, validate its complete shape,
   assignment and TLS trust material. Configure frpc with an explicit
   `trustedCaFile` and `serverName`. The relay address can differ from the TLS
   identity; a successful TCP connection does not verify that identity.
4. The agent starts the platform's managed frpc service. Signed claims authorize
   one assigned route. The relay forwards GUI TLS without decrypting it; the
   router still requires its own login. Console Open adds a separate source-IP
   grant and does not replace router authentication.

Enrollment and device secrets are 32 random bytes in canonical unpadded
base64url, represented by 43 characters. The deployment frp token is 32 random
bytes represented by 64 lowercase hexadecimal characters. Public examples are
fixtures and must never become deployment defaults.

The domain claim has exactly five fields in canonical order: `device_id`,
`subdomain`, `tenant_id`, `issued_at`, `key_id`. Its timestamp is UTC RFC3339 with
six fractional digits. Verification checks canonical bytes and the signature;
parsing the claim as a valid JSON object is insufficient.

## Health, removal and rotation

After enrollment, authenticated requests carry
`Authorization: Bearer <device_secret>` and the device ID in the JSON body.
Status reporting does not make a device online: the console uses recent relay
observations. Removal revokes the device; reporting success or retaining an old
local configuration does not restore its authority.

The lifecycle router implements `/api/v1/devices/{status,unenroll,rotate}`.
Protocol 1.6 rotation binds one privately journaled candidate to one operation;
its transaction advances the credential hash and claim timestamp with an immutable
operation/audit. A response-loss retry authenticates the committed candidate and
recovers that assignment. Genuine SQL/publication-fence and official Linux frpc
checks have passed; they do not establish installed-device acceptance. The native journal/model workflow, command and UI are under combined
validation; this is not yet accepted operational device rotation. See the
[rotation contract and limits](../proto/ROTATION.md).

<a id="gui-certificate-lifecycle"></a>

## Protocol extensions and GUI certificates

The extensions add separate checks; none grants general remote configuration
authority over the router.

| Minimum minor | Extension                                                                                              |
| ------------- | ------------------------------------------------------------------------------------------------------ |
| 1.1           | Enrollment can bind one P-256 GUI public key and require the exact server fingerprint acknowledgement. |
| 1.2           | Authenticated GUI certificate settings and signed CSR admission.                                       |
| 1.3           | Authenticated delivery of a pending or issued public certificate generation.                           |
| 1.4           | Authenticated report of a verified, durably applied GUI generation.                                    |
| 1.5           | Authenticated current relay trust delivery and application receipt.                                    |
| 1.6           | Operation-bound credential rotation with an exact retained relay-trust digest and recoverable candidate. |

The optional enrollment key is canonical unpadded base64url P-256 SubjectPublicKeyInfo.
Its acknowledgement is the SHA256 of its DER bytes. A supplied key must receive
that exact acknowledgement; do not silently downgrade to an unbound enrollment.
There is no bearer-only key backfill. The private GUI key remains on the device.

The certificate endpoints are
`/api/v1/devices/gui-certificate/{settings,request,issued,applied}`. They require
the live device credential and the applicable protocol minor. Settings supplies
the assigned GUI hostname and either no request or the original request record.
CSR admission checks canonical Base64 DER, signature, the single assigned DNS
SAN and the enrollment-bound key. Identical retries return the original record;
changed signed bytes conflict. Admission is not proof of issuance or installation.

Issued delivery is pinned to the original request and CSR fingerprint. It returns
pending or an immutable public generation, including bounded certificate PEM,
fingerprints and server timestamps. A recipient independently verifies its local
key, request, exact hostname, public chain and validity before installation.
Polling does not enqueue renewals. The public wire contains no device/CA private
key, ACME account/order URL or lease token.

The applied report names the exact request, CSR and generation. It contains no
PEM, client timestamp or path override. Send it only after native verification and
durable application. An exact retry retains the original acceptance time and
audit, while live revocation, assignment and validity are rechecked. A lost report
reply does not authorize reinstalling or rolling back a valid GUI certificate.
The receipt proves authenticated device reporting, not what a later external
browser actually reached.

## Relay trust lifecycle

Protocol 1.5 adds `/api/v1/devices/relay-trust/{settings,applied}`. Settings returns
the current public trust generation or explicit pending null. A generation binds
its monotonic number/ID, server name, canonical CA bundle, bundle fingerprint and
server validity/publication times. An overlap bundle can contain two public CAs;
the agent must validate content and identity rather than trusting the count.

The application report carries the exact generation and bundle fingerprint. A
receipt is not permission to accept an older generation, change server identity
or remove an offline device's recovery path. Server publication, overlap,
retirement barriers and authority migration are separate protected operations;
see [authority operations](../deploy/relay-authority-operations.md).

## Adding another router platform

The protocol accepts bounded lowercase platform identifiers and dotted capability
names. Only OPNsense currently has an implemented and tested adapter. Accepting a
new identifier on the server does not install an agent or prove a capability.

A new adapter must supply protected local storage, native configuration/service
integration, a local stop mechanism, validation before activation, last-good
recovery and durable state. Implement the same enrollment, status/removal,
certificate and trust contracts without adding platform-specific settings to
shared wire messages. Advertise only capabilities the adapter implements.

Future platform work must validate the public contracts and run real platform
lifecycle/TLS tests. The existing OPNsense model/configd/cron implementation is
one adapter, not a requirement to reproduce OPNsense APIs on every system.

## Evidence and remaining work

The shared [protocol tests](../proto/README.md#tests-and-examples), actual-role
PostgreSQL/HTTP tests and [native public-certificate record](../deploy/validation-native-public-certificate.md)
cover different boundaries. Keep those scopes separate. Public/network samples,
signed packaging, restore and operational rotation remain independent gates.
This walkthrough does not complete W7 or replace the schemas and runtime checks.
