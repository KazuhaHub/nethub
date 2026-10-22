# Device protocol

The shared device protocol is version **1.5.0**, recorded in `VERSION`.
`v1/*.schema.json` are JSON Schema draft 2020-12 documents used by Go and Python
contract tests. Enrollment, signed claims and native OPNsense enrollment are
implemented. Authenticated status/removal and native appliance lifecycle behavior
have passed acceptance. GUI issuance and authenticated public-chain delivery are
implemented. Native installation/rollback and interrupted boot recovery have
private-CA appliance evidence; protocol 1.4 adds authenticated application reports.
Renewals, trust acknowledgements, credential rotation and the combined public/native
pipeline remain separate work.

## Messages

| Schema | Purpose |
|---|---|
| enroll-request | One-use enrollment token, agent/protocol versions, platform, capabilities, hostname and boolean cluster hint |
| enroll-response | Assigned device identity, device secret, signed claim, relay token/address/port, server name and public CA bundle |
| domain-claim | Strict five-field payload covered by the domain signature |
| status-request / status-response | Bounded health report and acknowledgement; online state comes from relay observation |
| rotate-request / rotate-response | Authenticated identity request and replacement credentials/trust; operational rotation is W7 work |
| unenroll-request / unenroll-response | Authenticated removal request and confirmed revocation |
| certificate-settings-request / certificate-settings-response | Live assigned GUI hostname, enrollment key fingerprint and original public CSR, when present |
| certificate-submit-request / certificate-submit-response | Enrollment-bound signed CSR admission and exact durable readback |
| certificate-issued-request / certificate-issued-response | Authenticated original-request pins and pending or issued public generation |
| certificate-applied-request / certificate-applied-response | Authenticated verified-generation report and immutable server receipt |
| relay-trust-settings-request / relay-trust-settings-response | Authenticated current public trust generation, or explicit pending null |
| relay-trust-applied-request / relay-trust-applied-response | Exact current trust identity report and original server acceptance receipt |

The public device endpoints are `/api/v1/devices/{enroll,status,rotate,unenroll}`
under the administrator-selected HTTPS console origin. Enrollment carries its
opaque one-use token in the JSON body. Other device endpoints use the device
secret as `Authorization: Bearer <device_secret>`, with the device ID in the body.
Never put credentials in query strings, redirects, command arguments or logs.
Authentication, one-use consumption, transaction scope and rate limits belong to
handlers; schema validity does not authenticate a request.

Protocol 1.2 adds optional authenticated POST endpoints
`/api/v1/devices/gui-certificate/{settings,request}`. They are exposed only when
authz is configured with its trusted `--device-domain` suffix; the console origin
must be outside that suffix. Both require a major-1 client with minor >= 2.
Existing major-1 enrollment, health and removal behavior remains compatible with
1.1 agents; existing response field sets are unchanged.

CSR transport uses canonical padded standard Base64 DER, limited to 4096 decoded
bytes. Settings returns the exact live assignment and either `request: null` or
the original request ID, DER, SHA256 fingerprint and microsecond UTC creation
time. Upload returns that original record on identical retries; changed signed
bytes conflict. A response is not an issuance grant or proof of GUI installation.
Schemas bound shape; runtime validation additionally checks canonical encoding,
CSR signature, single assigned DNS SAN and the enrollment-bound P-256 key.
The agent wire helper checks its expected device/subdomain/key fingerprint and
record hash. Cache restoration must still verify the CSR against the protected
local key; wire parsing alone does not authorize persistence or key creation.

Protocol 1.3 adds authenticated POST `/api/v1/devices/gui-certificate/issued` for
major-1 clients with minor >= 3. The request carries the device ID, original
request ID and CSR SHA256 fingerprint. A live device receives its same signed
request/assignment and either `issued: null` or an immutable public generation:
generation ID/number, canonical certificate PEM, leaf SHA256 and microsecond UTC
not-before/not-after/effective-validity/renewal times. A mismatch or revoked
assignment is denied. Settings reads and delivery polls never enqueue renewals.

Protocol 1.4 adds authenticated POST `/api/v1/devices/gui-certificate/applied`
for major-1 clients with minor >= 4. Its seven bounded fields are protocol/device
identity, original request ID/CSR fingerprint, generation ID/number and leaf
fingerprint. No PEM, private key, client timestamp or host/path override is sent.
The response echoes that identity with `accepted: true` and the original
microsecond UTC `accepted_at` server receipt.

The live credential and assignment remain locked through request/key/generation
checks, immutable report insertion and one audit. Only valid issued material for
the current tenant/device/key/host can be reported. A newer issuance alone does
not invalidate an older valid installed generation. After application of a newer
generation is confirmed, older reports are refused. Exact retries retain the
first receipt and audit; revocation, changed credentials/assignment and expiry
are rechecked even for retries. Reports grant no issuance authority or online
state. They are authenticated device reporting, not independent server proof of
what the GUI serves. Application roles have no raw report table/column access;
only authz has the narrow function, with forced RLS and immutable history.

The native coordinator reports only after its served CA/hostname/leaf/GET probe
and durable applied journal succeed. A lost response keeps that certificate and
retries against the same reverified generation, without reinstalling or issuing
another one. A protocol-1.3 console remains usable for local installation, but
status is `applied_unconfirmed` with an upgrade message and no unsupported POST.
A console minor upgrade alone does not reinstall unchanged material. Reporting
failures remain separate from tunnel health and do not roll back a valid GUI.

The chain is at most 32768 bytes, with at most five canonical public certificates;
the whole message remains limited to 65536 bytes. Leaf/key/exact-name/CSR and
metadata correlation are checked before emission. SQL delivery has a narrow
authz-only function, holding the same live assignment lock and filtering expired
generations; application roles receive no raw generation/lease/checkpoint access.
Public wire validation does not establish a trusted root or application success.
The recipient must independently verify its local key, CSR, exact hostname and
certificate chain using native trust before installation. No CA key, device key,
account/order URL or lease token is a delivery field.

The combined private fixture now uses compiled HTTP enrollment and CSR admission,
the host worker, genuine test CA/Caddy validation and authenticated chain download,
then checks refusal after removal. It seeds only initial admin/token authority.
Its internal HTTP bridge and logical client do not replace public HTTPS or native
appliance acceptance. The public sample leaf is a test wire example with an
ephemeral in-memory fixture signer; it is not a trusted root or deployment policy.

An enroll response includes `server_name` and `relay_ca_pem`. The agent must
verify console HTTPS before accepting them, validate certificates and the relay
identity before activation, and configure explicit frpc trustedCaFile/serverName.
The PEM shape permits one or two public CA certificates within 32 KiB for a
staged transition. This does not replace certificate validity, CA constraints or
handshake checks. D22 lifecycle details must be settled before enrollment ships.

## Compatibility and bounds

Use one SemVer for the whole protocol. Changes to this directory update the
version, affected consumers, examples, tests and compatibility statement together.
Required fields and their meaning remain stable within a major; minor additions
are optional. Both sides reject an incompatible major with a readable error.
The server checks compatibility before consuming any token. Current consumers
support major 1; malformed SemVer is invalid input.

Version 1.1 adds optional `gui_public_key` to enrollment and optional
`gui_key_fingerprint` to its response. The key is a canonical unpadded base64url
P-256 SubjectPublicKeyInfo (91 DER bytes / 122 characters); its acknowledgement is
the lowercase SHA256 hex digest of those DER bytes. JSON Schema checks shape;
both request consumers also validate the encoding and public point. The initial
one-use enrollment transaction stores this binding permanently. No update or
bearer-only backfill endpoint exists; legacy devices remain unbound until
re-enrollment. A later exact-assignment signed CSR must match the stored key.

Unbound 1.0 requests remain valid and omit both optional values. A caller that
supplies a key must require its exact fingerprint acknowledgement: a 1.0 server
may ignore the extension and consume the token, but it cannot confirm a binding.
Upgrade that server before issuing another one-use token; do not silently accept
the downgraded enrollment. The OPNsense request/network helpers support this
optional binding and validation, but the native enrollment UI does not generate
or supply a key yet. No GUI certificate capability is advertised or installed by
this protocol change. Future platform adapters use the same public-key contract.

Requests and responses are UTF-8 JSON objects limited to 64 KiB before parsing.
Known fields have explicit length/type/range limits. Each ordinary message permits
at most sixteen extra properties; consumers ignore bounded optional extensions
and never persist them as settings. Duplicate keys, including escaped duplicates,
are invalid. The Go enrollment parser additionally limits nesting to sixteen,
arrays to 256 elements and each object to 64 properties. All required fields
must be present with their declared types; missing and null are not interchangeable.

Claims are stricter: exactly `device_id`, `subdomain`, `tenant_id`, `issued_at`,
`key_id`, in that order for canonical JSON signing. No optional or duplicate fields
are accepted. `issued_at` is UTC RFC3339 with exactly six fractional digits,
matching PostgreSQL microsecond precision. Rotation must lock the device and
advance this timestamp monotonically, including multiple rotations in one second.
Signing/verification must enforce canonical encoding independently of the schema.

Enrollment and device secrets are 32 random bytes in canonical unpadded base64url
(43 characters). The deployment frp token is 32 random bytes in lowercase hex
(64 characters). UUIDs use lowercase canonical text. Schema constraints describe
shape; they do not prove randomness, signature validity or token freshness.

## Platform boundary

`platform` is a lowercase ASCII identifier matching `^[a-z][a-z0-9-]{0,31}$`.
Capabilities are unique dotted names with explicit size/count bounds. The OPNsense
request builder declares `opnsense` and `remote.web`. Other platform identifiers
can use the same contract without adding platform-specific fields to these
schemas. Only OPNsense currently has an implemented/tested platform adapter.

Migration 00003 replaces the original OPNsense-only database constraint without
rewriting old migrations or changing runtime grants/RLS. An accepted identifier
is not evidence of a supported agent or implemented capability. Installation,
configuration persistence and service control remain each agent's responsibility.

## Tests and examples

`examples/manifest.json` identifies valid and invalid examples for both suites.
All fixture credentials and claim signatures are public test values, not usable
credentials or cryptographic proofs. The public fixture CA has no retained
private key. Never use these values as deployment defaults.

From `server/`, run `GOWORK=off go test -count=1 ./internal/protocol`. From the repository
root, with pytest 8.3.5 and jsonschema 4.25.1 installed in a development environment,
run `python3 -m pytest -q agents/opnsense/tests`. Python jsonschema is a host/CI
dependency; the appliance request builder uses only the standard library.
Both suites resolve shared resources locally and validate the same manifest.
Use `-count=1`: Go's test cache must not hide changes to schemas outside its module.
CI also runs actual-role PostgreSQL migration/identifier checks separately.

These are the first published schema definitions; there is no deployed stable
protocol agent to migrate. Existing W2 debug settings are not a protocol client.
Future handlers must validate their actual outputs against these schemas, rather
than treating fixture round-trips as endpoint evidence.

The historical [frp 0.71.0 hook observations](frp-hooks-0.71.0.md) are W0 evidence,
not NetHub message schemas. Stock frp remains pinned to 0.71.1 across components.
