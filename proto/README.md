# Device protocol

The shared device protocol is version **1.0.0**, recorded in `VERSION`.
`v1/*.schema.json` are JSON Schema draft 2020-12 documents used by Go and Python
contract tests. Schemas and bounded request construction/parsing exist; device
HTTP handlers, claim signing and appliance enrollment UI remain W4 work.

## Messages

| Schema | Purpose |
|---|---|
| enroll-request | One-use enrollment token, agent/protocol versions, platform, capabilities, hostname and boolean cluster hint |
| enroll-response | Assigned device identity, device secret, signed claim, relay token/address/port, server name and public CA bundle |
| domain-claim | Strict five-field payload covered by the domain signature |
| status-request / status-response | Bounded health report and acknowledgement; online state comes from relay observation |
| rotate-request / rotate-response | Authenticated identity request and replacement credentials/trust; operational rotation is W7 work |
| unenroll-request / unenroll-response | Authenticated removal request and confirmed revocation |

The public device endpoints are `/api/v1/devices/{enroll,status,rotate,unenroll}`
under the administrator-selected HTTPS console origin. Enrollment carries its
opaque one-use token in the JSON body. Other device endpoints use the device
secret as `Authorization: Bearer <device_secret>`, with the device ID in the body.
Never put credentials in query strings, redirects, command arguments or logs.
Authentication, one-use consumption, transaction scope and rate limits belong to
handlers; schema validity does not authenticate a request.

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
