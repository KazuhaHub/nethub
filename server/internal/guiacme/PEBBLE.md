# Genuine ACME order interoperability

The isolated deployment harness runs `TestPebbleOrderAdmission` against the
official [Pebble 2.10.1 release](https://github.com/letsencrypt/pebble/tree/v2.10.1).
Its Linux/amd64 image is pinned to
`sha256:5080492187bea12909c053d7a2b90a9e95104ef1c82381828e7823db71ce7e54`.
The loaded revision matched release commit
`b1e1ca4f3c30abb64111adaca4544bc5374cc306`. The registry's version label is the
major version `2`; it is not used as the patch-version identity.

The test creates a nonoverlapping internal bridge, publishes no host ports and
verifies container/image/network identity and read-only root storage. Only three
fixture files are mounted read-only: private API TLS leaf, public certificate and
test configuration. The ephemeral API trust authority stays in the driver; its
private key is not mounted. No operator bundle, signing key, account store or
system trust store is exposed to the container. Management endpoints are disabled.
Root execution is confined to this capability-free test container; it is not a
production deployment setting.

Real SDK requests to Pebble passed explicit current-terms consent, persistent
account registration, a bound single-name pending order, an advertised default
profile and three observations of the same order. Pebble's own log confirmed one
order; account state stayed unchanged. No challenge was accepted and no device
certificate was issued. This proves order interoperability, not HTTP-01 validation,
issuance, delivery, native installation, renewal or complete W4 acceptance.

The native rehearsal passed in 2.44 seconds. Its independent exact-resource guard
verified container/network removal and deletion of the complete temporary-key
namespace before cancellation. Original public services remained running. Earlier
failed rehearsals were retained: a boolean CLI argument needed `-strict=false`,
and the client initially rejected Pebble's inline plain-text terms reference.

Terms remain comparison-only metadata, never fetched/executed/rendered as HTML.
In addition to canonical HTTPS references, the client now accepts bounded canonical
`data:text/plain,` references with printable ASCII text and no markup/control
characters. HTML, base64, scripts, files, HTTP, malformed/ambiguous encoding and
oversized values fail closed. Creating an account still requires exact current
explicit consent. All actual network endpoints remain approved HTTPS origins.
This follows the directory metadata distinction in
[RFC 8555 section 7.1.1](https://www.rfc-editor.org/rfc/rfc8555#section-7.1.1)
and the [data URL format](https://www.rfc-editor.org/rfc/rfc2397).

Pebble is a test-only MPL-2.0 dependency; it is not copied into the product or
shipped in a runtime image. Its process loses CA state on restart and its roots
must never be installed for ordinary browsing or production use. Current-head
CI and the genuine deployment run remain merge gates.

The later HTTP-01 fixture extends this harness with the exact deployment Caddy
image and the production isolated publisher. It proves a real CA-source fetch,
the same order reaching ready, valid-authorization recovery and response retirement.
See [HTTP-01 evidence and limits](HTTP01.md). It does not finalize a certificate.

A separate opt-in issuance fixture completes finalization and verifies the exact
chain under independently configured test roots, then reopens the account and
recovers the same issued material without another CSR submission. See
[finalization evidence and remaining work](FINALIZATION.md). Only this fixture
enables private management access for the public root; ordinary order/validation
fixtures keep it disabled.
