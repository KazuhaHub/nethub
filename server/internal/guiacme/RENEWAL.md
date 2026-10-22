# Genuine GUI renewal fixture

`TestPebbleProtectedHostIssuerRenewal` exercises the compiled host command and
device HTTP API with real PostgreSQL, Pebble and Caddy. It starts with authenticated
device enrollment and the original client-held key/CSR. Only initial tenant,
administrator and enrollment-token authority is seeded.

The host issues generation one, and the logical client validates its chain
against independent fixture roots before reporting that generation. The first
successful report response body is discarded; its retry must recover the exact
database acceptance timestamp. This models an unused response, not an interrupted
TCP connection or a native appliance serving that certificate.

To exercise renewal immediately, the labelled disposable database administratively
ages only generation one's issuance/schedule metadata. Its genuine chain, key and
expiry are unchanged. The immutable trigger is restored in that same transaction;
no host or CA clock changes. The protected host then admits and issues generation
two using the same request/key. Independent validation must accept a distinct
leaf, and authenticated polling must return that exact new generation.

Both reports retain one receipt/audit despite retries. After generation two is
confirmed, an older report is denied. The final counts must be one request, two
jobs, two issued generations, two application receipts/audits and one renewal
admission audit. An idle issuer retry cannot create another order. Client removal
denies subsequent delivery and reporting. The CA log independently requires
exactly two original orders and two finalize POSTs. Existing single-order recovery
fixtures retain their separate exactly-one assertions.

Deployment CI selects both protected host tests under the independent guard.
Its receipt requires each exact test to pass, the single-order and two-order
CA proofs, and authenticated delivery/reporting evidence. Missing, skipped or
partial logs fail acceptance; the receipt exposes `renewal_verified` explicitly.

The independent outer guard owns the nonce-bound containers, networks, volume,
units and temporary keys. Cleanup and original-service/authority checks are
required even after a failing test. A periodic cleanup namespace-lock skip is
retried explicitly within 15 seconds; it is never treated as an issuance result.
The stopped-timer gate stops its fixture service too before expecting refusal.

This private-CA logical-client evidence does not establish browser/public trust,
native OPNsense installation, an on-device served-leaf probe, actual transport
response loss, a production renewal latency or public-account terms consent.
