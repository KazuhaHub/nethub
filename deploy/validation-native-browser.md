# Native browser enrollment

On 2026-10-23 UTC, a fresh OPNsense client completed the actual browser path:
console login, token generation, native enrollment, saved settings, tunnel
startup and a rendered **Recently online** inventory row. The API reported
online after 4.922 seconds; the console rendered that state after 5.968 seconds
from clicking Enroll. The token input cleared. Both pages reported no script
errors or requests outside their allowed origins. The native settings response
exposed only the activation flag; the removed debug endpoint returned 404.

The [sanitized receipt](validation-native-browser.json) binds the source,
unsigned package, browser runner and five screenshots. Screenshots and raw
operational evidence remain private. An earlier run reached API online in
3.244 seconds, but its final screenshot captured the loading state. It does
not establish rendered-online timing. A new genuine enrollment supplied the
complete screenshot sequence; the earlier profile was retained.

## Provenance and recovery

For each flow, independent PostgreSQL snapshots confirmed one new device, one
consumed UI-generated token and three appended audits: login, token creation
and enrollment. Earlier device, token and audit records remained unchanged.
The decoded token's SHA256 matched its database row. The native device ID and
subdomain matched the console and database.

The production NetHub Argon2id password verifier confirmed both archived native
device secrets against their independently captured database hashes and rejected
changed-secret controls. Go's independent key parser confirmed that each
archived private key matched the public DER saved in both the native key record
and PostgreSQL. Model and key files were exported with hashes before rollback.
These are actual PHP-saved model records, not reconstructed protocol assignment
responses. They remain available for subsequent genuine recovery tests.

Independent guards restored the original 0.0.6 appliance package, exact native
configuration and stopped tunnel intent. Subsequent SSH checks confirmed that
baseline. The original 14 relay containers and listener owners were verified;
the test stack stopped while its database, authorities and profiles were retained.

## Scope

The client started from its clean, unenrolled baseline. The isolated backend
retained earlier test history; this was not a new server initialization. Server
and image inputs were unchanged from the accepted image source through PR #131.
The test used the owner's approved 1 GiB appliance allocation.

The console's fixture CA and hostname were independently verified before browser
startup. Browser exceptions were limited to that verified console SPKI and the
pinned original native GUI SPKI. The appliance used its default trust store with
the temporary fixture CA. Neither public certificate trust nor GUI certificate
issuance, installation, renewal, rollback or reboot persistence is established
here. A later [fresh-backend run](validation-native-fresh-browser.md) covers the
clean initialization and browser flow; W4's other acceptance items remain open.

The original receipt used screenshot filenames as JSON keys. The scanner treated
the masked enrollment-token screenshot's digest as a credential. Current receipts
separate filename and SHA256 fields. The exact historical path/field/digest has
one bounded exception, with changed-value, field, path, adjacent and same-line
credential controls alongside the earlier checks. Default rules and full fetched
history scanning remain enabled.
