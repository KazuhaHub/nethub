# Public relay trust bundles

`Parse` validates one or two distinct currently valid, self-issued and self-signed
CA certificates. It rejects unrelated PEM data, headers, nested/malformed blocks,
unknown critical extensions, invalid signing usage and oversized bundles. This
package contains no signing key or issuer operation.

Root identities are lowercase SHA256 hashes of their DER certificates. Sort
those identities lexically, emit each corresponding certificate using ordinary
LF-terminated PEM, and hash the exact UTF-8 bytes of
`nethub-relay-trust-v1:` followed by that canonical PEM. This defines the public
bundle fingerprint. Reordering certificates or changing input PEM whitespace
does not create another identity. Adding, removing or changing a certificate does.

The effective validity window is the latest root `NotBefore` through the earliest
root `NotAfter`, with an exclusive expiry. Public certificate copies and root-ID
slices are independent of the validated snapshot. Ordinary JSON serialization
does not expose bundle fields; distribution needs an explicit wire value.

Enrollment now uses this shared validator. In particular it refuses duplicate
roots that the existing agent would reject. Tests exercise actual verified TLS
against old and new relay leaves: old trust accepts only old, overlapping trust
accepts both, and final new trust rejects old. Overlap does not bypass hostname
authentication. These are local Go TLS tests, not frp/device deployment evidence.

A fingerprint is content identity, not a monotonic version, assignment authority
or application receipt. Durable publication, authenticated device delivery and
applied acknowledgements must use separate records and current-credential checks.
Planned removal of old trust must wait for nonrevoked devices to acknowledge, or
for an explicit offline quarantine/recovery decision. This validator alone does
not permit changing the active relay issuer or establish those transition gates.

## Durable publication and application history

Migration 00014 stores immutable public generations, a singleton current pointer
and tenant/device application receipts. Global public rows have forced RLS and no
application/issuer raw table or column grants. Only narrow owner-defined functions
are executable by the no-login host issuer or authenticated device repository.
They contain no signing key and do not change the relay's active issuer.

`Publisher` validates the bundle before a bounded stdin-only SQL call using the
existing protected local administrator adapter and explicit issuer identity.
Publication locks the current pointer, compares the expected generation and
returns the same current row after an exact lost-reply retry. A shared root and
unchanged server name are required for subsequent planned generations. Removing
an old root requires every nonrevoked device to have acknowledged the preceding
current generation. Offline devices block that operation; there is no automatic
quarantine or emergency-root-replacement bypass in this component.

The pointer lock precedes device locks. A device insertion trigger also shares
that lock, so publication cannot silently miss an uncommitted enrollment. Reports
accept only the current generation's exact ID, number and content fingerprint.
`RelayTrustStore` holds both locks and rechecks the authenticated current secret
hash and tenant through commit. A revoked, stale, cross-tenant or changed-secret
report is refused. A repeated current report preserves its original timestamp
and one audit. Receipt insertion and audit commit atomically; existing history
cannot be updated or deleted.

`DecodeGeneration` independently reparses public material from SQL and compares
the configured relay name, canonical PEM/root identities, fingerprint and actual
validity window. An SQL row or response alone cannot bypass X.509 validation.
SQL encoding/identity checks do not replace the host's signature validation.

This component is not wired into an HTTP route, startup publication, enrollment
delivery or the native adapter yet. Repository tests simulate authenticated
application reports; they do not establish an appliance applied trust. The
all-reported retirement test advances database public metadata, not relay
certificates or the protected deployment authority. Public delivery/protocol,
applied-file verification, offline quarantine/recovery and authority-switch
integration still require separate implementation and acceptance.
