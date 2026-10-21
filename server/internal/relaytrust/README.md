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
