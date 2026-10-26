# SAML provider administration

PR #179 was accepted at final main-based source `cb7c2dfc0775` and merged as
`2820debc6b4d`. Run `40394350562` passed all six jobs. Actual SQL and inherited
deployment/two-Dex logs, three DCOs and both final regression images/hashes passed
review. The earlier fixture compilation failure remains retained. This is
provider backend acceptance, not complete SAML login or W6 acceptance.

Administrators can list, create, update and delete SAML providers through
`/api/v1/console/saml-providers`. Mutations require the normal console Origin,
session and CSRF token. The repository independently checks the current active
administrator before metadata validation and again inside the final transaction.

Creation accepts `slug`, `display_name`, `entity_id`, `metadata_xml`,
`email_attribute` and optional `enabled` (default false). The entity ID selects
the trusted IdP from the supplied metadata; `email_attribute` is an exact SAML
Attribute Name. Metadata is supplied explicitly, never fetched from an arbitrary
URL. The selected document must be unexpired, and its Redirect endpoints must
pass the deployment's existing SSO HTTPS/DNS policy.

XML is limited to 1 MiB after JSON decoding. Only these administrator operations
allow the larger wire body needed for JSON escaping; other APIs keep their
64-KiB limit. Unknown, repeated, null and mistyped fields are refused. PATCH
accepts the mutable creation fields except `slug`; omitted fields are retained.
Disabling or renaming works without remote validation. Enabling or replacing
the identity/metadata validates again. Concurrent changes return a conflict
instead of overwriting newer state. A bound IdP entity ID cannot be changed.

Each provider receives an independent RSA-3072 SP signing key and self-signed
certificate with a two-year initial validity. This is a SAML key certificate,
not the reverse proxy's HTTPS certificate. The bounded private PEM bundle is
sealed under the deployment key using the tenant/provider/SAML-purpose binding.
Ordinary metadata edits preserve the exact encrypted signing identity. Neither
the list nor mutation API returns private keys or echoes the supplied IdP XML.
Explicit SP signing-key/certificate rotation remains further lifecycle work;
these operations do not silently rotate an IdP's registered trust.

Public SP metadata is available at
`/api/v1/console/saml/{slug}/metadata`, including while disabled for initial IdP
registration. It advertises the matching SP entity, POST callback, persistent
NameID and signed AuthnRequests through authcore. Reading metadata never creates
login state or changes a key. A deleted provider is no longer published.

Deletion refuses providers with bound identities. Otherwise it cancels unused
restricted invitations, removes the encrypted SP private material and tombstones
the disabled provider in the same audit transaction. The callback slug and
invitation provider restrictions remain reserved. An audit failure rolls back
the entire mutation.

Local tests cover HTTP permissions/CSRF/schema/body boundaries, private bundle
refusal and an independently verified actual authcore RSA request signature.
The added PostgreSQL cases require the genuine database suite; a local unit run
does not establish those boundaries. Full browser-bound SAML login, ACS and
invitation/session admission, management pages, signed deployed IdP acceptance
and complete W6 acceptance remain unfinished.
