# Relay certificate material

This package prepares an isolated deployment CA and issues server-authentication
leaves for one protected DNS identity. Renewal preserves the authority and rotates
the leaf key. A critical DNS constraint limits the authority to the configured
relay name and its subtree; each leaf has exactly the configured name. Runtime
validation needs the public root, leaf and leaf key, never the signing key.

The current engineering defaults are a ten-year authority and one-year leaf,
clamped to the authority's expiry. They do not establish configurable lifetime
policy or approve the superseded manual-renewal workflow. Inputs must contain
single canonical PEM blocks; mismatched keys, identities, chains and validity
intervals fail with a fixed error. Material has no JSON representation.

Tests include a verified local TLS handshake, key rotation under the same root,
the authority's expiry boundary and invalid key/hostname/PEM/time inputs.

No files, jobs or services are changed by this package. Protected persistence,
backup acknowledgement, scheduled renewal, durable apply/retry/rollback, fresh
relay handshake verification and trust-generation acknowledgements remain
deployment work. This is not router GUI ACME issuance or installation. Those are
also required in v1 by [the certificate design](../../../docs/certificate-automation.md).
Console HTTPS remains owned by the selected reverse proxy.
