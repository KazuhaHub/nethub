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

Renewal assessment derives its lead from actual certificate dates (at most 30
days and one third of the lifetime), reports expired leaves and authority expiry,
and identifies leaves whose expiry cannot be extended under the current root.
Historical identity/key/chain validation allows an expired leaf to be assessed
for recovery; it does not enable current TLS trust or expired rollback material.
A fresh bounded TLS observer verifies hostname/chain and returns the served DER
fingerprint for comparison with the intended generation. File hashes or process
running state alone do not establish that application succeeded.

No files, jobs or services are changed by this package. The
[host maintenance engine](../relaymaint/README.md) implements protected generation
persistence and durable apply/retry/rollback; deployment acceptance of that new
command is pending. Authenticated trust-generation acknowledgements remain
separate work. This is not router GUI ACME issuance or installation. Those are
also required in v1 by [the certificate design](../../../docs/certificate-automation.md).
Console HTTPS remains owned by the selected reverse proxy.
