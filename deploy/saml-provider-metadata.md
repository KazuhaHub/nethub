# SAML provider metadata preparation

`sso.ParseSAMLMetadata` validates an administrator-supplied XML document and
selects the explicitly configured IdP entity ID. It accepts an individual entity
or a bounded aggregate; it never chooses the first member implicitly. Entity IDs
are identifiers and may be URNs rather than HTTPS addresses.

Documents are limited to 1 MiB, 64 XML levels and 128 entities. DTDs, external
processing instructions, duplicate attributes, multiple roots, conflicting
namespaces and duplicate selected entities are refused. The existing shared XML
round-trip validator runs before the crewjam metadata decoder.

The selected entity must advertise one SAML 2.0 IdP role, an HTTPS Redirect
endpoint and a pinned RSA-2048-or-stronger or ECDSA-256-or-stronger signing
certificate. Reserved SAML binding query parameters are refused; ordinary
endpoint query parameters are retained. The earliest aggregate, entity or role
validity deadline is preserved for runtime admission. Certificate validity dates
do not reject the entire document during import: metadata can contain rollover
keys. Assertion validation remains the responsibility of authcore and its
underlying verifier.

This parser neither downloads metadata nor verifies a metadata signature.
Administrators must obtain the document through a trusted channel. It does not
establish ownership of an IdP or allow an untrusted metadata URL to install keys.
Runtime provider management must enforce the saved metadata deadline and the
deployment's endpoint/DNS policy before starting a browser login.

The direct authcore dependency is pinned to verified upstream PR #34 merge
`ee68d852d973`. Both its PR and matching-tree main runs passed full Linux/race,
supported compiler, vulnerability and API checks. Shared AuthnRequest signing
handles RSA/ECDSA, the trusted IdP signing requirement and exact Redirect binding
octets. NetHub does not implement assertion signature verification itself.

Local SSO tests and vet cover the parser and existing protocol adapters. Provider
CRUD, signing-key storage, browser-bound requests, ACS and invitation/session
transactions, pages and signed deployed SAML acceptance remain unfinished. These
preparation components are not complete W6 acceptance.
