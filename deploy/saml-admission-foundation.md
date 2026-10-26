# SAML admission foundation

SAML is part of v1. These components prepare account admission and persistent
replay protection; they do not expose a working SAML sign-in endpoint yet.
Provider configuration, trusted metadata management, browser-bound requests,
ACS handling, invitation/session transactions, console pages and signed IdP
deployment acceptance remain required W6 work.

PR #177 was accepted at final main-based source `3b92f89854ad` and merged as
`fe20f71eb947`. Run `40340926136` passed all six required jobs. Actual logs
confirmed the genuine SQL cases below, together with inherited deployment and
two-Dex gates. Two DCOs and both final hosted screenshots/hashes were reviewed;
the merge tree equals the tested tree. This remains foundation acceptance rather
than a working SAML login endpoint.

NetHub imports authcore at the verified upstream merge `48a74a506790`.
Upstream PR #33 preserves signed NameID qualifiers and passed the full Linux
suite on both supported compiler versions, race checks, vulnerability scanning
and API compatibility. NetHub continues to delegate SAML protocol validation to
authcore. No XML parser or signature verifier is copied into the application.

`SAMLIdentityPolicy` consumes only an already validated assertion. The initial
policy requests and requires a persistent NameID; transient, mailbox and unspecified formats
do not establish a stable account key. Nonempty IdP and SP qualifiers must match
the configured entity IDs. An omitted qualifier has the same effective scope as
its explicit expected value. The subject hashes a versioned tuple of issuer,
SP entity, NameID format and exact NameID bytes. Mailbox changes and an alternate
SPProvidedID do not change that key. Email comes from one exact Attribute Name,
with at most one mailbox value; FriendlyName aliases are not used. A missing
email does not erase a stable identity, but cannot satisfy a new-account
invitation. This is not an OIDC `email_verified` claim or account authorization.

`ConsoleStore.SAMLReplayCache` implements authcore's replay interface with
PostgreSQL. Only assertion-ID digests are stored, scoped to tenant and provider.
The records survive store/connection replacement and provider metadata revision
changes. Database time governs cleanup; the caller's clock cannot expire an
existing record. A tenant advisory lock serializes cleanup, capacity checks and
insertion across Web instances. At 10,000 unexpired records, fresh assertions
fail closed while recorded IDs remain protected through their full supplied
expiry. Database failures also fail closed. Disabled, deleted and foreign-tenant
providers cannot add records. Authz has no table access; backup has read access.

Unit tests cover identity scope, significant identifier bytes, unstable formats,
qualifier mismatch, ambiguous email and redacted formatting. The genuine
PostgreSQL boundary suite additionally exercises fresh-pool durability,
eight-way single use, tenant/provider separation, role privileges, revision and
caller-clock resistance, a full cache, and concurrent recovery of the final
expired slot. Those SQL cases require `tests/postgres.sh`; a local unit-only
run is not evidence that PostgreSQL or complete SAML admission passed.
