# SAML console pages

The Identity providers section offers OpenID Connect and SAML pages. The SAML
page supports pagination, creation, changed-field edits, enable/disable, deletion
and copying the SP metadata/entity and reply addresses. Metadata XML is supplied
explicitly; a blank replacement field preserves the saved document and signing
identity. Private SP key material never appears in a form or provider response.

The existing native dialog, pending-operation protection and uncertain-delivery
behavior apply. A lost mutation response does not replay a write. Closing and
refreshing is required before another attempt. Inventory checks remain passive
while visible, and loss of administrator authority clears the management view.

The marked background `GET /api/v1/console/saml-providers` uses passive session
validation, preserving the idle deadline while still checking the live account
and administrator role. Explicit reads and mutations remain active operations;
the background header does not bypass their authentication or CSRF checks. The
HTTP regression covers this distinction, and the genuine PostgreSQL HTTPS
fixture compares stored `last_seen_at` before and after all inventory polls.

Sign-in reads both protocol catalogs independently. Available choices survive
failure of the other catalog; local-password sign-in remains independent. Each
button starts its provider's protocol explicitly. Invitation claims retain the
memory-only bearer and the exact provider restriction, including SAML. The
administrator's invitation selector includes enabled providers of either kind.

Copy targets must exactly match the current HTTPS console origin and provider
slug. Raw metadata and invitation values stay in request bodies. The metadata
input enforces the server's one-MiB UTF-8 limit before a write; omitted fields
are not sent as empty replacements.

Local API/form tests cover changed fields, UTF-8 bounds, private-field refusal,
copy-origin checks, protocol selection and password fallback. The browser suite
uses an explicitly synthetic SAML fixture for management and navigation only;
it cannot issue assertions or establish SAML accounts. It exercises pagination,
copying, mobile native dialogs, account restrictions, light/dark contrast and
protocol-specific invitation/sign-in navigation under strict CSP.

These page checks do not establish genuine IdP or database admission. The
backend's signed-XML and PostgreSQL results are recorded separately. Final
hosted page screenshots were hash-verified and visually reviewed after all six
checks passed in run `40401585107`; PR #181 merged with the tested tree intact.
The separate [Keycloak deployment](validation-keycloak-saml.md) later passed
signed request/response admission with normal TLS in PR #182. Public-provider
and complete W6 acceptance remain open; synthetic page screenshots do not
establish either result.
