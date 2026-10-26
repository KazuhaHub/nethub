# OIDC provider administration

The administrator API supports listing, creating, editing and deleting OIDC
providers. The management page and durable login/invitation callback flow remain
unfinished W6 work. A successful discovery check does not establish a working
client registration or an accepted user identity.

## Shared protocol and network policy

NetHub directly imports `authcore/oidc`, pinned to the verified upstream merge
`211d823f478ccdbf6bde8e5b85487e56bbdfe671` through its Go pseudo-version. This is
a development pin, not a new authcore release. Authcore owns discovery and the
authorization-code protocol, including PKCE and token verification. NetHub owns
deployment egress policy, accounts, permissions, storage and admission.

Only HTTPS endpoints are accepted. DNS resolution is bounded; every answer must
pass the destination policy before any connection is attempted. The dialer uses
validated IP literals and validates again on each new connection, preventing a
second hostname lookup from bypassing the check. Mixed public/private answers,
oversized answer sets and scoped addresses are refused. TLS still validates the
endpoint hostname with system trust. Ambient HTTP proxies are disabled.

The default policy refuses private, loopback, link-local, special-purpose and
translation/tunnel address ranges, including the Azure host-service virtual IP.
It conservatively rejects entire registered special prefixes, including their
globally reachable exceptions. The sources are the
[IANA IPv4 registry](https://www.iana.org/assignments/iana-ipv4-special-registry/),
[IANA IPv6 registry](https://www.iana.org/assignments/iana-ipv6-special-registry/),
and [Azure virtual-IP documentation](https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16).

For an intentional internal IdP, pass `--oidc-private-host dex-one:5556` to
`nethub init` or manual `nethub web`. Repeat for up to 16 exact authorities. The
default port is 443; another port or subdomain needs its own entry. Wildcards,
URL paths and URL credentials are refused. Exceptions permit private unicast
destinations at that authority, with normal TLS verification; they never allow
unspecified or multicast addresses. The deployer must control its DNS and TLS
trust. Resume preserves the saved policy rather than silently replacing it.
Generated commands and backup identity comparisons include these exceptions.

Discovery and signing-key responses are limited to 1 MiB, headers to 64 KiB,
with finite DNS, dial, TLS, header and request deadlines. Encoded responses are
refused. GET redirects are bounded and remain subject to HTTPS/destination
checks; token POST redirects are refused. There is no application token-exchange
retry. Advertised authorization, token and key URLs are checked before saving.
API discovery failures return one fixed 422 message without upstream diagnostics.

## Writes and lifecycle

Provider creation and protocol edits validate discovery before writing. Live
administrator authority is checked before remote I/O and again in the final SQL
transaction. No actor/provider lock is held during discovery. The final edit
locks the provider and compares its revision; a concurrent committed edit causes
`409 provider_changed`. The caller must reload before editing again.

Changing the display name or disabling a provider does not require the IdP to be
online. Enabling it, changing issuer/client/scopes, or replacing/removing its
credential does. Omitted credentials preserve the exact stored envelope. A supplied
nonempty value gets fresh authenticated encryption; an explicit empty value is
stored as SQL NULL only after discovery accepts a public client. JSON null is
invalid. API responses include only `has_client_secret`, never credential bytes,
ciphertext or a digest. Default scopes are `openid email profile`; providers are
disabled by default. Audit metadata contains only provider ID and normalized
source IP, and commits atomically with each mutation.

Issuer changes and deletion are refused once any user is bound. Deleting an
unbound provider disables it, clears its encrypted credential, marks a tombstone
and cancels unused restricted invitations in one transaction. Invitation rows
retain their original provider restriction. Deleted providers do not appear in
the list and cannot be edited. Their slugs remain reserved so an old callback or
invitation cannot be repurposed for a different provider. No provider history is
physically deleted. Repeated deletion returns 404; clients should reload after an
uncertain response rather than automatically replaying a mutation.

## Verification scope

Unit tests exercise destination filtering, mixed DNS answers, rebinding, exact
exceptions, normal TLS trust/refusal, redirects, cancellation, response bounds
and the authcore adapter. HTTP fixtures cover permission/CSRF/input boundaries,
callback projection and fixed error responses. Genuine PostgreSQL tests cover
encrypted writes, tenant/admin isolation, omitted-secret preservation, nonce
rotation, live authority changes, concurrent revision refusal, identity guards,
audit rollback and retained invitation restrictions. The SQL test's discovery
callback is controlled; transport behavior is proven separately. Hosted execution
and actual logs are required before accepting the complete backend. Two-Dex,
public IdP, browser provider management and actual SSO admission remain pending.
