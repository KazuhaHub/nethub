# Issuer-owned HTTP-01 publication

This package publishes public challenge resources and renders an optional Caddy
HTTP route. It does not authorize devices, place ACME orders, load account keys,
issue certificates or install anything on routers. The isolated issuer must first
authorize the live device/hostname assignment and its bound signed CSR, then derive
the key authorization with the existing ACME library. A valid CSR or publication
record alone is not proof of that authorization.

The scope follows [RFC 8555 sections 8.1 and 8.3](https://www.rfc-editor.org/rfc/rfc8555.html#section-8.3).
Tokens are bounded base64url-alphabet strings of at least 22 characters; this checks
shape, not entropy. The supplied response must contain that exact token and a
canonical SHA256 account-key thumbprint. Hostnames are one assigned eight-character
label below the configured device domain, excluding protected console names. No
wildcard/private key/PEM/general response template is accepted.

Public directories/files use owner-controlled 0755/0644 access. Private operation
state and tombstones use 0700/0600 and must remain outside the public directory.
The namespace is bound to both root paths and the protected-host policy; it
cannot be adopted silently after private state loss. Target files that are unknown,
links, writable permissions, hardlinks and mismatched bodies cause fixed errors.
Only the issuer writes here. Mount the public directory read-only into the proxy;
an external host worker also needs traversal permission on its parent directories.

Each host has one nonblocking OS lease. Immutable operation input, publication
intent and the active generation are durable before a complete public file is
atomically installed. A retry resumes that same generation. Removal records intent
first and checks current generation/content, so delayed cleanup cannot delete a
newer operation. Completed records remain as private tombstones against stale
publication. Empty public directories are retained; no recursive deletion occurs.

The issuer recovery loop must invoke CleanupExpired for known active hosts.
Ordinary static file serving has no per-request expiry check; resources remain
available until that cleanup executes. This foundation does not install its own
timer or enable HTTP routing in an existing deployment.

The Caddy snippet uses an HTTP-only catch-all with exact host/original-URI/method
matching and fixed static files, without directory listing or templates. Existing
console-specific automatic redirects retain precedence. GUI names are not added
to TLS automation. See [Caddy matchers](https://caddyserver.com/docs/caddyfile/matchers)
and [automatic HTTPS ordering](https://caddyserver.com/docs/automatic-https#effects).
The genuine deployment test checks body/header correctness, cross-host replay,
encoded/traversal/query/method rejection, read-only access, cleanup, retained console
TLS/redirects and absence of a managed GUI identity.

Windows exercises local state-machine tests only. Linux CI additionally exercises
filesystem permissions/link checks, restrictive issuer umask and genuine Caddy in
an isolated nonroot/read-only container. The production runtime image does not
contain the separately compiled acceptance binary. No public ACME account, live
certificate issuance, device key binding or GUI certificate installation is
established by these tests.
