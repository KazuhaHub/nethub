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

`SweepExpired` scans up to 128 hosts per batch using a bounded-memory selection
and durable lexical cursor. Busy/corrupt hosts advance the cursor rather than
starving later hosts. Expired current generations use the same locked removal
and retained tombstones as explicit retirement. Unknown files/links are reported
without following or deleting them; other valid entries can still be cleaned.
Only numeric counters enter status JSON. A caller can repeat batches until
`cycle_complete`, resuming a timed-out invocation from its protected cursor.

Install a root-owned mode-0600 policy using `deploy/http01-policy.example.json`,
then explicitly initialize its namespace against the confirmed deployment:

```sh
nethub certificates initialize-http01 \
  --directory /srv/nethub-deployment --config-file /etc/nethub/http01.json
```

This Linux root operation verifies the independent authority backup, exact device
domain and console exclusion before creating public/private roots. Their existing
parents must be protected and the roots must remain outside the deployment.
An exact retry verifies the existing identity; partial or damaged state requires
review and is retained. The command does not register an account, publish a
challenge, change proxy configuration or enable services.

`nethub certificates cleanup-http01 --config-file /etc/nethub/http01.json` runs a
30-second scan budget on the Linux root host without database/account/signer dependencies.
The root-owned 0600 policy contains exactly the fields in
`deploy/http01-policy.example.json`. Both namespace identities and their lease
must already exist and match; cleanup never initializes a missing namespace or
repairs existing permissions. Public/state roots must remain outside each other.

The optional `deploy/systemd/nethub-http01-cleanup.{service,timer}` runs this
command every minute and after boot, independently of the issuer. It uses private
networking, masks conventional Docker/PostgreSQL sockets, drops capabilities and
makes the filesystem read-only except the two publisher roots. The defaults are
`/srv/nethub-http01` (0755 public) and `/var/lib/nethub-http01` (0700 private),
with the CLI installed at `/usr/local/libexec/nethub`. Custom roots must match
both the policy and unit's `ReadWritePaths`/`StateDirectory`. After initializing
the issuer-owned namespace and installing the protected policy, install the two
units, reload systemd, start the service once and enable the timer. Nothing here
enables a timer or HTTP routing in an existing deployment automatically.

Ordinary static file serving has no per-request expiry check. Responses remain
available until a successful cleanup, including during busy/error conditions;
the actual CA worker must separately reject expired proof/assignment/lease use.
Publication must not be enabled before independent cleanup has been configured
and verified. Protected host worker configuration/startup remains separate work.

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

The Linux host probes the genuine test proxy through its verified private address
on an owned internal bridge. No host ports are requested or effectively published.
The harness verifies the network identity, internal flag and container membership;
it does not assume Docker implements port publishing for an internal network.
See [Docker bridge isolation and host reachability](https://docs.docker.com/engine/network/port-publishing/#gateway-modes).
