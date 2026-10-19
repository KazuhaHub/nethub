# Restricted ACME account client

This package uses the existing `golang.org/x/crypto/acme` RFC 8555 implementation
for account lookup and registration. It does not implement its own JWS protocol.
It is an issuer component, not an application service or a public API endpoint.

The caller must durably store its P-256 account key in protected issuer state
before constructing a client. This package never creates, replaces or writes that
key. Each operation discovers the directory and looks up the same key first.
After a lost registration response, another operation can recover the existing
account. A known account URI must match exactly; a missing, deactivated, revoked
or changed account cannot trigger silent replacement. Successful account metadata
is excluded from ordinary JSON. Persist it explicitly in private issuance state.

New registration is off by default. The operator must explicitly allow creation
and supply the exact currently advertised Terms of Service URL. Discovery is fresh
for every operation, so an earlier cached agreement is insufficient. This library
does not fetch or accept terms for the operator. External-account-binding CAs need
a separate explicit credential workflow and currently fail closed.

Every request, including endpoints supplied by the CA, must use the configured
directory origin or an explicitly configured additional HTTPS origin. Comparison
includes the port. Directory endpoints and returned account identities are checked;
redirects are rejected even between approved origins. Proxy environment variables
are not used. Independent configured/system trust verifies CA TLS and its hostname;
there is no insecure mode. Account keys and custom root pools are snapshotted.

Each operation has a 45-second deadline, including waiting for the per-client
account gate. Requests have bounded dial/handshake/header/body timeouts, a 64 KiB
response-header limit and a 128 KiB fully consumed response-body limit. Compressed
responses are rejected. SDK retries are disabled: a future durable scheduler owns
retry timing and budgets. Errors expose fixed categories, not CA response content,
request URLs, account identities or submitted tokens.

The TLS protocol fixture verifies the actual SDK JWS signature, account public key
and single-use nonce. Tests cover consent changes, ambiguous-response recovery,
concurrent account setup, identity mismatches, untrusted TLS, endpoint confinement,
redirects, body/header handling and cancellation. These tests are not genuine CA
issuance acceptance. No live public account is created and no deployment route or
timer is installed.

The separate `AccountStore` implements protected key/account persistence and
recovery; see [its contract](STORE.md). Deployment wiring, current-assignment
authorization, durable order jobs, HTTP-01 execution, authenticated delivery and
native GUI installation remain required before issuing router certificates.
The existing `guicert` and `http01` packages provide separate request,
chain and publication checks; none of those checks alone authorize issuance.
