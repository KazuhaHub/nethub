# Account-bound HTTP-01 challenge operations

`PrepareHTTP01` rechecks a durable order snapshot against the current signed CSR,
immutable device public key and registered CA account. It requires the same order
URI, request fingerprint, hostname, selected profile, authorization and finalize
URLs. It verifies a non-wildcard DNS authorization with a future expiry and selects
one bounded HTTP-01 challenge on an approved HTTPS origin. The key authorization
is derived from the persisted account key; no arbitrary response body is accepted.
It publishes nothing and accepts no challenge by itself.

Before `AcceptHTTP01`, the future durable worker must reauthorize the live
tenant/device/assignment and publish the exact response through the isolated
publisher. This package does not establish those preconditions or replace the job
journal. Acceptance reloads the order and authorization, compares the saved
challenge URI/token/key authorization and refuses an expired publication proof.
Processing or validated challenges are observed without another acceptance POST.
An already valid authorization completes this phase without publishing/accepting
another challenge. Responses are confined to fixed statuses/private metadata;
untrusted CA diagnostics never leave this boundary.

Each operation shares one 45-second account lease/SDK lifetime. It cannot create
or repair an account, replace the order, wait indefinitely or accept an arbitrary
URL. A lost acceptance reply can recover the existing processing challenge without
reposting. If the CA still reports pending, a future durable retry policy must
bound another acceptance of that same challenge; exactly-once POST is not claimed.
Keep publication until validation has completed, then remove its owned generation.

TLS/JWS fixtures exercise preparation without acceptance, exact-publication
correlation, changed order/authorization/challenge rejection, duplicate or missing
HTTP challenges, invalid tokens/origins/errors, already valid authorization and
lost/changed acceptance responses. Finalization, certificate fetching, queue/API
wiring and native installation remain separate work.

The focused genuine Pebble/Caddy fixture passed in 4.71 seconds: an unpublished
response returned 404, the exact durable response was served only for its host,
the real CA fetched it and the same order reached ready. The proxy access log
independently matched the CA container's source address and exact host/path.
After validated-authorization recovery, retiring the publication returned 404.
The source check normalizes only an explicit HTTP port 80 in the Host authority;
the first fixture run rejected that equivalent authority and was retained.

Both containers used a nonoverlapping internal bridge and no published host ports.
The nonroot read-only proxy mounted only public responses, its route and separate
scratch directories; private publisher/account state was not mounted. Independent
cleanup removed both containers, network and complete temporary-key namespace
before cancelling its guard. Original public services stayed running. No
certificate was finalized or installed. Current-head CI remains required;
GitHub-hosted jobs are presently stopped before execution by account billing/
spending restrictions, so this local/native proof does not authorize a merge.
