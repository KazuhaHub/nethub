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
