# Fenced certificate work

Migration 00008 stores immutable tenant/device/CSR/generation identities separately
from the original signed request. Initial enqueue is idempotent, including after
a terminal failure; it does not turn a retry or missing cache into another
issuance. One active job per device and one audit entry per initial generation
are enforced by PostgreSQL. No application or issuer role receives raw table
access. Queue admission rechecks the authenticated device credential and original
CSR under the same parent lock used by revocation.

The no-login issuer has narrow functions to claim, renew and release a lease.
Every function locks the device before its job, checks current key/name/revocation
and uses the database clock after locking. Claims skip blocked parent rows before
the batch limit, so a locked prefix does not starve unrelated devices. A lease
has a new random token and an increasing version; stale tokens, versions and
expired leases cannot renew or release current work. Device revocation or a
subdomain change immediately cancels queued/leased/retry work and retires leases.

Initial limits are a 120-second lease and two-hour immutable job deadline, three
expired-lease recoveries, five transient failures and sixty pending observations.
Transient retries use bounded exponential backoff; ordinary pending observations
wait thirty seconds without consuming the failure budget. Policy failures and
indeterminate order creation are terminal. A terminal initial enqueue returns
the same job. Renewal admission authorizes another generation only from an issued
generation that has reached its database renewal time; terminal recovery still
requires operator review rather than resetting counters silently.

`DecodeSnapshot` independently checks the host's trusted device suffix/exclusions,
canonical identity/timing/budget fields, immutable public key, original CSR hash,
exact SAN/profile and signature. A valid decoded object is not permission to use
an expired snapshot: fetch fresh fenced state before every CA mutation/delivery.
The private snapshot and lease are excluded from ordinary JSON; raw CA metadata,
request material and lease tokens must not enter command arguments or logs.

Migration 00009 adds a private progress record with fenced read/save functions.
Explicit encoding retains order intent, original URI/profile/authorization/
finalize/download identity and exact HTTP-01 publication generation. The same
protected account URL policy validates all saved endpoints without opening or
initializing account key state. Creation intent precedes remote order creation;
known order metadata precedes publication/acceptance; finalizing intent precedes
CSR submission. Phase transitions and saved order/download identity are checked
in PostgreSQL as well as the typed codec. Saving advances the lease version, so
a lost/stale reply cannot silently overwrite a later checkpoint.

Expired proof metadata remains readable under a valid lease for exact resource
cleanup, but it is not authority to publish or accept an expired challenge.
Current assignment/lease checks still precede every external mutation. An
ambiguous new-order reply without a saved URI is terminal indeterminate work;
resume must not blindly create another order. Ordinary JSON excludes progress.

Migration 00010 stores independently validated public chains as immutable
generations. Completion requires a fresh live lease and a saved valid/finalizing
order with its download identity. The same completion token/version and exact
material recover the original generation after a lost reply; another payload
cannot replace it. Completion and one issuance audit commit together. Revocation
blocks completion/readback while retaining issued evidence. No private device
key enters the table or payload.

Material validation uses independently configured roots and the original bound
CSR/key/SAN/current validity. Renewal follows the earliest validated chain expiry,
with a lead bounded by actual lifetime and stable per-device spread. A minimum
issuance interval rejects material too near expiry to schedule safely, avoiding
an immediate short-lifetime renewal loop. These are issuance states, not verified
device application or an assertion that a router is serving the new leaf.

Migration 00013 adds issuer-only renewal admission. The existing protected host
command checks deployment, account, trust, cleanup and database readiness first,
then claims existing work first. An idle invocation scans at most 32 due devices
and admits at most one renewal, matching its one-job capacity and avoiding a
renewal batch expiring behind its own queue. It accepts no client
clock, requested generation, hostname override or private key. The host's exact
device suffix and exclusions fence the scan. Parent locks serialize enrollment,
renewal and revocation; blocked parents are skipped. Every predicate is rechecked
under the lock, and one next-generation job plus its audit commit atomically.
Concurrent scans and lost replies retain that same job. The original CSR/key
stays bound; a new CA order belongs to the new job, not to delivery or reporting.

The latest issued generation supplies `renew_after`, derived from validated
effective chain expiry. Expired certificates remain eligible for recovery, but
an active or terminal newer job prevents automatic creation of more CA work.
Failed initial issuance also has no issued generation to renew. Polling and
application acknowledgements never enqueue renewals; an offline device does not
need to report before the issuer renews its current immutable assignment.
Scheduling fixtures deliberately seed public material/clock metadata and do not
establish genuine renewed issuance or native installation acceptance.

`SQLStore` connects private queue/progress/completion functions through a bounded
stdin-only SQL runner. Every fresh session suppresses statement/error text before
selecting the no-login issuer identity. Canonical identifiers and hex-encoded
checkpoint/material fields avoid accepting arbitrary SQL text. Renew/save must
return the exact original tenant/device/request/key/CSR identity and the next
version; missing, oversized, stale or ambiguous responses stop the operation.
Errors never return runner diagnostics. A lost completion reply keeps its exact
token/version/material for recovery. The runner contract requires bounded output,
discarded stderr and a trusted local administrator socket; the privileged host
and administrator logging policy remain trusted.

`NewDockerSQLRunner` supplies the Linux root adapter for an independently
verified full container/image/project binding. It fixes the local Docker Unix
socket and executable, scrubs inherited daemon/database/proxy environment,
rechecks the exact running private PostgreSQL identity before each invocation,
and rejects privileged, published-port, host/shared or unrelated network
configurations. SQL travels only on stdin to passwordless local-socket psql;
stdout is bounded and stderr is discarded. This runner never starts a container,
changes its configuration or reads an application database password. The root
host, daemon and independently selected immutable deployment identity remain
trusted. Selecting a container from its labels alone is insufficient.

The real PostgreSQL acceptance uses this adapter for claim/renew/read/save,
failure/poll release and immutable completion/recovery, including the existing
revocation, stale-version and retry-budget checks. No mocked database response
is used to claim those boundaries.

`Coordinator.Step` connects these pieces to the registered ACME account and
HTTP-01 publisher. It renews the fenced current assignment before every remote
operation, persists creation/publication/acceptance/finalizing intent before its
side effect, retires only the exact publication generation and independently
validates the resulting original-key chain before completion. Steps have a
110-second ceiling; SDK and SQL operations retain their narrower limits. Waiting
and transient errors use the durable queue budgets. Missing save replies stop the
invocation and require recovery from current persisted state.

A recovered creation intent without an order URI is terminal indeterminate work,
including the conservative case where no remote order was actually created.
Known orders retain their URI and request. Acceptance recovery re-observes the
same challenge; the SDK avoids POST for processing/valid challenges. Finalizing
recovery fetches the already valid order's chain rather than submitting another
CSR. Expired proofs are removed and rejected. An independent expiry cleanup
mechanism is still required before enabling static publication in production.

Unit recovery tests inject committed-but-lost replies at each checkpoint and
verify one original order, finalization and issued generation. They additionally
cover ambiguous creation, revoked work and expired publication cleanup. The
genuine CA fixture recreates account/worker handles after lost published-proof
and issued-order replies using file-backed test checkpoints; it checks actual
CA-source HTTP fetches, retired responses and one original order/finalize POST.
Its file-backed store does not claim combined PostgreSQL/CA acceptance.

A separate combined fixture uses the actual local Docker SQL runner, PostgreSQL
queue/progress/completion functions and genuine Pebble/Caddy. Explicit fixture
ownership, immutable container/image/project identities and the private network
are checked before administrative seeding or clock-fault injection. Two saved
checkpoint replies are lost; only that job's lease is expired, old workers are
refused and a new lease/account/coordinator recovers the same CSR/order. The
persisted chain is independently checked, with one job, issued generation,
issuance audit and finalize POST. Retry/lease clocks are deliberately advanced
in this test; it does not measure production recovery latency or replace device
enrollment acceptance. Its separate tenant is created after ordinary deployment
bootstrap/browser/relay checks, and all fixture state is destroyed at teardown.

These components do not configure an account, start a scheduler/host command,
deliver a chain or change a device. Protected host configuration/scheduling,
independent proof expiry cleanup, verified native application and retrying
deployment of the same issued generation remain separate integration work.

Fresh bootstrap creates the reserved no-login role. Migration remains compatible
with a disabled legacy deployment where that role is absent; enabling an issuer
on such a volume needs an explicit reviewed role/function-grant upgrade. It must
not regenerate authority or use runtime migration credentials. The privileged
host and PostgreSQL administrator remain trusted boundaries.

The genuine PostgreSQL suite covers fresh and issuer-role-absent upgrades,
explicit later role/function preparation, eight concurrent enqueue retries,
four competing claimers, token/version/expiry fencing, expiry while waiting on
the device lock, polling/failure budgets, revocation and a 33-device locked
prefix. The compiled HTTP device suite remains part of that acceptance. Private
snapshot tests additionally reject mismatched domains/keys/CSRs and ambiguous
metadata while checking ordinary JSON exclusion.
