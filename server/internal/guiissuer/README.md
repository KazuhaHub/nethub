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
the same job; a future explicit renewal/recovery operation must authorize another
generation rather than reset these counters silently.

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

The real PostgreSQL acceptance uses this adapter for claim/renew/read/save,
failure/poll release and immutable completion/recovery, including the existing
revocation, stale-version and retry-budget checks. No mocked database response
is used to claim those boundaries.

These foundations do not configure an account, start a scheduler/host adapter,
call a CA, deliver a chain or change a device. The actual CA coordinator and
recovery fixture are not connected yet. Verified native application and retrying
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
