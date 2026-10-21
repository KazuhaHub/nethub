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

This slice stores admission, lease and retry state only. It does not persist CA
order checkpoints, issued chains or deployment status, configure an account,
start a scheduler/host adapter, call a CA or change a device. Do not begin CA
operations until durable order intent/identity and issuance recovery are wired.
Issued material and verified native application will remain separate states.

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
