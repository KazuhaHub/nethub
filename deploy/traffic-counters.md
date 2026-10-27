# Relay traffic soft counters

The W7-2 sampling foundation is in progress. The tenant/month API, console view,
warning configuration and actual frps/PostgreSQL/browser acceptance are still
required; these source changes do not establish completed traffic reporting.

## Source and accounting

The existing bounded private `GET /api/proxy/https` snapshot includes frp 0.71.1's
`todayTrafficIn` and `todayTrafficOut` integers. These are daily in-memory proxy
counters. A normal reconnect updates `lastStartTime` without clearing them, so
that timestamp is not used as a reset epoch. New generated frps containers set
`TZ=UTC` in the image, preserving the protected authority binding's refusal of
runtime environment overrides. Existing or externally managed relays must also use UTC
before sampling; an HTTP Date header cannot establish the process timezone.

Each recognized device and matching assignment gets a durable daily baseline and per-tenant/device/month
facts. Repeated or older snapshots do not add bytes. In the same UTC day,
increases add their difference; an observed decrease adds the new value as an
estimated reset segment. Directions are independent, with one reset event per
sample. A new day starts from its first observed daily totals. The initial
tracking sample includes the relay's current daily totals, not just subsequent
traffic. Monthly facts survive device removal, while its cursor is removed.

This is approximate visibility, not billing or proof of complete traffic. A
relay restart/reset can go undetected if its new counter already exceeds the
old value. Missed polls, midnight gaps, pruned metrics and coalesced snapshots
can lose unobserved bytes. A compromised relay or authz process can falsify these
telemetry values. Monthly attribution follows observed UTC daily
counters; no attempt is made to reconstruct unavailable historical traffic.

## Boundaries and resource limits

Online samples must retain the existing canonical device proxy/configuration
checks. Unknown devices are not created. An offline proxy can have no
configuration; its counters are accepted only after a prior verified baseline
exists. Offline counters never refresh online status. Online samples with the wrong assigned subdomain cannot update a device's counts.

Malformed numeric counters suspend telemetry for that snapshot while preserving
valid route observations. Malformed route or JSON admission still follows the
existing refusal rules. The one-MiB/1,024-proxy snapshot, private transport,
credential custody and five-second observation cadence remain unchanged.

A separate worker keeps at most one pending traffic snapshot and gives storage
two seconds. It never waits in the online-observation path or participates in
heartbeat, source-IP grants, disconnect, anomaly decisions or revocation.
Shutdown cancels its work. Fixed failure/recovery messages omit credentials,
URLs, response bodies and dependency diagnostics.

Storage uses current database tenant/device rows, forced RLS and the existing
authz role. Per-tenant telemetry serialization skips a busy writer. A monthly
fact and its next baseline commit atomically; timestamps are bounded and
ordered, and old responses cannot create artificial resets. The Web role can
read monthly facts but cannot change them or read sampling baselines. The
backup role can read both tables without receiving write authority. Wide
monthly totals use exact decimal storage rather than overflowing an int64 sum.

## Validation still required

Local parser/worker tests exercise numeric limits, offline admission, bounded
coalescing, a stalled storage writer, continued observations and cancellation.
The genuine PostgreSQL suite adds fresh-pool persistence, replay/reset handling,
concurrent accounting, month boundaries, exact wide values, removed-device
history, role/RLS isolation, malformed input and advisory-lock skipping. Those
SQL cases must actually execute at the tested source revision. Real pinned
frps/frpc traffic and a rendered console must also be checked before accepting
the complete W7-2 path. No threshold may block or revoke a device.
