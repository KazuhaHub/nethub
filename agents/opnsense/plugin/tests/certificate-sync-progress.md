# Native GUI certificate synchronization

The 0.0.7 source adds a separate `agentctl certificate` action. The package-owned
system cron starts it at second 40 under the same nonblocking `lockf` lock used
by reconcile, reporting and watchdog. A 20-second internal deadline sits inside
a 25-second process deadline. Disabled, stopped, revoked and uninstalling intent
prevents synchronization. Failures update a separate filtered certificate status;
they do not restart frpc or overwrite tunnel reconciliation state.

The synchronizer requires the existing enrolled P-256 key. It restores an
accepted original CSR from authenticated bytes, or creates one for an existing
key when no request has been accepted, then submits the same signed request and
polls protocol 1.3 delivery. It never regenerates a missing key. Repeating CSR
admission also repairs an older accepted request without an initial issuance job.

Before staging, native OpenSSL verifies the exact hostname, TLS server purpose
and chain against independently provisioned trust. Response certificates cannot
provide their own trust anchor. Environment overrides for OpenSSL trust and
configuration are removed from that verification process. An explicit protected
public CA file is supported by the verifier for isolated tests; the scheduled
action uses native system trust. The signed leaf must match the enrolled public
key and original CSR, one exact DNS SAN, server signing usage and the public
validity metadata. Ordered, unique supplied certificates and effective expiry
are checked. Verification at the last included effective-expiry second also
checks independently selected roots omitted from the response.

Only normalized public protocol material is atomically staged in
`/usr/local/etc/nethub-agent/gui-certificate.json`, mode 0600. Generation numbers
cannot regress; one generation cannot change material or reuse another
generation's identifier. Unchanged delivery preserves the existing file. Expired
previous staging metadata does not block a newly verified generation. A pending
response or failed write retains the current candidate. Confirmed enrollment
removal deletes only the known public request/candidate artifacts before runtime
key cleanup, without touching the independent native certificate store.

Focused tests use actual generated keys, signed CSRs, a private root and native
OpenSSL verification. They cover trust injection, wrong profiles/signatures,
omitted-root expiry, duplicate/unrelated chain entries, original-CSR recovery,
pending delivery, monotonic staging, failed replacement, shared locking and
tunnel-state isolation. Native source-only validation runs from an isolated test
directory with temporary dependencies; it verifies the full configuration hash,
removes temporary keys and reports the installed package version. Exact source
and archive identities belong in the associated validation receipt and PR.

This does not import a certificate into OPNsense, select the GUI certref, reload
the GUI or prove a production renewal. The lab remains on installed 0.0.6 until
a separately guarded installation. Before any native GUI change, the lab watcher
must cover precisely the owned certificate/certref and persistent last-good/apply
journal, including boot recovery, while preserving unrelated configuration.
Renewal authorization, installation acknowledgements and offline trust recovery
remain required.
