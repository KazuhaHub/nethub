# Protected host operation lease

Relay renewal, public trust inspection/publication and offline authority commands
share `<deployment>/relay-operation.lock`. They first validate the confirmed
deployment, acquire this nonblocking OS lease, and revalidate the authority and
backup before reading operation inputs. Renewal then takes its existing narrower
maintenance-journal lease. The lock order is shared host lease before operation
journal/database locks; callers must not acquire it in reverse order.

The lease file is empty, persistent and never replaced or removed by the API.
Canonical paths, a protected parent, a regular single-linked owned inode, exact
POSIX modes and opened/path identity are checked. The operating system provides
contention and releases the lease when its holder exits. File existence or a
remembered PID is not evidence of a live holder.

Renewal keeps its existing busy-skip behavior; public trust and offline authority
commands return their fixed refusal diagnostics during contention. None reports
application or changes signer state merely because it failed to acquire a lease.
Calls can be retried after release. The lease serializes cooperating commands;
it does not confine a compromised root user, Docker daemon or external file editor.

Tests use a real separate process to hold the lease, prove contention, kill that
exact owned process and acquire the unchanged file again. POSIX tests cover
linked paths, unsafe ownership/modes and outside-file preservation. Windows
checks local content/LockFileEx behavior; deployed host commands require Linux.
The protected Docker-host fixture additionally holds this exact lease while
invoking all three command families and requires refusal/skip, recovery and an
unchanged authority/runtime/public head.

This is a prerequisite for authority activation, not its transaction journal.
Signer/manifest/backup migration, database rollout barriers, candidate custody,
served-certificate verification and crash recovery remain separate requirements.
