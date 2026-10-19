# Relay maintenance journal

The host engine holds one nonblocking OS file lease across issuance, publication,
recreation and verification. Public state uses fixed phases/error codes, bounded
attempts and private generation snapshots. State decoding requires the exact
canonical format written by this engine; it rejects unknown/duplicate fields,
trailing content, linked paths, unexpected permissions and invalid references.
Generation directories are atomically published after both PEM files and their
directory have been synced. Complete pending material survives a process exit
before the issued transition and is reused. Local signing output that has not
yet been durably published can be lost at process exit; this is not global
exactly-once issuance.

Application intent and attempt count are durable before runtime files change.
Interrupted mixed pairs are replaced from the complete issued snapshot. A fresh
verified served fingerprint is required before marking success. If an interrupted
application is already served, recovery records that fact without restarting;
the original interruption duration is unknown in that case.

Failed application persists rollback intent, restores a still-valid last-good
generation and verifies it through a fresh TLS connection. Rollback has an
independent bounded cleanup context. Three automatic attempts use the same issued
generation; durable backoff and terminal failure prevent repeated signing or
unbounded restarts. Explicit root retry bypasses pending backoff or resets an
exhausted budget, while reusing valid issued material.

A valid but expired candidate enters a durable replacing phase before pending
retirement. Its immutable generation remains available and the superseded
fingerprint is recorded. A complete replacement pending pair survives interruption
and is reused instead of signed again. Corrupt, wrong-identity or wrong-key
material is refused without retirement. Exhausted jobs still require explicit
retry; an interrupted final attempt first rolls back instead of gaining another
deployment budget. An expired last-good generation is never restored. These new
canonical journal fields/phases fail closed in older engines; keep the new host
command after replacement rather than downgrading it against this journal.

A timer does not start an intentionally stopped service. An interrupted applying
or rollback transition can finish its already-authorized recovery, and an
explicit root retry can restart its pending generation. Expired old material is
never accepted as last-good rollback. An expired authority or a leaf whose expiry
cannot improve requires authority rotation, rather than useless repeated issuance.

Production is restricted to a protected local Linux filesystem and a Linux root
host command. Windows file locking exists for local tests; it does not establish
Linux directory-sync durability. The host adapter, not this engine, verifies
deployment authority/backup, isolates key material and limits Docker to the
configured local frps service. Trust rotation and router GUI ACME are separate.
