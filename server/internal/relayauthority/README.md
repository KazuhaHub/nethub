# Offline relay authority candidates

This package prepares a successor outside the active deployment before any
signer change. It binds the original CA DER fingerprint, a distinct successor
fingerprint, relay name, preparation time and exact hashes of the four material
files. The original CA/key must match; identity inspection does not sign or
require the original CA to remain unexpired. New material must pass current
certificate/key/name validation.

Preparation and backup require new canonical directories below protected parents.
They never overwrite an existing or interrupted candidate. Material files are
created exclusively with mode 0600 and synced before the completion metadata;
the directory and its parent are synced. Partial outputs remain private and are
refused on inspection. Unknown files, duplicate/noncanonical metadata, wrong
keys, changed bytes, links and unsafe POSIX ownership/modes fail closed.

An independent backup contains exact bytes in a separate directory. Verification
checks both validated copies and refuses overlapping namespaces or shared file
identities. A matching local copy proves neither off-host custody nor operator
approval to activate a signer. No verification flag changes active state.

## Protected host commands

On the confirmed Linux host, choose a private parent outside the deployment and
its existing authority backup, then use explicit paths:

```sh
nethub certificates relay-authority prepare --directory /srv/nethub \
  --candidate-directory /root/relay-offline/successor --expected-root CURRENT_ROOT_SHA256
nethub certificates relay-authority inspect --directory /srv/nethub \
  --candidate-directory /root/relay-offline/successor
nethub certificates relay-authority backup --directory /srv/nethub \
  --candidate-directory /root/relay-offline/successor \
  --backup-directory /root/relay-offline/successor-backup
nethub certificates relay-authority verify-backup --directory /srv/nethub \
  --candidate-directory /root/relay-offline/successor \
  --backup-directory /root/relay-offline/successor-backup
```

The expected root is the configured issuer's DER SHA256 identity, also exposed
among the roots by the public trust inspection command after initialization.
Use mode 0700 for the parent. Every invocation rechecks the original confirmed
deployment and its independent backup; candidates for another original authority
or relay identity are refused. Output contains metadata, not keys or PEM. These
commands do not require Docker and open no listeners.

## Explicit backup acknowledgement

After independently reviewing the candidate and backup, the operator can record
that assertion in a new protected file outside both material directories:

```sh
nethub certificates relay-authority acknowledge-backup --directory /srv/nethub \
  --candidate-directory /root/relay-offline/successor \
  --backup-directory /root/relay-offline/successor-backup \
  --custody-file /root/relay-offline/successor-custody.json \
  --acknowledge 'I HAVE VERIFIED THE INDEPENDENT RELAY AUTHORITY BACKUP'
nethub certificates relay-authority verify-custody --directory /srv/nethub \
  --candidate-directory /root/relay-offline/successor \
  --backup-directory /root/relay-offline/successor-backup \
  --custody-file /root/relay-offline/successor-custody.json
```

The receipt binds canonical source/backup paths, original/successor root identity,
the candidate metadata digest and first acknowledgement time. Creation is
exclusive and synced. Exact retries recheck both material sets, preserve the
first timestamp and sync the existing receipt again. Changed or partial receipts
are not overwritten; a different backup cannot silently reuse the same receipt.
Verification always revalidates both current independent copies. A receipt alone
cannot authorize missing, expired, modified or aliased material.

This records explicit operator intent, not independently observed off-host
custody. Tests use disposable local fixtures and do not acknowledge operational
material on the operator's behalf. No active signer, manifest, public generation
or service changes during acknowledgement.

## Durable transition coordinator

The internal `Transition` engine holds the shared relay operation lease and
persists an immutable intent bound to the deployment, exact database switch
request and host snapshot digest. Prepared state is synced before the intent
completion marker. A missing state beside an existing intent is refused; it
cannot silently restart an operation whose live writes may already have begun.
Canonical private JSON, owner/mode/single-link checks, file sync, atomic state
replacement and parent-directory sync protect the journal. Exact retry syncs the
existing intent/state again. Interrupted initialization remains for inspection.

The database fence precedes live changes. `applying` is persisted before host
writes; an interrupted application recovers toward rollback. Independently
verified new state is followed by a durable `committing` decision. A lost terminal
reply leaves that decision intact and retries it; it never selects the opposite
terminal state. Failed rollback retains the pending database fence. Adopting an
already terminal database receipt requires a matching local decision and fresh
host verification, and performs no host writes.

The host interface must preserve and revalidate a synced immutable before/after
snapshot, covering authority files, ownership, runtime trust, setup manifest,
independent full backup and maintenance journal. Apply/restore may change only
known before/after states. Verification must independently check the resulting
files/backup and actual CA/name/served leaf. Callbacks must honor cancellation
and bound commands; the coordinator supplies a three-minute context.

Fault tests reopen the disk journal with a fresh host object at preparation,
fence, apply, commit, rollback and lost-reply boundaries. They use synthetic host
bytes and an in-memory database seam, so they do not prove actual deployment
migration, PostgreSQL integration, backup custody or TLS observation. POSIX unsafe
path tests run on the privileged-host platform. A concrete protected deployment
adapter and genuine combined acceptance are still required before activation.

## Activation remains separate

An explicit preparation cancellation can resolve partial snapshot/metadata output
without reconstructing it. The host independently verifies current original
files, ownership, the independent backup, maintenance and actual original TLS
twice under the shared lease. The immutable SQL cancellation decision precedes
an atomically published terminal marker. Existing switches are refused, even if
their admission reply was lost; a null lookup is never used as absence proof.
Lost replies leave the original journal protected until an exact retry receives
the same decision. Partial files and backups remain untouched for inspection.
Staging and admission refuse the marker; only a correlated valid receipt permits
ordinary maintenance. A completed retry preserves its first timestamps without
replaying host effects. This path requires explicit original options and does
not accept an expired original TLS endpoint or discover missing options itself.

Ordinary relay maintenance checks retained transition journals both before and
under the shared lease. Releasing a crashed process's lease does not reopen
renewal: nonterminal, partial, missing or malformed intent/state blocks it.
Structurally valid committed/rolled-back records or verified cancellation receipts permit normal maintenance,
which still performs its original authority/runtime checks. This prevents a timer
from modifying a planned mixed deployment before recovery acquires the lease.

There is deliberately no activate command in this component. Active deployment
files, runtime mounts, setup manifest, database trust head and services remain
unchanged. Complete activation still requires verified candidate custody,
authenticated overlap application or explicit offline quarantine, a shared host
mutation lease, a crash-recoverable authority/manifest/backup transition, actual
served-certificate verification and rollback/recovery. Public trust retirement
must follow the active signer and retain the database application barrier.
Preparing material alone establishes none of those gates.
