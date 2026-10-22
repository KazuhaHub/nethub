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

## Activation remains separate

There is deliberately no activate command in this component. Active deployment
files, runtime mounts, setup manifest, database trust head and services remain
unchanged. Complete activation still requires verified candidate custody,
authenticated overlap application or explicit offline quarantine, a shared host
mutation lease, a crash-recoverable authority/manifest/backup transition, actual
served-certificate verification and rollback/recovery. Public trust retirement
must follow the active signer and retain the database application barrier.
Preparing material alone establishes none of those gates.
