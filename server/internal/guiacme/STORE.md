# Private account persistence

`NewAccountStore` validates configuration without creating files, generating a
key or contacting a CA. Its configuration must not contain a caller-supplied key.
An explicit offline `Initialize` creates the private P-256 account identity;
ordinary `EnsureAccount` operations can only use that previously stored identity.
Initialization can validate an existing intact store without changing its key.

The directory is owned 0700; canonical account JSON and the empty OS lease are
owned 0600 single-link regular files. Canonical parent paths reject directory
aliases and group/other-writable parents. A nonblocking Unix/Windows lease excludes
another initializer or account operation. Unknown nonempty initial namespaces,
missing keys/leases, corrupt/ambiguous JSON, altered policy, links and unsafe modes
fail closed without replacement or permission repair. A dangling lease link cannot
create an outside file. Windows tests exercise state logic only; production file
and directory durability requires Unix.

The private record contains the P-256 PKCS8 key and optional registered account
identity. Its immutable policy binds the exact directory URL, normalized approved
origins and contact. Custom TLS root pools are snapshotted; TLS trust can evolve
across process starts without changing the CA account identity. Roots never come
from a CA response. Changing the immutable account policy requires an explicit
separate migration/new state namespace, not automatic key replacement.

Complete private state is synced and atomically renamed before any account lookup
or registration. A lost response leaves the original key available; another
operation looks up that same key and persists the recovered identity. Account URI
changes are rejected after it is known. Matching URI/order metadata is not
rewritten on ordinary retries. The record is bounded to 32 KiB and is never an
ordinary JSON status value. Error categories contain no private key, CA response,
account identity or request URL.

An interrupted initial publication may leave private unpublished state; it is
preserved for explicit recovery and never silently adopted or regenerated. A
temporary file left after a later metadata update does not replace the durable
record or its key. The implementation removes only its own temporary file during
normal completion/failure; it never recursively deletes another namespace.

The protocol fixtures verify actual SDK JWS requests against the durably stored
key, explicit consent, unchanged retries and lost-response recovery after opening
a new store instance. Filesystem tests cover OS exclusion, state/lease loss,
corruption, policy mismatches, foreign data and production Unix link/mode/umask
boundaries. They do not create a public account or prove genuine CA issuance.

This component installs no CLI, application mount, timer or production path. Keep
its directory in protected issuer state, outside web/authz/frps and HTTP-01 public
mounts, and include it in the eventual verified private backup/recovery procedure.
Full deployment integration, issuance authorization, durable order jobs, native
delivery and certificate application remain separate work.

## Explicit private backup and recovery

`Backup` copies the validated complete account record and a fresh empty lease to
an independent protected directory. It holds the source lease, writes through the
existing synced private-state codec, then loads the result to verify canonical
encoding, policy, key consistency, ownership, mode and single-link files. The
operation contacts no CA, generates no key and never changes source state.
An existing exact backup is an idempotent retry; files and directories are synced
again before success. A changed account record requires a new backup directory.
The backup contains a private signing key and needs private storage and transport;
filesystem protection does not encrypt it.

`VerifyBackup` locks both stores and compares the same immutable key/policy. It
permits a pre-registration backup to remain useful after registration adds public
metadata, but conflicting known account or orders identities are refused. It
neither looks up nor creates an account. This is a local readable-copy check, not
evidence of an independent storage failure domain or an external archive upload.

`Restore` is an explicit operation into a new protected namespace. It preserves
the backed-up key and known account identity without contacting the CA. A later
lookup with creation disabled can recover an account whose registration response
was lost after that offline backup. An intact exact destination is idempotent;
an existing different, incomplete, corrupt or foreign destination is never
repaired or overwritten. Same, nested and parent account/backup namespaces are
refused. Failed publications remain for operator review; no recursive cleanup
or automatic adoption occurs.

Backup/recovery follow the original Unix ownership and durability contract;
Windows tests cover state logic only. These library operations do not enable a
production account, accept Terms of Service, install a timer or wire an operator
command. Explicit provisioning/current-terms consent and deployment acceptance
remain separate work.
