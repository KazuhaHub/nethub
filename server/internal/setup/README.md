# Deployment initializer

The Linux/root CLI creates a new private directory, independent cryptographic
random values for ten logical secrets, seventeen service-bound file copies,
reviewed templates, nonsecret Compose overrides, and a checksum/UID manifest.
It refuses overwrite. Every generated secret has a verified separate backup
before an exact acknowledgement and service UID assignment can confirm setup.
Resume requires an intact unconfirmed manifest and reuses the existing values.

Unit tests cover path/role coverage, random independence and intended sharing,
domain/subnet validation, non-overwrite, independent backup checks, corrupt copies,
unconfirmed state, permission rejection, and template parity. Native tests cover
Linux ownership (70/65532), actual Compose config, interruption/resume without
key changes, and complete container startup in the deployment acceptance script.

The manifest is an operational consistency record, not protection against a root
compromise. A local backup copy is not an off-site durability claim. Default
initialization checks DNS only against the operator's expected public address;
it cannot prove inbound firewall/port/TLS reachability. Offline preparation is
explicit. Full doctor checks for runtime grants/mounts, public TLS/ports, relay,
and scheduled database backups remain follow-up work and are reported untested.

The internal Linux authority snapshot helper stages all 22 secrets, runtime
leaf/key/trust, exact before/after manifests and retained maintenance bytes under
the shared relay lease. It verifies the acknowledged candidate and creates a new
independent full successor backup while retaining the original backup. Exact
retry revalidates both staged copies and backups; partial output is not replaced.
Its unresolved operation blocks ordinary renewal even after the process exits.
There is no snapshot/activate CLI. This does not replace live files, resolve a
database switch fence, reload services or prove combined migration/TLS recovery.

`RelayAuthoritySnapshotHost` attaches staged files to the durable transition
coordinator. Before writing it validates every active file against the pinned
before/after identities and original ownership. It archives the exact original
maintenance journal with a reversible rename, replaces only known files using
synced private temporaries, writes the manifest last and rechecks the complete
authority/backup. Restore accepts a planned mixed state and returns the original
journal without deleting a new or unexpected one. Unexpected bytes fail closed.

The injected trusted service adapter must reload authz and frps and independently
observe CA/name/served leaf. Current integration tests use genuine files and
PostgreSQL with a local TLS fixture, including failed reload rollback and a
discarded committed database reply. They do not exercise production authz/frps
reload, per-write process termination or native appliance recovery. The protected
service adapter, unattended unfenced-preparation abort/reprepare path and complete
combined deployment acceptance remain required before exposing activation.

The Linux `BoundRelayAuthorityService` binds protected Compose file hashes,
merged configuration, exact local image IDs/environment and expected application
commands. It checks actual container labels/work directory, private read-only
mounts, nonroot user, capabilities, network and origin publication on every
reload/observation. Initial binding requires running services and healthy authz;
recovery of stopped or absent services requires the identical fingerprint from protected
snapshot options. A production binding cannot be attached without that digest.

Reload verifies active trust/authority, recreates only authz, waits for health,
then recreates frps. It performs no build/pull/dependency startup. Observation
requires both bound services and a fresh independent CA/name-verified control TLS
connection. Tests of actual Docker reload use the unchanged authority; full
database-fenced root migration, process termination and authenticated appliance
recovery still need combined acceptance. No activation CLI is exposed.

`RunBoundRelayAuthorityTransition` composes the exact Compose database identity,
restricted SQL publisher, snapshot host and bound authz/frps adapter under the
shared transition lease. Inputs carry the explicit operation/current-overlap and
before/after leaf identities plus service fingerprint; it never publishes trust
or supplies device acknowledgements itself. `ResumeBoundRelayAuthorityTransition`
loads original options from protected snapshot metadata, rather than deriving a
new predecessor from live files that may already be partly changed.

The opt-in combined deployment test publishes overlapping trust, validates and
stores it in two authenticated fixture clients, reports through the compiled API,
switches actual authority/files/backups/services, resumes the exact terminal
operation and retires old trust. It verifies successor TLS and old-root refusal.
These fixture reports are not native-router installation evidence. Process-kill
recovery, safe cancellation of unfenced preparation and native reconnect/renewal
remain required before enabling unattended activation or adding an activation CLI.
