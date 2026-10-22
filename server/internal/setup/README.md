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
