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
Linux ownership (999/65532), actual Compose config, interruption/resume without
key changes, and complete container startup in the deployment acceptance script.

The manifest is an operational consistency record, not protection against a root
compromise. A local backup copy is not an off-site durability claim. Default
initialization checks DNS only against the operator's expected public address;
it cannot prove inbound firewall/port/TLS reachability. Offline preparation is
explicit. Full doctor checks for runtime grants/mounts, public TLS/ports, relay,
and scheduled database backups remain follow-up work and are reported untested.
