# Native certificate store adapter

The 0.0.8 development source adds a PHP store adapter and private CLI boundary
alongside the durable transaction journal. The scheduled action still performs
verification/staging only. No installed package or actual GUI configuration has
changed as part of these source-only tests.

The store uses the native `Config::lock/object/save/unlock` interface. It creates
one managed certificate entry with the device-held key and complete public chain,
then selects only that refid for the GUI. It does not create trust authorities,
change passwords/SSH, add Alternate Hostnames or disable GUI checks. The assigned
hostname must already be listed exactly in the administrator's Alternate
Hostnames before preparation; the CLI returns a fixed prerequisite code when
that step is missing.

Preparation checks the active enrollment and service intent, staged-file digest,
enrolled P-256 key agreement, leaf fingerprint/SAN/validity, current GUI selection
and previously applied managed-entry identity. A protected immutable snapshot
contains only the owned before/after entries and prior GUI ref, not the whole
configuration. Its private key material remains local in mode-0600 files beneath
a mode-0700 directory. Public CLI replies expose only hashes, refs, the GUI port
and probe metadata. Input is bounded stdin JSON; command-line parameters and
unknown operations/fields are refused.

Installation and rollback recheck the durable journal, snapshot hash, ownership
and exact before/after native entry/ref. Rollback removes a first-install entry or
restores the previous owned entry; it refuses conflicts or a changed original GUI
certificate. Other certificate entries and configuration fields stay intact.
Native configuration writes are flushed before returning. The installed Core
audit implementation was inspected: it logs revision metadata, not entry/key
contents; ordinary protected native backups remain enabled.

OPNsense's system OpenSSL and Python SSL have different compiled default trust
paths on the test appliance. FreeBSD verification now explicitly loads the
administrator-managed `/usr/local/etc/ssl/cert.pem`, with the existing ownership,
mode and public-material checks, and disables competing default trust sources.
Private fixtures substitute their own independent bundle without editing the
appliance trust store. The later TLS probe must use this same managed trust.

Tests execute the actual PHP store with a locked temporary XML configuration and
real signed P-256 material. A marked fixture guard prevents using host config.
They exercise import, idempotence, renewal rollback, wrong keys, inactive/revoked
intent, duplicate refs, hostname prerequisites, operator conflicts and malformed
CLI input. PHP XML extensions are explicit CI dependencies on Ubuntu 24.04/PHP
8.3; appliance tests exercise its installed PHP directly. A test-only configuration
object, paths and owner are injected; the production CLI fixes all of these to
native locations and root ownership.

The model probe is a test flag. These results do not establish actual Core
integration, GUI reload, a served TLS chain or reboot recovery. Next, add the
bounded native backend/probe, early boot recovery and removal handling; extend
the lab watcher before enabling/installing the GUI-changing flow, then validate
the real appliance and public pipeline without bypassing CA/account consent.
