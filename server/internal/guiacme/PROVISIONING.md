# Protected host account commands

`nethub certificates account` manages the GUI issuer's existing protected policy.
It is a root-host operation, not a web endpoint or scheduled account creator.
The deployment must already have verified/acknowledged authority backup, a
protected issuer policy and HTTP-01 policy/directories. The commands do not
initialize a publisher, start services, change Docker, or modify an appliance.

The account and snapshot directories must be independent from each other, the
deployment runtime tree and both HTTP-01 namespaces. Parent paths must be
canonical and protected. Provision their root-owned private parent directories
first; these commands do not create or repair missing parent paths. An account key must not enter an application container
or a public validation mount. Keep the configured account below the issuer
service's explicit private `ReadWritePaths`; moving it outside that boundary
requires an operator-reviewed unit override. Do not widen the sandbox to an
entire home, deployment or filesystem.

Use the same `--directory` and `--config-file` for each command. The default paths
are `/srv/nethub-deployment` and `/etc/nethub/gui-issuer.json`.

1. `account initialize` creates the offline identity explicitly. Ordinary lookup,
   review, registration and background issuance cannot initialize missing state.
2. `account backup --backup-directory /var/backups/nethub/gui-account-initial`
   creates an immutable complete snapshot. Then use `account verify-backup` with
   that directory. This checks a readable identity copy, not independent storage;
   retain an additional protected off-host copy and verify its recovery procedure.
3. `account terms` returns fresh, bounded `terms_reference` metadata. Review that
   exact agreement independently. The command neither follows nor renders the
   reference, accepts it, nor looks up/registers an account. Empty metadata still
   requires explicit creation opt-in. Inline plain-text references remain data.
4. Only after review, create a root-owned 0600 consent JSON file in a protected
   directory with exactly one string field, `accepted_terms_reference`. It must
   exactly match the currently advertised reference, including an empty string
   when none is advertised. Duplicate, null, non-string and extra fields fail.
5. Explicitly run `account register --backup-directory SNAPSHOT --terms-file FILE
   --allow-create`. Registration verifies the backed-up key first, re-discovers
   current terms and refuses a changed agreement. It reuses the durable key and
   recovers an existing matching account before considering creation. External
   account binding remains unsupported and fails closed.
6. Create a new immutable snapshot directory after registration to retain its
   public account metadata too. Preserve the initial snapshot for fixed-key
   recovery; registration does not overwrite it. No command prints the signing
   key or account URI.

`account lookup` recovers only an existing account using the stored key, with
creation disabled. `account restore --backup-directory SNAPSHOT` explicitly
installs a snapshot into the new namespace named in the protected issuer policy.
It refuses an existing different, damaged or partial namespace. After restoring
a pre-registration snapshot, `lookup` can recover the original registered URI
without accepting terms again or registering another key. A missing account,
changed known identity, TLS failure or unsupported CA policy needs operator
review; ordinary work never silently replaces it.

Registration success does not enable the issuer timer, authorize a device job or
install any GUI certificate. The private-CA provisioning fixture additionally
proves real certificate issuance through the protected host using the recovered
account. It does not register a public account, accept public terms for an
operator, establish an off-host backup or prove native router installation.
