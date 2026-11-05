# Clean-host recovery drill

The combined hosted flow passed its
[merged PR #194 integration](../../../deploy/validation-clean-host-restore.md), including
current-key/database recovery and both retained source-host TLS routes. Later
changes still need their own required checks. This isolated
fixture does not complete W7-5, a public operator drill, protected-host issuer
restoration or durable off-host backup custody.

The dated Canonical image is pinned by SHA256 and checked against its signed
checksum list. The signing fingerprint comes from Canonical's
[cloud image verification guide](https://ubuntu.com/docs/public-images/public-images-how-to/verify-image-checksum/).
The [NoCloud seed procedure](https://ubuntu.com/docs/public-images/public-images-how-to/use-local-cloud-init-ds/)
supplies per-run client and host keys; SSH checks the prebound host key and
accepts no passwords. Only the SSH forward binds to host loopback. No source
filesystem or Docker socket is shared with the guest.

`Fresh recovery target` is a manual hosted-only workflow. It checks a new
machine/boot identity, empty deployment/database paths, and an empty Docker
daemon before returning closed decisions and runtime versions. Apt installs
the distribution's signed Docker packages. The harness stops only its owned
QEMU process on success or failure. Raw disks, seeds, keys, console output and
machine identifiers are private and are never uploaded. Only
`target-result.json` is eligible for publication. Temporary hosted storage is
not an independently retained recovery copy.

Run the source refusal checks without launching a guest:

```sh
python3 -m unittest discover -s server/tests/recovery -p 'test_*.py'
```

## Combined installed-device drill

The installed-native workflow calls `restore.py` after the real shared-token
cutover and native Rotate. It leaves the OPNsense guest and independent client
running. The source must have exactly the six owned services and a current
post-rotation independent backup. This is an isolated fixture driver, not a
general production restore CLI.

1. Prepare a distinct empty Linux guest and privately transfer the same tested
   images. Bind the source archive's configuration digest to each running
   container, hash every uncompressed layer against the config's rootfs diff IDs,
   then export the loaded target images and compare all configuration/layer
   identities. This permits a different Docker storage backend without accepting
   changed image content. Create only new empty target volumes.
2. Acquire the same host operation lease used by relay maintenance. Stop source
   writers, create and hash a new restricted custom archive, and compare all
   public tables, sequences, owners, ACLs and role metadata before/after the dump.
   Stop the original PostgreSQL service as well.
3. Transfer current deployment files, the original and successor secret backups,
   complete retained operation history and stopped Caddy/backup volumes over
   pinned SSH. A bounded private archive refuses links, traversal, foreign owners,
   duplicate paths and existing data. Restore exact bytes and numeric ownership;
   never run initialization to generate replacement credentials.
4. Bootstrap approved roles on a new PostgreSQL cluster, verify its distinct
   system identifier and schema-empty database, then restore in one transaction
   with ownership and ACLs. Compare the complete private database fingerprint
   before application startup. Start the normal services and run database role,
   audit-chain, current-file and service separation checks.
5. Forward the unchanged logical endpoints to the recovered host. Log in with
   the original administrator credentials from the source host and inspect its
   original inventory over verified HTTPS. Select an owned primary-interface
   address outside the Docker edge subnet using read-only route metadata. Send
   normal Open requests from that bound address to the existing private Caddy
   endpoint, with the same session, CSRF token, canonical origin and verified
   HTTPS hostname. Match each response's expiry to the exact persisted
   actor/source grant; a newer unrelated grant cannot select the forwarding
   path. The browser forward uses that same owned address. No grant is inserted,
   forwarding header forged or service binding changed. Both original assigned routes must recover with
   verified TLS. Native model and GUI identity/security checks must be unchanged;
   no native restart, Rotate or new enrollment is performed by this driver.
6. Remove the owned target stack and stop its guest. Recover the original fixture
   services, wait for both clients to reconnect again, then continue genuine
   native Remove and the complete existing Compose cleanup tail.

Only the closed `installed-host-restore.json` is added to public exports. The
restricted dump, file inventory/hashes, SQL rows, transferred images, console
state and key material stay private. The original control connections are
necessarily replaced by the planned host outage; later removal uses the
reconnected control as its baseline. Independent encrypted, durable custody and
public/operator checks remain separate requirements, even after this drill passes.

The fixture does not restore a separately configured protected host issuer's
ACME account, HTTP-01 publisher policy/state, installed helper binary or systemd
services/timers. A production cold-host procedure must preserve that state,
quiesce those writers and verify resumed issuance separately. Six-service
recovery alone does not establish this certificate-automation recovery scope.

A refused source payload reports only a fixed reason, source category and bounded
octal mode. File names, paths, owners, content and raw child diagnostics remain
private. This diagnostic does not relax source permissions or archive admission.

Database comparisons retain table contents, sequences, ownership, object/column
and default grants, role memberships/settings, function definitions, extensions,
RLS policies, constraints and indexes. A mismatch reports only fixed category
names and the comparison phase; private rows, names, grants and hashes remain
private. The actual custom-archive regression uses a second owned database and
substitutes only that fixture's database name. The separate-host drill requires
the original database identity without that substitution.

Relation grants use PostgreSQL's `acldefault` only when the stored ACL is NULL;
an explicit empty ACL is still empty. Owner, grantee, grantor, grant options and
RLS flags remain compared. Constraint definitions use PostgreSQL's own pretty
deparser on both sides under the same tested image, preserving expression
precedence without a custom string rewriter. These comparison forms distinguish
actual authority from the default-ACL and associative-AND representations changed
by a logical dump/restore. They are not used to generate or edit the dump.
See PostgreSQL's [catalog function semantics](https://www.postgresql.org/docs/16/functions-info.html).

The dump omits extension ownership. Before import, the driver checks the retained
inventory and creates only the approved pgcrypto 1.3 extension as its original
`nethub_owner`, with the original public schema. The existing plpgsql metadata
must match. Unknown extensions, changed owner/version/schema and conflicting
existing material are refused; no existing extension is repaired or reassigned.
The complete fingerprint still checks extension metadata after import.

Real PostgreSQL negative controls add a table grant, change its grant option,
revoke an owner privilege, and change a constraint's lower bound, hash prefix
and boolean operator. Each must change the fingerprint, and reverting them must
recover the original fingerprint. Full dump/restore, original Web safe-column
access and credential-column refusal remain independent requirements.

`Recovery database diagnosis` is a separate hosted workflow for changed recovery
sources and manual runs. It builds the
same PostgreSQL image and bootstrap hooks, applies the actual migration Up DDL as
its normal owner, dumps as the restricted backup role and compares default,
session-authorization and precreated-extension restore modes. Its closed report
contains only fixed categories/field identifiers and missing/extra-object flags.
Raw SQL output, dumps, credentials and logs are never uploaded. This experiment
diagnoses restore semantics; it does not run the application migration CLI,
recover a separate host, preserve production state or accept a successful mode
as complete application restoration. The strict installed-device drill remains
required. No restore-mode change is selected automatically from this report.

On reconnect failure, both original routes are checked independently. A read-only
diagnostic records only native/witness process availability, route verification
booleans and each exact proxy's online/offline/absent/unavailable state from the
restored private admin API. Raw responses, configuration, identities, credentials
and addresses remain private. Unavailable observations stay explicitly unknown;
they do not count as an offline proxy or explain a failed TLS route. This does
not restart either client, change its saved assignment, create a source grant or
extend the recovery success deadline.

The source probes also retain only numeric curl exit/HTTP status and route
verification booleans. After a failed reconnect, separate read-only probes on
the target bind the already admitted Open source, use each original SNI and CA,
and require the original GUI/witness response. Their output is limited to fixed
transport, TLS, HTTP and payload outcome labels. This distinguishes source-side
forwarding failures from target-local route failures without exporting addresses,
certificates, response bodies or exception text. A target-local success is only
diagnostic; it cannot substitute for either original source route or extend the
90-second reconnect success window.

Failure diagnostics further distinguish certificate-identity rejection from a
closed TLS stream and other handshake errors. Bounded private authz logs yield
only counts of fixed NewUserConn decisions; raw lines and extra fields are not
exported. A separate rollback-only transaction calls the real source-access
function under the authz role for the already granted address, returning only
two booleans or explicit unavailable states. It never inserts or renews a grant.
These observations distinguish admission from transport symptoms without
treating a zero log count, an unavailable query or a local probe as acceptance.
The closed log projection separately counts fixed device-state and source-access
denial causes. Older decisions without a cause remain explicitly unavailable.

The pinned frps 0.71.1 rejection log also records the actual user connection
peer before its work connection is acquired. The failure-only projection reads
that existing private log and emits only bounded counts comparing rejected peers
with the address admitted by normal Open, plus fixed loopback/private/other
categories. IPv4-mapped peers are normalized. Addresses, ports, proxy identities
and rejection text are never exported. Missing entries remain explicitly
unavailable; malformed or excessive observations are refused. This adds no
request logging to the product, does not restart a service or create a grant,
and cannot turn a failed route into recovery acceptance.
