# Protected host worker

`nethub certificates issue-gui` advances one queued GUI certificate job in an
existing Linux deployment. It uses the durable SQL coordinator and account
store, with an independent HTTP-01 cleanup service. It does not initialize an
account, accept CA terms, generate device keys or apply certificates to a router.
Console HTTPS remains the reverse proxy's responsibility.

## Deployment prerequisites

- An initialized deployment with its independently verified authority backup.
  Ordinary work verifies that retained identity before discovering a database.
- A protected, explicitly initialized and registered ACME account. Registration
  and current CA terms consent remain separate operator actions. The ordinary
  worker performs an offline account readiness check and never replaces keys.
- An existing HTTP-01 namespace and root-owned mode-0600 cleanup policy. Its
  device suffix must match the setup manifest and it must exclude the manifest's
  console hostname. Extra exclusions may narrow publication.
- An active independent cleanup timer, successful service result and complete
  namespace-bound cleanup observation younger than two minutes. Failed scans
  supersede previous success. The worker rechecks this gate before each phase
  and publication; it cannot substitute its own successful issuance for cleanup.
- The current schema, forced certificate RLS, enabled identity/cancellation
  guards, and the restricted no-login issuer role and function grants.

The host is trusted, including root and the local Docker daemon. Discovery uses
the fixed local socket, explicit project and protected Compose files; it verifies
full container/image IDs, working directory, read-only secret/hook bind mounts,
the exact data volume and its project labels. The SQL runner rechecks the exact
portless, nonprivileged running database before each stdin-only SQL operation.
This does not confine a compromised root account or Docker daemon.

## Authenticated initial queue

The authz server's certificate endpoint uses `GUIJobQueue` when configured with
the device domain. A successful signed-request submission commits the immutable
CSR, generation-one job and requested/queued audits in one device-locked
transaction. A queue error rolls all of them back. Identical submissions return
the same public request and retain the same initial job; changed signed bytes
still conflict. No issuer job ID or internal checkpoint enters the public reply.
Settings reads stay read-only. A previously admitted metadata-only request is
queued on its next identical submission, without replacing that request.

Initial admission does not create a CA account or start a worker. The explicitly
provisioned host command must satisfy the prerequisites above. Device revocation
cancels its queued work in the same database transaction and the certificate API
denies later reads. Renewals require separate generation/due authorization;
retrying initial admission never authorizes a renewal.

## Explicit policy and invocation

Adapt `deploy/gui-issuer.example.json` to the deployment and install it as
`/etc/nethub/gui-issuer.json`, root-owned mode 0600. All nine fields are required;
unknown/duplicate fields and null origin lists are refused. Paths must be
absolute and canonical. The example directory/contact are placeholders.

`api_roots_file` controls HTTPS trust for the ACME API. Independently,
`certificate_roots_file` controls trust for issued GUI chains. An empty value
explicitly selects the system trust pool. A configured root-owned public PEM
bundle must contain CA certificates only; the worker does not obtain trust from
an order, certificate response or management endpoint. Account policy also
constrains every saved remote URL to configured HTTPS origins.

```sh
/usr/local/libexec/nethub certificates issue-gui \
  --directory /srv/nethub-deployment \
  --project-name nethub \
  --config-file /etc/nethub/gui-issuer.json
```

Use `--compose-file /absolute/protected/override.yml` if the running deployment
uses an additional override, matching relay maintenance. It is not a way to
select another deployment's secrets or volume. JSON output contains only a fixed
state and step count. Errors do not print SQL, account state, CSRs or CA replies.
Idle and deferred work exit zero; terminal work/readiness failures exit nonzero.
An occupied namespace or host lock skips without acquiring a job lease.

Each invocation has a three-minute budget and at most sixteen coordinator steps.
Each host command is independently bounded with scrubbed environment and capped
output. Pending CA work releases the job for the durable queue's retry policy.
The worker stops acquiring remote work before its deadline is too short for
renewed lease safety; interruption recovery retains the original job/order/CSR.

The optional `deploy/systemd/nethub-gui-issuer.*` units schedule one invocation
per minute, offset from cleanup. Install only after prerequisites are satisfied;
review exact paths/project/overrides in the service. The units neither provision
an account nor authorize public CA registration. Root's Docker access remains
privileged despite service filesystem and capability restrictions. The service
retains `CAP_DAC_OVERRIDE` to verify hashes of mode-0600 service-owned secrets;
removing it prevents the required authority preflight. Custom paths
need matching `ReadWritePaths`; home directories are masked. Do not automatically
enable these units in existing installations while provisioning is incomplete.

## Evidence and remaining wiring

The opt-in `TestPebbleProtectedHostIssuer` uses a fresh generated deployment and
independent backup, genuine Compose PostgreSQL, the compiled production CLI,
registered private Pebble account, independent API/issuing roots and real Caddy
HTTP-01 serving. It verifies idle discovery, stopped-cleanup-timer refusal,
original-key issuance and idle retry. CA logs independently verify one order and
one finalization. An outer exact-resource expiry guard precedes the test; normal
and expiry cleanup remove only that nonce's services, volumes, networks and keys.

The host fixture's cleanup timer uses explicit temporary paths under a private
home; it does not claim the shipped cleanup sandbox. The shipped cleanup unit has
separate genuine native acceptance. The issuer service template is run with
fixture paths/project and read-only home access instead of masked home, retaining
its strict system filesystem, privilege restrictions and explicit writable paths.
Public CSR metadata is administratively
seeded only in this labelled disposable database, and retry time is advanced
only there. The separate compiled HTTP/database fixture checks actual enrolled
device CSR admission and atomic queueing, failure rollback, duplicate audit/job
refusal and cancellation after revocation. These remain separate from combined
enrollment-to-issuance acceptance, production recovery timing, renewal authorization, issued-chain
delivery, native GUI installation/rollback, or staged trust transitions. Those
remain required before W4 certificate automation is complete.
