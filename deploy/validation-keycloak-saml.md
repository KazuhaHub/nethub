# Independent SAML deployment check

`server/tests/saml-compose.py` prepares a fresh production deployment and a
disposable official Keycloak 26.8.1 instance, pinned by registry digest. It reuses
the accepted product-image archive integrity checks and ownership-scoped cleanup
helpers. The six required CI jobs and their existing deadlines remain intact.
This check runs after the two-Dex deployment has removed its owned resources.

The browser imports real IdP metadata through the provider page, obtains the
actual public SP certificate and registers it with Keycloak. The client requires
signed AuthnRequests, emits signed responses and assertions, and returns the
persistent NameID and exact signed `mail` attribute. Registration and password
reset are closed. Generated credentials, SAML packets, cookies and diagnostic
stacks stay in the private temporary directory; only two selected inventory
screenshots and bounded result fields are eligible for artifact upload.

The planned acceptance covers provider-restricted invitation claims, stable
identity without a second invitation, database-backed session survival across a
real Web restart, response replay, browser binding, signed-email tampering,
existing-mailbox refusal, separate member inventories and account disable.
Inventory devices are deliberate SQL fixtures, not agent enrollments or tunnel
tests. The callback capture header parks a genuine IdP POST at the disposable
edge and must be removed before submitting it to the actual ACS.

Both browser and direct IdP administration use CA and hostname verification. A
private test CA is installed only in the isolated browser profile and Web trust
mount. Only the loopback TLS edge is published; the IdP has no host port and no
host privilege. Its development-mode writes are confined to its owned container
overlay. It is not a production Keycloak configuration example.

The test respects the production per-provider attempt limits and does not
relax them for its negative cases. Cleanup checks the exact project labels and
image identities and never prunes unrelated Docker resources. A failed cleanup
retains its private recovery pointer outside the artifact allowlist.

Implementation is under validation. No deployed Keycloak success, assertion
encryption, public IdP, mobile login or complete W6 acceptance is established by
the local syntax, TLS-fixture and orchestration-boundary tests.
