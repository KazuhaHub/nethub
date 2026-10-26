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

The browser check covers provider-restricted invitation claims, stable
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

## Accepted source and evidence

PR #182 merged as `e5b412b` with the same tree as tested head
`9ed3c0d5bc02622cab120dfbc25c8a2a522a7ec7`. All six jobs passed in
[run 40410562829](https://github.com/KazuhaHub/nethub/actions/runs/40410562829).
Actual logs retained all inherited database, process, deployment, cleanup,
vulnerability and two-Dex gates. Three human DCOs, all eight selected image hashes
and their visual output were checked before the protected merge.

Ten actual Keycloak browser/SQL checks passed. Alice's signed SAML email admitted
the invited account even with Keycloak's OIDC `emailVerified` flag false. Fresh
IdP sessions retained the persistent identity; a real Web restart retained the
database session. Replaying the signed response, presenting the wrong browser,
changing signed email and matching an existing administrator mailbox were
refused. The original valid browser could still complete after wrong-browser
refusal. Live disable rejected the retained cookie and another valid IdP login,
while local administrator recovery stayed usable.

Both actual SAML member screenshots showed only their deliberate owned fixture
rows. Normal TLS remained enabled, with zero CSP violations, script errors,
unexpected destinations or console-cookie leaks. Service logs were checked for
generated authentication material. Exact owned resources and private temporary
material were removed. The first navigation-response read failure and the later
independent formatting failure remain retained; neither is used as a successful
overall-run receipt.

This is an isolated official IdP deployment, not a public-provider or mobile
test. Assertion encryption, real device enrollment/tunnels, complete W6 and the
full HANDOFF goal remain separate acceptance. Local syntax/fixture checks alone
would not establish these deployed results.
