# Deployed OIDC acceptance with two Dex issuers

`server/tests/oidc-compose.py` tests the production binary, console and database
against two official Dex instances. It uses an independent fresh deployment after
the existing Compose suite; it does not replace the SQL, signed-IdP unit or native
appliance checks. A successful run is scoped to these disposable issuers. It does
not establish public-provider, SAML, mobile or complete W6 acceptance.

PR #176 was accepted at source `8ca3583c73ff` and merged as `14a12537e340`.
Run `40338271728` passed all six exact-head jobs. Actual logs, all inherited
gates, eleven DCO sign-offs, both final hosted screenshots and their hashes were
reviewed. The merged tree equals the tested tree. The previous failed fixture
trials remain retained; they are not counted as successful acceptance.

## Runtime and trust

The test pins official Dex v2.46.1 by its multi-platform registry digest. The
release's static-password configuration supports explicit `emailVerified:false`;
the fixture includes that value instead of relying on Dex's default. An independent
client uses `authcore/oidc` to verify the actual signed false claim before the
NetHub invitation rejection is tested. The probe has its own one-use state and
cannot create a NetHub session.

The disposable Caddy configuration serves a static claim-probe callback. Browser
request events capture its real redirect URL; the test does not rely on
Playwright routing intercepting a later redirect hop. For the state-tampering
case only, a fixed test header parks the genuine callback at Caddy before Web
consumes it. The browser then removes that header and navigates to the altered
state. The normal Web callback and its SQL refusal remain under test, and the
original valid flow must remain unused. These routes exist only in the generated
test configuration.

The four deployed images come from the preceding assembled-image acceptance
archive. Its SHA256, image IDs and filesystem-layer identities must match before
reuse. The helper is built as a separate Docker target and is absent from the
product image. Private host exceptions are restricted to `dex-one.test` and
`dex-two.test`; other destination policies remain active.

An ephemeral CA signs a two-hour certificate for the three test origins. Caddy
terminates HTTPS; Web receives only the public test root and its normal deployment
secrets. The CA private key is never written to disk or mounted in a container.
Chromium uses an isolated HOME/NSS database containing the public root, with
`ignoreHTTPSErrors:false`. Backend discovery, code exchange and the independent
probe retain CA and hostname verification. A loopback-only CONNECT proxy routes
only those three HTTPS authorities and passes TLS through unchanged.
The isolated trust database uses Chromium's
[current Linux NSS location](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/linux/cert_management.md),
`$HOME/.local/share/pki/nssdb`, matching the pinned Chromium 151.

## Browser and database checks

The administrator configures both issuers through the actual management page.
The browser opens invitation fragments and uses the real claim/sign-in controls.
Genuine PostgreSQL observations verify the resulting accounts, identities,
invitation consumption, encrypted credentials, sessions and audit events.

The run requires:

- A claim through the first issuer and a subsequent login through its durable
  issuer/subject binding; a separate restricted claim through the second issuer.
- Refusal of an existing local mailbox and of the first user's same email and
  subject at the other issuer without an invitation. An independently verified
  second-issuer assertion must confirm subject equality. Neither attempt may
  create an account.
- Refusal of the wrong issuer for a restricted invitation, with the grant unused.
- Refusal of the independently verified signed false email claim, with no account
  or invitation consumption.
- Replay refusal after an actual Web restart, with the original browser binding,
  no additional session and a state-invalid audit reason. The existing SSO session
  must survive restart. A tampered state must leave its valid flow unused.
- Immediate refusal of an existing disabled user's session and subsequent valid
  IdP login, together with the existing local administrator remaining available.
- Separate real SSO members seeing only their own seeded device rows and receiving
  404 when trying to revoke the other's row with valid CSRF. These device rows are
  deliberate inventory fixtures, not agent enrollment or tunnel evidence.
- Required authentication/provider/invitation/disable audit events, no private
  authentication values in service or audit logs, no console cookies sent to an
  IdP, and zero unexpected requests, browser errors or console CSP violations.

The test honors a real `Retry-After` before at most one explicit retry; production
rate budgets are unchanged. Successful screenshots and their hashes are retained.
Credentials, callback material, protocol state and detailed private diagnostics
are excluded from uploaded artifacts.

## Running and cleanup

Run on an isolated Linux Docker 28+ host with Compose, Chromium/Playwright,
`libnss3-tools`, curl and Node 24. Supply the exact image archive directory emitted
by `NETHUB_IMAGE_EVIDENCE` from `server/tests/compose.sh` and a fresh evidence path:

```sh
sudo --preserve-env=NETHUB_NODE_BINARY,PLAYWRIGHT_BROWSERS_PATH \
  python3 server/tests/oidc-compose.py /path/to/accepted-image-archive /path/to/new-evidence
```

The program refuses unrelated image tags, conflicting image identities, existing
evidence directories, externally owned Compose resources and occupied relay test
ports. It never stops an existing service or prunes global Docker state. Container,
network, volume, newly loaded image and private-directory cleanup are checked;
preexisting image references are retained. If cleanup cannot be confirmed, the run
fails and keeps protected bind sources with a recovery pointer outside uploaded
artifacts. A green workflow plus exact-head logs, result checks and manual review
of both final screenshots are required before accepting a run.
