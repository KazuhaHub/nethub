# W4 enrollment implementation and acceptance

The development package moves to 0.0.3 without changing the 1.0.0 wire contract.
It implements the confirmed separate console HTTPS address and one-use token
flow. The runtime Python client has no jsonschema dependency: it validates known
fields, bounded optional extensions, current CA material and claim identity,
then returns selected fields only. PHP independently validates them and writes
through the native model/configuration lock. The settings/debug credential
editor is removed.

The token crosses configd only inside a private mode-0600 request file. The
helper checks the canonical parent, owner/mode/type/link count and bound, opens
without following links, consumes/unlinks once, and performs verified HTTPS.
It refuses redirects, ambient proxies and ambiguous/oversized/deep JSON.
The helper has an internal deadline and a separate base-system timeout wrapper;
configd output is uncached and stderr never includes submitted material.
The browser receives fixed results and public device status, never credentials.

Initial CA material persists in the model and is reconstructed on reconcile.
It cannot silently replace a different existing CA; authenticated root transition
and acknowledgements remain required. An enrolled device does not request another
token. Saved enrollment survives tunnel-start failure and can be applied again.
A response lost after server commit does not authorize reuse of the consumed
token; orphan recovery requires console inspection/revocation.

## Evidence so far

Windows tests exercise actual local TLS with a generated test CA, successful
enrollment, ignored proxy variables, hostname/root rejection, redirect rejection,
oversize/duplicate/encoded/truncated responses, response/claim/origin boundaries
and existing wire examples. POSIX handoff and full reconcile cases require Linux
CI or the target appliance. Real TLS testing caught a closed-socket deadline
update after complete HTTP responses; the corrected reader also rejects a
declared-length truncation.

Read-only runs on the actual OPNsense 26.7.7 test guest passed six PHP syntax
checks, native OpenSSL assignment/origin validation, and eight controller
contract scenarios using isolated model/backend fixtures. Those scenarios cover
save-under-lock, failed start, invalid response/model, existing device, wrong
method, read-only user and contention. They do not substitute for actual Phalcon
model persistence or native browser enrollment. The base timeout probe killed
a bounded sleep with exit 124 after 1.069 seconds; no appliance configuration
or login policy was changed by these checks.

Current-head CI, package upgrade and actual public-console → native plugin →
relay → online-device/browser acceptance remain pending. W4-8 unenroll/status,
authenticated trust distribution, CA rotation, expired-candidate replacement
and GUI ACME issuance/installation/renewal are not implemented by this increment.
