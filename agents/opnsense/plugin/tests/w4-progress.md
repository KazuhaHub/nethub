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

## Native upgrade and recovery

All six checks passed on 4c8361e1a46f2e016920c656a7c2b8a0ae9b513b
(run 39259650675). Plugin CI ran 170 checks; only the existing native FreeBSD
lockf check was skipped on Linux. New HTTPS/POSIX/PHP tests ran. Deployment logs
confirm all four image scans and bundled/external/browser/relay regressions.

An initial Windows subtree export inherited CRLF and failed before building or
installing a package. The native exporter and platform LF attributes were fixed.
The exact 4c8361e development package built and installed on OPNsense 26.7.7:
SHA256 8fe6a5f15175927e3033bcc10c441682b1f4f804544965767555d6fc96bde9f9.
Installed checksums, all twelve real model fields and native validation passed.
The new browser page has enrollment controls, filtered public APIs and no debug
editor; the old debug getter returns 404. Local browser TLS was a pinned,
self-signed appliance fixture; this does not waive console HTTPS verification.

Before changing the device, an independent nonce-bound restore watcher was
rehearsed on the actual machine. Both the timed rehearsal and post-upgrade
restoration passed: native model field values, eleven owned runtime files,
original stopped service intent and absence of request tokens. Canonical hashes
of the system and unrelated configuration matched. Original credentials and SSH
policy stayed unchanged; the tested 0.0.3 package remains installed. The upgrade
window is closed and its watcher has exited. Private backups and logs are retained.

The console now also displays/copies its origin beside the opaque token; browser
tests check both values and screenshots mask both fields.

## Public console and actual native enrollment

PR #58 merged as a3bc4da after all six checks passed on
d1c8f34c7e897709f6a886589d4ed0594ab11363 (run 39264535841); actual job logs
were inspected. Deployment logs include all four image scans, complete real
browser/relay/external-proxy flows and renewal/rollback/two-client recovery in
639 ms, with the actual host timer. Plugin CI passed 170 tests with the existing
FreeBSD-only lock test skipped on Linux.

Native acceptance used a fresh isolated database and authority and all four exact
CI images. Installed package source and build inputs matched the tested server
revision. The actual OPNsense 26.7.7 NAT guest enrolled through its browser UI
against independently verified public console HTTPS. Click to online inventory
took 3.642 seconds. The native model contained the assignment, initial CA material
matched its mode-0600 file, frpc was running, and the consumed request was absent.
The browser cleared the token input; page errors and external requests were zero.
Repeated enrollment returned the existing assignment without another server
request. Settings remained filtered and the old debug endpoint returned 404.
Checked assignment credentials were absent from five device logs and service logs.

The public window lasted 103.551 seconds. Independent restoration was armed
before changes. Original services/listeners were restored, test control port
closed, both authorities unchanged and scoped doctor passed. Device model values,
eleven owned files, stopped service intent and system/unrelated configuration
hashes matched the baseline; the watcher exited. Root credentials, password SSH
and GUI security checks were unchanged. The owner-approved 1 GiB lab exception
remains; local GUI access used the pinned self-signed lab certificate. This is
native enrollment acceptance, not formal GUI certificate or full W4 acceptance.

W4-8 unenroll/status,
authenticated trust distribution, CA rotation, expired-candidate replacement
and GUI ACME issuance/installation/renewal are not implemented by this increment.
