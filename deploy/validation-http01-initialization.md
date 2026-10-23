# HTTP-01 namespace initialization

The Linux root host executed the production CLI and setup test binary built from
`0ab6753`. All three initialization cases and eight refusal subcases passed without
skips. The compiled command returned `{"state":"initialized"}`; the ordinary
cleanup opener then accepted the real namespace.

The tests cover deployment-bound creation, unchanged identity on exact retry,
and refusal after loss of the private namespace identity. Before creating either
root, initialization refused a different device domain, missing console exclusion,
deployment overlap, writable parent, canceled context, unconfirmed deployment,
missing independent backup and a preexisting partial namespace. Rejected calls
left private state absent and preserved the partial public directory.

An independent timer used the existing exact-resource cleanup guard. Its receipt
confirmed removal of temporary authority keys and owned resources/units. A further
check found the control directory absent and the guard inactive; binary hashes
matched the tested inputs. All 14 original running container IDs and the original
Xray service remained running. No router, account registration, HTTP route or
public listener was changed.

Local policy/CLI tests, Go formatting, shell parsing and credential-history
controls also passed. Complete hosted regression and image acceptance remain
separate merge gates. This initializes publication metadata only; it does not
establish ACME issuance, native GUI installation or renewal. Private logs and
temporary-file receipts remain outside Git.
