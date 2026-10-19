# Device-owned enrollment certificate key

The 0.0.6 source generates and durably saves a P-256 PKCS8 key before requesting
one-use enrollment. Only its canonical public SPKI enters protocol 1.1; the
network helper requires the exact fingerprint acknowledgement before returning
the assignment to the existing native PHP configuration writer. Existing enrolled
devices skip key generation and cannot silently backfill their server binding.
The existing GUI certificate, root credentials and SSH policy are unchanged.

`certificate_key.py` uses the appliance's base OpenSSL with fixed arguments and
bounded execution, never key contents in command arguments or diagnostic output.
The private directory is 0700 and its key/record are owned 0600 single-link files.
The canonical record contains only the public key and fingerprint. Both files and
directory are synced before atomic publication. Existing key/record corruption,
links, unsafe ownership/modes and missing bound material fail without replacement.
An unpublished interrupted staging directory is not adopted automatically.

Enrollment now takes the same mutation lock as reconcile/removal, including the
configd entry point. Errors retain a successfully saved key for retry. Confirmed
removal and cleared native enrollment fields permit deletion of this runtime key;
the private key is removed before its record so interrupted removal can finish
explicitly without ever regenerating a missing bound key. The native certificate
store remains independent: an eventual GUI installation must retain its own native
key/certificate reference, and removal here must not destroy local GUI management.
Package uninstall continues retaining saved settings and private runtime state.

The focused native FreeBSD rehearsal passed eleven cases using new private test
directories: actual OpenSSL P-256 generation, ownership/modes, file/directory
fsync, reuse after opening another store instance, tampered record denial, no
regeneration after key loss, symbolic/hard-link rejection, wrong owner/mode
rejection, idempotent explicit removal and interrupted-removal recovery. Temporary
test keys were removed. The installed development package remained 0.0.4.

A second native run staged pure test dependencies privately and passed all 37
selected agent/reconcile/watchdog/lifecycle tests, including the actual FreeBSD
lockf exclusion test. The appliance configuration hash stayed unchanged and all
temporary test-key directories were removed. No dependency or package was
installed on the appliance. Local cross-platform key tests additionally cover
ambiguous PEM, pre/post-publication failures, child diagnostic filtering and
retained key identity. PR #65 passed all six checks at
`b320cebef7fdf3bb1d6963b8ff5100514ba45dcb` (run 39292394067),
including 249 plugin tests and the genuine deployment regressions.

The exact unsigned 0.0.6 development package subsequently passed native build,
installation, package checksums and the twelve-field OPNsense model checks.
A fresh private server used all four verified images from that same CI run and
protocol 1.1 with migration 00006. The real browser enrollment reached online
inventory in 9.006 seconds. Public console TLS verified normally; the relayed
router TLS leaf matched the existing appliance leaf observed through pinned SSH.

The appliance validated its private key locally; only its public SPKI and
fingerprint were compared with the immutable database binding. They matched
before and after a manual health report and an actual scheduled report. No device
private key was exported. Native removal took 1.849 seconds, cleared assignment
fields, stopped frpc and removed the runtime GUI-key directory. Repeated removal
passed; the revoked native client could not log in with its retained old claim.
The database showed one removal audit event and the revoked/offline device.
Token/assignment-secret scans passed in appliance and server logs; browser page
errors and unexpected external requests were zero. Masked enrollment/removal
screenshots were reviewed privately.

The 136.56-second public window closed with original listeners restored, test
control port closed, both authorities unchanged and doctor passing. Native model
fields, fifteen owned files, stopped intent and system/unrelated configuration
hashes returned to baseline. The independent watcher exited. Package 0.0.6 is
retained under the accepted 1 GiB lab exception; root credentials, password SSH,
Alternate Hostnames and both GUI security checks stayed unchanged.

This is key storage and admission wiring, not full GUI certificate acceptance.
The public router check pins the existing GUI leaf; it does not prove an
authenticated GUI session under a newly assigned hostname or a public CA leaf.
Private account persistence has separate accepted coverage; deployment wiring,
job persistence, current-assignment issuer authorization, actual ACME
orders, signed CSR submission, certificate delivery, native import/application,
rollback and reboot/offline renewal remain required. Until native certificate
import exists, this key is outside XML configuration backups; loss of an enrolled
key requires restoring its protected runtime state or explicit re-enrollment.
