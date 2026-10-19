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
retained key identity; full current-head CI remains a merge gate.

This is key storage and admission wiring, not full GUI certificate acceptance.
The 0.0.6 source has not been installed or enrolled against a fresh server yet.
Account/job persistence, current-assignment issuer authorization, actual ACME
orders, signed CSR submission, certificate delivery, native import/application,
rollback and reboot/offline renewal remain required. Until native certificate
import exists, this key is outside XML configuration backups; loss of an enrolled
key requires restoring its protected runtime state or explicit re-enrollment.
