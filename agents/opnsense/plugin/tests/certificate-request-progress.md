# Immutable device certificate requests

`certificate_request.RequestStore` prepares one PKCS#10 request for an existing
protected P-256 device key, exact DNS assignment and expected bound fingerprint.
It never initializes/replaces a key or contacts an issuer. The caller must hold
the shared mutation lock and authorize the live assignment before using it.

The fixed DER profile has an empty subject, the existing public SPKI, one
noncritical SAN containing only that assigned DNS name, and ECDSA with SHA-256.
Only public request information enters the signing process; the private key stays
in its existing file. Base OpenSSL signs with bounded fixed arguments and verifies
each generated or loaded request. Verification requires both a successful exit
and the exact positive verification diagnostic: the first Linux CI run exposed
OpenSSL returning zero after rejecting a mutated signature. That failure is
retained and a regression covers the zero-exit failure response. The loader reconstructs the expected canonical
request information and algorithm before checking the signature, rejecting other
names, attributes, keys or request profiles. Child diagnostics are not returned.

An owned 0700 directory contains one canonical 0600 single-link JSON record.
File/directory fsync precede atomic directory publication. Repeated reads return
the exact saved signed bytes; they do not create a new ECDSA signature and job
fingerprint on each poll. Changed assignments/bindings, missing key material,
unknown contents, malformed/noncanonical state, invalid signatures and unsafe
paths/modes/links fail without replacement or permission repair. A failure after
publication can reuse the committed request; unpublished partial files are not
adopted.

This is an initializer/cache component, not a certificate polling endpoint.
There is no API/configd/cron integration, CSR upload, issuance authorization,
certificate installation, cleanup integration or package upgrade in this change.
Future job state must distinguish a first request from loss of an already
submitted cache, recover the original job rather than initialize blindly, and
remove only the owned cache after confirmed assignment removal. Different live
assignments require an explicit transition, not automatic cache replacement.

Local tests passed 24 cases with three POSIX-only skips, exercising real OpenSSL
signatures/reuse, maximum DNS length, invalid
identities, changed bindings/assignments, a valid signature for another name,
corrupt/ambiguous records, key loss, child failures, interruption boundaries and
POSIX storage refusal. The corrected native FreeBSD run passed all 27 cases and staged source/dependencies privately
without installing packages or changing appliance configuration. A generated
native request also passed the production Go `ValidateBoundCSR` validator; wrong
host and missing binding were rejected. Native temporary key material was removed.
Current-head CI remains a merge gate. Full GUI certificate acceptance remains open.
