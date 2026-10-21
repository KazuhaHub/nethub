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

Newly created cache directories and records receive explicit 0700/0600 modes
before validation/fsync/publication, independent of a restrictive process umask.
The native regression first reproduced a successful initial return with mode-000
storage under umask 0777; the next read could not reuse that cache. Creation now
establishes and validates the required modes. Existing unsafe storage is still
rejected without permission repair.

`restore` accepts the original canonical public DER and hash from the authenticated
settings response. It requires the intact existing bound key, reconstructs the
same restricted request profile and verifies the signature before publication.
It never invokes the signer or creates a key. Identical recovery reuses the same
record; another existing signed request, corrupt storage or unsafe modes/links
are preserved for review. A hash match alone is not sufficient. Atomic publication
and fsync/mode checks are shared with initialization, including restrictive umask
and retry after a committed rename followed by parent-fsync failure.

This remains a cache component, not a certificate polling endpoint. Protocol 1.2
has separate server admission/recovery routes and agent wire helpers, but these
are not connected to configd/cron/reconcile or a package upgrade. Future job state
must distinguish a proven fresh assignment from loss of an already submitted
cache; a null server response alone does not authorize blind reinitialization.
Remove only the owned cache after confirmed assignment removal. Different live
assignments require an explicit transition, not automatic cache replacement.

The original cache tests passed 24 local cases with four POSIX-only skips, exercising real OpenSSL
signatures/reuse, maximum DNS length, invalid
identities, changed bindings/assignments, a valid signature for another name,
corrupt/ambiguous records, key loss, child failures, interruption boundaries and
POSIX storage refusal and restrictive-umask creation. The corrected native FreeBSD
run passed all 28 cases and staged source/dependencies privately
without installing packages or changing appliance configuration. A generated
native request also passed the production Go `ValidateBoundCSR` validator; wrong
host and missing binding were rejected. Native temporary key material was removed.
Current-head CI remains a merge gate. Full GUI certificate acceptance remains open.

The recovery extension passed 33 Windows/OpenSSL cases with five POSIX skips and
all 38 cases on native FreeBSD. It covers exact recovery without signing, another
intact signature, wrong name/key/hash/encoding/signature, missing key preservation,
restrictive-umask modes and post-publication retry. Native configuration remained
unchanged, package 0.0.6 stayed installed, and temporary test keys were removed.
The generated native request also passed production Go bound-CSR admission again.
