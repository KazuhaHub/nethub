# Public CA chain format diagnostic

The guarded public-CA trial reached genuine HTTP-01 validation and certificate
issuance, but the host issuer rejected the downloaded chain. No GUI certificate
was installed. The created device was revoked and the original native baseline,
managed trust, restart script, fourteen services and listener owners were
independently verified after restoration.

A separate bounded diagnostic inspected only that existing order, authorization
and certificate using the retained account. It performed no registration, new
order, challenge acceptance or finalization. The order and authorization were
valid; certificate download returned HTTP 200. The response contained blank lines
between certificate blocks. Raw chain inspection failed, while canonicalizing
the same certificate blocks passed both exact CSR/name/key inspection and
independent system-root verification. The account and original services remained
unchanged. Operational addresses, certificate bodies and private receipts remain
outside the repository.

The defect was a byte comparison against an entirely canonical PEM response.
The validator now compares each consumed block after normalizing CRLF, permits
ASCII separators between blocks, and returns canonical installation bytes.
Checking consumed bytes preserves rejection of text or malformed blocks that
`pem.Decode` could otherwise skip. Certificate size/count, headers, signatures,
validity, identity, usage, ordering, duplicates and independent trust checks remain.

Regression tests fail against the previous implementation for blank separators,
CRLF and spaced separators, including signed ACME finalization with a real TLS/JWS
fixture. The corrected finalization and saved-order recovery return identical
canonical material with one CSR submission. Refusal tests cover prefix, suffix,
interblock text, nested or malformed skipped blocks, and Unicode separators.

The same bounded read-only diagnostic was then rebuilt with the corrected
production parser and fetched the same existing certificate again. Its raw
response passed inspection, while independent system-root validation still
passed. No new order or finalization was performed, and the account and original
services remained unchanged.

This diagnostic establishes the format defect and successful issuance, not
native public-certificate installation or full W4 acceptance. The failed trial
retains its original outcome; combined certificate acceptance and W5-W7 remain
incomplete. The existing 1 GiB native resource deviation also remains.
