# Router certificate requests

The certificate boundary accepts a signed P-256/SHA-256 CSR for exactly the
device's assigned DNS name. It rejects other identities, wildcards, extra SANs,
subject fields and requested certificate extensions, malformed signatures,
unsupported keys and ambiguous PEM. Public output has defensive copies and no
ordinary JSON representation. Errors contain no submitted data.

The chain validator revalidates the signed CSR and binds the leaf to its public
key and exact assigned SAN. It requires independently supplied roots; certificates
returned by the issuer cannot grant their own trust. Bounded canonical PEM must
contain an ordered, nonduplicate current server chain, without keys or unrelated
certificates. Public status includes the leaf dates and the earlier effective
chain expiry. Raw installation bytes are excluded from JSON and copied on return.

This supports a device-generated private key: the issuer receives only a CSR,
and returns the public certificate chain for installation beside the retained
device key. The caller must authorize the current tenant/device/hostname before
validation; these functions do not implement authorization, ACME, persistence,
authenticated transport, OPNsense installation or any renewal scheduler.

Those components and authenticated relay trust distribution remain required by
[the certificate lifecycle design](../../../docs/certificate-automation.md).
