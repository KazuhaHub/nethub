# Router certificate requests

The certificate boundary accepts a signed P-256/SHA-256 CSR for exactly the
device's assigned DNS name. It rejects other identities, wildcards, extra SANs,
subject fields and requested certificate extensions, malformed signatures,
unsupported keys and ambiguous PEM. Public output has defensive copies and no
ordinary JSON representation. Errors contain no submitted data.

This supports a device-generated private key: the issuer receives only a CSR,
and returns the public certificate chain for installation beside the retained
device key. The caller must authorize the current tenant/device/hostname before
validation; this function does not implement authorization, ACME, persistence,
authenticated transport, OPNsense installation or any renewal scheduler.

Those components and relay renewal/trust automation remain required by
[the certificate lifecycle design](../../../docs/certificate-automation.md).
