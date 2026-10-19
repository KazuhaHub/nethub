# Device certificate request API

`authz --device-domain <assigned-device-suffix>` enables two optional POST routes
under the configured HTTPS console origin:

- `/api/v1/devices/gui-certificate/settings` accepts the device identity and
  returns its live assigned hostname, enrollment key fingerprint and original
  signed CSR, or a null request before first submission.
- `/api/v1/devices/gui-certificate/request` additionally accepts `csr_der` and
  returns the exact committed public record. Identical retries are idempotent;
  another signed DER conflicts, even for the same key and hostname.

Both require the existing device-secret Bearer header and protocol >= 1.2 within
major 1. They share lifecycle's bounded per-source rate budget and Argon2 worker
pool, with a ten-second operation deadline. Certificate jobs must not poll this
admission boundary every heartbeat. Host/origin/proxy/body/media/method/query
checks and fixed no-store responses follow the existing device API. No request
body, credential, CSR or dependency diagnostic is logged. Invalid CSRs return
400, failed device/live-assignment authentication 401, changed requests 409 and
dependency/readiness failures 503. Limits retain the existing 429 responses.

The trusted suffix and database binding determine the hostname/public key; no
caller-supplied tenant, host or replacement key is admitted. The store rechecks
the verified credential hash and current assignment under the same device lock
as revocation. Responses validate device/name/key/DER/hash correlation before
encoding. `Health` requires the immutable-request guard and expected role grants.
The console origin must remain outside the assigned-device suffix.

The compiled authz integration fixture enables the flag against genuine
PostgreSQL and exercises actual HTTP enrollment with an initial public key,
settings, signed CSR admission, exact retry/recovery, changed signatures, wrong
SANs and rejection after revocation. Public Go/Python message examples are shared
with the protocol schema suite; their throwaway signing key is not retained.

This boundary enables request admission only. Default Compose settings do not yet
enable it. The installed native package is unchanged; agent wire helpers are not
connected to reconcile or a configd action. Durable issuer jobs, account policy,
HTTP-01 publication, certificate delivery, protected local-cache recovery and
native GUI installation/rollback remain separate integration work. No CA is
contacted and no private device key is uploaded by these routes.
