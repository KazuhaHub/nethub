# Generated certificate admission configuration

The generated authorization-service command omitted `--device-domain`. Enrollment
and relay trust worked, but the native GUI certificate settings endpoint returned
404 because certificate admission was not configured. The generator now passes
the deployment's device domain to both the web and authorization services, in
bundled and external reverse-proxy modes.

## Observed failure and control

On 2026-10-23, guarded tests used the retained isolated deployment and unsigned
native package 0.0.14. Actual browser enrollment and exact operator-configured
Alternate Hostnames succeeded. Certificate synchronization stopped before
issuance. The new test enrollments were removed through the genuine device
protocol before restoring the appliance checkpoint; their history was retained.
These attempts do not establish certificate installation or renewal.

A focused diagnostic used an existing active device without another enrollment
or CSR. The request included the configured console Host header and original
device credentials. Inspection of the actual authorization container confirmed
that its command lacked `--device-domain`.

| Configuration | HTTP result | Native settings parser |
| --- | --- | --- |
| Retained generated command, no domain argument | 404, `not_found` | No settings returned |
| Same service with the exact device domain supplied | 200 | Passed |

The positive control changed only the owned authorization service through a
temporary Compose command override. PostgreSQL device, token and CSR records
were identical before and after. The override was removed and the original
service command restored. Independent closure checks confirmed all 14 original
running container identities, original public listener owners and service
configurations, with the isolated stack stopped. Private credentials, responses
and container inspection data remain outside Git.

## Regression and limits

`TestGeneratedCertificateAdmissionDomain` generates real deployment bundles in
both proxy modes and checks that web and authorization commands contain exactly
one matching device-domain argument. Both cases failed against the previous
generator and passed after the change. Local setup, device and protocol tests
passed; hosted checks remain a separate merge gate.

This corrects newly generated bundles. Existing protected bundles are not
rewritten automatically. Do not edit their manifests or replace retained
authorities to conceal the configuration difference. Complete native GUI
issuance, natural renewal, application retry, wrong-host/key rejection, rollback,
offline recovery, reboot persistence and UI removal still require their own
acceptance evidence. The private CA fixture does not establish public CA trust
or authorize registration with a public CA.
