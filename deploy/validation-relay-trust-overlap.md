# Native overlap and lost-response validation

On 2026-10-22, the installed OPNsense agent applied a two-root relay trust
generation. A loopback fixture discarded its first successful application-report
response after the backend committed. The native retry confirmed the application
without changing the frpc PID or CA bytes. PostgreSQL retained the first
acceptance timestamp, one application row and one audit event for that device
and generation.

The [sanitized receipts](validation-relay-trust-overlap.json) describe this
follow-up to [initial native enrollment](validation-relay-trust-native.md).
Credential-bearing assignments, configurations, process identities and logs
remain outside Git. This evidence does not complete W4.

## Inputs and environment

The relay used the four accepted images from [CI run 39828844165](https://github.com/KazuhaHub/nethub/actions/runs/39828844165),
built at `9ffcb2d`. Deployment and runtime inputs were unchanged through
`3b2d7fc`. The unsigned 0.0.12 native package was built at `e6ce45c`; its SHA256
was `3af38de19479bf24203c4f97eae081ae9d4b26acf39e42255bd6f17dc93c7b19`.
Both frp peers used 0.71.1 built with Go 1.26.10.

This deployment ran on a Linux LXC with 4 GiB RAM and Docker 29.2.1. Its
Python 3.11.2 runtime passed all eight accepted loopback fixture tests, including
the actual Linux/root admission and deadline cases, without skips. The four
loaded image manifests, configurations and layers were independently matched
to the accepted archive before use.

The OPNsense VM retained the owner-approved 1 GiB memory deviation. Enrollments
were performed sequentially on that appliance. A previously enrolled identity
remained active but offline at generation 1 while a separately enrolled live
identity applied generation 2. This is functional evidence, not capacity or
latency acceptance.

External-proxy mode used an independent private CA for console HTTPS. Windows
public-path HTTPS and TCP control-port checks passed before native enrollment.
Native requests retained chain and hostname verification. Application HTTP
origins remained bound to loopback. CA signing keys stayed outside
application mounts.

## Observed sequence

| Step | Evidence |
| --- | --- |
| Retained deployment | Resumption preserved the database, administrator, proxy container, authority/runtime files and exact initial publication. No new authority was initialized. |
| Live enrollment | Actual configd enrollment and native PHP validation saved a genuine assignment. The assignment was exported before rollback. Scheduled trust output confirmed generation 1, and frps reported the assigned HTTPS proxy online. |
| Offline enrollment | Its existing generation-1 application remained present and its device record stayed active throughout the live test. |
| Overlap publication | The protected host CLI prepared a successor, verified its separate same-host backup, and published generation 2 using compare-and-swap. Both old and new public roots were included; the active signer was unchanged. |
| First application | A worker holding the actual shared reconcile lock invoked the installed agent's trust action. The CA file contained both published roots. The native result was `applied_unconfirmed` after loss of the matching backend's accepted HTTP 200 response. |
| Backend commit | PostgreSQL held one application and one application audit event for the live device and generation 2. Its acceptance timestamp matched the response-loss receipt. |
| Retry | The native result became `applied` and confirmed. PID, CA bytes, first acceptance timestamp and application/audit counts were unchanged. frps reported the HTTPS proxy online after both samples. |
| Fixture restoration | The original proxy configuration was restored byte for byte, and the owned forwarder exited. |

The fault was scoped to one device, one generation and the application-report
endpoint. It forwarded the real authenticated request and waited for the real
backend result before discarding the response. There are no production fault
flags or fabricated native application reports in this measurement. The worker
used the installed agent under the same lock as scheduled synchronization;
it did not invoke the manual configd trust action for the overlap application.

Independent guards bounded relay and appliance windows. Final checks confirmed
the original 14 running container identities and original 443/8443 service
owners/configurations. Test services were stopped while the database and
authority state were retained. The appliance returned to its original 0.0.6
package, exact configuration and stopped intent through its cold checkpoint.

## Limits and remaining acceptance

An earlier manual configd trust invocation during initial synchronization hit
the harness's 95-second deadline. Later configd polls on an exported, already
applied model completed in 1.775 and 1.261 seconds, retained PID/CA bytes and
preserved the database's first acceptance. Those observations do not resolve
the initial timeout or establish which initial caller completed the application.
First-application configd latency still needs a controlled reproduction.

Successor preparation and overlap distribution do not establish signer
activation, old-root retirement, the all-active-device retirement barrier, or
offline manual recovery. Existing active enrollments were preserved; their
acknowledgements were not fabricated to bypass those gates.

An online frps proxy is not a browser login or a complete GUI certificate flow.
Browser enrollment, GUI certificate issuance/installation/renewal and the
combined public GUI path remain unverified. The console used a private fixture
CA; no public CA account or order is covered. W5 source-IP gating/revocation,
W6 identity-provider integration and W7 release/operations remain separate.

The later [admission and recovery record](validation-relay-trust-recovery.md)
verifies refusal with unconfirmed enrollments and genuine scheduled recovery
of the retained older identity. It does not establish signer activation or
retirement.
