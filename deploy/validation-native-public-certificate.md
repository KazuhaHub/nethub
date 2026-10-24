# Native public certificate acceptance (2026-10-24)

A fresh native enrollment in the retained isolated deployment passed real public
CA issuance, genuine package-cron installation, authenticated public GUI access
and normal UI removal. Independent checks verified the original environment after
restoration. Earlier failed trials and issued material remain in the database.

## Runtime and measurements

The host issuer used accepted source `c29c8e0`, with six successful jobs in run
40075177159, actual log gates and DCO verification before adoption. The unsigned
0.0.16 appliance package retained its accepted native source `0ed94ed`. Backend
and proxy image identities remained bound to their earlier accepted sources;
this does not claim that every runtime image was rebuilt from the issuer revision.

| Observation | Result |
| --- | --- |
| Enrollment click to console online, without reload/manual refresh | 8.852 seconds |
| Issuance to accepted native confirmation | 31.496 seconds |
| Public certificate lifetime | 7,775,999 seconds |
| Current device generations and immutable first applications | One each |
| Observed tunnel PIDs during issuance/application | One |
| Native allocation | 1,024 MiB |

The host issuer reused its protected registered account. The CA order was valid
and the HTTP-01 proof was retired. Native installation retained the original
device key and CSR; sampled tunnel state stayed running with the same PID.
Applied material was exported and every exported file was independently hashed.
The prior issued generation/application remained byte-for-byte identical.

A public TLS probe checked independent system trust, the exact assigned hostname
and the issued leaf fingerprint, then obtained a valid GUI HTTP response. A
separate Chrome flow used normal public DNS and system trust, with no TLS
exception or DNS override. It logged into the router and verified the actual
enrolled device through its native API.

Normal native UI removal completed cleanup. A fresh console login rendered the
device Revoked. The public TCP listener remained reachable while the former
device subdomain could no longer complete TLS. Issuer units and independent
guards were closed. The original configuration, package, stopped intent, managed
trust, restart script, fourteen original services and port owners were restored
and independently checked. A separate guarded database-only inspection retained
the valid order and verified unchanged earlier generations/applications.

## Corrections and retained failures

Earlier trials exposed missing initial trust publication, an account-readiness
assumption about the CA order-list URL, and overly strict PEM formatting. The
accepted fixes retain account identity, URL confinement, CSR/name/key binding and
independent certificate trust. A read-only fetch of an existing issued order
reproduced and verified the PEM correction without another order or finalization.
[Chain diagnostic](validation-public-chain-format.md).

One subsequent trial passed public issuance, native confirmation and the public
TLS probe, then failed while exporting evidence: its temporary Python wrapper
lacked the helper import path. Its device was genuinely revoked, its environment
restored and its failed outcome retained. The corrected wrapper passed an isolated
import control before the final complete run. No failed record was rewritten as
a successful trial.

## Combined W4 certificate requirement

| Required behavior | Accepted evidence |
| --- | --- |
| External proxy owns console TLS; isolated origin and forwarding-header boundary | [External proxy and native deployment](validation-w4.md#existing-host-https-proxy) |
| Public GUI issuance, native installation and authenticated public TLS | This run |
| Natural renewal using the same native key/CSR | [Native lifecycle](validation-native-gui-lifecycle.md) |
| Wrong-host/key refusal at both installed boundaries | [Identity controls](validation-native-certificate-identity.md) |
| Restart failure, rollback and retry without reissuing | [Rollback and retry](validation-native-certificate-rollback.md) |
| Renewal while off, reboot persistence and cron application | [Offline renewal](validation-native-offline-renewal.md) |
| Offline root switch/retirement and authenticated recovery | [Physical root recovery](validation-native-offline-root-recovery.md) |

Renewal and fault controls retain their measured private-CA scope. Public renewal
was not accelerated or waited out. Initial enrollment/removal used the independently
checked original local GUI SPKI pin; public console and public GUI acceptance used
normal system trust. The accepted 1 GiB appliance allocation remains below the
documented 3 GiB VM minimum. This establishes functional lab acceptance, not
production sizing or load capacity. Raw addresses, credentials, certificates,
screenshots and private receipts remain outside Git. No signed release was made;
W5-W7 remain separate work.
