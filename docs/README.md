# docs/ — NetHub documentation index

NetHub is pre-alpha. The repository includes a Go control plane, React console,
OPNsense development plugin and deployment tooling. Accepted checks cover
specific sources and environments; they do not establish a production release
or completion of W5-W7. Start with the [handoff](HANDOFF_PROMPT.md) for current
acceptance records and the [execution plan](PLAN.md) for remaining requirements.

| Document                             | Status                                         | Purpose                                                                                                                                                                                                                                                                                    |
| ------------------------------------ | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [`DESIGN.md`](DESIGN.md)             | Design and recorded decisions                  | Architecture, trust boundaries, enrollment, tunnel routing, accounts and the v1 product boundary. Use implementation and validation records to distinguish decisions from completed behavior.                                                                                              |
| [`threat-model.md`](threat-model.md) | Historical draft; revision pending             | Initial trust-boundary and attacker analysis. Some open findings and W0 assumptions have been superseded; reconcile each against accepted runtime records before relying on it as a current assessment.                                                                                    |
| [`deployment.md`](deployment.md)     | Operator guide; complete restore drill pending | Current initialization, proxy/certificate ownership, readiness checks and troubleshooting. Scheduled database backups, off-host durability and clean-host restore are still W7 requirements.                                                                                               |
| [`protocol.md`](protocol.md)         | Current protocol walkthrough                   | Major-1 enrollment, lifecycle, certificate/trust extensions and future platform adapters. Distinguishes implemented routes from reserved rotate schemas.                                                                                                                                   |
| [`console-api.md`](console-api.md)   | Draft reference; conformance review pending    | Console sessions, CSRF, roles, errors, pagination and planned endpoint shapes. The console API is implemented in [`server/internal/web`](../server/internal/web), but this draft still needs a complete comparison with the current routes. Device contracts are in [`proto/`](../proto/). |
| [`README.zh-CN.md`](README.zh-CN.md) | Translation; synchronization pending           | Simplified Chinese translation of the top-level README. The English README is authoritative; both still need the W7 implementation and acceptance review.                                                                                                                                  |

## Implementation and validation guides

| Guide                                                                                                                                            | Scope                                                                                                                                                                                                |
| ------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Deployment quickstart](../deploy/QUICKSTART.md), [stack guide](../deploy/README.md)                                                             | Current initialization, service isolation and proxy configuration. Read the operator guide for the remaining upgrade, backup and restore requirements.                                               |
| [Native public certificates](../deploy/validation-native-public-certificate.md), [authority operations](../deploy/relay-authority-operations.md) | Scoped public CA issuance, native application and protected relay authority operations. Retain each record's runtime, recovery and release limitations.                                              |
| [Device Open](../deploy/device-open.md), [installed heartbeat and Revoke](../deploy/validation-native-w5-heartbeat.md)                           | Explicit source-IP grants, native outage/recovery and revocation measurements. Mobile Open and the recorded Revoke timing comparison remain separate gates.                                          |
| [OIDC providers](../deploy/oidc-providers.md), [OIDC login](../deploy/oidc-login.md), [two-Dex validation](../deploy/validation-two-dex.md)      | Administrator configuration, invitation-only identity admission and two independent deployed issuers. A public-provider test and full W6 acceptance remain open.                                     |
| [SAML providers](../deploy/saml-providers.md), [SAML login](../deploy/saml-login.md), [SAML pages](../deploy/saml-console.md)                    | Shared authcore protocol processing, trusted metadata, signed requests, durable replay protection, account admission and administration pages. Deployed vendor IdP acceptance is tracked separately. |
| [OPNsense plugin](../agents/opnsense/plugin/README.md), [protocol contracts](../proto/README.md)                                                 | Current device implementation and versioned wire contracts. The protocol walkthrough links these contracts and their runtime boundaries.                                                             |

## Contributing docs

If you want to help write any of the above, that's a welcome contribution —
see `CONTRIBUTING.md` at the repository root for how PRs, DCO sign-off, and
commit conventions work. Docs PRs follow the same process as code PRs.

A couple of standing rules that apply to every document in this directory,
not just the ones already listed:

- **No real deployment details.** No real hostnames, domains, IPs, ports, or
  credentials from anyone's actual deployment. Use `example.com`,
  `router.example.com` and `203.0.113.10` (an RFC 5737 documentation address)
  the way the rest of the project's public docs do.
- **Match claims to evidence.** Distinguish a design decision, implemented code,
  a synthetic fixture, genuine database/protocol checks, native or public-network
  measurements, and a signed release. Cite the applicable acceptance record and
  keep its limitations. A passing subset does not complete W5-W7. Configuration
  backup/delivery, fleet upgrades and telemetry remain roadmap work. Current v1
  scope includes invitation-only OIDC/SAML console access and per-device public
  certificates; it does not authorize general device configuration changes.
