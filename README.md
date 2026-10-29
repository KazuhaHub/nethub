# NetHub

Self-hosted remote access and fleet management for open-source routers and
firewalls. Starts with OPNsense; the architecture leaves room for OpenWrt and
VyOS.

![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)
![Stars](https://img.shields.io/github/stars/KazuhaHub/nethub?style=social)

**Status: pre-alpha, W7 implementation and acceptance.** The control plane and OPNsense development
plugin are implemented, with scoped public/native certificate and trust records.
W5–W7 remain incomplete; there is no production release. See
[Project status](#project-status) for evidence and remaining gates.

**Before you self-host, you will need:** a domain name you control DNS for, a
**wildcard DNS record** (`*.router.example.com` → your relay server's public
IP), and a relay server reachable from the public internet on ports **443**,
**7000** and **8443**. There is no hosted option and no shortcut around this —
see [Requirements](#requirements) for the full list.

- [What v1 is designed to do](#what-v1-is-designed-to-do)
- [What NetHub does not do (yet)](#what-nethub-does-not-do-yet)
- [Why not just use Tailscale / Cloudflare Tunnel / expose the web UI directly?](#why-not-just-use-tailscale--cloudflare-tunnel--expose-the-web-ui-directly)
- [How it works](#how-it-works)
- [Repository layout](#repository-layout)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Documentation](#documentation)
- [Security model](#security-model)
- [Project status](#project-status)
- [Roadmap](#roadmap)
- [License](#license)
- [Contributing](#contributing)
- [中文](#中文)

## What v1 is designed to do

The following describes the complete v1 scope. Implementation and integration
are in progress; this is not a released deployment.

- Give an OPNsense box sitting behind CGNAT or a dynamic IP a stable, working
  web UI URL — no port forwarding, no dynamic DNS hacks, no VPN client
  running on your laptop.
- Enroll a device with a one-time token, assign it a random per-device
  subdomain (for example `abcd1234.router.example.com`), and keep a
  persistent tunnel alive from the device to your own relay.
- Show device online/offline status and basic connection metadata in the
  control plane's web console.
- Support more than one console user: `admin` and `member` roles, joining by
  invitation only, signing in with a local password, OIDC or SAML through
  authcore. Multiple identity providers can be configured.
- Issue and renew per-device public GUI certificates, with device-local keys
  and verified native application.

The execution plan tracks the confirmed scope and its remaining acceptance.

## What NetHub does not do (yet)

- **No general device configuration API.** NetHub does not expose a firewall,
  arbitrary command or configuration-push interface. The plugin manages its
  own tunnel/settings and bounded GUI certificate installation, which can
  reload the GUI service. See [Security model](#security-model).

- **No fleet operations.** No bulk upgrades, no scheduled jobs, no
  fleet-wide config push.
- **No telemetry.** No metrics collection, no dashboards, no alerting beyond
  "is the tunnel up."
- **No OpenWrt or VyOS support.** The directory layout and protocol are
  designed not to assume a single platform, but v1 targets OPNsense only.

If you're looking for a configuration manager for your fleet, that's on the
[roadmap](#roadmap), not in v1.

## Why not just use Tailscale / Cloudflare Tunnel / expose the web UI directly?

Fair question, and for most people the honest answer is: use Tailscale.

- **Tailscale** is simpler to set up, runs no server of your own, and just
  works across NAT. If you have one device, or a handful, and you don't mind
  a third party's coordination plane sitting in the connection path — use
  Tailscale. NetHub does not try to out-convenience it.
- **Cloudflare Tunnel** is a similar trade: no infrastructure to run
  yourself, backed by Cloudflare's edge. Same caveat — you're trusting
  Cloudflare with the path and, to some extent, the identity model.
- **Exposing the OPNsense web UI directly to the internet** (port-forwarded
  or otherwise) is the risk that Tailscale and Cloudflare Tunnel exist to help
  you avoid — and NetHub is **not** a way around it. By design NetHub also
  makes the device's own login page reachable from the public internet,
  through your relay (see
  [Exposure of the device web UI](#exposure-of-the-device-web-ui)). What it
  removes is the need for inbound port forwarding on the device's network,
  which CGNAT often makes impossible anyway — not the exposure itself. If a
  publicly reachable OPNsense login page is not acceptable to you, use
  Tailscale.

NetHub is for a narrower situation: you want to **own the relay** end to
end — self-hosted, on infrastructure you control, with no third-party
coordination service in the loop — you're managing **more than one
device**, and you expect to grow toward **config backup and push** without
switching tools later. If none of those three apply to you, NetHub is more
infrastructure than you need; go install Tailscale.

## How it works

The control plane and OPNsense development plugin implement this architecture.
Accepted workflows and remaining validation are listed under [Project status](#project-status).

```
             SNI = abcd1234.router.example.com                     frp tunnel
                     (TLS stays end-to-end                    (device-specific,
                      to the device the whole way)              persistent)

+-----------+          +----------------------------+          +------------------------+
|  Browser  |  HTTPS   |         frps :8443         |  :7000   |     vendored frpc      |
|           | ───────► |      (vhostHTTPSPort)      | ───────► |    -> 127.0.0.1:443    |
|           | ◄─────── |    SNI passthrough only    | ◄─────── |   (OPNsense webGUI)    |
+-----------+          +----------------------------+          +------------------------+
                                      │  Login / NewProxy checks
                                      ▼  (httpPlugins, internal network)
                  +--------------------------------------+
                  |           Go control plane           |
                  |      nethub web + nethub authz       |
                  |     behind Caddy :443 + Postgres     |
                  +--------------------------------------+
                  console, enrollment, identity, status —
                       not in the web UI data path
```

- Every enrolled device gets a random subdomain assigned by the server, e.g.
  `abcd1234.router.example.com`, resolved by your own wildcard DNS record to
  the relay's IP.
- The device's `frpc` dials out to `frps` on port **7000** (TLS) and keeps that
  control channel open. Browser traffic for the device's subdomain arrives on
  port **8443** and is carried to the device over the tunnel the device
  opened.
- `frps` on the relay accepts the TCP connection but reads only the TLS
  ClientHello's **SNI** field to decide which device's tunnel to forward the
  bytes to — it never decrypts the connection.
- Because nothing decrypts, terminates, or rewrites the traffic, OPNsense's
  PHP-rendered pages and inline JS arrive at your browser byte-for-byte as
  the device sent them. There's no path-prefix rewriting to break relative
  URLs, and no proxy layer that has to track every OPNsense frontend change.
- The control plane is one Go binary, `nethub`, run as two roles: `nethub web`
  (the console) and `nethub authz` (the device API and the `frps` plugin
  endpoint), with Postgres behind them and Caddy in front on port **443**.
  `frps` asks `nethub authz` to approve each device's login and proxy
  registration. The control plane handles the console, enrollment, device
  identity, and status. It is not in the data path for the web UI traffic
  itself — that's the whole point.

## Repository layout

```
proto/            protocol definitions (JSON Schema) — platform-neutral, single source of truth
server/           control plane: Go, one binary `nethub` (web | authz | migrate | init | doctor)
  web/              console source: React + TypeScript + Vite (build output embedded in the binary)
agents/opnsense/  the OPNsense agent: os-nethub-agent plugin source (PHP MVC, rc.d, agentctl.py)
deploy/           docker-compose, Caddy config, per-service secrets layout
docs/             DESIGN.md (v0.3, in Chinese), operator/protocol/security/API references, Chinese README
weekend0/         Weekend 0 transport-test kit (RUNBOOK, frps/frpc configs, probe.py)
```

This layout includes planned components. The repository currently contains the
documentation, Weekend 0 kit, and OPNsense development plugin.

All of NetHub lives in this repository, including the OPNsense plugin source
under `agents/opnsense/plugin/`. FreeBSD packages are *built* elsewhere:
[`KKazuhaK/OPNsense-repo`](https://github.com/KKazuhaK/OPNsense-repo) will
carry a packaging recipe that fetches a tagged NetHub release, verifies its
checksum, and runs it through an existing FreeBSD build/signing/publish
pipeline — the same way it already packages sing-box and frp. From
that repository's point of view NetHub is just another upstream. Full detail:
[`CONTRIBUTING.md`](CONTRIBUTING.md#license-and-repository-layout).

## Requirements

Self-hosting NetHub means having, before you start:

1. **A domain name** you control DNS for.
2. **A wildcard DNS record**: `*.router.example.com` → your relay server's
   public IP (e.g. `203.0.113.10`).
3. **A relay server reachable from the public internet** with three ports
   open:
   - **443** — Caddy: the web console and the device enroll API;
   - **7000** — `frps` `bindPort`: the device control channel (TLS);
   - **8443** — `frps` `vhostHTTPSPort`: browser to device, SNI passthrough.

   Everything else (the `frps` admin API, the `nethub authz` plugin endpoint,
   Postgres) stays on the internal Docker network and is not published.
4. **Docker and Docker Compose** on that server.

There is no hosted option. If you don't want to run a server, see
[Why not just X?](#why-not-just-use-tailscale--cloudflare-tunnel--expose-the-web-ui-directly)
above.

## Quick start

Use the [deployment guide](docs/deployment.md) and
[verified command examples](deploy/QUICKSTART.md) on a dedicated test host.
The development plugin is unsigned; package-repository release and a complete
friend-from-zero deployment remain separate acceptance. No setup-time estimate
is established.

1. Prepare DNS, listeners and protected deployment/backup parents.
2. Run `nethub init`, verify its secret backup and acknowledge it.
3. Build/start the generated Compose stack; run the separate `admin-bootstrap`
   service with its hidden password prompt.
4. Sign in as the local administrator; optionally configure OIDC/SAML providers
   and issue invitations.
5. Create a one-use enrollment token, then enter it with the console HTTPS
   address in the OPNsense plugin.
6. Verify tunnel observation and the device's current GUI certificate application.
7. Click Open to grant the current source IP access, then authenticate in
   OPNsense itself. Verify the public hostname and certificate normally.

## Documentation

- [Deployment and operations](docs/deployment.md): current commands, proxy and
  certificate ownership, troubleshooting, and the remaining backup/restore work.
- [Device protocol](docs/protocol.md): enrollment, certificate/trust lifecycles,
  compatibility and the platform adapter boundary.
- [Documentation index](docs/README.md) and [accepted evidence/remaining work](docs/HANDOFF_PROMPT.md).

These guides do not establish a production release or complete W5-W7 acceptance.

## Security model

Summary of what v1 is designed to guarantee:

- **There is no general device configuration or command interface.** The
  plugin owns its local NetHub configuration, tunnel lifecycle and verified GUI
  certificate application. That bounded certificate path can reload the GUI;
  it does not grant firewall or arbitrary service control.

- **Enroll tokens are one-time use and expire after 15 minutes.**
- **Device identity is a signed domain claim** (HMAC-SHA256) issued at enroll
  time. When a device's `frpc` logs in or registers its proxy, `frps` asks
  `nethub authz`, which checks both the signature *and* that it matches the
  database record — two independent checks, not one.
- **The signing key lives only in `nethub authz`.** The public console
  (`nethub web`) is a separate process with its own database role; it never
  holds the signing key or the `frps` admin credentials, cannot create device
  rows, and cannot write subdomains or claim fields. So even a fully
  compromised console cannot mint a claim for an existing device or reassign
  a subdomain. It *could* still create enroll tokens (enrolling a new device
  under a new subdomain), revoke devices, read device metadata and the audit
  log, and manage users and sign-in providers — that is, take over the
  console. The full boundary is in [`docs/DESIGN.md`](docs/DESIGN.md) §6.
- **Console sign-in supports local passwords, OIDC and SAML.** The separate
  `admin-bootstrap` service creates the first local-password administrator
  (argon2id), which stays as a break-glass account. OIDC/SAML use authcore for protocol verification.
  OIDC identities use `(issuer, subject)`; SAML uses a persistent NameID scoped
  to its IdP and SP. Neither protocol binds by email alone,
  and there is no self sign-up: other users join by invitation. Sessions are
  server-side, with CSRF protection and a strict Content-Security-Policy.
- **The agent verifies relay TLS.** Enrollment supplies the assigned server
  name and public deployment CA bundle; frpc uses explicit `serverName` and
  `trustedCaFile`. Preserve authenticated trust delivery and the protected
  authority-transition procedure. [Native trust evidence](deploy/validation-relay-trust-native.md)
  is scoped to its recorded runtime; it is not a production security audit.

- **Every device carries a local kill switch file.** An operator can disable
  remote access from the device itself, independent of the control plane.
- **Deployment secrets are generated locally by `nethub init`**, on the deployer's
  own machine, and written per service so each container only receives the
  ones it needs. The NetHub project does not hold, issue, or have access to
  any global key, and no central service your instance depends on exists.

### Exposure of the device web UI

SNI passthrough keeps the device's own authentication. During normal operation,
NewUserConn also requires an unexpired grant for the device and browser source
IP. An authorized console Open click grants 30 minutes; another click renews it.
Traffic and inventory polling do not extend the window. Knowing a hostname alone
does not grant a new connection. See [Open behavior](deploy/device-open.md).

This gate checks network location, not a person. CGNAT peers can share an IP;
console/router IPv4 or IPv6 source differences can cause refusal. Existing
connections can outlive the grant, and a compromised relay can skip its hooks.
Public GUI certificates are in v1 scope and can disclose hostnames through
Certificate Transparency; random subdomains are not an authorization control.

Per-device public certificates have [scoped native/public evidence](deploy/validation-native-public-certificate.md).
A reported installation does not establish what a later external connection
serves; the browser must verify its CA chain and hostname. Keep OPNsense's DNS
rebinding and HTTP_REFERER checks enabled and add the exact assigned Alternate
Hostname as required by the [W0 decisions](weekend0/results-2026-10-17.md).

Either way, enable OPNsense's own TOTP two-factor authentication on every
enrolled device.

Full write-up: the [threat model](docs/threat-model.md) and
[`docs/DESIGN.md`](docs/DESIGN.md).

## Project status

The [handoff](docs/HANDOFF_PROMPT.md) binds accepted changes to source revisions,
CI runs and native/public measurements. W0 and W2 records are historical inputs,
not complete evidence for later product workflows.

The [native public-certificate record](deploy/validation-native-public-certificate.md)
covers issuance, scheduled application, authenticated public GUI access and
restoration in the approved isolated environment. The
[installed heartbeat/Revoke record](deploy/validation-native-w5-heartbeat.md)
retains the slower Revoke measurement and the missing mobile Open sample.

Two deployed Dex issuers have [accepted OIDC evidence](deploy/validation-two-dex.md).
SAML backend/pages and an independent [Keycloak deployment](deploy/validation-keycloak-saml.md)
have scoped accepted evidence. Public-provider and complete W6 acceptance remain open.

The [scheduled database backup service](deploy/database-backups.md) passed
[scoped container and restore checks](deploy/validation-database-backups.md).
Per-device [credential rotation](deploy/device-rotation.md), including two genuine
native interruption recoveries, has scoped installed acceptance. Deployment-wide
[shared-token incident recovery](deploy/shared-relay-token-rotation.md) has scoped
server/reference-client cutover evidence; its installed-native recovery remains
under validation. Public/mobile gates remain separate.
Complete clean-host/current-key/device recovery, full document
review, friend-from-zero deployment and signed/faulty-version release gates remain
W7 work. There is no released package or production-readiness claim.

## Roadmap

Everything in this table is plan, not shipped.

| Version | Focus |
|---|---|
| v1 | Remote web UI access for OPNsense devices behind CGNAT/dynamic IP, plus a multi-user console (admin/member, invitation-only) with OIDC/SAML sign-in and per-device public GUI certificates — no general configuration API |
| v1.1 | arm64 |
| v1.2 | Telemetry: tunnel/device health metrics |
| v2 | Encrypted config backup: the device encrypts `config.xml` with a key derived on the device before uploading, and the control plane stores ciphertext it cannot decrypt (so no server-side diffing) |
| v2.5 | Config push (send config changes to devices) |

Later console option: passkey sign-in.

## License

Apache-2.0. See [`LICENSE`](LICENSE).

## Contributing

Contributions require a **Developer Certificate of Origin** sign-off
(`git commit -s`) — no CLA. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the
DCO, how this repository relates to the packaging repository, and the PR
checklist.

---

*OPNsense® is a registered trademark of Deciso B.V. NetHub is an independent
project and is not affiliated with, endorsed by, or sponsored by Deciso B.V.*

## 中文

NetHub 是一个自托管的远程访问与设备管理工具：让藏在 CGNAT 或动态 IP 后面的
开源路由器/防火墙（首发支持 OPNsense）无需端口转发即可远程打开 Web UI。v1
不提供通用设备配置接口；插件的隧道及 GUI 证书管理有独立边界，批量升级和遥测不在 v1 范围内。控制台
已实现多用户（admin / member，邀请制）、OIDC 和 SAML 登录接口及页面。项目处于 pre-alpha 的 W7 实现和验收阶段，已有按环境和版本记录的原生／公网证书及定时数据库备份验收；W5–W7、公开 IdP 和正式发布仍有未完成项，不能用于生产。中文设计文档见
[`docs/DESIGN.md`](docs/DESIGN.md)，完整的中文 README 见
[`docs/README.zh-CN.md`](docs/README.zh-CN.md)。
