# NetHub

Self-hosted remote access and fleet management for open-source routers and
firewalls. Starts with OPNsense; the architecture leaves room for OpenWrt and
VyOS.

![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)
![Stars](https://img.shields.io/github/stars/KazuhaHub/nethub?style=social)

**Status: pre-alpha, W2 tunnel integration.** W0 measurements are accepted;
the OPNsense development plugin has native tunnel, recovery, scheduler lifecycle,
and coexistence validation. Enrollment and the control plane remain unimplemented. See
[Project status](#project-status) before using the development files.

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
- [Security model](#security-model)
- [Project status](#project-status)
- [Roadmap](#roadmap)
- [License](#license)
- [Contributing](#contributing)
- [中文](#中文)

## What v1 is designed to do

The following describes the complete v1 scope; only the transport and development
plugin are implemented.

- Give an OPNsense box sitting behind CGNAT or a dynamic IP a stable, working
  web UI URL — no port forwarding, no dynamic DNS hacks, no VPN client
  running on your laptop.
- Enroll a device with a one-time token, assign it a random per-device
  subdomain (for example `abcd1234.router.example.com`), and keep a
  persistent tunnel alive from the device to your own relay.
- Show device online/offline status and basic connection metadata in the
  control plane's web console.
- Support more than one console user: `admin` and `member` roles, joining by
  invitation only, signing in with a local password or with OIDC (multiple
  identity providers can be configured).

That is the planned scope of v1. The final v1 feature list is still to be
confirmed.

## What NetHub does not do (yet)

- **No configuration management.** The control plane cannot read a device's
  `config.xml`, change firewall rules, or restart services. This is not an
  oversight — it's a deliberate v1 boundary, described in
  [Security model](#security-model) below.
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

This is the designed architecture (design v0.3). None of it is built yet.

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
docs/             DESIGN.md (v0.3, in Chinese), threat model and console API (drafts), Chinese README
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

> **Note — these commands don't exist yet.** NetHub is pre-alpha (see
> [Project status](#project-status)). The steps below describe the intended
> v1 flow so you know what "done" looks like; `nethub init`, the console, and
> enrollment are not implemented. The development plugin is for isolated tests;
> the complete self-hosted stack cannot be run yet.

| Step | What happens | Time |
|---|---|---|
| 1 | `nethub init` — ask for your domain, generate all secrets locally into per-service files, prompt you to back them up, create the first admin (local password), run preflight checks | ~2 min |
| 2 | `docker compose up -d` — start `nethub web`, `nethub authz`, Postgres, Caddy, `frps` (and a backup job) | ~2 min |
| 3 | Sign in to the console as the first admin; optionally add OIDC providers and invite other users | ~1 min |
| 4 | Create a device, copy the one-time enroll token (15-minute expiry) | ~1 min |
| 5 | Install the NetHub agent plugin on OPNsense, paste the token in its GUI | ~3 min |
| 6 | Device enrolls, tunnel comes up, status flips to online | ~1 min |
| 7 | Click "Open" on the device, see the OPNsense login screen (you still sign in with OPNsense's own account) | — |

**Total: about 10 minutes**, most of it spent on the plugin install.

## Security model

Summary of what v1 is designed to guarantee:

- **The control plane cannot read or modify device configuration.** This is
  architectural, not a policy promise — the design contains no path from the
  control plane into `config.xml`, firewall rules, or service restarts.
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
- **Console sign-in is a local password or OIDC.** `nethub init` creates the
  first admin with a local password (argon2id), which stays as a break-glass
  account. OIDC supports multiple providers (SAML is planned for v1.1).
  External identities are bound by `(issuer, subject)`, never by email alone,
  and there is no self sign-up: other users join by invitation. Sessions are
  server-side, with CSRF protection and a strict Content-Security-Policy.
- **Open before v1: the device–relay control channel is not yet
  authenticated.** As currently designed, `frpc` does not verify the relay's
  certificate. An attacker on the device's network path could therefore pose
  as the relay and steal the device's claim (`docs/DESIGN.md` §14, Q10;
  [threat model](docs/threat-model.md) F1). The fix is designed but not yet
  decided.
- **Every device carries a local kill switch file.** An operator can disable
  remote access from the device itself, independent of the control plane.
- **All secrets are generated locally by `nethub init`**, on the deployer's
  own machine, and written per service so each container only receives the
  ones it needs. The NetHub project does not hold, issue, or have access to
  any global key, and no central service your instance depends on exists.

### Exposure of the device web UI

Be clear-eyed about what the passthrough design implies. Anyone who knows or
guesses a device's hostname can open
`https://<subdomain>.router.example.com:8443` and reach that device's own
OPNsense login page. The console's login and SSO do **not** stand in front of
it — they protect the console, while the device keeps its own login.
Subdomains are random, which raises the cost of guessing; but once per-device
public certificates arrive in v1.1 they will be logged in Certificate
Transparency logs, which makes hostnames enumerable.

A candidate mitigation is a source-IP gate: `frps` reports each incoming
browser connection to `nethub authz` (the `NewUserConn` hook), and authz lets
it through only if that IP was recently registered by a signed-in console user
clicking "Open" for that device. Whether the hook fires for this kind of proxy
and reports the real client IP has to be confirmed in Weekend 0, and whether
to adopt the gate is still an open decision (`docs/DESIGN.md` §14, Q7). The
gate would check network location, not the person.

OPNsense's own DNS-rebind and HTTP_REFERER checks may also block access
through the relay hostname (`docs/DESIGN.md` §14, Q9; not yet tested). If
they do, add the hostname under OPNsense's "Alternate Hostnames" rather than
switching the checks off.

Either way, enable OPNsense's own TOTP two-factor authentication on every
enrolled device.

Full write-up: the [threat model draft](docs/threat-model.md) and
[`docs/DESIGN.md`](docs/DESIGN.md).

## Project status

The repository contains the design, accepted [W0 results](weekend0/results-2026-10-17.md),
and the [W2 development plugin](agents/opnsense/plugin/README.md).
[Native validation](agents/opnsense/plugin/tests/w2-progress.md) covers tunnel
startup, authenticated relay TLS, safe configuration application, bounded recovery,
cron lifecycle, WAN reconnect, reboot, and os-frp coexistence on OPNsense 26.7.7.
There is no released version or complete deployment. Interfaces remain subject to change.

The owner selected shadcn/ui with native dialog, source-IP gating, and explicit
heartbeat revocation. Those product controls are design requirements awaiting
implementation. Remaining decisions are tracked in [DESIGN](docs/DESIGN.md) §14.

## Roadmap

Everything in this table is plan, not shipped.

| Version | Focus |
|---|---|
| v1 | Remote web UI access for OPNsense devices behind CGNAT/dynamic IP, plus a multi-user console (admin/member, invitation-only) with OIDC sign-in — no config read/write |
| v1.1 | SAML sign-in, per-device TLS certificates, arm64 |
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
只做远程访问，不读取、不修改设备配置；批量升级和遥测都不在 v1 范围内。控制台
计划支持多用户（admin / member，邀请制）和 OIDC 登录（可配置多个 IdP），SAML
放在 v1.1。项目目前处于 pre-alpha 的设计阶段：设计方案是 v0.3 草案，还没有任何
代码，Weekend 0 传输层验证也尚未运行，不能用于生产。中文设计文档见
[`docs/DESIGN.md`](docs/DESIGN.md)，完整的中文 README 见
[`docs/README.zh-CN.md`](docs/README.zh-CN.md)。
