# NetHub threat model (draft)

> **Status: draft, written 2026-10-16 against design v0.3.** Nothing described
> here is implemented: there is no code yet.
>
> Several statements depend on measurements that have not been made (Weekend 0)
> or on decisions that are still open. Each of those is marked **(unverified)**
> or **(open)** and points to the relevant section of [`DESIGN.md`](DESIGN.md),
> which is the authority on the design.
>
> This document will be revised after Weekend 0 and again before the first
> public release.

This document says what NetHub v1 is designed to protect, against whom, how,
and where the protection stops. It is meant to be read by people deciding
whether to deploy NetHub and by people reviewing or extending it.

## Contents

- [1. Scope](#1-scope)
- [2. System and trust boundaries](#2-system-and-trust-boundaries)
- [3. Assets](#3-assets)
- [4. Attackers and what they can do](#4-attackers-and-what-they-can-do)
- [5. Open findings](#5-open-findings)
- [6. Accepted risks and known open risks](#6-accepted-risks-and-known-open-risks)
- [7. Out of scope](#7-out-of-scope)
- [8. Assumptions this model depends on](#8-assumptions-this-model-depends-on)

## 1. Scope

In scope: NetHub v1 as designed in `DESIGN.md` v0.3. That is:

- the relay (`frps`);
- the control plane, one Go binary running as `nethub web` and `nethub authz`,
  with Postgres behind it and Caddy in front;
- the OPNsense agent `os-nethub-agent` (`agentctl.py`, a vendored `frpc`, and
  the plugin's web pages);
- the enrollment, sign-in, revocation and remote-access flows that connect
  them.

Not in scope: vulnerabilities in OPNsense itself, in frp, or in the operating
system of the relay host, except where NetHub's design makes them more or less
reachable. See [§7](#7-out-of-scope).

## 2. System and trust boundaries

```
 Browser (operator) ──HTTPS :8443──► frps (relay) ◄──TLS :7000── frpc (on the device) ──► OPNsense web GUI 127.0.0.1
        │                              │   ▲                         │
        │                              │   │ admin API (internal)    │ HTTPS :443 (enroll, rotate, status)
        │ HTTPS :443                   ▼   │                         ▼
        └──────────► Caddy ──► nethub web      nethub authz ◄──── httpPlugins (internal: Login / NewProxy / …)
                                   │               │
                                   ▼               ▼
                              Postgres (role nethub_web)   Postgres (role nethub_authz)
                                   │
                                   ▼
                          OIDC identity providers
```

The trust boundaries that matter:

| # | Boundary | What crosses it | Protection, as currently designed |
|---|---|---|---|
| B1 | Internet → relay port 8443 | Browser TLS to the device, routed by SNI | The relay never decrypts. TLS runs end to end between the browser and the device's own web GUI |
| B2 | Device → relay port 7000 | frp control channel: login, proxy registration, heartbeats, multiplexed browser streams | TLS (`transport.tls.enable`), frps auth token, signed domain claim checked by authz on `Login` / `NewProxy`. **The server certificate is not verified as currently designed; see [F1](#f1-the-devicerelay-control-channel-is-not-authenticated)** |
| B3 | Device → Caddy port 443 → `nethub authz` | Enroll, rotate, unenroll, status | HTTPS with a publicly trusted certificate, plus a one-time enroll token. That the agent verifies this certificate against the system CA bundle and never disables verification is an assumption the rest of the model depends on. DESIGN §4 does not yet state it ([§8](#8-assumptions-this-model-depends-on), item 7) |
| B4 | Operator browser → Caddy port 443 → `nethub web` | Console sign-in and API | Server-side sessions, CSRF tokens, strict CSP, login throttling, argon2id, OIDC with PKCE |
| B5 | `frps` ↔ `nethub authz` (internal network) | Plugin calls (`Login`, `NewProxy`, optionally `NewUserConn`, `Ping`); admin-API polling | Internal network only; not published |
| B6 | `nethub web` / `nethub authz` → Postgres | Queries under two different roles | Row-level security per tenant; column-level grants; the web role cannot create devices or write identity columns |
| B7 | `nethub web` → OIDC providers | Authorization-code flow | PKCE, state, nonce, ID-token verification; identities bound by `(issuer, subject)` |
| B8 | Plugin web pages → configd → `agentctl.py` | Privileged actions on the device | Only explicitly registered configd actions; no arbitrary shell path |

## 3. Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| The device's configuration (`config.xml`), firewall rules, services | The device | What an attacker on a firewall ultimately wants. **The control plane has no designed path to read or change any of it** (DESIGN §1, §8) |
| The path to the device's admin login | The relay and the tunnel | Whoever can reach the login page can try to log in; whoever can impersonate it can phish credentials |
| Subdomain ownership ("this hostname is this device") | Postgres `devices` + the signed domain claim | If it can be forged or moved, an attacker can serve a look-alike login page on a real device's hostname |
| Claim signing key | Only in the `nethub authz` container | Lets its holder mint claims for any subdomain |
| frps admin credentials, frps auth token | `frps` and `nethub authz` | Admin API access; the first gate on the control channel |
| Device credentials (`device_secret`, frp token, claim) | The device, in plaintext (accepted, see [§6](#6-accepted-risks-and-known-open-risks)) | Let their holder act as that one device |
| Enroll tokens and invite links in transit | Wherever the person who created them passes them on (chat, email, paper) | Bearer credentials. A leaked enroll token puts an attacker's device in the victim's device list. Whoever opens an invite link first gets that invite's role: the password path checks no email. An admin invite therefore makes its first holder an admin |
| Console accounts and sessions | Postgres (`users`, `sessions`, `user_identities`) | Console access: enroll, revoke, see devices and audit |
| OIDC client secrets | Postgres, encrypted with `NETHUB_SECRETS_KEY` (held by `nethub web` only) | Let their holder act as NetHub towards the identity provider |
| Audit log | Postgres `audit_log` (hash-chained) | After-the-fact accountability. The chain detects accidental damage, **not** tampering by someone with database write access (DESIGN §6) |
| Deployment secrets backup | Wherever the deployer keeps it | There is no recovery path if it is lost (DESIGN decision #21) |
| Availability of remote access | The relay VM, `frps`, `nethub authz` | The reason the product exists |

## 4. Attackers and what they can do

Each subsection lists what the attacker **can** do, what they **cannot** do,
which defences the design relies on, and what risk remains.

### 4.1 Anyone on the internet

**Can:**
- Reach the console login page, the enroll API, `frps` on 7000, and any
  device's login page on 8443 if they know or guess its hostname.
- Try passwords against the console, which is throttled per IP and per
  account.
- Try passwords against a device's own OPNsense login. NetHub does not
  throttle that.

**Cannot, as designed:**
- Enroll a device without a valid one-time enroll token. Tokens are random,
  stored only as hashes, single-use and expire after 15 minutes.
- Register a proxy on `frps` without the frps auth token *and* a domain claim
  that authz accepts.

**Residual risk:**
- **The device login page is exposed (open, DESIGN §14 Q7).**
  - With SNI passthrough, the console's login and SSO do not stand in front of
    the device's own login.
  - Subdomains are random, which raises the cost of guessing. But from v1.1,
    per-device public certificates will appear in Certificate Transparency
    logs, which makes hostnames enumerable.
  - The candidate mitigation is a source-IP gate on `frps`'s `NewUserConn`
    hook. It is **unverified** until Weekend 0 and **open** pending a decision.
  - Enable OPNsense's own TOTP two-factor authentication on every device
    regardless.
- **The device sees every relayed client as `127.0.0.1` (unverified).**
  `frpc` connects to the GUI on `127.0.0.1:443`, so every browser reaching the
  device through the relay appears to OPNsense to come from the device itself.
  As a result, OPNsense's own per-address login lockout and its logs either
  cannot tell attackers apart, or lock everyone out at once. Check this in
  Weekend 0.
- **OPNsense's own hostname checks (open, DESIGN §14 Q9).** OPNsense's
  DNS-rebind and HTTP_REFERER checks may block access through the relay
  hostname. The preferred route is to add the hostname to OPNsense's
  "Alternate Hostnames". Turning the checks off is not.

### 4.2 An attacker on the network between the browser and the relay

**Can:**
- See which device hostname is being visited. SNI is sent in clear in TLS 1.2
  and 1.3 unless Encrypted ClientHello (ECH) is used.
- Interfere with or block the connection.

**Cannot:**
- Read or modify the traffic between the browser and the device, as long as
  the operator does not accept a forged certificate.

**Residual risk:**
- **v1 uses the device's self-signed certificate.** The browser warns every
  time, so users learn to click through the warning. An attacker who can
  redirect the connection can present their own certificate, and the warning
  looks the same.
- Per-device publicly trusted certificates in v1.1 address this (DESIGN
  decision #9). Until then, the only check is to compare the certificate
  fingerprint with the one shown in the device's own GUI.

### 4.3 An attacker on the network between the device and the relay

Examples: the ISP or CGNAT operator, a compromised upstream router, or a
hostile network at a remote site.

**Can, as currently designed (see [F1](#f1-the-devicerelay-control-channel-is-not-authenticated)):**
- Impersonate the relay towards the device: `frpc` does not verify the relay's
  TLS certificate.
- Read the `Login` message, including the domain claim in its metadata.
- Replay that `Login` message to the real relay. frp's token authentication
  has no timestamp freshness check, so the attacker does not even need the
  frps token (from reading the frp source; **unverified**).
- Keep the real device offline at will by dropping its traffic, and then
  register the victim's subdomain while the device is away.
- As the fake relay, reach the device's GUI directly. Any `NewUserConn` gate
  on the real relay is bypassed.

**Cannot:**
- Decrypt the browser ↔ device TLS that is multiplexed inside the tunnel.

**Residual risk:**
- **Subdomain takeover: open finding F1.** The attacker can serve a
  look-alike login page on a real device's hostname. The impact is the same
  as DESIGN §13 scenario #1, but it needs no control-plane compromise. It
  must be fixed before v1.

### 4.4 A compromised console (`nethub web`)

For example: an API authorization bug, SQL injection, XSS that rides an admin
session, or session forgery.

**Can** (DESIGN §6, "安全论证"):
- Create enroll tokens, and so enroll a *new* device under a *new* subdomain.
- Revoke devices (an availability attack).
- Read device metadata and the audit log.
- **Phish through the console.**
  - Even SQL injection alone is enough: insert an enroll token whose value the
    attacker knows and which is attributed to the victim, enroll the
    attacker's own box under it, and copy a real device's label onto it.
  - With code execution, simply return any URL from the console's "Open"
    action.
  - Either way, a user who clicks "Open" without checking the hostname can be
    sent to a look-alike login page.
- Manage users, invites and OIDC providers, and decrypt the OIDC client
  secrets: that is, take over the console.
- Set an arbitrary enroll-token expiry, unless enroll-token columns are
  granted per column. DESIGN §6 mitigates this with column-level INSERT,
  database defaults and a maximum age enforced in `consume_enroll_token`.
- If the Q7 gate is adopted, register any source IP for any device. The gate
  is only as strong as the console.
- Un-revoke a stolen device, unless revocation is made one-way. DESIGN §6
  recommends one-way revocation (**open**).

**Cannot:**
- Obtain a valid claim for an *existing* subdomain: the signing key is not in
  the web container.
- Change which device owns a subdomain. The web role has no write access to
  `devices.subdomain` or to the claim and hash columns, and cannot insert
  devices.
- Put a look-alike on an existing device's **real** hostname.
- Read or change any device's configuration.

**Defences:**
- the web/authz process split;
- separate Postgres roles with column-level grants;
- row-level security;
- no server-side templates, a strict CSP, and per-session CSRF tokens.

**Residual risk:** users who do not check the hostname they are opening are
not protected against console-based phishing.

### 4.5 A compromised `nethub authz`

**Can:**
- Mint claims for any subdomain.
- Accept or reject any device, and assign subdomains.
- Change `devices` rows. authz needs write access to them, so it can also
  un-revoke devices and change their owner.
- Use the frps admin credentials.

This is a compromise of the relay identity layer: an attacker can impersonate
any device's hostname.

**Cannot:**
- Read or change device configuration. No such path exists, and the device
  runs only registered configd actions.
- Sign in to the console. authz has no access to the user, session, invite or
  OIDC tables, and does not hold `NETHUB_SECRETS_KEY`.

**Defences:** a small, explicit surface. authz exposes only the device API,
through Caddy, and an internal plugin endpoint. It keeps strict internal
timeouts on database calls.

**Residual risk:**
- authz is a single point of failure for new connections.
- If `frps` also subscribes the `Ping` hook, which is the candidate cut-off
  mechanism, authz becomes a single point of failure for **all** remote
  access. This is **unverified**; see DESIGN §5 and §12, and Weekend 0 item ⑥.

### 4.6 A compromised `frps` or Caddy process

Both processes sit on the public edge and parse untrusted input before
anything else does.

**A compromised `frps`:**
- Can route any subdomain's port-8443 traffic anywhere.
- Can skip the plugin calls altogether. authz's verdicts only matter while
  frps honours them.
- Reads every device's domain claim from `Login`, because it terminates the
  control-channel TLS.

The result is hostname impersonation without touching authz or the database.

**A compromised Caddy:**
- Terminates TLS for the console and the device API.
- So it sees console passwords and sessions, enroll tokens, and the device
  credentials (`device_secret`, frp token, claim) in enroll and rotate
  responses.

**Defences, proposed and not yet in DESIGN:**
- containers with the least privilege they need;
- separate internal networks, so that only the web and authz roles can reach
  Postgres, and only authz can reach the frps admin API;
- frps holds only its own secrets.

### 4.7 A compromised relay host (root on the VM)

**Can:**
- Do everything in 4.4 to 4.6. All secrets except the deployer's offline
  backup live on this host.
- Stop all tunnels.

**Cannot:**
- Read or change device configuration.
- Decrypt browser ↔ device TLS, unless the operator accepts a forged
  certificate (see 4.2).

**Residual risk:** v1 accepts a single control-plane VM as a single point of
failure (DESIGN §12). The host's security is the deployer's responsibility.

### 4.8 A malicious console user

**A `member`:**
- Can manage their own devices and see their own audit entries.
- Must not be able to see or act on another user's devices. That isolation is
  enforced in the application (a `store`-layer filter on `owner_user_id`),
  **not** by row-level security, which only separates tenants (DESIGN §13
  scenario #2). A missing filter on one endpoint would be a real leak; the W3
  tests are the defence.

**A member also controls a sibling origin.**
- The content served on `<subdomain>.router.example.com` comes from that
  member's own device.
- The device's label and hostname are shown to admins in the console.

That gives a member three ways to attack the console:

- **Cookies.** The device's pages are same-site with the console, so they can
  try to set cookies the console will read.
- **The opened tab.** The tab the console opens can reach back to the console
  tab through `window.opener`.
- **The console's own hostname.** If a device could register the console's
  hostname as a custom domain on port 8443, it would receive the console's
  cookies, because cookies are not scoped by port. frps 0.71.0 itself accepts
  custom domains that are not *below* `subDomainHost`.

**Defences (`docs/console-api.md`):**
- **For cookies:** `__Host-` cookies.
- **For the opened tab:** opening devices with `noopener`, plus
  `Cross-Origin-Opener-Policy: same-origin`.
- **For the console hostname:**
  - authz rejects every `NewProxy` request that has any custom domain, is not
    of type `https`, or whose subdomain differs from the device's record;
  - no device ever serves the console's hostname.

**An `admin`** has full control of the console by design. Within NetHub's
boundary there is no defence against a malicious admin beyond the audit log.

### 4.9 A compromised identity provider or IdP account

**Can:** sign in to the console as any user bound to that provider. For an
admin that means sending invites, revoking every device and reading the audit
log.

**Cannot:**
- Obtain claims, move subdomains or read device configuration (same boundary
  as 4.4).
- Use a matching email address to take over a user or claim an invite.
  Bindings are by `(issuer, subject)`. A new binding only happens in a flow
  started from an invite link, with a valid invite token, `email_verified=true`
  and a matching email (DESIGN decision #22, §13 scenario #13).

**Residual risk:** the local break-glass admin does not depend on any IdP and
stays available. The console API is designed so that at least one local admin
always remains.

### 4.10 A stolen or compromised device

**Can:**
- With root on the device, read its credentials. They are stored in plaintext,
  at the same level as OPNsense's own API keys (accepted).
- Act as that one device, on its own subdomain, until it is revoked.

**Cannot:**
- Act as any other device.
- Reach the console.

**Residual risk:**
- **A live tunnel may survive revocation (open).** frps 0.71.0's admin API has
  no endpoint that disconnects a connected client, and the candidate
  mechanisms are unverified (DESIGN §5). A revoked device may keep its live
  tunnel until it reconnects.
- **A modified `frpc` can outlast revocation.** One that ignores the error
  response to a rejected heartbeat loses its control connection only after
  `heartbeatTimeout`. According to the frp source, its open streams may
  survive even that (DESIGN §12).

### 4.11 Supply chain

| Component | Trust root, as designed | Gap |
|---|---|---|
| frp binaries | The official upstream release, SHA-256 pinned and verified at build time. The same version runs on device and relay (DESIGN decision #19) | — |
| Plugin package (`os-nethub-agent`) | Signed by the package repository's signing key and built from a tagged release, in a separate packaging repository | The signing host must never run the NetHub agent (DESIGN decision #20). That is operational discipline, not a technical control (Q4) |
| Go modules, npm packages | `go.sum` and lock files. Proposed, not yet in DESIGN: `govulncheck` and Dependabot in CI | — |
| Container images | Not decided: who builds and publishes them, and whether deployers pin digests | **Open** and not yet tracked in DESIGN §14 (F2) |
| Shared Go module `authcore` | Pinned to a verified tag (DESIGN decision #23) | — |

### 4.12 The deployer's own mistakes

| Mistake | Consequence | Defence, as designed or proposed |
|---|---|---|
| Losing the secrets backup | No recovery: device claims can no longer be verified, and OIDC secrets cannot be decrypted (DESIGN §13 scenario #12) | `nethub init` forces a backup prompt; `nethub doctor` checks that a backup exists |
| Misconfigured trusted proxies | Client IPs can be spoofed via `X-Forwarded-For`, defeating login throttling and polluting the audit log | Forwarded headers are honoured only from declared proxies; a loud warning when an undeclared peer sends them |
| Publishing internal ports (admin API, plugin endpoint, Postgres) | Direct access to internals | The compose stack is designed to publish only 443, 7000 and 8443. `nethub doctor` checks that those three are reachable. A check that the internal ports are **not** reachable is proposed |
| Turning off OPNsense's DNS-rebind / HTTP_REFERER checks to make access work | Weakens the device's own protection | Documentation says to add the relay hostname to "Alternate Hostnames" instead (Q9) |
| Installing the agent on a production router without out-of-band access | A NetHub failure can lock the operator out | The enroll page asks the user to confirm independent out-of-band access; a local kill switch exists |

## 5. Open findings

These weaknesses were found while writing this model. They are not yet
reflected in a decided design.

### F1. The device–relay control channel is not authenticated

**What the code does.** Checked against the frp v0.71.0 source:

- `pkg/transport/tls.go`, `NewClientTLSConfig`: sets
  `InsecureSkipVerify = true` whenever no CA file is configured. So `frpc` with
  `transport.tls.enable = true` and no `transport.tls.trustedCaFile` accepts
  any certificate. It never falls back to the system root store.
- `NewServerTLSConfig`: generates a random key pair at every start when no
  certificate is configured.
- `frps` loads its certificate once at start-up and never reloads it.

**Consequence.** As currently designed, the control channel is encrypted but
not authenticated. Section 4.3 describes what an attacker on the device's
network path can do with that.

**Proposed fix (open, DESIGN §14 Q10):**

1. `nethub init` generates a deployment CA and issues a long-lived server
   certificate for the relay hostname.
   - `frps` gets only that certificate and its key.
   - The CA's private key goes into the deployer's secrets backup and is
     mounted into no container. It is a new secret under DESIGN decision #21.
   - A publicly trusted certificate would also work, but it renews about every
     90 days and frps must restart to load it, which drops every tunnel. A
     long-lived certificate from a deployment CA avoids that.
2. The enroll and rotate responses deliver the CA certificate as PEM. Those
   responses travel over the verified HTTPS channel B3. frpc reads only a PEM
   file and has no fingerprint pinning.
3. The agent renders `transport.tls.trustedCaFile` and
   `transport.tls.serverName` into `frpc.toml`.

The claim stays a bearer credential even with server authentication. Mutual
TLS (DESIGN Q1) is the long-term option.

### F2. Container image provenance is undecided

See 4.11. Until it is decided, a deployer has no designed way to verify that
the images they run were built from a given release. This is not yet an open
question in DESIGN §14.

## 6. Accepted risks and known open risks

This is a selection, grouped for deployers. DESIGN §12 is the full list.

**Accepted:**

- Device credentials are stored in plaintext on the device.
- v1 uses self-signed device certificates, so browsers show warnings (fixed
  in v1.1).
- The control-plane VM is a single point of failure, with no hot standby.
- Online status reflects the tunnel, not the health of the OPNsense GUI.
- `rotate` needs the device to be online; offline devices must re-enroll.
- The signing-host exclusion (decision #20) is operational discipline.
- Login throttling is in-process (a single web instance is assumed).
- A compromised console can revoke every device, read metadata and audit,
  and phish through the device list (4.4). That is availability, disclosure
  and phishing, not impersonation of an existing hostname.
- A compromised IdP account gives console access for the users bound to it,
  bounded as in 4.9.
- After a reboot the default route may fail to install, and NetHub has no
  technical defence against that (DESIGN §12, §13 scenario #9).

**Open until Weekend 0 or a decision:**

- There is no verified way yet to cut a live tunnel (4.10).
- `nethub authz` is a single point of failure for new connections, and for
  all tunnels if `Ping` is subscribed (4.5).
- A modified `frpc` may outlast revocation (4.10).
- The device login page is exposed through the relay (Q7, 4.1).
- How `frps` behaves when a plugin call fails or hangs is unverified ([§8](#8-assumptions-this-model-depends-on)).
- The control channel is unauthenticated (F1, Q10).

## 7. Out of scope

- Vulnerabilities in OPNsense, frp, Postgres, Caddy or the relay's operating
  system themselves. NetHub's job is not to make them more reachable than
  necessary; Q7 and Q9 are about exactly that.
- Denial of service against the relay. One VM is accepted.
- Hostile tenants sharing one instance. v1 has exactly one tenant per
  instance; multi-tenancy is v3.
- Compromise of the deployer's own workstation or secrets backup.
- Physical attacks on the relay host.

## 8. Assumptions this model depends on

If any of these turns out false, this document must be revised.

1. **`frps` fails closed** when the plugin backend errors or hangs. This
   comes from reading the source and is **unverified** (Weekend 0 item ③).
2. **`NewProxy` plugin requests carry the device identity from `Login`**
   (`user.metas`), so ownership can be checked in one request. From reading
   the source; **unverified** (Weekend 0 item ②).
3. **`NewUserConn` fires for HTTPS vhost proxies and reports the real client
   IP.** **Unverified** (Weekend 0 item ⑤). It also depends on how `frps` is
   run under Docker.
4. **There is a working way to cut a live tunnel.** **Unverified** (Weekend 0
   item ⑥).
5. **The column-level grants and one-way revocation** in DESIGN §6 are
   implemented as written (**open**).
6. **Users enable OPNsense's own two-factor authentication** on enrolled
   devices. NetHub cannot enforce this.
7. **The agent's HTTPS client** for enroll, rotate and status verifies the
   port-443 certificate against the system CA bundle and never disables
   verification. The F1 fix depends on it. DESIGN §4 does not yet state it.
8. **How the device's GUI sees relayed clients** (as `127.0.0.1`), and what
   that does to OPNsense's own lockout and logs, is **unverified** (4.1).
