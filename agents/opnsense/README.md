# agents/opnsense/ — the OPNsense agent

This directory holds **everything NetHub runs on an OPNsense box**: the plugin
source, the protocol adapter, and the platform capability declaration.

```
agents/opnsense/
  plugin/          the os-nethub-agent plugin source (PHP MVC, rc.d, configd,
                   Jinja2 templates, agentctl.py)
  capabilities.md  what this platform can do, as reported to the control plane
  tests/           contract tests against ../../proto/
```

> **Status: pre-alpha with scoped installed acceptance.** The plugin includes
> verified enrollment, native settings, tunnel/recovery scheduling, GUI certificate
> automation, relay trust and recoverable credential rotation. See the
> [plugin guide](plugin/README.md) and [current acceptance records](../../docs/HANDOFF_PROMPT.md).
> Each record binds its source and environment; changed builds require their own
> checks. Public/operator W5-W7 and formal release remain incomplete.

## Why the source lives here and not in the packaging repository

The intended formal NetHub packaging flow uses a separate
repository — `KKazuhaK/OPNsense-repo` — which has a working FreeBSD build,
signing, and pkg-repository pipeline that would be expensive and pointless to
reproduce. It is the owner's own fork, developed independently, so there is no
co-maintainer to coordinate with.

The planned integration carries a **packaging recipe**, not duplicate source:

```
KKazuhaK/OPNsense-repo/
  packaging/plugins.json          one entry registering os-nethub-agent
  src/os-nethub-agent/build.sh    fetches a tagged NetHub release tarball,
                                  verifies its sha256, stages it into the pkg
```

This mirrors what that repository already does for `os-sing-box`, `os-frp`
and `os-easytier`: it packages upstream software it does not own. From its
point of view, NetHub is simply another upstream.

Keeping the source here buys three things:

1. **One copyright, one license.** Every line of NetHub is Apache-2.0 and owned
   by its authors. The packaging repository is MIT and has other copyright
   holders in its history; mixing a new project into it would leave ownership
   permanently ambiguous.
2. **No protocol drift.** `proto/`, the agent, and the server are in the same
   repository, so a protocol change is a single pull request with contract
   tests that run against both sides. A cross-repository split is where this
   class of project usually rots.
3. **Room for other platforms.** `agents/openwrt/` and `agents/vyos/` can sit
   beside this directory without either of them needing to know anything about
   FreeBSD packaging.

The cost is that day-to-day iteration on the plugin's web UI spans two
checkouts. During development, symlink or `rsync` this directory into the
packaging repository's `src/os-nethub-agent/` instead of committing to both —
only the release flow is genuinely cross-repository.

## What the agent is

The device runs **no NetHub daemon**. The only persistent process is a
independently packaged, unmodified `frpc` binary. Everything else is a one-shot script
invoked through OPNsense's `configd`, which is what keeps the agent's
privileges narrow: the control plane cannot execute arbitrary commands, only
the actions explicitly registered in `actions_nethub-agent.conf`.

The device side stays **Python 3.13 (`agentctl.py`) plus PHP/Phalcon MVC**,
because OPNsense dictates both. This is separate from the control plane, which
is Go (see [`server/README.md`](../../server/README.md)); across the project,
Python also implements the agent's bounded protocol, recovery and certificate/trust
helpers and isolated acceptance tooling; it is not the control-plane runtime.

`agentctl.py` exposes these bounded operations. PHP owns native model writes;
Python requests and validates assignments. Retried mutations retain their durable
operation state rather than creating another enrollment or candidate:

| Subcommand  | What it does |
|-------------|--------------|
| `enroll`    | Exchanges a token from a private request file over verified console HTTPS, validates the assignment and returns it to PHP for native persistence. The relay control channel is separately on port 7000. |
| `reconcile` | Checks the local kill switch first, then renders `frpc.toml` from settings to a temporary file, validates it with `frpc verify` **before** replacing the live file, and restarts the tunnel only if validation passed. If it fails, the old file is kept and nothing restarts. WAN changes rely on frpc reconnect and periodic reconcile. W2 measures recovery; a debounced hook is required only if automatic recovery fails (D21). |
| `status`    | Reports service state, the tail of the plugin's own `frpc` log, and the last reconcile result — without enabling `frpc`'s `[webServer]` (see below). Whether the device is online is tracked by the control plane separately, as `last_seen_at`. |
| `unenroll`, `forget` | Revoke/remove the assignment or explicitly forget terminal local state through the guarded native workflow. |
| `rotate` | Journal one replacement candidate, recover the same operation across interruption and let PHP save the verified assignment. Identity and local policy remain unchanged. |
| `report` | Send bounded health and learn revocation; reports do not establish relay-observed online state. |
| `certificate`, `trust` | Independently synchronize and verify GUI certificate or relay trust state under the common mutation lock. |
| `start`, `stop`, `restart`, `disable`, `enable` | Operate the owned tunnel or local circuit breaker while respecting disabled/revoked/recovery state. |

## Coexisting with `os-frp`

A user may already run `os-frp` for their own frpc/frps. NetHub does not reuse
it, and the two must not interfere (DESIGN decision #2 and §4).

`os-frp` installs `/usr/local/sbin/frpc`, `/usr/local/etc/frp/frpc.toml`, the
rc.d script `frpc`, `rc.conf.d/frpc`, and its own pidfile and log. **NetHub
reuses none of them:**

| | `os-frp` | `os-nethub-agent` |
|---|---|---|
| Binary | `/usr/local/sbin/frpc` | `/usr/local/opnsense/nethub-agent/bin/frpc` |
| Config | `/usr/local/etc/frp/frpc.toml` | `/usr/local/etc/nethub-agent/frpc.toml`, rendered by template |
| rc.d name | `frpc` | `nethub_agent_frpc` |
| pidfile, log, daemon title | its own | its own, separate |

Rules that follow from this:

- **Do not enable `frpc`'s `[webServer]`.** Its default `127.0.0.1:7400` would
  collide with `os-frp`'s admin UI. `agentctl.py status` instead combines three
  sources: the rc.d state, a log tail, and the last reconcile result. The
  control plane separately knows `last_seen_at`.
- **Ship a `FRP_VERSION` file** in both packages, so CI can enforce that the
  frp version in `os-frp` and in `os-nethub-agent` match (DESIGN decision
  #19). The selected pin is 0.71.1 (D4 confirmed), and the `frps` image on the server side
  must match.
- **Test it on a box that has `os-frp` installed and running.** Weekend 2's
  acceptance is that `os-frp` keeps working — its process, config and ports
  untouched. Kazuha permits the designated packaging test machine to build
  and sign packages while also running NetHub tests (DESIGN decision #20,
  revised 2026-10-17). It must not be a production router.

## Platform capabilities

The control plane never hardcodes "OPNsense". A device reports a `platform`
identifier and a `capabilities` list at enrollment, and the console enables
features from that list. For v1 the OPNsense agent declares exactly one
capability: `remote.web` — proxy the local HTTPS web UI. Configuration
backup, configuration push, and telemetry are v2+ capabilities and are
deliberately absent.

See [`../../proto/README.md`](../../proto/README.md) for the wire format and
[`../../docs/DESIGN.md`](../../docs/DESIGN.md) for the full design and threat
model.
