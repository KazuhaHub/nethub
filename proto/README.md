# proto/ — NetHub protocol definitions

This directory is the **single source of truth** for the wire protocol
between the NetHub control plane (`server/`) and any device agent. It is
consumed by:

- the control plane in this repository — the device API that `nethub authz`
  serves (see [Messages v1 needs to define](#messages-v1-needs-to-define));
- the platform agents under `agents/`, which reference these schemas directly
  rather than vendoring a copy, and whose contract tests run against them in
  this repository's CI.

If you are adding or changing a message shape, also read the
["Changing the protocol"](../CONTRIBUTING.md#changing-the-protocol-proto)
section of `CONTRIBUTING.md` — it covers the required version bump, contract
test update, and compatibility statement for any PR that touches this
directory.

> **Status:** pre-alpha, design stage. The design is v0.3 (a draft, see
> [`docs/DESIGN.md`](../docs/DESIGN.md)). No schema files exist yet; this
> README describes the intended shape of the directory and the messages v1
> needs, not a finished, stable API. Treat anything here as subject to change
> until a `1.0.0` schema version is cut.

W0 captured the upstream hook inputs in
[Observed frp 0.71.0 hook inputs](frp-hooks-0.71.0.md). These are evidence for
future consumers, not a published NetHub schema.

## Why this directory exists

The control plane and every platform agent have to agree, exactly, on what a
message looks like. When that agreement is implicit — each side keeping its
own idea of the wire format — they drift apart silently, and the failure shows
up in the field rather than in CI.

Keeping the agents in this repository removes the cross-repository version of
that problem, but not the problem itself: a deployed agent can be months older
than the server it talks to. So the schemas here are versioned, agents report
an `agent_protocol_version` at enrollment, and the server rejects incompatible
versions with a readable error instead of half-working.

`proto/` exists to make that impossible by construction: there is exactly one
place the message schemas are defined, this repository, and every consumer
reads from it rather than redefining it.

## Format: JSON Schema

Messages are defined as **JSON Schema** documents. JSON Schema was chosen
because it is:

- language-neutral (the control plane is Go; the OPNsense agent is PHP and
  Python — `agentctl.py` — driving a vendored Go binary, `frpc`), so no single
  language's native type system should own the schema;
- directly usable for contract testing on both sides: this repository's CI
  validates real request/response payloads against the schemas for **both**
  the Go server side (the device API served by `nethub authz`) and the Python
  agent side (`agentctl.py`);
- human-readable enough to diff sensibly in a PR.

## Platform neutrality

`proto/` must stay platform-neutral. OPNsense is the only shipped platform in
v1, but the architecture leaves room for OpenWrt and VyOS agents later
without a protocol rewrite. Concretely, that means:

- **No OPNsense-specific vocabulary in the schemas.** Do not use field names
  like `config_xml`, `pf_rules`, or anything else that assumes a specific
  platform's internals. Use platform-neutral terms instead: `device`,
  `platform` (an enum/string identifying which agent implementation this is,
  e.g. `"opnsense"`), and `capabilities` (a list/set describing what this
  device/agent combination can actually do).
- **Capability-gated, not platform-gated.** If a future message needs to
  express "this device can do X," express it as a capability the device
  reports, not as an `if platform == "opnsense"` special case baked into the
  schema.
- A reviewer should reject a PR that leaks a platform-specific concept into a
  schema under this directory; that concept belongs in the consuming agent's
  own directory under `agents/` instead (e.g. how `os-nethub-agent` maps a
  NetHub-level concept onto OPNsense's actual config internals is entirely
  that agent's concern, not this directory's).

## Versioning

Each schema/message carries a version. The exact scheme (semver on the whole
`proto/` directory vs. per-message versioning) is still being decided — this
section will be filled in with the finalized policy before the first
non-prerelease tag. What is already decided, and non-negotiable:

- A breaking change to an existing message's shape requires a version bump,
  not an in-place mutation of the existing version.
- Every enroll request carries an `agent_protocol_version` field so the
  control plane knows exactly which protocol version a given agent speaks.
- The control plane **explicitly rejects** an agent reporting an incompatible
  `agent_protocol_version` (clear error, not silent misbehavior). It does not
  attempt best-effort compatibility shims across incompatible versions in v1.
- A PR that changes `proto/` updates every affected agent under `agents/` in
  the same PR, and the contract tests run in this repository's CI.

## Packaging and deployed agents

The packaging repository (`KKazuhaK/OPNsense-repo`) holds only a packaging
recipe: it builds NetHub packages from tagged releases of this repository, so
it inherits whatever schema version that tag contains and never pins or tracks
`proto/` on its own. There is no second repository whose CI has to be kept in
step, and no contract tests run there — they run here.

What still needs care is the *deployed* agent against a running server, since
the two are upgraded independently:

1. At runtime, the agent reports `agent_protocol_version` on enroll (see
   above), so a deployed agent built against an older schema than the server
   expects is caught at enrollment, not discovered through odd behaviour
   later.
2. The server answers an incompatible version with a clear, readable error
   rather than letting the agent half-connect.

## Messages v1 needs to define

The following messages are the minimum set required for the v1 feature (see
the top-level project README): remote access to an OPNsense box behind
CGNAT/dynamic IP, with no port forwarding, without the control plane ever
touching the device's `config.xml`, firewall rules, or services.

The device API is served by **`nethub authz`**, at
`/api/v1/devices/{enroll,rotate,unenroll,status}`; Caddy routes these paths
from public port 443 to `nethub authz`. The console's own JSON API
(`/api/v1/console/...`, served by `nethub web` to its SPA) is not a device
protocol and is out of scope for this directory.

- **Enroll request / response** — sent once when a device is onboarded, to
  `/api/v1/devices/enroll`. The request carries at minimum: `platform`,
  `platform_version`, `agent_version`, `agent_protocol_version`,
  `capabilities` (for the v1 OPNsense agent, just `remote.web`), and the
  one-time enroll token that authenticates the request. The response carries
  the assigned subdomain (random, generated by the server — never chosen by
  the client), the signed domain claim (see below), and what the device needs
  to bring up its tunnel: the device credentials, the `frps` token, and the
  relay address and port (7000).
- **Domain claim** — the HMAC-signed statement, issued by `nethub authz` at
  enroll time, that binds a device identity to its `*.router.example.com`
  subdomain: HMAC-SHA256 over a canonical payload
  `{device_id, subdomain, tenant_id, issued_at, key_id}`, where `key_id` lets
  the signing key be rotated. The signing key never reaches the web process;
  only `nethub authz` signs and verifies, and only the signature and claim
  payload are handed to the device. `frps`'s `httpPlugins` (`Login`/`NewProxy`)
  are handled by `nethub authz`, which verifies that a claim is both
  cryptographically valid **and** consistent with what the database currently
  has on record for that device — this message's schema needs to carry
  everything both checks require. (The exact field names `frps` sends to its
  plugin are confirmed by Weekend 0, not assumed here.)
- **Status report** — an agent-to-control-plane report, to
  `/api/v1/devices/status`. Platform-neutral device health information, not
  device configuration state. Whether a device is online is derived from its
  `frpc` control connection, not from this message.
- **Rotate** — request/response for rotating device credentials (e.g. the
  material backing the domain claim) or the relay address, to
  `/api/v1/devices/rotate`, driven by `agentctl.py rotate`.
- **Unenroll** — request/response for cleanly removing a device's enrollment
  (releasing its subdomain and invalidating its domain claim so it can no
  longer authenticate), to `/api/v1/devices/unenroll`, driven by
  `agentctl.py unenroll`.
- **Reconcile** — re-applies the device's last-known enrollment state locally
  (e.g. re-rendering the `frpc` config from the stored settings and
  restarting the tunnel if it drifted), driven by `agentctl.py reconcile`.
  It may turn out to be **purely agent-local**, with no wire message of its
  own beyond what `status` already carries; that is not yet decided.

`agentctl.py` is expected to expose five one-shot subcommands in total —
`enroll`, `reconcile`, `status`, `unenroll`, `rotate` — while this list names
six messages, so the two do not map one to one:

- `enroll`, `status`, `rotate` and `unenroll` each correspond to an endpoint
  above;
- the domain claim is a payload carried inside the enroll response, not an
  endpoint or a subcommand of its own;
- `reconcile` is a subcommand that may have no wire message at all.

Exact field-level schemas for each of these are not yet written; this list is
the contract for what needs to exist, to be turned into actual `.schema.json`
files (or similarly named) in this directory as they're implemented.
