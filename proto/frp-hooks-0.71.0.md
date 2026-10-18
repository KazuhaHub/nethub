# Observed frp 0.71.0 hook inputs

W0 experiment ② captured these requests from the pinned, unmodified frpc and
frps 0.71.0 binaries. The client ran on OPNsense 26.7.7 behind local host NAT;
the server ran in the remote Linux LXC. A fresh all-allow connection produced
both requests. Raw payloads remain in private test evidence because they
contain deployment identifiers, network addresses, and authentication material.

These are implementation input notes, not a NetHub message schema or a change
to the device protocol. No deployed-agent compatibility or schema version
changes result from this document. Contract tests belong with the eventual
consumers; there are no consumers to update yet.

## Login

The request envelope contains `version`, `op`, and `content`; `op` is `Login`.
The observed content has these keys:

| Field | Observation |
|---|---|
| `arch`, `os`, `version`, `hostname` | Client-reported platform, binary version, and hostname |
| `client_spec` | Present in the captured request |
| `pool_count`, `timestamp`, `privilege_key` | Present; the authentication value is retained only privately |
| `metas.device_id` | Matches the client configuration's top-level `metadatas.device_id` |
| `metas.claim_placeholder` | Matches top-level `metadatas.claim_placeholder` |
| `client_address` | Control-connection peer in address-and-port form; its address matched an independent SSH connection through the same host NAT |

`client_id` and `run_id` were absent from this fresh Login JSON. Consumers must
not require them to be present or mistake the missing initial `run_id` for a
missing identity claim.

## NewProxy

The request envelope has the same structure, with `op` equal to `NewProxy`.

| Field | Observation |
|---|---|
| `proxy_name` | The configured test proxy name |
| `proxy_type` | `https` |
| `subdomain` | Exactly the configured test subdomain |
| `user.user` | Present in the user object |
| `user.run_id` | A nonempty server-assigned run identifier |
| `user.metas` | Identical to the preceding Login's `content.metas`, including both configured keys |

For this subdomain-based proxy, `custom_domains` and proxy-level `metas` were
absent from the captured NewProxy content. Device identity comes from
`content.user.metas`; it must not be confused with optional proxy metadata.

The same NewProxy request carries the device metadata and requested subdomain.
This confirms the input needed for a single-request ownership check. W0 used a
placeholder claim: it did not implement or validate NetHub HMAC signatures,
database ownership, or revocation policy. Treat all client-supplied claims as
untrusted until those checks are implemented.

See [RUNBOOK experiment ②](../weekend0/RUNBOOK.md) for the capture procedure
and the distinction between Login metadata and proxy metadata.
