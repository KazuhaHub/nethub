# Relay observations

The authz runtime polls frps immediately, then every 15 seconds without overlapping
requests. Enable it with `--frps-admin-origin`, `--frps-admin-user-file` and
`--frps-admin-password-file`; partial configuration fails startup. Credentials
come from private regular files. The origin has an explicit port and no path,
userinfo, query or fragment. DNS results must all be private or loopback; the
transport dials a validated literal address, ignores environment proxies and
never follows redirects. HTTPS uses normal system-root/hostname verification.

The fixed read-only request is `GET /api/proxy/https`, following frp 0.71.1's
[router](https://github.com/fatedier/frp/blob/v0.71.1/server/api_router.go),
[controller](https://github.com/fatedier/frp/blob/v0.71.1/server/http/controller.go)
and [response types](https://github.com/fatedier/frp/blob/v0.71.1/server/http/model/types.go).
Admin JSON embeds configuration with camelCase `customDomains`; callback JSON
uses `custom_domains`. Only canonical per-device HTTPS names with a matching
configuration name, assigned subdomain, no custom domains and no shared group
become observations. Offline and unrelated proxies do not refresh devices.
Duplicate keys/names, malformed recognized routes and incomplete responses fail
the whole poll before storage.

Limits are 1 MiB, 1,024 proxy entries, a three-second HTTP operation and two-second
storage operation within a five-second poll context. Unsupported encodings and
ambiguous media headers fail. Large historical lists require operator maintenance;
this poller does not prune them or call any mutation endpoint. The shared JSON
reader's default 64 KiB/256-item device request limits remain unchanged.

Storage gets tenant scope from existing database rows under the authz role and
preserves forced RLS. It updates only `last_seen_at`, using the database clock,
where device ID/subdomain match and the device is not revoked. Unknown devices
are not created. Busy device rows are skipped to avoid delaying authorization;
they can be observed on the next poll. No secrets, claims, grants, identity fields
or revocation state change. Admin status is a display signal, not signed identity
or permission to access a router.

Failures leave timestamps untouched. The console already labels a matching
observation as recent for 45 seconds; missing observations naturally age out.
Log fixed failure/recovery transitions without URLs, admin credentials, response
bodies or dependency diagnostics. An admin outage does not stop the authorization
listeners. Shutdown cancels the poller and closes its idle connections before
closing the shared database pool.

Local Go tests cover parsing, bounds, private address policy, authenticated GET,
redirect/proxy isolation, TLS rejection, stalled responses and safe retry logging.
The genuine PostgreSQL follow-up tests matching/unknown/revoked/wrong routes,
multiple tenant scopes, unchanged identity fields, console expiry, lock skipping
and role grants. Its compiled CLI test uses a local admin HTTP fixture at the
real 15-second cadence and checks persisted status plus clean shutdown. Those
native additions still need CI. Real frps responses and multi-client traffic
remain W4 deployment acceptance; the fixture is not a real relay process.
