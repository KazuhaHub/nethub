# Native enrollment and initial trust application

On 2026-10-22, the isolated OPNsense VM enrolled into a generated NetHub
deployment and acknowledged its first relay trust generation. The relay
registered the native HTTPS proxy. A subsequent trust poll retained the frpc
PID and CA bytes.

The [sanitized receipts](validation-relay-trust-native.json) record the observed
results. Credential-bearing requests, configurations and logs remain outside Git.

## Inputs and environment

The server used the four images from [CI run 39767150067](https://github.com/KazuhaHub/nethub/actions/runs/39767150067),
tested at `ffe87fc` and accepted in PR #123. The native unsigned 0.0.12 package
was built at `e6ce45c`; its SHA256 is
`3af38de19479bf24203c4f97eae081ae9d4b26acf39e42255bd6f17dc93c7b19`.
The plugin and protocol inputs were unchanged between these revisions. Both
frp peers were 0.71.1 built with Go 1.26.10.

The appliance retained the owner-approved 1 GiB memory deviation. Its server
ran in a separate Debian 13 Hyper-V VM with 512 MiB RAM, 2 GiB swap and two
virtual CPUs, using Docker 29.9.2 and Compose 5.6.1. Capacity and latency remain
unvalidated.

The generated deployment used external-proxy mode. An operator-owned Caddy
provided console HTTPS using an independent private CA. Only its public
certificate entered the appliance's default trust store. TLS chain and hostname
verification remained enabled. CA signing keys stayed on the server outside
application mounts.

## Observations

| Path | Verified behavior |
| --- | --- |
| Generated deployment | Services became healthy; verified HTTPS login produced a secure administrator session. Console health and relay hooks remained private. HTTP origins refused connections through the server's LAN address. |
| Native enrollment | A protected request file reached configd. The native agent enrolled over verified HTTPS; PHP assignment validation and the genuine OPNsense model saved the response. Explicit service start succeeded. |
| Relay registration | The frps administration API reported the assigned native HTTPS proxy online. |
| Trust application | Scheduled native synchronization applied generation 1 and confirmed it with the server. PostgreSQL contained one matching application row and one application audit event. |
| Repeated poll | A further native worker invocation under the shared reconcile lock remained confirmed, retained the frpc PID and left CA bytes unchanged. |
| Server interruption | After the first bounded server shutdown, PostgreSQL recovered and the host CLI returned the exact previous publication. Services and verified console HTTPS recovered. |
| Appliance restoration | Independent cold-checkpoint restoration returned the original 0.0.6 package, configuration hash, runtime permissions and stopped intent. All 25 baseline file locations were checked. The minute cron refreshed `state.json`; immutable files matched. Temporary CA trust, hosts, key and transaction paths were removed. |

The enrollment harness exercised configd and the PHP assignment/model path.
Browser submission of the enrollment form remains pending. The repeated-poll
measurement held the shared lock across PID sampling and the worker call;
an earlier unlocked sample encountered the scheduler's normal quiesce window.

The second server window received a guest shutdown request before its guard
completed with the VM off and disk retained. A clean PostgreSQL stop for that
window has not been independently established. The appliance's final restoration
was verified separately over pinned SSH. Existing shared LXC services were
untouched.

## Remaining acceptance

Native retry after a lost successful report response, overlap deployment,
authority switch, retirement barriers and offline recovery remain required.
This run also leaves browser enrollment, automated GUI certificate issuance,
installation and renewal, and the combined public GUI path unverified. No public
CA account or order was created. W4 remains open; this evidence does not complete
the later source-IP gating, revocation, identity-provider or release gates.
