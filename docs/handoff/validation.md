# Validation at the handoff boundary

The handoff step was finished as a result review, including its failures; no
new runtime trial was started after the owner requested the handoff. The
continuation's later results come first; the handoff sections follow unchanged. All runs below
were terminal when reviewed. The numeric `source71`/`source72` directory names
are evidence labels, not release versions.

## Beta 3 private deployment acceptance

The signed appliance package 0.0.23 from source `f5151a8` installed on
a dedicated OPNsense VM and enrolled through its native management API.
The console and relay were reached over Tailscale. The test reapplied the
private hostname mapping after OPNsense regenerated its hosts file at
boot. An operator rule confined relay inventory access to the authorization
container and its local bridge gateway.

With the device online, Open issued a grant with 1,799 seconds remaining.
The relayed TLS leaf matched the device's local certificate fingerprint,
and the GUI returned an HTTP response. The device certificate state was
pending, so ordinary browser trust for the assigned hostname remains
unverified. Revoke denied a new GUI connection within 375 ms of the API
request, with no GUI reconnect observed for 30 seconds. Existing-stream
cutoff and mobile-carrier behavior were outside this trial.

Native resolver configuration kept the private route after reboot. The
console observed a fresh online sample after 33,580 ms from VM startup.
After a separate six-second WAN link interruption, it observed a fresh
sample 4,749 ms after link restoration. The frpc PID and start time, OPNsense
configuration hash and generated runtime hash stayed the same. Open reached
the original GUI after recovery. WAN address change was outside this trial.

A read-only grant check matched the exact requesting Tailscale source and
verified a 1,800-second lifetime. Inventory reads and relayed GUI requests
preserved expiry. An explicit second Open advanced the same grant.

Normal rotation changed the device secret and domain claim while preserving
device ID and hostname. The rotated device came online after another cold
boot and Open reached its GUI. An offline device was then revoked. Its
original Login was denied after boot. Normal local removal and manual
re-enrollment returned the replacement device to the console and GUI route.
This covered a single offline device on the private deployment.

The Beta PostgreSQL archive passed the deployment-bound hash and freshness
checks. Restoring it to an isolated PostgreSQL container reproduced device,
user and audit row counts. That container and its temporary volume were
removed. Off-host custody, whole-service restoration and renewal remain
open. These observations are from private operator records outside the
repository verifier.

### Cellular console reachability and GUI certificate preparation

The operator confirmed the Beta login page opened on a phone using cellular
data with Tailscale connected. The operator later confirmed Beta sign-in, and a read-only database check
verified that the temporary test account received a 30-minute Open grant
bound to its Tailscale source. The operator confirmed router login and
dashboard refresh from the phone. The mobile evidence is an operator report.
A masked recording and independent mobile certificate validation remain open.

The Beta deployment repaired an integrity mismatch caused by an earlier
loopback relay hook port change. The live manifest now points to a successor
backup checked against all 22 protected files. The protected host check passed
and the deployment kept running. Web and device API health checks passed at
their loopback origins. These live observations are retained in private
operator records outside the repository verifier.

The signed 0.0.23 test device enrolled with a fresh assignment and submitted
its initial GUI certificate request. After the operator accepted the CA terms,
the issuer built from `a3b23f5` registered its account and issued generation
one through Let's Encrypt DNS-01. The existing DNS provider added the exact
challenge TXT value and removed it after issuance. The authoritative servers
confirmed its removal. After the assigned hostname was added to OPNsense
Alternate Hostnames, the agent installed the certificate and confirmed
application to NetHub.

A developer host used the normal Open grant over Tailscale and verified the
device hostname and TLS chain against system trust. The served leaf fingerprint
matched the issued generation. The temporary test account logged in to the
OPNsense GUI over that route and loaded the authenticated dashboard twice.

[PR #287](https://github.com/KazuhaHub/nethub/pull/287) added the configurable
loopback port. [PR #286](https://github.com/KazuhaHub/nethub/pull/286) added
manual DNS-01. The first CI and FreeBSD runs passed for the respective merge
commits `01d2251` and `a3b23f5`. The
[protected-host cold recovery run](https://github.com/KazuhaHub/nethub/actions/runs/44658760875)
passed on PR head `eff3dd1`, whose tree matches `a3b23f5`. Its frozen
validator bound the recovery receipt to the exact-source CI producer.
The recovery fixture exercised the existing private ACME path. The Beta
DNS-01 trial verified initial issuance and application on one test device.
Renewal and mobile browser acceptance remain open.

## NetHub Beta package: 3e88574

[NetHub v0.0.19 Beta 1](https://github.com/KazuhaHub/nethub/releases/tag/v0.0.19-beta.1)
published a signed repository snapshot for FreeBSD 15 amd64 with
`os-nethub-agent-0.0.19`. Its source archive is bound to
`3e88574f79a45063684b6f5d0113bc607bd47484`. The independent candidate
verification matched all 99 files and four lifecycle hooks and bound the
package SHA-256
`05746b3d4d62d88c4491d7c92d925ba28ef0015dc413670defad4272186079ac`.
An isolated OPNsense VM installed and removed that package through the
signed snapshot and verified frpc 0.71.1. This first package has no prior
formal release for a downgrade test.

The [formal package feed](https://kazuhahub.github.io/OPNsense-repo/) lists the
same signed package under FreeBSD 15 amd64 after
[OPNsense-repo #60](https://github.com/KazuhaHub/OPNsense-repo/pull/60) and
[Pages run 44302288719](https://github.com/KazuhaHub/OPNsense-repo/actions/runs/44302288719).
The live release report passed signature verification and the HTTPS package
matched the VM-tested digest above. An isolated OPNsense VM fetched and
verified the package through the signed public catalog, installed it, verified
frpc 0.71.1 and removed it. The test VM and its volumes were removed. Public
enrollment and mobile acceptance remain open.

The package-channel drill used a separate signed test catalog offered only to a
disposable OPNsense VM. Comparing the 99 package entries and four hooks found
only the deliberate bad-template change and the product version change.
The VM installed public `0.0.19`, explicitly opted into test `0.0.20`,
confirmed the public channel still offered `0.0.19`, and downgraded to that
public package. The VM and overlay were removed. This drill exercised
package selection and rollback. Enrolled reconcile, watchdog and rollout
observation remain open.

The follow-up used the original signed public package and its normal native
enrollment page. The control plane observed the enrolled device online.
Installing the separate signed bad-template package passed strict candidate
refusal and live-configuration hash checks but failed process continuity,
before the watchdog phase. FreeBSD pkg 2.9.2 invokes the old pre-deinstall
hook on replacement, and that hook in 0.0.19 stops frpc. The source
correction skips that removal hook during package upgrades. Upgrading from
an installed 0.0.19 still runs 0.0.19's own hook, so its first transition
requires a maintenance window and independent access.

On fix source `b85af04`, a second disposable OPNsense VM enrolled through the
native GUI against an isolated Ubuntu control plane. It upgraded from signed
test baseline `0.0.21` to signed bad-template `0.0.22` in a separate test
catalog. Reconcile refused the candidate, retained the exact live configuration
and frpc PID/start time, and produced a failure audit event. Watchdog returned
`running` without a recovery journal. Downgrading to the signed test baseline
preserved the process and configuration. Neither test package was added to the
public feed. The published `0.0.19` was unaffected.

[OPNsense-repo #61](https://github.com/KazuhaHub/OPNsense-repo/pull/61)
added the independently verified frp version to the signed package release
report. [Pages run 44304655033](https://github.com/KazuhaHub/OPNsense-repo/actions/runs/44304655033)
published it. The NetHub doctor verifier fetched the public report, pinned
the repository key, verified the signature and matched frp 0.71.1 to
package 0.0.19. In an isolated Ubuntu deployment of doctor source
`fafc446`, `doctor --relay-hook --published-appliance` exercised the TLS
Login-hook rejection path and matched the running frps 0.71.1 with the same
public signed package record. This run used a private VM deployment.
[NetHub #279](https://github.com/KazuhaHub/nethub/pull/279) passed its triggered
checks and merged as `b0b6c65` with the tested tree unchanged.

## NetHub Agent 0.0.21 Beta 2

[NetHub #280](https://github.com/KazuhaHub/nethub/pull/280) source
`84f7d36` builds the 0.0.21 package with the upgrade guard. Independent
verification compared 99 files and four hooks. The exact candidate verified
its catalog signature on an isolated OPNsense VM, installed, reported frpc
0.71.1 and uninstalled. Its signed package SHA-256 is
`89e20a71cffb7d0c2cf9f5d3d64492af15908d12749c544d321b4704cb92d510`.

The first-attempt [appliance preparation run](https://github.com/KazuhaHub/nethub/actions/runs/44308601955)
passed on the same source. The collected zip, exact source-archive hash and
four inspected views were independently verified. The separate
[FreeBSD contracts run](https://github.com/KazuhaHub/nethub/actions/runs/44308602031)
passed 438 cases, and all 284 source blobs matched Git. The first-attempt
[deployment CI](https://github.com/KazuhaHub/nethub/actions/runs/44308601919)
passed all six jobs. [Protected cold recovery](https://github.com/KazuhaHub/nethub/actions/runs/44308601961)
and [installed native rotation](https://github.com/KazuhaHub/nethub/actions/runs/44308602168)
passed using its same-source image. Independent verification checked the
archive hashes and provenance. Native package migration passed all ten
phases, and revocation made the device proxy go offline in 1,027 ms with
no reconnect during the subsequent 30,068 ms observation window.

#280 merged as `d16f91f` with the tested tree. The
[signed Beta 2 prerelease](https://github.com/KazuhaHub/nethub/releases/tag/v0.0.21-beta.2)
tags `84f7d36`. A fresh download verified all four asset digests against
the published checksum file. The staged formal feed keeps
0.0.19 downloadable as a signed rollback archive and leaves the 19 other
FreeBSD 15 catalog entries unchanged. A disposable, unenrolled OPNsense VM
installed public `0.0.19`, upgraded to the exact `0.0.21` candidate through
the staged signed catalog, then explicitly rolled back to public `0.0.19`.
Both versions reported frpc 0.71.1. A separate offline VM then
installed 0.0.21 from the replacement catalog and explicitly downgraded
from the retained signed Beta 1 snapshot while the replacement catalog
continued to offer 0.0.21.

[OPNsense-repo #62](https://github.com/KazuhaHub/OPNsense-repo/pull/62)
and the [signed Pages deployment](https://github.com/KazuhaHub/OPNsense-repo/actions/runs/44320847995)
published the 0.0.21 catalog. The public HTTPS report matched the staged
bytes and verified against the pinned signing key. A disposable OPNsense
VM fetched the package from the public catalog, checked its SHA-256,
installed 0.0.21, confirmed frpc 0.71.1 and removed the package. The
test VM and its storage were removed. This test covered package
distribution and installation. Enrollment through the public NetHub
service is a separate acceptance item.

A second disposable OPNsense VM enrolled against an isolated Ubuntu
deployment of `84f7d36` after installing the formal public package.
It then installed a signed 0.0.22 bad-template package from the isolated
canary catalog. The strict verifier rejected the unknown key, reconcile
recorded the failure, and watchdog kept the original frpc process running.
Downgrading to the hash-verified public 0.0.21 preserved the same frpc
process identity and live configuration. Both VMs, their storage and
fixture credentials were removed.

## NetHub Agent 0.0.23 Beta 3

The [signed Beta 3 prerelease](https://github.com/KazuhaHub/nethub/releases/tag/v0.0.23-beta.3)
tags `f5151a8`. The independently checked FreeBSD package matched 101 files
and four hooks, including the NetHub LICENSE and NOTICE. All five hosted
checks passed on their first attempt. In the [installed native rotation](https://github.com/KazuhaHub/nethub/actions/runs/44343985060),
the proxy went offline 1,933 ms after revocation and did not reconnect
during the subsequent 30,065 ms observation window.

The [signed formal feed deployment](https://github.com/KazuhaHub/OPNsense-repo/actions/runs/44358205707)
published 0.0.23 and retained 0.0.19 and 0.0.21 as rollback packages.
A disposable OPNsense VM fetched 0.0.23 over HTTPS, verified the signed
catalog and package hash, installed it, checked both notices against the
source, then uninstalled it and verified their removal. A separate
unenrolled VM verified upgrade from public 0.0.21 to the signed candidate
and rollback to public 0.0.21.

The [first CI push run](https://github.com/KazuhaHub/nethub/actions/runs/44358079115)
on merge commit `96087ed` failed in the relay fleet pressure stage. The
changed control connection and frps Ping plugin EOF were recorded. No
hook deadline hint was retained, and the cause remains unproven. The
[FreeBSD contracts push run](https://github.com/KazuhaHub/nethub/actions/runs/44358079190)
on the same merge commit passed.

## Dependency follow-up

[NetHub #237](https://github.com/KazuhaHub/nethub/pull/237) updated lucide-react
to 1.73.0 and merged as `6f512ba` after its triggered checks passed, including
installed native rotation and protected host recovery.
[NetHub #238](https://github.com/KazuhaHub/nethub/pull/238) updated goose to
3.30.1 and merged as `f32b347` after its triggered checks passed. Both merges
are ancestors of the current release candidate.

On 2026-11-18, [authcore #37](https://github.com/KazuhaHub/authcore/pull/37)
was still a draft. Build and API compatibility passed, and
[govulncheck](https://github.com/KazuhaHub/authcore/actions/runs/42537018755/job/128903467803)
failed on GO-2026-6909. The [Go vulnerability database record](https://vuln.go.dev/ID/GO-2026-6909.json)
listed no fixed version. The reviewed interim SAML dependency pin remains
in use. The frp 0.71.1 pin remains under the owner's hold on the 0.72.0 update.

## Main integration: 0dafb70 through 24b7f29

The continuation chain was merged into `main` on 2026-11-17 as `0dafb70`
(through #272). Its tree is byte-identical to `6e948e9`, whose CI
[44048514837](https://github.com/KazuhaHub/nethub/actions/runs/44048514837)
and native filesystem contracts
[44048514709](https://github.com/KazuhaHub/nethub/actions/runs/44048514709)
passed. Side
branches #256 and #262 were not merged; #242 and #244 were closed as
superseded by content already on `main`. Every run below is a first attempt;
none was rerun.

| Change | Gates on the pull request head (tree identical to the merge) | Result |
| --- | --- | --- |
| #241 dependency refresh (`35eacc4`, merged as `9fad6ab`) | CI [44056735913](https://github.com/KazuhaHub/nethub/actions/runs/44056735913), contracts [44056735623](https://github.com/KazuhaHub/nethub/actions/runs/44056735623), preparation [44056735716](https://github.com/KazuhaHub/nethub/actions/runs/44056735716), cold recovery [44056735747](https://github.com/KazuhaHub/nethub/actions/runs/44056735747), installed native [44056735791](https://github.com/KazuhaHub/nethub/actions/runs/44056735791) | All passed; native Revoke 1,326 ms, reconcile audit with zero busy retries |
| #273 migration client classification (`aaa662e`, merged as `33b473b`) | CI [44067927567](https://github.com/KazuhaHub/nethub/actions/runs/44067927567), contracts [44067927496](https://github.com/KazuhaHub/nethub/actions/runs/44067927496), installed native [44067927669](https://github.com/KazuhaHub/nethub/actions/runs/44067927669) | All passed; native Revoke 1,841 ms |
| #274 bounded FreeBSD package fetch (`c49c339`, merged as `2a2c2fa`) | CI [44084955438](https://github.com/KazuhaHub/nethub/actions/runs/44084955438), contracts [44084961029](https://github.com/KazuhaHub/nethub/actions/runs/44084961029) | Both passed; packages fetched in 9 s and installed from cache |
| #276 relay hook response diagnostics (`c13f8e1`, merged as `24b7f29`) | CI [44097794727](https://github.com/KazuhaHub/nethub/actions/runs/44097794727), contracts [44097794467](https://github.com/KazuhaHub/nethub/actions/runs/44097794467), preparation [44097794641](https://github.com/KazuhaHub/nethub/actions/runs/44097794641), cold recovery [44097794263](https://github.com/KazuhaHub/nethub/actions/runs/44097794263), installed native [44097794581](https://github.com/KazuhaHub/nethub/actions/runs/44097794581) | All passed; native Revoke 1,125 ms |

The other completed `main` push runs passed. Three did not; they are
retained, not rerun:

- `0dafb70` CI [44056416105](https://github.com/KazuhaHub/nethub/actions/runs/44056416105)
  **failed** in Deployment checks. The heartbeat migration's command-line
  check on a freshly started frpc client failed with no recorded cause. The
  identical tree passed on its pull request. #273 makes that check report a
  closed category; the cause remains unknown.
- Native filesystem contracts on `9fad6ab`
  ([44067897336](https://github.com/KazuhaHub/nethub/actions/runs/44067897336))
  and `33b473b`
  ([44078984712](https://github.com/KazuhaHub/nethub/actions/runs/44078984712))
  were **cancelled** at the 15-minute job timeout. The FreeBSD mirror took 7
  and 10 minutes to serve `rust-1.99.1`. Both trees were identical to pull
  request heads whose contracts passed. #274 bounds and classifies that fetch.

The first CI run of this record's own pull request (#275, head `486d79b`,
[44090800058](https://github.com/KazuhaHub/nethub/actions/runs/44090800058))
**failed** at the relay fleet's ten-client stage: frps received EOF from the
authz Ping hook (the `relay_frps_Ping_plugin_EOF` hint, seen in 2 of 44
fleet runs collected before #276; the other is
[43978549471](https://github.com/KazuhaHub/nethub/actions/runs/43978549471)).
Pings run every second, so the earlier idle-timeout race is not expected to
apply. authz left no evidence because allowed Pings log at debug and the
harness read only its last 100 log lines. #276 makes slow handling
and failed hook writes report closed categories; a handler that finishes
after its write deadline reproduces the EOF in a test, but the cause of that
run is unproven. It was retained, not rerun.

Like the 5cf0f8e section, these results were verified outside the
repository against the official artifacts; the repository verifiers do not
check them. The `2a2c2fa` push runs passed (CI
[44090246565](https://github.com/KazuhaHub/nethub/actions/runs/44090246565),
contracts [44090246327](https://github.com/KazuhaHub/nethub/actions/runs/44090246327),
packages fetched in 13 s). The `24b7f29` push runs were still in progress
when this was written and are not recorded here. This is isolated hosted acceptance, not
public-network, mobile,
formal package or release acceptance.

## Continuation acceptance: be3d67c, 9c6713b and 95dbf20

Every run below is an original first attempt (`run_attempt` 1); none was
rerun. Like the 5cf0f8e section, these results were verified outside the
repository from local receipts and the official artifacts; the repository
verifiers do not check them.

**`be3d67c` (documentation corrections).** This commit corrected 18 files
against current behavior: user and deployment guides, package READMEs,
`docs/PLAN.md` and the dated `validation-w3.md` record. Its `proto/README.md`
change matched the installed-native path filter. CI
[44024374189](https://github.com/KazuhaHub/nethub/actions/runs/44024374189) and
native contracts
[44024373983](https://github.com/KazuhaHub/nethub/actions/runs/44024373983)
(417 cases, 284 files) passed. Installed native
[44024374047](https://github.com/KazuhaHub/nethub/actions/runs/44024374047)
**failed** at the reconcile-failure audit replay. WAN settling and package
migration had already passed in that run. The probe reported every refusal as
one generic category, so the failing step is unknown. Contention for the
plugin cron's `reconcile.lock` is a hypothesis, not a finding. The failure
remains unclassified. Cold recovery and appliance preparation were not
triggered.

**`9c6713bae3fb653083e6d6bea4411d155ee1e180` (probe classification).** Each
replay refusal now has its own closed category, and the probe waits out a busy
cron lock for up to 100 s per action, recording the waits. All five triggered
gates passed:

| Workflow | Original run | Result |
| --- | --- | --- |
| Complete six-job CI | [44033054224](https://github.com/KazuhaHub/nethub/actions/runs/44033054224) | Passed; producer of the tested images |
| Native FreeBSD contracts | [44033054206](https://github.com/KazuhaHub/nethub/actions/runs/44033054206) | Passed; 438 cases (new tests added) and all 284 source files bound |
| Unsigned appliance preparation | [44033054362](https://github.com/KazuhaHub/nethub/actions/runs/44033054362) | Passed; source and installed binary checked; two of four views identical to earlier reviewed captures, two reviewed (same layout apart from timestamps) |
| Protected-host cold recovery | [44033054210](https://github.com/KazuhaHub/nethub/actions/runs/44033054210) | Passed within the isolated scope; baseline route 90,681 ms, initial issuance 122,350 ms |
| Installed native rotation | [44033054221](https://github.com/KazuhaHub/nethub/actions/runs/44033054221) | **Passed every phase of the run**; isolated scope, not full rotation acceptance |

In the installed run, WAN change/restore took 3,526/4,492 ms. Bounded settling
was stable for 15,367 ms within 34,409 ms over 33 samples (maximum gap
657 ms). One sample had no route, and the fixture's private observer was
restarted once (recovered in 18,464 ms), which reset the stable window. The
reconcile-failure audit (record v2) passed with **zero** busy retries, so this
run neither supports nor rules out the lock hypothesis. Console Revoke took
the native proxy offline in **1,022 ms**, with no reconnect during a 30,056 ms
observation.

**`95dbf201ebff1a5d3e01cf3c8eae2495fdffafb0` (proxied origin idle timeout).**
The bundled Caddy v2.11.9 keeps idle upstream connections for 2 minutes, but
the web and authz origins closed them after 60 s. A reused connection could
therefore be closed under a POST, which cannot be replayed, and return 502. In
a scaled reproduction (origin idle 50 ms, client pool 2 s, 400 POSTs), 71
requests failed. None failed once the origin outlasted the pool. The origins
now keep idle connections for 150 s. CI
[44043802223](https://github.com/KazuhaHub/nethub/actions/runs/44043802223)
(six jobs, Deployment checks included) and native contracts
[44043802167](https://github.com/KazuhaHub/nethub/actions/runs/44043802167)
(438 cases, 284 files) passed. Its paths trigger no cold-recovery, preparation
or installed-native gate, so no installed or cold run has exercised this
server change yet.

The same scope limits as below apply: this is isolated hosted acceptance, not
public-network, mobile, formal package or release acceptance.

## Continuation acceptance: 5cf0f8e

The handoff results below are retained unchanged. On
`5cf0f8ef1826087d03df1c7f1258ba115b159b94` the five gates triggered by its
changes each ran once, as first attempts. The recovery database and recovery
target workflows were not triggered by these changes and did not run:

| Workflow | Original run | Result |
| --- | --- | --- |
| Complete six-job CI | [44009160953](https://github.com/KazuhaHub/nethub/actions/runs/44009160953) | Passed; producer of the tested images |
| Native FreeBSD contracts | [44009160940](https://github.com/KazuhaHub/nethub/actions/runs/44009160940) | Passed; 417 cases and all 284 source files bound |
| Unsigned appliance preparation | [44009160948](https://github.com/KazuhaHub/nethub/actions/runs/44009160948) | Passed; source, installed binary and four views checked |
| Protected-host cold recovery | [44009161079](https://github.com/KazuhaHub/nethub/actions/runs/44009161079) | Passed within the isolated scope; baseline route 106,331 ms, initial issuance 169,016 ms |
| Installed native rotation | [44009161022](https://github.com/KazuhaHub/nethub/actions/runs/44009161022) | **Passed every phase of the run**; isolated scope, not full rotation acceptance |

The appliance was OPNsense **26.7.9_3** with **3072 MiB** guest memory, frp
**0.71.1** and compiler **Go 1.26.11**; the immutable rollback source remained
`c9e74abb1fb1c060ab32ee880d20f32d8d7a653b`. The installed run passed:

- WAN change/restore (4,347/4,208 ms) and bounded settling: 15,297 ms stable
  within 33,449 ms over 32 samples, maximum sample gap 659 ms. The fixture's
  private observer sshd was found dead after SIGTERM and restarted once over
  the serial console; that sample counted as a restart and reset the stable
  window. In a local stock OPNsense lab and in the `ac6de06` console evidence,
  `rc.newwanip` regenerated OpenSSH after a WAN address event; this run records
  only the dead process and its signal.
- All ten package migration phases, including `upgrade`, which failed in a29.
  This run does not establish a29's original cause; none of the fixes listed
  below is known to address it.
- Reconcile-failure audit delivery with its actual browser view.
- Normal and interrupted Rotate (normal rotation to verified route 2,240 ms),
  trust publication conflict and committed replay, shared-token recovery.
- Console Revoke: native proxy offline in **920 ms** against the five-second
  target, no reconnect during a 30,059 ms observation, and the independent
  device unchanged.
- Restoration onto a distinct, empty Ubuntu 24.04 machine with a new
  PostgreSQL cluster: 56,453 ms from source stop to verified native and witness
  routes, without restart, Rotate or re-enrollment; off-host durable custody is
  not covered. Fixture removal through the native page also passed.

Causes of other failures fixed on the way, each with its own gates: the authorization hook
server's idle timeout was shorter than the frps plugin client's keep-alive, so
reused connections failed Ping checks (`IdleTimeout` is now 120 s); SSH banner
timeouts are classified separately; WAN identity failures retain closed console
evidence. Earlier failed originals were not rerun to replace their outcome.

This is isolated hosted acceptance. It is not public-network, mobile, formal
package or release acceptance. Its evidence is the linked original runs and
their artifacts, verified independently outside the repository; no snapshot
of them is committed here, and the repository verifiers do not check these
claims.

## External doctor public samples

Each sample ran once against the development host's own public address, with
only `--external-tcp-check-host --expected-address`, using a binary built
offline from the stated source. The doctor and external probe code is
identical in both sources.

- Closed ports, `898c3e0` (no listener, no forward): exit status 1 with the
  observer refusal message and no partial success output.
- Positive, `5cf0f8e`: temporary forwards of 443/7000/8443 to an owned disposable VM
  listener; all three ports reported **3/3** Check-Host observers connected,
  exit status 0 in 6,478 ms. The forwards and VM were removed afterwards.

These samples prove external TCP reachability only. They do not cover TLS,
relay admission or agreement with a published agent package version.

## Latest native transport correction: a29fbfe

| Workflow | Original run | Result |
| --- | --- | --- |
| Complete six-job CI | [43698475583](https://github.com/KazuhaHub/nethub/actions/runs/43698475583) | Passed; complete logs and required browser views reviewed |
| Recovery database diagnosis | [43698475548](https://github.com/KazuhaHub/nethub/actions/runs/43698475548) | Passed; seven negative controls checked |
| Distinct fresh recovery target | [43698475611](https://github.com/KazuhaHub/nethub/actions/runs/43698475611) | Passed; 121 source cases and three actual systemd controls |
| Native FreeBSD contracts | [43698475578](https://github.com/KazuhaHub/nethub/actions/runs/43698475578) | Passed; 248 cases and all 256 source files bound |
| Unsigned appliance preparation | [43698475767](https://github.com/KazuhaHub/nethub/actions/runs/43698475767) | Passed; source, installed binary, four image hashes and views checked |
| Protected-host cold recovery | [43698475660](https://github.com/KazuhaHub/nethub/actions/runs/43698475660) | Passed within the isolated scope below |
| Installed package lifecycle | [43698475533](https://github.com/KazuhaHub/nethub/actions/runs/43698475533) | **Failed at upgrade invariants** |

The appliance was OPNsense **26.7.9_1**, with **3072 MiB** guest memory, unsigned
plugin **0.0.19**, frp **0.71.1** and compiler **Go 1.26.11**. The installed frpc
SHA256 was `60f14c1bbe0504e4fdf8ce69767ba9732e289ef81374bfe02f3cda6b5fa605b8`.
The immutable rollback source was
`c9e74abb1fb1c060ab32ee880d20f32d8d7a653b`, producing unsigned **0.0.18**.
This is not a signed package or a firmware rollback qualification.

The installed failure's official artifact is **14157298029**, SHA256
`eb2c1b2c9a9e9f54eb32555029476c5c1185027a3c6b1ae346e1b5b2ec2bb290`.
Its original small ZIP is committed with the result snapshots. The seven
completed phases are `baseline`, `widen`, `offline_rollback`, `rollback`,
`legacy_recovered`, `legacy_steady`, `offline_upgrade`. The next phase was
`upgrade`; it did not pass. The report retains both outage observations and
the cleanup outcome. Guest exit and owned-image cleanup were checked; the
failed migration stopped the owned relay and restored its original config.
This does not qualify the current package, later Rotate or a new console Revoke.

The four-event read-only SSH recovery budget was preserved. One earlier
inspection preflight recovered after a connect timeout in 10,394 ms. It is not
evidence for the cause of the later upgrade-invariant failure.

## External doctor candidate: a4d8a1c

| Workflow | Original run | Result |
| --- | --- | --- |
| Complete six-job CI | [43697195854](https://github.com/KazuhaHub/nethub/actions/runs/43697195854) | Passed; full logs and required views reviewed |
| Native FreeBSD contracts | [43697195836](https://github.com/KazuhaHub/nethub/actions/runs/43697195836) | Passed; 248 cases/all 256 files |
| Unsigned appliance preparation | [43697195778](https://github.com/KazuhaHub/nethub/actions/runs/43697195778) | Passed within preparation scope |
| Protected-host cold recovery | [43697195787](https://github.com/KazuhaHub/nethub/actions/runs/43697195787) | Passed within isolated scope |
| Installed package lifecycle | [43697195777](https://github.com/KazuhaHub/nethub/actions/runs/43697195777) | **Failed transferring a private input over SSH** |

Its native run passed enrollment and WAN recovery but did not enter package
migration. No package migration report was produced. The original artifact is
**14157086578**, SHA256
`31363d5c58a5e23de2eac0c282a49a25122d58f74e4c80453c5b88c589562cb9`.
No read-only recovery event was recorded. Keep this failure separate from a29's
later upgrade failure. Neither failed original was rerun to replace its outcome.

The external doctor package and CLI boundaries passed `go test -race -count=1
./...` and `go vet ./...`. Its tests use HTTP transport fixtures; **a real
owned-public positive/closed-port drill had not been performed** at that
source (later samples: see External doctor public samples above). It sends a
public IP and ports to Check-Host only with the explicit flag. Normal doctor
modes do not contact that provider. See the candidate's
[source documentation](https://github.com/KazuhaHub/nethub/blob/a4d8a1c456464bb3a5707ad8b5c4fa6071ea592e/server/internal/externalprobe/README.md).

## Scoped measurements

| Measurement | a4d8a1c | a29fbfe |
| --- | ---: | ---: |
| Combined fault: SQL dispatch to original control/proxy closure | 1490 ms | 1459 ms |
| Combined fault: SQL dispatch to fresh verified TLS refusal | 1499 ms | 1468 ms |
| Owned packet loss | 1304 ms | 1282 ms |
| Dropped packets/bytes | 6 / 782 | 6 / 782 |
| No authenticated proxy reconnect | 30135 ms | 30187 ms |
| Minimum genuine Pongs per original reference | 33 | 33 |
| Worst of five direct-cache phases, SQL dispatch to TLS refusal | 2126 ms | 1904 ms |
| Cold baseline route, from source stop | 126986 ms | 108498 ms |
| Original initial issuance/native acknowledgement/served route, from source stop | 187491 ms | 152101 ms |
| Same issuance result, from checkpoint start | 200173 ms | 167435 ms |

Combined faults retained 99,000 synthetic revoked rows and 99,000 floors plus
twelve genuine original reference controls/routes. Valid source grants,
identities, all six service identities and the original OUTPUT rules survived.
The clock starts before SQL dispatch while actual packets are dropping. These
are isolated loopback/SQL measurements, not native confirmation-to-cutoff,
arbitrary public loss or large online-fleet capacity. Fourteen configuration
migration phases also passed; they do not replace the failed native package test.

Cold recovery restored a distinct empty target after reaping the source. The
same registered ACME account, complete database, device identity/key/CSR,
original Open grant and native retry process survived. Genuine Remove and
cleanup passed. Public operator recovery, encrypted durable off-host custody,
real renewal clocks and formal release remain open.

## Evidence and limits

[The committed index](evidence/index.json) binds original workflow/job IDs,
source hashes, artifact digests and the included result files. The native and
cold ZIPs are retained byte-for-byte. Selected closed CI reports and required
masked images are also included; this is not an archive of every CI log or OCI
image. Complete decoded job-log SHA256 values are recorded. Those logs were
checked without treating their UTF-8 encoding as the original compressed log
archive identity. GitHub artifact retention is short (the image producer uses
one day); rebuild new exact-source evidence if downloads have expired.

Each source's thirteen required console images were checked: seven changed
views were displayed, six were byte-identical to previously reviewed pixels.
The live traffic page preserved access after a warning; the 15.9 EiB values
belong to synthetic boundary fixtures. SAML and OIDC member inventories show
only their own fixture device. All cold/native enrollment/removal views were
reviewed. Native fixed-footer clipping and preformatted mobile horizontal
scrolling remain known visual limits, not claims of a polished native layout.

Earlier scoped native/public results and failures are recorded in
[the deadline history](../w5-revocation-deadline.md). The original 17.218-second
failure and earlier incomplete observers remain failures. Historical local
1 GiB testing is not the configuration of these fresh 3 GiB hosted guests.
