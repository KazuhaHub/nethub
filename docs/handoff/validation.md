# Validation at the handoff boundary

The handoff step was finished as a result review, including its failures; no
new runtime trial was started after the owner requested the handoff. The
continuation's later results come first; the handoff sections follow unchanged. All runs below
were terminal when reviewed. The numeric `source71`/`source72` directory names
are evidence labels, not release versions.

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
