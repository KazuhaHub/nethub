# Validation at the handoff boundary

The current step is finished as a result review, including its failures. No new
runtime trial was started after the owner requested the handoff. All runs below
were terminal when reviewed. The numeric `source71`/`source72` directory names
are evidence labels, not release versions.

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
owned-public positive/closed-port drill has not been performed**. It sends a
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
