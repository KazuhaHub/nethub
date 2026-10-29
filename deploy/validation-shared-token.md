# Shared-token incident validation

Source `e3dfef5394d6e6f907b67b257b3aca616abfca2b` passed the isolated host and
online native/reference recovery checks on 2026-10-29. The
[operation procedure](shared-relay-token-rotation.md) covers the controlled
window and manual offline recovery. This accepts the recorded operation scope;
public/mobile, complete restoration, off-host custody and release gates remain
separate. [Closed measurements and image hashes](validation-shared-token.json).

## Host command and reference clients

All six jobs in [CI 40845857458](https://github.com/KazuhaHub/nethub/actions/runs/40845857458)
passed. Complete official logs and the actual compiled-command outcomes were
independently checked.

- With a genuinely empty device table, the command refused before preparation.
  Secrets, runtime, backup and all six service IDs stayed unchanged; no command,
  operation or candidate-backup record was created.
- SIGTERM during the durable reload phase retained the candidate and ordinary
  maintenance fence. Resume completed the same operation and verified actual
  candidate/previous/candidate Login over trusted local TLS.
- Only authz/frps were re-created. Four unrelated services and the original
  backup survived; a complete current-key successor verified independently.
  A completed retry verified current state without another reload.
- Two original online reference clients obtained the replacement through their
  saved device bearers. Candidate replay was identical, old bearers received
  HTTP 401, identity/source grants survived, and both original assigned HTTPS
  routes recovered in 693 ms.

The [protected Linux run](https://github.com/KazuhaHub/nethub/actions/runs/40845857293)
passed all 92 required filesystem/phase identities; its exact-source validator,
complete log and bounded receipt were checked. These use synthetic protected
material. The [FreeBSD run](https://github.com/KazuhaHub/nethub/actions/runs/40845857289)
passed 214 actual cases, including the required journal identity, with all 242
source blobs verified against Git.

## Installed OPNsense

[Preparation 40845857269](https://github.com/KazuhaHub/nethub/actions/runs/40845857269)
installed unsigned development package 0.0.18 on a fresh verified OPNsense 26.7.7
guest. Configd and desktop/mobile page checks passed. The installed frpc was
0.71.1, built with Go 1.26.10. The exact archive, image signature, package/runtime
result, log, guest exit zero and four image hashes/visuals were checked. Two
mobile images are byte-identical. Preparation alone covers an unconfigured page.

[Complete installed run 40845857496](https://github.com/KazuhaHub/nethub/actions/runs/40845857496)
used the same source's tested immutable images and performed a second host token
replacement. It resumed an actual SIGTERM interruption and refused the first,
now-superseded completed operation without rolling back token bytes or changing
service IDs. Genuine native **Rotate credentials**, through independent private
management, recovered the original assigned HTTPS route in 2617 ms. The saved
bearer supplied the new assignment; no new enrollment token was delivered.

Native model readback confirmed new token/bearer/claim and retained policy,
identity, source grants, GUI key, both GUI security checks and exact alias. The
independent official-client witness also recovered its original verified route.
Old native device credentials received HTTP 401.

The existing per-device cases also passed: initial recovery 2584 ms, lost
committed-response retry 2366 ms, and received-assignment/native-save interruption
retry 2586 ms with the rotation endpoint returning verified HTTPS 503. Genuine
Remove confirmed revocation, cleared model, stopped service, removed journal and
closed route while preserving the independent witness. The full remaining
Compose tail and owned image cleanup completed; the guest exited zero.

The exact source archive, both complete official logs, standalone incident report
and eight page/image hashes were checked. All corresponding visuals were
reviewed; four positive rotation images are byte-identical. The Remove image is
cropped at the Enrollment heading by the native footer. Its cleared state has
independent DOM/database/XML/service/route proof and is not visually visible in
that crop.

## Retained limits and earlier gap

Source `19bfce2`'s installed run `40841093577` succeeded functionally, but its
upload list omitted the new standalone report and PNG. Its nested outcome and
eighth page/hash receipt survived; full acceptance was withheld. The corrected
upload contract has a regression check against the approved public evidence
list. The current run retained every required export. The earlier successful job
and its evidence gap remain recorded separately.

These measurements use fresh hosted VMs, owned loopback/NAT fixtures and test
CAs. The management browser permits the fixture GUI's self-signed certificate;
the separate assigned-route checks verify the expected CA and hostname. The
timings are observations, not a fleet or production performance guarantee.

Host completion still requires an eligible nonrevoked enrolled identity; an
empty or fully revoked deployment is refused before mutation. The identity may
be offline. Keep one eligible identity through server verification, then revoke
offline entries requiring manual re-enrollment before returning them to service.
Token replacement itself does not expire stored device bearers or deliver
automatic fleet updates.

The installed cases cover response loss and native save interruption. The
trust-publication-conflict/synchronization branch retains its separate SQL and
native-contract evidence; this report does not claim an additional installed
conflict scenario. Unknown partial files require local review; arbitrary
hard-kill and power-loss recovery are not established. No formal signing,
published package, public-network incident, offline-fleet drill or complete
clean-host/key/device restoration was performed here.
