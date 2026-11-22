# Decisions and related repositories

These are the recorded owner decisions to preserve. The source-of-truth details
remain in [PLAN](../PLAN.md), [DESIGN](../DESIGN.md),
[W4 decisions](../w4-decisions.md) and the stage-specific deployment guides.

## Product and security boundaries

- Apache-2.0 is the approved license exception. The source repository was made
  public; that does not close the remaining D12 content review or permit history
  rewriting without a separate decision.
- Preserve future platform interfaces (`proto/`, platform/capability fields and
  adapter separation). Only the OPNsense agent is implemented; do not claim an
  OpenWrt/VyOS agent exists.
- Use authcore for shared local/OIDC/SAML authentication. SAML is implemented;
  the remaining public-provider sample is not a missing SAML feature. Do not
  duplicate authcore in NetHub.
- Keep the three frp consumers aligned at **0.71.1**. PR #236's 0.72 update is
  not the approved three-way upgrade. Keep the Go **1.26.11** compiler pin and
  source/SDK/checksum verification.
- Retain port **8443** and the **five-second** revocation target. Current
  heartbeat configuration is **1-second interval / 3-second timeout**; older
  10/30 settings belong to the explicit mixed-profile migration test, not the
  desired new deployment. Backend/hook failures must remain bounded; no bypass
  of deny decisions to preserve an apparently healthy tunnel.
- Source-IP access is an explicit **Open** grant for 30 minutes. Clicking again
  renews it; traffic alone does not extend it.
- shadcn/ui with native `dialog` is the approved console choice. Keep CSP checks.
- Enrollment has a separate console HTTPS-address field and token. Keep SemVer
  compatibility checks, PHP model writes and 0600 temporary token-file paths
  passed to configd rather than raw token arguments.
- Keep exact manually configured Alternate Hostnames and both native GUI
  security checks enabled. Do not disable them to make passthrough succeed.
- There is no `newwanip` restart hook. frpc reconnects; periodic reconcile checks
  state. WAN recovery must be measured and the fallback revisited if it cannot
  recover normally.
- Package-owned cron.d entries run reconcile every minute and an independent
  watchdog every five minutes, with root/absolute paths/log output. Both share
  `lockf -t 0`. Persist bad-config hashes and one-attempt state; do not reapply an
  abandoned desired config until it changes. Disabled/revoked devices must not
  be restarted by the watchdog. Install/reboot/uninstall cron checks remain part
  of device acceptance.
- Use deployment-specific relay trust. Application containers do not receive CA
  signing authority. Keep automatic device GUI certificate issuance, application
  and renewal within v1; console reverse-proxy TLS belongs to the proxy operator.
- D14 is confirmed: device mTLS stays a v1.1 evaluation; audit chains have no
  external anchoring and document that limit; the owner allows packaging/signing
  on the same host, but runtime containers must not mount signing authority;
  CARP has cluster labels/alarms, not verified transparent failover.

## Related work and exact references

| Work | Repository / PR | Exact head at handoff | Disposition |
| --- | --- | --- | --- |
| Native/deadline work | [NetHub #231](https://github.com/KazuhaHub/nethub/pull/231) | `a29fbfe52a1a7774a538a33081277be2a253ab97` | Draft; resolve native upgrade failure before merge |
| External TCP doctor | [NetHub #242](https://github.com/KazuhaHub/nethub/pull/242) | `a4d8a1c456464bb3a5707ad8b5c4fa6071ea592e` | Draft; integrate after current native correction and validate new source/public samples |
| Seven non-frp dependency updates | [NetHub #241](https://github.com/KazuhaHub/nethub/pull/241) | `5a4ccf3c1f952c497126454a5d1a8b9b4139abbb` | Draft; earlier native Rotate returned explicit busy; later empty-lock inspection did not prove the cause |
| frp 0.72 update | [NetHub #236](https://github.com/KazuhaHub/nethub/pull/236) | `7b874d701e29f567bdc74ba53c7eb5aadf3c89d9` | Not approved for adoption; preserve 0.71.1 |
| SAML upstream compatibility | [authcore #37](https://github.com/KazuhaHub/authcore/pull/37) | `e3e8cc05330fcff6cbd21c6f38e10320a165c0e1` | Draft; not the active NetHub module pin; review old scan failure and compatibility before adoption |
| Formal packaging preparation | [OPNsense-repo #52](https://github.com/KKazuhaK/OPNsense-repo/pull/52) | `85c5c522735a723ebb07a324283a7be62da6255c` | Draft; source/adapter/license groundwork, not registry entry or signed publication |

The active authcore and SAML parser pins are in `server/go.mod`/`go.sum`:
authcore commit `c1447857d71b`, with the explicitly repeated OpenCTEM parser
replacement at `2b3cdad337cd`. Replacements are not inherited from a dependency.
Read [the SAML dependency record](../../deploy/saml-dependency-security.md) before
changing it. A successful call-graph scan does not mean every advisory is absent;
recheck current upstream advisories and preserve the distinction.

The packaging and authcore repositories remain independent projects, as the
owner requested. Their pending patches are copied into this repository for
handoff portability, with base/head references in [patches](patches/README.md).
On Ubuntu clone them normally when needed:

```sh
git clone https://github.com/KKazuhaK/OPNsense-repo.git
git clone https://github.com/KazuhaHub/authcore.git
```

For packaging, restore the recorded base `fcaf6fe67c1bd296ebb7e5652183512fcf2983fa`
before applying the preparation patch. For authcore, its patch base is
`f3886de2dcef2fc09536b97b4ec4c93dcf5df1cb`. Do not infer acceptance of either PR
from its presence here. The final release still needs a real NetHub tag/archive
and SHA256, candidate/native verification, registry integration, signing,
publication, a small canary, and rollback/bad-canary evidence. Signing keys and
account credentials must be supplied by their operator, never stored here.

## Stable release numbering

NetHub stable releases use UTC ISO week-year and week. The first release of
a week uses `YYYY.W`, with an unpadded week and no `.0` suffix. Further
releases in that week use `YYYY.W.1`, `YYYY.W.2`, and so on. For example,
`2026.47` is followed by `2026.47.1` if there is another release that week.

Git tags add a leading `v`. The Docker and OPNsense package versions use the
same number without that prefix. Existing Beta tags and the device protocol
version retain their own numbering.

Run **Prepare weekly release** from `main` to create the source update for
the next release. The workflow reads published Git tags, allocates the
number and returns a patch and its base commit. The candidate still needs
to pass the release checks before the tag, archives and signed package are
published.
