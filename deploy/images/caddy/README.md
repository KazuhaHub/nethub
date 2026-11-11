# Caddy helper dependencies

The image rebuilds the standard Caddy 2.11.9 bundle with the pinned Go toolchain
and module checksums. `v2.11.9-nethub.1` identifies the local dependency rebuild;
it is not an upstream Caddy release.

The compression dependency is pinned to `github.com/klauspost/compress v1.20.2`
for GO-2026-6865. The required scan reached the vulnerable FSE/Huffman code through
the standard Caddy bundle at v1.20.1. Keep this reviewed dependency while updating
the standard bundle; no scanner exception is introduced. The
prepared source, helper tests, source/image scans and actual deployment must be
revalidated for this build; prior image evidence is not acceptance of this pin.

The network dependency is pinned to `golang.org/x/net v0.62.0` for
[GO-2026-6860](https://pkg.go.dev/vuln/GO-2026-6860), an HTML parser complexity
vulnerability. The prior assembled-image scan reported CVE-2026-78661 at v0.61.0.
This pin must pass the prepared helper tests, source and assembled-image scans
and actual deployment checks; a previous called-code scan does not replace the
required final-image scan.

The Smallstep crypto dependency now uses the reviewed upstream
[v0.92.0 release](https://github.com/smallstep/crypto/releases/tag/v0.92.0), which
includes the merged JOSE v4 migration and replaces the earlier pre-release pin.
It removes legacy JOSE from the linked standard bundle while retaining Smallstep's
compatibility API. This helper module pins JOSE v4.1.9, including the retained RSA
parameter bounds. [The upstream advisory](https://github.com/go-jose/go-jose/security/advisories/GHSA-mgcc-cww5-fp2q)
lists no patched v3 release; updating v4 alone leaves v3 linked through the older
Smallstep wrapper.

`prepare-jose.go` supplies five adaptations in four source files from Smallstep
certificates v0.30.2: the AWS JWT builder uses `Serialize`; Azure/OIDC and ACME
single-audience expectations use `AnyAudience`. Source SHA256 values and exact replacement counts
must match before a separate vendored build is prepared. The module cache is not
modified, and the original module/version metadata remains intact. Docker
builds, helper tests and vulnerability analysis use the same vendored sources; the
final image retains this modification notice with upstream licenses. A module
upgrade or changed input refuses preparation and requires review.

For a direct helper build, first run `go run prepare-jose.go /new/absolute/path`,
then change to that directory and set `GOFLAGS=-mod=vendor` for Go build, test and
analysis commands. Docker performs these steps automatically. Building without
the prepared sources is unsupported because the old provisioner calls do not compile
against the migrated crypto API.

Helper tests reject oversized RSA JWKs through that wrapper and require the
patched linked dependency. Acceptance must also pass the existing real internal
CA, public-route and protected host issuance/renewal cases, and scan the assembled
image at HIGH/CRITICAL severity. No vulnerability suppression or scanner exception
is introduced. A released dependency does not replace these integration gates;
rerun the complete helper and deployment acceptance for the changed inputs.

Smallstep v0.92.0 also fixes its upstream JOSE tests for the removed
`jose.RandReader` hook. A separate execution of that release's actual `./jose`
suite passed 415 cases without failures or skips. This does not establish
NetHub's assembled image or runtime behavior. The helper's focused production-API
tests and actual Caddy issuance/renewal acceptance remain required.

The build retains linked dependency licenses and module identities in the final
image. Dependency verification and source tests do not establish a signed NetHub
release or production recovery acceptance.

## Storage permissions

The image sets `/config`, `/config/caddy`, `/data` and `/data/caddy` to mode
0700, owned by root. The generated Caddy service uses that identity. The Compose
acceptance checks these permissions inside the running service after Docker has
populated its actual named volumes.

Existing volumes retain their contents and permissions when an image is rebuilt.
An older volume may still contain [upstream mode-1777 application directories](https://github.com/caddyserver/caddy-docker/blob/master/2.11/alpine/Dockerfile).
Before backup/restoration, inspect the exact project's Caddy mounts and review
those directory owners/modes with Caddy stopped and independent management
available. Correct only the approved directories; do not delete volumes,
regenerate certificate state or recursively change unrelated files. The recovery
archive continues to refuse world-writable or special-mode input. Custom runtime
users and mounts require separate review.
