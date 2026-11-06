# Caddy helper dependencies

The image rebuilds the standard Caddy 2.11.7 bundle with the pinned Go toolchain
and module checksums. `v2.11.7-nethub.4` identifies the local dependency rebuild;
it is not an upstream Caddy release.

The compression dependency is pinned to `github.com/klauspost/compress v1.20.2`
for GO-2026-6865. The required scan reached the vulnerable FSE/Huffman code through
the standard Caddy bundle at v1.20.1. This rebuild changes that dependency without
changing the upstream Caddy version or introducing a scanner exception. The
prepared source, helper tests, source/image scans and actual deployment must be
revalidated for this build; prior image evidence is not acceptance of this pin.

The network dependency is pinned to `golang.org/x/net v0.62.0` for
[GO-2026-6860](https://pkg.go.dev/vuln/GO-2026-6860), an HTML parser complexity
vulnerability. The prior assembled-image scan reported CVE-2026-78661 at v0.61.0.
This pin must pass the prepared helper tests, source and assembled-image scans
and actual deployment checks; a previous called-code scan does not replace the
required final-image scan.

The Smallstep crypto dependency is pinned to upstream maintainer commit
[`00c45432f48558f92a6e7da6d885d94e90db4d7a`](https://github.com/smallstep/crypto/commit/00c45432f48558f92a6e7da6d885d94e90db4d7a),
the [pending JOSE v4 migration](https://github.com/smallstep/crypto/pull/1157).
This is an unreleased dependency, selected explicitly to remove the legacy JOSE
implementation from the linked standard bundle while retaining Smallstep's
compatibility API. The root module pins JOSE v4.1.6, including its RSA parameter
bounds. [The upstream advisory](https://github.com/go-jose/go-jose/security/advisories/GHSA-mgcc-cww5-fp2q)
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
is introduced. Replace this pre-release pin with a reviewed upstream release when
it includes the migration; rerun the complete helper and deployment acceptance.

The upstream package's own tests still reference the removed `jose.RandReader`
test hook and cannot compile against v4.1.6. They are not reported as passing.
The helper's focused production-API tests and the actual Caddy issuance/renewal
acceptance remain required for this integration.

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
