# Caddy helper dependencies

The image rebuilds the standard Caddy 2.11.7 bundle with the pinned Go toolchain
and module checksums. `v2.11.7-nethub.2` identifies the local dependency rebuild;
it is not an upstream Caddy release.

The Smallstep crypto dependency is pinned to upstream maintainer commit
[`00c45432f48558f92a6e7da6d885d94e90db4d7a`](https://github.com/smallstep/crypto/commit/00c45432f48558f92a6e7da6d885d94e90db4d7a),
the [pending JOSE v4 migration](https://github.com/smallstep/crypto/pull/1157).
This is an unreleased dependency, selected explicitly to remove the legacy JOSE
implementation from the linked standard bundle while retaining Smallstep's
compatibility API. The root module pins JOSE v4.1.6, including its RSA parameter
bounds. [The upstream advisory](https://github.com/go-jose/go-jose/security/advisories/GHSA-mgcc-cww5-fp2q)
lists no patched v3 release; updating v4 alone leaves v3 linked through the older
Smallstep wrapper.

`prepare-jose.go` supplies three downstream adaptations in Smallstep certificates
v0.30.2: the AWS JWT builder uses `Serialize`, and the Azure/OIDC single-audience
expectations use `AnyAudience`. Source SHA256 values and exact replacement counts
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
