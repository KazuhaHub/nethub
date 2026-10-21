# Go X.509 security update (2026-10-21)

Go 1.26.10 replaces 1.26.9 for the server and all rebuilt Go helpers. Advisory
[GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809) requires distrusting compromised
intermediate certificates in `crypto/x509`. The newly available hosted source
scan reported a reachable standard-library finding with Go 1.26.9. The patch
updates `.go-version` and all four Docker builder tags/digests together, without
suppressing the advisory or changing the module compatibility floor.

The builder digest was resolved from the official `library/golang` OCI index
for `1.26.10-bookworm` and checked against its response content hash. The Go
release metadata and vulnerability database both identify 1.26.10 as fixed.
The rebuilt PostgreSQL helper also updates `github.com/moby/sys/user` from
v0.1.0 to v0.4.1 for [GO-2026-6686](https://pkg.go.dev/vuln/GO-2026-6686).
The hosted helper scan identified a reachable path through gosu's user setup.
The upstream gosu source revision remains pinned; its dependency graph is rebuilt
with the fixed user lookup module.

Current hosted source, helper and assembled-image checks must pass before merge.
The earlier measurements below are historical and do not establish current
vulnerability status.

# W3 security scan checkpoint (2026-10-18)

The Linux/amd64, CGO-disabled source scan uses govulncheck v1.9.0 and the
compiler pinned in `server/.go-version`. CI checks the compiler version before
scanning and testing; the Docker builder checks the same file before downloading
modules. Its image tag and digest pin Go 1.26.9. The module's Go 1.26.0 line
is a compatibility floor and does not select the production compiler.

The Go 1.26.0 baseline reported 31 distinct advisories with symbol-level call
traces. Repeating the scan with Go 1.26.9 reported zero affected symbols and
zero affected imported packages. One advisory remains in a required module
whose vulnerable package is not imported. The full authcore checkout was also
scanned with Go 1.26.9: zero affected symbols/packages, with ten module-only
advisories. These results describe reachability, not an absence of every advisory
in all module source. NetHub directly consumes authcore v0.6.2, including its
fail-closed SAML replay-cache fix; complete SAML integration remains W6.

Run the source check from `server/` with the pinned compiler:

```sh
GOWORK=off GOTOOLCHAIN=local GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

## Container remediation validation

The derived helper builds use Caddy 2.11.7 with x/net 0.60.0 and PostgreSQL
16 Alpine with gosu rebuilt from its 1.19 commit. All three Go binaries use
Go 1.26.9. The actual assembled runtime, PostgreSQL, and Caddy images each
passed pinned Trivy HIGH/CRITICAL checks with exit-code enforcement and no
ignore rules. CI run 39183393699 on source commit b3efbd4 passed all six jobs;
Deployment checks took 4m38s and printed the three-image success marker before
running fresh Compose acceptance. The resulting stack passed first-start,
UID/mount isolation, one-shot administrator login, empty inventory, token
issuance, private health routing, log-secret exclusion, and failed-migration
startup gating. Required helper-module advisory results are scoped below:
gosu's x/sys advisory affects Windows code; Caddy's x/crypto advisory concerns
the unimported openpgp package. Neither source scan reports an affected symbol
or imported package, and neither produced a HIGH/CRITICAL image finding.

The native derived PostgreSQL build passed all thirteen live boundary groups,
including initial admin creation, forced RLS/column grants, tenant/member scope,
single-use token concurrency, read-only dump, revocation/audit, authentication,
and the actual HTTP/database integration (3.87 seconds). Repeated bootstrap also
passed. The runtime and PostgreSQL images built successfully. Native Caddy
compilation was stopped when free disk on the shared test LXC fell to about
1.3 GiB; removing only the owned build container/cache restored about 4.4 GiB.
This interruption is preserved as resource-limited evidence, not a Caddy build
failure diagnosis. The complete three-image check passed on an ephemeral CI
runner. Owned native
images/stages were removed after private archival; original 443/8443 listeners
were independently verified present.

Trivy 0.76.0 was pinned to
`aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222`.
Baseline scans used remote image retrieval, vulnerability scanning only,
HIGH/CRITICAL severity, JSON reports, and no ignore rules or `--ignore-unfixed`.
Their report-mode exit zero only means the scanner completed; it is not a clean
security result. Full baseline reports remain in private test evidence. The
assembled-image CI checks instead use saved image tar files and `--exit-code 1`;
their log success marker requires all three scans to return zero.

- The deployment's pinned distroless base reported zero HIGH/CRITICAL findings.
  This does not cover the NetHub binary subsequently copied into the image.
- The original pinned Caddy image reported four HIGH findings in its Go binary: x/net
  CVE-2026-78669 and three standard-library findings. Official Caddy 2.11.7
  currently resolves to the same digest, so changing its tag alone is no fix.
- The original pinned PostgreSQL image reported HIGH/CRITICAL OS and embedded Go
  findings. Candidate current PostgreSQL 16 images were compared without
  changing the deployment: default Debian reported 62 OS and 25 gosu findings;
  Bookworm reported 74 OS and 25 gosu findings; Alpine reported zero OS but
  retained 25 gosu findings. Counts are package/advisory occurrences, not
  distinct CVE counts. Switching to Alpine alone would not clear this gate.

The rebuilt helpers and assembled-image scans resolve this scoped gate. Results
are a dated snapshot; future database updates can introduce new findings and
CI will fail closed. No existing relay services were stopped for these scans.
Public ACME and deployed-browser acceptance subsequently passed on the existing
LXC and in a combined clean-host public run; see
[deployment validation](validation-w3.md). Full doctor coverage remains W7 work.
Device/enrollment and SSO readiness are separate stage gates.
