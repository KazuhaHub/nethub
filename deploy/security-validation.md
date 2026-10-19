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

## Container findings remain open

Trivy 0.76.0 was pinned to
`aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222`.
Scans used remote image retrieval, vulnerability scanning only, HIGH/CRITICAL
severity, JSON reports, and no ignore rules or `--ignore-unfixed`. Report-mode
exit zero only means the scanner completed; it is not a clean security result.
Full reports remain in private test evidence.

- The deployment's pinned distroless base reported zero HIGH/CRITICAL findings.
  This does not cover the NetHub binary subsequently copied into the image.
- The pinned Caddy image reported four HIGH findings in its Go binary: x/net
  CVE-2026-78669 and three standard-library findings. Official Caddy 2.11.7
  currently resolves to the same digest, so changing its tag alone is no fix.
- The pinned PostgreSQL image reported HIGH/CRITICAL OS and embedded Go
  findings. Candidate current PostgreSQL 16 images were compared without
  changing the deployment: default Debian reported 62 OS and 25 gosu findings;
  Bookworm reported 74 OS and 25 gosu findings; Alpine reported zero OS but
  retained 25 gosu findings. Counts are package/advisory occurrences, not
  distinct CVE counts. Switching to Alpine alone would not clear this gate.

Image remediation, a scan of the actual assembled NetHub runtime image, and
repeat deployment acceptance remain required. No existing relay services were
stopped for these scans. Public ACME and deployed-browser acceptance also remain
open. W3 is not complete.
