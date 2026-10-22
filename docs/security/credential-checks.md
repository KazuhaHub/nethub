# Credential history checks

The `workflow lint` job scans all fetched history with Gitleaks 8.30.1. Checkout
uses full history, the Linux release archive has a pinned SHA256, and the scanner
retains its default rules. Inline ignore comments and repository ignore files
are disabled. Findings are fully redacted; CI prints locations instead of
matching content and does not upload scanner reports.

Run the same check locally with a verified Gitleaks 8.30.1 executable:

```sh
python3 tools/check_credentials.py --scanner /path/to/gitleaks
```

The configuration has two exceptions for exact public verification values:

- The SHA256 SPKI digests from the public enrollment and certificate request
  fixtures, restricted to their protocol response fixture paths and complete
  `gui_key_fingerprint` lines.
- The pinned OPNsense release public-key checksum, restricted to its complete
  `KEY_SHA256` assignment in the image preflight script.

These are rule-specific conjunctions of path and exact content. The project adds
no whole-path, commit or detection-rule exclusion. Five executable controls verify accepted
public values and refusal of a changed fingerprint, an adjacent credential, the
same public value at another path and a credential appended to the checksum line.
Control credentials are generated in temporary directories and never committed.

## Historical review

On 2026-10-22, an unsuppressed default-rule scan at main `f30e453` covered 452
reachable commits across 254 fetched references. Ten matches were individually
classified: eight digests matched the public SPKI or CSR in the same historical
commit; two were checksums of the public OPNsense release verification key.
No credential was confirmed among those matches. Redacted reports, scanner
checksums, reference inventory digest and classification evidence remain outside
Git.

Coverage is limited to fetched, reachable history and the pinned detection
rules. It does not prove that all sensitive information is absent or complete
the separate D12 content review. Repository publication was explicitly approved
by Kazuha; this scan does not rewrite history or change visibility.
