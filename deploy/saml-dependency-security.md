# SAML assertion dependency pin

GO-2026-6909 blocked the required CI image producer for the protected-host recovery
drill. The original `crewjam/saml` v0.5.1 reproduced foreign-namespace NameID
admission and a missing-Subject panic with genuine signed/encrypted fixtures in
the shared authcore package. This is a dependency repair, separate from the
recovery harness and its acceptance.

The candidate server graph uses authcore commit
`c1447857d71bdfc9b93e7d1efca7f771d0eff4c8` and repeats its replacement:

```go
replace github.com/crewjam/saml => github.com/openctemio/saml v0.5.2-0.20261106014128-2b3cdad337cd
```

That pin is the unmerged proposal in
[crewjam/saml#674](https://github.com/crewjam/saml/pull/674), exact commit
`2b3cdad337cdd14eeeeec91cd4c7405d6ec590ba`. It binds assertion fields to XML
namespaces and refuses missing pointers after decryption. It is not an official
crewjam release. Authcore also rejects ambiguous plaintext identity structure
before the original signature, condition and replay checks. Go does not propagate
dependency replacements, so the server must carry the same explicit pin and
module checksums.

Authcore's local SAML tests passed both valid and malformed signed/encrypted
cases; an isolated original-dependency control reproduced the failures. Its
Linux-target scan found no called vulnerability, but the advisory database may
not track this fork. Source review and independent regressions remain required;
no scanner ignore or exception was added. The advisory's specific Issuer nil
claim differs from the pinned source's value field; that particular panic has
not been reproduced.

Authcore PR #36 merged after exact-source Linux CI `42211692260` passed build,
vet, formatting, full tests, source vulnerability scan and API compatibility;
the complete official logs were checked. NetHub's local SSO/Web tests also passed.
NetHub PR #215 was closed and replaced by draft #223. Source `908acb4` passed all
six CI jobs in `42534592560`, including five assembled-image scans and actual
Keycloak/Dex browser admission. Complete protected-host cold recovery remains
unaccepted. Those scoped results do not make the interim pin an official release.
The upstream package suite under the interim graph has two
exact-error-message failures for XSW-7/8 with the selected signature library;
the original dependency has the same failures and rejects both attack fixtures.
Full local authcore testing also fails Windows GeoIP mapped-file replacement and
cleanup. Those results do not count as passing checks. See authcore's
`saml/SECURITY-NOTES.md` for the candidate's limits, including the separate OAEP
digest-URI compatibility issue. Replace this interim pin with an official fixed
release only after the same tests and downstream deployment checks pass.

Upstream subsequently closed #674 in favor of
[#679](https://github.com/crewjam/saml/pull/679), which merged the namespace and
nil-pointer repair. Official module version v0.6.3 is tagged at
`c5725cd857625e4c1f6dbbe5e0b3822def94b581`. Authcore's candidate
[PR #37](https://github.com/KazuhaHub/authcore/pull/37) removes the fork, adapts
RelayState escaping and verifies modern encrypted assertions plus default
RSA1_5 refusal. Its local SAML tests and hosted compiler/race/API checks passed,
but actual govulncheck still reports called GO-2026-6909 for v0.6.3 without a
fixed version. JSON scan mode exited zero despite that finding. The candidate
remains a draft; it is not adopted here, and no advisory exception was added.
The scan's advisory status and the independent source/regression evidence remain
separate requirements.
