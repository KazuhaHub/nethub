# Hosted native filesystem contracts

The separate `Native filesystem contracts` workflow runs the current source in
an isolated FreeBSD 15.1 amd64 guest. It preserves the six existing required CI
jobs and their deadlines. The guest uses two CPUs and 2 GiB on the hosted runner;
it does not start a local appliance or use operational SSH resources.

Checkout selects the exact pull-request head. A clean-source manifest hashes the
tracked appliance, protocol and test files, including the driver and workflow.
Its digest travels through the host step output to guest execution and host
verification. All source bytes must match before and after the selected tests.

The groups exercise enrollment/scheduler lock exclusion and PHP handoff,
service/circuit/watchdog behavior, shared wire/model encoding and rotation
candidate durability/recovery. Both actual
FreeBSD `lockf` tests must execute. A skipped or failed case, missing group,
source mismatch or incorrect platform fails acceptance. The guest records its
Python/tool versions and bounded outcomes; the host independently checks them.
A guest test failure returns its receipt for inspection, and the following host
verification makes the CI job fail. The workflow must retain that verification.

Only source hashes and the bounded receipt are eligible for artifact upload.
Raw test XML, fixture diagnostics, VM disks and runtime credentials are excluded.
The VM action is pinned to reviewed commit
`c46abacb49f09938ca4e1702d15d836285d694cc` (v1.5.9), whose FreeBSD 15.1
configuration selects AnyVM 0.7.2 and image builder 2.2.8. System Python 3.12 pip
bootstraps a private Python 3.13 environment with the same top-level pytest,
Jinja2 and jsonschema versions as Linux CI. Rust supports native build-only test
dependencies; it is not part of an appliance package. PHP 8.5 includes OpenSSL.
Actual tool versions are recorded rather than represented as product-image pins.

This workflow is under acceptance. It runs filesystem and PHP-model contract
fixtures on FreeBSD, not an installed OPNsense framework or an installed frpc
binary. Package installation, GUI actions, public control-channel recovery and
the full W5/W7 native acceptance remain separate requirements. Earlier native
execution records remain tied to their original source; they are not relabeled
when this workflow tests a newer source.
