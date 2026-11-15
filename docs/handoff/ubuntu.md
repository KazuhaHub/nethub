# Resume on Ubuntu

Use Ubuntu 24.04 x86_64 for the closest match to CI. The current agent target is
FreeBSD/OPNsense amd64; do not infer an arm64 or OpenWrt/VyOS agent from the
control-plane interfaces. A normal development checkout needs no router,
private keys, existing deployment or previous workstation files.

## Checkout and inspect

```sh
git clone --branch docs/ubuntu-handoff https://github.com/KazuhaHub/nethub.git
cd nethub
git status --short
python3 tools/handoff/verify.py
```

Keep this handoff checkout as a reference. Create a work branch for fixes. Its
parent product source is `a29fbfe52a1a7774a538a33081277be2a253ab97`; the
handoff commit itself has only documentation, evidence and development helpers.
Use your existing Git identity and DCO sign-off (`git commit -s`).

## Development dependencies

Install the ordinary Ubuntu tools:

```sh
sudo apt-get update
sudo apt-get install -y git curl ca-certificates python3 python3-venv \
  openssl jq unzip xz-utils shellcheck php8.3-cli php8.3-xml
```

Install Docker Engine and the Compose plugin using
[Docker's official Ubuntu apt instructions](https://docs.docker.com/engine/install/ubuntu/).
Use **Engine 28 or newer** and **Compose 2.24.4 or newer**; the repository's
loopback isolation and `!override` configuration depend on those versions.
Ensure your user can run `docker info` and `docker compose version`.
Do not substitute an old distribution Docker/Compose installation without
checking these requirements.

The repository pins Go **1.26.11** in `server/.go-version`, Node **24.14.0** in
the build/CI files, frp **0.71.1** and Python test dependencies in CI.
The portable helper below uses the exact Node/Go container digests already in
`deploy/Dockerfile`, so a host Go or Node installation is optional. Python
3.11+ is needed for host-side `tomllib`/file hashing; Ubuntu 24.04 supplies 3.12.
The guest's Python 3.13 is installed by the appliance fixture, not copied from
the workstation.

The helper checks host PHP/OpenSSL before running the Python contracts. It
extracts the pinned Node executable into `.handoff-build/bin` for the Python
JavaScript projection test, and adds OpenSSL to a derived console-check image
for the ephemeral-certificate negative control. Neither operation installs
software on the host or changes the production build image.

Allow roughly 12 GiB free for the portable build's images/caches/output and
reserve, and more for full integration. A disposable integration machine with
16 GiB RAM and 40 GiB free storage is a reasonable planning allocation; check
actual free resources before downloading images. These are capacity estimates,
not measured production sizing.

## Portable checks and CLI build

From the target worktree:

```sh
bash tools/handoff/ubuntu-checks.sh
```

If testing a separate worktree that does not yet contain this helper:

```sh
bash ../nethub/tools/handoff/ubuntu-checks.sh "$PWD"
```

It builds/tests the console, runs all Go packages with race detection and vet,
runs portable plugin/agent tests with pinned Python dependencies, and builds
`.handoff-build/nethub`. It does not start a deployment, open public ports,
enroll a device, call Check-Host or dispatch Actions. FreeBSD/integration skips
are reported by the suite and are not acceptance. The helper's container build
commands were syntax-reviewed here; they were not executed on this Windows
workstation. The corresponding component commands already passed in the
source-bound Ubuntu CI runs listed in [validation](validation.md).

For a quick focused regression with the helper-created Python environment:

```sh
.handoff-build/venv/bin/python -m pytest -q \
  agents/opnsense/tests/test_native_guest.py \
  agents/opnsense/tests/test_native_package_migration.py \
  agents/opnsense/tests/test_native_image_provenance.py
```

## Full integration on a disposable Ubuntu host

For the local isolated six-service harness, read its preflight and then run:

```sh
sudo sh server/tests/compose.sh
```

It needs Docker 28+, `iptables`, and unused TCP 7000/8443 plus loopback 9000.
Install `iptables` and `iproute2` if absent. It creates a uniquely named owned
test stack and removes its own resources. Use a disposable host rather than a
production Docker daemon. The basic command is not the complete browser/native
gate: the additional scan/browser environments are defined in
`.github/workflows/ci.yml`. Do not enable them with an invented binary path.

The full **native and protected-host cold-recovery fixtures intentionally
require a fresh GitHub-hosted Ubuntu/KVM runner**. `Guest`, `with_images.py` and
`cold_entry.py` enforce `GITHUB_ACTIONS=true` and
`RUNNER_ENVIRONMENT=github-hosted`. Do not forge those values on a local machine
or remove the guards. The workflow provisions QEMU/KVM, a fresh signed Nano
image, ephemeral SSH keys/host trust, the pinned FreeBSD SDK and browsers.
It uses a 3 GiB guest and requires at least 4500 MiB available host memory.

Use your own GitHub CLI login/permissions. After opening a fix PR, first wait
for its exact-source six-job CI producer. Automatic native/cold workflows use
the image gate. For an explicit dispatch at that same branch/source:

```sh
SOURCE_BRANCH=feat/your-fix
ACCEPTED_CI_RUN=replace_with_its_successful_CI_run_id
gh workflow run native-enrolled.yml --repo KazuhaHub/nethub \
  --ref "$SOURCE_BRANCH" -f accepted_ci_run="$ACCEPTED_CI_RUN"
gh workflow run cold-recovery.yml --repo KazuhaHub/nethub \
  --ref "$SOURCE_BRANCH" -f accepted_ci_run="$ACCEPTED_CI_RUN"
gh run list --repo KazuhaHub/nethub --branch "$SOURCE_BRANCH" --limit 20
```

Replace both values before use. The producer SHA must exactly match the
consumer source, all six CI jobs must succeed, and the image artifact must still
exist. Image artifacts retain only one day. If expired, regenerate producer
evidence through a new source PR/workflow cycle; never substitute another
source's image or erase an old failure. Poll the original run/job until its
terminal state; a watch timeout is not a reason to start another operation.

Archive results before expiration:

```sh
RUN_ID=replace_with_the_completed_run_id
mkdir -p evidence
gh run view "$RUN_ID" --repo KazuhaHub/nethub --log > "evidence/$RUN_ID.log"
gh run download "$RUN_ID" --repo KazuhaHub/nethub --dir "evidence/$RUN_ID"
```

Keep any unmasked operational material private. Publish only closed reports,
hashes and reviewed masked views, with source, run attempt and scope.

## Fresh operator deployment and public samples

Follow [QUICKSTART](../../deploy/QUICKSTART.md) and
[deployment operations](../deployment.md), using your own disposable public
Linux ingress, DNS zone/wildcard and non-production OPNsense device. Init creates
new service-separated secrets and requires an independent verified backup; no
old workstation secret or router disk is needed. Do not commit those secrets.
External reverse proxies manage their console TLS; NetHub's relay trust and
device GUI-certificate lifecycle remain separate.

The Check-Host mode exists only in PR #242 until integrated. Its patch is in
[patches](patches/README.md). The required real positive/closed-port sample is
still open. It must use an owned public test endpoint, explicit provider opt-in,
an independent deadline/cleanup for any temporary listener, and unchanged
unrelated services. Record provider errors as failures; do not manufacture a
positive result or relax the three-observer requirement.

For the mobile/signed-package acceptance, use normal console **Open**, actual
router login and a masked recording. For the independent-deployer requirement,
the recipient must use their own server/device and report documentation gaps.
The prior W0 phone feedback does not close these W5/W7 requirements.
