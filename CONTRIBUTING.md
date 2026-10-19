# Contributing to NetHub

Thanks for your interest in NetHub. This document covers how contributions are
licensed, how the repository is organized and how it relates to the separate
packaging repository, and the conventions we expect from pull requests.

NetHub is **pre-alpha**, with accepted W0 measurements and natively validated
W2 OPNsense tunnel integration. There is no released version or complete deployment;
enrollment and the control plane remain unimplemented. The design and
stage-specific READMEs distinguish verified behavior from planned features.

## Table of contents

- [Developer Certificate of Origin (DCO)](#developer-certificate-of-origin-dco)
- [License and repository layout](#license-and-repository-layout)
- [Changing the protocol (`proto/`)](#changing-the-protocol-proto)
- [Development setup](#development-setup)
- [Filing issues](#filing-issues)
- [Commit message conventions](#commit-message-conventions)
- [No AI attribution in commits](#no-ai-attribution-in-commits)
- [Pull request checklist](#pull-request-checklist)

## Developer Certificate of Origin (DCO)

NetHub uses the **Developer Certificate of Origin (DCO)** instead of a
Contributor License Agreement (CLA).

**What this means for you:** you keep the copyright to your own contribution.
You are not assigning or licensing your copyright to the project maintainers
or to any single entity — you are simply certifying, for each commit, that you
wrote it (or otherwise have the right to submit it) and that you are
knowingly submitting it under the project's license (Apache-2.0, see below).
There is no separate agreement to read, sign, or fax in; the certification
lives in your commit itself.

The full text of the DCO is the standard one used by the Linux kernel and many
other open source projects: <https://developercertificate.org/>.

**Why DCO instead of a CLA:** a CLA typically requires a copyright license (or
assignment) to the project or a foundation, often via a separate legal
document and sometimes a CLA-bot gate on every PR. DCO keeps things simpler
and puts fewer legal hurdles between a contributor and their first patch,
while still giving the project a clear, auditable trail of who certified what
and when.

### How to sign off your commits

Every commit that lands in this repository must carry a `Signed-off-by`
trailer. The easiest way to add it is the `-s` (or `--signoff`) flag on
`git commit`:

```
git commit -s -m "fix: handle expired enroll tokens"
```

This appends a line to your commit message in the form:

```
Signed-off-by: Your Name <your.email@example.com>
```

The name and email must match a real identity associated with the commit
(typically your `user.name` / `user.email` git config). Anonymous or
pseudonymous sign-offs are fine as long as they are consistent and you are
willing to stand behind them — what matters is that the certification is
genuine, not that it is legally your full name.

If you forgot to sign off a commit, you can amend it:

```
git commit --amend -s --no-edit
```

For a multi-commit branch, you can sign off retroactively with an interactive
rebase, or simply ensure your final squashed commit (see
[Pull request checklist](#pull-request-checklist)) carries the trailer.

PRs with unsigned commits will be asked to add sign-off before merge.

## License and repository layout

This repository (`KazuhaHub/nethub`) is licensed under **Apache-2.0**. See
`LICENSE` at the repository root. All contributions to this repo — the
control plane, the protocol schemas, the agents, docs, and deploy tooling —
are made under Apache-2.0.

All NetHub source lives in one repository. A second, separate repository only
packages it, and the difference is worth being explicit about:

- **`KazuhaHub/nethub`** (this repo): protocol definitions (`proto/`), the
  control plane (`server/`: a Go binary, `nethub`, plus the React console
  source in `server/web/`), the platform agents (`agents/`), deploy tooling
  (`deploy/`), project docs (`docs/`), and the Weekend 0 transport-test kit
  (`weekend0/`). Apache-2.0 throughout. `agents/` holds the agents for each
  supported platform, including the OPNsense plugin source under
  `agents/opnsense/plugin/`. **Every NetHub contribution goes here**, and your
  DCO sign-off certifies submission under Apache-2.0.

- **`KKazuhaK/OPNsense-repo`**: a separate, pre-existing repository that hosts
  an unrelated collection of OPNsense plugins together with a working FreeBSD
  packaging, signing, and pkg-repository pipeline. It will carry a *packaging
  recipe* for NetHub — an entry in its `packaging/plugins.json` and a
  `build.sh` that fetches a tagged NetHub release, verifies its checksum, and
  stages it into a signed package. It does **not** hold NetHub source, it does
  not hold a copy of `proto/`, and it runs no NetHub tests: it only builds
  tagged releases. You should not need to touch it to contribute here, except
  when iterating on the plugin's web UI (see `docs/DESIGN.md` §2).

  That repository is MIT-licensed and has other copyright holders in its
  history, which is exactly why NetHub source does not live in it: keeping all
  of NetHub in one Apache-2.0 repository keeps ownership and licensing
  unambiguous. It will package NetHub the same way it already packages
  sing-box and frp — as third-party upstream software.

## Changing the protocol (`proto/`)

`proto/` in this repository is the **single source of truth** for the wire
protocol between the NetHub control plane and any device agent (OPNsense is
the first target; OpenWrt/VyOS are architecturally anticipated but not
planned for v1). Nothing else holds a copy of the schema: the packaging
repository only builds tagged releases and runs no contract tests. The
contract tests run in **this** repository's CI and check both sides against
the schemas — the Go server (the device API served by `nethub authz`) and the
Python agent (`agentctl.py`).

A device agent in the field can easily be months older than the control plane
it talks to, so protocol changes are the single easiest place to break
already-deployed agents. So any PR that touches anything under `proto/`
**must**:

1. **Bump the schema version.** See `proto/README.md` for the current
   versioning scheme. Do not silently change a message shape under an
   existing version number.
2. **Update or add contract tests** covering the change, for both the Go
   server side and the Python agent side, in whatever form `proto/README.md`
   currently documents (this is still being fleshed out — see the note in
   that file about its pre-alpha state).
3. **State the compatibility impact on already-enrolled agents** in the PR
   description explicitly. At minimum, answer: does an agent running the
   previous protocol version still work against a control plane running this
   change? Does a control plane on the previous version still accept agents
   running this change? If either answer is "no," say so loudly — this is
   exactly the kind of change the server is expected to reject cleanly via
   `agent_protocol_version` rather than fail unpredictably.
4. **Update every agent in the same pull request.** A protocol change that
   lands without the corresponding change under `agents/` is how the control
   plane and a deployed device end up disagreeing in the field. Since the
   agents live in this repository, there is no excuse for splitting that
   across pull requests.

Reviewers should treat an undocumented compatibility answer on a `proto/`
change as a blocking request for changes, not a nitpick.

## Development setup

### Where things stand

NetHub is pre-alpha. As of this writing the repository holds documentation
and the Weekend 0 kit only. There is no `nethub` binary, no `docker compose`
stack and no agent plugin yet. This section therefore has two parts:

- what you can set up and run **today**;
- the workflow that is **planned** for when code lands. That part is marked
  as planned, and will be replaced with tested steps in the same pull request
  that adds the code.

### Tools

| Tool | Version | Used for | Check |
|---|---|---|---|
| Git and the GitHub CLI | any recent | everything | `git --version`, `gh --version` |
| Go | 1.26.9 (the build pin in `server/.go-version`; `go.mod` declares the compatibility floor) | the control plane in `server/` | `go version` |
| Node.js | the current LTS release, not "Current" | the console source in `server/web/` | `node -v` |
| Docker and Docker Compose | any recent | the local stack (Postgres 16, Caddy, `frps`, `nethub web`, `nethub authz`) | `docker version`, `docker compose version` |
| Python | 3.13.x (the version OPNsense 26.7 ships); any Python 3.11 or newer is enough for today's two checks below | the OPNsense agent (`agentctl.py`) and its tests, and `weekend0/probe.py`. Python is used nowhere else | `python3.13 --version` |
| PHP CLI | the same major and minor version as the test device's OPNsense | syntax checks (`php -l`) of the plugin's PHP files | `php -v` |
| `psql` | 16 or newer | inspecting the local database | `psql --version` |

On macOS with Homebrew, two packages need care:

- `brew install node` installs the "Current" release. Install the LTS line
  explicitly, for example `brew install node@24`; check `brew info node` for
  which major version is LTS.
- `psql` comes from `brew install libpq`.

Both are keg-only, so add their `bin` directories to your `PATH` as Homebrew
instructs.

### Repository-specific notes

- **`go.work` in a parent directory.** If your checkout sits under a directory
  that contains a `go.work` file, Go treats it as a workspace and pulls in
  unrelated modules. Check with `go env GOWORK`. If it prints a path, run Go
  commands with `GOWORK=off`.
- **Editor and tool files stay out of the repository.** The project's
  `.gitignore` already covers common editor files (`.idea/`, `.vscode/`, swap
  files). Put anything else your local tools create in your own global ignore
  file, not in the project's `.gitignore`. Check
  `git config --global core.excludesFile` first, and add to that file if one is
  already set.
- **Secrets never get committed.** `.env`, `*.key`, `*.pem` and
  `deploy/secrets/` are ignored. Do not force-add them. If you ever commit a
  secret, do not try to rewrite history; tell a maintainer and rotate the
  secret.
- **Placeholders only.** Examples, tests, docs and logs pasted into issues or
  pull requests use `example.com`, `router.example.com` and `203.0.113.10`.
  Never real hostnames, addresses or credentials.

### What you can run today

The Weekend 0 kit can be checked without any test infrastructure. Run these
from the repository root:

```bash
# The frp configs parse, and their keys sit at the intended level
python3 -I -c "import tomllib; c=tomllib.load(open('weekend0/frpc.toml','rb')); s=tomllib.load(open('weekend0/frps.toml','rb')); print(sorted(c), sorted(s))"

# The probe compiles (the cache goes to /tmp so nothing lands in the repo)
python3 -I -X pycache_prefix=/tmp/nethub-pycache -m py_compile weekend0/probe.py
```

Running the actual Weekend 0 experiment needs:

- a public VPS;
- a domain with wildcard DNS;
- a test OPNsense device (see below);
- a phone on a mobile network.

`weekend0/RUNBOOK.md` walks through it step by step.

### A test OPNsense device

Anything that touches the agent needs an OPNsense machine to install it on.

- **Use a disposable test machine, never a production router.**
  - A fresh VM is best. The agent targets amd64 in v1 (arm64 is planned for
    v1.1), so on an Apple Silicon Mac use a separate x86 host or a cloud VM
    rather than emulation.
  - The VM must run OPNsense 26.7, version 26.7.1_1 or later (`opnsense-version`).
  - Take a snapshot of the clean install and restore it whenever you need a
    clean state.
- **Use the owner-approved test host.** Kazuha explicitly permits package
  building, signing, and NetHub testing on the designated packaging test
  machine (2026-10-17, DESIGN decision #20). Removing signing keys or build
  scratch is no longer a prerequisite for that host. Other signing hosts
  remain outside the deployment scope.
- **Behind NAT is ideal.** If the test VM has a public address instead, block
  all inbound traffic except SSH from your own address. Only then does a
  working tunnel prove that no inbound port is needed.
- **SSH as root with a key:**
  - System → Settings → Administration → Secure Shell: enable it, permit root
    login, and disable password login;
  - System → Access → Users → root: add your public key.

### Planned local workflow (not yet available)

This is how development is expected to work once the code exists. Some of
it is still a proposal and is marked as such.

**Control plane:**

1. Start a local Postgres, bound to `127.0.0.1` only. The proposal is a
   development compose file, `deploy/compose.dev.yml`; it does not exist yet.
2. Build the console first. From `server/web/`, run `npm ci`, then
   `npm run build`. The Go binary embeds the build output with `go:embed`, so
   `go build` fails until it exists. The build output itself is not committed.
3. Run the Go checks from `server/`. `gofmt -l` only lists unformatted files;
   it does not fail on them, hence the `test -z`:

   ```bash
   go build ./... && go vet ./... && test -z "$(gofmt -l .)" && go test ./... -race -count=1
   ```

   The integration tests (row-level security, column grants) need the local
   Postgres.

**Full stack:**

1. `nethub init` writes per-service secrets into `deploy/secrets/`.
2. `docker compose up -d` starts the stack.
3. `nethub doctor` checks it.

**OPNsense agent:**

- `docs/DESIGN.md` §2 describes the development loop. Symlink or `rsync`
  `agents/opnsense/plugin/` into the packaging repository's
  `src/os-nethub-agent/`, build a development package with that repository's
  tooling on the test device, and install it there.
- The exact plugin layout and build entry point are still being settled. The
  steps here will be made concrete when the plugin skeleton lands.
- Signed packages for real installs are built and published separately, from
  tagged releases only (see
  [License and repository layout](#license-and-repository-layout)).

**Contract tests:** the JSON Schemas live in `proto/`. The contract tests
check both the Go server and the agent (`agents/opnsense/tests/`) against
them, and they run in CI on every pull request. A change to the server or the
agent can break the contract without touching `proto/` at all.

### Help wanted

If you want to help get this section written for real, that is itself a
welcome contribution. Open an issue describing what you got working and how.

## Filing issues

When filing an issue, please include:

- **What you were trying to do** and what you expected to happen.
- **What actually happened**, including exact error messages/logs where
  applicable. Redact anything sensitive (see the note on public files below).
- **Component**: which part this touches — `proto/`, `server/`,
  `agents/opnsense/`, `deploy/`, `weekend0/`, or docs. If the problem is with
  the *packaged* plugin rather than its source (install, upgrade, signing, pkg
  repository), say so — that points at the packaging repository instead.
- **Environment**: NetHub version/commit, OPNsense version if relevant, OS of
  the control-plane host.
- For a feature request: which milestone it fits — please check
  `docs/DESIGN.md` (v0.3, written in Chinese; the roadmap, the non-goals and
  the open questions are near the end) to see if it's already scoped as a
  v1.1/v1.2/v2/v2.5 item, ruled out as a non-goal, or still an open question,
  rather than v1. What v1 may do to a device is intentionally narrow (see the
  project README); "can it also do X" for X outside that scope is still a
  useful issue, just expect it to be triaged as future work rather than a v1
  bug.

**Never include real hostnames, IP addresses, domains, ports, tokens, or
credentials from your own deployment in a public issue.** Use placeholders
like `example.com` / `203.0.113.10` (RFC 5737 documentation addresses) when
giving examples, the same way the rest of this project's public docs do.

## Commit message conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <short summary>

<optional body>

Signed-off-by: Your Name <your.email@example.com>
```

Common types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`,
`build`. Scope is usually a directory or component, e.g. `feat(proto): add
rotate response schema` or `fix(server): reject stale enroll tokens`.

Keep the summary line imperative and under ~72 characters where reasonable.
Put the "why," not just the "what," in the body when it isn't obvious from the
diff alone — this matters a lot for `proto/` changes given the compatibility
concerns above.

## No AI attribution in commits

This is a project rule, not a preference: **do not add AI co-authorship or
attribution lines to commits or PR descriptions in this repository** (for
example, no `Co-authored-by: <AI tool>` trailers, no "Generated with ..."
footers). Whatever tools you used to help write a patch, the commit should be
signed off and authored as your own contribution per the DCO above. If your
tooling adds such lines automatically, please strip them before submitting.

## Pull request checklist

Before opening a PR:

- [ ] All commits are signed off (`git commit -s`); no AI attribution lines.
- [ ] Commit messages follow Conventional Commits.
- [ ] If you touched `proto/`: schema version bumped, contract tests
      updated, compatibility impact stated in the PR description (see
      [Changing the protocol](#changing-the-protocol-proto) above).
- [ ] If you touched `proto/`, every affected agent under `agents/` is updated
      in the same pull request.
- [ ] No real domains, IPs, ports, or credentials from a real deployment
      anywhere in the diff — use `example.com` / `203.0.113.10` style
      placeholders.
- [ ] The PR description explains *why*, not just *what*.

Maintainers may ask for changes on any of the above before merge. Thanks again
for contributing.
