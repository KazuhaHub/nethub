#!/usr/bin/env bash
# Build and test a chosen worktree without starting a deployment or public probe.
set -euo pipefail
umask 077

root=$(git -C "${1:-.}" rev-parse --show-toplevel)
cd "$root"
if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  echo 'Use this helper on Linux x86_64; the handoff documents the Ubuntu environment.' >&2
  exit 2
fi
for command in docker python3 git; do
  command -v "$command" >/dev/null || { echo "Install $command first." >&2; exit 2; }
done
docker info >/dev/null
docker compose version >/dev/null
available_kib=$(df -Pk . | awk 'NR == 2 {print $4}')
if (( available_kib < 12 * 1024 * 1024 )); then
  echo 'Allow 12 GiB free for build output/cache and reserve before this portable check.' >&2
  exit 2
fi
node_image=$(awk '$1 == "FROM" && $NF == "console" {print $2}' deploy/Dockerfile)
go_image=$(awk '$1 == "FROM" && $NF == "build" {print $2}' deploy/Dockerfile)
[[ $node_image == node:*@sha256:* && $go_image == golang:*@sha256:* ]] || {
  echo 'Expected digest-pinned build images in deploy/Dockerfile.' >&2
  exit 2
}
mkdir -p .handoff-build
python3 -m venv .handoff-build/venv
.handoff-build/venv/bin/python -m pip install --disable-pip-version-check \
  pytest==8.3.5 jinja2==3.1.6 jsonschema==4.25.1
.handoff-build/venv/bin/python -m pytest -q agents/opnsense/plugin/tests agents/opnsense/tests

docker run --rm --user "$(id -u):$(id -g)" \
  --env HOME=/tmp --env npm_config_cache=/tmp/npm-cache \
  --volume "$root:/src" --workdir /src/server/web "$node_image" \
  sh -eu -c 'npm ci --ignore-scripts; npm run format:check; npm test; npm run build'
docker run --rm --user "$(id -u):$(id -g)" \
  --env HOME=/tmp --env GOWORK=off --env GOTOOLCHAIN=local \
  --env GOCACHE=/tmp/go-build --env GOPATH=/tmp/go \
  --volume "$root:/src" --workdir /src/server "$go_image" \
  sh -eu -c 'test "$(go env GOVERSION)" = "go$(cat .go-version)"; go test -race -count=1 ./...; go vet ./...; go build -o /src/.handoff-build/nethub ./cmd/nethub'
git diff --check
echo 'Portable checks finished. Environment-dependent skips, native/public and release gates remain separate.'
