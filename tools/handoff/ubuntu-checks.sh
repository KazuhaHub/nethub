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
for command in docker python3 git php openssl; do
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
# The Python action-response contract invokes Node even when the console checks
# run in Docker. Supply that executable from the same pinned runtime rather than
# silently depending on an optional host installation.
mkdir -p .handoff-build/bin
docker run --rm --entrypoint cat "$node_image" /usr/local/bin/node > .handoff-build/bin/node.new
chmod 0755 .handoff-build/bin/node.new
mv .handoff-build/bin/node.new .handoff-build/bin/node
export PATH="$root/.handoff-build/bin:$PATH"
test "$(node --version)" = v24.14.0

# The production console builder does not need OpenSSL, but the TLS negative
# control creates an ephemeral certificate. Install it in a derived check image;
# keep both the production image and the host unchanged.
docker build --build-arg "NODE_IMAGE=$node_image" --iidfile .handoff-build/node-check-image - <<'DOCKERFILE'
ARG NODE_IMAGE
FROM ${NODE_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*
DOCKERFILE
node_check_image=$(cat .handoff-build/node-check-image)
python3 -m venv .handoff-build/venv
.handoff-build/venv/bin/python -m pip install --disable-pip-version-check \
  pytest==8.3.5 jinja2==3.1.6 jsonschema==4.25.1
.handoff-build/venv/bin/python -m pytest -q agents/opnsense/plugin/tests agents/opnsense/tests

docker run --rm --user "$(id -u):$(id -g)" \
  --env HOME=/tmp --env npm_config_cache=/tmp/npm-cache \
  --volume "$root:/src" --workdir /src/server/web "$node_check_image" \
  sh -eu -c 'npm ci --ignore-scripts; npm run format:check; npm test; npm run build'
docker run --rm --user "$(id -u):$(id -g)" \
  --env HOME=/tmp --env GOWORK=off --env GOTOOLCHAIN=local \
  --env GOCACHE=/tmp/go-build --env GOPATH=/tmp/go \
  --volume "$root:/src" --workdir /src/server "$go_image" \
  sh -eu -c 'test "$(go env GOVERSION)" = "go$(cat .go-version)"; go test -race -count=1 ./...; go vet ./...; go build -o /src/.handoff-build/nethub ./cmd/nethub'
git diff --check
echo 'Portable checks finished. Environment-dependent skips, native/public and release gates remain separate.'
