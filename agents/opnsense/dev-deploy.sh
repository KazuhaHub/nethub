#!/bin/sh
set -eu
: "${NETHUB_SSH_TARGET:?Set NETHUB_SSH_TARGET to the isolated test guest}"
port=${NETHUB_SSH_PORT:-22}
case "$port" in ''|*[!0-9]*) echo 'Invalid SSH port' >&2; exit 1 ;; esac
case "$NETHUB_SSH_TARGET" in -*|*[!A-Za-z0-9_.@:-]*) echo 'Invalid SSH target' >&2; exit 1 ;; esac
case "${1:-build}" in build|install) action=${1:-build} ;; *) echo 'Usage: dev-deploy.sh [build|install]' >&2; exit 1 ;; esac
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
remote=$(ssh -p "$port" -o BatchMode=yes -o StrictHostKeyChecking=yes "$NETHUB_SSH_TARGET" 'umask 077; mktemp -d /tmp/nethub-w1.XXXXXXXX')
case "$remote" in /tmp/nethub-w1.*) ;; *) echo 'Unexpected staging path' >&2; exit 1 ;; esac
COPYFILE_DISABLE=1 tar -C "$root/plugin" --exclude=dist --exclude=__pycache__ --exclude=.pytest_cache -cf - . |
    ssh -p "$port" -o BatchMode=yes -o StrictHostKeyChecking=yes "$NETHUB_SSH_TARGET" "tar -C '$remote' -xf -"
ssh -p "$port" -o BatchMode=yes -o StrictHostKeyChecking=yes "$NETHUB_SSH_TARGET" "cd '$remote' && sh build.sh"
if [ "$action" = install ]; then
    ssh -p "$port" -o BatchMode=yes -o StrictHostKeyChecking=yes "$NETHUB_SSH_TARGET" "pkg add -f '$remote/dist/os-nethub-agent.pkg'"
fi
printf 'Development files retained at %s\n' "$remote"
