#!/bin/sh
set -eu
VERSION=0.0.10
if [ "$(uname -s)" != FreeBSD ]; then
    echo 'Build this unsigned development package on FreeBSD/OPNsense.' >&2
    exit 1
fi
for tool in pkg sha256 python3.13 go; do
    command -v "$tool" >/dev/null 2>&1 || { echo "Missing build tool: $tool" >&2; exit 1; }
done
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3.13 "$root/build.py" "$VERSION"
