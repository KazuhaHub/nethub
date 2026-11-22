"""Allocate the next UTC ISO-week release version from the remote Git tags."""
import argparse
from datetime import datetime, timezone
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BUILD = 'agents/opnsense/plugin/build.sh'
VERSION_FILES = (
    BUILD,
    'agents/opnsense/plugin/src/usr/local/opnsense/version/nethub-agent',
    'agents/opnsense/plugin/src/usr/local/opnsense/mvc/app/models/OPNsense/NetHubAgent/NetHubAgent.xml',
    'agents/opnsense/acceptance/package_migration.py',
    'agents/opnsense/acceptance/package_probe.py',
    'agents/opnsense/acceptance/reconcile_failure.py',
    'agents/opnsense/acceptance/README.md',
    'agents/opnsense/tests/test_native_package_migration.py',
    'agents/opnsense/tests/test_native_reconcile_failure.py',
    'agents/opnsense/tests/test_native_post_wan_failure.py',
)


def next_version(now, tags):
    iso = now.astimezone(timezone.utc).isocalendar()
    prefix = f'{iso.year}.{iso.week}'
    pattern = re.compile(rf'v{re.escape(prefix)}(?:\.([1-9][0-9]*))?')
    occupied = [int(match[1] or 0) for tag in tags if (match := pattern.fullmatch(tag))]
    return prefix if not occupied else f'{prefix}.{max(occupied) + 1}'


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args], text=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true', help='Update source files for a release candidate')
    args = parser.parse_args()
    tags = [line.split('refs/tags/', 1)[1] for line in git('ls-remote', '--refs', '--tags', 'origin').splitlines()]
    version = next_version(datetime.now(timezone.utc), tags)
    if args.apply:
        if git('status', '--porcelain', '--', *VERSION_FILES):
            raise SystemExit('Release version files must be clean before preparing a candidate')
        current = re.search(r'^VERSION=([0-9]+(?:\.[0-9]+)+)$', (ROOT / BUILD).read_text(), re.M)
        if current is None:
            raise SystemExit('Cannot identify the current appliance version')
        pattern = re.compile(rf'(?<![0-9.]){re.escape(current[1])}(?![0-9.])')
        updates = {}
        for name in VERSION_FILES:
            path = ROOT / name
            raw = path.read_bytes()
            updated, count = pattern.subn(version, raw.decode('utf-8'))
            if not count:
                raise SystemExit(f'Expected version binding missing from {name}')
            updates[path] = updated.encode('utf-8')
        for path, contents in updates.items():
            path.write_bytes(contents)
    print(version)


if __name__ == '__main__':
    main()
