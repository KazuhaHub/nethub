"""Extract one exact Git source archive into a new owned recovery guest path."""
import hashlib
from pathlib import Path, PurePosixPath
import re
import tarfile


MAX_BYTES = 256 * 1024**2


def members_for_source(bundle, head):
    if (re.fullmatch('[a-f0-9]{40}', head) is None
            or bundle.pax_headers.get('comment') != head):
        raise ValueError('Recovery source archive identity refused')
    members, kinds, size = [], {}, 0
    for member in bundle:
        name = PurePosixPath(member.name)
        canonical = name.as_posix()
        if (not name.parts or name.is_absolute() or canonical != member.name.rstrip('/')
                or '..' in name.parts or '\\' in member.name
                or any(ord(char) < 32 for char in member.name) or canonical in kinds
                or member.type not in (tarfile.REGTYPE, tarfile.DIRTYPE) or member.mode & ~0o755
                or member.size < 0 or member.size > MAX_BYTES
                or member.isdir() and member.size != 0
                or set(member.pax_headers) - {'comment', 'path', 'size'}
                or member.pax_headers.get('comment') != head):
            raise ValueError('Recovery source archive member refused')
        kinds[canonical] = member.isdir()
        members.append(member)
        size += member.size
        if size > MAX_BYTES or len(members) > 10000:
            raise ValueError('Recovery source archive size refused')
    if not members:
        raise ValueError('Recovery source archive size refused')
    for name in kinds:
        if any(kinds.get(parent.as_posix()) is False for parent in PurePosixPath(name).parents):
            raise ValueError('Recovery source archive parent refused')
    return members


def extract(archive, destination, expected_sha256, head):
    archive, destination = Path(archive), Path(destination)
    if (re.fullmatch('[a-f0-9]{64}', expected_sha256) is None
            or archive.stat().st_size > MAX_BYTES):
        raise ValueError('Recovery source archive bound refused')
    with archive.open('rb') as source:
        if hashlib.file_digest(source, 'sha256').hexdigest() != expected_sha256:
            raise ValueError('Recovery source archive checksum refused')
        source.seek(0)
        with tarfile.open(fileobj=source, mode='r:') as bundle:
            members = members_for_source(bundle, head)
            if (not destination.is_absolute() or destination != destination.resolve()
                    or not destination.parent.is_dir() or destination.exists()):
                raise ValueError('New canonical recovery source destination required')
            destination.mkdir(mode=0o700)
            bundle.extractall(destination, members=members, filter='data')
    return {'source_archive_verified': True, 'source_files': len(members)}


if __name__ == '__main__':
    import json
    import os
    import sys

    if os.name != 'posix' or os.geteuid() != 0 or len(sys.argv) != 5:
        raise SystemExit('Owned Linux root recovery guest required')
    try:
        print(json.dumps(extract(*sys.argv[1:])))
    except Exception:
        raise SystemExit('Private recovery source archive refused') from None
