"""Private, bounded file transfer for the owned clean-host recovery drill."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile


LIMIT = 256 * 1024**2
OWNERS = {0, 70, 65532}


class PayloadError(Exception):
    pass


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def metadata(info, name, content_hash=''):
    return [name, 'directory' if stat.S_ISDIR(info.st_mode) else 'file',
            stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid,
            0 if stat.S_ISDIR(info.st_mode) else info.st_size, content_hash]


def inventory_hash(entries):
    return hashlib.sha256(json.dumps(sorted(entries), separators=(',', ':')).encode()).hexdigest()


def private_info(path):
    info = path.lstat()
    if (path.absolute() != path.resolve(strict=True) or info.st_uid not in OWNERS
            or info.st_gid not in OWNERS or stat.S_IMODE(info.st_mode) & ~0o755
            or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
            or stat.S_ISREG(info.st_mode) and (info.st_nlink != 1 or info.st_size > 64 * 1024**2)):
        raise PayloadError('Recovery source contains an unsafe file')
    return info


def unchanged(info):
    # Reading can update atime even though the retained material is unchanged.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def pack(paths, archive):
    """Paths explicitly select current deployment, matching backups and stopped volumes."""
    entries, total = [], 0
    with archive.open('xb') as output, tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as bundle:
        for path in sorted(set(paths), key=lambda item: (len(item.parts), str(item))):
            info = private_info(path)
            name = path.as_posix().lstrip('/')
            content = b''
            if stat.S_ISREG(info.st_mode):
                with path.open('rb') as source:
                    current = os.fstat(source.fileno())
                    if (current.st_dev, current.st_ino, current.st_nlink) != (info.st_dev, info.st_ino, 1):
                        raise PayloadError('Recovery source changed during read')
                    content = source.read(64 * 1024**2 + 1)
                    if len(content) != info.st_size or source.read(1):
                        raise PayloadError('Recovery source size changed')
                    if unchanged(os.fstat(source.fileno())) != unchanged(current):
                        raise PayloadError('Recovery source changed during read')
                total += len(content)
                if total > LIMIT - 1024**2:
                    raise PayloadError('Recovery payload exceeds its bound')
            member = tarfile.TarInfo(name)
            member.type = tarfile.DIRTYPE if stat.S_ISDIR(info.st_mode) else tarfile.REGTYPE
            member.mode, member.uid, member.gid = stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid
            member.size = len(content)
            bundle.addfile(member, io.BytesIO(content) if content else None)
            entries.append(metadata(info, name, hashlib.sha256(content).hexdigest() if member.isfile() else ''))
        bundle.close()
        output.flush()
        os.fsync(output.fileno())
    archive.chmod(0o600)
    if archive.stat().st_size > LIMIT:
        raise PayloadError('Recovery archive exceeds its bound')
    return {'sha256': digest(archive), 'inventory_sha256': inventory_hash(entries), 'entries': len(entries)}


def validate_members(members, roots):
    names, size = set(), 0
    for member in members:
        name = PurePosixPath(member.name)
        if (not member.name or name.is_absolute() or name.as_posix() != member.name
                or any(part in ('.', '..') for part in name.parts) or '\\' in member.name
                or any(ord(char) < 32 for char in member.name)
                or member.name in names or not (member.isfile() or member.isdir())
                or member.pax_headers or member.uid not in OWNERS or member.gid not in OWNERS
                or member.mode & ~0o755 or member.size < 0 or member.size > 64 * 1024**2
                or member.isdir() and member.size != 0
                or not any(name == root or name.is_relative_to(root) for root in roots)):
            raise PayloadError('Recovery archive member refused')
        names.add(member.name)
        size += member.size
    if not names or len(names) > 4096 or size > LIMIT - 1024**2:
        raise PayloadError('Recovery archive shape refused')
    if not {str(root) for root in roots}.issubset(names):
        raise PayloadError('Recovery archive root missing')


def restore(archive, roots, expected_hash, expected_inventory):
    if (not all(re.fullmatch('[a-f0-9]{64}', value) for value in (expected_hash, expected_inventory))
            or archive.stat().st_size > LIMIT or digest(archive) != expected_hash):
        raise PayloadError('Recovery archive integrity refused')
    canonical = []
    for root in roots:
        if not root.is_absolute() or root != root.resolve() or root == Path('/'):
            raise PayloadError('Recovery destination is aliased')
        if root.exists() and (not root.is_dir() or any(root.iterdir())):
            raise PayloadError('Recovery destination is not empty')
        canonical.append(PurePosixPath(root.as_posix().lstrip('/')))
    entries, directories = [], []
    with tarfile.open(archive, 'r:') as bundle:
        members = bundle.getmembers()
        validate_members(members, canonical)
        for member in sorted(members, key=lambda item: (len(PurePosixPath(item.name).parts), item.name)):
            target = Path('/') / member.name
            if target != target.resolve() or not target.parent.is_dir():
                raise PayloadError('Recovery parent is unsafe or missing')
            if member.isdir():
                if not target.exists():
                    target.mkdir(mode=0o700)
                elif target not in roots or not target.is_dir() or any(target.iterdir()):
                    raise PayloadError('Recovery directory already contains state')
                directories.append((target, member))
                content_hash = ''
            else:
                source = bundle.extractfile(member)
                if source is None:
                    raise PayloadError('Recovery content is missing')
                with source, target.open('xb') as output:
                    data = source.read(member.size + 1)
                    if len(data) != member.size:
                        raise PayloadError('Recovery content is truncated')
                    output.write(data)
                    output.flush()
                    os.fsync(output.fileno())
                os.chown(target, member.uid, member.gid)
                target.chmod(member.mode)
                content_hash = digest(target)
            entries.append([member.name, 'directory' if member.isdir() else 'file', member.mode,
                            member.uid, member.gid, member.size, content_hash])
        if inventory_hash(entries) != expected_inventory:
            raise PayloadError('Recovered file inventory differs')
        for target, member in reversed(directories):
            os.chown(target, member.uid, member.gid)
            target.chmod(member.mode)
    return {'files_restored': True, 'inventory_verified': True, 'entries': len(entries)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('archive', type=Path)
    parser.add_argument('sha256')
    parser.add_argument('inventory_sha256')
    parser.add_argument('roots', nargs='+', type=Path)
    args = parser.parse_args()
    if os.name != 'posix' or os.geteuid() != 0:
        raise SystemExit('Owned Linux root recovery target required')
    try:
        print(json.dumps(restore(args.archive, args.roots, args.sha256, args.inventory_sha256)))
    except Exception:
        raise SystemExit('Private recovery payload refused') from None
