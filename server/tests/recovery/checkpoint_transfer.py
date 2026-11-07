"""Read only the three private exports from an owned recovery guest namespace."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

from host_layout import RECEIVE_LIMITS, TRANSFER


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def export(action, name):
    if (sys.platform != 'linux' or os.geteuid() != 0 or action not in ('info', 'read')
            or name not in RECEIVE_LIMITS or Path(__file__).resolve().parent != Path(TRANSFER)):
        raise ValueError('Owned private checkpoint export required')
    root = Path(TRANSFER)
    parent = root.lstat()
    if (root != root.resolve(strict=True) or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != 0 or stat.S_IMODE(parent.st_mode) != 0o700):
        raise ValueError('Private checkpoint namespace differs')
    path = root / name
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= RECEIVE_LIMITS[name]
                or identity(path.lstat()) != identity(info)):
            raise ValueError('Private checkpoint file refused')
        value = hashlib.sha256()
        total = 0
        while block := source.read(65536):
            total += len(block)
            if total > info.st_size:
                raise ValueError('Private checkpoint export grew')
            value.update(block)
            if action == 'read':
                sys.stdout.buffer.write(block)
        if (total != info.st_size or identity(os.fstat(source.fileno())) != identity(info)
                or identity(path.lstat()) != identity(info)):
            raise ValueError('Private checkpoint file changed during transfer')
        if action == 'read':
            sys.stdout.buffer.flush()
            return None
        return {'bytes': total, 'sha256': value.hexdigest()}


if __name__ == '__main__':
    try:
        if len(sys.argv) != 3:
            raise ValueError('Private checkpoint export action required')
        result = export(*sys.argv[1:])
        if result is not None:
            print(json.dumps(result))
    except Exception:
        raise SystemExit('Private checkpoint export refused') from None
