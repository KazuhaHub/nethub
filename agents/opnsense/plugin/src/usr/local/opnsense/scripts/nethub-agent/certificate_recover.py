"""Recover pending local GUI transactions before normal GUI startup."""
import argparse
import json
import os
from pathlib import Path

from certificate_backend import NativeGuiBackend
from certificate_key import KeyStore
from certificate_transaction import CertificateTransaction


def recover_pending(config, state, backend=None, locked=False, boot=True):
    config, state = Path(config), Path(state)
    directory = config / 'gui-apply'
    if not directory.exists() and not directory.is_symlink():
        return {'success': True, 'action': 'certificate_recover', 'phase': 'idle', 'message': 'No pending GUI certificate transaction'}
    import fcntl
    os.umask(0o077)
    files = KeyStore(config / 'gui-key')
    files._protected(config, directory=True)
    files._protected(directory, directory=True)
    state.mkdir(parents=True, mode=0o700, exist_ok=True)
    files._protected(state, directory=True)
    path = state / 'reconcile.lock'
    if path.exists() or path.is_symlink():
        files._protected(path)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(descriptor, 'a+b') as lock:
        info = files._protected(path)
        opened = os.fstat(lock.fileno())
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError('Recovery lock changed')
        if not locked:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return {'success': False, 'action': 'certificate_recover', 'phase': 'busy', 'message': 'Another service operation is running'}
        native = backend if backend is not None else NativeGuiBackend(files, boot=boot)
        result = CertificateTransaction(directory, native).recover()
        return result if result is not None else {
            'success': True, 'action': 'certificate_recover', 'phase': 'idle', 'message': 'No pending GUI certificate transaction'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--locked', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--running', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if not hasattr(os, 'geteuid') or os.geteuid() != 0:
            raise ValueError('Native recovery requires root')
        result = recover_pending('/usr/local/etc/nethub-agent', '/var/db/nethub-agent', locked=args.locked, boot=not args.running)
    except Exception:
        result = {'success': False, 'action': 'certificate_recover', 'phase': 'error',
                  'message': 'Pending GUI certificate recovery failed; local review is required'}
    print(json.dumps(result))
    return 1 if result.get('success') is False else 0


if __name__ == '__main__':
    raise SystemExit(main())
