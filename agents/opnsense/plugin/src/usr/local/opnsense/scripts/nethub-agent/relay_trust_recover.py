"""Recover public trust locally and guard direct tunnel startup."""
import argparse
import base64
import json
import os
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

from certificate_key import KeyStore
from enrollment import validate_ca
from relay_trust import verify_settings
from relay_trust_backend import NativeTrustBackend, model_snapshot
from relay_trust_transaction import TrustTransaction


def quiesce_owned(run=subprocess.run):
    def service(verb):
        result = run(['/usr/sbin/service', 'nethub_agent_frpc', verb], capture_output=True, timeout=8)
        if len(result.stdout) > 65536 or len(result.stderr) > 16384:
            raise ValueError('Service output exceeds its limit')
        return result.returncode
    if service('onestatus') == 0 and service('onestop') != 0:
        return False
    return service('onestatus') != 0


def recover_pending(config, state, backend=None, quiesce=None, locked=False):
    config, state = Path(config), Path(state)
    directory = config/'relay-trust'
    if not directory.exists() and not directory.is_symlink():
        return {'success': True, 'phase': 'idle'}
    import fcntl
    files = KeyStore(config/'gui-key')
    files._protected(config, directory=True)
    files._protected(directory, directory=True)
    state.mkdir(parents=True, mode=0o700, exist_ok=True)
    files._protected(state, directory=True)
    path = state/'reconcile.lock'
    if path.exists() or path.is_symlink():
        files._protected(path)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(descriptor, 'a+b') as lock:
        info = files._protected(path)
        opened = os.fstat(lock.fileno())
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError('Trust recovery lock changed')
        if not locked:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return {'success': False, 'phase': 'busy'}
        transaction = TrustTransaction(config, backend or NativeTrustBackend(), quiesce or quiesce_owned, lambda: False)
        result = transaction.recover()
        return {'success': True, 'phase': 'recovered' if result is not None else 'idle'}


def startup_allowed(config, configuration, backend=None, controlled=False, openssl='/usr/bin/openssl'):
    """Read without acquiring the parent's held mutation lock; never mutate.

    Only an explicit controlled written-phase reload may cross a pending journal.
    It must still match the native binding, exact saved model/file and valid CA.
    No environment override can authorize prepared, corrupt or conflicting state.
    """
    try:
        config = Path(config)
        model = ET.parse(configuration).find('OPNsense/NetHubAgent')
        managed = model is not None and bool(model.findtext('relay_trust_state'))
        directory = config/'relay-trust'
        journal = directory.exists() or directory.is_symlink()
        if not managed and not journal:
            return True
        native = backend or NativeTrustBackend(configuration=configuration)
        transaction = TrustTransaction(config, native, lambda: False, lambda: False, openssl=openssl)
        value = transaction.read()
        if value is not None:
            if value['phase'] in ('prepared', 'written'):
                if not controlled or value['phase'] != 'written':
                    return False
                if not transaction._current(value):
                    return False
            elif not transaction._current(value, after=value['phase'] == 'applied'):
                return False
        current = native.read()
        pem = base64.b64decode(current['nodes']['relay_ca'], validate=True)
        if transaction._ca_bytes() != pem:
            return False
        if current['nodes']['relay_trust_state']:
            snapshot = model_snapshot(current['device_id'], current['nodes'])
            verify_settings(snapshot, current['device_id'], current['server_name'], config, openssl=openssl)
        else:
            validate_ca(pem.decode('ascii'))
        return True
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--locked', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--check-start', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if not hasattr(os, 'geteuid') or os.geteuid() != 0:
            raise ValueError('Trust recovery requires root')
        if args.check_start:
            success = startup_allowed('/usr/local/etc/nethub-agent', '/conf/config.xml',
                controlled=os.environ.get('NETHUB_TRUST_APPLY_ONCE') == '1')
            result = {'success': success, 'phase': 'checked'}
        else:
            result = recover_pending('/usr/local/etc/nethub-agent', '/var/db/nethub-agent', locked=args.locked)
    except Exception:
        result = {'success': False, 'phase': 'error'}
    if not args.check_start:
        print(json.dumps(result))
    return 0 if result['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
