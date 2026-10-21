"""Respect Core-owned configuration without relaxing private plugin ownership."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from test_native_certificate_store import SCRIPT, store, apply
from test_certificate_chain import chain
from certificate_transaction import CertificateTransactionError

pytestmark = pytest.mark.skipif(os.name == 'nt', reason='Native account and ownership contracts require POSIX')


def php(code, arguments=(), value=None):
    executable = os.environ.get('NETHUB_TEST_PHP') or shutil.which('php')
    assert executable, 'Native PHP is required'
    return subprocess.run([executable, '-r', code, str(SCRIPT), *map(str, arguments)],
                          input=json.dumps(value).encode(), capture_output=True, timeout=8)


def test_native_owner_resolution_uses_the_local_account_database_without_posix_extension():
    import grp
    import pwd
    user = pwd.getpwuid(0).pw_name
    group = grp.getgrgid(0).gr_name
    code = 'require $argv[1]; echo json_encode(NativeGuiCertificateStore::configurationIdentity(json_decode(stream_get_contents(STDIN), true)));'
    result = php(code, value=user + ':' + group)
    assert result.returncode == 0 and json.loads(result.stdout) == {'uid': 0, 'gid': 0}


@pytest.mark.parametrize('ownership', ['root', 'root:wheel:extra', '-root:wheel', 'root:../wheel',
                                       'root:wheel\n', 'nethub_no_such_account:root'])
def test_unknown_or_malformed_native_ownership_is_refused(ownership):
    code = ('require $argv[1]; try { NativeGuiCertificateStore::configurationIdentity(json_decode(stream_get_contents(STDIN), true));'
            ' exit(1); } catch (Throwable $error) { echo "refused"; }')
    result = php(code, value=ownership)
    assert result.returncode == 0 and result.stdout == b'refused'


@pytest.mark.skipif(not hasattr(os, 'geteuid') or os.geteuid() != 0, reason='Changing a synthetic file owner requires root')
@pytest.mark.parametrize('case', ['configured', 'wrong_user', 'wrong_group', 'public_mode', 'private_key'])
def test_only_the_native_configuration_accepts_its_configured_service_owner(store, case):
    import pwd
    journal, backend, value, _, _ = store
    service = pwd.getpwnam('nobody').pw_uid
    assert service != 0
    backend.config_identity = {'uid': service, 'gid': os.getegid()}
    os.chown(backend.configuration, service, os.getegid())
    backend.configuration.chmod(0o640)
    if case == 'wrong_user':
        backend.config_identity['uid'] = 0
    elif case == 'wrong_group':
        backend.config_identity['gid'] = os.getegid() + 1
    elif case == 'public_mode':
        backend.configuration.chmod(0o644)
    elif case == 'private_key':
        os.chown(backend.parent / 'gui-key/key.pem', service, os.getegid())
    before = backend.configuration.read_bytes()
    if case == 'configured':
        assert apply(journal, backend, value)['phase'] == 'applied'
        assert backend.configuration.stat().st_uid == service
    else:
        with pytest.raises(CertificateTransactionError):
            journal.apply(value)
        assert backend.configuration.read_bytes() == before


@pytest.mark.skipif(not sys.platform.startswith('freebsd') or not hasattr(os, 'geteuid') or os.geteuid() != 0,
                    reason='Read-only installed Core identity acceptance requires the native appliance')
def test_installed_core_configuration_identity_is_accepted_without_mutating_it(tmp_path):
    configuration = Path('/conf/config.xml')
    before = hashlib.sha256(configuration.read_bytes()).digest()
    parent = tmp_path / 'native-identity'
    parent.mkdir(mode=0o700)
    directory = parent / 'gui-apply'
    directory.mkdir(mode=0o700)
    code = ("require '/usr/local/opnsense/mvc/script/load_phalcon.php'; require $argv[1];"
            "$identity = NativeGuiCertificateStore::configurationIdentity((string)(new \\OPNsense\\Core\\AppConfig())->globals->owner);"
            "new NativeGuiCertificateStore(new stdClass(), $argv[2], '/conf/config.xml', $argv[3], 0, $identity);"
            "echo json_encode(['accepted' => true]);")
    result = php(code, (directory, parent / 'state'))
    assert result.returncode == 0 and json.loads(result.stdout) == {'accepted': True}
    assert hashlib.sha256(configuration.read_bytes()).digest() == before
