"""Exercise the privileged fixture's wrong-host refusal with the real PHP CLI."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


@pytest.mark.skipif(sys.platform.startswith('freebsd'), reason='This refusal case needs a non-FreeBSD host')
@pytest.mark.parametrize('fixture', ['native-fixture.php', 'rotation-save-lock.php'])
def test_native_fixture_refuses_other_hosts_before_native_configuration(fixture):
    configured = os.environ.get('NETHUB_TEST_PHP')
    php = configured or shutil.which('php')
    if not php:
        pytest.skip('PHP is required in the hosted plugin job')
    if configured:
        assert Path(configured).is_file(), 'Configured required PHP CLI is missing'
    script = Path(__file__).resolve().parents[1] / 'acceptance' / fixture
    result = subprocess.run([php, '-d', 'register_argc_argv=1', str(script)],
                            input=b'{}', capture_output=True, timeout=10)
    assert result.returncode == 1
    assert result.stderr == b''
    expected = ({'success': False, 'fixture_phase': 'host_freebsd'}
                if fixture == 'native-fixture.php' else {'success': False})
    assert json.loads(result.stdout) == expected


def test_native_fixture_preserves_suppressed_native_warning_semantics(tmp_path):
    configured = os.environ.get('NETHUB_TEST_PHP')
    php = configured or shutil.which('php')
    if not php:
        pytest.skip('PHP is required in the hosted plugin job')
    source = Path(__file__).resolve().parents[1] / 'acceptance/native-fixture.php'
    header = source.read_text(encoding='utf-8').split("$phase = 'host_boundary';", 1)[0]
    contract = tmp_path / 'native-error-contract.php'
    contract.write_text(header + r'''
try {
    @unlink(__FILE__ . '.absent');
    $suppressed = true;
    trigger_error('private warning must not escape', E_USER_WARNING);
    exit(2);
} catch (ErrorException $error) {
    echo json_encode(['suppressed_warning_ignored' => $suppressed ?? false,
        'unsuppressed_warning_rejected' => $error->getSeverity() === E_USER_WARNING,
        'raw_message_excluded' => $error->getMessage() === 'Fixture failed']);
}
''', encoding='utf-8')
    result = subprocess.run([php, str(contract)], capture_output=True, timeout=10)
    assert result.returncode == 0 and result.stderr == b''
    assert json.loads(result.stdout) == {'suppressed_warning_ignored': True,
        'unsuppressed_warning_rejected': True, 'raw_message_excluded': True}
