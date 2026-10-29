"""Exercise the privileged fixture's wrong-host refusal with the real PHP CLI."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


@pytest.mark.skipif(sys.platform.startswith('freebsd'), reason='This refusal case needs a non-FreeBSD host')
def test_native_fixture_refuses_other_hosts_before_native_configuration():
    configured = os.environ.get('NETHUB_TEST_PHP')
    php = configured or shutil.which('php')
    if not php:
        pytest.skip('PHP is required in the hosted plugin job')
    if configured:
        assert Path(configured).is_file(), 'Configured required PHP CLI is missing'
    script = Path(__file__).resolve().parents[1] / 'acceptance/native-fixture.php'
    result = subprocess.run([php, '-d', 'register_argc_argv=1', str(script)],
                            input=b'{}', capture_output=True, timeout=10)
    assert result.returncode == 1
    assert result.stderr == b''
    assert json.loads(result.stdout) == {'success': False, 'fixture_phase': 'host_freebsd'}
