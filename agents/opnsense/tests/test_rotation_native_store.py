"""Exercise the actual PHP rotation model boundary with native framework doubles."""
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[3]
PLUGIN = ROOT / 'agents/opnsense/plugin'
SCRIPTS = PLUGIN / 'src/usr/local/opnsense/scripts/nethub-agent'
PHP = os.environ.get('NETHUB_TEST_PHP') or shutil.which('php')


@pytest.mark.skipif(PHP is None, reason='Requires target PHP or Linux/FreeBSD CI')
@pytest.mark.parametrize('field_order', ['native', 'journal'])
def test_native_rotation_model_keeps_policy_and_confirms_single_save(tmp_path, field_order):
    result = subprocess.run([PHP, str(PLUGIN / 'tests/rotation_store_contract.php'),
                             str(SCRIPTS / 'rotation_store.php'),
                             str(PLUGIN / 'src/usr/local/opnsense/mvc/app/models/OPNsense/NetHubAgent/Enrollment.php'),
                             str(ROOT / 'proto/examples/valid/enroll-response.json'), str(tmp_path / 'native'), field_order],
                            capture_output=True, timeout=10, check=True)
    assert json.loads(result.stdout) == dict(stable_policy=True, single_save=True, readback=True,
                                           conflicts_refused=True, revoked_refused=True,
                                           journal_key_order=field_order == 'journal', invalid_field_sets_refused=True)
