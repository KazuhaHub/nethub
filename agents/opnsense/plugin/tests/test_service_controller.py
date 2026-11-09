"""Run the actual PHP action dispatch with bounded framework doubles."""
import json
import os
from pathlib import Path
import shutil
import subprocess


def test_circuit_controller_requires_post_write_access_and_bounded_backend():
    root = Path(__file__).resolve().parents[1]
    php = os.environ.get('NETHUB_TEST_PHP') or shutil.which('php')
    assert php, 'PHP is required for the service controller contract'
    result = subprocess.run([php, str(root / 'tests/service_controller_contract.php'),
                             str(root / 'src/usr/local/opnsense/mvc/app/controllers/OPNsense/NetHubAgent/Api/ServiceController.php')],
                            capture_output=True, timeout=8, check=True)
    evidence = json.loads(result.stdout)
    assert evidence['service_cases_passed'] == [
        action + ':' + case for action in ('disable', 'enable', 'rotate')
        for case in ('get', 'readonly', 'success', 'busy', 'invalid', 'trust_changed')]
    assert evidence['rotation_failure_cases_passed'] == [
        'trust_sync', 'trust_recovery', 'trust_recovery', 'native_model', 'rotation_journal',
        'native_save', 'native_save', 'interrupted', 'unclassified', 'unclassified',
        'backend_response', 'backend_response', 'backend_response', 'backend_exception']
