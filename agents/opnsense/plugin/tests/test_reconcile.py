"""Exercise reconcile against controlled service and template commands."""
import importlib.util
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'src/usr/local/opnsense/scripts/nethub-agent/agentctl.py'
SPEC = importlib.util.spec_from_file_location('agentctl', SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
sys.path.insert(0, str(SCRIPT.parent))

VALID = '''serverAddr = "relay.example.com"
auth.token = "test-only"
transport.tls.enable = true
transport.tls.serverName = "relay.example.com"
transport.tls.trustedCaFile = "/usr/local/etc/nethub-agent/relay-ca.pem"
[[proxies]]
subdomain = "device-test"
'''


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'conf').mkdir()
        self.set_enabled(True)
        self.active = True
        self.reject = False
        self.render = VALID
        self.calls = []
        self.agent = MODULE.Agent(self.root, self.command)
        self.agent.config.mkdir(parents=True)
        (self.agent.config / 'relay-ca.pem').write_text('test CA')
        self.agent.live.write_text(VALID)

    def set_enabled(self, enabled):
        (self.root / 'conf/config.xml').write_text(
            '<opnsense><OPNsense><NetHubAgent><enabled>' + ('1' if enabled else '0') +
            '</enabled></NetHubAgent></OPNsense></opnsense>')

    def command(self, args, **kwargs):
        args = [str(arg) for arg in args]
        self.calls.append(args)
        code = 0
        if args[0] == '/usr/sbin/service':
            action = args[-1]
            if action == 'onestatus':
                code = 0 if self.active else 1
            else:
                self.active = action != 'onestop'
        elif args[0] == '/usr/local/sbin/configctl':
            self.agent.candidate.write_text(self.render)
            self.agent.candidate.chmod(0o644)
        elif args[0] == str(self.agent.binary):
            code = 1 if self.reject else 0
        return subprocess.CompletedProcess(args, code, '', 'credential-containing child output')

    def mutations(self):
        return [call[-1] for call in self.calls if call[0] == '/usr/sbin/service' and call[-1] != 'onestatus']

    def test_changed_configuration_is_verified_before_restart(self):
        self.render = VALID.replace('device-test', 'device-next')
        result = self.agent.apply('reconcile')
        self.assertTrue(result['success'])
        self.assertEqual(self.agent.live.read_text(), self.render)
        self.assertEqual(self.agent.backup.read_text(), VALID)
        self.assertEqual(self.mutations(), ['onerestart'])
        self.assertEqual(self.agent.live.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.agent.backup.stat().st_mode & 0o777, 0o600)

    def test_verify_failure_preserves_live_file_and_process(self):
        self.reject = True
        self.render = VALID.replace('device-test', 'device-next')
        result = self.agent.apply('reconcile')
        self.assertFalse(result['success'])
        self.assertEqual(self.agent.live.read_text(), VALID)
        self.assertEqual(self.mutations(), [])
        self.assertEqual(self.agent.candidate.stat().st_mode & 0o777, 0o600)
        self.assertNotIn('credential-containing', json.dumps(self.agent.status()))

    def test_unchanged_running_service_is_not_restarted(self):
        self.assertTrue(self.agent.apply('reconcile')['success'])
        self.assertEqual(self.mutations(), [])

    def test_unchanged_stopped_service_is_started(self):
        self.active = False
        self.assertEqual(self.agent.apply('reconcile')['action'], 'start')
        self.assertEqual(self.mutations(), ['onestart'])

    def test_kill_switch_stops_without_writing_config_xml(self):
        original = (self.root / 'conf/config.xml').read_bytes()
        self.agent.state.mkdir(parents=True)
        (self.agent.state / 'disabled').touch()
        self.assertTrue(self.agent.apply('reconcile')['success'])
        self.assertEqual(self.mutations(), ['onestop'])
        self.assertIn('NO', (self.root / 'etc/rc.conf.d/nethub_agent_frpc').read_text())
        self.assertEqual((self.root / 'conf/config.xml').read_bytes(), original)

    def test_disabled_settings_stop_service(self):
        self.set_enabled(False)
        self.agent.apply('reconcile')
        self.assertEqual(self.mutations(), ['onestop'])

    def test_explicit_stop_survives_periodic_reconcile(self):
        self.agent.apply('stop')
        self.agent.apply('reconcile')
        self.assertFalse(self.active)
        self.assertTrue((self.agent.state / 'stopped').exists())
        self.agent.apply('start')
        self.assertTrue(self.active)

    def test_ca_and_server_name_are_required(self):
        self.render = VALID.replace('transport.tls.serverName', 'untrustedServerName')
        self.assertFalse(self.agent.apply('reconcile')['success'])
        self.assertEqual(self.mutations(), [])

    def test_concurrent_operation_does_not_apply(self):
        self.agent.state.mkdir(parents=True)
        with (self.agent.state / 'reconcile.lock').open('a') as lock:
            MODULE.fcntl.flock(lock, MODULE.fcntl.LOCK_EX | MODULE.fcntl.LOCK_NB)
            self.assertEqual(self.agent.apply('reconcile')['action'], 'busy')
        self.assertEqual(self.calls, [])

    def test_log_tail_only_returns_recognized_events(self):
        log = self.root / 'var/log/nethub-agent/frpc.log'
        log.parent.mkdir(parents=True)
        log.write_text('old-credential must never be shown\nlogin to server success, old-credential\n')
        self.assertEqual(self.agent.status()['log'], 'Relay login succeeded')

    def test_missing_ca_preserves_configuration_and_reports_safe_error(self):
        (self.agent.config / 'relay-ca.pem').unlink()
        result = self.agent.apply('reconcile')
        self.assertFalse(result['success'])
        self.assertEqual(result['message'], 'Install the relay CA before enabling the tunnel')
        self.assertEqual(self.agent.live.read_text(), VALID)
        self.assertEqual(self.mutations(), [])

    def test_enrollment_ca_is_restored_from_model_without_changing_config_xml(self):
        sample = json.loads((ROOT.parents[2] / 'proto/examples/valid/enroll-response.json').read_text())
        ca = sample['relay_ca_pem'].encode()
        configuration = ('<opnsense><OPNsense><NetHubAgent><enabled>1</enabled><relay_ca>' +
                         base64.b64encode(ca).decode() + '</relay_ca></NetHubAgent></OPNsense></opnsense>').encode()
        (self.root / 'conf/config.xml').write_bytes(configuration)
        path = self.agent.config / 'relay-ca.pem'
        path.unlink()
        self.assertTrue(self.agent.apply('reconcile')['success'])
        self.assertEqual(path.read_bytes(), ca)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.root / 'conf/config.xml').read_bytes(), configuration)
        self.assertEqual(self.mutations(), [])
        path.unlink()
        self.assertTrue(self.agent.apply('reconcile')['success'])
        self.assertEqual(path.read_bytes(), ca)

    def test_unreviewed_trust_change_keeps_existing_live_material(self):
        sample = json.loads((ROOT.parents[2] / 'proto/examples/valid/enroll-response.json').read_text())
        (self.root / 'conf/config.xml').write_text(
            '<opnsense><OPNsense><NetHubAgent><enabled>1</enabled><relay_ca>' +
            base64.b64encode(sample['relay_ca_pem'].encode()).decode() +
            '</relay_ca></NetHubAgent></OPNsense></opnsense>')
        result = self.agent.apply('reconcile')
        self.assertFalse(result['success'])
        self.assertEqual((self.agent.config / 'relay-ca.pem').read_text(), 'test CA')
        self.assertEqual(self.agent.live.read_text(), VALID)
        self.assertEqual(self.mutations(), [])

    def test_existing_device_does_not_consume_another_server_token(self):
        self.agent.state.mkdir(parents=True)
        requests = self.agent.state / 'requests'
        requests.mkdir(mode=0o700)
        path = requests / ('enroll-' + 'a' * 32 + '.json')
        path.write_text(json.dumps({'origin': 'https://console.example.com', 'token': 'A' * 43}))
        path.chmod(0o600)
        (self.root / 'conf/config.xml').write_text(
            '<opnsense><OPNsense><NetHubAgent><device_id>existing</device_id></NetHubAgent></OPNsense></opnsense>')
        original = (self.root / 'conf/config.xml').read_bytes()
        with mock.patch('enrollment.request_enrollment') as network:
            self.assertEqual(self.agent.enroll(path), {'success': True, 'enrolled': True})
            network.assert_not_called()
        self.assertFalse(path.exists())
        self.assertEqual((self.root / 'conf/config.xml').read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
