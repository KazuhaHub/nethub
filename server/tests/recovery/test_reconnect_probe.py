"""Proxy observation diagnostics never export raw relay metadata."""
import json
import unittest

from reconnect_probe import project


IDS = ['00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002']


class ClosedProxyStates(unittest.TestCase):
    def test_distinguishes_online_offline_and_absent_without_metadata(self):
        raw = json.dumps({'proxies': [{'name': 'nethub-' + IDS[0] + '-web', 'status': 'online',
                                      'conf': {'private': 'private-value'}}]}).encode()
        self.assertEqual(project(raw, IDS), {'native_proxy': 'online', 'witness_proxy': 'absent'})
        self.assertNotIn('private', str(project(raw, IDS)))
        self.assertEqual(project(raw.replace(b'online', b'offline'), IDS)['native_proxy'], 'offline')

    def test_duplicate_keys_or_proxy_names_are_refused_without_echo(self):
        name = 'nethub-' + IDS[0] + '-web'
        row = {'name': name, 'status': 'online'}
        for raw in (b'{"proxies":[],"proxies":"private"}',
                    json.dumps({'proxies': [row, row]}).encode()):
            with self.assertRaises(ValueError) as caught:
                project(raw, IDS)
            self.assertEqual(str(caught.exception), 'Restored relay observation unavailable')

    def test_oversized_or_unknown_state_is_refused(self):
        for raw in (b'x' * (1024**2 + 1), json.dumps({'proxies': [
                {'name': 'private-name', 'status': 'private-state'}]}).encode()):
            with self.assertRaises(ValueError) as caught:
                project(raw, IDS)
            self.assertEqual(str(caught.exception), 'Restored relay observation unavailable')
