"""Refuse detached server bindings and deadlines without operating a guest."""
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import cold_flow as flow
from linux_guest import RecoveryError


class ColdFlowAdmission(unittest.TestCase):
    def native(self):
        return SimpleNamespace(device='11111111-1111-4111-8111-111111111111',
            host='abcdefgh.devices.example.test', original_request={'original_cached_csr_sha256': 'a' * 64,
            'enrollment_gui_key_fingerprint': 'b' * 64})

    def test_actual_server_request_must_keep_original_host_CSR_and_key(self):
        native = self.native()
        row = {'id': '22222222-2222-4222-8222-222222222222', 'host': native.host, 'csr': 'a' * 64, 'key': 'b' * 64}
        host = SimpleNamespace(query=Mock(return_value=json.dumps(row)))
        self.assertEqual(flow.original_request(host, native), row['id'])
        for key, value in (('host', 'unrelated.example'), ('csr', 'c' * 64), ('key', 'd' * 64)):
            host.query.return_value = json.dumps({**row, key: value})
            with self.subTest(field=key), self.assertRaises(RecoveryError):
                flow.original_request(host, native)
        self.assertTrue(all(call.args[0].startswith('SELECT ') for call in host.query.call_args_list))

    def test_missing_generation_is_pending_but_malformed_generation_is_not_success(self):
        native = self.native()
        host = SimpleNamespace(query=Mock(return_value=''))
        request = '22222222-2222-4222-8222-222222222222'
        self.assertIsNone(flow.issued(host, native.device, request))
        for value in ({'id': request, 'leaf': 'invalid'}, {'id': 'invalid', 'leaf': 'a' * 64}):
            host.query.return_value = json.dumps(value)
            with self.subTest(value=value), self.assertRaises((RecoveryError, ValueError)):
                flow.issued(host, native.device, request)

    def test_failed_route_is_not_accepted_after_deadline(self):
        with patch.object(flow, 'route', return_value=False), patch.object(flow.time, 'monotonic', return_value=12):
            with self.assertRaises(RecoveryError):
                flow.wait_route(self.native(), 18443, Path('/unexecuted-roots'), 'a' * 64, 10)


if __name__ == '__main__':
    unittest.main()
