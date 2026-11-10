"""Reject unbounded or private diagnostic exports without starting a guest."""
import ast
import copy
import re
import unittest
import urllib.parse

import recovery_network_probe as probe


class ClosedNetworkEvidence(unittest.TestCase):
    def setUp(self):
        self.value = {'configured_source_count': 0, 'probes': [
            {'label': label, 'dns': 'resolved', 'ipv4_tcp': 'connected',
             'ipv6_tcp': 'error', 'metadata': 'index-header'}
            for label in ('official-http', 'official-https')]}

    def test_private_fields_unknown_states_and_missing_baselines_are_refused(self):
        self.assertEqual(probe.validate(self.value), self.value)
        for field, value in [('address', '192.0.2.1'), ('dns', 'private text'),
                             ('label', 'https://private.example'), ('metadata', 'signature-verified')]:
            candidate = copy.deepcopy(self.value)
            candidate['probes'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                probe.validate(candidate)
        with self.assertRaises(ValueError):
            probe.validate({**self.value, 'probes': self.value['probes'][:1]})
        with self.assertRaises(ValueError):
            probe.validate({**self.value, 'configured_source_count': True})

    def test_guest_source_parser_and_destination_allowlist(self):
        tree = ast.parse(probe.GUEST)
        allowed = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'allowed')
        namespace = {'urllib': __import__('urllib')}
        exec(compile(ast.Module(body=[allowed], type_ignores=[]), 'guest-allowlist', 'exec'), namespace)
        for url in ['http://archive.ubuntu.com/ubuntu', 'https://security.ubuntu.com/ubuntu']:
            self.assertTrue(namespace['allowed'](url))
        for url in ['http://127.0.0.1/', 'http://ubuntu.com.evil.example/',
                    'https://user:password@archive.ubuntu.com/', 'http://archive.ubuntu.com:7000/',
                    'https://archive.ubuntu.com/?secret=value', 'file:///etc/passwd']:
            self.assertFalse(namespace['allowed'](url))
        pattern = next(n.args[0].value for n in ast.walk(tree) if isinstance(n, ast.Call)
                       and isinstance(n.func, ast.Attribute) and n.func.attr == 'findall')
        self.assertEqual(re.findall(pattern, 'URIs: http://archive.ubuntu.com/ubuntu https://security.ubuntu.com/ubuntu\nSuites: noble'),
                         ['http://archive.ubuntu.com/ubuntu', 'https://security.ubuntu.com/ubuntu'])


if __name__ == '__main__':
    unittest.main()
