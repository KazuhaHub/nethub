"""Reject unbounded or private diagnostic exports without starting a guest."""
import ast
import copy
import re
import signal
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
import urllib.parse
from unittest.mock import Mock, patch

import recovery_network_probe as probe


class ClosedNetworkEvidence(unittest.TestCase):
    def setUp(self):
        self.value = {'configured_source_count': 0, 'probes': [
            {'label': label, 'dns': 'resolved', 'ipv4_tcp': 'connected',
             'ipv6_tcp': 'error', 'metadata': 'index-header'}
            for label in ('official-http', 'official-https')], 'apt_update': {
                'timed_out': False, 'exit_status': 0, 'elapsed_seconds': 3,
                'process_reaped': True, 'output_truncated': False,
                'markers': dict.fromkeys(('dns', 'connection', 'lock', 'http', 'signature', 'certificate'), False)}}

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
        for key, value in [('raw_output', 'private host'), ('elapsed_seconds', 999), ('process_reaped', False)]:
            candidate = copy.deepcopy(self.value)
            candidate['apt_update'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                probe.validate(candidate)

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

    def test_active_sources_exclude_comments_and_non_uri_metadata(self):
        tree = ast.parse(probe.GUEST)
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'source_urls')
        namespace = {'re': re}
        exec(compile(ast.Module(body=[function], type_ignores=[]), 'guest-parser', 'exec'), namespace)
        text = '# See http://docs.ubuntu.com/example\nURIs: http://archive.ubuntu.com/ubuntu\nSigned-By: /key\n'
        self.assertEqual(namespace['source_urls'](text, True), ['http://archive.ubuntu.com/ubuntu'])
        text = '# deb http://old.ubuntu.com/ubuntu noble main\ndeb http://archive.ubuntu.com/ubuntu noble main # http://comment.ubuntu.com/\n'
        self.assertEqual(namespace['source_urls'](text, False), ['http://archive.ubuntu.com/ubuntu'])

    def test_apt_timeout_reaps_group_and_exports_only_closed_markers(self):
        tree = ast.parse(probe.GUEST)
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'apt_probe')
        process = Mock(pid=12345, returncode=-9)
        process.wait.side_effect = [subprocess.TimeoutExpired('private command', 120), -9]
        process.poll.side_effect = [None, -9]
        def launch(command, **kwargs):
            self.assertEqual(command[-2:], ['update', '-qq'])
            self.assertNotIn('install', command)
            self.assertTrue(kwargs['start_new_session'])
            kwargs['stdout'].write(b'Temporary failure resolving private.example; Could not get lock /private/path')
            return process
        kill = Mock()
        namespace = {'subprocess': subprocess, 'tempfile': tempfile, 'time': time,
                     'os': SimpleNamespace(killpg=kill), 'signal': SimpleNamespace(SIGKILL=9)}
        exec(compile(ast.Module(body=[function], type_ignores=[]), 'guest-apt', 'exec'), namespace)
        with patch('subprocess.Popen', side_effect=launch):
            result = namespace['apt_probe']()
        kill.assert_called_once_with(12345, 9)
        self.assertIs(result['timed_out'], True)
        self.assertIs(result['process_reaped'], True)
        self.assertIs(result['markers']['dns'], True)
        self.assertIs(result['markers']['lock'], True)
        self.assertNotIn('private', str(result))
        candidate = copy.deepcopy(self.value)
        candidate['apt_update'] = result
        probe.validate(candidate)


if __name__ == '__main__':
    unittest.main()
