"""Classify failed continuity observations without replay or private data."""
from contextlib import redirect_stdout
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import json

from relay_fleet import require_original_controls, require_retained_controls, recent_failure_hints, frps_plugin_failure_hints, report_failure_context, PONG_REASONS


class FleetFailureTests(unittest.TestCase):
    def test_recent_failure_context_never_exports_private_child_fields(self):
        raw = b'\n'.join(json.dumps(value).encode() for value in [
            {'msg': 'Relay hook decision', 'operation': 'Ping', 'decision': 'unavailable', 'private': 'must-not-escape'},
            {'msg': 'Relay hook decision', 'operation': 'Ping', 'decision': 'device_denied'},
            {'msg': 'Relay hook decision', 'operation': 'unknown', 'decision': 'busy'},
            {'msg': 'Revocation refresh failed; retaining previous snapshot', 'private': 'must-not-escape'},
            {'msg': 'Relay hook decision', 'operation': 'Login', 'decision': 'unavailable'},
            {'msg': 'private', 'operation': 'Ping', 'decision': 'private'}, ['private']])
        self.assertEqual(recent_failure_hints(raw), {
            'relay_recent_Ping_unavailable', 'relay_recent_Ping_device_denied',
            'relay_recent_hook_busy', 'relay_recent_snapshot_refresh_failed'})
        self.assertEqual(recent_failure_hints(b'private non-JSON\n'), set())
        with self.assertRaises(ValueError):
            recent_failure_hints(b'x' * (1024**2 + 1))

    def test_unowned_context_never_runs_a_child_or_exports_error_text(self):
        output = io.StringIO()
        with patch('relay_fleet.subprocess.run', side_effect=AssertionError('unexpected child')):
            with redirect_stdout(output):
                report_failure_context(Path('/private'), ['private-command'])
        self.assertEqual(output.getvalue(), 'NETHUB_NATIVE_HINT=relay_failure_context_unavailable\n')

    def _owned(self):
        stage = Path('/tmp/nethub-stack-test-context')
        compose = ['docker', 'compose', '-p', 'nethub-stack-test-context']
        for name in ('deployment/docker-compose.yml', 'deployment/docker-compose.override.yml', 'test.yml'):
            compose += ['-f', str(stage / name)]
        return stage, compose

    def test_owned_failure_context_reads_once_without_replaying_a_mutation(self):
        stage, compose = self._owned()
        output = io.StringIO()
        authz = SimpleNamespace(returncode=0,
            stdout=b'{"msg":"Relay hook decision","operation":"Ping","decision":"unavailable","private":"hidden"}')
        frps = SimpleNamespace(returncode=0,
            stdout=b'x send Ping request to plugin [private] error: do http request error code: 404 10.0.0.1:8080\n')
        with patch('relay_fleet.subprocess.run', side_effect=[authz, frps]) as run:
            with redirect_stdout(output):
                report_failure_context(stage, compose)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[0].args[0], compose + ['logs', '--no-color', '--no-log-prefix', '--tail', '100', 'nethub-authz'])
        self.assertEqual(run.call_args_list[1].args[0], compose + ['logs', '--no-color', '--no-log-prefix', '--tail', '200', 'frps'])
        self.assertEqual(output.getvalue(),
            'NETHUB_NATIVE_HINT=relay_frps_Ping_plugin_status_404\nNETHUB_NATIVE_HINT=relay_recent_Ping_unavailable\n')
        self.assertNotIn('private', output.getvalue())

    def test_frps_read_failure_keeps_authz_hints_and_is_closed(self):
        stage, compose = self._owned()
        output = io.StringIO()
        authz = SimpleNamespace(returncode=0,
            stdout=b'{"msg":"Relay hook decision","operation":"Ping","decision":"unavailable"}')
        with patch('relay_fleet.subprocess.run', side_effect=[authz, SimpleNamespace(returncode=1, stdout=b'private')]):
            with redirect_stdout(output):
                report_failure_context(stage, compose)
        self.assertEqual(output.getvalue(),
            'NETHUB_NATIVE_HINT=relay_frps_context_unavailable\nNETHUB_NATIVE_HINT=relay_recent_Ping_unavailable\n')
        # A failed authz read must not suppress the independent owned frps read.
        output = io.StringIO()
        frps = SimpleNamespace(returncode=0,
            stdout=b'send Ping request to plugin [private] error: Post "http://private": EOF\n')
        with patch('relay_fleet.subprocess.run', side_effect=[SimpleNamespace(returncode=1, stdout=b'private'), frps]) as run:
            with redirect_stdout(output):
                report_failure_context(stage, compose)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(output.getvalue(),
            'NETHUB_NATIVE_HINT=relay_failure_context_unavailable\nNETHUB_NATIVE_HINT=relay_frps_Ping_plugin_EOF\n')

    def test_frps_ping_plugin_categories_are_closed_and_never_export_private_text(self):
        cases = {
            'do http request error code: 403': 'status_403', 'do http request error code: 404': 'status_404',
            'do http request error code: 405': 'status_405', 'do http request error code: 500': 'status_other',
            'Post "http://10.1.2.3:7600/handler": EOF': 'EOF', 'unexpected EOF': 'truncated',
            'read tcp 10.1.2.3:1->10.1.2.4:2: read: connection reset by peer': 'reset',
            'dial tcp 10.1.2.3:7600: connect: connection refused': 'refused',
            'dial tcp 10.1.2.3:7600: i/o timeout': 'timeout', 'context deadline exceeded': 'timeout',
            'Client.Timeout exceeded while awaiting headers': 'timeout',
            'http: server closed idle connection': 'closed_idle',
            'invalid character x looking for value': 'decode', 'unexpected end of JSON input': 'decode',
            'json: cannot unmarshal string': 'decode', 'private-secret surprise': 'unclassified'}
        for suffix, category in cases.items():
            with self.subTest(suffix=suffix):
                raw = ('2026 [W] [manager.go:1] [reqid-private] send Ping request to plugin [private-name] error: '
                       + suffix + '\n').encode()
                hints = frps_plugin_failure_hints(raw)
                self.assertEqual(hints, {'relay_frps_Ping_plugin_' + category})
                self.assertNotIn('private', ''.join(hints))
                # frps console output is colourised; Compose --no-color does not strip it.
                self.assertEqual(frps_plugin_failure_hints(b'\x1b[1;33m' + raw + b'\x1b[0m'), hints)
        self.assertEqual(frps_plugin_failure_hints(
            b'send Login request to plugin [x] error: do http request error code: 404\nunrelated\n'
            b'send Ping request to plugin [x] no marker\n'), set())
        with self.assertRaises(ValueError):
            frps_plugin_failure_hints(b'x' * (1024**2 + 1))

    def test_pong_reasons_require_exact_fixed_suffixes_and_keep_control_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / 'client.log'
            for raw, category in list(PONG_REASONS.items()) + [(b'unavailable private-secret', None)]:
                log.write_bytes(b'private-prefix pong message contains error: ' + raw + b'\n')
                output = io.StringIO()
                with self.subTest(category=category), redirect_stdout(output), self.assertRaises(AssertionError):
                    require_original_controls({1: {'changed'}}, {1: {'original'}}, [], [(None, log, SimpleNamespace(pid=1))], 1)
                expected = {'NETHUB_NATIVE_HINT=relay_fleet_stage_ten',
                    'NETHUB_NATIVE_HINT=relay_fleet_dedicated_control_changed',
                    'NETHUB_NATIVE_HINT=relay_fleet_changed_client_Pong_error'}
                if category is not None:
                    expected.add('NETHUB_NATIVE_HINT=relay_fleet_changed_client_Pong_' + category)
                self.assertEqual(set(output.getvalue().splitlines()), expected)
                self.assertNotIn('private', output.getvalue())

    def test_batch_can_add_members_without_replacing_any_retained_socket(self):
        retained = {101: {('original-source', 'original-peer', 'original-inode')}}
        actual = dict(retained)
        actual[202] = {('new-source', 'new-peer', 'new-inode')}
        output = io.StringIO()
        with redirect_stdout(output):
            require_retained_controls(actual, retained, [SimpleNamespace(pid=101)], [], 0)
        self.assertEqual(output.getvalue(), '')
        self.assertEqual(set(retained), {101})
        self.assertEqual(set(actual), {101, 202})

    def test_batch_replaced_or_missing_originals_still_refuse_with_closed_hints(self):
        retained = {101: {('private-source', 'private-peer', 'private-inode')}}
        for actual, missing in (({101: {('changed', 'peer', 'inode')}, 202: {'new'}}, False),
                                ({202: {'new'}}, True)):
            output = io.StringIO()
            with self.subTest(missing=missing), redirect_stdout(output), self.assertRaises(AssertionError):
                require_retained_controls(actual, retained, [SimpleNamespace(pid=101)], [], 1)
            expected = {'NETHUB_NATIVE_HINT=relay_fleet_stage_ten',
                        'NETHUB_NATIVE_HINT=relay_fleet_original_control_changed'}
            if missing:
                expected.add('NETHUB_NATIVE_HINT=relay_fleet_inventory_changed')
            self.assertEqual(set(output.getvalue().splitlines()), expected)
            self.assertNotIn('private', output.getvalue())
            self.assertNotIn('101', output.getvalue())

    def test_unchanged_controls_do_not_inspect_private_logs(self):
        class Refuse:
            def __getattr__(self, _name):
                raise AssertionError('Passing observation must not read any log')
        output = io.StringIO()
        baseline = {101: {('private-source', 'private-peer', 'private-inode')}}
        with redirect_stdout(output):
            require_original_controls(dict(baseline), baseline, [], [(None, Refuse(), Refuse())], 0)
        self.assertEqual(output.getvalue(), '')

    def test_failed_controls_keep_only_fixed_stage_and_presence_hints(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / 'client.log'
            log.write_bytes(b'private-peer secret-key 555\nreceive heartbeat from server\n'
                            b'pong message contains error\nheartbeat timeout\n')
            baseline = {101: {('private-source', 'private-peer', 'private-inode')}, 202: {('a', 'b', 'c')}}
            for stage, name in ((0, 'five'), (1, 'ten'), (2, 'pressure')):
                output = io.StringIO()
                with self.subTest(stage=stage), redirect_stdout(output), self.assertRaisesRegex(
                        AssertionError, '^fleet control disconnected or reconnected under bounded load$'):
                    require_original_controls({101: {('x', 'y', 'z')}, 202: {('b', 'c', 'd')}}, baseline,
                        [SimpleNamespace(pid=101)], [(None, log, SimpleNamespace(pid=202))], stage)
                self.assertEqual(set(output.getvalue().splitlines()), {
                    'NETHUB_NATIVE_HINT=relay_fleet_stage_' + name,
                    'NETHUB_NATIVE_HINT=relay_fleet_original_control_changed',
                    'NETHUB_NATIVE_HINT=relay_fleet_dedicated_control_changed',
                    'NETHUB_NATIVE_HINT=relay_fleet_changed_client_heartbeat_timeout',
                    'NETHUB_NATIVE_HINT=relay_fleet_changed_client_Pong_error',
                    'NETHUB_NATIVE_HINT=relay_fleet_changed_client_Pong_observed'})
                self.assertNotIn('private', output.getvalue())
                self.assertNotIn('202', output.getvalue())

    def test_missing_failure_log_cannot_hide_original_refusal(self):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as temporary, redirect_stdout(output), self.assertRaises(AssertionError):
            require_original_controls({1: {'changed'}}, {1: {'original'}}, [],
                [(None, Path(temporary) / 'missing', SimpleNamespace(pid=1))], 2)
        self.assertIn('relay_fleet_failure_log_unavailable', output.getvalue())

    def test_ambiguous_inventory_still_refuses(self):
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(AssertionError):
            require_original_controls({1: {'same'}, 2: {'extra'}}, {1: {'same'}}, [], [], 0)
        self.assertIn('relay_fleet_inventory_changed', output.getvalue())


if __name__ == '__main__':
    unittest.main()
