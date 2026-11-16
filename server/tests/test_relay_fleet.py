"""Classify failed continuity observations without replay or private data."""
from contextlib import redirect_stdout
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import json

from relay_fleet import require_original_controls, require_retained_controls, recent_failure_hints, report_failure_context, PONG_REASONS


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

    def test_owned_failure_context_reads_once_without_replaying_a_mutation(self):
        stage = Path('/tmp/nethub-stack-test-context')
        compose = ['docker', 'compose', '-p', 'nethub-stack-test-context']
        for name in ('deployment/docker-compose.yml', 'deployment/docker-compose.override.yml', 'test.yml'):
            compose += ['-f', str(stage / name)]
        output = io.StringIO()
        with patch('relay_fleet.subprocess.run', return_value=SimpleNamespace(returncode=0,
                stdout=b'{"msg":"Relay hook decision","operation":"Ping","decision":"unavailable","private":"hidden"}')) as run:
            with redirect_stdout(output):
                report_failure_context(stage, compose)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0], compose + ['logs', '--no-color', '--no-log-prefix', '--tail', '100', 'nethub-authz'])
        self.assertEqual(output.getvalue(), 'NETHUB_NATIVE_HINT=relay_recent_Ping_unavailable\n')

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
