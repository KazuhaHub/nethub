"""Preserve one-way revocation and cleanup when a combined observation fails."""
import hashlib
import copy
from contextlib import ExitStack, redirect_stdout
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import relay_combined_fault as combined


class Clock:
    def __init__(self):
        self.value = 1000.0

    def monotonic(self):
        return self.value

    def sleep(self, seconds):
        self.value += seconds


def fixture(tmp_path, monkeypatch, failure=None):
    clock = Clock()
    monkeypatch.setattr(combined, 'time', clock)
    stage = tmp_path / 'stage'
    (stage / 'official').mkdir(parents=True)
    binary = stage / 'official/frpc'
    binary.write_bytes(b'fixture')
    work = stage / 'relay-test'
    work.mkdir()
    configs = {}
    for pid in range(1, 14):
        path = work / (str(pid) + '.json')
        path.write_text(json.dumps({'transport': {'heartbeatInterval': 1, 'heartbeatTimeout': 3},
                                   'log': {'level': 'debug'}}))
        path.with_suffix('.log').write_bytes(b'heartbeat timeout\n')
        configs[pid] = path
    secrets = stage / 'deployment/secrets/frps'
    secrets.mkdir(parents=True)
    for name in ('frps_admin_user', 'frps_admin_password'):
        (secrets / name).write_text('private-test-value')
    original_read = Path.read_bytes

    def read(path):
        if str(path).replace('\\', '/').startswith('/proc/'):
            pid = int(path.parts[-2])
            return str(binary).encode() + b'\0-c\0' + str(configs[pid]).encode() + b'\0'
        if path.suffix == '.log' and path.stem.isdecimal() and int(path.stem) <= 12:
            return b'receive heartbeat from server\n' * int(clock.value - 1000)
        return original_read(path)

    monkeypatch.setattr(Path, 'read_bytes', read)
    state = {'revoked': False, 'active': False, 'mutations': 0, 'target_stops': 0, 'fresh_refusals': 0}

    class Fault:
        def __init__(self, binding, _directory):
            assert binding[0] == '127.0.0.1:52013' and binding[1] == '127.0.0.1:7000'
            self.restored = False
            self.interrupted = False
            state['fault'] = self

        def __enter__(self):
            state['active'] = True
            self.started = clock.value
            return self

        def counters(self):
            return {'packets': 2, 'bytes': 152}

        def __exit__(self, *_args):
            state['active'] = False
            self.removed = clock.value
            self.restored = True

    monkeypatch.setattr(combined, 'ControlDrop', Fault)
    references = [SimpleNamespace(pid=i, poll=lambda: None) for i in range(1, 13)]
    target_client = SimpleNamespace(pid=13, poll=lambda: None)
    assignment = {'device_id': '11111111-1111-4111-8111-111111111111', 'subdomain': 'combined-target'}
    compose = ['docker', 'compose', '--project-name', 'nethub-stack-test-unit']

    def run(args, **_kwargs):
        assert args == ['ss', '-tnpeH']
        pids = list(range(1, 13)) + ([13] if not state['revoked'] or state['active'] else [])
        raw = '\n'.join('ESTAB 0 0 127.0.0.1:' + str(52000 + pid)
            + ' 127.0.0.1:7000 users:(("frpc",pid=' + str(pid) + ',fd=3)) ino:' + str(100 + pid) for pid in pids)
        return SimpleNamespace(returncode=0, stdout=raw)

    def output(args, **_kwargs):
        if args[:4] == compose:
            return hashlib.sha256(args[-1].encode()).hexdigest().encode()
        assert args[:2] == ['docker', 'inspect']
        return json.dumps([{'Image': 'sha256:' + args[-1],
            'Config': {'Labels': {'com.docker.compose.project': compose[3]}},
            'State': {'Running': True, 'OOMKilled': False, 'Pid': 100, 'StartedAt': 'original'}}]).encode()

    monkeypatch.setattr(combined.subprocess, 'run', run)
    monkeypatch.setattr(combined.subprocess, 'check_output', output)

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def read(self, _bound):
            return json.dumps({'proxies': [{'name': 'nethub-' + assignment['device_id'] + '-web',
                'status': 'offline' if state['revoked'] and not state['active'] else 'online'}]}).encode()

    monkeypatch.setattr(combined.urllib.request, 'build_opener', lambda *_: SimpleNamespace(open=lambda *_args, **_kwargs: Response()))
    pressure = {'synthetic_revoked_rows': 99000, 'synthetic_rotation_floors': 99000,
                'global_revoked_rows': 99010, 'global_rotation_floors': 99000, 'tenants': 1}

    def sql(query, **kwargs):
        if query.startswith('WITH changed AS'):
            assert state['active'] and kwargs == {'timeout': 1}
            state['mutations'] += 1
            state['revoked'] = True
            if failure == 'unconfirmed_commit':
                raise TimeoutError('Unconfirmed one-way commit')
            if failure == 'late_observation':
                clock.value += 5.000001
            return '1'
        if 'json_build_object' in query:
            return json.dumps(dict(pressure, global_revoked_rows=pressure['global_revoked_rows'] + int(state['revoked'])))
        if 'jsonb_build_array' in query:
            return 'same-private-identity'
        if query.startswith('SELECT source_ip'):
            return 'same-private-grant'
        assert query.startswith('SELECT count(*) FROM device_access_grants')
        return '1'

    def stop(client):
        assert client is target_client
        state['target_stops'] += 1

    def fresh(target, index):
        assert target == assignment and index == 30
        state['fresh_refusals'] += 1

    arguments = (stage, compose, references, pressure,
        lambda: (assignment, configs[13].with_suffix('.log'), target_client), stop,
        lambda *_: SimpleNamespace(returncode=int(state['revoked']), stdout=b'combined-target.router.example.com'),
        '127.0.0.1', '172.18.0.1', sql, fresh, lambda: None)
    return arguments, state, stage / 'combined-fault-test/result-private.json'


class CombinedObservationTests(unittest.TestCase):
    def scenario(self, stack, failure=None):
        directory = stack.enter_context(tempfile.TemporaryDirectory())
        patches = SimpleNamespace(setattr=lambda obj, name, value: stack.enter_context(patch.object(obj, name, value)))
        return fixture(Path(directory), patches, failure)

    def test_combined_clock_requires_observed_loss_and_one_commit(self):
        with ExitStack() as stack:
            arguments, state, report = self.scenario(stack)
            output = io.StringIO()
            with redirect_stdout(output):
                combined._exercise_combined_fault(*arguments)
            result = json.loads(report.read_text())
            self.assertTrue(result['passed'] and result['owned_rules_restored'])
            self.assertEqual((state['mutations'], state['target_stops'], state['fresh_refusals']), (1, 1, 1))
            self.assertLessEqual(result['SQL_dispatch_to_fresh_TLS_refusal_ms'], 5000)
            self.assertGreaterEqual(result['minimum_reference_Pongs_during_fault_and_denial_observation'], 20)
            self.assertFalse(result['public_native_large_fleet_or_full_W5_acceptance'])
            self.assertNotIn('private-test-value', output.getvalue())
            for key, value in [('private', 'must-not-be-exported'), ('owned_rules_restored', False),
                    ('SQL_dispatch_to_fresh_TLS_refusal_ms', 5001), ('identity_fields_sha256', True),
                    ('packet_loss_dispatch_to_restored_ms', 1801), ('no_reconnect_observation_ms', 29999),
                    ('public_native_large_fleet_or_full_W5_acceptance', True)]:
                changed = copy.deepcopy(result)
                changed[key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    combined.validate_result(changed)
            changed = copy.deepcopy(result)
            changed['snapshot_pressure']['private'] = 'must-not-be-exported'
            with self.assertRaises(ValueError):
                combined.validate_result(changed)

    def failed_case(self, failure):
        with ExitStack() as stack:
            arguments, state, report = self.scenario(stack, failure)
            with self.assertRaises((TimeoutError, ValueError)):
                combined._exercise_combined_fault(*arguments)
            result = json.loads(report.read_text())
            self.assertFalse(result['passed'])
            self.assertTrue(result['owned_rules_restored'])
            self.assertEqual(state['mutations'], 1)
            self.assertEqual(state['target_stops'], 1)
            self.assertEqual(state['fresh_refusals'], 0)
            self.assertFalse(state['active'])

    def test_unconfirmed_commit_is_never_replayed(self):
        self.failed_case('unconfirmed_commit')

    def test_late_observation_is_not_promoted(self):
        self.failed_case('late_observation')


if __name__ == '__main__':
    unittest.main()
