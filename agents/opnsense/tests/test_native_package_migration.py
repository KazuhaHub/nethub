"""Reject leaked/partial migration reports and unsafe replay after package changes."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


DIRECTORY = Path(__file__).resolve().parents[1] / 'acceptance'
sys.path.insert(0, str(DIRECTORY))
try:
    SPEC = importlib.util.spec_from_file_location('native_package_migration_test', DIRECTORY / 'package_migration.py')
    MIGRATION = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(MIGRATION)
    PROBE = sys.modules['package_probe']
finally:
    sys.path.pop(0)


def hashed(value):
    return hashlib.sha256(value.encode()).hexdigest()


def packages():
    return {'baseline_source': MIGRATION.BASELINE, 'baseline_source_archive_sha256': 'a' * 64,
            'package_sha256': {'0.0.18': 'b' * 64, '0.0.19': 'c' * 64}, 'formal_release': False}


class Clock:
    def __init__(self):
        self.value = 1000

    def monotonic(self):
        self.value += 1
        return self.value

    def sleep(self, amount):
        self.value += amount


class Guest:
    def __init__(self, context, *, lost_install=False, changed_model=False):
        self.context = context
        self.version = '0.0.19'
        self.pid = 123
        self.installations = []
        self.lost_install = lost_install
        self.changed_model = changed_model
        self.model_hash = 'a' * 64
        self.process = SimpleNamespace(poll=lambda: None)
        self.console = SimpleNamespace(command=self.command)

    def put(self, *_args):
        raise AssertionError('Package observations must use the previously staged read-only probe')

    def ensure_ssh(self):
        return False

    def command(self, script, timeout):
        version = next(version for version, path in MIGRATION.GUEST_PACKAGES.items() if path in script)
        assert 'pkg add -f ' in script and packages()['package_sha256'][version] in script
        assert timeout == 180
        self.installations.append(version)
        self.version = version
        self.pid += 1
        if self.changed_model:
            self.model_hash = 'f' * 64
        if self.lost_install:
            raise MIGRATION.GuestError('Simulated unconfirmed package mutation')

    def observation(self):
        result = {key: 'a' * 64 for key in PROBE.HASHES}
        present = self.context['online'] or self.context.get('linger_remaining', 0) > 0
        if not self.context['online'] and self.context.get('linger_remaining', 0) > 0:
            self.context['linger_remaining'] -= 1
        result.update(version=1, package_version=self.version, profile=MIGRATION.PROFILES[self.version],
            markers={name: False for name in PROBE.MARKERS}, running=True, pid=self.pid,
            process_sha256=hashed(str(self.pid)),
            control_sha256=hashed(str(self.pid) + ':' + str(self.context['epoch'])) if present else None,
            model_values_sha256=self.model_hash)
        return result

    def ssh_read_only_inspection(self, script):
        assert script.startswith('/usr/local/bin/python3.13 /root/nethub-ci/package_probe.py ')
        assert script.endswith(' ' + 'a' * 32 + '\n')
        return json.dumps(self.observation()).encode()


def setup(tmp_path, monkeypatch, *, lost_install=False, changed_model=False):
    stage = tmp_path / 'stage'
    config = stage / 'deployment/secrets/frps/frps.toml'
    config.parent.mkdir(parents=True)
    original = b'bindPort = 7000\ntransport.heartbeatTimeout = 3\n'
    config.write_bytes(original)
    evidence = tmp_path / 'evidence'
    evidence.mkdir()
    context = {'online': True, 'epoch': 0, 'calls': []}
    guest = Guest(context, lost_install=lost_install, changed_model=changed_model)
    project = 'nethub-stack-test-unit'
    compose = ['docker', 'compose', '-p', project]
    roles = ['postgres', 'nethub-web', 'nethub-authz', 'caddy', 'backup', 'frps']
    identifiers = {hashed(role): role for role in roles}

    def invoke(args, _label, **_kwargs):
        if args[:4] == compose:
            action = args[4]
            context['calls'].append(action)
            if action == 'ps':
                return hashed(args[-1]).encode()
            if action == 'stop':
                context['online'] = False
                if context['calls'].count('stop') == 2:
                    context['linger_remaining'] = context.get('linger_probes', 0)
            elif action == 'start':
                timeout = 30 if b'heartbeatTimeout = 30' in config.read_bytes() else 3
                assert guest.version != '0.0.18' or timeout == 30, 'old package was started behind a short relay timeout'
                context['online'] = True
                context['epoch'] += 1
            else:
                assert action == 'exec'
            return b''
        assert args[:2] == ['docker', 'inspect']
        role = identifiers[args[2]]
        running = context['online'] if role == 'frps' else True
        epoch = context['epoch'] if role == 'frps' else 0
        return json.dumps([{'Config': {'Labels': {'com.docker.compose.project': project}},
            'Image': 'sha256:' + hashed(role + '-image'),
            'State': {'OOMKilled': False, 'Running': running, 'Pid': 200 + epoch if running else 0,
                      'StartedAt': str(epoch)}}]).encode()

    monkeypatch.setattr(MIGRATION, 'invoke', invoke)
    monkeypatch.setattr(MIGRATION, 'time', Clock())
    monkeypatch.setattr(MIGRATION.os, 'fchmod', lambda *_: None, raising=False)
    monkeypatch.setattr(MIGRATION.os, 'fchown', lambda *_: None, raising=False)
    monkeypatch.setenv('NETHUB_SOURCE_HEAD', 'd' * 40)
    witness = SimpleNamespace(poll=lambda: None)
    arguments = (guest, stage, compose, evidence, 'a' * 32, packages(), lambda _name: {'same': 'assignment'},
        lambda: context['online'], lambda: {'same': 'GUI'}, lambda: None, witness,
        lambda: context['online'], lambda: {('control', context['epoch'])} if context['online'] else set())
    return arguments, context, guest, config, original, evidence


def test_real_phase_engine_preserves_order_and_restores_current_profile(tmp_path, monkeypatch):
    arguments, context, guest, config, original, evidence = setup(tmp_path, monkeypatch)
    result = MIGRATION._exercise(*arguments)
    MIGRATION.validate(result)
    assert result['passed'] is True and guest.installations == ['0.0.18', '0.0.19']
    assert context['online'] is True and config.read_bytes() == original
    assert [row['phase'] for row in result['steps']] == list(MIGRATION.PHASES[:-1])
    assert json.loads((evidence / 'installed-package-migration.json').read_text()) == result


def test_outage_observes_guest_tcp_settlement_without_replaying_mutations(tmp_path, monkeypatch):
    arguments, context, guest, *_ = setup(tmp_path, monkeypatch)
    context['linger_probes'] = 2
    result = MIGRATION._exercise(*arguments)
    assert result['passed'] is True and result['version'] == 3
    outage, legacy = result['outages']
    assert outage['first']['native_control_present'] is True
    assert outage['last']['native_control_present'] is False
    assert outage['last']['elapsed_ms'] > outage['first']['elapsed_ms']
    assert outage['budget_ms'] == 13000 and legacy['budget_ms'] == 40000
    assert guest.installations == ['0.0.18', '0.0.19']
    assert context['calls'].count('stop') == 3


def test_unsettled_outage_fails_before_any_package_installation(tmp_path, monkeypatch):
    arguments, context, guest, config, original, evidence = setup(tmp_path, monkeypatch)
    context['linger_probes'] = 1000
    with pytest.raises(MIGRATION.GuestError, match='observation bound'):
        MIGRATION._exercise(*arguments)
    result = json.loads((evidence / 'installed-package-migration.json').read_text())
    MIGRATION.validate(result)
    assert result['passed'] is False and result['phase'] == 'offline_rollback'
    assert result['outages'][0]['last']['native_control_present'] is True
    assert result['outages'][0]['last']['elapsed_ms'] > result['outages'][0]['budget_ms']
    assert guest.installations == [] and context['online'] is False
    assert config.read_bytes() == original and result['cleanup_stopped_failed_relay'] is True
    assert context['calls'].count('stop') == 3


@pytest.mark.parametrize('failure', ['unconfirmed_install', 'changed_model'])
def test_failed_package_mutation_is_not_replayed_or_restarted_with_short_timeout(tmp_path, monkeypatch, failure):
    arguments, context, guest, config, original, evidence = setup(tmp_path, monkeypatch,
        lost_install=failure == 'unconfirmed_install', changed_model=failure == 'changed_model')
    with pytest.raises(MIGRATION.GuestError):
        MIGRATION._exercise(*arguments)
    result = json.loads((evidence / 'installed-package-migration.json').read_text())
    MIGRATION.validate(result)
    assert result['passed'] is False and result['phase'] == 'rollback'
    assert guest.installations == ['0.0.18'] and context['online'] is False
    assert config.read_bytes() == original and result['cleanup_stopped_failed_relay'] is True


def test_private_model_values_and_inconsistent_process_state_are_not_publishable():
    context = {'online': True, 'epoch': 0}
    valid = Guest(context).observation()
    PROBE.validate(valid)
    for key, value in [('private', 'must-not-be-published'), ('running', False), ('pid', True),
                       ('profile', [True, 3]), ('model_values_sha256', 'not-a-hash')]:
        changed = copy.deepcopy(valid)
        changed[key] = value
        with pytest.raises(ValueError):
            PROBE.validate(changed)


@pytest.mark.parametrize('phase,version', [('rollback', '0.0.18'), ('upgrade', '0.0.19')])
@pytest.mark.parametrize('category', MIGRATION.INVARIANTS)
def test_invariant_diagnosis_is_closed_and_keeps_failed_install_terminal(tmp_path, monkeypatch, phase, version, category):
    arguments, context, guest, config, original, evidence = setup(tmp_path, monkeypatch)
    observation = guest.observation

    def changed():
        return bool(guest.installations) and guest.version == version

    def probe():
        value = observation()
        if changed():
            if category in PROBE.HASHES:
                value[category] = 'f' * 64
            elif category == 'lifecycle_markers':
                value['markers']['stopped'] = True
        return value

    monkeypatch.setattr(guest, 'observation', probe)
    arguments = list(arguments)
    if category == 'gui_readback':
        arguments[8] = lambda: {'private': 'must-not-be-published'} if changed() else {'same': 'GUI'}
    elif category == 'witness_process':
        arguments[10] = SimpleNamespace(poll=lambda: 1 if changed() else None)
    with pytest.raises(MIGRATION.GuestError, match=category) as error:
        MIGRATION._exercise(*arguments)
    raw = (evidence / 'installed-package-migration.json').read_text()
    result = json.loads(raw)
    MIGRATION.validate(result)
    assert result['invariant_failures'] == [category]
    assert result['phase'] == phase and result['passed'] is False
    assert guest.installations == (['0.0.18'] if phase == 'rollback' else ['0.0.18', '0.0.19'])
    assert context['online'] is False and result['cleanup_stopped_failed_relay'] is True
    assert config.read_bytes() == original
    assert 'must-not-be-published' not in raw + str(error.value)
    assert 'f' * 64 not in raw + str(error.value)


def test_report_rejects_missing_rollback_short_windows_and_public_claims(tmp_path, monkeypatch):
    arguments, *_ = setup(tmp_path, monkeypatch)
    valid = MIGRATION._exercise(*arguments)
    cases = []
    for key, value in [('private', 'must-not-be-published'), ('full_W5_acceptance', True),
                       ('original_relay_configuration_restored', False)]:
        changed = copy.deepcopy(valid)
        changed[key] = value
        cases.append(changed)
    for diagnosis in [['model_values_sha256'], ['private-value'], ['gui_readback', 'gui_readback'],
                      ['witness_process', 'gui_readback'], {'private': 'must-not-be-published'}, [None], None]:
        changed = copy.deepcopy(valid)
        changed['invariant_failures'] = diagnosis
        cases.append(changed)
    changed = copy.deepcopy(valid)
    changed['steps'][3]['package_version'] = '0.0.19'
    changed['steps'][3]['profile'] = [1, 3]
    cases.append(changed)
    changed = copy.deepcopy(valid)
    changed['steps'][5]['elapsed_ms'] = 34999
    cases.append(changed)
    changed = copy.deepcopy(valid)
    changed['outages'][0]['first']['source_address'] = 'must-not-be-published'
    cases.append(changed)
    changed = copy.deepcopy(valid)
    changed['outages'][0]['last']['native_control_present'] = True
    cases.append(changed)
    changed = copy.deepcopy(valid)
    changed['outages'][0]['budget_ms'] = 300000
    cases.append(changed)
    changed = copy.deepcopy(valid)
    changed['outages'] = []
    cases.append(changed)
    changed = copy.deepcopy(valid)
    changed['outages'][1]['last']['elapsed_ms'] = 40001
    cases.append(changed)
    for case in cases:
        with pytest.raises(ValueError):
            MIGRATION.validate(case)


def test_unowned_guest_is_refused_before_any_command():
    guest = Guest({'online': True, 'epoch': 0})
    with pytest.raises(MIGRATION.GuestError):
        MIGRATION.prepare(guest, Path('/unrelated'))
    assert guest.installations == []
