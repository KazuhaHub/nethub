"""Drop one owned loopback control's packets without changing other host rules."""
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time
import uuid

from relay_migration import control_bindings


def owned_tuple(binding):
    if not isinstance(binding, tuple) or len(binding) != 3:
        raise ValueError('one established owned control required')
    source, destination, inode = binding
    try:
        src, source_port = source.rsplit(':', 1)
        dst, destination_port = destination.rsplit(':', 1)
        if (ipaddress.ip_address(src) != ipaddress.ip_address('127.0.0.1')
                or ipaddress.ip_address(dst) != ipaddress.ip_address('127.0.0.1')
                or not source_port.isdecimal() or not 1024 <= int(source_port) <= 65535
                or str(int(source_port)) != source_port
                or destination_port != '7000' or source_port == '7000'
                or not re.fullmatch('[1-9][0-9]*', inode)):
            raise ValueError('network fault must target an owned ephemeral loopback tuple')
    except (AttributeError, TypeError) as error:
        raise ValueError('invalid owned control tuple') from error
    return ['-p', 'tcp', '-s', src, '--sport', source_port,
            '-d', dst, '--dport', destination_port]


def drop_counters(raw):
    rows = [line.split() for line in raw.decode('ascii').splitlines() if 'DROP' in line.split()]
    if (len(rows) != 1 or len(rows[0]) < 9 or rows[0][2] != 'DROP'
            or not rows[0][0].isdecimal() or not rows[0][1].isdecimal()):
        raise ValueError('exact owned DROP counter required')
    return {'packets': int(rows[0][0]), 'bytes': int(rows[0][1])}


def exercise_network_blip(stage, compose, clients, check_tunnels):
    assert os.geteuid() == 0 and len(clients) == 2
    work = Path(stage) / 'network-blip-test'
    work.mkdir(mode=0o700)
    iptables = shutil.which('iptables')
    assert iptables, 'iptables required for the isolated owned-control packet-loss test'
    chain = 'nh-blip-' + uuid.uuid4().hex[:12]
    result = {'passed': False, 'phase': 'prepare', 'public_network_or_fleet_acceptance': False}
    create_attempted, interrupted_requested, cleaning = False, False, False

    def record():
        (work / 'result-private.json').write_text(json.dumps(result, indent=2), encoding='utf-8')

    def command(args, name, required=True):
        if interrupted_requested and not cleaning:
            raise SystemExit('owned packet-loss test interrupted')
        value = subprocess.run([iptables, '-w', '2', *args], capture_output=True, timeout=3)
        (work / (name + '.log')).write_bytes(value.stdout + value.stderr)
        if required:
            assert value.returncode == 0, 'owned loopback packet-loss command failed'
        return value

    def controls():
        if interrupted_requested:
            raise SystemExit('owned packet-loss test interrupted')
        assert all(client.poll() is None for client in clients)
        value = subprocess.run(['ss', '-tnpeH'], capture_output=True, text=True, timeout=1)
        assert value.returncode == 0
        bound = control_bindings(value.stdout, [client.pid for client in clients])
        assert all(bound.values())
        return bound

    def service_identity(role):
        identifier = subprocess.check_output(compose + ['ps', '--quiet', role], timeout=3).decode().strip()
        assert re.fullmatch('[a-f0-9]{64}', identifier)
        info = json.loads(subprocess.check_output(['docker', 'inspect', identifier], timeout=3))[0]
        assert info['State']['Running'] and not info['State']['OOMKilled']
        return (identifier, info['Image'], info['State']['Pid'], info['State']['StartedAt'])

    original = controls()
    rule = owned_tuple(original[clients[0].pid]) + ['-j', chain]
    args = Path(f'/proc/{clients[0].pid}/cmdline').read_bytes().rstrip(b'\0').split(b'\0')
    assert len(args) == 3 and args[1] == b'-c'
    assert Path(os.fsdecode(args[0])).resolve() == Path(stage) / 'official/frpc'
    config = Path(os.fsdecode(args[2]))
    assert config.parent == Path(stage) / 'relay-test' and config.resolve() == config and not config.is_symlink()
    settings = json.loads(config.read_bytes())
    assert settings['transport']['heartbeatInterval'] == 1 and settings['transport']['heartbeatTimeout'] == 3
    assert settings['log']['level'] == 'debug'
    log = config.with_suffix('.log')
    assert log.is_file() and not log.is_symlink()
    identities = {role: service_identity(role) for role in ('frps', 'nethub-authz')}
    original_rules = command(['-S', 'OUTPUT'], 'original-output').stdout
    assert command(['-S', chain], 'chain-absent', required=False).returncode == 1
    check_tunnels()
    record()

    def interrupted(_number, _frame):
        nonlocal interrupted_requested
        # Let an in-flight atomic iptables operation finish before inspecting
        # its actual result and removing only this attempt's exact rules.
        interrupted_requested = True

    prior = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        create_attempted = True
        command(['-N', chain], 'create-chain')
        command(['-A', chain, '-j', 'DROP'], 'add-drop')
        assert drop_counters(command(['-nvx', '-L', chain], 'zero-counters').stdout)['packets'] == 0
        assert log.stat().st_size <= 4 * 1024**2
        before_pongs = log.read_bytes().count(b'receive heartbeat from server')
        until = time.monotonic() + 5
        while True:
            anchor_pongs = log.read_bytes().count(b'receive heartbeat from server')
            if anchor_pongs > before_pongs:
                break
            assert controls() == original and time.monotonic() < until
            time.sleep(.01)
        pong_observed = time.monotonic()
        time.sleep(.7)
        result['phase'] = 'drop_one_original_control'
        record()
        assert controls() == original, 'owned control changed before packet-loss dispatch'
        assert log.read_bytes().count(b'receive heartbeat from server') == anchor_pongs, 'selected Pong phase was already superseded'
        started = time.monotonic()
        command(['-I', 'OUTPUT', '1', *rule], 'link-owned-rule')
        while time.monotonic() - started < .65:
            assert controls() == original
            time.sleep(.02)
        counters = drop_counters(command(['-nvx', '-L', chain], 'actual-drop-counters').stdout)
        assert log.read_bytes().count(b'receive heartbeat from server') == anchor_pongs, 'packet loss did not withhold the selected next Pong'
        command(['-D', 'OUTPUT', *rule], 'unlink-owned-rule')
        removed = time.monotonic()
        assert .65 <= removed - started <= 1, 'owned packet loss exceeded its one-second bound'
        assert counters['packets'] > 0 and counters['bytes'] > 0, 'no actual owned control packets were dropped'
        until = removed + 3
        while log.read_bytes().count(b'receive heartbeat from server') <= anchor_pongs:
            assert controls() == original and time.monotonic() < until
            time.sleep(.01)
        recovered = time.monotonic()
        assert 1.25 <= recovered - pong_observed < 3, 'actual successful-Pong delay was outside the selected short-loss case'
        steady_start = time.monotonic()
        offset = log.stat().st_size
        while time.monotonic() - steady_start < 10:
            assert controls() == original
            time.sleep(.1)
        assert log.stat().st_size <= 4 * 1024**2
        recent = log.read_bytes()[offset:]
        assert recent.count(b'receive heartbeat from server') >= 5
        assert b'heartbeat timeout' not in recent and b'pong message contains error' not in recent
        check_tunnels()
        assert controls() == original
        assert {role: service_identity(role) for role in identities} == identities
        result.update(passed=True, phase='complete', dropped=counters,
            clock_start='owned OUTPUT rule installation dispatch',
            dispatch_to_unlink_completed_ms=round((removed-started)*1000),
            observed_successful_Pong_gap_ms=round((recovered-pong_observed)*1000),
            post_recovery_observation_ms=round((time.monotonic()-steady_start)*1000),
            both_original_controls_processes_and_services_retained=True,
            normal_verified_routes_before_and_after=True)
    finally:
        cleaning = True
        try:
            if create_attempted:
                actual = command(['-S', chain], 'cleanup-inspect-chain', required=False)
                assert actual.returncode in (0, 1)
                if actual.returncode == 0:
                    lines = actual.stdout.decode('ascii').splitlines()
                    assert lines and set(lines) <= {'-N ' + chain, '-A ' + chain + ' -j DROP'}
                    link = command(['-C', 'OUTPUT', *rule], 'cleanup-inspect-link', required=False)
                    assert link.returncode in (0, 1)
                    if link.returncode == 0:
                        command(['-D', 'OUTPUT', *rule], 'cleanup-unlink-owned-rule')
                    if '-A ' + chain + ' -j DROP' in lines:
                        command(['-D', chain, '-j', 'DROP'], 'cleanup-remove-drop')
                    command(['-X', chain], 'cleanup-delete-chain')
            assert command(['-S', 'OUTPUT'], 'restored-output').stdout == original_rules
            assert command(['-S', chain], 'removed-chain', required=False).returncode == 1
            result['owned_chain_removed_original_OUTPUT_rules_restored'] = True
        finally:
            for sig, handler in prior.items():
                signal.signal(sig, handler)
            record()
    if interrupted_requested:
        raise SystemExit('owned packet-loss test interrupted after cleanup')
    print(json.dumps({'official_frp_short_packet_loss': result}), flush=True)
