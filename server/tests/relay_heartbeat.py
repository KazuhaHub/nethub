"""Measure real control-session loss and recovery with the pinned official clients."""
import base64
import json
import re
import socket
from pathlib import Path
import subprocess
import time
import urllib.request
import uuid


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise RuntimeError('unexpected private frps admin redirect')


def exercise_heartbeats(stage, compose, assignments, clients, gateway, sql,
                        check_tunnels, probe, source, hook_events, revocation_client):
    work = Path(stage) / 'heartbeat-test'
    work.mkdir(mode=0o700)
    secrets = Path(stage) / 'deployment/secrets/frps'
    credentials = ((secrets / 'frps_admin_user').read_text().strip() + ':' +
                   (secrets / 'frps_admin_password').read_text().strip()).encode()
    authorization = 'Basic ' + base64.b64encode(credentials).decode()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    expected = {'nethub-' + str(uuid.UUID(item['device_id'])) + '-web' for item in assignments}

    def online():
        request = urllib.request.Request('http://' + gateway + ':7500/api/proxy/https',
                                         headers={'Authorization': authorization, 'Accept': 'application/json'})
        with opener.open(request, timeout=2) as response:
            raw = response.read(1048577)
            assert len(raw) <= 1048576 and response.status == 200
            value = json.loads(raw)
        rows = value.get('proxies') or []
        assert isinstance(rows, list)
        return {row['name'] for row in rows if row['name'] in expected and row.get('status') == 'online'}

    def wait_online(wanted, deadline, observe=None):
        while True:
            active = online()
            if observe is not None:
                observe(active, active == wanted)
            if active == wanted:
                if time.monotonic() > deadline:
                    raise RuntimeError('official control-session state was observed after its deadline')
                return
            if time.monotonic() >= deadline:
                raise RuntimeError('official control-session state exceeded the heartbeat deadline')
            time.sleep(0.1)

    def command(arguments, label):
        result = subprocess.run(compose + arguments, capture_output=True, timeout=20)
        (work / (label + '.log')).write_bytes(result.stdout + result.stderr)
        assert result.returncode == 0, 'isolated authz lifecycle command failed'

    def control_sockets():
        result = subprocess.run(['ss', '-tnpeH'], capture_output=True, text=True, timeout=3)
        assert result.returncode == 0, 'isolated control socket inventory failed'
        peers = set()
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 6 and fields[0] == 'ESTAB' and fields[4].endswith(':7000') and any(
                    re.search(r'pid=' + str(client.pid) + r'[,)]', line) for client in clients):
                inode = re.search(r'\bino:([0-9]+)\b', line)
                assert inode is not None, 'original control socket identity unavailable'
                peers.add((fields[3], fields[4], inode[1]))
        return peers

    def diagnose_outage(original, started):
        # Keep the failed 45s gate failed. Additional samples explain whether
        # original sockets or only frps proxy cleanup outlive that gate.
        samples = []
        deadline = time.monotonic() + 20
        while True:
            current = control_sockets()
            active = online()
            samples.append({'elapsed_ms': round((time.monotonic() - started) * 1000),
                            'original_established_sockets': len(original & current),
                            'current_established_sockets': len(current), 'online_proxy_count': len(active)})
            if not active or time.monotonic() >= deadline:
                break
            time.sleep(0.5)
        log_counts = []
        for index in range(len(clients)):
            raw = (Path(stage) / 'relay-test' / ('client' + str(index) + '.log')).read_text()
            log_counts.append({'heartbeat_timeout': raw.count('heartbeat timeout'),
                               'pong_error': raw.count('pong message contains error')})
        result = {'failed_sampling_deadline_seconds': 45, 'samples': samples,
                  'original_established_socket_count': len(original), 'client_event_counts': log_counts,
                  'diagnostic_only_not_acceptance': True}
        (work / 'outage-deadline-diagnostic.json').write_text(json.dumps(result, indent=2))
        print(json.dumps({'heartbeat_outage_deadline_diagnostic': result}), flush=True)

    wait_online(expected, time.monotonic() + 10)
    original_sockets = control_sockets()
    assert len(original_sockets) >= len(clients), 'original control sockets were not bound to official client PIDs'
    identity = subprocess.run(compose + ['ps', '--quiet', 'nethub-authz'], capture_output=True, text=True, timeout=10)
    container_id = identity.stdout.strip()
    assert identity.returncode == 0 and re.fullmatch('[a-f0-9]{64}', container_id)
    outage_samples = []
    stopped = False
    try:
        started = time.monotonic()
        command(['stop', '--timeout', '3', 'nethub-authz'], 'authz-stop')
        stopped = True
        stop_completed = time.monotonic()
        stop_command_ms = round((stop_completed - started) * 1000)
        inspected = subprocess.run(['docker', 'inspect', '--format', '{{json .State}}', container_id], capture_output=True, timeout=5)
        assert inspected.returncode == 0
        stopped_state = json.loads(inspected.stdout)
        assert stopped_state['Running'] is False and stopped_state['OOMKilled'] is False
        (work / 'authz-stopped-state.json').write_bytes(inspected.stdout)
        callback_probe_started = time.monotonic()
        try:
            with socket.create_connection(('127.0.0.1', 9000), timeout=1):
                raise AssertionError('stopped authz still accepts loopback callbacks')
        except ConnectionRefusedError:
            callback_refusal_ms = round((time.monotonic() - callback_probe_started) * 1000)
        def observe_outage(active, final):
            elapsed = round((time.monotonic() - started) * 1000)
            if final or not outage_samples or elapsed - outage_samples[-1]['elapsed_ms'] >= 1000:
                outage_samples.append({'elapsed_ms': elapsed,
                    'original_established_sockets': len(original_sockets & control_sockets()),
                    'online_proxy_count': len(active)})
        # TLS failure alone cannot prove this: NewUserConn also depends on authz.
        # Query frps directly to observe removal of both actual proxy sessions.
        try:
            # Bound observation after Docker confirms stop; retain dispatch-to-loss
            # and command overhead separately instead of subtracting them away.
            wait_online(set(), stop_completed + 45, observe_outage)
        except RuntimeError:
            diagnose_outage(original_sockets, started)
            raise
        outage_ms = round((time.monotonic() - started) * 1000)
        after_stop_ms = round((time.monotonic() - stop_completed) * 1000)
        original_sockets_gone_ms = next((sample['elapsed_ms'] for sample in outage_samples if sample['original_established_sockets'] == 0), None)
        assert original_sockets_gone_ms is not None
        (work / 'outage-samples.json').write_text(json.dumps(outage_samples, indent=2))
        assert all(client.poll() is None for client in clients)
    finally:
        if stopped:
            command(['start', 'nethub-authz'], 'authz-start')
    started = time.monotonic()
    check_tunnels()
    wait_online(expected, time.monotonic() + 10)
    recovery_ms = round((time.monotonic() - started) * 1000)
    assert all(client.poll() is None for client in clients)
    print(json.dumps({'official_frp_authz_outage': {
        'authz_stop_command_ms': stop_command_ms, 'authz_stop_exit_code': stopped_state['ExitCode'],
        'stopped_authz_loopback_callback_refused_ms': callback_refusal_ms,
        'authz_outage_original_sockets_gone_ms': original_sockets_gone_ms,
        'authz_outage_controls_offline_ms': outage_ms,
        'authz_outage_after_confirmed_stop_ms': after_stop_ms,
        'authz_restart_recovery_ms': recovery_ms}}), flush=True)

    # A stopped listener refuses callbacks quickly. Freeze the owned process as
    # a separate case: a connected HTTP hook can hang without returning a Pong.
    freeze_original = control_sockets()
    assert len(freeze_original) == len(clients), 'original multiplexed controls required before authz freeze'
    freeze_samples = []
    frozen = False
    freeze_started = time.monotonic()
    try:
        command(['pause', 'nethub-authz'], 'authz-pause')
        frozen = True
        while True:
            remaining = len(freeze_original & control_sockets())
            elapsed = time.monotonic() - freeze_started
            freeze_samples.append({'elapsed_ms': round(elapsed * 1000), 'original_controls': remaining})
            assert elapsed <= 5, 'original controls survived the five-second frozen-hook deadline'
            if remaining == 0:
                break
            time.sleep(0.1)
        freeze_gone_ms = round(elapsed * 1000)
        # Proxy labels may lag while the callback is frozen. Report them rather
        # than substituting their state for observed original TCP closure.
        frozen_labels_online = len(online())
        assert all(client.poll() is None for client in clients)
    finally:
        (work / 'frozen-authz-samples.json').write_text(json.dumps(freeze_samples, indent=2))
        if frozen:
            command(['unpause', 'nethub-authz'], 'authz-unpause')
    resumed = time.monotonic()
    check_tunnels()
    wait_online(expected, resumed + 20)
    freeze_recovery_ms = round((time.monotonic() - resumed) * 1000)
    assert all(client.poll() is None for client in clients)
    # Live controls can recover before Docker's scheduled health probe catches
    # up. The next host operation independently requires a healthy authz binding.
    # Observe that restoration without restarting or changing the cutoff clock.
    health_samples = []
    while True:
        status = subprocess.run(compose + ['ps', '--all', '--format', 'json', 'nethub-authz'],
                                capture_output=True, timeout=3)
        assert status.returncode == 0 and len(status.stdout) <= 65536
        rows = json.loads(status.stdout)
        if isinstance(rows, dict):
            rows = [rows]
        assert isinstance(rows, list) and len(rows) == 1
        healthy = rows[0].get('Health') == 'healthy'
        health_elapsed = time.monotonic() - resumed
        health_samples.append({'elapsed_ms': round(health_elapsed * 1000), 'healthy': healthy})
        assert health_elapsed <= 30, 'authz did not regain runtime-binding health after unpause'
        if healthy:
            break
        time.sleep(0.2)
    (work / 'frozen-authz-health-recovery.json').write_text(json.dumps(health_samples, indent=2))
    freeze_health_ms = round(health_elapsed * 1000)
    print(json.dumps({'official_frp_authz_freeze': {
        'clock_start': 'owned compose pause dispatch', 'original_controls_gone_ms': freeze_gone_ms,
        'deadline_ms': 5000, 'proxy_labels_still_online_after_original_TCP_loss': frozen_labels_online,
        'same_clients_recovered_after_unpause_ms': freeze_recovery_ms,
        'runtime_binding_health_after_unpause_ms': freeze_health_ms,
        'revoked_device_or_public_network_acceptance': False}}), flush=True)

    # Later authority tests retain the original two enrollments. Revocation is
    # irreversible: create a separate authenticated identity for this control.
    target = revocation_client()
    target_name = 'nethub-' + target['device_id'] + '-web'
    expected.add(target_name)
    wait_online(expected, time.monotonic() + 15)
    deadline = time.monotonic() + 10
    while True:
        ready = probe(target, source)
        if ready.returncode == 0 and ready.stdout.decode() == target['subdomain'] + '.router.example.com':
            break
        assert time.monotonic() < deadline, 'dedicated revocation client never completed verified TLS'
        time.sleep(0.1)
    before = hook_events('before-revoked-heartbeat')
    prior_ping = sum(event.get('operation') == 'Ping' and event.get('decision') == 'device_denied' for event in before)
    prior_login = sum(event.get('operation') == 'Login' and event.get('decision') == 'device_denied' for event in before)
    device = str(uuid.UUID(target['device_id']))
    survivor_sockets = control_sockets()
    assert len(survivor_sockets) == len(clients), 'one original multiplexed control per survivor required'
    started = time.monotonic()
    survivor_samples = []

    def observe_survivors(_active=None, _complete=False):
        original = len(survivor_sockets & control_sockets())
        survivor_samples.append({'elapsed_ms': round((time.monotonic() - started) * 1000),
                                 'original_survivor_controls': original})
        assert original == len(clients), 'revocation interrupted an unrelated original control'

    sql("UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id='" + device + "';")
    wait_online(expected - {target_name}, started + 5, observe_survivors)
    revoked_ms = round((time.monotonic() - started) * 1000)
    deadline = time.monotonic() + 20
    while True:
        observe_survivors()
        events = hook_events('after-revoked-heartbeat')
        pings = sum(event.get('operation') == 'Ping' and event.get('decision') == 'device_denied' for event in events)
        logins = sum(event.get('operation') == 'Login' and event.get('decision') == 'device_denied' for event in events)
        if pings > prior_ping and logins > prior_login:
            break
        if time.monotonic() >= deadline:
            raise RuntimeError('revoked control session lacked actual Ping and reconnect Login denials')
        time.sleep(0.2)
    assert probe(target, source).returncode != 0
    survivor = probe(assignments[1], source)
    assert survivor.returncode == 0 and survivor.stdout.decode() == assignments[1]['subdomain'] + '.router.example.com'
    assert online() == expected - {target_name}
    check_tunnels()
    observe_survivors()
    (work / 'revocation-survivor-samples.json').write_text(json.dumps(survivor_samples, indent=2))
    result = {'heartbeat_interval_seconds': 1, 'heartbeat_timeout_seconds': 3,
              'revocation_deadline_ms': 5000, 'revocation_measurement_start': 'SQL update dispatch',
              'console_dispatch_or_public_mobile_deadline_accepted': False,
              'control_state_probe_timeout_seconds': 2,
              'authz_outage_controls_offline_ms': outage_ms, 'authz_restart_recovery_ms': recovery_ms,
              'authz_stop_command_ms': stop_command_ms, 'authz_stop_exit_code': stopped_state['ExitCode'],
              'stopped_authz_loopback_callback_refused_ms': callback_refusal_ms,
              'authz_outage_after_confirmed_stop_ms': after_stop_ms,
              'authz_outage_original_sockets_gone_ms': original_sockets_gone_ms,
              'frozen_authz_original_controls_gone_ms': freeze_gone_ms,
              'frozen_authz_proxy_labels_still_online_after_TCP_loss': frozen_labels_online,
              'same_clients_recovered_after_unpause_ms': freeze_recovery_ms,
              'frozen_authz_runtime_binding_health_recovery_ms': freeze_health_ms,
              'revoked_control_offline_ms': revoked_ms, 'unrevoked_control_and_verified_TLS_preserved': True,
              'unrevoked_original_control_sockets_preserved': True,
              'original_survivor_control_count': len(survivor_sockets),
              'actual_Ping_and_fresh_Login_denials': True, 'passed': True}
    (work / 'result.json').write_text(json.dumps(result, indent=2))
    print(json.dumps({'official_frp_heartbeat_controls': result}))
    print('Official frps heartbeat passed two control-session losses on authz outage, automatic recovery, cached revocation Ping refusal, fresh Login refusal and unaffected verified TLS')
