"""Measure real control-session loss and recovery with the pinned official clients."""
import base64
import json
import re
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

    def wait_online(wanted, deadline):
        while True:
            if online() == wanted:
                return
            if time.monotonic() >= deadline:
                raise RuntimeError('official control-session state exceeded the heartbeat deadline')
            time.sleep(0.1)

    def command(arguments, label):
        result = subprocess.run(compose + arguments, capture_output=True, timeout=20)
        (work / (label + '.log')).write_bytes(result.stdout + result.stderr)
        assert result.returncode == 0, 'isolated authz lifecycle command failed'

    def control_sockets():
        result = subprocess.run(['ss', '-tnpH'], capture_output=True, text=True, timeout=3)
        assert result.returncode == 0, 'isolated control socket inventory failed'
        peers = set()
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 6 and fields[0] == 'ESTAB' and fields[4].endswith(':7000') and any(
                    re.search(r'pid=' + str(client.pid) + r'[,)]', line) for client in clients):
                peers.add((fields[3], fields[4]))
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
    stopped = False
    try:
        started = time.monotonic()
        command(['stop', '--timeout', '3', 'nethub-authz'], 'authz-stop')
        stopped = True
        # TLS failure alone cannot prove this: NewUserConn also depends on authz.
        # Query frps directly to observe removal of both actual proxy sessions.
        try:
            wait_online(set(), started + 45)
        except RuntimeError:
            diagnose_outage(original_sockets, started)
            raise
        outage_ms = round((time.monotonic() - started) * 1000)
        assert all(client.poll() is None for client in clients)
    finally:
        if stopped:
            command(['start', 'nethub-authz'], 'authz-start')
    started = time.monotonic()
    check_tunnels()
    wait_online(expected, time.monotonic() + 10)
    recovery_ms = round((time.monotonic() - started) * 1000)
    assert all(client.poll() is None for client in clients)

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
    started = time.monotonic()
    sql("UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id='" + device + "';")
    wait_online(expected - {target_name}, started + 48)
    revoked_ms = round((time.monotonic() - started) * 1000)
    deadline = time.monotonic() + 20
    while True:
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
    result = {'heartbeat_interval_seconds': 10, 'heartbeat_timeout_seconds': 30,
              'control_state_probe_timeout_seconds': 2,
              'authz_outage_controls_offline_ms': outage_ms, 'authz_restart_recovery_ms': recovery_ms,
              'revoked_control_offline_ms': revoked_ms, 'unrevoked_control_and_verified_TLS_preserved': True,
              'actual_Ping_and_fresh_Login_denials': True, 'passed': True}
    (work / 'result.json').write_text(json.dumps(result, indent=2))
    print(json.dumps({'official_frp_heartbeat_controls': result}))
    print('Official frps heartbeat passed two control-session losses on authz outage, automatic recovery, cached revocation Ping refusal, fresh Login refusal and unaffected verified TLS')
