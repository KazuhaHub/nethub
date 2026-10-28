"""Exercise credential rotation against actual authz, PostgreSQL and official frp."""
import json
from pathlib import Path
import re
import secrets
import subprocess
import time
import uuid


def exercise_rotation(stage, port, assignments, valid_clients, start_client, stop_client,
                      backend_port, source, probe, check_tunnels, hook_events, sql):
    stage = Path(stage)
    work = stage / 'rotation-test'
    work.mkdir(mode=0o700)
    previous = dict(assignments[0])
    device = str(uuid.UUID(previous['device_id']))
    operation = str(uuid.uuid4())
    candidate = secrets.token_urlsafe(32)
    body = {'agent_protocol_version': '1.6.0', 'device_id': device,
            'operation_id': operation, 'replacement_secret': candidate}
    payload = work / 'request.json'
    payload.write_text(json.dumps(body), encoding='utf-8')
    payload.chmod(0o600)

    def request(secret, expected):
        header = work / 'authorization'
        header.write_text('Authorization: Bearer ' + secret + '\n', encoding='utf-8')
        header.chmod(0o600)
        result = subprocess.run(['curl', '--silent', '--noproxy', '*', '--max-time', '10',
                                 '--cacert', str(stage / 'console-ca.pem'),
                                 '--connect-to', f'console.example.com:443:127.0.0.1:{port}',
                                 '-H', '@' + str(header), '-H', 'Content-Type: application/json',
                                 '--data-binary', '@' + str(payload), '--write-out', '\n%{http_code}',
                                 'https://console.example.com/api/v1/devices/rotate'],
                                capture_output=True, timeout=12)
        raw, _, status = result.stdout.rpartition(b'\n')
        assert result.returncode == 0 and status == str(expected).encode(), 'verified rotation HTTP outcome differed'
        value = json.loads(raw)
        if expected != 200:
            assert candidate not in raw.decode() and previous['device_secret'] not in raw.decode(), 'rotation error disclosed credentials'
        return value

    identity_query = "SELECT jsonb_build_array(id,tenant_id,owner_user_id,subdomain,gui_public_key,enrolled_at)::text FROM devices WHERE id='" + device + "';"
    identity = sql(identity_query)
    grants_query = "SELECT source_ip::text||expires_at::text FROM device_access_grants WHERE device_id='" + device + "' ORDER BY source_ip;"
    grants = sql(grants_query)
    old_client = valid_clients[0]

    def old_control_sockets():
        result = subprocess.run(['ss', '-tnpH'], capture_output=True, text=True, timeout=3)
        assert result.returncode == 0, 'rotation control socket inventory failed'
        peers = set()
        for line in result.stdout.splitlines():
            fields = line.split()
            if (len(fields) >= 6 and fields[0] == 'ESTAB' and fields[4].endswith(':7000')
                    and re.search(r'pid=' + str(old_client.pid) + r'[,)]', line)):
                peers.add((fields[3], fields[4]))
        return peers

    original_sockets = old_control_sockets()
    assert original_sockets, 'rotation did not bind the original official control socket'
    before = hook_events('before-real-rotation')
    prior_ping = sum(e.get('operation') == 'Ping' and e.get('decision') == 'device_denied' for e in before)
    started = time.monotonic()
    replacement = request(previous['device_secret'], 200)
    assert replacement['device_id'] == device and replacement['subdomain'] == previous['subdomain']
    assert replacement['operation_id'] == operation and replacement['device_secret'] == candidate
    assert replacement['domain_claim'] != previous['domain_claim']
    assert replacement['relay_ca_pem'] == previous['relay_ca_pem']
    (work / 'assignment-private.json').write_text(json.dumps(replacement), encoding='utf-8')
    (work / 'assignment-private.json').chmod(0o600)
    request(previous['device_secret'], 401)
    assert request(candidate, 200) == replacement, 'candidate retry changed a committed assignment'
    assert sql(identity_query) == identity and sql(grants_query) == grants, 'rotation changed identity or source grants'
    assert sql("SELECT count(*) FROM device_rotations WHERE device_id='" + device + "' AND operation_id='" + operation + "';") == '1'
    assert sql("SELECT count(*) FROM audit_log WHERE target_device_id='" + device + "' AND action='device.rotated';") == '1'

    deadline = time.monotonic() + 45
    while True:
        events = hook_events('rotation-cutoff-observation')
        denied_ping = sum(e.get('operation') == 'Ping' and e.get('decision') == 'device_denied' for e in events) > prior_ping
        if denied_ping and not original_sockets.intersection(old_control_sockets()):
            break
        assert time.monotonic() < deadline, 'old official control socket survived rotation heartbeat denial'
        time.sleep(.2)
    cutoff_ms = round((time.monotonic() - started) * 1000)
    # Official frpc retries after an established control fails even when its
    # first-login failure policy exits. Observe the original socket, not its PID.
    assert old_client.poll() is None
    assert probe(previous, source).returncode != 0, 'rotated old route remained reachable'
    stop_client(old_client)
    survivor = probe(assignments[1], source)
    assert survivor.returncode == 0 and survivor.stdout.decode() == assignments[1]['subdomain'] + '.router.example.com', 'rotation affected the other device'

    before = hook_events('before-stale-rotation-login')
    stale = start_client(previous, 'rotation-old-claim', backend_port)
    try:
        assert stale.wait(timeout=10) != 0, 'old rotated claim established a new control'
    except subprocess.TimeoutExpired:
        raise RuntimeError('old rotated claim was not promptly refused') from None
    finally:
        stop_client(stale)
    events = hook_events('after-stale-rotation-login')[len(before):]
    assert any(e.get('operation') == 'Login' and e.get('decision') == 'device_denied' for e in events)
    assert not any(e.get('operation') == 'Login' and e.get('decision') == 'allowed' for e in events)
    restored = time.monotonic()
    new_client = start_client(replacement, 'rotation-new-claim', backend_port)
    valid_clients[0] = new_client
    assignments[0] = replacement
    check_tunnels()
    recovery_ms = round((time.monotonic() - restored) * 1000)
    assert new_client.poll() is None and sql(identity_query) == identity and sql(grants_query) == grants
    result = {'passed': True, 'official_frp': '0.71.1', 'old_control_cutoff_ms': cutoff_ms,
              'replacement_route_recovery_ms': recovery_ms, 'actual_denied_Ping_and_Login': True,
              'candidate_retry_did_not_rotate_again': True, 'device_identity_and_source_grants_preserved': True,
              'other_device_verified_TLS_preserved': True, 'same_assigned_route_verified_TLS_recovered': True,
              'native_appliance_or_public_network_acceptance': False}
    (work / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps({'official_frp_rotation': result}), flush=True)
    print('Actual HTTPS device rotation passed candidate recovery, old official control Ping cutoff and fresh Login refusal, stable identity/grants and same-route verified TLS recovery')
