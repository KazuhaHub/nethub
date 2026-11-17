"""Bracket real memory-denial publication without adding a product test endpoint."""
import base64
import hashlib
import json
import math
from pathlib import Path
import subprocess
import threading
import time
import urllib.request
import uuid

from relay_heartbeat import NoRedirect
from relay_migration import control_bindings


def cutoff_ms(started, observed):
    if (any(type(value) not in (int, float) or not math.isfinite(value) for value in (started, observed))
            or not 0 < started <= observed or observed - started > 5):
        raise ValueError('actual observation exceeded the five-second cutoff deadline')
    return round((observed - started) * 1000)


def ping_decision(status, raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate callback response key')
            result[key] = value
        return result

    if status != 200 or not isinstance(raw, bytes) or not 0 < len(raw) <= 1024:
        raise ValueError('bounded successful callback response required')
    value = json.loads(raw, object_pairs_hook=unique)
    if type(value) is not dict:
        raise ValueError('callback object required')
    if set(value) == {'reject', 'unchange'} and value['reject'] is False and value['unchange'] is True:
        return 'allowed'
    if set(value) == {'reject', 'reject_reason'} and value['reject'] is True and value['reject_reason'] == 'not_authorized':
        return 'denied'
    raise ValueError('unavailable or unexpected callback cannot anchor cache publication')


def publication_bracket(last_allowed, first_denied):
    for row in (last_allowed, first_denied):
        if (not isinstance(row, dict) or set(row) != {'started', 'finished', 'decision'}
                or any(type(row[key]) not in (int, float) for key in ('started', 'finished'))
                or not 0 < row['started'] <= row['finished']):
            raise ValueError('complete monotonic callback observation required')
    if (last_allowed['decision'] != 'allowed' or first_denied['decision'] != 'denied'
            or first_denied['started'] < last_allowed['finished']):
        raise ValueError('ordered allow-to-deny transition required')
    width = first_denied['finished'] - last_allowed['started']
    if not 0 < width <= .150:
        raise ValueError('cache publication observation bracket exceeded 150 ms')
    return {'earliest': last_allowed['started'], 'latest': first_denied['finished'],
            'uncertainty_ms': round(width * 1000, 3)}


def exercise_cache_phases(stage, assignments, clients, fresh_pair, start_client,
                          stop_client, backend_port, check_tunnels, sql, probe, source, gateway,
                          fresh_revoked_login):
    work = Path(stage) / 'cache-phase-test'
    work.mkdir(mode=0o700)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    secrets = Path(stage) / 'deployment/secrets/frps'
    credentials = ((secrets / 'frps_admin_user').read_text().strip() + ':' +
        (secrets / 'frps_admin_password').read_text().strip()).encode()
    authorization = 'Basic ' + base64.b64encode(credentials).decode()
    rows = []

    def save():
        (work / 'attempts-private.json').write_text(json.dumps(rows, indent=2), encoding='utf-8')

    def ping(assignment):
        body = json.dumps({'version': '0.1.0', 'op': 'Ping', 'content': {'user': {'metas': {
            key: assignment[key] for key in ('device_id', 'domain_claim')}}}}).encode()
        request = urllib.request.Request('http://127.0.0.1:9000/api/v1/frp/hooks?op=Ping&version=0.1.0',
            data=body, headers={'Content-Type': 'application/json'}, method='POST')
        started = time.monotonic()
        with opener.open(request, timeout=.5) as response:
            decision = ping_decision(response.status, response.read(1025))
        return {'started': started, 'finished': time.monotonic(), 'decision': decision}

    def controls(target=None):
        assert all(client.poll() is None for client in clients), 'cache-phase reference client exited'
        result = subprocess.run(['ss', '-tnpeH'], capture_output=True, text=True, timeout=3)
        assert result.returncode == 0
        value = control_bindings(result.stdout, [client.pid for client in clients] +
            ([] if target is None else [target.pid]))
        assert all(value[client.pid] for client in clients), 'cache-phase reference control disappeared'
        return value

    def target_online(assignment):
        request = urllib.request.Request('http://' + gateway + ':7500/api/proxy/https',
            headers={'Authorization': authorization, 'Accept': 'application/json'})
        with opener.open(request, timeout=2) as response:
            raw = response.read(1048577)
            assert response.status == 200 and len(raw) <= 1048576
        value = json.loads(raw)
        assert isinstance(value, dict) and isinstance(value.get('proxies'), list)
        proxies = value['proxies']
        assert len(proxies) <= 1024
        assert all(isinstance(row, dict) and isinstance(row.get('name'), str)
            and row.get('status') in ('online', 'offline') for row in proxies)
        assert len({row['name'] for row in proxies}) == len(proxies)
        name = 'nethub-' + assignment['device_id'] + '-web'
        return any(row['name'] == name and row['status'] == 'online' for row in proxies)

    reference = controls()
    for index, offset in enumerate((0, 200, 400, 600, 800)):
        row = {'round': index, 'offset_after_first_observed_memory_denial_ms': offset,
               'passed': False, 'phase': 'prepare', 'clock_start': 'before SQL update dispatch',
               'deadline_ms': 5000, 'cache_publication_exact_timestamp_measured': False,
               'native_console_public_or_fleet_accepted': False}
        rows.append(row)
        save()
        target_client = None
        try:
            canary, target = fresh_pair(index)
            assert canary['device_id'] != target['device_id']
            identities = ','.join("'" + str(uuid.UUID(item['device_id'])) + "'" for item in (canary, target))
            before = sql("SELECT jsonb_agg(jsonb_build_array(id,tenant_id,subdomain,device_secret_hash,"
                "domain_claim_issued_at) ORDER BY id)::text FROM devices WHERE id IN (" + identities + ");")
            target_client = start_client(target, 'cache-phase-' + str(index), backend_port, debug=True)
            log = Path(stage) / 'relay-test' / ('cache-phase-' + str(index) + '.log')
            deadline = time.monotonic() + 15
            while True:
                ready = probe(target, source)
                if ready.returncode == 0 and ready.stdout.decode() == target['subdomain'] + '.router.example.com':
                    break
                assert time.monotonic() < deadline, 'cache-phase target never completed verified TLS'
                time.sleep(.1)
            assert ping(canary)['decision'] == ping(target)['decision'] == 'allowed'
            assert ping(assignments[1])['decision'] == 'allowed' and controls() == reference
            original_target = controls(target_client)[target_client.pid]
            assert original_target is not None and target_online(target)
            row['phase'] = 'observe_canary_memory_publication'
            save()
            canary_id = str(uuid.UUID(canary['device_id']))
            observations, observation_errors = [], []
            observing, stop_observing = threading.Event(), threading.Event()

            def observe_publication():
                try:
                    until = time.monotonic() + 3
                    while not stop_observing.is_set():
                        observation = ping(canary)
                        observations.append(observation)
                        observing.set()
                        if observation['decision'] == 'denied':
                            return
                        assert time.monotonic() < until, 'canary memory publication not observed within three seconds'
                        stop_observing.wait(.01)
                except Exception as error:
                    observation_errors.append(type(error).__name__)
                    observing.set()

            observer = threading.Thread(target=observe_publication)
            observer.start()
            try:
                assert observing.wait(1) and observations and observations[0]['decision'] == 'allowed'
                # Observe concurrently: SQL command latency must not widen or hide
                # the interval between the actual last allow and first denial.
                assert sql("WITH changed AS (UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id='" +
                    canary_id + "' AND NOT revoked RETURNING id) SELECT count(*) FROM changed;") == '1'
                observer.join(3.6)
                assert not observer.is_alive() and not observation_errors and len(observations) >= 2
                last_allowed, observed = observations[-2:]
                bracket = publication_bracket(last_allowed, observed)
            finally:
                stop_observing.set()
                observer.join(1)
                (work / ('publication-observer-' + str(index) + '-private.json')).write_text(
                    json.dumps({'observations': observations, 'error_types': observation_errors,
                        'observer_stopped': not observer.is_alive()}), encoding='utf-8')
                assert not observer.is_alive(), 'owned publication observer did not stop'
            # Preparation and network failures are never accepted as publication.
            # The exact same signed Ping body was allowed before the one-way SQL
            # mutation; unavailable responses are a separate rejected wire shape.
            row['publication_bracket_uncertainty_ms'] = bracket['uncertainty_ms']
            remaining = observed['finished'] + offset / 1000 - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)
            started = time.monotonic()
            row['observed_memory_denial_to_SQL_dispatch_ms'] = round((started - observed['finished']) * 1000, 3)
            assert offset <= row['observed_memory_denial_to_SQL_dispatch_ms'] < offset + 50, 'cache-phase dispatch missed its preselected offset'
            row['publication_to_SQL_dispatch_interval_ms'] = [
                round((started - bracket['latest']) * 1000, 3),
                round((started - bracket['earliest']) * 1000, 3)]
            row['phase'] = 'SQL_dispatch_and_actual_client_cutoff'
            save()
            target_id = str(uuid.UUID(target['device_id']))
            assert sql("WITH changed AS (UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id='" +
                target_id + "' AND NOT revoked RETURNING id) SELECT count(*) FROM changed;") == '1'
            deadline = started + 5
            while True:
                assert controls() == reference and target_client.poll() is None
                assert log.stat().st_size <= 4 * 1024**2
                if b'pong message contains error: not_authorized' in log.read_bytes():
                    break
                assert time.monotonic() < deadline, 'cache-phase official client did not receive revocation Pong within five seconds'
                time.sleep(.01)
            row['SQL_dispatch_to_actual_Pong_denial_ms'] = cutoff_ms(started, time.monotonic())
            while True:
                observed_controls = controls(target_client)
                assert {client.pid: observed_controls[client.pid] for client in clients} == reference
                if observed_controls[target_client.pid] != original_target and not target_online(target):
                    break
                assert time.monotonic() < deadline, 'cache-phase original control or proxy remained online beyond five seconds'
                time.sleep(.01)
            row['SQL_dispatch_to_proxy_and_original_control_offline_ms'] = cutoff_ms(started, time.monotonic())
            assert probe(target, source).returncode != 0
            row['SQL_dispatch_to_fresh_TLS_refusal_ms'] = cutoff_ms(started, time.monotonic())
            observation_started = time.monotonic()
            # Keep these names separate from the earlier five Pong-phase clients.
            fresh_revoked_login(target, index + 5)
            while True:
                assert target_client.poll() is None, 'revoked original client exited instead of retaining denied retries'
                current = controls(target_client)
                assert {client.pid: current[client.pid] for client in clients} == reference
                assert current[target_client.pid] != original_target and not target_online(target)
                elapsed = time.monotonic() - observation_started
                assert elapsed < 35, 'cache-phase no-reconnect observation exceeded its bound'
                if elapsed >= 30:
                    break
                time.sleep(.2)
            row['no_reconnect_observation_ms'] = round(elapsed * 1000)
            row['fresh_official_Login_refused'] = True
            check_tunnels()
            assert controls() == reference and ping(assignments[1])['decision'] == 'allowed'
            after = sql("SELECT jsonb_agg(jsonb_build_array(id,tenant_id,subdomain,device_secret_hash,"
                "domain_claim_issued_at) ORDER BY id)::text FROM devices WHERE id IN (" + identities + ");")
            assert after == before
            row.update(passed=True, phase='complete', original_reference_controls_retained=True,
                identity_credentials_and_claims_unchanged=True,
                identity_fields_sha256=hashlib.sha256(before.encode()).hexdigest())
        finally:
            if target_client is not None:
                stop_client(target_client)
            save()
    result = {'passed': True, 'samples': rows, 'publication_observed_through_memory_only_Ping': True,
              'exact_publication_timestamp_or_console_public_native_fleet_accepted': False}
    (work / 'result-private.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps({'official_frp_cache_phase': result}), flush=True)
