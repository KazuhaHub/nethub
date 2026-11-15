"""Measure revocation during owned packet loss and a retained bounded fleet load."""
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.request
import uuid

from relay_cache_phase import cutoff_ms
from relay_control_drop import ControlDrop
from relay_heartbeat import NoRedirect
from relay_migration import control_bindings


PRESSURE_FIELDS = ('synthetic_revoked_rows', 'synthetic_rotation_floors',
                   'global_revoked_rows', 'global_rotation_floors', 'tenants')
SEED_FIELDS = ('seed_ms', 'signed_claims_or_enrollments_created', 'retained_until_owned_database_teardown')
FLAGS = ('original_reference_controls_retained', 'fresh_official_Login_refused',
         'identity_and_valid_source_grants_unchanged', 'service_identities_retained',
         'normal_reference_routes_verified', 'owned_rules_restored')
METRICS = ('SQL_dispatch_to_commit_ms', 'SQL_dispatch_to_original_control_and_proxy_offline_ms',
           'SQL_dispatch_to_fresh_TLS_refusal_ms', 'actual_drop_packets', 'actual_drop_bytes',
           'packet_loss_dispatch_to_restored_ms', 'no_reconnect_observation_ms',
           'minimum_reference_Pongs_during_fault_and_denial_observation')


def pressure_baseline(value):
    if (not isinstance(value, dict) or set(value) not in (set(PRESSURE_FIELDS), set(PRESSURE_FIELDS + SEED_FIELDS))
            or any(type(value.get(key)) is not int for key in PRESSURE_FIELDS)
            or value.get('synthetic_revoked_rows') != 99000
            or value.get('synthetic_rotation_floors') != 99000 or type(value.get('tenants')) is not int or value['tenants'] != 1
            or any(type(value.get(key)) is not int or not 99000 <= value[key] <= 100000
                   for key in ('global_revoked_rows', 'global_rotation_floors'))):
        raise ValueError('Actual retained snapshot pressure required')
    if 'seed_ms' in value and (type(value['seed_ms']) is not int or not 0 <= value['seed_ms'] <= 180000
            or value['signed_claims_or_enrollments_created'] is not False
            or value['retained_until_owned_database_teardown'] is not True):
        raise ValueError('Unexpected retained pressure seed receipt')
    return {key: value[key] for key in PRESSURE_FIELDS}


def validate_result(value):
    required = {'version', 'passed', 'phase', 'deadline_ms', 'clock_start', 'genuine_reference_clients',
        'snapshot_pressure', 'public_native_large_fleet_or_full_W5_acceptance'} | set(FLAGS)
    allowed = required | set(METRICS) | {'pressure_immediately_before_fault', 'identity_fields_sha256'}
    if (not isinstance(value, dict) or not required <= set(value) <= allowed
            or type(value['version']) is not int or value['version'] != 1 or type(value['passed']) is not bool
            or value['phase'] not in ('prepare', 'drop_then_revoke_once', 'complete')
            or type(value['deadline_ms']) is not int or value['deadline_ms'] != 5000
            or value['clock_start'] != 'before SQL revocation dispatch while actual control packets are dropping'
            or type(value['genuine_reference_clients']) is not int or value['genuine_reference_clients'] != 12
            or value['public_native_large_fleet_or_full_W5_acceptance'] is not False
            or any(type(value[key]) is not bool for key in FLAGS)
            or any(type(value[key]) is not int or not 0 <= value[key] <= 2**53 for key in METRICS if key in value)):
        raise ValueError('Unexpected closed combined-fault result')
    pressure_baseline(value['snapshot_pressure'])
    if 'pressure_immediately_before_fault' in value:
        pressure_baseline(value['pressure_immediately_before_fault'])
    if 'identity_fields_sha256' in value and (not isinstance(value['identity_fields_sha256'], str)
            or not re.fullmatch('[a-f0-9]{64}', value['identity_fields_sha256'])):
        raise ValueError('Unexpected combined-fault identity fingerprint')
    if value['passed']:
        if (value['phase'] != 'complete' or set(value) != allowed or not all(value[key] for key in FLAGS)
                or not 0 <= value[METRICS[0]] <= value[METRICS[1]] <= value[METRICS[2]] <= 5000
                or not 1250 <= value['packet_loss_dispatch_to_restored_ms'] <= 1800
                or not 30000 <= value['no_reconnect_observation_ms'] <= 35000
                or value['actual_drop_packets'] <= 0 or value['actual_drop_bytes'] <= 0
                or value['minimum_reference_Pongs_during_fault_and_denial_observation'] < 20):
            raise ValueError('Incomplete combined-fault success')
    elif value['phase'] == 'complete':
        raise ValueError('Failed combined-fault observation cannot be complete')


def exercise_combined_fault(stage, compose, references, pressure, create_target, stop_client,
                            probe, source, gateway, sql, fresh_revoked_login, check_tunnels):
    stage = Path(stage)
    project = compose[3] if isinstance(compose, list) and len(compose) > 3 else ''
    expected = ['docker', 'compose', '--project-name', project,
        '--file', str(stage / 'deployment/docker-compose.yml'),
        '--file', str(stage / 'deployment/docker-compose.override.yml'), '--file', str(stage / 'test.yml')]
    if (os.name != 'posix' or os.uname().sysname != 'Linux' or os.geteuid() != 0
            or stage.parent not in (Path('/tmp'), Path('/var/tmp')) or stage.resolve(strict=True) != stage
            or not re.fullmatch('nethub-stack-test-[a-z0-9-]+', project) or compose != expected):
        raise ValueError('Owned isolated Linux Compose fixture required')
    return _exercise_combined_fault(stage, compose, references, pressure, create_target, stop_client,
        probe, source, gateway, sql, fresh_revoked_login, check_tunnels)


def _exercise_combined_fault(stage, compose, references, pressure, create_target, stop_client,
                             probe, source, gateway, sql, fresh_revoked_login, check_tunnels):
    pressure = pressure_baseline(pressure)
    if (len(references) != 12 or any(type(client.pid) is not int or client.pid <= 0 for client in references)
            or len({client.pid for client in references}) != 12):
        raise ValueError('Twelve distinct genuine reference processes required')
    stage = Path(stage)
    if (str(ipaddress.ip_address(source)) != source or str(ipaddress.ip_address(gateway)) != gateway
            or not ipaddress.ip_address(source).is_private or not ipaddress.ip_address(gateway).is_private
            or ipaddress.ip_address(source).version != 4 or ipaddress.ip_address(gateway).version != 4):
        raise ValueError('Exact measured isolated IPv4 sources required')
    work = stage / 'combined-fault-test'
    work.mkdir(mode=0o700)
    result = {'version': 1, 'passed': False, 'phase': 'prepare', 'deadline_ms': 5000,
        'clock_start': 'before SQL revocation dispatch while actual control packets are dropping',
        'genuine_reference_clients': 12, 'snapshot_pressure': pressure,
        'public_native_large_fleet_or_full_W5_acceptance': False}
    result.update({key: False for key in FLAGS})
    target_client, fault = None, None

    def save():
        validate_result(result)
        (work / 'result-private.json').write_text(json.dumps(result, indent=2), encoding='utf-8')

    def controls(target=None):
        if any(client.poll() is not None for client in references):
            raise ValueError('Combined-fault reference client exited')
        raw = subprocess.run(['ss', '-tnpeH'], capture_output=True, text=True, timeout=1)
        if raw.returncode:
            raise ValueError('Combined-fault original control inventory unavailable')
        return control_bindings(raw.stdout, [client.pid for client in references]
            + ([] if target is None else [target.pid]))

    def service(role):
        identifier = subprocess.check_output(compose + ['ps', '--quiet', role], timeout=3).decode().strip()
        if not re.fullmatch('[a-f0-9]{64}', identifier):
            raise ValueError('Owned combined-fault service required')
        value = json.loads(subprocess.check_output(['docker', 'inspect', identifier], timeout=3))[0]
        state = value['State']
        if (not state['Running'] or state['OOMKilled']
                or value['Config']['Labels'].get('com.docker.compose.project') != compose[3]):
            raise ValueError('Combined-fault service stopped')
        return (identifier, value['Image'], state['Pid'], state['StartedAt'])

    original = controls()
    if not all(original.values()):
        raise ValueError('Original combined-fault controls required')
    services = {role: service(role) for role in ('nethub-authz', 'frps', 'postgres', 'nethub-web', 'caddy', 'backup')}
    secrets = stage / 'deployment/secrets/frps'
    credentials = ((secrets / 'frps_admin_user').read_text().strip() + ':'
        + (secrets / 'frps_admin_password').read_text().strip()).encode()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def proxy_online(assignment):
        request = urllib.request.Request('http://' + gateway + ':7500/api/proxy/https',
            headers={'Authorization': 'Basic ' + base64.b64encode(credentials).decode()})
        with opener.open(request, timeout=1) as response:
            raw = response.read(1048577)
            if response.status != 200 or len(raw) > 1048576:
                raise ValueError('Bounded actual proxy state required')
        value = json.loads(raw)
        rows = value.get('proxies')
        if (not isinstance(rows, list) or len(rows) > 1024
                or any(not isinstance(row, dict) or not isinstance(row.get('name'), str)
                    or row.get('status') not in ('online', 'offline') for row in rows)
                or len({row['name'] for row in rows}) != len(rows)):
            raise ValueError('Unambiguous combined-fault proxy state required')
        return any(row['name'] == 'nethub-' + assignment['device_id'] + '-web'
                   and row['status'] == 'online' for row in rows)

    def retained():
        if controls() != original:
            raise ValueError('Combined-fault reference control changed')

    def reference_pongs():
        counts = []
        for client in references:
            raw = Path(f'/proc/{client.pid}/cmdline').read_bytes().rstrip(b'\0').split(b'\0')
            if len(raw) != 3 or raw[1] != b'-c' or Path(raw[0].decode()).resolve() != stage / 'official/frpc':
                raise ValueError('Actual owned reference client required')
            path = Path(raw[2].decode())
            if path.parent != stage / 'relay-test' or path.is_symlink() or path.resolve() != path:
                raise ValueError('Owned reference configuration required')
            settings = json.loads(path.read_bytes())
            if ([settings['transport']['heartbeatInterval'], settings['transport']['heartbeatTimeout']] != [1, 3]
                    or settings['log']['level'] != 'debug'):
                raise ValueError('Current genuine reference heartbeat observations required')
            log = path.with_suffix('.log')
            if not log.is_file() or log.is_symlink() or log.stat().st_size > 4 * 1024**2:
                raise ValueError('Bounded actual reference log required')
            counts.append(log.read_bytes().count(b'receive heartbeat from server'))
        return counts

    save()
    try:
        # Clear the ordinary enrollment rate window without retrying a token or
        # a revocation. The twelve established references stay alive throughout.
        until = time.monotonic() + 61
        while time.monotonic() < until:
            retained()
            time.sleep(.2)
        target, log, target_client = create_target()
        log = Path(log)
        deadline = time.monotonic() + 15
        while True:
            retained()
            ready = probe(target, source)
            if ready.returncode == 0 and ready.stdout.decode() == target['subdomain'] + '.router.example.com':
                break
            if target_client.poll() is not None or time.monotonic() >= deadline:
                raise ValueError('Combined-fault target never served verified TLS')
            time.sleep(.1)
        binding = controls(target_client)[target_client.pid]
        if binding is None or not proxy_online(target):
            raise ValueError('Original target control and proxy required')
        args = Path(f'/proc/{target_client.pid}/cmdline').read_bytes().rstrip(b'\0').split(b'\0')
        if (len(args) != 3 or args[1] != b'-c' or Path(args[0].decode()).resolve() != stage / 'official/frpc'):
            raise ValueError('Only the owned official target may receive packet loss')
        config = Path(args[2].decode())
        if config.parent != stage / 'relay-test' or config.is_symlink() or config.resolve() != config:
            raise ValueError('Owned target configuration required')
        settings = json.loads(config.read_bytes())
        if [settings['transport']['heartbeatInterval'], settings['transport']['heartbeatTimeout']] != [1, 3]:
            raise ValueError('Current heartbeat target profile required')
        device = str(uuid.UUID(target['device_id']))
        identity_query = ("SELECT jsonb_build_array(id,tenant_id,subdomain,device_secret_hash,domain_claim_issued_at)::text "
            "FROM devices WHERE id='" + device + "';")
        grant_query = "SELECT source_ip::text||expires_at::text FROM device_access_grants WHERE device_id='" + device + "' ORDER BY source_ip;"
        identity, grants = sql(identity_query), sql(grant_query)
        if not identity or not grants:
            raise ValueError('Target identity and an explicit valid source grant required')
        active_grant = "SELECT count(*) FROM device_access_grants WHERE device_id='" + device + "' AND source_ip='" + source + "'::inet AND expires_at>clock_timestamp();"
        if sql(active_grant) != '1':
            raise ValueError('The actual TLS source must retain a valid grant')
        pressure_query = ("SELECT json_build_object('synthetic_revoked_rows',(SELECT count(*) FROM devices "
            "WHERE id::text LIKE 'ffffffff-ffff-ffff-ffff-%' AND revoked),"
            "'synthetic_rotation_floors',(SELECT count(DISTINCT r.device_id) FROM device_rotations r "
            "JOIN devices d ON d.tenant_id=r.tenant_id AND d.id=r.device_id WHERE d.id::text LIKE 'ffffffff-ffff-ffff-ffff-%'),"
            "'global_revoked_rows',(SELECT count(*) FROM devices WHERE revoked),"
            "'global_rotation_floors',(SELECT count(DISTINCT (tenant_id,device_id)) FROM device_rotations),"
            "'tenants',(SELECT count(*) FROM tenants));")
        measured_pressure = json.loads(sql(pressure_query))
        pressure_baseline(measured_pressure)
        result['pressure_immediately_before_fault'] = measured_pressure
        pongs_before = reference_pongs()
        result['phase'] = 'drop_then_revoke_once'
        save()
        fault = ControlDrop(binding, work / 'owned-rules')
        with fault:
            loss_started = fault.started
            while True:
                retained()
                dropped = fault.counters()
                if dropped['packets'] > 0 and dropped['bytes'] > 0:
                    break
                if time.monotonic() - loss_started >= 1.1:
                    raise ValueError('No actual target packets dropped before revocation')
                time.sleep(.02)
            if fault.interrupted:
                raise SystemExit('Owned combined-fault fixture interrupted before revocation')
            started = time.monotonic()
            if sql("WITH changed AS (UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id='"
                    + device + "' AND NOT revoked RETURNING id) SELECT count(*) FROM changed;", timeout=1) != '1':
                raise ValueError('Exactly one new target revocation required')
            result['SQL_dispatch_to_commit_ms'] = cutoff_ms(started, time.monotonic())
            while time.monotonic() - loss_started < 1.25:
                retained()
                time.sleep(.02)
            dropped = fault.counters()
        removed = fault.removed
        if not 1.25 <= removed - loss_started <= 1.8:
            raise ValueError('Combined-fault packet loss exceeded its preselected bound')
        result['actual_drop_packets'] = dropped['packets']
        result['actual_drop_bytes'] = dropped['bytes']
        result['packet_loss_dispatch_to_restored_ms'] = round((removed - loss_started) * 1000)
        while True:
            retained()
            target_control = controls(target_client)[target_client.pid]
            if target_control != binding and not proxy_online(target):
                break
            cutoff_ms(started, time.monotonic())
            time.sleep(.01)
        result['SQL_dispatch_to_original_control_and_proxy_offline_ms'] = cutoff_ms(started, time.monotonic())
        if probe(target, source).returncode == 0:
            raise ValueError('Revoked target still served fresh verified TLS')
        result['SQL_dispatch_to_fresh_TLS_refusal_ms'] = cutoff_ms(started, time.monotonic())
        observation = time.monotonic()
        fresh_revoked_login(target, 30)
        while True:
            retained()
            if (target_client.poll() is not None or controls(target_client)[target_client.pid] == binding
                    or proxy_online(target)):
                raise ValueError('Revoked target reconnected or lost its original retry process')
            elapsed = time.monotonic() - observation
            if elapsed > 35:
                raise ValueError('Combined-fault no-reconnect observation exceeded its bound')
            if elapsed >= 30:
                break
            time.sleep(.2)
        result['no_reconnect_observation_ms'] = round(elapsed * 1000)
        if sql(identity_query) != identity or sql(grant_query) != grants or sql(active_grant) != '1':
            raise ValueError('Combined fault changed target identity or its valid source grant')
        if {role: service(role) for role in services} != services:
            raise ValueError('Combined fault replaced a service')
        after_pressure = json.loads(sql(pressure_query))
        pressure_baseline(after_pressure)
        if any(after_pressure[key] != value + (1 if key == 'global_revoked_rows' else 0)
               for key, value in measured_pressure.items()):
            raise ValueError('Combined fault changed unrelated snapshot authority rows')
        pongs_after = reference_pongs()
        if any(after - before < 20 for before, after in zip(pongs_before, pongs_after)):
            raise ValueError('Reference processes lacked genuine Pongs during combined faults')
        result['minimum_reference_Pongs_during_fault_and_denial_observation'] = min(
            after - before for before, after in zip(pongs_before, pongs_after))
        check_tunnels()
        retained()
        if not log.is_file() or log.stat().st_size > 4 * 1024**2:
            raise ValueError('Bounded actual target log required')
        events = log.read_bytes()
        if b'heartbeat timeout' not in events and b'pong message contains error: not_authorized' not in events:
            raise ValueError('Actual official-client cutoff event required')
        result.update(passed=True, phase='complete', original_reference_controls_retained=True,
            fresh_official_Login_refused=True, identity_and_valid_source_grants_unchanged=True,
            service_identities_retained=True, normal_reference_routes_verified=True,
            identity_fields_sha256=hashlib.sha256(identity.encode()).hexdigest())
    finally:
        if target_client is not None:
            stop_client(target_client)
        result['owned_rules_restored'] = fault is not None and fault.restored
        save()
        print(json.dumps({'official_frp_combined_fault': result}), flush=True)
