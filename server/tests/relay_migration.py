"""Exercise heartbeat configuration rollout and rollback with actual official clients."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import tomllib
import uuid


def require_compatible(timeout, timings):
    if (type(timeout) is not int or timeout not in (3, 30) or not isinstance(timings, (list, tuple))
            or not timings or any(not isinstance(pair, tuple) or len(pair) != 2
                or any(type(v) is not int for v in pair) or pair not in ((1, 3), (10, 30)) for pair in timings)):
        raise ValueError('unsupported migration timing profiles')
    if any(pair[0] >= timeout for pair in timings):
        raise ValueError('relay timeout is incompatible with an old client')


def timeout_config(raw, timeout):
    if type(timeout) is not int or timeout not in (3, 30):
        raise ValueError('unsupported migration timeout')
    parsed = tomllib.loads(raw.decode('utf-8'))
    previous = parsed.get('transport', {}).get('heartbeatTimeout')
    matches = list(re.finditer(rb'(?m)^transport\.heartbeatTimeout[ \t]*=[ \t]*(3|30)[ \t]*\r?$', raw))
    if type(previous) is not int or previous not in (3, 30) or len(matches) != 1:
        raise ValueError('unexpected rendered relay heartbeat configuration')
    match = matches[0]
    replacement = raw[:match.start(1)] + str(timeout).encode() + raw[match.end(1):]
    expected = dict(parsed)
    expected['transport'] = dict(parsed['transport'], heartbeatTimeout=timeout)
    if tomllib.loads(replacement.decode('utf-8')) != expected:
        raise ValueError('migration changed unrelated relay settings')
    return replacement


def control_bindings(raw, pids):
    if (not isinstance(raw, str) or len(raw) > 1024**2 or not isinstance(pids, (list, tuple)) or not pids
            or any(type(pid) is not int or pid <= 0 for pid in pids) or len(set(pids)) != len(pids)):
        raise ValueError('invalid migration control inventory')
    bindings = {pid: [] for pid in pids}
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) < 6 or fields[0] != 'ESTAB' or not fields[4].endswith(':7000'):
            continue
        owners = [pid for pid in pids if re.search(r'pid=' + str(pid) + r'[,)]', line)]
        if not owners:
            continue
        inode = re.search(r'\bino:([0-9]+)\b', line)
        if len(owners) != 1 or inode is None or int(inode[1]) <= 0:
            raise ValueError('ambiguous original migration control')
        bindings[owners[0]].append((fields[3], fields[4], inode[1]))
    if any(len(values) > 1 for values in bindings.values()):
        raise ValueError('multiple established migration controls')
    inodes = [values[0][2] for values in bindings.values() if values]
    if len(set(inodes)) != len(inodes):
        raise ValueError('migration controls share a socket inode')
    return {pid: values[0] if values else None for pid, values in bindings.items()}


def exercise_migration(stage, compose, assignments, clients, start_client, stop_client,
                       backend_port, check_tunnels, sql):
    stage = Path(stage)
    work = stage / 'heartbeat-migration-test'
    work.mkdir(mode=0o700)
    assert len(assignments) == len(clients) == 2
    config = stage / 'deployment/secrets/frps/frps.toml'
    info = config.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not config.is_symlink()
    original = config.read_bytes()
    assert tomllib.loads(original.decode())['transport']['heartbeatTimeout'] == 3
    candidate = config.with_name('frps-migration-candidate.toml')
    assert not candidate.exists() and not candidate.is_symlink()
    attempts, client_logs = [], [None, None]
    outcome = {'passed': False, 'official_frp': '0.71.1', 'native_package_or_public_migration_accepted': False}

    def save(name, value):
        (work / name).write_text(json.dumps(value, indent=2), encoding='utf-8')

    def attempt(phase):
        value = {'phase': phase, 'passed': False}
        attempts.append(value)
        save('attempts-private.json', attempts)
        return value

    def execute(arguments, name, timeout=20):
        result = subprocess.run(arguments, capture_output=True, timeout=timeout)
        (work / (name + '.log')).write_bytes(result.stdout + result.stderr)
        assert result.returncode == 0, 'owned migration command failed'
        return result.stdout

    def service(role):
        identifier = execute(compose + ['ps', '--quiet', role], role + '-identity').decode().strip()
        assert re.fullmatch('[a-f0-9]{64}', identifier)
        value = json.loads(execute(['docker', 'inspect', identifier], role + '-inspect'))[0]
        assert value['State']['Running'] and not value['State']['OOMKilled']
        return {'id': identifier, 'image': value['Image'], 'pid': value['State']['Pid'],
                'started': value['State']['StartedAt']}

    def bindings():
        assert all(client.poll() is None for client in clients), 'migration client exited'
        result = subprocess.run(['ss', '-tnpeH'], capture_output=True, text=True, timeout=3)
        assert result.returncode == 0
        return control_bindings(result.stdout, [client.pid for client in clients])

    def ready():
        check_tunnels()
        deadline = time.monotonic() + 5
        while True:
            observed = bindings()
            if all(observed.values()):
                return observed
            assert time.monotonic() < deadline, 'migration controls not established'
            time.sleep(.1)

    def invariants():
        identifiers = ','.join("'" + str(uuid.UUID(a['device_id'])) + "'" for a in assignments)
        identities = sql("SELECT jsonb_agg(jsonb_build_array(id,tenant_id,owner_user_id,subdomain,"
            "gui_public_key,device_secret_hash,domain_claim_issued_at,enrolled_at) ORDER BY id)::text "
            "FROM devices WHERE id IN (" + identifiers + ");")
        grants = sql("SELECT jsonb_agg(jsonb_build_array(device_id,user_id,source_ip,granted_at,expires_at) "
            "ORDER BY device_id,user_id,source_ip)::text FROM device_access_grants "
            "WHERE device_id IN (" + identifiers + ");")
        return {'identity': hashlib.sha256(identities.encode()).hexdigest(),
                'grants': hashlib.sha256(grants.encode()).hexdigest(),
                'assignments': hashlib.sha256(json.dumps(assignments, sort_keys=True).encode()).hexdigest()}

    authz = service('nethub-authz')
    relay = service('frps')
    binary = stage / 'official/frpc'
    assert execute([str(binary), '--version'], 'official-client-version').strip() == b'0.71.1'
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()

    def client_timing(index):
        args = Path(f'/proc/{clients[index].pid}/cmdline').read_bytes().rstrip(b'\0').split(b'\0')
        assert len(args) == 3 and Path(os.fsdecode(args[0])).resolve() == binary.resolve() and args[1] == b'-c'
        path = Path(os.fsdecode(args[2]))
        assert path.parent == stage / 'relay-test' and path.resolve() == path and not path.is_symlink()
        value = json.loads(path.read_bytes())
        assert value['serverAddr'] == '127.0.0.1' and value['serverPort'] == assignments[index]['server_port']
        assert value['auth']['method'] == 'token'
        assert value['auth']['token'] == assignments[index]['frp_token']
        assert value['metadatas'] == {key: assignments[index][key] for key in ('device_id', 'domain_claim')}
        assert value['transport']['tcpMux'] is True
        assert value['transport']['tls'] == {'enable': True, 'serverName': assignments[index]['server_name'],
            'trustedCaFile': str(stage / 'relay-test/relay-ca.pem')}
        assert value['proxies'] == [{'name': 'nethub-' + assignments[index]['device_id'] + '-web', 'type': 'https',
            'localIP': '127.0.0.1', 'localPort': backend_port, 'subdomain': assignments[index]['subdomain']}]
        return (value['transport']['heartbeatInterval'], value['transport']['heartbeatTimeout'])

    timings = [client_timing(index) for index in range(2)]
    server_timeout = 3
    require_compatible(server_timeout, timings)
    identifiers = ','.join("'" + str(uuid.UUID(a['device_id'])) + "'" for a in assignments)
    remaining = sql("SELECT floor(extract(epoch FROM min(expires_at)-clock_timestamp()))::int "
        "FROM device_access_grants WHERE device_id IN (" + identifiers + ");")
    assert remaining.isdecimal() and int(remaining) >= 600, 'insufficient source-grant window for migration'
    before = invariants()
    save('before-private.json', {'authz': authz, 'relay': relay, 'invariants': before,
        'relay_config_sha256': hashlib.sha256(original).hexdigest()})
    config_changed = False

    def unchanged_config():
        current = config.lstat()
        assert stat.S_ISREG(current.st_mode) and current.st_nlink == 1
        assert (current.st_ino, stat.S_IMODE(current.st_mode), current.st_uid, current.st_gid) == (
            current_inode[0], stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid)
        assert config.read_bytes() == current_config[0], 'relay config changed outside migration'

    def restart_relay(timeout, label):
        nonlocal config_changed, server_timeout
        row = attempt(label)
        require_compatible(timeout, timings)
        previous_bindings = ready()
        previous_relay = service('frps')
        raw = timeout_config(original, timeout)
        assert not candidate.exists() and not candidate.is_symlink()
        with candidate.open('xb') as stream:
            os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))
            os.fchown(stream.fileno(), info.st_uid, info.st_gid)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        execute(compose + ['exec', '-T', 'frps', '/frps', 'verify', '-c',
            '/run/secrets/' + candidate.name], label + '-official-verify')
        unchanged_config()
        os.replace(candidate, config)
        current_inode[0] = config.stat().st_ino
        current_config[0] = raw
        config_changed = raw != original
        pids = [client.pid for client in clients]
        started = time.monotonic()
        execute(compose + ['restart', '--timeout', '3', 'frps'], label + '-restart')
        observed = ready()
        elapsed = round((time.monotonic() - started) * 1000)
        assert elapsed <= 45000 and [client.pid for client in clients] == pids
        now = service('frps')
        assert (now['id'], now['image']) == (relay['id'], relay['image'])
        assert now['started'] != previous_relay['started'], 'relay restart did not replace its process'
        assert all(observed[pid] != previous_bindings[pid] for pid in pids)
        assert service('nethub-authz') == authz
        server_timeout = timeout
        row.update(passed=True, server_timeout_seconds=timeout, dispatch_to_verified_routes_ms=elapsed,
                   clock_start='owned compose restart dispatch',
                   same_client_processes_recovered=True, actual_controls_replaced_after_planned_restart=True)
        save('attempts-private.json', attempts)
        return observed

    def replace_client(index, heartbeat, label):
        row = attempt(label)
        proposed = list(timings)
        proposed[index] = heartbeat
        require_compatible(server_timeout, proposed)
        other = clients[1-index]
        witness = ready()[other.pid]
        started = time.monotonic()
        stop_client(clients[index])
        clients[index] = start_client(assignments[index], label, backend_port, debug=True, heartbeat=heartbeat)
        client_logs[index] = stage / 'relay-test' / (label + '.log')
        assert client_timing(index) == heartbeat
        timings[index] = heartbeat
        observed = ready()
        elapsed = round((time.monotonic() - started) * 1000)
        assert elapsed <= 45000 and observed[other.pid] == witness
        assert invariants() == before and service('nethub-authz') == authz
        row.update(passed=True, heartbeat_interval_seconds=heartbeat[0], heartbeat_timeout_seconds=heartbeat[1],
                   dispatch_to_verified_routes_ms=elapsed, unrelated_original_control_retained=True)
        save('attempts-private.json', attempts)

    def steady(label, seconds, timeout):
        row = attempt(label)
        assert server_timeout == timeout
        require_compatible(server_timeout, timings)
        assert [client_timing(index) for index in range(2)] == timings
        original_bindings = ready()
        offsets = [path.stat().st_size for path in client_logs]
        counts = [0, 0]
        started = time.monotonic()
        while True:
            assert bindings() == original_bindings, 'migration steady control was replaced'
            for index, path in enumerate(client_logs):
                assert path.stat().st_size <= 4 * 1024**2
                raw = path.read_bytes()[offsets[index]:]
                assert b'pong message contains error' not in raw and b'heartbeat timeout' not in raw
                counts[index] = raw.count(b'receive heartbeat from server')
            elapsed = time.monotonic() - started
            if elapsed >= seconds:
                break
            time.sleep(.2)
        assert min(counts) >= 2, 'migration window lacks successful Pongs from both clients'
        check_tunnels()
        assert bindings() == original_bindings and service('nethub-authz') == authz
        assert invariants() == before
        assert [client_timing(index) for index in range(2)] == timings
        unchanged_config()
        row.update(passed=True, observation_ms=round(elapsed * 1000), successful_Pongs=counts,
                   server_timeout_seconds=timeout, client_heartbeat_profiles=list(timings),
                   both_original_controls_retained=True,
                   verified_TLS_routes_before_and_after=True)
        save('attempts-private.json', attempts)

    current_inode = [info.st_ino]
    current_config = [original]
    try:
        restart_relay(30, 'widen-before-legacy-client')
        replace_client(1, (1, 3), 'migration-current-witness')
        replace_client(0, (10, 30), 'migration-legacy-target')
        steady('mixed-before-upgrade', 45, 30)
        replace_client(0, (1, 3), 'migration-upgraded-target')
        steady('upgraded-before-tightening', 10, 30)
        restart_relay(3, 'tighten-after-client-upgrade')
        steady('upgraded-with-short-relay-timeout', 10, 3)
        restart_relay(30, 'widen-before-client-rollback')
        replace_client(0, (10, 30), 'migration-rolled-back-target')
        steady('mixed-after-rollback', 45, 30)
        replace_client(0, (1, 3), 'migration-restored-target')
        restart_relay(3, 'restore-original-relay-timeout')
        steady('restored-original-configuration', 10, 3)
        assert config.read_bytes() == original and invariants() == before
        after_info = config.stat()
        assert (stat.S_IMODE(after_info.st_mode), after_info.st_uid, after_info.st_gid) == (
            stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid)
        assert hashlib.sha256(binary.read_bytes()).hexdigest() == binary_hash
        outcome.update(passed=True, phases=attempts, safe_upgrade_and_rollback_order_verified=True,
            identity_credentials_claims_and_grants_unchanged=True, original_authz_process_retained=True,
            exact_original_relay_config_restored=True, same_pinned_official_binary=True,
            official_client_sha256=binary_hash)
    finally:
        if not outcome['passed']:
            # Failed migration observations are never replayed. Stop these owned
            # clients before restoring the initial config for stack teardown.
            outcome['failed_attempts_retained'] = attempts
            save('failed-attempts-private.json', outcome)
            for client in clients:
                stop_client(client)
            if config_changed:
                unchanged_config()
                if candidate.exists():
                    candidate_info = candidate.lstat()
                    assert stat.S_ISREG(candidate_info.st_mode) and candidate_info.st_nlink == 1
                    candidate.unlink()
                with candidate.open('xb') as stream:
                    os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))
                    os.fchown(stream.fileno(), info.st_uid, info.st_gid)
                    stream.write(original)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(candidate, config)
                execute(compose + ['restart', '--timeout', '3', 'frps'], 'failed-migration-restore')
        if candidate.exists():
            candidate.unlink()
        save('result-private.json', outcome)
    print(json.dumps({'official_frp_heartbeat_migration': outcome}), flush=True)
