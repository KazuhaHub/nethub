"""Observe small genuine frp fleets without inferring a larger capacity limit."""
import json
import os
from pathlib import Path
import re
import subprocess
import time


def exercise_fleet(stage, compose, originals, create_client, stop_client,
                   revoke_clients, check_tunnels, probe, source, seed_pressure):
    work = Path(stage) / 'fleet-test'
    work.mkdir(mode=0o700)
    owned, attempts = [], []
    ticks = os.sysconf('SC_CLK_TCK')
    page_size = os.sysconf('SC_PAGE_SIZE')

    def sockets(clients):
        result = subprocess.run(['ss', '-tnpeH'], capture_output=True, text=True, timeout=3)
        assert result.returncode == 0, 'fleet control inventory unavailable'
        peers = {client.pid: set() for client in clients}
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) < 6 or fields[0] != 'ESTAB' or not fields[4].endswith(':7000'):
                continue
            inode = re.search(r'\bino:([0-9]+)\b', line)
            assert inode is not None, 'fleet TCP inode unavailable'
            for pid, values in peers.items():
                if re.search(r'pid=' + str(pid) + r'[,)]', line):
                    values.add((fields[3], fields[4], inode[1]))
        assert all(len(values) == 1 for values in peers.values()), 'one original multiplexed control per fleet client required'
        return peers

    def process(role):
        result = subprocess.run(compose + ['ps', '--quiet', role], capture_output=True, text=True, timeout=5)
        identifier = result.stdout.strip()
        assert result.returncode == 0 and re.fullmatch('[a-f0-9]{64}', identifier)
        result = subprocess.run(['docker', 'inspect', '--format', '{{.State.Pid}}', identifier],
                                capture_output=True, text=True, timeout=5)
        assert result.returncode == 0 and result.stdout.strip().isdecimal()
        pid = int(result.stdout.strip())
        expected = 'nethub' if role == 'nethub-authz' else 'frps'
        assert Path(f'/proc/{pid}/comm').read_text().strip() == expected, 'actual fleet service process required'
        return pid

    def usage(pid):
        value = Path(f'/proc/{pid}/stat').read_text()
        fields = value[value.rindex(')') + 2:].split()
        assert len(fields) >= 22
        return {'start_ticks': int(fields[19]), 'CPU_ticks': int(fields[11]) + int(fields[12]),
                'resident_bytes': int(fields[21]) * page_size}

    def cgroup(role):
        identifier = subprocess.run(compose + ['ps', '--quiet', role], capture_output=True, text=True, timeout=5)
        assert identifier.returncode == 0 and re.fullmatch('[a-f0-9]{64}', identifier.stdout.strip())
        identifier = identifier.stdout.strip()
        result = subprocess.run(['docker', 'inspect', '--format', '{{.State.Pid}}', identifier],
                                capture_output=True, text=True, timeout=5)
        assert result.returncode == 0 and result.stdout.strip().isdecimal()
        pid = int(result.stdout.strip())
        membership = Path(f'/proc/{pid}/cgroup').read_text().splitlines()
        assert len(membership) == 1, 'one unified container cgroup required'
        hierarchy, controllers, relative = membership[0].split(':', 2)
        assert hierarchy == '0' and controllers == '' and relative.startswith('/'), 'unified container cgroup required'
        assert re.fullmatch(r'/(?:system.slice/docker-' + identifier + r'\.scope|docker/' + identifier + ')', relative), 'dedicated Docker cgroup required'
        root = Path('/sys/fs/cgroup').resolve(strict=True)
        folder = (root / relative.lstrip('/')).resolve(strict=True)
        assert folder.is_relative_to(root) and folder != root
        assert pid in [int(item) for item in (folder / 'cgroup.procs').read_text().split()]
        return folder, folder.stat().st_ino

    def container_usage(binding):
        folder, inode = binding
        assert folder.stat().st_ino == inode, 'original container cgroup replaced'
        raw = (folder / 'cpu.stat').read_text()
        assert len(raw) <= 4096
        values = dict(line.split() for line in raw.splitlines())
        assert values['usage_usec'].isdecimal()
        memory = (folder / 'memory.current').read_text().strip()
        assert memory.isdecimal()
        return {'CPU_us': int(values['usage_usec']), 'memory_bytes': int(memory),
                'sampled_at': time.monotonic()}

    roles = {role: process(role) for role in ('nethub-authz', 'frps')}
    groups = {role: cgroup(role) for role in ('nethub-authz', 'frps', 'postgres')}
    original_controls = sockets(originals)
    retained_controls = original_controls
    try:
        for stage_index, total in enumerate((5, 10, 10)):
            sample = {'passed': False, 'phase': 'preparation', 'dedicated_clients': total,
                      'unrelated_original_clients': len(originals), 'measurement_seconds': 30,
                      'larger_fleet_capacity_accepted': False, 'full_W5_acceptance': False}
            attempts.append(sample)
            try:
                # Use ordinary authenticated enrollment. Clear the five-token
                # minute window once per batch, never retry a failed load case.
                if stage_index < 2:
                    time.sleep(60)
                else:
                    sample['phase'] = 'snapshot_pressure_preparation'
                    sample['snapshot_fixture'] = seed_pressure()
                while len(owned) < total:
                    assignment, log, client = create_client(len(owned))
                    owned.append((assignment, log, client))
                    deadline = time.monotonic() + 15
                    while True:
                        result = probe(assignment, source)
                        if result.returncode == 0 and result.stdout.decode() == assignment['subdomain'] + '.router.example.com':
                            break
                        assert client.poll() is None and time.monotonic() < deadline, 'genuine fleet route did not become available'
                        time.sleep(0.1)
                clients = originals + [entry[2] for entry in owned]
                baseline = sockets(clients)
                assert all(baseline[pid] == values for pid, values in retained_controls.items()), 'batch preparation replaced an original fleet control'
                retained_controls = baseline
                check_tunnels()
                for assignment, _, _ in owned:
                    result = probe(assignment, source)
                    assert result.returncode == 0 and result.stdout.decode() == assignment['subdomain'] + '.router.example.com'
                assert sockets(clients) == baseline, 'fleet TLS preflight replaced an original control'
                before = {role: usage(pid) for role, pid in roles.items()}
                peak = {role: value['resident_bytes'] for role, value in before.items()}
                container_before = {role: container_usage(binding) for role, binding in groups.items()}
                container_peak = {role: value['memory_bytes'] for role, value in container_before.items()}
                counts, initial, observed, gaps = {}, {}, {}, []
                for index, (_, log, _) in enumerate(owned):
                    counts[index] = log.read_bytes().count(b'receive heartbeat from server')
                    initial[index] = counts[index]
                sample['phase'] = 'steady_state'
                started = time.monotonic()
                while time.monotonic() - started < 30:
                    assert all(client.poll() is None for client in clients), 'fleet client exited under bounded load'
                    assert sockets(clients) == baseline, 'fleet control disconnected or reconnected under bounded load'
                    now = time.monotonic()
                    for index, (_, log, _) in enumerate(owned):
                        assert log.stat().st_size <= 4 * 1024**2, 'bounded private fleet log required'
                        raw = log.read_bytes()
                        assert b'pong message contains error' not in raw and b'heartbeat timeout' not in raw
                        count = raw.count(b'receive heartbeat from server')
                        if count > counts[index]:
                            assert count == counts[index] + 1, 'Pong observation missed an interval'
                            if index in observed:
                                gaps.append(now - observed[index])
                            observed[index], counts[index] = now, count
                    for role, pid in roles.items():
                        value = usage(pid)
                        assert value['start_ticks'] == before[role]['start_ticks'], 'fleet service process changed'
                        peak[role] = max(peak[role], value['resident_bytes'])
                    for role, binding in groups.items():
                        value = container_usage(binding)
                        container_peak[role] = max(container_peak[role], value['memory_bytes'])
                    time.sleep(0.2)
                elapsed = time.monotonic() - started
                assert all(counts[index] - initial[index] >= 20 for index in initial), 'insufficient actual successful Pongs per live client'
                assert gaps and max(gaps) < 3, 'successful Pong observation gap reached heartbeat timeout'
                after = {role: usage(pid) for role, pid in roles.items()}
                cpu = {}
                for role in roles:
                    assert after[role]['start_ticks'] == before[role]['start_ticks']
                    used = (after[role]['CPU_ticks'] - before[role]['CPU_ticks']) / ticks
                    assert used >= 0
                    cpu[role] = {'process_CPU_ms': round(used * 1000),
                                 'mean_CPU_cores': round(used / elapsed, 4),
                                 'maximum_observed_resident_bytes': peak[role]}
                containers = {}
                for role, binding in groups.items():
                    value = container_usage(binding)
                    used = value['CPU_us'] - container_before[role]['CPU_us']
                    window = value['sampled_at'] - container_before[role]['sampled_at']
                    assert used >= 0
                    assert window >= 30
                    containers[role] = {'container_CPU_us': used, 'measurement_ms': round(window * 1000),
                                        'mean_CPU_cores': round(used / 1000000 / window, 4),
                                        'maximum_observed_charged_memory_bytes': max(container_peak[role], value['memory_bytes'])}
                check_tunnels()
                for assignment, _, _ in owned:
                    result = probe(assignment, source)
                    assert result.returncode == 0 and result.stdout.decode() == assignment['subdomain'] + '.router.example.com'
                assert sockets(clients) == baseline
                sample.update(passed=True, phase='completed', elapsed_ms=round(elapsed * 1000),
                              successful_dedicated_Pongs=sum(counts[i] - initial[i] for i in initial),
                              minimum_Pongs_per_dedicated_client=min(counts[i] - initial[i] for i in initial),
                              maximum_observed_Pong_gap_ms=round(max(gaps) * 1000),
                              original_controls_retained=len(clients), process_usage=cpu,
                              container_usage=containers,
                              container_scope='dedicated cgroup-v2 tasks and descendants; memory.current includes charged cache; excludes clients and observer',
                              CPU_scope='authz and frps process only; excludes PostgreSQL, clients and observer',
                              Pong_scope='successful pinned-client debug log observations, 200ms requested polling; not HTTP callback latency')
            finally:
                (work / 'attempts.json').write_text(json.dumps(attempts, indent=2))
                key = 'official_frp_snapshot_pressure' if stage_index == 2 else 'official_frp_small_fleet'
                print(json.dumps({key: sample}), flush=True)
    finally:
        for _, _, client in owned:
            stop_client(client)
        # Irreversible cleanup of only identities created by this fixture. The
        # enclosing owned Compose/database teardown remains the final boundary.
        revoke_clients([assignment for assignment, _, _ in owned])
    assert len(attempts) == 3 and all(item['passed'] for item in attempts)
    assert sockets(originals) == original_controls
    check_tunnels()
