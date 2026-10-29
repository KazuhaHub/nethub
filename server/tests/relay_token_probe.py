"""Prove the pinned Login verifier against official frp without replacing controls."""
import json
import os
from pathlib import Path
import re
import subprocess


def exercise_token_probe(stage, assignments, clients, check_tunnels):
    stage = Path(stage)

    def sockets(client):
        result = subprocess.run(['ss', '-tnpH'], capture_output=True, text=True, timeout=3)
        if result.returncode:
            raise RuntimeError('Token probe original control inventory failed')
        found = set()
        for line in result.stdout.splitlines():
            fields = line.split()
            if (len(fields) >= 6 and fields[0] == 'ESTAB' and fields[4].endswith(':7000')
                    and re.search(r'pid=' + str(client.pid) + r'[,)]', line)):
                found.add((fields[3], fields[4]))
        return found

    if len(assignments) != 2 or len(clients) != 2:
        raise RuntimeError('Two original official clients required for token probe')
    before = [sockets(client) for client in clients]
    if not all(before) or any(client.poll() is not None for client in clients):
        raise RuntimeError('Original official controls unavailable before token probe')
    check_tunnels()
    environment = dict(os.environ, NETHUB_TEST_TOKEN_ASSIGNMENT=str(stage / 'relay-test/assignment0.json'))
    result = subprocess.run([str(stage / 'setup.test'), '-test.v', '-test.run', '^TestNativeRelayTokenProbe$',
                             '-test.timeout=25s'], env=environment, capture_output=True, timeout=30)
    output = result.stdout + result.stderr
    log = stage / 'relay-test/relay-token-probe-private.log'
    log.write_bytes(output)
    log.chmod(0o600)
    for assignment in assignments:
        for key in ('device_secret', 'frp_token', 'domain_claim'):
            if assignment[key].encode('ascii') in output:
                raise RuntimeError('Token probe output disclosed credential material')
    text = output.decode('utf-8')
    if (result.returncode or text.count('--- PASS: TestNativeRelayTokenProbe (') != 1
            or '--- SKIP:' in text or '--- FAIL:' in text or not text.rstrip().endswith('PASS')):
        raise RuntimeError('Actual official token Login admission receipt missing')
    if any(client.poll() is not None or not original.issubset(sockets(client))
           for client, original in zip(clients, before)):
        raise RuntimeError('Token Login probe replaced an original official control')
    check_tunnels()
    outcome = {'passed': True, 'official_frp': '0.71.1', 'valid_token_Login_accepted': True,
               'independent_token_exact_auth_refusal': True, 'valid_token_reaccepted': True,
               'both_original_controls_and_verified_TLS_retained': True,
               'shared_token_replacement_or_fleet_recovery_accepted': False}
    (stage / 'relay-test/relay-token-probe-result.json').write_text(json.dumps(outcome), encoding='utf-8')
    print(json.dumps({'shared_token_login_probe': outcome}), flush=True)
