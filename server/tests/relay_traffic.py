"""Check actual pinned frps counters, durable console totals and warning-only access."""
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request
import uuid

from relay_heartbeat import NoRedirect


def exercise_traffic(stage, port, assignments, gateway, curl, check_tunnels, sql):
    stage = Path(stage)
    work = stage / 'traffic-test'
    work.mkdir(mode=0o700)
    secrets = stage / 'deployment/secrets/frps'
    credential = ((secrets / 'frps_admin_user').read_text().strip() + ':' +
                  (secrets / 'frps_admin_password').read_text().strip()).encode()
    authorization = 'Basic ' + base64.b64encode(credential).decode()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    names = {'nethub-' + str(uuid.UUID(item['device_id'])) + '-web': item['device_id'] for item in assignments}
    month = datetime.now(timezone.utc).strftime('%Y-%m')

    def metrics():
        request = urllib.request.Request('http://' + gateway + ':7500/api/proxy/https', headers={'Authorization': authorization})
        with opener.open(request, timeout=2) as response:
            raw = response.read(1048577)
            assert response.status == 200 and len(raw) <= 1048576
        rows = json.loads(raw).get('proxies') or []
        result = {}
        for row in rows:
            if row.get('name') in names:
                incoming, outgoing = row['todayTrafficIn'], row['todayTrafficOut']
                assert type(incoming) is int and type(outgoing) is int and incoming >= 0 and outgoing >= 0
                result[names[row['name']]] = incoming + outgoing
        assert set(result) == set(names.values())
        return result

    def report():
        page = curl('/api/v1/console/traffic?month=' + month, authenticated=True)
        assert page['month'] == month
        assert int(page['in_bytes']) + int(page['out_bytes']) == int(page['total_bytes'])
        return page

    before_metrics, before_report = metrics(), report()
    ids = sorted(str(uuid.UUID(item['device_id'])) for item in assignments)
    predicate = ','.join("'" + value + "'" for value in ids)
    grants_before = sql('SELECT device_id::text||source_ip::text||expires_at::text FROM device_access_grants WHERE device_id IN (' + predicate + ') ORDER BY device_id,source_ip;')
    for assignment in assignments:
        host = assignment['subdomain'] + '.router.example.com'
        result = subprocess.run(['curl', '--silent', '--fail', '--noproxy', '*', '--max-time', '5', '--interface', gateway,
                                 '--cacert', str(stage / 'relay-test/backend-cert.pem'), '--connect-to', f'{host}:443:{gateway}:8443',
                                 f'https://{host}/traffic'], capture_output=True, timeout=7)
        assert result.returncode == 0 and result.stdout == b'x' * 65536, 'actual relay payload transfer failed'
    deadline = time.monotonic() + 20
    while True:
        target = metrics()
        if all(target[key] >= before_metrics[key] + 65536 for key in target):
            break
        assert time.monotonic() < deadline, 'actual frps metrics did not record the payload'
        time.sleep(.25)
    deadline = time.monotonic() + 20
    while True:
        current = report()
        rows = {row['device_id']: row for row in current['items']}
        if all(key in rows and int(rows[key]['total_bytes']) >= target[key] for key in target):
            break
        assert time.monotonic() < deadline, 'actual relay traffic did not reach durable console totals'
        time.sleep(.5)
    assert int(current['total_bytes']) > int(before_report['total_bytes'])
    persisted = sql('SELECT device_id::text||\':\'||(in_bytes+out_bytes)::text FROM relay_traffic_months WHERE device_id IN (' + predicate + ") AND month_start='" + month + "-01'::date ORDER BY device_id;")
    durable = dict(line.split(':') for line in persisted.splitlines())
    assert all(int(durable[key]) >= target[key] for key in target)
    result = curl('/api/v1/console/traffic/settings', {'warning_bytes': '1', 'expected_revision': current['warning_revision']}, authenticated=True, method='PATCH')
    assert result['warning_bytes'] == '1'
    assert report()['warning'] is True
    check_tunnels()
    check_tunnels()
    assert sql('SELECT device_id::text||source_ip::text||expires_at::text FROM device_access_grants WHERE device_id IN (' + predicate + ') ORDER BY device_id,source_ip;') == grants_before
    assert sql('SELECT count(*) FROM devices WHERE id IN (' + predicate + ') AND revoked_at IS NOT NULL;') == '0'
    browser_verified = False
    if os.environ.get('NETHUB_BROWSER_TEST') == '1':
        browser_evidence = os.environ.get('NETHUB_BROWSER_EVIDENCE') or str(work / 'browser')
        Path(browser_evidence).mkdir(mode=0o700, exist_ok=True)
        reply = subprocess.run([os.environ.get('NETHUB_NODE_BINARY', 'node'), str(Path(__file__).resolve().parents[1] / 'web/tests/traffic-deployment.mjs'),
                                str(port), str(stage / 'admin-password'), browser_evidence], capture_output=True, timeout=150)
        (work / 'browser-private.log').write_bytes(reply.stdout + reply.stderr)
        assert reply.returncode == 0, 'deployed traffic console verification failed; private log retained'
        if os.environ.get('NETHUB_BROWSER_EVIDENCE'):
            # The harness runs under sudo; only these reviewed public artifacts
            # return to the invoking runner, never the private browser log.
            uid, gid = int(os.environ.get('SUDO_UID', '0')), int(os.environ.get('SUDO_GID', '0'))
            for name in ('deployed-traffic.png', 'traffic-deployment-results.json'):
                artifact = Path(browser_evidence) / name
                assert artifact.is_file() and not artifact.is_symlink()
                artifact.chmod(0o600)
                os.chown(artifact, uid, gid)
        browser_verified = True
    receipt = {'passed': True, 'official_frp': '0.71.1', 'actual_transferred_payload_bytes_per_device': 65536,
               'devices': len(assignments), 'durable_monthly_totals_verified': True,
               'warning_did_not_change_grants_or_revoke': True, 'new_verified_TLS_connections_succeeded': True,
               'deployed_browser_verified': browser_verified,
               'billing_accuracy_claimed': False, 'public_network_or_native_appliance_claimed': False}
    (work / 'results.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    print('Actual frp 0.71.1 payload counters reached durable monthly console totals; exceeded warning preserved grants, devices and new verified TLS connections')
    if browser_verified:
        print('Deployed traffic page passed actual monthly totals and warning under strict CSP')
