"""Recover a real committed native candidate after the public trust head changes."""
import base64
import hashlib
import json
import time

from guest import GuestError
from rotation_recovery import owned_edge_fault


def validate_response(value, before, pending):
    expected = {key: before[key] for key in
                ('device_id', 'frp_token', 'server_addr', 'server_name', 'subdomain')}
    expected.update(operation_id=pending['operation_id'], device_secret=pending['candidate'],
                    server_port=int(before['server_port']),
                    relay_ca_pem=base64.b64decode(before['relay_ca'], validate=True).decode('ascii'))
    if (not isinstance(value, dict) or any(value.get(key) != item for key, item in expected.items())
            or not isinstance(value.get('domain_claim'), str)
            or value['domain_claim'] == before['domain_claim']):
        raise GuestError('Committed replay did not retain its original assignment and trust')


def validate_current_trust(model, desired):
    try:
        public = base64.b64decode(model['relay_ca'], validate=True)
        metadata = json.loads(base64.b64decode(model['relay_trust_state'], validate=True))
        if (public != desired['ca_pem'].encode('ascii')
                or hashlib.sha256(b'nethub-relay-trust-v1:' + public).hexdigest() != desired['bundle_fingerprint']
                or any(metadata[key] != desired[key] for key in
                       ('generation_id', 'generation', 'bundle_fingerprint'))):
            raise ValueError('different trust')
    except (KeyError, ValueError, TypeError, UnicodeError, AttributeError):
        raise GuestError('Committed replay native trust differs from the authenticated head') from None


def prepare(guest, stage, compose, page_action, native_read, read_pending, sql,
            device, stable_query, grants_query):
    before = native_read('native-committed-publication-before.json')
    counts = ("SELECT count(*) FROM device_rotations WHERE device_id='" + device + "';",
              "SELECT count(*) FROM audit_log WHERE action='device.rotated' AND target_device_id='" + device + "';")
    expected = [int(sql(query)) + 1 for query in counts]
    stable, grants = sql(stable_query), sql(grants_query)
    with owned_edge_fault(stage, compose):
        page_action('rotate', expected=False, label='rotate-publication-committed-lost')
        pending = read_pending(guest)
        if (pending['native_before'] != before
                or native_read('native-committed-publication-retained.json') != before):
            raise GuestError('Committed publication interruption changed the original native model')
        digest = hashlib.sha256(pending['candidate'].encode('ascii')).hexdigest()
        match = ("SELECT count(*) FROM device_rotations WHERE device_id='" + device
                 + "' AND operation_id='" + pending['operation_id']
                 + "' AND encode(candidate_digest,'hex')='" + digest + "';")
        if sql(match) != '1' or [int(sql(query)) for query in counts] != expected:
            raise GuestError('Publication replay requires one genuine committed candidate and audit')
    state_query = ("SELECT jsonb_build_array(device_secret_hash,domain_claim_issued_at)::text "
                   "FROM devices WHERE id='" + device + "';")
    return {'before': before, 'pending': pending, 'counts': counts, 'expected': expected,
            'match': match, 'stable': stable, 'grants': grants,
            'state_query': state_query, 'committed_state': sql(state_query)}


def recover(context, guest, native_read, read_pending, native_trust, page_action,
            request, sql, route, desired_head, device, stable_query, grants_query):
    before, pending = context['before'], context['pending']
    if read_pending(guest) != pending:
        raise GuestError('Committed candidate changed before publication replay')
    applications = "SELECT count(*) FROM relay_trust_applications WHERE device_id='" + device + "';"
    reports = sql(applications)
    blocked = native_trust(guest)
    if (blocked.get('phase') != 'rotation_pending' or blocked.get('confirmed') is not False
            or native_read('native-committed-publication-blocked.json') != before
            or read_pending(guest) != pending or sql(applications) != reports):
        raise GuestError('Changed publication altered an ambiguous committed native operation')
    body = {'agent_protocol_version': '1.6.0', 'device_id': device,
            'operation_id': pending['operation_id'], 'replacement_secret': pending['candidate'],
            'expected_relay_ca_sha256': hashlib.sha256(base64.b64decode(before['relay_ca'], validate=True)).hexdigest()}
    settings = request('/api/v1/devices/relay-trust/settings',
                       {'agent_protocol_version': '1.6.0', 'device_id': device}, secret=pending['candidate'])
    desired = settings.get('desired') if isinstance(settings, dict) else None
    if (not isinstance(desired, dict)
            or any(desired.get(key) != desired_head[key] for key in
                   ('generation_id', 'generation', 'server_name', 'bundle_fingerprint'))
            or desired.get('ca_pem') == base64.b64decode(before['relay_ca'], validate=True).decode('ascii')):
        raise GuestError('Committed replay did not cross a genuinely changed authenticated trust head')
    request('/api/v1/devices/rotate', body, secret=before['device_secret'], expected=401)
    replayed = request('/api/v1/devices/rotate', body, secret=pending['candidate'])
    validate_response(replayed, before, pending)
    if ([int(sql(query)) for query in context['counts']] != context['expected']
            or sql(context['match']) != '1' or sql(applications) != reports
            or sql(context['state_query']) != context['committed_state']
            or read_pending(guest) != pending):
        raise GuestError('Candidate replay mutated history or the retained native operation')
    started = time.monotonic()
    page_action('rotate', label='rotate-publication-committed-recovered')
    after = native_read('native-committed-publication-after.json')
    if (after['device_secret'] != pending['candidate'] or after['domain_claim'] != replayed['domain_claim']
            or any(after[key] != before[key] for key in before
                   if key not in ('device_secret', 'domain_claim', 'relay_ca', 'relay_trust_state'))):
        raise GuestError('Native publication replay did not apply the same committed candidate')
    # Cron can legitimately apply the new head after journal completion. Accept
    # only the exact retained trust or that independently delivered current head.
    if (after['relay_ca'], after['relay_trust_state']) != (before['relay_ca'], before['relay_trust_state']):
        validate_current_trust(after, desired)
    guest.ssh('test ! -e /var/db/nethub-agent/rotation.json\n', 'committed publication journal completion')
    if native_trust(guest).get('confirmed') is not True:
        raise GuestError('Native trust did not converge after committed publication replay')
    final = native_read('native-committed-publication-synchronized.json')
    validate_current_trust(final, desired)
    if (any(final[key] != after[key] for key in after if key not in ('relay_ca', 'relay_trust_state'))
            or [int(sql(query)) for query in context['counts']] != context['expected']
            or sql(context['match']) != '1' or sql(context['state_query']) != context['committed_state']
            or sql(stable_query) != context['stable']
            or sql(grants_query) != context['grants']):
        raise GuestError('Committed publication recovery changed history, identity or policy')
    for _ in range(30):
        if route():
            break
        time.sleep(1)
    else:
        raise GuestError('Committed publication recovery did not restore verified TLS')
    return ({'passed': True, 'actual_committed_response_loss': True,
             'prepared_journal_and_original_model_retained': True,
             'authenticated_current_head_differs_from_retained_assignment': True,
             'scheduled_trust_blocked_while_commit_ambiguous': True,
             'previous_credential_HTTP_401': True,
             'candidate_API_replayed_exact_original_assignment_and_trust': True,
             'native_page_recovered_same_committed_candidate': True,
             'one_operation_and_audit_without_replay_mutation': True,
             'completed_journal_removed_and_new_head_confirmed': True,
             'identity_and_source_grants_retained': True, 'same_route_verified_TLS_recovered': True,
             'retry_to_verified_route_ms': round((time.monotonic() - started) * 1000),
             'public_network_or_formal_release_acceptance': False, 'full_goal_complete': False},
            [final['device_secret'], final['domain_claim']])
