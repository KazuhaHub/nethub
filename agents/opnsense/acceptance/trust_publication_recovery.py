"""Exercise a genuine trust publication against a prepared native rotation."""
import base64
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import re
import time
import uuid

from guest import GuestError, invoke
from rotation_recovery import owned_edge_fault


def native_trust(guest):
    value = json.loads(guest.ssh('/usr/local/sbin/configctl nethub-agent trust\n',
                                 'installed scheduled trust action', timeout=100))
    if value.get('success') is not True or value.get('action') != 'trust':
        raise GuestError('Installed trust action was not confirmed')
    return value


def pending_rotation(guest):
    raw = guest.ssh("cd /usr/local/opnsense/scripts/nethub-agent\n"
        "/usr/local/bin/python3.13 - <<'PY'\n"
        "import json\nfrom rotation import RotationJournal\n"
        "print(json.dumps(RotationJournal('/var/db/nethub-agent')._read()))\nPY\n",
        'private publication-conflict rotation readback')
    value = json.loads(raw)
    operation = str(uuid.UUID(value['operation_id']))
    if (value['phase'] != 'prepared' or operation != value['operation_id']
            or uuid.UUID(operation).version != 4
            or re.fullmatch('[A-Za-z0-9_-]{43}', value['candidate']) is None):
        raise GuestError('Publication conflict requires a genuine prepared rotation')
    return value


class Publication:
    def __init__(self, stage, project):
        self.stage = Path(stage)
        self.directory = self.stage / 'deployment'
        self.command = [str(self.stage / 'http01-nethub'), 'certificates', 'relay-trust']
        self.options = ['--directory', str(self.directory), '--project-name', project,
                        '--compose-file', str(self.stage / 'test.yml')]
        # Publication requires a root-owned input. Do not change the runtime
        # mount's ownership or mode to make a protected command accept it.
        self.original = self.directory / 'secrets/issuer/ca.pem'

    def current(self):
        return json.loads(invoke(self.command + ['current', *self.options],
                                 'protected installed-fixture trust head', timeout=95))

    def publish(self, path, previous):
        condition = ['--initialize'] if previous['state'] == 'pending' else [
            '--expected-generation', previous['generation_id']]
        value = json.loads(invoke(self.command + ['publish', *self.options,
            '--bundle-file', str(path), *condition], 'protected trust publication', timeout=95))
        if value.get('state') != 'current' or value.get('generation_id') == previous.get('generation_id'):
            raise GuestError('Protected trust publication did not advance its exact head')
        return value

    @contextmanager
    def overlap(self):
        current = self.current()
        if current['state'] == 'pending':
            current = self.publish(self.original, current)
        expected = hashlib.sha256(invoke(['openssl', 'x509', '-in', str(self.original),
            '-outform', 'DER'], 'original protected authority fingerprint')).hexdigest()
        if current.get('root_fingerprints') != [expected]:
            raise GuestError('Installed publication fixture requires the original single authority')
        parent = self.stage / 'native-publication'
        parent.mkdir(mode=0o700)
        candidate, backup = parent / 'candidate', parent / 'backup'
        authority = [str(self.stage / 'http01-nethub'), 'certificates', 'relay-authority']
        options = ['--directory', str(self.directory), '--candidate-directory', str(candidate)]
        prepared = json.loads(invoke(authority + ['prepare', *options, '--expected-root', expected],
                                     'protected independent authority preparation', timeout=35))
        metadata = prepared['candidate']
        if metadata['previous_root_fingerprint'] != expected or metadata['next_root_fingerprint'] == expected:
            raise GuestError('Protected preparation did not create an independent successor')
        for action in ('backup', 'verify-backup'):
            checked = json.loads(invoke(authority + [action, *options, '--backup-directory', str(backup)],
                                        'independent candidate backup verification', timeout=35))
            if checked.get('backup_verified') is not True or checked.get('candidate') != metadata:
                raise GuestError('Prepared authority backup was not independently verified')
        public = parent / 'overlap.pem'
        public.write_bytes(self.original.read_bytes() + (candidate / 'ca.pem').read_bytes())
        public.chmod(0o600)
        published = self.publish(public, current)
        if (set(published['root_fingerprints']) != {expected, metadata['next_root_fingerprint']}
                or published['generation'] != current['generation'] + 1):
            raise GuestError('Protected overlap differs from its prepared roots')
        try:
            yield published
        finally:
            # Retain the active authority and restore through a second genuine
            # CAS publication, never by rewriting history or fixture SQL.
            restored = self.publish(self.original, published)
            if restored['root_fingerprints'] != [expected]:
                raise GuestError('Owned publication did not restore the original authority')


def exercise_publication_conflict(guest, stage, project, compose, page_action,
        native_read, sql, route, request, device, stable_query, grants_query, check_unavailable):
    publication = Publication(stage, project)
    current = publication.current()
    if current['state'] == 'pending':
        publication.publish(publication.original, current)
    synced = native_trust(guest)
    if synced.get('confirmed') is not True:
        raise GuestError('Original native trust was not confirmed before the conflict')
    before = native_read('native-publication-before.json')
    stable, grants = sql(stable_query), sql(grants_query)
    state_query = ("SELECT jsonb_build_array(device_secret_hash,domain_claim_issued_at)::text "
                   "FROM devices WHERE id='" + device + "';")
    rotation_query = "SELECT count(*) FROM device_rotations WHERE device_id='" + device + "';"
    audit_query = "SELECT count(*) FROM audit_log WHERE action='device.rotated' AND target_device_id='" + device + "';"
    applications = "SELECT count(*) FROM relay_trust_applications WHERE device_id='" + device + "';"
    original_state = sql(state_query)
    operations, audits = int(sql(rotation_query)), int(sql(audit_query))
    with owned_edge_fault(stage, compose, unavailable=True):
        check_unavailable()
        page_action('rotate', expected=False, label='rotate-publication-unavailable')
        pending = pending_rotation(guest)
        if pending['native_before'] != before or native_read('native-publication-prepared.json') != before:
            raise GuestError('Unavailable rotation changed its original native assignment')
        if sql(state_query) != original_state or int(sql(rotation_query)) != operations or int(sql(audit_query)) != audits:
            raise GuestError('Unavailable rotation reached a credential commit')
    rejected_operation = pending['operation_id']
    credentials = [pending['candidate'], before['device_secret'], before['domain_claim']]
    with publication.overlap() as overlap:
        reported = sql(applications)
        blocked = native_trust(guest)
        if (blocked.get('phase') != 'rotation_pending' or blocked.get('confirmed') is not False
                or native_read('native-publication-blocked.json') != before
                or pending_rotation(guest) != pending or sql(applications) != reported):
            raise GuestError('Scheduled trust changed a pending native rotation or its receipt')
        body = {'agent_protocol_version': '1.6.0', 'device_id': device,
                'operation_id': rejected_operation, 'replacement_secret': pending['candidate'],
                'expected_relay_ca_sha256': hashlib.sha256(base64.b64decode(before['relay_ca'], validate=True)).hexdigest()}
        rejected = request('/api/v1/devices/rotate', body, secret=before['device_secret'], expected=409)
        if rejected.get('code') != 'rotation_trust_changed':
            raise GuestError('Previous-credential attempt did not prove the exact publication conflict')
        page_action('rotate', expected=False, label='rotate-publication-conflict')
        guest.ssh('test ! -e /var/db/nethub-agent/rotation.json\n', 'definitively uncommitted journal cleanup')
        if (sql(state_query) != original_state or int(sql(rotation_query)) != operations
                or int(sql(audit_query)) != audits or sql(stable_query) != stable or sql(grants_query) != grants):
            raise GuestError('Rejected publication conflict mutated credential history or policy')
        synced = native_trust(guest)
        trusted = native_read('native-publication-synchronized.json')
        metadata = json.loads(base64.b64decode(trusted['relay_trust_state'], validate=True))
        bundle = base64.b64decode(trusted['relay_ca'], validate=True)
        if (synced.get('confirmed') is not True or trusted['relay_ca'] == before['relay_ca']
                or any(trusted[key] != before[key] for key in before if key not in ('relay_ca', 'relay_trust_state'))
                or metadata['generation_id'] != overlap['generation_id']
                or metadata['generation'] != overlap['generation']
                or metadata['bundle_fingerprint'] != overlap['bundle_fingerprint']
                or hashlib.sha256(b'nethub-relay-trust-v1:' + bundle).hexdigest() != overlap['bundle_fingerprint']):
            raise GuestError('Native synchronization did not apply the genuine overlap bundle')
        started = time.monotonic()
        page_action('rotate', label='rotate-publication-recovered')
        after = native_read('native-publication-after.json')
        if (after['device_secret'] in (before['device_secret'], pending['candidate'])
                or after['domain_claim'] == before['domain_claim']
                or any(after[key] != trusted[key] for key in trusted if key not in ('device_secret', 'domain_claim'))
                or int(sql(rotation_query)) != operations + 1 or int(sql(audit_query)) != audits + 1
                or sql("SELECT count(*) FROM device_rotations WHERE device_id='" + device
                       + "' AND operation_id='" + rejected_operation + "';") != '0'):
            raise GuestError('Fresh native rotation did not retain one distinct committed operation')
        guest.ssh('test ! -e /var/db/nethub-agent/rotation.json\n', 'fresh native rotation journal completion')
        for _ in range(30):
            if route():
                break
            time.sleep(1)
        else:
            raise GuestError('Publication recovery did not restore the original verified GUI route')
        elapsed = round((time.monotonic() - started) * 1000)
        credentials += [after['device_secret'], after['domain_claim']]
    if native_trust(guest).get('confirmed') is not True:
        raise GuestError('Native trust did not confirm the restored original authority')
    if sql(stable_query) != stable or sql(grants_query) != grants or not route():
        raise GuestError('Publication fixture cleanup changed identity, grants or verified GUI access')
    return ({'actual_uncommitted_native_journal_from_unavailable_endpoint': True,
        'protected_independent_candidate_and_backup_verified': True,
        'genuine_overlap_published_by_compare_and_swap': True,
        'pending_rotation_blocked_scheduled_trust_and_application_receipt': True,
        'old_credential_exact_HTTP_409_before_mutation': True,
        'native_page_removed_only_definitively_uncommitted_journal': True,
        'new_trust_synchronized_and_confirmed': True,
        'fresh_candidate_and_single_rotation_audit_verified': True,
        'original_authority_republished_and_native_confirmed': True,
        'identity_and_source_grants_retained': True,
        'same_route_verified_TLS_recovered': True,
        'retry_to_verified_route_ms': elapsed,
        'public_network_or_formal_release_acceptance': False,
        'full_goal_complete': False}, credentials)
