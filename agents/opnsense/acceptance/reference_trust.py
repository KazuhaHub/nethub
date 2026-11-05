"""Apply reference trust through the real device API before guarded retirement."""
import hashlib
import json
from pathlib import Path
import re
import uuid

from guest import GuestError, invoke


def synchronize_references(stage, generation, request, sql, native_id, witness_id, install_witness):
    stage = Path(stage)
    assignments = [json.loads((stage / 'relay-test' / ('assignment' + str(i) + '.json')).read_text(encoding='utf-8'))
                   for i in range(2)]
    identities = [str(uuid.UUID(item['device_id'])) for item in assignments]
    if (len(set([native_id, *identities])) != 3 or witness_id not in identities
            or set(sql('SELECT id::text FROM devices WHERE NOT revoked ORDER BY id;').splitlines())
                != {native_id, *identities}):
        raise GuestError('Reference trust application does not cover the exact active fixture inventory')
    generation_id = str(uuid.UUID(generation['generation_id']))
    if (generation_id != generation['generation_id']
            or re.fullmatch('[a-f0-9]{64}', generation['bundle_fingerprint']) is None
            or type(generation['generation']) is not int or not 1 <= generation['generation'] <= 2147483647
            or not isinstance(generation['root_fingerprints'], list)
            or not 1 <= len(generation['root_fingerprints']) <= 2
            or any(not isinstance(root, str) or re.fullmatch('[a-f0-9]{64}', root) is None
                   for root in generation['root_fingerprints'])):
        raise GuestError('Reference trust generation identity differs')
    witness_ms = None
    for index, assignment in enumerate(assignments):
        if (assignment['device_id'] != identities[index]
                or re.fullmatch('[A-Za-z0-9_-]{43}', assignment['device_secret']) is None
                or assignment['server_name'] != generation['server_name']):
            raise GuestError('Current reference assignment is invalid')
        body = {'agent_protocol_version': '1.6.0', 'device_id': assignment['device_id']}
        settings = request('/api/v1/devices/relay-trust/settings', body, secret=assignment['device_secret'])
        desired = settings['desired']
        for key in ('generation_id', 'generation', 'server_name', 'bundle_fingerprint'):
            if desired[key] != generation[key]:
                raise GuestError('Reference API delivered a different trust generation')
        public = desired['ca_pem'].encode('ascii')
        if (not 64 <= len(public) <= 32768
                or hashlib.sha256(b'nethub-relay-trust-v1:' + public).hexdigest() != generation['bundle_fingerprint']):
            raise GuestError('Reference trust material differs from the protected publication')
        blocks = re.findall(rb'-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n', public)
        if len(blocks) not in (1, 2) or b''.join(blocks) != public:
            raise GuestError('Reference trust certificate framing is invalid')
        target = stage / 'native-publication' / ('reference-' + str(index) + '.pem')
        target.write_bytes(public)
        target.chmod(0o600)
        fingerprints = set()
        for offset, block in enumerate(blocks):
            certificate = target.with_name('reference-' + str(index) + '-root-' + str(offset) + '.pem')
            certificate.write_bytes(block)
            certificate.chmod(0o600)
            fingerprints.add(hashlib.sha256(invoke(['openssl', 'x509', '-in', str(certificate),
                '-outform', 'DER'], 'independent reference root fingerprint')).hexdigest())
            invoke(['openssl', 'verify', '-CAfile', str(target), str(certificate)],
                   'independent reference root validation')
        if fingerprints != set(generation['root_fingerprints']) or len(fingerprints) != len(blocks):
            raise GuestError('Reference trust roots differ from the prepared authorities')
        if assignment['device_id'] == witness_id:
            # A running official client must actually reload the new trust pool.
            # Do not report its application from an edited file alone.
            witness_ms = install_witness(public)
            if type(witness_ms) is not int or not 0 < witness_ms < 60000:
                raise GuestError('Planned witness trust reconnection was not verified')
        report = dict(body, generation_id=generation_id, generation=generation['generation'],
                      bundle_fingerprint=generation['bundle_fingerprint'])
        accepted = request('/api/v1/devices/relay-trust/applied', report, secret=assignment['device_secret'])
        if (any(accepted.get(key) != value for key, value in report.items() if key != 'agent_protocol_version')
                or not isinstance(accepted.get('accepted_at'), str) or not accepted['accepted_at']):
            raise GuestError('Authenticated reference trust application was not confirmed')
    # This is the real retirement barrier. Never insert application rows or
    # revoke another device to make a fixture publication pass it.
    missing = sql("SELECT count(*) FROM devices d WHERE NOT revoked AND NOT EXISTS "
        "(SELECT FROM relay_trust_applications a WHERE a.device_id=d.id AND a.tenant_id=d.tenant_id "
        "AND a.generation_id='" + generation_id + "' AND a.bundle_fingerprint='"
        + generation['bundle_fingerprint'] + "');")
    if missing != '0' or witness_ms is None:
        raise GuestError('A current device has not actually confirmed the trust publication')
    return witness_ms
