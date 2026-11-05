"""Drive the original installed appliance through normal native APIs.

Only baseline provisioning uses the disposable PHP fixture. The enrollment key
never leaves the appliance; the host signs its original public cached CSR for
the initial fixture leaf. Real issuance/application remains the restored host's
stock timer and the installed agent's responsibility.
"""
import json
import os
from pathlib import Path
import re
import time
import uuid

from guest import Guest, GuestError, invoke


class ColdNative:
    def __init__(self, guest, directory, evidence):
        if (type(guest) is not Guest or guest.process is None or guest.process.poll() is not None
                or os.environ.get('GITHUB_ACTIONS') != 'true'
                or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
            raise GuestError('Original live owned appliance required')
        parent = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
        self.directory, self.evidence = Path(directory), Path(evidence)
        for path in (self.directory, self.evidence):
            if path != path.resolve() or not path.is_relative_to(parent) or path == parent:
                raise GuestError('New private native recovery workspace required')
            path.mkdir(mode=0o700)
        self.guest, self.counter, self.nonce = guest, 0, uuid.uuid4().hex
        self.device, self.host = None, None
        marker = self.write('native-fixture-nonce', (self.nonce + '\n').encode())
        guest.put(marker, marker.name)
        for name in ('native-fixture.php', 'native_model_probe.py', 'cold_native_probe.py'):
            guest.put(Path(__file__).with_name(name), name)
        guest.ssh('chmod 0600 /root/nethub-ci/native-fixture-nonce\n', 'Original private native fixture identity')

    def write(self, name, content):
        path = self.directory / name
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        return path

    def input(self, value):
        self.counter += 1
        return self.write('input-' + str(self.counter) + '.json', (json.dumps(value) + '\n').encode())

    def fixture(self, action, **fields):
        if action not in ('trust-cold', 'install-bound-key'):
            raise GuestError('Cold native fixture action refused')
        path = self.input(dict(action=action, nonce=self.nonce, **fields))
        self.guest.put(path, path.name)
        value = json.loads(self.guest.ssh('/usr/local/bin/php -d register_argc_argv=1 '
            '/root/nethub-ci/native-fixture.php < /root/nethub-ci/' + path.name + '\n',
            'Original cold native fixture ' + action))
        if set(value) != {'success', 'result'} or value['success'] is not True or not isinstance(value['result'], dict):
            raise GuestError('Original cold native fixture outcome differs')
        return value['result']

    def trust(self, ca):
        if not isinstance(ca, bytes) or not 256 <= len(ca) <= 16384:
            raise GuestError('Owned public native trust root required')
        if self.fixture('trust-cold', ca_pem=ca.decode('ascii')) != {'trusted': True}:
            raise GuestError('Owned public native trust installation differs')

    def page(self, action, token=''):
        if action not in ('enroll', 'remove'):
            raise GuestError('Cold native page action refused')
        config = self.input({'origin': 'https://127.0.0.1:' + str(self.guest.gui_port),
                             'console': 'https://console.example.com', 'token': token,
                             'action': action, 'expected_success': True, 'evidence': str(self.evidence)})
        invoke([os.environ['NETHUB_NODE_BINARY'], str(Path(__file__).with_name('enrolled-browser.mjs')), str(config)],
               'Original cold native ' + action + ' page', timeout=120)
        result = json.loads((self.evidence / ('installed-' + action + '-page.json')).read_text())
        if (result.get('passed') is not True or result.get('actual_native_write_API') is not True
                or result.get('action') != action or result.get('expected_success') is not True):
            raise GuestError('Original cold native page not confirmed')
        return result

    def enroll(self, token):
        if getattr(self, 'enrollment_attempted', False):
            raise GuestError('Original native enrollment cannot be replayed')
        self.enrollment_attempted = True
        self.guest.ssh("printf '\\n10.0.2.100 console.example.com\\n' >> /etc/hosts\n",
                       'Original canonical console resolution')
        self.page('enroll', token)
        self.guest.ssh('/usr/local/sbin/configctl nethub-agent trust\n', 'Original native trust preflight')
        value = json.loads(self.guest.ssh('/usr/local/bin/python3.13 /root/nethub-ci/native_model_probe.py\n',
                                        'Original private native model'))
        self.write('original-model-private.json', (json.dumps(value) + '\n').encode())
        device, subdomain = value.get('device_id'), value.get('subdomain')
        if (not isinstance(device, str) or str(uuid.UUID(device)) != device
                or not isinstance(subdomain, str) or re.fullmatch('[a-z0-9]{8}', subdomain) is None
                or value.get('enabled') != '1'):
            raise GuestError('Original enabled native enrollment identity differs')
        self.device, self.host = device, subdomain + '.devices.example.test'
        return {'device_id': self.device, 'host': self.host}

    def probe(self):
        if self.device is None:
            raise GuestError('Original native enrollment required before inspection')
        path = self.input({'nonce': self.nonce, 'device_id': self.device, 'host': self.host})
        self.guest.put(path, path.name)
        value = json.loads(self.guest.ssh('/usr/local/bin/python3.13 /root/nethub-ci/cold_native_probe.py '
                         '< /root/nethub-ci/' + path.name + '\n', 'Original private enrolled key and cached CSR'))
        self.write('probe-' + str(self.counter) + '-private.json', (json.dumps(value) + '\n').encode())
        if value == {'available': False, 'reason': 'mutation_busy'}:
            return None
        if (value.get('device_id') != self.device or value.get('host') != self.host
                or value.get('native_security_checks_enabled') is not True
                or value.get('certificate_application_or_full_recovery_accepted') is not False):
            raise GuestError('Original private native probe binding differs')
        return value

    def initial_request(self):
        value = json.loads(self.guest.ssh('/usr/local/sbin/configctl nethub-agent certificate\n',
                                         'Original normal native certificate submission'))
        if value.get('success') is not True or value.get('phase') != 'pending':
            raise GuestError('Original genuine native certificate request is not pending')
        deadline = time.monotonic() + 15
        while True:
            result = self.probe()
            if result is not None:
                self.original_request = result
                return result
            if time.monotonic() >= deadline:
                raise GuestError('Original cached CSR inspection lock remained busy')
            time.sleep(.2)

    def prepare_baseline(self):
        if not hasattr(self, 'original_request') or hasattr(self, 'baseline'):
            raise GuestError('Original cached CSR and new baseline setup required')
        csr = self.write('original-public.csr', self.original_request['original_cached_csr_pem'].encode('ascii'))
        key = self.write('fixture-ca.key', b'')
        ca, certificate = self.directory / 'fixture-ca.pem', self.directory / 'fixture-leaf.pem'
        invoke(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=NetHub isolated cold baseline', '-addext', 'basicConstraints=critical,CA:TRUE',
                '-keyout', str(key), '-out', str(ca)], 'Owned cold baseline fixture authority')
        ca.chmod(0o600)
        extensions = self.write('fixture-leaf.ext', ('basicConstraints=critical,CA:FALSE\n'
            'keyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:' + self.host + '\n').encode())
        invoke(['openssl', 'x509', '-req', '-in', str(csr), '-CA', str(ca), '-CAkey', str(key),
                '-CAcreateserial', '-days', '1', '-sha256', '-extfile', str(extensions), '-out', str(certificate)],
               'Original cached public CSR fixture signing')
        certificate.chmod(0o600)
        installed = self.fixture('install-bound-key', host=self.host, ca_pem=ca.read_text(),
                                 certificate_pem=certificate.read_text())
        if installed.get('installed') is not True or installed.get('security_checks_enabled') is not True:
            raise GuestError('Explicit original enrolled-key GUI baseline not installed')
        self.guest.ssh('/usr/local/etc/rc.restart_webgui\n', 'Explicit pre-baseline native GUI reload', timeout=30)
        value = self.probe()
        if (value is None or value['native_GUI_already_uses_enrollment_key'] is not True
                or value['native_alternate_present'] is not True
                or any(value[key] != self.original_request[key] for key in
                       ('enrollment_gui_key_fingerprint', 'original_cached_csr_sha256',
                        'private_assignment_fingerprint', 'frpc_pid', 'frpc_started'))):
            raise GuestError('Explicit GUI baseline changed original key CSR assignment or tunnel')
        self.baseline = value
        return value

    def wait_application(self, generation_id, leaf_fingerprint, *, timeout=180):
        if (not hasattr(self, 'baseline') or not isinstance(generation_id, str)
                or str(uuid.UUID(generation_id)) != generation_id
                or not isinstance(leaf_fingerprint, str) or re.fullmatch('[a-f0-9]{64}', leaf_fingerprint) is None
                or type(timeout) is not int or not 1 <= timeout <= 180):
            raise GuestError('Actual issued generation and original baseline required')
        deadline = time.monotonic() + timeout
        while True:
            value = self.probe()
            if value is not None:
                for key in ('enrollment_gui_key_fingerprint', 'original_cached_csr_sha256',
                            'private_assignment_fingerprint', 'frpc_pid', 'frpc_started'):
                    if value[key] != self.baseline[key]:
                        raise GuestError('Original enrolled key CSR assignment or process changed during recovery')
                applied = value['native_apply']
                if (applied is not None and applied['phase'] == 'applied' and applied['device_id'] == self.device
                        and applied['generation_id'] == generation_id and applied['generation'] == 1
                        and value['native_leaf_fingerprint'] == leaf_fingerprint
                        and value['native_GUI_already_uses_enrollment_key'] is True
                        and value['native_alternate_present'] is True
                        and value['native_applied_selection_and_verified_loopback_TLS_confirmed'] is True):
                    self.applied = value
                    return value
            if time.monotonic() >= deadline:
                raise GuestError('Stock native certificate application not confirmed within recovery deadline')
            time.sleep(1)

    def remove(self):
        if not hasattr(self, 'applied') or getattr(self, 'removal_attempted', False):
            raise GuestError('Confirmed original application required before one native removal')
        self.removal_attempted = True
        self.page('remove')
        self.guest.ssh("/usr/local/bin/python3.13 - <<'PY'\n"
            "from pathlib import Path\n"
            "import subprocess,xml.etree.ElementTree as ET\n"
            "node=ET.parse('/conf/config.xml').getroot().find('OPNsense/NetHubAgent')\n"
            "assert node is not None\n"
            "for name in ('console_url','server_addr','server_name','relay_ca','relay_trust_state',"
            "'subdomain','device_id','device_secret','frp_token','domain_claim'):\n"
            " assert (node.findtext(name) or '')==''\n"
            "assert node.findtext('enabled')=='0'\n"
            "assert not Path('/var/db/nethub-agent/rotation.json').exists()\n"
            "status=subprocess.run(['/usr/sbin/service','nethub_agent_frpc','onestatus'],capture_output=True,timeout=10)\n"
            "assert status.returncode!=0\n"
            "PY\n", 'Original native removal cleared model and stopped service')
        return {'normal_native_remove_page_passed': True, 'original_native_model_cleared_and_service_stopped': True,
                'server_revocation_route_closure_or_complete_recovery_accepted': False}
