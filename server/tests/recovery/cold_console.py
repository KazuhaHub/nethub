"""Use normal verified console HTTPS for the owned cold-host fixture.

Passwords, cookie jars, CSRF headers, enrollment tokens and response bodies stay
in the caller's private workspace. No trusted-proxy header or database grant is
manufactured here. The same original administrator can log in after restoration.
"""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid

from linux_guest import RecoveryError


def canonical_device(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def permitted_request(method, path):
    if method == 'GET':
        return path == '/api/v1/console/devices'
    if method != 'POST':
        return False
    if path in ('/api/v1/console/login', '/api/v1/console/enroll-tokens'):
        return True
    prefix, suffix = '/api/v1/console/devices/', '/open'
    return isinstance(path, str) and path.startswith(prefix) and path.endswith(suffix) and canonical_device(path[len(prefix):-len(suffix)])


def private_password(path):
    info = path.lstat()
    if (path != path.resolve(strict=True) or not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or not 32 <= info.st_size <= 1024):
        raise RecoveryError('Original private administrator password file refused')
    return path.read_text().strip()


class ColdConsole:
    def __init__(self, directory, port, ca_pem, password):
        if (sys.platform != 'linux' or os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true'
                or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
                or type(port) is not int or not 1024 <= port <= 65535
                or not isinstance(ca_pem, bytes) or not 256 <= len(ca_pem) <= 16384):
            raise RecoveryError('Owned verified cold console endpoint required')
        self.directory = Path(directory)
        parent = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
        if (self.directory != self.directory.resolve() or not self.directory.is_relative_to(parent)
                or self.directory == parent):
            raise RecoveryError('New private console workspace required')
        self.directory.mkdir(mode=0o700)
        self.port, self.password, self.actor, self.counter = port, Path(password), None, 0
        self.write('console-ca.pem', ca_pem)
        self.write('cookies', b'')

    def write(self, name, data):
        path = self.directory / name
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        return path

    def request(self, method, path, body=None, *, expected=200):
        if (not permitted_request(method, path) or method == 'GET' and body is not None
                or type(expected) is not int or not 200 <= expected <= 299):
            raise RecoveryError('Owned console API request refused')
        login = path == '/api/v1/console/login'
        if (not login and self.actor is None) or login and self.actor is not None:
            raise RecoveryError('Original console session phase differs')
        self.counter += 1
        name = 'request-' + str(self.counter)
        args = ['curl', '--silent', '--show-error', '--noproxy', '*', '--max-time', '15',
                '--max-filesize', '1048576', '--proto', '=https', '--cacert', str(self.directory / 'console-ca.pem'),
                '--connect-to', 'console.example.com:443:127.0.0.1:' + str(self.port),
                '--cookie-jar', str(self.directory / 'cookies')]
        if not login:
            args += ['--cookie', str(self.directory / 'cookies'), '-H', '@' + str(self.directory / 'csrf-header')]
        if method == 'POST':
            payload = self.write(name + '.json', (json.dumps(body) + '\n').encode())
            args += ['-H', 'Content-Type: application/json', '-H', 'Origin: https://console.example.com',
                     '--data-binary', '@' + str(payload)]
        args += ['--write-out', '\n%{http_code}', 'https://console.example.com' + path]
        try:
            result = subprocess.run(args, capture_output=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            raise RecoveryError('Original verified console request unavailable or timed out') from None
        self.write(name + '-response-private.log', result.stdout + result.stderr)
        if result.returncode or len(result.stdout) > 1048580:
            raise RecoveryError('Original verified console request failed')
        raw, _, status = result.stdout.rpartition(b'\n')
        if status != str(expected).encode():
            raise RecoveryError('Original verified console status differs')
        return json.loads(raw)

    def login(self, *, original_actor=None):
        if original_actor is not None and not canonical_device(original_actor):
            raise RecoveryError('Original administrator identity differs')
        value = self.request('POST', '/api/v1/console/login',
                             {'email': 'cold-admin@example.com', 'password': private_password(self.password)})
        actor, csrf = value['user']['id'], value['csrf_token']
        if (not canonical_device(actor) or value['user']['role'] != 'admin'
                or original_actor is not None and actor != original_actor
                or not isinstance(csrf, str) or re.fullmatch('[A-Za-z0-9_-]{16,256}', csrf) is None):
            raise RecoveryError('Original administrator login identity or CSRF differs')
        self.write('csrf-header', ('X-CSRF-Token: ' + csrf + '\n').encode('ascii'))
        self.actor = actor
        return actor

    def enrollment_token(self):
        if getattr(self, 'token_requested', False):
            raise RecoveryError('Enrollment token creation cannot be replayed')
        self.token_requested = True
        token = self.request('POST', '/api/v1/console/enroll-tokens', {}, expected=201)['token']
        if not isinstance(token, str) or re.fullmatch('[A-Za-z0-9_-]{32,256}', token) is None:
            raise RecoveryError('Original owned enrollment token differs')
        self.write('enrollment-token.json', (json.dumps({'token': token}) + '\n').encode())
        return token

    def open_device(self, device):
        if not canonical_device(device):
            raise RecoveryError('Original enrolled device identity differs')
        return self.request('POST', '/api/v1/console/devices/' + device + '/open', {})
