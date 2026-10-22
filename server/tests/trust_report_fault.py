"""Lab-only loopback forwarding that loses one committed trust report response."""
import argparse
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import stat
import sys
import threading
import time
import uuid

PATH = '/api/v1/devices/relay-trust/applied'
HOP_HEADERS = {'connection', 'keep-alive', 'transfer-encoding', 'te', 'trailer',
               'upgrade', 'proxy-authorization', 'proxy-authenticate', 'content-length'}
MAX_BODY = 65536


def write_once(path, value):
    raw = json.dumps(value, sort_keys=True).encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if os.name == 'posix':
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)


class State:
    def __init__(self, directory, device_id, generation, backend_port):
        self.directory = directory
        self.device_id = device_id
        self.generation = generation
        self.backend_port = backend_port
        self.lock = threading.Lock()

    def lose_response(self, request, status, response):
        if status != 200:
            return False
        try:
            sent, accepted = json.loads(request), json.loads(response)
            if not isinstance(sent, dict) or not isinstance(accepted, dict):
                return False
            matches = (sent['device_id'] == self.device_id and
                       type(sent['generation']) is int and sent['generation'] == self.generation and
                       accepted.get('accepted') is True and
                       type(accepted['generation']) is int and
                       all(accepted[key] == sent[key] for key in
                           ['agent_protocol_version', 'device_id', 'generation_id', 'generation', 'bundle_fingerprint']) and
                       isinstance(accepted['accepted_at'], str) and bool(accepted['accepted_at']))
        except (ValueError, KeyError, TypeError):
            return False
        if not matches:
            return False
        with self.lock:
            try:
                write_once(self.directory / 'dropped.json', {
                    'device_id': self.device_id, 'generation': self.generation,
                    'accepted_at': accepted['accepted_at'], 'backend_status': status,
                    'response_sha256': hashlib.sha256(response).hexdigest(),
                })
            except FileExistsError:
                return False
        return True


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        try:
            length = int(self.headers['Content-Length'])
        except (ValueError, TypeError):
            self.send_error(411)
            return
        if length < 1 or length > MAX_BODY or 'Transfer-Encoding' in self.headers:
            self.send_error(413)
            return
        self.connection.settimeout(10)
        body = self.rfile.read(length)
        if len(body) != length:
            self.send_error(400)
            return
        if self.path != PATH:
            self.send_error(404)
            return
        headers = {key: value for key, value in self.headers.items() if key.lower() not in HOP_HEADERS}
        headers['Content-Length'] = str(len(body))
        connection = http.client.HTTPConnection('127.0.0.1', self.server.state.backend_port, timeout=10)
        try:
            connection.request('POST', PATH, body, headers)
            response = connection.getresponse()
            data = response.read(MAX_BODY + 1)
            if len(data) > MAX_BODY:
                self.send_error(502)
                return
            json_response = (response.getheader('Content-Type', '').split(';')[0].strip().lower() == 'application/json'
                             and response.getheader('Content-Encoding', 'identity') == 'identity')
            if json_response and self.server.state.lose_response(body, response.status, data):
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                return
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in HOP_HEADERS:
                    self.send_header(key, value)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        finally:
            connection.close()


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *args):
        self.slots = threading.BoundedSemaphore(4)
        super().__init__(*args)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.close_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, _request, _client_address):
        # Requests carry bearer credentials. Never emit an exception/request dump.
        try:
            write_once(self.state.directory / 'connection-error.json', {'connection_error': True})
        except FileExistsError:
            pass


def validate_settings(value):
    if type(value) is not dict or set(value) != {'device_id', 'generation', 'backend_port', 'listen_port', 'seconds'}:
        raise ValueError('Unexpected fixture options')
    if not isinstance(value['device_id'], str) or str(uuid.UUID(value['device_id'])) != value['device_id'] or uuid.UUID(value['device_id']).int == 0:
        raise ValueError('Canonical device identity required')
    for key in ['backend_port', 'listen_port']:
        if type(value[key]) is not int or not 1024 < value[key] < 65536:
            raise ValueError('Loopback fixture port required')
    if value['backend_port'] == value['listen_port'] or type(value['generation']) is not int or not 1 <= value['generation'] <= 2147483647:
        raise ValueError('Invalid report target')
    if type(value['seconds']) is not int or not 1 <= value['seconds'] <= 600:
        raise ValueError('Bounded fixture duration required')
    return value


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate fixture option')
        result[key] = value
    return result


def load(directory):
    if sys.platform != 'linux' or os.geteuid() != 0 or directory.resolve() != directory:
        raise ValueError('Private root-owned Linux fixture required')
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('Private fixture directory required')
    path = directory / 'config.json'
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 4096:
        raise ValueError('Private fixture configuration required')
    for name in ['ready.json', 'dropped.json', 'connection-error.json']:
        if (directory / name).exists() or (directory / name).is_symlink():
            raise ValueError('Fresh fixture directory required')
    raw = path.read_bytes()
    value = validate_settings(json.loads(raw, object_pairs_hook=unique_fields))
    return value, hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    value, config_sha256 = load(args.directory)
    state = State(args.directory, value['device_id'], value['generation'], value['backend_port'])
    with Server(('127.0.0.1', value['listen_port']), Handler) as server:
        server.state = state
        server.timeout = .2
        write_once(args.directory / 'ready.json', {
            'pid': os.getpid(), 'port': server.server_port,
            'config_sha256': config_sha256,
        })
        deadline = time.monotonic() + value['seconds']
        while time.monotonic() < deadline:
            server.handle_request()


if __name__ == '__main__':
    main()
