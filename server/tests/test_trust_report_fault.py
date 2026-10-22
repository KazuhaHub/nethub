"""Exercise lost-response forwarding over real loopback HTTP connections."""
import http.client
import http.server
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout

import trust_report_fault as fixture

DEVICE = '01234567-89ab-4cde-8123-456789abcdef'
OTHER = '11234567-89ab-4cde-8123-456789abcdef'


class Backend(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        value = json.loads(body)
        self.server.requests.append((self.path, body, self.headers.get('Authorization'),
                                     self.headers.get('X-Forwarded-For')))
        response = dict(value, accepted=True, accepted_at='2026-10-22T00:00:00.000001Z')
        response.update(self.server.override)
        raw = self.server.raw if self.server.raw is not None else json.dumps(response).encode()
        self.send_response(self.server.status)
        self.send_header('Content-Type', self.server.content_type)
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class ResponseLoss(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.backend = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Backend)
        self.backend.requests = []
        self.backend.status = 200
        self.backend.override = {}
        self.backend.raw = None
        self.backend.content_type = 'application/json'
        self.front = fixture.Server(('127.0.0.1', 0), fixture.Handler)
        self.front.state = fixture.State(self.root, DEVICE, 2, self.backend.server_port)
        self.threads = []
        for server in [self.backend, self.front]:
            worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
            worker.start()
            self.threads.append(worker)
        self.payload = {'agent_protocol_version': '2.1.0', 'device_id': DEVICE,
                        'generation_id': OTHER, 'generation': 2, 'bundle_fingerprint': 'a' * 64}

    def tearDown(self):
        for server in [self.front, self.backend]:
            server.shutdown()
            server.server_close()
        for worker in self.threads:
            worker.join(2)
        self.directory.cleanup()

    def request(self, payload=None, path=fixture.PATH, headers=None):
        client = http.client.HTTPConnection('127.0.0.1', self.front.server_port, timeout=2)
        values = {'Content-Type': 'application/json', 'Authorization': 'Bearer private-test-credential',
                  'Host': 'console.example.com', 'X-Forwarded-For': '192.0.2.1'}
        values.update(headers or {})
        try:
            client.request('POST', path, json.dumps(payload or self.payload).encode(), values)
            response = client.getresponse()
            return response.status, response.read()
        finally:
            client.close()

    def test_loses_only_first_matching_success_after_backend_receives_credentials(self):
        captured = io.StringIO()
        with redirect_stdout(captured), redirect_stderr(captured):
            with self.assertRaises(http.client.RemoteDisconnected):
                self.request()
            first = json.loads((self.root / 'dropped.json').read_text())
            status, body = self.request()
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['accepted_at'], first['accepted_at'])
        self.assertEqual(len(self.backend.requests), 2)
        self.assertEqual(self.backend.requests[0], self.backend.requests[1])
        self.assertEqual(self.backend.requests[0][2:], ('Bearer private-test-credential', '192.0.2.1'))
        self.assertEqual(first, json.loads((self.root / 'dropped.json').read_text()))
        self.assertNotIn('private-test-credential', (self.root / 'dropped.json').read_text() + captured.getvalue())

    def test_denial_wrong_identity_generation_and_mismatched_success_are_forwarded(self):
        self.backend.status = 409
        self.assertEqual(self.request()[0], 409)
        self.backend.status = 200
        self.assertEqual(self.request(dict(self.payload, device_id=OTHER))[0], 200)
        self.assertEqual(self.request(dict(self.payload, generation=1))[0], 200)
        self.backend.override = {'device_id': OTHER}
        self.assertEqual(self.request()[0], 200)
        self.backend.override = {'accepted': False}
        self.assertEqual(self.request()[0], 200)
        self.assertFalse((self.root / 'dropped.json').exists())

    def test_other_paths_and_oversize_requests_never_reach_backend(self):
        self.assertEqual(self.request(path='/api/v1/devices/enroll')[0], 404)
        client = http.client.HTTPConnection('127.0.0.1', self.front.server_port, timeout=2)
        try:
            # Reject the announced length before the client sends an oversized body.
            client.putrequest('POST', fixture.PATH)
            client.putheader('Content-Length', str(fixture.MAX_BODY + 1))
            client.endheaders()
            response = client.getresponse()
            self.assertEqual(response.status, 413)
            response.read()
        finally:
            client.close()
        self.assertEqual(self.backend.requests, [])

    def test_malformed_or_non_json_success_is_forwarded_without_a_drop_receipt(self):
        for raw in [b'[]', b'null', b'not-json']:
            self.backend.raw = raw
            self.assertEqual(self.request(), (200, raw))
        self.backend.raw = None
        self.backend.content_type = 'text/plain'
        self.assertEqual(self.request()[0], 200)
        self.assertFalse((self.root / 'dropped.json').exists())

    def test_full_worker_budget_refuses_another_connection_without_forwarding(self):
        for _ in range(4):
            self.assertTrue(self.front.slots.acquire(blocking=False))
        try:
            with self.assertRaises(ConnectionError):
                self.request()
            self.assertEqual(self.backend.requests, [])
        finally:
            for _ in range(4):
                self.front.slots.release()


class FixtureOptions(unittest.TestCase):
    def test_invalid_network_duration_and_identity_options_are_refused(self):
        good = {'device_id': DEVICE, 'generation': 2, 'backend_port': 18081,
                'listen_port': 18991, 'seconds': 300}
        self.assertEqual(fixture.validate_settings(good), good)
        for change in [{'backend_host': 'example.com'}, {'listen_port': 443}, {'backend_port': 18991},
                       {'seconds': 601}, {'generation': True}, {'device_id': DEVICE.upper()},
                       {'backend_port': True}, {'device_id': None}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                fixture.validate_settings(dict(good, **change))
        with self.assertRaises(ValueError):
            json.loads('{"seconds":1,"seconds":600}', object_pairs_hook=fixture.unique_fields)


if __name__ == '__main__':
    unittest.main()
