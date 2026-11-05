"""Target route observations retain TLS identity and closed failure outcomes."""
import ssl
import unittest
from unittest.mock import patch

from route_probe import probe, validate


HOST = 'abcdefgh.router.example.com'
ROUTE = {'hostname': HOST, 'ca_pem': 'private-public-certificate'}


class TargetRouteProbe(unittest.TestCase):
    def test_refuses_public_destinations_unknown_fields_and_duplicate_routes(self):
        for value in ({'address': '8.8.8.8', 'routes': {'native': ROUTE, 'witness': ROUTE}},
                      {'address': '127.0.0.1', 'routes': {'native': ROUTE, 'witness': ROUTE}},
                      {'address': '172.18.0.1', 'routes': {'native': ROUTE, 'witness': ROUTE}},
                      {'address': '172.18.0.1', 'routes': {}, 'secret': 'private'}):
            with self.assertRaises(ValueError):
                validate(value)

    def test_preserves_sni_trust_source_and_expected_host_header(self):
        for label, body, header in (('native', b'<input name="usernamefld">', HOST + ':8443'),
                                    ('witness', HOST.encode(), HOST)):
            with self.subTest(label=label), patch('route_probe.ssl.create_default_context') as trust, \
                    patch('route_probe.socket.create_connection') as connect, \
                    patch('route_probe.http.client.HTTPConnection') as http:
                response = http.return_value.getresponse.return_value
                response.status, response.read.return_value = 200, body
                self.assertEqual(probe('172.18.0.1', ROUTE, label), 'verified')
                trust.assert_called_once_with(cadata=ROUTE['ca_pem'])
                connect.assert_called_once_with(('172.18.0.1', 8443), timeout=3,
                                                source_address=('172.18.0.1', 0))
                trust.return_value.wrap_socket.assert_called_once_with(
                    connect.return_value.__enter__.return_value, server_hostname=HOST)
                http.return_value.request.assert_called_once_with('GET', '/',
                    headers={'Host': header, 'Accept-Encoding': 'identity'})
                response.read.assert_called_once_with(1024**2 + 1)
                http.return_value.close.assert_called_once()

    def test_tls_and_transport_errors_never_export_exception_text(self):
        for error, expected in ((ssl.SSLCertVerificationError('private hostname'), 'tls_rejected'),
                                (TimeoutError('private address'), 'timeout'),
                                (ConnectionRefusedError('private peer'), 'connect_failed')):
            with patch('route_probe.ssl.create_default_context'), \
                    patch('route_probe.socket.create_connection', side_effect=error):
                self.assertEqual(probe('172.18.0.1', ROUTE, 'native'), expected)

    def test_http_and_payload_failures_never_export_response_content(self):
        for status, body, expected in ((403, b'private error', 'http_rejected'),
                                      (200, b'private body', 'payload_mismatch'),
                                      (200, b'usernamefld' + b'x' * 1024**2, 'payload_mismatch')):
            with patch('route_probe.ssl.create_default_context'), \
                    patch('route_probe.socket.create_connection'), \
                    patch('route_probe.http.client.HTTPConnection') as http:
                response = http.return_value.getresponse.return_value
                response.status, response.read.return_value = status, body
                self.assertEqual(probe('172.18.0.1', ROUTE, 'native'), expected)


if __name__ == '__main__':
    unittest.main()
