"""Export only closed DNS/TCP/system-TLS/HTTP outcomes for the owned console."""
import errno
import json
import socket
import ssl
import urllib.error
import urllib.request


FIELDS = {'passed', 'phase', 'failure', 'http_status', 'verify_code',
          'default_CA_file_available', 'default_CA_directory_available'}
PHASES = ('dns', 'tcp', 'tls', 'http', 'complete')
FAILURES = ('', 'dns_resolution', 'dns_mismatch', 'tcp_refused', 'tcp_timeout', 'tcp_connect',
            'tls_verify', 'tls_handshake', 'http_status', 'http_failure', 'unexpected')


def validate_result(value):
    if (not isinstance(value, dict) or set(value) != FIELDS
            or any(type(value[name]) is not bool for name in
                   ('passed', 'default_CA_file_available', 'default_CA_directory_available'))
            or not isinstance(value['phase'], str) or value['phase'] not in PHASES
            or not isinstance(value['failure'], str) or value['failure'] not in FAILURES
            or type(value['http_status']) is not int or not 0 <= value['http_status'] <= 599
            or type(value['verify_code']) is not int or not 0 <= value['verify_code'] <= 1000
            or value['passed'] != (value['phase'] == 'complete' and value['failure'] == ''
                                   and value['http_status'] == 200 and value['verify_code'] == 0)):
        raise ValueError('Unexpected closed console probe result')


def probe():
    result = {'passed': False, 'phase': 'dns', 'failure': '', 'http_status': 0, 'verify_code': 0,
              'default_CA_file_available': False, 'default_CA_directory_available': False}
    try:
        paths = ssl.get_default_verify_paths()
        result['default_CA_file_available'] = paths.cafile is not None
        result['default_CA_directory_available'] = paths.capath is not None
        if socket.gethostbyname('console.example.com') != '10.0.2.100':
            result['failure'] = 'dns_mismatch'
            return result
        result['phase'] = 'tcp'
        with socket.create_connection(('console.example.com', 443), timeout=5):
            pass
        result['phase'] = 'tls'
        with socket.create_connection(('console.example.com', 443), timeout=5) as connection:
            with ssl.create_default_context().wrap_socket(connection, server_hostname='console.example.com'):
                pass
        result['phase'] = 'http'
        with urllib.request.urlopen('https://console.example.com/', timeout=10) as response:
            result['http_status'] = response.status
        if result['http_status'] != 200:
            result['failure'] = 'http_status'
            return result
        result.update(passed=True, phase='complete')
    except urllib.error.HTTPError as error:
        result.update(failure='http_status', http_status=error.code if 100 <= error.code <= 599 else 0)
    except ssl.SSLCertVerificationError as error:
        code = getattr(error, 'verify_code', 0)
        result.update(failure='tls_verify', verify_code=code if type(code) is int and 0 <= code <= 1000 else 0)
    except ssl.SSLError:
        result['failure'] = 'tls_handshake'
    except socket.gaierror:
        result['failure'] = 'dns_resolution'
    except TimeoutError:
        result['failure'] = 'tcp_timeout' if result['phase'] == 'tcp' else 'http_failure'
    except OSError as error:
        if result['phase'] == 'tcp':
            result['failure'] = 'tcp_refused' if error.errno == errno.ECONNREFUSED else 'tcp_connect'
        else:
            result['failure'] = 'http_failure'
    except Exception:
        result['failure'] = 'unexpected'
    return result


if __name__ == '__main__':
    outcome = probe()
    validate_result(outcome)
    print(json.dumps(outcome))
