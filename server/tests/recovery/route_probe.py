"""Compare the retained routes without exporting destinations or response bodies."""
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import stat
import sys


OUTCOMES = {'verified', 'connect_failed', 'timeout', 'tls_rejected', 'http_rejected',
            'tls_identity_rejected', 'tls_closed', 'payload_mismatch', 'unavailable'}


def validate(value):
    if not isinstance(value, dict) or set(value) != {'address', 'routes'}:
        raise ValueError('Private route probe input unavailable')
    address = ipaddress.IPv4Address(value['address'])
    if not address.is_private or address.is_unspecified or address.is_multicast or address.is_loopback:
        raise ValueError('Private route probe input unavailable')
    routes = value['routes']
    if not isinstance(routes, dict) or set(routes) != {'native', 'witness'}:
        raise ValueError('Private route probe input unavailable')
    for route in routes.values():
        if (not isinstance(route, dict) or set(route) != {'hostname', 'ca_pem'}
                or not isinstance(route['hostname'], str)
                or re.fullmatch('[a-z0-9]{8}\\.router\\.example\\.com', route['hostname']) is None
                or not isinstance(route['ca_pem'], str) or not 1 <= len(route['ca_pem']) <= 16384):
            raise ValueError('Private route probe input unavailable')
    if routes['native']['hostname'] == routes['witness']['hostname']:
        raise ValueError('Private route probe input unavailable')
    return str(address), routes


def probe(address, route, label):
    connection = None
    try:
        context = ssl.create_default_context(cadata=route['ca_pem'])
        with socket.create_connection((address, 8443), timeout=3, source_address=(address, 0)) as raw:
            with context.wrap_socket(raw, server_hostname=route['hostname']) as secured:
                connection = http.client.HTTPConnection(route['hostname'], timeout=3)
                connection.sock = secured
                host = route['hostname'] + (':8443' if label == 'native' else '')
                connection.request('GET', '/', headers={'Host': host, 'Accept-Encoding': 'identity'})
                response = connection.getresponse()
                body = response.read(1024**2 + 1)
                if response.status != 200:
                    return 'http_rejected'
                if len(body) > 1024**2:
                    return 'payload_mismatch'
                matches = b'usernamefld' in body if label == 'native' else body == route['hostname'].encode('ascii')
                return 'verified' if matches else 'payload_mismatch'
    except (socket.timeout, TimeoutError):
        return 'timeout'
    except ssl.SSLCertVerificationError:
        return 'tls_identity_rejected'
    except (ssl.SSLEOFError, ssl.SSLZeroReturnError):
        return 'tls_closed'
    except ssl.SSLError:
        return 'tls_rejected'
    except (ConnectionError, OSError):
        return 'connect_failed'
    except (ValueError, http.client.HTTPException):
        return 'unavailable'
    finally:
        if connection is not None:
            connection.close()


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2:
        raise ValueError
    path = Path(sys.argv[1])
    info = path.lstat()
    if (path != path.resolve(strict=True) or not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1 or not 1 <= info.st_size <= 65536):
        raise ValueError
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError
            value[key] = item
        return value
    address, routes = validate(json.loads(path.read_bytes(), object_pairs_hook=unique))
    def deadline(*_):
        raise TimeoutError
    signal.signal(signal.SIGALRM, deadline)
    results = {}
    for name, route in routes.items():
        signal.alarm(4)
        try:
            results[name] = probe(address, route, name)
        finally:
            signal.alarm(0)
    print(json.dumps(results, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({'native': 'unavailable', 'witness': 'unavailable'}))
