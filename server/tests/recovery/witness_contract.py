"""Admit only the independent private CA's fixed cold-recovery ready message."""
import ipaddress
from pathlib import PurePosixPath
import re
from urllib.parse import urlsplit


def valid_ready(value, assigned_host, control):
    keys = {'version', 'host', 'directory_url', 'contact_email', 'api_roots_file',
            'certificate_roots_file', 'account_backup_directory', 'http01_route_file',
            'forward_address', 'forward_port'}
    try:
        if (not isinstance(value, dict) or set(value) != keys or type(value['version']) is not int
                or value['version'] != 1 or value['host'] != assigned_host
                or re.fullmatch(r'[a-z0-9]{8}\.devices\.example\.test', assigned_host) is None
                or value['contact_email'] != 'admin@example.test'
                or type(value['forward_port']) is not int or not 1024 <= value['forward_port'] <= 65535):
            return False
        root = PurePosixPath(control)
        if (not root.is_absolute() or str(root) != control or '..' in root.parts
                or re.fullmatch(r'nethub-cold-witness-[a-f0-9]{16}', root.name) is None):
            return False
        gateway = ipaddress.IPv4Address(value['forward_address'])
        if str(gateway) != value['forward_address'] or gateway.packed[:2] != bytes((172, 30)):
            return False
        if not 100 <= gateway.packed[2] < 250 or gateway.packed[3] != 1:
            return False
        directory = urlsplit(value['directory_url'])
        if (value['directory_url'] != 'https://' + str(gateway + 1) + ':14000/dir'
                or directory.scheme != 'https' or directory.port != 14000):
            return False
        stage = PurePosixPath(value['api_roots_file']).parent
        if not stage.is_relative_to(root / 'tmp') or stage == root / 'tmp':
            return False
        expected = {'api_roots_file': stage / 'api-root.pem',
                    'certificate_roots_file': stage / 'issuing-root.pem',
                    'account_backup_directory': stage / 'account-registered',
                    'http01_route_file': root / 'http01.caddy'}
        return all(isinstance(value[key], str) and str(path) == value[key]
                   and '..' not in path.parts and '\\' not in value[key]
                   and not any(ord(char) < 32 for char in value[key])
                   for key, path in expected.items())
    except (KeyError, TypeError, ValueError, AttributeError):
        return False
