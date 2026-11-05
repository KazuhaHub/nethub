"""Read a restored relay's private admin API and export only two proxy states."""
import base64
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import tomllib


def project(raw, identities):
    message = 'Restored relay observation unavailable'
    try:
        if (not isinstance(raw, bytes) or len(raw) > 1024**2 or len(identities) != 2
                or len(set(identities)) != 2 or any(re.fullmatch(
                    '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', value) is None
                    for value in identities)):
            raise ValueError
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError
                result[key] = value
            return result
        value = json.loads(raw, object_pairs_hook=unique)
        proxies = value['proxies']
        if not isinstance(proxies, list) or len(proxies) > 1024:
            raise ValueError
        states = {}
        for item in proxies:
            name, status = item['name'], item['status']
            if (not isinstance(name, str) or not 1 <= len(name) <= 512 or name in states
                    or status not in ('online', 'offline')):
                raise ValueError
            states[name] = status
        return {label: states.get('nethub-' + identity + '-web', 'absent')
                for label, identity in zip(('native_proxy', 'witness_proxy'), identities)}
    except (KeyError, TypeError, ValueError):
        raise ValueError(message) from None


def private(path, maximum):
    info = path.lstat()
    if (path != path.resolve(strict=True) or not stat.S_ISREG(info.st_mode)
            or info.st_uid != 65532 or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1 or not 1 <= info.st_size <= maximum):
        raise ValueError('Restored relay observation unavailable')
    return path.read_bytes()


def main():
    if os.geteuid() != 0 or len(sys.argv) != 4:
        raise ValueError
    directory = Path(sys.argv[1])
    info = directory.lstat()
    if (directory != directory.resolve(strict=True) or not directory.is_dir()
            or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError
    secrets = directory / 'secrets/frps'
    config = tomllib.loads(private(secrets / 'frps.toml', 32768).decode())
    web = config['webServer']
    address, port = ipaddress.IPv4Address(web['addr']), web['port']
    if (not address.is_private or address.is_unspecified or address.is_multicast
            or type(port) is not int or port != 7500):
        raise ValueError
    credentials = [private(secrets / name, 65).decode().strip()
                   for name in ('frps_admin_user', 'frps_admin_password')]
    if any(re.fullmatch('[a-f0-9]{64}', value) is None for value in credentials):
        raise ValueError
    connection = http.client.HTTPConnection(str(address), port, timeout=3)
    try:
        token = base64.b64encode(':'.join(credentials).encode()).decode()
        connection.request('GET', '/api/proxy/https', headers={
            'Authorization': 'Basic ' + token, 'Accept': 'application/json', 'Accept-Encoding': 'identity'})
        response = connection.getresponse()
        if response.status != 200 or response.getheader('Content-Encoding') is not None:
            raise ValueError
        result = project(response.read(1024**2 + 1), sys.argv[2:])
    finally:
        connection.close()
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
        print(json.dumps({'native_proxy': 'unavailable', 'witness_proxy': 'unavailable'}))
