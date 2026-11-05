"""Verify the native login through the owned forwarded SNI route."""
import hashlib
import os
from pathlib import Path
import re
import socket
import ssl
import sys


def check(host, port, roots, fingerprint):
    if (sys.platform != 'linux' or os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or not isinstance(host, str) or re.fullmatch(r'[a-z0-9]{8}\.devices\.example\.test', host) is None
            or type(port) is not int or not 1024 <= port <= 65535
            or not isinstance(fingerprint, str) or re.fullmatch('[a-f0-9]{64}', fingerprint) is None):
        raise ValueError('Owned hosted native route required')
    roots = Path(roots)
    if (roots != roots.resolve(strict=True) or not roots.is_relative_to(Path(os.environ['RUNNER_TEMP']).resolve(strict=True))
            or not roots.is_file() or roots.stat().st_uid != 0 or roots.stat().st_mode & 0o077
            or roots.stat().st_nlink != 1 or not 256 <= roots.stat().st_size <= 32768):
        raise ValueError('Owned private route trust file required')
    context = ssl.create_default_context(cafile=str(roots))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname=host) as peer:
                if hashlib.sha256(peer.getpeercert(binary_form=True)).hexdigest() != fingerprint:
                    return False
                peer.sendall(('GET / HTTP/1.1\r\nHost: ' + host + ':8443\r\nConnection: close\r\n\r\n').encode('ascii'))
                with peer.makefile('rb') as response:
                    status = response.readline(4097)
                    if len(status) > 4096 or not re.fullmatch(rb'HTTP/1\.[01] 200 [^\r\n]*\r\n', status):
                        return False
                    body = response.read(32768)
                    return b'usernamefld' in body and b'passwordfld' in body
    except (OSError, ValueError):
        return False
