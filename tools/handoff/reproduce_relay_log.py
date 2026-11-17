#!/usr/bin/env python3
"""Reproduce Docker log framing with a pinned helper and an owned local container."""
import argparse
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
SOURCE = '2523ab981f953e0a4d5dce994fbdff593d09d8fe'
PROGRAM = r'''printf '{"msg":"Relay hook decision","padding":"' >&2
head -c 20000 /dev/zero | tr '\000' x >&2
touch /tmp/ready
while [ ! -e /control/release ]; do sleep 0.01; done
printf '"}\n' >&2
while [ ! -e /control/stop ]; do sleep 0.01; done
'''


def command(arguments, timeout=10):
    return subprocess.check_output(arguments, stderr=subprocess.DEVNULL, timeout=timeout)


def reproduce(source):
    if not re.fullmatch('[a-f0-9]{40}', source):
        raise ValueError('A complete reviewed source commit is required')
    endpoint = os.environ.get('DOCKER_HOST')
    if endpoint is None:
        endpoint = command(['docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}']).decode().strip()
    if not endpoint.startswith('unix://'):
        raise ValueError('A local Docker endpoint is required')
    helper = command(['git', '-C', str(ROOT), 'show', source + ':server/tests/relay_log.py'])
    dockerfile = command(['git', '-C', str(ROOT), 'show', source + ':deploy/Dockerfile']).decode()
    image = next(line.split()[1] for line in dockerfile.splitlines()
                 if line.startswith('FROM ') and line.split()[-1] == 'build')
    if not re.fullmatch(r'[a-z0-9./:_-]+@sha256:[a-f0-9]{64}', image):
        raise ValueError('The recorded build image must be pinned')
    image_id = command(['docker', 'image', 'inspect', '--format', '{{.Id}}', image]).decode().strip()
    result = {'version': 1, 'scope': 'Owned local Docker log framing only',
              'framing_reproduction_passed': False, 'product_native_or_public_accepted': False,
              'helper_source_commit': source, 'helper_sha256': hashlib.sha256(helper).hexdigest(),
              'runtime_image': image, 'runtime_image_id': image_id, 'log_driver': 'json-file'}
    with tempfile.TemporaryDirectory(prefix='nethub-log-framing-', dir='/tmp') as temporary:
        stage, container = Path(temporary), None
        try:
            path = stage / 'relay_log.py'
            path.write_bytes(helper)
            spec = importlib.util.spec_from_file_location('recorded_relay_log', path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            name = 'nethub-log-framing-' + uuid.uuid4().hex[:16]
            identifier = command(['docker', 'create', '--pull', 'never', '--name', name,
                '--network', 'none', '--cpus', '1', '--memory', '64m', '--pids-limit', '32',
                '--log-driver', 'json-file', '--log-opt', 'max-size=1m', '--log-opt', 'max-file=1',
                '--volume', str(stage) + ':/control:ro', image, '/bin/sh', '-eu', '-c', PROGRAM]).decode().strip()
            if not re.fullmatch('[a-f0-9]{64}', identifier):
                raise ValueError('Owned container identity was not confirmed')
            container = identifier
            command(['docker', 'start', container])
            deadline = time.monotonic() + 10
            while subprocess.run(['docker', 'exec', container, 'test', '-f', '/tmp/ready'],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2).returncode:
                if time.monotonic() >= deadline:
                    raise ValueError('Owned log producer did not become ready')
                time.sleep(0.05)
            # Docker routes container stderr to the CLI's stderr. Capture both
            # streams exactly as the existing acceptance reader does.
            calls = []
            def read(remaining):
                calls.append(remaining)
                raw = subprocess.check_output(['docker', 'logs', container], stderr=subprocess.STDOUT,
                    timeout=10 if remaining is None else remaining)
                if len(calls) == 1:
                    result['first_bytes'] = len(raw)
                    result['first_ends_newline'] = raw.endswith(b'\n')
                    try:
                        json.loads(raw)
                        result['first_json_valid'] = True
                    except ValueError:
                        result['first_json_valid'] = False
                    (stage / 'release').touch()
                return raw
            with redirect_stdout(io.StringIO()):
                events = module.hook_events(read)
            complete = subprocess.check_output(['docker', 'logs', container], stderr=subprocess.STDOUT, timeout=10)
            result.update(reader_calls=len(calls), parsed_events=len(events), completed_bytes=len(complete),
                          all_padding_preserved=len(events) == 1 and events[0].get('padding') == 'x' * 20000,
                          completed_json_valid=isinstance(json.loads(complete), dict))
            assert result['first_bytes'] > 0 and result['first_json_valid'] is False
            assert result['first_ends_newline'] is False and result['all_padding_preserved']
            result['framing_reproduction_passed'] = True
        except Exception:
            result['framing_reproduction_passed'] = False
            result['failure_kind'] = 'bounded_fixture_error'
        finally:
            removed = container is None or subprocess.run(['docker', 'rm', '-f', container],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10).returncode == 0
            result['owned_container_cleanup_confirmed'] = removed
            result['framing_reproduction_passed'] = result['framing_reproduction_passed'] and removed
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-commit', default=SOURCE)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        result = reproduce(args.source_commit)
    except Exception:
        print('Local framing reproduction unavailable; use a complete clone, local Docker and its cached pinned build image.')
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0 if result['framing_reproduction_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
