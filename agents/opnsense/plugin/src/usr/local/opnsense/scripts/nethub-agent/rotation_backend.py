"""Pass private native rotation snapshots over stdin; PHP owns configuration."""
import base64
import json
import os
from pathlib import Path
import subprocess

from enrollment import decode_json, validate_response, validate_origin
from protocol import ProtocolError, VERSION
from rotation import RotationError

FIELDS = ('console_url', 'device_id', 'device_secret', 'frp_token', 'server_addr', 'server_port',
          'server_name', 'subdomain', 'domain_claim', 'relay_ca', 'relay_trust_state', 'enabled')


def assignment(nodes):
    if (not isinstance(nodes, dict) or set(nodes) != set(FIELDS)
            or any(not isinstance(value, str) for value in nodes.values())
            or nodes['enabled'] not in ('0', '1') or not nodes['server_port'].isdigit()
            or str(int(nodes['server_port'])) != nodes['server_port']):
        raise RotationError('Invalid native rotation snapshot')
    validate_origin(nodes['console_url'])
    pem = base64.b64decode(nodes['relay_ca'], validate=True)
    if base64.b64encode(pem).decode('ascii') != nodes['relay_ca']:
        raise RotationError('Invalid native rotation trust')
    value = {key: nodes[key] for key in ('device_id', 'device_secret', 'frp_token', 'server_addr',
                                        'server_name', 'subdomain', 'domain_claim')}
    value.update(agent_protocol_version=VERSION, server_port=int(nodes['server_port']), relay_ca_pem=pem.decode('ascii'))
    return validate_response(value)


def replacement(before, response):
    """Preserve policy and managed trust; a separate trust operation owns CA changes."""
    current = assignment(before)
    response = validate_response(response)
    if (response['device_id'] != current['device_id'] or response['subdomain'] != current['subdomain']
            or response['relay_ca_pem'] != current['relay_ca_pem']
            or before['relay_trust_state'] and response['server_name'] != current['server_name']):
        raise RotationError('Update relay trust before completing credential rotation')
    after = dict(before)
    for key in ('device_secret', 'frp_token', 'server_addr', 'server_name', 'domain_claim'):
        after[key] = response[key]
    after['server_port'] = str(response['server_port'])
    return after


class NativeRotationBackend:
    """The root caller holds reconcile.lock across read, HTTP and install/readback."""

    def __init__(self, run=subprocess.run, configuration=Path('/conf/config.xml')):
        self.run = run
        self.configuration = Path(configuration)
        self.script = Path(__file__).with_name('rotation_model.php')

    def _call(self, action, request):
        try:
            if not hasattr(os, 'geteuid') or os.geteuid() != 0 or action not in ('read', 'install'):
                raise ValueError('Native rotation requires root')
            data = json.dumps({'action': action, 'request': request}, separators=(',', ':')).encode('ascii')
            if len(data) > 131072:
                raise ValueError('Native rotation input exceeds its limit')
            result = self.run(['/usr/local/bin/php', str(self.script)], input=data, capture_output=True, timeout=5)
            if result.returncode or len(result.stdout) > 65536 or len(result.stderr) > 8192:
                raise ValueError('Native rotation failed')
            value = decode_json(result.stdout)
            if set(value) != {'success', 'result'} or value['success'] is not True or not isinstance(value['result'], dict):
                raise ValueError('Invalid native rotation response')
            return value['result']
        except (OSError, ValueError, TypeError, ProtocolError, subprocess.SubprocessError):
            raise RotationError('Native rotation model operation failed') from None

    def read(self):
        try:
            value = self._call('read', [])
            if set(value) != {'nodes'}:
                raise ValueError('Invalid native snapshot')
            assignment(value['nodes'])
            return value['nodes']
        except (KeyError, ValueError, TypeError, ProtocolError, RotationError):
            raise RotationError('Native rotation model operation failed') from None

    def install(self, before, after):
        assignment(before)
        assignment(after)
        result = self._call('install', {'before': before, 'after': after})
        if set(result) != {'selected', 'changed'} or result['selected'] is not True or type(result['changed']) is not bool:
            raise RotationError('Native rotation model save is unconfirmed')
        target = self.configuration.resolve(strict=True)
        descriptor = os.open(target.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if self.read() != after:
            raise RotationError('Native rotation model save is unconfirmed')
        return result['changed']
