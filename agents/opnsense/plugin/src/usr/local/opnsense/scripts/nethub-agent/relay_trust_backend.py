"""Bounded PHP model operations; callers verify candidates and journal mutations."""
import base64
import json
import os
from pathlib import Path
import re
import subprocess

from enrollment import decode_json, _hostname, _UUID
from certificate_key import KeyStore
from protocol import ProtocolError


class NativeTrustError(Exception):
    """A fixed diagnostic without native settings or child-process output."""


def model_nodes(verified):
    """Encode an independently verified desired snapshot for the native model."""
    desired = verified['desired']
    metadata = {key: value for key, value in desired.items() if key != 'ca_pem'}
    return {'relay_ca': base64.b64encode(desired['ca_pem'].encode('ascii')).decode('ascii'),
            'relay_trust_state': base64.b64encode(KeyStore._encoded(metadata)).decode('ascii')}


def _nodes(value):
    if not isinstance(value, dict) or set(value) != {'relay_ca', 'relay_trust_state'}:
        raise ValueError('Invalid native trust nodes')
    result = {}
    for key, maximum in (('relay_ca', 32768), ('relay_trust_state', 4096)):
        encoded = value[key]
        if not isinstance(encoded, str) or len(encoded) > (maximum+2)//3*4:
            raise ValueError('Invalid native trust encoding')
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) > maximum or base64.b64encode(raw).decode('ascii') != encoded:
            raise ValueError('Invalid native trust encoding')
        result[key] = encoded
    return result


class NativeTrustBackend:
    """The root caller holds reconcile.lock; PHP owns all model writes.

    A replacement is compare-and-swap against both enrollment binding and exact
    before/after trust nodes. Only a separate transaction may decide application
    or rollback; a successful model write is not a successful tunnel reload.
    """

    def __init__(self, run=subprocess.run, configuration=Path('/conf/config.xml')):
        self.run = run
        self.configuration = Path(configuration)
        self.script = Path(__file__).with_name('relay_trust_model.php')

    def _call(self, action, request):
        try:
            if not hasattr(os, 'geteuid') or os.geteuid() != 0 or action not in ('read', 'install', 'rollback'):
                raise ValueError('Native trust operations require root')
            body = json.dumps({'action': action, 'request': request}, separators=(',', ':')).encode('ascii')
            if len(body) > 131072:
                raise ValueError('Native trust request exceeds its limit')
            result = self.run(['/usr/local/bin/php', str(self.script)], input=body, capture_output=True, timeout=5)
            if result.returncode or len(result.stdout) > 65536 or len(result.stderr) > 8192:
                raise ValueError('Native trust operation was not confirmed')
            response = decode_json(result.stdout)
            if set(response) != {'success', 'result'} or response['success'] is not True or not isinstance(response['result'], dict):
                raise ValueError('Invalid native trust response')
            return response['result']
        except (OSError, ValueError, TypeError, ProtocolError, subprocess.SubprocessError):
            raise NativeTrustError('Native relay trust operation failed') from None

    def read(self):
        try:
            value = self._call('read', [])
            if (set(value) != {'binding', 'device_id', 'server_name', 'nodes'}
                    or not isinstance(value['binding'], str) or not re.fullmatch('[a-f0-9]{64}', value['binding'])
                    or not isinstance(value['device_id'], str) or not _UUID.fullmatch(value['device_id'])
                    or not _hostname(value['server_name'])):
                raise ValueError('Invalid native trust identity')
            value['nodes'] = _nodes(value['nodes'])
            return value
        except (KeyError, TypeError, ValueError):
            raise NativeTrustError('Native relay trust operation failed') from None

    def replace(self, binding, before, after, rollback=False):
        try:
            if not isinstance(binding, str) or not re.fullmatch('[a-f0-9]{64}', binding):
                raise ValueError('Invalid native trust binding')
            request = {'binding': binding, 'before': _nodes(before), 'after': _nodes(after)}
            result = self._call('rollback' if rollback else 'install', request)
            if set(result) != {'selected', 'changed'} or result['selected'] is not True or type(result['changed']) is not bool:
                raise ValueError('Native trust write was not confirmed')
            # Core may atomically replace config.xml. Flush its real containing
            # directory before the transaction records this model phase durable.
            target = self.configuration.resolve(strict=True)
            descriptor = os.open(target.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            return result['changed']
        except (KeyError, OSError, ValueError, TypeError):
            raise NativeTrustError('Native relay trust operation failed') from None
