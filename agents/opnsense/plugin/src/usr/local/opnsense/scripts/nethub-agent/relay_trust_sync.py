"""Fetch authenticated desired trust and retry confirmation without reinstalling."""
from datetime import datetime, timezone
import http.client
import socket
import ssl

from enrollment import request_json
from protocol import ProtocolError
from relay_trust import verify_settings
from relay_trust_backend import model_snapshot, NativeTrustError
from relay_trust_protocol import settings_request, applied_request
from relay_trust_transaction import TrustTransactionError


class TrustSyncError(Exception):
    """A fixed diagnostic independent of remote and native response content."""

    STAGES = ('recover', 'native_snapshot', 'binding', 'history', 'request', 'verify', 'apply', 'report', 'unclassified')
    KINDS = ('protocol', 'protocol_dns', 'protocol_connect', 'protocol_timeout', 'protocol_tls_verify',
             'protocol_tls', 'protocol_http', 'protocol_rejected', 'transaction', 'native', 'storage',
             'value', 'type', 'key', 'unclassified')

    def __init__(self, stage='unclassified', kind='unclassified'):
        super().__init__('Relay trust synchronization failed; inspect local trust and recovery status')
        self.stage = stage
        self.kind = kind

    def diagnostic(self):
        return {'version': 1,
                'stage': self.stage if isinstance(self.stage, str) and self.stage in self.STAGES else 'unclassified',
                'kind': self.kind if isinstance(self.kind, str) and self.kind in self.KINDS else 'unclassified'}


def protocol_failure_kind(error):
    """Classify fixed local exception types without copying remote text or data."""
    cause = error.__context__
    for kind, types in (
            ('protocol_tls_verify', (ssl.SSLCertVerificationError,)),
            ('protocol_tls', (ssl.SSLError,)), ('protocol_dns', (socket.gaierror,)),
            ('protocol_timeout', (TimeoutError,)), ('protocol_http', (http.client.HTTPException,)),
            ('protocol_connect', (ConnectionError,))):
        if isinstance(cause, types):
            return kind
    if str(error) == 'Console rejected the device request; check enrollment and connectivity':
        return 'protocol_rejected'
    return 'protocol'


class TrustSynchronizer:
    """The caller checks activation/lifecycle intent and holds reconcile.lock.

    This component has no scheduler or production startup hook. The transaction
    must provide an approved native model backend and bounded reload/recovery.
    All HTTPS uses the configured console origin and its independent trust roots.
    Every poll fetches current desired state before any report retry, including
    after stale409 or a lost report reply. Delivery alone never reports applied.
    """

    def __init__(self, transaction):
        self.transaction = transaction

    def sync(self, origin, secret, device_id, server_name, context=None):
        transaction = self.transaction
        stage = 'recover'
        try:
            transaction.recover()
            stage = 'native_snapshot'
            current = transaction.backend.read()
            stage = 'binding'
            if current['device_id'] != device_id or current['server_name'] != server_name:
                raise ValueError('Native enrollment identity differs')
            stage = 'history'
            history = transaction.read()
            previous = history['snapshot']['desired'] if history else None
            if previous is None and current['nodes']['relay_trust_state']:
                previous = model_snapshot(device_id, current['nodes'])['desired']
            stage = 'request'
            response = request_json(origin, '/api/v1/devices/relay-trust/settings', settings_request(device_id),
                                    secret=secret, context=context)
            stage = 'verify'
            verified = verify_settings(response, device_id, server_name, transaction.config, previous=previous,
                now=datetime.fromtimestamp(transaction.clock(), timezone.utc), openssl=transaction.openssl)
            if verified['desired'] is None:
                return {'success': True, 'phase': 'pending', 'confirmed': False}
            stage = 'apply'
            result = transaction.apply(verified, binding=current['binding'])
            if result['phase'] != 'applied' or result['confirmed']:
                return result
            stage = 'report'
            desired = verified['desired']
            report = applied_request(device_id, desired['generation_id'], desired['generation'], desired['bundle_fingerprint'])
            try:
                response = request_json(origin, '/api/v1/devices/relay-trust/applied', report, secret=secret, context=context)
                return transaction.confirm(response)
            except (ProtocolError, TrustTransactionError, OSError, ValueError, TypeError, KeyError):
                # Application remains good if the report reply is lost, stale,
                # rejected or unavailable. The next poll fetches before retry.
                return dict(result, phase='applied_unconfirmed', confirmed=False)
        except (ProtocolError, TrustTransactionError, NativeTrustError, OSError, ValueError, TypeError, KeyError) as error:
            kind = next(name for error_type, name in (
                (ProtocolError, 'protocol'), (TrustTransactionError, 'transaction'), (NativeTrustError, 'native'),
                (OSError, 'storage'), (ValueError, 'value'), (TypeError, 'type'), (KeyError, 'key'))
                if isinstance(error, error_type))
            if kind == 'protocol':
                kind = protocol_failure_kind(error)
            raise TrustSyncError(stage, kind) from None
