"""Fetch authenticated desired trust and retry confirmation without reinstalling."""
from datetime import datetime, timezone

from enrollment import request_json
from protocol import ProtocolError
from relay_trust import verify_settings
from relay_trust_backend import model_snapshot
from relay_trust_protocol import settings_request, applied_request
from relay_trust_transaction import TrustTransactionError


class TrustSyncError(Exception):
    """A fixed diagnostic independent of remote and native response content."""


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
        try:
            transaction.recover()
            current = transaction.backend.read()
            if current['device_id'] != device_id or current['server_name'] != server_name:
                raise ValueError('Native enrollment identity differs')
            history = transaction.read()
            previous = history['snapshot']['desired'] if history else None
            if previous is None and current['nodes']['relay_trust_state']:
                previous = model_snapshot(device_id, current['nodes'])['desired']
            response = request_json(origin, '/api/v1/devices/relay-trust/settings', settings_request(device_id),
                                    secret=secret, context=context)
            verified = verify_settings(response, device_id, server_name, transaction.config, previous=previous,
                now=datetime.fromtimestamp(transaction.clock(), timezone.utc), openssl=transaction.openssl)
            if verified['desired'] is None:
                return {'success': True, 'phase': 'pending', 'confirmed': False}
            result = transaction.apply(verified, binding=current['binding'])
            if result['phase'] != 'applied' or result['confirmed']:
                return result
            desired = verified['desired']
            report = applied_request(device_id, desired['generation_id'], desired['generation'], desired['bundle_fingerprint'])
            try:
                response = request_json(origin, '/api/v1/devices/relay-trust/applied', report, secret=secret, context=context)
                return transaction.confirm(response)
            except (ProtocolError, TrustTransactionError, OSError, ValueError, TypeError, KeyError):
                # Application remains good if the report reply is lost, stale,
                # rejected or unavailable. The next poll fetches before retry.
                return dict(result, phase='applied_unconfirmed', confirmed=False)
        except (ProtocolError, TrustTransactionError, OSError, ValueError, TypeError, KeyError):
            raise TrustSyncError('Relay trust synchronization failed; inspect local trust and recovery status') from None
