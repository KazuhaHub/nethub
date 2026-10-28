"""Recover credential rotation under one native mutation lock without re-enrollment."""
from enrollment import request_json
from rotation import RotationError
from rotation_backend import assignment, replacement


def rotate(journal, backend, reconcile, transport=request_json, rebind_trust=None):
    """Caller owns reconcile.lock. Never clear policy or revert a committed secret.

    Retain the received journal until native save/readback and ordinary idempotent
    reconcile succeed. After an interruption a second model save is unnecessary;
    reconcile can observe an already running identical configuration.
    """
    current = backend.read()
    value = journal.prepare(current['console_url'], assignment(current), native_before=current)
    before = value['native_before']
    if before is None:
        raise RotationError('Pending rotation has no native model binding; local review required')
    # Do not contact the server after policy/trust/configuration changed locally.
    if current != before:
        if value['phase'] != 'received' or current != replacement(before, value['assignment']):
            raise RotationError('Native settings changed during rotation; retain the journal for review')
    response = journal.request(current['console_url'], assignment(current), transport=transport)
    after = replacement(before, response)
    backend.install(before, after)
    saved = backend.read()
    if saved != after:
        raise RotationError('Native rotation save is unconfirmed; retain the journal')
    if rebind_trust is not None:
        rebind_trust(before, after)
    result = reconcile()
    if not isinstance(result, dict) or result.get('success') is not True:
        return {'success': False, 'action': 'rotate', 'phase': 'saved',
                'message': 'Credentials saved; tunnel reconciliation needs attention. Retry rotation to finish.'}
    journal.complete(saved['console_url'], assignment(saved))
    return {'success': True, 'action': 'rotate', 'phase': 'applied',
            'message': 'Credentials rotated; local access policy retained.'}
