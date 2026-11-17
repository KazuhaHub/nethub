"""Parse complete authz log records without accepting malformed or lost history."""
import json
import time


STARTUP = {b'Read-only relay observation enabled', b'Relay observation and anomaly confirmation enabled',
           b'Device enrollment API and internal relay hooks started'}
LIMIT = 8 * 1024 * 1024
HINT_KINDS = frozenset(('json_prefix', 'plain_prefix', 'runtime_fault', 'client_warning', 'service_failure',
    'runtime_exit', 'initial_snapshot_failure', 'initial_database_failure', 'revocation_liveness',
    'invalid_record', 'invalid_shape', 'invalid_size', 'history_changed', 'read_failed',
    'budget_expired', 'pending_tail_observed', 'pending_tail_completed'))


def hint(kind):
    if kind not in HINT_KINDS:
        raise ValueError('Closed relay log hint required')
    print('NETHUB_NATIVE_HINT=relay_hook_log_' + kind, flush=True)


def refuse(kind):
    hint(kind)
    raise AssertionError('Authz hook log snapshot could not be verified') from None


def invalid_record(line):
    hint('json_prefix' if line.lstrip().startswith((b'{', b'[')) else 'plain_prefix')
    if line.startswith((b'panic:', b'fatal error:', b'goroutine ')):
        hint('runtime_fault')
    if line.startswith(b'WARNING:'):
        hint('client_warning')
    failures = {b'Authz HTTP service stopped unexpectedly': 'runtime_exit',
                b'Initial relay revocation snapshot is unavailable': 'initial_snapshot_failure',
                b'Authz database connection failed; check settings and the authz password file': 'initial_database_failure'}
    if line in failures:
        hint('service_failure')
        hint(failures[line])
    refuse('invalid_record')


def hook_events(read, *, now=time.monotonic, pause=time.sleep):
    """One normal read; at most one second to complete an unterminated tail.

    read(remaining) must retain the same container identity and cap a retry's
    underlying I/O at remaining seconds. Every observed byte must be retained.
    This never retries a terminated invalid record or changes cutoff deadlines.
    """
    previous, deadline = None, None
    while True:
        remaining = None if deadline is None else deadline - now()
        if remaining is not None and remaining <= 0:
            refuse('budget_expired')
        try:
            raw = read(remaining)
        except Exception:
            refuse('read_failed')
        if deadline is not None and now() > deadline:
            refuse('budget_expired')
        if not isinstance(raw, bytes) or len(raw) >= LIMIT:
            refuse('invalid_size')
        if previous is not None and not raw.startswith(previous):
            refuse('history_changed')
        lines, events = raw.splitlines(), []
        for index, line in enumerate(lines):
            if not line.strip() or line in STARTUP:
                continue
            try:
                record = json.loads(line)
            except (ValueError, UnicodeDecodeError):
                if index == len(lines) - 1 and not raw.endswith(b'\n'):
                    if deadline is None:
                        deadline = now() + 1
                        hint('pending_tail_observed')
                    previous = raw
                    break
                invalid_record(line)
            if not isinstance(record, dict):
                refuse('invalid_shape')
            if record.get('msg') == 'Authz HTTP service stopped unexpectedly':
                hint('runtime_exit')
                if record.get('reason') == 'revocation_liveness':
                    hint('revocation_liveness')
            if record.get('msg') == 'Relay hook decision':
                events.append(record)
        else:
            if previous is not None:
                hint('pending_tail_completed')
            return events
        remaining = deadline - now()
        if remaining <= 0:
            refuse('budget_expired')
        pause(min(0.02, remaining))
