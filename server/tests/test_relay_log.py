"""Keep every record and reject malformed, changed or unfinished authz history."""
from contextlib import redirect_stdout
import io
import json
import unittest

import relay_log


class Clock:
    value = 0

    def now(self):
        return self.value

    def pause(self, seconds):
        self.value += seconds


class RelayLogTests(unittest.TestCase):
    def collect(self, read, clock=None):
        clock = clock or Clock()
        with redirect_stdout(io.StringIO()):
            return relay_log.hook_events(read, now=clock.now, pause=clock.pause)

    def test_complete_records_and_known_startup_keep_the_existing_policy(self):
        event = {'msg': 'Relay hook decision', 'operation': 'Ping', 'decision': 'device_denied'}
        raw = b'\n'.join(sorted(relay_log.STARTUP)) + b'\n\n' + json.dumps({'msg': 'Other JSON event'}).encode()
        raw += b'\n' + json.dumps(event).encode()
        calls = []
        self.assertEqual(self.collect(lambda remaining: calls.append(remaining) or raw), [event])
        self.assertEqual(calls, [None])

    def test_partial_tail_waits_without_losing_or_duplicating_earlier_events(self):
        first = json.dumps({'msg': 'Relay hook decision', 'operation': 'Login'}).encode() + b'\n'
        tail = b'{"msg":"Relay hook decision","operation":"Ping"}\n'
        raw = [first + tail[:25], first + tail]
        calls = []
        def read(remaining):
            calls.append(remaining)
            return raw.pop(0)
        result = self.collect(read)
        self.assertEqual([v['operation'] for v in result], ['Login', 'Ping'])
        self.assertEqual(calls[0], None)
        self.assertTrue(0 < calls[1] <= 1)
        self.assertEqual(raw, [])

    def test_terminated_invalid_record_is_never_retried_or_exported(self):
        for raw in (b'private-value is not JSON\n', b'{"private-value":bad}\n', b'{"msg":"\xff"}\n'):
            with self.subTest(raw=raw):
                calls, output = [], io.StringIO()
                with redirect_stdout(output), self.assertRaisesRegex(AssertionError, '^Authz hook log snapshot could not be verified$'):
                    relay_log.hook_events(lambda remaining: calls.append(remaining) or raw)
                self.assertEqual(calls, [None])
                self.assertNotIn('private-value', output.getvalue())
                self.assertIn('relay_hook_log_invalid_record', output.getvalue())

    def test_json_non_object_remains_refused(self):
        for raw in (b'[]\n', b'null\n', b'"private-value"\n'):
            with self.subTest(raw=raw), self.assertRaises(AssertionError):
                self.collect(lambda remaining: raw)

    def test_changed_prefix_cannot_drop_the_original_partial_record(self):
        raw = [b'{"msg":"Relay hook', b'{"msg":"different"}\n']
        with self.assertRaises(AssertionError):
            self.collect(lambda remaining: raw.pop(0))
        self.assertEqual(raw, [])

    def test_unfinished_tail_refuses_at_the_bound(self):
        clock, calls = Clock(), []
        with self.assertRaises(AssertionError):
            self.collect(lambda remaining: calls.append(remaining) or b'{"msg":"unfinished', clock)
        self.assertLessEqual(clock.value, 1)
        self.assertLessEqual(len(calls), 51)
        self.assertTrue(all(0 < value <= 1 for value in calls[1:]))

    def test_completion_after_the_bound_is_not_accepted(self):
        clock, calls = Clock(), []
        def read(remaining):
            calls.append(remaining)
            if remaining is None:
                return b'{"msg":"unfinished'
            clock.value += remaining + .01
            return b'{"msg":"unfinished"}\n'
        with self.assertRaises(AssertionError):
            self.collect(read, clock)
        self.assertEqual(len(calls), 2)

    def test_reader_error_does_not_export_exception_or_command(self):
        output = io.StringIO()
        def read(_remaining):
            raise RuntimeError('private command and credentials')
        with redirect_stdout(output), self.assertRaises(AssertionError) as caught:
            relay_log.hook_events(read)
        self.assertNotIn('private', output.getvalue() + str(caught.exception))
        self.assertTrue(caught.exception.__suppress_context__)

    def test_size_and_type_bounds_remain_enforced(self):
        for raw in (b'x' * relay_log.LIMIT, 'private-value'):
            with self.subTest(kind=type(raw)), self.assertRaises(AssertionError):
                self.collect(lambda remaining: raw)

    def test_unknown_hint_is_never_exported(self):
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaisesRegex(ValueError, '^Closed relay log hint required$'):
            relay_log.hint('private-value')
        self.assertEqual(output.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
