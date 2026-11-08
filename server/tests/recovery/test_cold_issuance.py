"""Exercise timeout observation without exporting child output or mutating state."""
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import cold_flow as flow
import cold_issuance as observation
from cold_evidence import validate_operation
from cold_operation import failure


DEVICE = '11111111-1111-4111-8111-111111111111'
REQUEST = '22222222-2222-4222-8222-222222222222'
SERVICE = (b'ActiveState=inactive\nResult=success\nExecMainStatus=0\n'
           b'ExecMainStartTimestampMonotonic=123\nExecMainExitTimestampMonotonic=456\n')


class IssuerTimeoutObservation(unittest.TestCase):
    def row(self):
        return {'job_state': 'retry_wait', 'failure_code': 'transient', 'progress_phase': 'validating',
                'failures': 1, 'recoveries': 0, 'polls': 2, 'lease_present': False,
                'lease_expired': False, 'deadline_expired': False, 'retry_due': True,
                'generation_present': False}

    def host(self, row=None):
        return SimpleNamespace(query=Mock(return_value=json.dumps(self.row() if row is None else row)),
                               remote=Mock(side_effect=[SERVICE, b'active\n', b'active\n']))

    def test_original_job_status_uses_only_read_only_closed_queries(self):
        host = self.host()
        value = observation.collect_status(host, DEVICE, REQUEST)
        self.assertTrue(value['db_observed'] and value['job_present'])
        self.assertEqual(value['job_state'], 'retry_wait')
        self.assertEqual(value['progress_phase'], 'validating')
        self.assertEqual(value['issuer_exit'], 0)
        self.assertTrue(value['issuer_started'] and value['issuer_finished'])
        query = host.query.call_args.args[0]
        self.assertTrue(query.startswith('SELECT '))
        self.assertNotIn(';', query)
        self.assertNotIn('checkpoint', query)
        self.assertIn("j.device_id='" + DEVICE + "'", query)
        self.assertIn("j.request_id='" + REQUEST + "' AND j.generation=1", query)
        self.assertEqual(len(host.remote.call_args_list), 3)
        for call in host.remote.call_args_list:
            self.assertEqual(call.args[0][:2], ['/usr/bin/systemctl', 'show'])
            self.assertEqual(call.kwargs['timeout'], 10)
        self.assertEqual(host.remote.call_args_list[2].args[0][2], 'nethub-http01-cleanup.timer')
        self.assertNotIn(DEVICE, json.dumps(value))
        self.assertNotIn(REQUEST, json.dumps(value))

    def test_missing_database_row_differs_from_unavailable_database(self):
        host = self.host()
        host.query.return_value = ''
        missing = observation.collect_status(host, DEVICE, REQUEST)
        self.assertTrue(missing['db_observed'])
        self.assertFalse(missing['job_present'])
        self.assertEqual(missing['job_state'], 'missing')
        host = self.host()
        host.query.side_effect = RuntimeError('private password')
        value = observation.collect_status(host, DEVICE, REQUEST)
        self.assertFalse(value['db_observed'])
        self.assertEqual(value['job_state'], 'unavailable')
        self.assertEqual(value['issuer_result'], 'success')
        self.assertNotIn('private', json.dumps(value))

    def test_bad_child_output_is_never_exported_or_counted_as_observed(self):
        for raw in ('private checkpoint', 'x' * 2049,
                    json.dumps({**self.row(), 'private': 'secret'}),
                    json.dumps({**self.row(), 'job_state': 'private-url'}),
                    json.dumps({**self.row(), 'failures': True}),
                    json.dumps(self.row())[:-1] + ',"polls":3}'):
            host = self.host()
            host.query.return_value = raw
            host.remote.side_effect = [b'private service log', b'https://private.example', b'x' * 65]
            value = observation.collect_status(host, DEVICE, REQUEST)
            self.assertEqual(value, observation.unavailable())
            self.assertNotIn('private', json.dumps(value))

    def test_service_admission_rejects_unknown_duplicate_or_out_of_range_properties(self):
        for raw in (SERVICE + b'Private=secret\n', SERVICE.replace(b'Result=success', b'Result=private'),
                    SERVICE.replace(b'Result=success', b'ActiveState=active'),
                    SERVICE.replace(b'ExecMainStatus=0', b'ExecMainStatus=256'),
                    SERVICE.replace(b'Monotonic=123', b'Monotonic=-1'), b'x' * 2049):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                observation.service_status(raw)

    def test_invalid_identity_never_reaches_a_child(self):
        for item in ('invalid', 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA', DEVICE + "'", None):
            host = self.host()
            self.assertEqual(observation.collect_status(host, item, REQUEST), observation.unavailable())
            host.query.assert_not_called()
            host.remote.assert_not_called()

    def test_closed_projection_rejects_private_fields_types_and_ranges(self):
        value = observation.collect_status(self.host(), DEVICE, REQUEST)
        for key, item in (('private', 'secret'), ('progress_phase', 'private'), ('issuer_exit', True),
                          ('issuer_exit', 256), ('polls', -2), ('failures', 6), ('db_observed', 1),
                          ('job_state', []), ('issuer_started', None)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                observation.validate_status({**value, key: item})

    def test_deadline_failure_retains_observation_without_restarting_or_retrying_issuer(self):
        host = self.host()
        with patch.object(flow, 'issued', return_value=None) as issued, \
                patch.object(flow.time, 'monotonic', return_value=120), patch.object(flow.time, 'sleep') as sleep:
            with self.assertRaises(TimeoutError) as caught:
                flow.wait_issued(host, DEVICE, REQUEST, 120)
        issued.assert_called_once_with(host, DEVICE, REQUEST)
        sleep.assert_not_called()
        value = failure(caught.exception, 'a' * 40, 'issued_generation')
        self.assertFalse(value['passed'])
        self.assertEqual(value['failure_kind'], 'timeout')
        self.assertEqual(value['issuer_status']['progress_phase'], 'validating')
        self.assertEqual(validate_operation(value, 'a' * 40), value)
        self.assertNotIn('issuer_status', failure(caught.exception, 'a' * 40, 'timer_resume'))
        with self.assertRaises(ValueError):
            validate_operation({**value, 'phase': 'timer_resume'}, 'a' * 40)
        with self.assertRaises(ValueError):
            validate_operation({**value, 'issuer_status': {'private': 'secret'}}, 'a' * 40)

    def test_observation_failure_preserves_timeout_and_success_needs_no_observation(self):
        host = self.host()
        host.query.side_effect = RuntimeError('private output')
        host.remote.side_effect = RuntimeError('private output')
        with patch.object(flow, 'issued', return_value=None), patch.object(flow.time, 'monotonic', return_value=120):
            with self.assertRaises(TimeoutError) as caught:
                flow.wait_issued(host, DEVICE, REQUEST, 120)
        value = failure(caught.exception, 'a' * 40, 'issued_generation')
        self.assertEqual(value['issuer_status'], observation.unavailable())
        self.assertNotIn('private', json.dumps(value))
        caught.exception.issuer_status = {'private': 'secret'}
        self.assertNotIn('issuer_status', failure(caught.exception, 'a' * 40, 'issued_generation'))
        generation = {'id': REQUEST, 'leaf': 'a' * 64}
        with patch.object(flow, 'issued', return_value=generation), patch.object(flow, 'collect_status') as collect:
            self.assertEqual(flow.wait_issued(host, DEVICE, REQUEST, 120), generation)
            collect.assert_not_called()


if __name__ == '__main__':
    unittest.main()
