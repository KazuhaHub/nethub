"""Exercise sampling integrity and the Q2 decision boundaries with synthetic data."""
import csv
from datetime import datetime, timedelta, timezone
import importlib.util
import io
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('network_summary', Path(__file__).with_name('network_summary.py'))
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)


def rows(baseline=20, tunnel=20):
    result = []
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for round_number in range(1, 21):
        for port, successes in [(443, baseline), (8443, tunnel)]:
            connected = round_number <= successes
            result.append({
                'Network': 'A', 'Round': str(round_number), 'Port': str(port),
                'StartedUtc': (start + timedelta(seconds=len(result))).isoformat(),
                'CurlExit': '0' if connected else '28', 'HttpCode': '200' if connected else '000',
                'TcpConnected': str(connected), 'TimeConnect': '0.03' if connected else '0',
                'TimeAppConnect': '0.1' if connected else '0',
                'TimeTotal': '0.13' if connected else '5', 'AddressFamily': 'IPv4',
            })
    return result


def encode(values):
    output = io.StringIO(newline='')
    writer = csv.DictWriter(output, fieldnames=list(values[0]))
    writer.writeheader()
    writer.writerows(values)
    return output.getvalue().encode('utf-8-sig')


class NetworkSummaryTests(unittest.TestCase):
    def test_twenty_point_boundary(self):
        for successes, triggered in [(17, False), (16, True)]:
            with self.subTest(tunnel=successes):
                result = summary.summarize(encode(rows(tunnel=successes)))
                self.assertEqual(result['q2_triggered'], triggered)
                self.assertEqual(result['difference_percentage_points'], 5 * (20 - successes))

    def test_zero_tunnel_triggers_even_when_baseline_is_zero(self):
        result = summary.summarize(encode(rows(0, 0)))
        self.assertTrue(result['q2_triggered'])
        self.assertTrue(result['both_ports_zero'])
        self.assertIsNone(result['ports']['8443']['tcp_median_seconds'])

    def test_tls_failure_does_not_become_tcp_failure(self):
        values = rows()
        values[1].update(CurlExit='35', HttpCode='000', TimeAppConnect='0')
        result = summary.summarize(encode(values))
        self.assertEqual(result['ports']['8443']['tcp_successes'], 20)
        self.assertEqual(result['ports']['8443']['tls_completed'], 19)
        self.assertEqual(result['ports']['8443']['curl_successes'], 19)
        self.assertFalse(result['q2_triggered'])

    def test_complete_data_does_not_certify_external_provenance(self):
        result = summary.summarize(encode(rows()))
        self.assertTrue(result['complete_alternating_sample'])
        self.assertFalse(result['external_network_provenance_verified'])
        self.assertFalse(result['experiment_4_accepted'])

    def test_missing_duplicate_and_reordered_rows_are_rejected(self):
        missing = rows()[:-1]
        duplicate = rows()
        duplicate[1] = duplicate[0].copy()
        reordered = rows()
        reordered[0], reordered[1] = reordered[1], reordered[0]
        for values in [missing, duplicate, reordered]:
            with self.subTest(count=len(values)):
                with self.assertRaises(summary.InvalidSample):
                    summary.summarize(encode(values))

    def test_mixed_networks_and_raw_address_columns_are_rejected(self):
        mixed = rows()
        mixed[-1]['Network'] = 'B'
        raw = rows()
        for row in raw:
            row['SourceAddress'] = 'withheld'
        for values in [mixed, raw]:
            with self.assertRaises(summary.InvalidSample):
                summary.summarize(encode(values))

    def test_invalid_timing_and_inconsistent_tcp_status_are_rejected(self):
        mutations = [
            {'TimeConnect': 'nan'}, {'TimeTotal': '-1'}, {'TimeAppConnect': 'inf'},
            {'TcpConnected': 'False'}, {'TimeConnect': '0.2'}, {'TimeAppConnect': '0.01'},
            {'StartedUtc': '2026-01-01'}, {'CurlExit': '-1'},
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                values = rows()
                values[0].update(mutation)
                with self.assertRaises(summary.InvalidSample):
                    summary.summarize(encode(values))


if __name__ == '__main__':
    unittest.main()
