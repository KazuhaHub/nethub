"""Prevent a packet-loss fixture from targeting another endpoint or faking counters."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent))
from relay_network_blip import drop_counters, owned_tuple


class OwnedNetworkFaultTests(unittest.TestCase):
    def test_only_one_ephemeral_loopback_control_can_be_selected(self):
        self.assertEqual(owned_tuple(('127.0.0.1:52001', '127.0.0.1:7000', '123')),
            ['-p', 'tcp', '-s', '127.0.0.1', '--sport', '52001', '-d', '127.0.0.1', '--dport', '7000'])

    def test_public_private_admin_and_noncanonical_tuples_are_refused(self):
        for binding in [('192.0.2.1:52001', '127.0.0.1:7000', '123'),
                ('127.0.0.1:52001', '192.0.2.1:7000', '123'),
                ('127.0.0.1:52001', '127.0.0.1:22', '123'),
                ('127.0.0.1:52001', '127.0.0.1:7500', '123'),
                ('127.0.0.1:7000', '127.0.0.1:7000', '123'),
                ('127.0.0.1:80', '127.0.0.1:7000', '123'),
                ('127.0.0.1:052001', '127.0.0.1:7000', '123'),
                ('[::1]:52001', '[::1]:7000', '123'),
                ('127.0.0.1:52001', '127.0.0.1:7000', '0'), None]:
            with self.subTest(binding=binding), self.assertRaises(ValueError):
                owned_tuple(binding)

    def test_exact_packet_and_byte_counts_are_read_without_rounding(self):
        raw = b'Chain owned (1 references)\n pkts bytes target prot opt in out source destination\n 2 152 DROP all -- * * 0.0.0.0/0 0.0.0.0/0\n'
        self.assertEqual(drop_counters(raw), {'packets': 2, 'bytes': 152})

    def test_missing_duplicate_or_invalid_drop_counters_are_refused(self):
        row = b'2 152 DROP all -- * * 0.0.0.0/0 0.0.0.0/0\n'
        for raw in [b'', row + row, row.replace(b'2 152', b'-1 152'), row.replace(b'2 152', b'2 unknown'), b'2 152 DROP\n']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                drop_counters(raw)


if __name__ == '__main__':
    unittest.main()
