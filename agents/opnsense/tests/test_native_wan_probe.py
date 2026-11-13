"""Reject ambiguous guest addressing and unrelated or unestablished controls."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('native_wan_probe_test',
    Path(__file__).resolve().parents[1] / 'acceptance/wan_probe.py')
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class WANProbeTests(unittest.TestCase):
    def test_only_fixed_single_address_and_subnet(self):
        text = 'em1: flags=8843\n\tinet 10.0.2.15 netmask 0xffffff00 broadcast 10.0.2.255\n'
        self.assertEqual(probe.address(text, 'em1', probe.ADDRESSES), '10.0.2.15')
        for bad in (text.replace('em1:', 'em0:'), text + text.splitlines()[1],
                    text.replace('10.0.2.15', '192.0.2.15'),
                    text.replace('0xffffff00', '0xffff0000'),
                    text.replace('10.0.2.255', '10.0.2.254')):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                probe.address(bad, 'em1', probe.ADDRESSES)

    def test_socket_requires_original_process_and_established_state(self):
        header = ' '.join(probe.HEADER) + '\n'
        row = '0 frpc 123 8 tcp4 10.0.2.16:12345 10.0.2.100:7000 ESTABLISHED\n'
        self.assertEqual(probe.controls(header + row, 123), ['10.0.2.16'])
        self.assertEqual(probe.controls(' '.join(probe.TCP_HEADER) + '\n' + row, 123), ['10.0.2.16'])
        self.assertEqual(probe.controls(header + row, 124), [])
        self.assertEqual(probe.controls(header + row.replace('ESTABLISHED', 'SYN_SENT'), 123), [])
        self.assertEqual(probe.controls(header, 123), [])
        for bad in (header + row + row, header.replace('CONN', 'UNKNOWN') + row,
                    header + row.replace('0 frpc', '1000 frpc'),
                    header + row.replace('frpc', 'other'),
                    header + row.replace('tcp4', 'udp4'),
                    header + row.replace('10.0.2.100:7000', '192.0.2.1:7000'),
                    header + row.replace(':12345', ':65536')):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                probe.controls(bad, 123)

    def test_non_guest_and_unknown_operations_cannot_run_commands(self):
        with patch.object(probe.os, 'name', 'nt'), patch.object(probe, 'run') as run:
            with self.assertRaises(ValueError):
                probe.operation('change', 'a' * 32)
            run.assert_not_called()
        with patch.object(probe, 'boundary') as boundary:
            with self.assertRaises(ValueError):
                probe.operation('restart', 'a' * 32)
            boundary.assert_not_called()

    def test_restore_does_not_require_the_changed_default_route_before_repair(self):
        with (patch.object(probe, 'boundary', side_effect=['10.0.2.16', '10.0.2.15']) as boundary,
              patch.object(probe, 'gateway') as gateway,
              patch.object(probe, 'run') as run):
            self.assertEqual(probe.operation('restore', 'a' * 32), {'restored': True})
            self.assertEqual(boundary.call_args_list[0].kwargs, {'require_route': False})
            run.assert_called_once_with(['/sbin/ifconfig', 'em1', 'inet', '10.0.2.15', 'netmask', '255.255.255.0'])
            gateway.assert_called_once_with(repair=True)

    def test_missing_gateway_is_repaired_and_verified_after_address_change(self):
        header = 'Routing tables\n\nInternet:\nDestination Gateway Flags Netif Expire\n'
        expected = header + 'default 10.0.2.2 UGS em1\n'
        route = '   gateway: 10.0.2.2\n interface: em1\n'
        with patch.object(probe, 'run', side_effect=[header, '', expected, route]) as run:
            probe.gateway(repair=True)
            self.assertEqual(run.call_args_list[1].args[0],
                             ['/sbin/route', '-n', 'add', 'default', '10.0.2.2'])
            self.assertEqual(run.call_count, 4)
        with patch.object(probe, 'run', return_value=header) as run:
            with self.assertRaisesRegex(probe.ProbeError, '^wan_route_missing$'):
                probe.gateway()
            run.assert_called_once()

    def test_unexpected_or_ambiguous_gateway_is_never_replaced(self):
        header = 'Destination Gateway Flags Netif Expire\n'
        row = 'default 10.0.2.2 UGS em1\n'
        for text in (header + row.replace('10.0.2.2', '10.0.2.3'),
                     header + row.replace('em1', 'em0'), header + row + row,
                     header.replace('Netif', 'Unknown') + row):
            with self.subTest(text=text), patch.object(probe, 'run', return_value=text) as run:
                with self.assertRaises(probe.ProbeError):
                    probe.gateway(repair=True)
                run.assert_called_once_with(['/usr/bin/netstat', '-rn', '-f', 'inet'])

    def test_change_repairs_gateway_inside_the_single_mutation(self):
        with (patch.object(probe, 'boundary', return_value='10.0.2.15'),
              patch.object(probe, 'inspect', return_value={}),
              patch.object(probe, 'gateway') as gateway,
              patch.object(probe, 'run') as run):
            probe.operation('change', 'a' * 32)
            run.assert_called_once_with(['/sbin/ifconfig', 'em1', 'inet', '10.0.2.16', 'netmask', '255.255.255.0'])
            gateway.assert_called_once_with(repair=True)


if __name__ == '__main__':
    unittest.main()
