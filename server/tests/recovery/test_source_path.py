"""Reject hairpin sources and stale grants before opening a browser forward."""
import copy
import unittest

from source_path import matching_grant, select_source


class SourcePath(unittest.TestCase):
    def setUp(self):
        self.routes = [{'dev': 'ens3', 'prefsrc': '10.0.2.15'}]
        self.interfaces = [{'ifname': 'ens3', 'addr_info': [
            {'family': 'inet', 'local': '10.0.2.15', 'scope': 'global'}]}]
        self.edge = '172.30.87.0/24'

    def test_primary_owned_source_outside_edge(self):
        self.assertEqual(select_source(self.routes, self.interfaces, self.edge), '10.0.2.15')

    def test_container_loopback_public_and_unspecified_sources_are_refused(self):
        for address in ('172.30.87.1', '127.0.0.1', '8.8.8.8', '0.0.0.0', '224.0.0.1'):
            with self.subTest(address=address), self.assertRaises(ValueError):
                select_source([{'dev': 'ens3', 'prefsrc': address}], self.interfaces, self.edge)

    def test_foreign_interface_and_ambiguous_route_are_refused(self):
        for routes in ([], self.routes * 2, [{'dev': 'docker0', 'prefsrc': '10.0.2.15'}],
                       [{'dev': 'ens3', 'prefsrc': '10.0.2.15', 'type': 'blackhole'}]):
            with self.subTest(routes=routes), self.assertRaises(ValueError):
                select_source(routes, self.interfaces, self.edge)

    def test_non_global_or_duplicate_interface_ownership_is_refused(self):
        interfaces = copy.deepcopy(self.interfaces)
        interfaces[0]['addr_info'][0]['scope'] = 'host'
        for value in (interfaces, self.interfaces * 2):
            with self.assertRaises(ValueError):
                select_source(self.routes, value, self.edge)

    def test_exact_fresh_actor_source_and_instant_are_required(self):
        row = {'source': '10.0.2.15', 'actor': 'original', 'expiry': '2026-11-04T12:00:00.123456+00:00'}
        expiry = '2026-11-04T12:00:00.123456Z'
        matching_grant([row], row['source'], row['actor'], expiry)
        # A newer unrelated grant cannot select routing or satisfy the response.
        unrelated = dict(row, source='172.30.87.1', expiry='2099-01-01T00:00:00Z')
        matching_grant([unrelated, row], row['source'], row['actor'], expiry)
        for rows in ([], [unrelated], [dict(row, actor='other')], [dict(row, expiry=expiry.replace('123456', '123455'))], [row, row]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                matching_grant(rows, row['source'], row['actor'], expiry)

    def test_naive_expiries_are_refused(self):
        with self.assertRaises(ValueError):
            matching_grant([], '10.0.2.15', 'original', '2026-11-04T12:00:00')


if __name__ == '__main__':
    unittest.main()
