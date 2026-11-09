"""Database differences retain every comparison without exporting private values."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from database import (CATEGORIES, DETAIL_FIELDS, bootstrap_extensions, difference_details,
                      differing_categories, snapshot_fingerprint)
from database_probe import Probe, ProbeCommandFailure


class ClosedProbeCommandFailures(unittest.TestCase):
    def test_build_failure_exports_only_closed_classification(self):
        private = b'private repository, credential and SQL; unable to select packages'
        result = subprocess.CompletedProcess(['private argument'], 1, private, private)
        with tempfile.TemporaryDirectory() as directory:
            probe = Probe(Path(directory), Path(directory))
            with patch('database_probe.subprocess.run', return_value=result):
                with self.assertRaises(ProbeCommandFailure) as caught:
                    probe.command(['build', 'private argument'], data=private)
            self.assertEqual((Path(directory) / 'step-1.log').read_bytes(), private + private)
        self.assertEqual(caught.exception.report, {
            'action': 'build', 'kind': 'nonzero_exit', 'package_resolution_failed': True,
        })
        self.assertNotIn('private', str(caught.exception) + json.dumps(caught.exception.report))

    def test_timeout_does_not_export_child_output_or_unknown_action(self):
        error = subprocess.TimeoutExpired(['private argument'], 1, output=b'private output', stderr=b'private error')
        with tempfile.TemporaryDirectory() as directory:
            probe = Probe(Path(directory), Path(directory))
            with patch('database_probe.subprocess.run', side_effect=error):
                with self.assertRaises(ProbeCommandFailure) as caught:
                    probe.command(['private action'])
        self.assertEqual(caught.exception.report, {
            'action': 'unknown', 'kind': 'timeout', 'package_resolution_failed': False,
        })
        self.assertNotIn('private', str(caught.exception) + json.dumps(caught.exception.report))


class ClosedDatabaseDifferences(unittest.TestCase):
    def test_each_category_change_is_detected_without_private_values(self):
        original = [(name, 'private table, row, grant or credential') for name in CATEGORIES]
        for index, name in enumerate(CATEGORIES):
            with self.subTest(category=name):
                changed = copy.deepcopy(original)
                changed[index] = (name, 'different private value')
                self.assertNotEqual(snapshot_fingerprint(original), snapshot_fingerprint(changed))
                result = differing_categories(original, changed)
                self.assertEqual(result, [name])
                self.assertNotIn('private', str(result))
        self.assertEqual(differing_categories(original, original), [])

    def test_missing_rows_or_categories_are_not_ignored(self):
        original = [('table', 'private-table', 'private-row-hash'), ('roles', 'private-role')]
        self.assertEqual(differing_categories(original, original[1:]), ['table'])
        self.assertEqual(differing_categories(original, original[:1]), ['roles'])

    def test_unknown_category_is_refused_without_echoing_it(self):
        with self.assertRaises(ValueError) as caught:
            differing_categories([], [('private-category', 'private-value')])
        self.assertEqual(str(caught.exception), 'Unexpected recovery database category')

    def test_detail_fields_never_export_object_names_or_values(self):
        for category, (key_size, fields) in DETAIL_FIELDS.items():
            row = ['private identity or value'] * len(fields)
            before = [(category, json.dumps(row))]
            for index in range(key_size, len(fields)):
                changed = list(row)
                changed[index] = 'different private value'
                result = difference_details(before, [(category, json.dumps(changed))])
                self.assertEqual(result, {category: {'missing_objects': False,
                    'extra_objects': False, 'fields': [fields[index]]}})
                self.assertNotIn('private', str(result))
            missing = difference_details(before, [(category, '')])
            self.assertTrue(missing[category]['missing_objects'])
            self.assertNotIn('private', str(missing))

    def test_malformed_detail_rows_are_refused_without_echoing_them(self):
        for raw in ('private invalid JSON', '["private"]', '{}'):
            with self.assertRaises(ValueError) as caught:
                difference_details([('owners', raw)], [('owners', '')])
            self.assertEqual(str(caught.exception), 'Unexpected recovery database detail layout')

    def test_unapproved_source_extension_cannot_issue_sql_or_disclose_values(self):
        def forbidden(query):
            self.fail('Unapproved source must be refused before SQL')
        rows = [['pgcrypto', 'private-version', 'private-owner', 'public', True, [], None],
                ['plpgsql', '1.0', 'postgres', 'pg_catalog', False, [], None]]
        with self.assertRaises(ValueError) as caught:
            bootstrap_extensions(forbidden, [('extensions', '\n'.join(map(json.dumps, rows)))])
        self.assertEqual(str(caught.exception), 'Recovery extension inventory or ownership differs')

    def test_existing_extension_conflict_is_not_repaired_or_disclosed(self):
        rows = [['pgcrypto', '1.3', 'nethub_owner', 'public', True, [], None],
                ['plpgsql', '1.0', 'postgres', 'pg_catalog', False, [], None]]
        current = copy.deepcopy(rows)
        current[0][2] = 'private-wrong-owner'
        calls = []
        def read(query):
            calls.append(query)
            self.assertTrue(query.startswith('SELECT '))
            return '\n'.join(map(json.dumps, current))
        with self.assertRaises(ValueError) as caught:
            bootstrap_extensions(read, [('extensions', '\n'.join(map(json.dumps, rows)))])
        self.assertEqual(len(calls), 1)
        self.assertEqual(str(caught.exception), 'Recovery extension inventory or ownership differs')


if __name__ == '__main__':
    unittest.main()
