"""Database differences retain every comparison without exporting private values."""
import copy
import unittest

from database import CATEGORIES, differing_categories, snapshot_fingerprint


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


if __name__ == '__main__':
    unittest.main()
