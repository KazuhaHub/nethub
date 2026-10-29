"""Reject skipped, substituted and partial protected-host receipts."""
import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location('relay_token_contracts', Path(__file__).with_name('relay-token-contracts.py'))
CONTRACTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTRACTS)


def passing():
    return ''.join('--- PASS: ' + name + ' (0.01s)\n' for name in sorted(CONTRACTS.REQUIRED)).encode() + b'PASS\n'


class ReceiptTests(unittest.TestCase):
    def test_complete_selected_cases(self):
        self.assertEqual(set(CONTRACTS.summarize(passing(), 0, 0, 0)), CONTRACTS.REQUIRED)

    def test_false_green_and_wrong_execution_fail(self):
        for name in ('exit', 'capture', 'uid', 'skip', 'failure', 'missing', 'duplicate', 'foreign', 'final', 'oversized'):
            with self.subTest(name=name):
                raw, code, capture, uid = passing(), 0, 0, 0
                if name == 'exit': code = 1
                elif name == 'capture': capture = 1
                elif name == 'uid': uid = 1001
                elif name == 'skip': raw = b'--- SKIP: unavailable root\n' + raw
                elif name == 'failure': raw = b'--- FAIL: filesystem\n' + raw
                elif name == 'missing': raw = raw.split(b'\n', 1)[1]
                elif name == 'duplicate': raw = raw.split(b'\n', 1)[0] + b'\n' + raw
                elif name == 'foreign': raw = b'--- PASS: Unrelated (0.01s)\n' + raw
                elif name == 'final': raw += b'not a complete test result\n'
                else: raw = b'x' * (1024**2 + 1)
                with self.assertRaises(ValueError): CONTRACTS.summarize(raw, code, capture, uid)


if __name__ == '__main__':
    unittest.main()
