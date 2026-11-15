"""Keep uncertain packet-loss mutations bounded to the original owned tuple."""
import copy
from contextlib import ExitStack
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import relay_control_drop as drop
from relay_combined_fault import _exercise_combined_fault, exercise_combined_fault, pressure_baseline


class Rules:
    def __init__(self, failure=None):
        self.chain = self.link = self.entry = False
        self.calls = []
        self.failure = failure
        self.foreign = False

    def run(self, arguments, **_kwargs):
        assert arguments[:3] == ['/owned/iptables', '-w', '2']
        args = arguments[3:]
        self.calls.append(args)
        action = args[0]
        output, status = b'', 0
        if action == '-S' and args[1] == 'OUTPUT':
            output = b'-P OUTPUT ACCEPT\n' + (b'owned tuple\n' if self.link else b'')
        elif action == '-S':
            status = 0 if self.chain else 1
            if self.chain:
                output = ('-N ' + args[1] + '\n' + ('-A ' + args[1] + ' -j DROP\n' if self.entry else '')
                    + ('-A ' + args[1] + ' -j ACCEPT\n' if self.foreign else '')).encode()
        elif action == '-N':
            self.chain = True
        elif action == '-A':
            self.entry = True
        elif action == '-I':
            self.link = True
        elif action == '-C':
            status = 0 if self.link else 1
        elif action == '-D' and args[1] == 'OUTPUT':
            self.link = False
        elif action == '-D':
            self.entry = False
        elif action == '-X':
            assert not self.link and not self.entry and not self.foreign
            self.chain = False
        elif action == '-nvx':
            output = b'2 152 DROP all -- * * 0.0.0.0/0 0.0.0.0/0\n' if self.link else b'0 0 DROP all -- * * 0.0.0.0/0 0.0.0.0/0\n'
        else:
            raise AssertionError('Unexpected rule operation')
        if action == self.failure:
            self.failure = None
            raise subprocess.TimeoutExpired(arguments, 3)
        return SimpleNamespace(returncode=status, stdout=output, stderr=b'')


class ControlDropTests(unittest.TestCase):
    def setup_context(self, directory, rules, stack=None):
        handlers = {}

        def handler(number, value):
            previous = handlers.get(number, signal.SIG_DFL)
            handlers[number] = value
            return previous

        enter = self.enterContext if stack is None else stack.enter_context
        enter(patch.object(drop.os, 'geteuid', return_value=0, create=True))
        enter(patch.object(drop.shutil, 'which', return_value='/owned/iptables'))
        enter(patch.object(drop.subprocess, 'run', side_effect=rules.run))
        enter(patch.object(drop.signal, 'signal', side_effect=handler))
        return drop.ControlDrop(('127.0.0.1:52001', '127.0.0.1:7000', '123'), Path(directory) / 'rules'), handlers

    def test_actual_counters_and_original_output_are_restored(self):
        with tempfile.TemporaryDirectory() as directory:
            rules = Rules()
            context, handlers = self.setup_context(directory, rules)
            with context:
                self.assertEqual(context.counters(), {'packets': 2, 'bytes': 152})
            self.assertTrue(context.restored)
            self.assertFalse(rules.chain or rules.entry or rules.link)
            self.assertLessEqual(context.started, context.removed)
            self.assertEqual(set(handlers.values()), {signal.SIG_DFL})
            self.assertFalse(any(args[0] in ('-F', '-P') for args in rules.calls))

    def test_unconfirmed_rule_mutation_is_inspected_and_removed_without_replay(self):
        for operation in ('-N', '-A', '-I'):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as directory:
                rules = Rules(operation)
                # Patches must leave scope before the next independent attempt.
                with ExitStack() as stack:
                    context, _ = self.setup_context(directory, rules, stack)
                    with self.assertRaises(subprocess.TimeoutExpired):
                        with context:
                            self.fail('Unconfirmed rule insertion was accepted')
                    self.assertTrue(context.restored)
                    self.assertFalse(rules.chain or rules.entry or rules.link)
                    self.assertEqual(sum(args[0] == operation for args in rules.calls), 1)

    def test_body_failure_and_signal_restore_owned_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            rules = Rules()
            context, _ = self.setup_context(directory, rules)
            with self.assertRaisesRegex(ValueError, 'original failure'):
                with context:
                    raise ValueError('original failure')
            self.assertTrue(context.restored)
            self.assertFalse(rules.link or rules.chain)

    def test_interruption_is_delayed_until_atomic_command_finishes(self):
        with tempfile.TemporaryDirectory() as directory:
            rules = Rules()
            context, _ = self.setup_context(directory, rules)
            with self.assertRaises(SystemExit):
                with context:
                    context.interrupt(signal.SIGTERM, None)
                    context.counters()
            self.assertTrue(context.restored)
            self.assertFalse(rules.link or rules.chain)

    def test_unknown_chain_content_is_preserved_after_own_link_is_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            rules = Rules()
            context, _ = self.setup_context(directory, rules)
            with self.assertRaisesRegex(ValueError, 'changed unexpectedly'):
                with context:
                    rules.foreign = True
            self.assertFalse(context.restored)
            self.assertFalse(rules.link)
            self.assertTrue(rules.chain and rules.foreign)
            self.assertFalse(any(args[0] in ('-X', '-F') for args in rules.calls))

    def test_nonroot_context_is_rejected_without_network_mutation(self):
        with patch.object(drop.os, 'geteuid', return_value=1, create=True), patch.object(drop.subprocess, 'run') as run:
            with self.assertRaises(ValueError):
                drop.ControlDrop(('127.0.0.1:52001', '127.0.0.1:7000', '123'), Path('/unused'))
            run.assert_not_called()


class CombinedPressureTests(unittest.TestCase):
    def test_only_actual_retained_pressure_counts_are_accepted(self):
        valid = {'synthetic_revoked_rows': 99000, 'synthetic_rotation_floors': 99000,
                 'global_revoked_rows': 99001, 'global_rotation_floors': 99000, 'tenants': 1}
        pressure_baseline(valid)
        for key, value in [('synthetic_revoked_rows', 98999), ('synthetic_rotation_floors', 0),
                           ('global_revoked_rows', 100001), ('global_rotation_floors', True), ('tenants', True)]:
            changed = copy.deepcopy(valid)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                pressure_baseline(changed)

    def test_twelve_distinct_references_are_required_before_any_mutation(self):
        valid = {'synthetic_revoked_rows': 99000, 'synthetic_rotation_floors': 99000,
                 'global_revoked_rows': 99001, 'global_rotation_floors': 99000, 'tenants': 1}
        for references in ([SimpleNamespace(pid=i) for i in range(11)], [SimpleNamespace(pid=1)] * 12):
            with self.assertRaises(ValueError):
                _exercise_combined_fault('/unused', None, references, valid, *([None] * 8))

    def test_unowned_platform_is_rejected_before_any_mutation(self):
        with self.assertRaises(ValueError):
            exercise_combined_fault('/unused', [], [], {}, *([None] * 8))


if __name__ == '__main__':
    unittest.main()
