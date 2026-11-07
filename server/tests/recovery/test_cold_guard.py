"""Exercise cleanup interruption and ownership refusals without host mutation."""
import hashlib
from pathlib import Path
import tempfile
import os
import sys
import unittest
from unittest.mock import patch

import cold_guard as guard


class ColdGuardAdmission(unittest.TestCase):
    def test_witness_cleanup_inherits_only_verified_hosted_identity(self):
        control = Path('/owned/nethub-cold-recovery-' + 'a' * 16)
        with patch.object(guard, 'control_identity', return_value='a' * 16) as identity, \
                patch.dict(os.environ, {'GH_TOKEN': 'private token', 'GITHUB_TOKEN': 'private token'}), \
                patch.object(guard.subprocess, 'run', side_effect=OSError('private child failure')) as run:
            with self.assertRaises(guard.GuardError):
                guard.command(control, ['/usr/bin/python3', '-I', '/owned/cleanup.py'], hosted_context=True)
        identity.assert_called_once_with(control)
        environment = run.call_args.kwargs['env']
        self.assertEqual(environment, {**guard.ENVIRONMENT, 'GITHUB_ACTIONS': 'true',
                         'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_TEMP': str(control.parent)})
        self.assertNotIn('GH_TOKEN', environment)
        self.assertNotIn('GITHUB_TOKEN', environment)

    def test_foreign_hosted_identity_cannot_launch_witness_cleanup(self):
        with patch.object(guard, 'control_identity', side_effect=guard.GuardError('fixture foreign owner')), \
                patch.object(guard.subprocess, 'run') as run:
            with self.assertRaises(guard.GuardError):
                guard.command(Path('/foreign'), ['/usr/bin/python3'], hosted_context=True)
        run.assert_not_called()

    def test_state_cannot_select_foreign_source_or_program(self):
        nonce = 'a' * 16
        original = {'version': 1, 'nonce': nonce, 'source_head': 'b' * 40,
                    'guard_sha256': 'c' * 64, 'witness_sha256': 'd' * 64}
        self.assertTrue(guard.valid_state(original, nonce))
        for key, value in (('version', True), ('nonce', 'e' * 16), ('source_head', '../main'),
                           ('guard_sha256', 'invalid'), ('witness_sha256', None)):
            with self.subTest(field=key):
                self.assertFalse(guard.valid_state({**original, key: value}, nonce))
        self.assertFalse(guard.valid_state({**original, 'extra': True}, nonce))

    def test_foreign_operation_is_not_stopped(self):
        control = Path('/owned/nethub-cold-recovery-' + 'a' * 16)
        with patch.object(guard, 'property_value', side_effect=['loaded', 'Unrelated operation']), \
                patch.object(guard, 'command') as command:
            with self.assertRaises(guard.GuardError):
                guard.stop_operation(control, 'a' * 16)
            command.assert_not_called()

    def test_active_witness_prevents_private_namespace_removal(self):
        witness = Path('/owned/nethub-cold-witness-' + 'a' * 16)
        with patch.object(guard, 'property_value', side_effect=['loaded', 'active']), \
                patch.object(guard, 'absent_resource') as absent:
            with self.assertRaises(guard.GuardError):
                guard.witness_absent(Path('/unexecuted'), witness)
            absent.assert_not_called()

    def test_missing_witness_after_prepared_removal_requires_fresh_absence_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            control = parent / ('nethub-cold-recovery-' + 'a' * 16)
            control.mkdir()
            (control / 'witness.json').write_text('private fixture pointer')
            witness = parent / ('nethub-cold-witness-' + 'b' * 16)
            binding = hashlib.sha256(str(witness).encode()).hexdigest()
            prepared = {'version': 1, 'witness_control_fingerprint': binding,
                        'resource_cleanup_confirmed_before_removal': True}
            values = {control / 'witness.json': {'version': 1, 'control': str(witness)},
                      control / 'witness-removal-prepared.json': prepared}
            with patch.object(guard, 'read_json', side_effect=lambda p: values[p]), \
                    patch.object(guard, 'witness_absent') as absent, patch.object(guard, 'save_once') as save:
                self.assertTrue(guard.clean_witness(control, {}))
                absent.assert_called_once_with(control, witness)
                self.assertEqual(save.call_count, 1)
            with patch.object(guard, 'read_json', side_effect=lambda p: values[p]), \
                    patch.object(guard, 'witness_absent', side_effect=guard.GuardError('fixture unavailable')), \
                    patch.object(guard, 'save_once') as save:
                with self.assertRaises(guard.GuardError):
                    guard.clean_witness(control, {})
                save.assert_not_called()


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'actual root-owned Linux files required')
class ActualGuardFiles(unittest.TestCase):
    def test_receipt_is_immutable_private_and_atomic_failure_leaves_no_partial_final(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            path = parent / 'receipt.json'
            value = {'version': 1, 'fixture': True}
            guard.save_once(path, value)
            self.assertEqual(guard.read_json(path), value)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            guard.save_once(path, value)
            with self.assertRaises(guard.GuardError):
                guard.save_once(path, {'version': 2})
            interrupted = parent / 'interrupted.json'
            with patch.object(guard.os, 'link', side_effect=OSError('fixture interrupted publication')):
                with self.assertRaises(OSError):
                    guard.save_once(interrupted, value)
            self.assertFalse(interrupted.exists())
            self.assertEqual({p.name for p in parent.iterdir()}, {'receipt.json'})

    def test_recursive_removal_preserves_aliased_or_foreign_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            original, alias = parent / 'original', parent / 'alias'
            original.mkdir(mode=0o700)
            (original / 'retained').write_text('fixture original')
            alias.symlink_to(original, target_is_directory=True)
            with self.assertRaises(guard.GuardError):
                guard.remove_owned_directory(alias, parent)
            with self.assertRaises(guard.GuardError):
                guard.remove_owned_directory(original, parent / 'unrelated')
            self.assertEqual((original / 'retained').read_text(), 'fixture original')
            guard.remove_owned_directory(original, parent)
            self.assertFalse(original.exists())


if __name__ == '__main__':
    unittest.main()
