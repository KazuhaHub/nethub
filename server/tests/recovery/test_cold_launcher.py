"""Refuse a non-hosted launcher before inspecting or mutating resources."""
from pathlib import Path
import unittest
from unittest.mock import patch

import cold_launcher as launcher
from cold_guard import GuardError


class LauncherAdmission(unittest.TestCase):
    def test_unowned_environment_cannot_run_git_or_stage_files(self):
        with patch.dict(launcher.os.environ, {'GITHUB_ACTIONS': 'false'}), \
                patch.object(launcher, 'invoke') as invoke, patch.object(launcher, 'stage_file') as stage:
            with self.assertRaises(GuardError):
                launcher.run(Path('/unexecuted'), None, {}, None, None)
            invoke.assert_not_called()
            stage.assert_not_called()


if __name__ == '__main__':
    unittest.main()
