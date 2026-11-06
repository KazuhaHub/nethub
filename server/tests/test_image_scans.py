"""Execute the real image-scan shell block with controlled Docker outcomes."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SHELL = (str(Path('C:/Program Files/Git/bin/bash.exe')) if os.name == 'nt'
         else shutil.which('sh'))
ROLES = ['runtime', 'postgres', 'caddy', 'frps', 'backup']
PREFIX = r'''
set -eu
stage=$SCAN_STAGE
image=runtime
postgres_image=postgres
caddy_image=caddy
frps_image=frps
backup_image=backup
python3() { "$SCAN_PYTHON" "$@"; }
docker() {
    if [ "$1 $2" = 'image save' ]; then
        role=$5
        printf 'export:%s\n' "$role" >> "$SCAN_TRACE"
        if [ "$role" = "$SCAN_EXPORT_FAILURE" ]; then return 1; fi
        printf 'fixture image %s\n' "$role" > "$4"
        return 0
    fi
    if [ "$1" = run ]; then
        role=
        for argument in "$@"; do
            case "$argument" in
                /scan/*.json) role=${argument#/scan/}; role=${role%.json} ;;
            esac
        done
        [ -n "$role" ]
        printf 'scan:%s\n' "$role" >> "$SCAN_TRACE"
        printf '{"Results":[]}\n' > "$stage/scans/$role.json"
        case ",$SCAN_FAILURES," in *,"$role",*) return 1 ;; esac
        return 0
    fi
    return 97
}
'''


@unittest.skipUnless(SHELL and Path(SHELL).is_file(), 'POSIX shell required')
class ImageScanGate(unittest.TestCase):
    def exercise(self, failures='', export_failure=''):
        source = (ROOT / 'server/tests/compose.sh').read_text(encoding='utf-8')
        start = source.index('if [ "${NETHUB_SCAN_IMAGES:-0}" = 1 ]; then\n')
        end = source.index('\nnative_setup_phase frps_smoke\n', start)
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory).resolve()
            trace = stage / 'trace'
            env = {**os.environ, 'NETHUB_SCAN_IMAGES': '1', 'SCAN_STAGE': stage.as_posix(),
                   'SCAN_TRACE': trace.as_posix(), 'SCAN_FAILURES': failures,
                   'SCAN_EXPORT_FAILURE': export_failure,
                   'SCAN_PYTHON': Path(sys.executable).as_posix()}
            result = subprocess.run([SHELL, '-s'], input=PREFIX + source[start:end],
                                    env=env, capture_output=True, text=True, timeout=20)
            steps = trace.read_text().splitlines() if trace.exists() else []
        return result, steps

    def test_one_failed_scan_does_not_hide_other_image_results(self):
        result, steps = self.exercise('runtime')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(steps, [step for role in ROLES for step in ('export:' + role, 'scan:' + role)])
        self.assertIn('Vulnerability check failed for runtime image', result.stderr)
        self.assertNotIn('All five assembled', result.stdout)

    def test_every_failed_scan_is_reported_without_success(self):
        result, steps = self.exercise(','.join(ROLES))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sum(step.startswith('scan:') for step in steps), 5)
        for role in ROLES:
            self.assertIn('Vulnerability check failed for ' + role + ' image', result.stderr)
        self.assertNotIn('All five assembled', result.stdout)

    def test_export_failure_never_scans_a_stale_image_or_passes(self):
        result, steps = self.exercise(failures='runtime', export_failure='postgres')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(steps, [step for role in ROLES for step in
                                (('export:' + role,) if role == 'postgres'
                                 else ('export:' + role, 'scan:' + role))])
        self.assertIn('Image export failed for postgres image', result.stderr)
        self.assertNotIn('All five assembled', result.stdout)

    def test_success_requires_all_five_actual_exports_and_scans(self):
        result, steps = self.exercise()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(steps, [step for role in ROLES for step in ('export:' + role, 'scan:' + role)])
        self.assertEqual(result.stdout.count('All five assembled deployment images passed'), 1)


if __name__ == '__main__':
    unittest.main()
