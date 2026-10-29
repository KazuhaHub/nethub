"""Require actual root filesystem cases, never a skipped or partial green log."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess


ROOTS = ('TestNativeRelayTokenJournal', 'TestNativeRelayTokenMaterial')
JOURNAL = ('ordered durable records and immutable intent', 'concurrent different candidates have one winner',
           'symlink', 'hardlink', 'unknown field', 'mode', 'owner', 'orphan', 'removed directory')
MATERIAL = ('exact retained material and independent complete successor', 'candidate', 'authority', 'runtime',
            'missing current leaf', 'extra backup file', 'mode', 'hardlink', 'symlink', 'manifest',
            'unknown metadata', 'different request', 'different backup', 'maintenance', 'old backup', 'cancelled')
REQUIRED = set(ROOTS) | {ROOTS[0] + '/' + name.replace(' ', '_') for name in JOURNAL} | {
    ROOTS[1] + '/' + name.replace(' ', '_') for name in MATERIAL}


def summarize(raw, exit_code, capture_exit, uid):
    if (type(exit_code) is not int or exit_code != 0 or type(capture_exit) is not int or capture_exit != 0
            or type(uid) is not int or uid != 0 or not isinstance(raw, bytes) or not 1 <= len(raw) <= 1024**2):
        raise ValueError('Actual root contract execution required')
    lines = raw.decode('utf-8').splitlines()
    if lines[-1] != 'PASS' or any('--- SKIP:' in line or '--- FAIL:' in line for line in lines):
        raise ValueError('Every selected contract must pass without skips')
    passed = []
    for line in lines:
        match = re.fullmatch(r'\s*--- PASS: ([A-Za-z0-9_/]{1,240}) \([0-9.]+s\)', line)
        if match:
            name = match[1]
            if not any(name == root or name.startswith(root + '/') for root in ROOTS):
                raise ValueError('Unexpected contract namespace')
            passed.append(name)
    if len(passed) != len(set(passed)) or not REQUIRED.issubset(passed):
        raise ValueError('Required root filesystem cases are missing')
    return sorted(passed)


def bounded_file(path, maximum):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= maximum:
        raise ValueError('Bounded regular contract evidence required')
    return path.read_bytes()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('log', 'binary', 'receipt'):
        parser.add_argument('--' + name, required=True, type=Path)
    for name in ('exit-code', 'capture-exit', 'uid'):
        parser.add_argument('--' + name, required=True, type=int)
    parser.add_argument('--source-head', required=True)
    parser.add_argument('--compiler', required=True)
    args = parser.parse_args()
    receipt = {'version': 1, 'passed': False, 'full_incident_acceptance': False, 'full_goal_complete': False}
    try:
        head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], timeout=10).decode('ascii').strip()
        expected_go = 'go' + (Path(__file__).resolve().parents[1] / '.go-version').read_text().strip()
        if not re.fullmatch('[a-f0-9]{40}', args.source_head) or head != args.source_head or args.compiler != expected_go:
            raise ValueError('Exact source and compiler required')
        passed = summarize(bounded_file(args.log, 1024**2), args.exit_code, args.capture_exit, args.uid)
        binary = bounded_file(args.binary, 100 * 1024**2)
        receipt.update(passed=True, source_head=head, compiler=args.compiler, uid=args.uid,
                       cases_passed=passed, binary_sha256=hashlib.sha256(binary).hexdigest())
    except Exception:
        receipt['failure'] = 'root_contracts_failed'
    args.receipt.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    if receipt['passed'] is not True:
        raise SystemExit('Protected relay token contracts failed; receipt retained')
    print('Protected relay token contracts passed:', len(receipt['cases_passed']))


if __name__ == '__main__':
    main()
