"""Check complete fetched history and exercise narrow public-value exceptions."""
import argparse
import ast
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = '8.30.1'
PUBLIC_SPKI = json.loads((ROOT / 'proto/examples/valid/enroll-bound-response.json').read_text())['gui_key_fingerprint']
PUBLIC_CSR_SPKI = json.loads((ROOT / 'proto/examples/valid/certificate-submit-response.json').read_text())['gui_key_fingerprint']
PUBLIC_RELEASE_KEY = next(node.value.value for node in ast.walk(ast.parse((ROOT / 'weekend0/vm_preflight.py').read_text()))
                          if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'KEY_SHA256'
                                                                 for target in node.targets))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scanner', type=Path, required=True)
    scanner = parser.parse_args().scanner.resolve(strict=True)
    version = subprocess.check_output([str(scanner), 'version'], text=True, timeout=10).strip()
    assert version == VERSION, 'Use the pinned scanner version'
    shallow = subprocess.check_output(['git', 'rev-parse', '--is-shallow-repository'], cwd=ROOT, text=True).strip()
    assert shallow == 'false', 'Fetch complete history before credential checks'
    config = ROOT / '.gitleaks.toml'
    with tempfile.TemporaryDirectory(prefix='nethub-credential-check-') as temporary:
        directory = Path(temporary)
        ignore = directory / 'empty-ignore'
        ignore.write_text('')

        def scan(mode, source, label, history=False):
            report = directory / (label + '.json')
            args = [str(scanner), mode, str(source) if history else '.', '--config', str(config),
                    '--gitleaks-ignore-path', str(ignore), '--ignore-gitleaks-allow',
                    '--redact=100', '--no-banner', '--no-color', '--report-format=json',
                    '--report-path', str(report), '--timeout=60' if history else '--timeout=8']
            if history:
                args.append('--log-opts=--all --full-history')
            result = subprocess.run(args, capture_output=True, timeout=75 if history else 12,
                                    cwd=ROOT if history else source,
                                    env=dict(os.environ, GIT_NO_REPLACE_OBJECTS='1'))
            assert result.returncode in (0, 1), 'Scanner failed; no clean result established'
            findings = json.loads(report.read_text())
            assert isinstance(findings, list)
            assert (result.returncode == 0) == (not findings)
            return findings

        def control(label, files, expected):
            fixture = directory / label
            fixture.mkdir()
            for name, data in files.items():
                path = fixture / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(data)
            findings = scan('dir', fixture, label)
            assert bool(findings) == expected, 'Credential exception control failed: ' + label
            if expected:
                assert any(finding['RuleID'] == 'generic-api-key' for finding in findings)

        allowed = 'proto/examples/valid/enroll-bound-response.json'
        line = '  "gui_key_fingerprint": "' + PUBLIC_SPKI + '",\n'
        release = 'KEY_SHA256 = "' + PUBLIC_RELEASE_KEY + '"\n'
        control('approved-public-values', {
            allowed: line,
            'proto/examples/valid/certificate-submit-response.json':
                '  "gui_key_fingerprint": "' + PUBLIC_CSR_SPKI + '",\n',
            'weekend0/vm_preflight.py': release,
        }, False)
        control('changed-fingerprint', {
            allowed: '  "gui_key_fingerprint": "' + secrets.token_hex(32) + '",\n',
        }, True)
        control('adjacent-credential', {
            allowed: line + 'api_key = "' + secrets.token_urlsafe(32) + '"\n',
        }, True)
        control('wrong-path', {'other.json': line}, True)
        control('same-line-credential', {
            'weekend0/vm_preflight.py': release.rstrip() + '; api_key = "' + secrets.token_urlsafe(32) + '"\n',
        }, True)
        findings = scan('git', ROOT, 'history', history=True)
        if findings:
            locations = [{key: finding.get(key) for key in ['RuleID', 'File', 'StartLine', 'Commit']}
                         for finding in findings]
            print(json.dumps({'credential_findings': locations}))
            raise SystemExit(1)
    print('Credential history scan passed with default rules, full fetched history and five exception controls; reports and matches were not published')


if __name__ == '__main__':
    main()
