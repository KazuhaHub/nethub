"""Refuse compiler, source and target substitution in a rebuilt client."""
import importlib.util
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location('frpc_source', ROOT/'frpc_source.py')
SOURCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SOURCE)

INFO = '''/fixture/frpc: go1.26.10
    path github.com/fatedier/frp/cmd/frpc
    mod github.com/fatedier/frp v0.71.1 h1:fixture
    build -tags=frpc,noweb
    build CGO_ENABLED=0
    build GOOS=freebsd
    build GOARCH=amd64
    build GOAMD64=v1
'''


def test_expected_build_profile():
    SOURCE.check_build_info(INFO, 'go1.26.10', '0.71.1')


@pytest.mark.parametrize('before,after', [('go1.26.10', 'go1.26.8'),
    ('v0.71.1', 'v0.71.0'), ('cmd/frpc', 'cmd/frps'), ('GOOS=freebsd', 'GOOS=linux'),
    ('GOARCH=amd64', 'GOARCH=arm64'), ('GOAMD64=v1', 'GOAMD64=v3'), ('CGO_ENABLED=0', 'CGO_ENABLED=1'),
    ('-tags=frpc,noweb', '-tags=frpc'), ('mod github.com/fatedier/frp', 'dep github.com/fatedier/frp')])
def test_substituted_build_is_refused(before, after):
    with pytest.raises(ValueError):
        SOURCE.check_build_info(INFO.replace(before, after), 'go1.26.10', '0.71.1')


def test_existing_output_is_not_overwritten(tmp_path):
    output = tmp_path/'frpc'
    output.write_bytes(b'existing client')
    with pytest.raises(ValueError, match='must be new'):
        SOURCE.build(output)
    assert output.read_bytes() == b'existing client'


def test_wrong_compiler_stops_before_module_or_output_changes(tmp_path, monkeypatch):
    output = tmp_path/'not-created'/'frpc'
    calls = []
    monkeypatch.setattr(SOURCE.shutil, 'which', lambda _: '/fixture/go')

    def run(args, **kwargs):
        calls.append(args[1:])
        return 'go1.26.8\n'

    monkeypatch.setattr(SOURCE.subprocess, 'check_output', run)
    with pytest.raises(ValueError, match='installed Go compiler differs'):
        SOURCE.build(output)
    assert calls == [['env', 'GOVERSION']]
    assert not output.parent.exists()
