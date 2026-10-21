"""Execute package pre-removal ordering with isolated command fixtures."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(os.name == 'nt', reason='FreeBSD package hooks run in a POSIX shell')
ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('recovery_exit', [0, 1])
@pytest.mark.parametrize('failing_stage', ['trust', 'gui'])
def test_failed_pending_recovery_aborts_removal_before_any_service_stop(tmp_path, recovery_exit, failing_stage):
    tmp_path.chmod(0o700)
    state, logs, binary = [tmp_path / name for name in ('state', 'logs', 'bin')]
    binary.mkdir()
    rc = tmp_path / 'rc-agent'
    rc.write_text('#!/bin/sh\nexit 0\n')
    rc.chmod(0o755)
    recovery = tmp_path / 'recover.py'
    gui_event = tmp_path/'gui-recovery-called'
    recovery.write_text('from pathlib import Path\nPath('+repr(str(gui_event))+').touch()\nraise SystemExit(' + str(recovery_exit if failing_stage == 'gui' else 0) + ')\n')
    trust = tmp_path/'trust-recover.py'
    trust.write_text('raise SystemExit('+str(recovery_exit if failing_stage == 'trust' else 0)+')\n')
    lock = tmp_path / 'locked.py'
    lock.write_text('import os,sys\nos.execv(sys.argv[2],sys.argv[2:])\n')
    events = tmp_path / 'service-events.jsonl'
    service = binary / 'service'
    service.write_text('#!' + sys.executable + '\nimport json,sys\nfrom pathlib import Path\np=Path(' + repr(str(events)) +
                       ')\nwith p.open("a") as f:f.write(json.dumps(sys.argv[1:])+"\\n")\n')
    service.chmod(0o755)
    text = (ROOT / 'packaging/freebsd/+PRE_DEINSTALL').read_text()
    for original, replacement in {
        '/usr/local/etc/rc.d/nethub_agent_frpc': str(rc),
        '/var/db/nethub-agent': str(state), '/var/log/nethub-agent': str(logs),
        '/usr/local/opnsense/scripts/nethub-agent/certificate_recover.py': str(recovery),
        '/usr/local/opnsense/scripts/nethub-agent/relay_trust_recover.py': str(trust),
        '/usr/local/bin/python3.13': sys.executable,
        '/usr/bin/lockf -k -t 30': shlex.quote(sys.executable) + ' ' + shlex.quote(str(lock)),
    }.items():
        text = text.replace(original, replacement)
    script = tmp_path / 'pre-deinstall.sh'
    script.write_text(text)
    env = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ['PATH'])
    result = subprocess.run(['sh', str(script)], env=env, capture_output=True, timeout=10)
    assert result.returncode == recovery_exit
    assert (state / 'uninstalling').exists()
    assert gui_event.exists() is not (recovery_exit == 1 and failing_stage == 'trust')
    if recovery_exit:
        assert not events.exists()
    else:
        assert [json.loads(line) for line in events.read_text().splitlines()] == [
            ['nethub_agent_frpc', 'onestatus'], ['nethub_agent_frpc', 'onestop']]
