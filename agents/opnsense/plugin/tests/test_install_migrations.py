"""Execute the real package hook with isolated native command boundaries."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

import pytest

pytestmark=pytest.mark.skipif(os.name=='nt',reason='Native package hooks execute in a POSIX shell')
ROOT=Path(__file__).resolve().parents[1]


def test_install_scopes_native_migration_before_reconcile_and_preserves_unrelated_files(tmp_path):
    tmp_path.chmod(0o700)
    commands=tmp_path/'bin';commands.mkdir()
    events=tmp_path/'events.jsonl'
    helper=commands/'native-command'
    helper.write_text('#!'+sys.executable+'\nimport json,sys\nfrom pathlib import Path\nwith Path('+repr(str(events))+').open("a") as f:f.write(json.dumps(sys.argv[1:])+"\\n")\n')
    helper.chmod(0o755)
    unrelated=tmp_path/'unrelated-plugin.xml';unrelated.write_text('retain unrelated plugin configuration')
    state=tmp_path/'state';logs=tmp_path/'logs';config=tmp_path/'config';requests=state/'requests'
    state.mkdir();(state/'uninstalling').write_text('old package intent')
    cache=tmp_path/'cache';cache.mkdir()
    script=(ROOT/'packaging/freebsd/+POST_INSTALL').read_text()
    replacements={
        '/usr/local/opnsense/scripts/firmware/register.php':shlex.quote(str(helper))+' register',
        '/usr/local/opnsense/mvc/script/run_migrations.php':shlex.quote(str(helper))+' migrate',
        '/usr/bin/lockf':shlex.quote(str(helper))+' locked',
        '/usr/local/etc/nethub-agent':str(config),'/var/db/nethub-agent':str(state),'/var/log/nethub-agent':str(logs),
        '/var/lib/php/tmp':str(cache),
        'service configd restart':shlex.quote(str(helper))+' service configd restart',
    }
    for before,after in replacements.items():script=script.replace(before,after)
    path=tmp_path/'post-install.sh';path.write_text(script)
    result=subprocess.run(['sh',str(path)],capture_output=True,timeout=10)
    assert result.returncode==0
    calls=[json.loads(line) for line in events.read_text().splitlines()]
    assert calls[:2]==[['register','install','os-nethub-agent'],['migrate','OPNsense/NetHubAgent/']]
    assert calls[2]==['service','configd','restart']
    assert calls[3][0]=='locked' and calls[3][-2:]==['--locked','reconcile']
    assert unrelated.read_text()=='retain unrelated plugin configuration'
    assert not (state/'uninstalling').exists() and requests.is_dir()
    assert (logs/'scheduler.log').stat().st_mode&0o777==0o600
