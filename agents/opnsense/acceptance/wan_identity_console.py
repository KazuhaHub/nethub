"""Retain one closed, read-only serial observation after an identity-phase WAN failure."""
import json
import os
from pathlib import Path
import re

FILENAME = 'installed-wan-identity-console.json'
COLLECTION_FAILURES = ('console_unavailable', 'console_error', 'invalid_output')
LOAD_BUCKETS = ('<1', '1-2', '2-4', '>=4')
BOOLS = ('private_sshd_pid_alive', 'lan_nic_up_running', 'lan_address_present', 'pf_enabled',
         'pf_rules_present', 'nethub_lock_holder_present', 'second_near_cron_start')
COUNTS = ('sshd_process_count', 'newwanip_last_200_lines', 'linkup_last_200_lines',
          'filter_reload_last_200_lines', 'openssh_last_200_lines', 'webgui_last_200_lines')
FIELDS = BOOLS + COUNTS + ('load_1min_bucket', 'second_of_minute')
CRON_SECONDS = (0, 20, 30, 40, 60)
_BUCKETS = {'lt1': '<1', '1to2': '1-2', '2to4': '2-4', 'ge4': '>=4'}
# second_of_minute, second_near_cron_start and the last-200-line log counts are
# observation-time values taken after the failure (up to ~30 s later).
# Read-only: reads only; no service, interface, route, pf or lock change.
SCRIPT = r"""PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
out() { printf 'NHWANID %s=%s\n' "$1" "$2"; }
logs() { tail -n 200 /var/log/system/latest.log 2>/dev/null; tail -n 200 /var/log/configd/latest.log 2>/dev/null; }
count() { logs | grep -c -i -E -e "$1"; }
printf '\nNH_%s_BEGIN\n' WANID
pid=$(head -n 1 /root/nethub-ci/sshd.pid 2>/dev/null)
if test -n "$pid" && kill -0 "$pid" 2>/dev/null; then out private_sshd_pid_alive 1; else out private_sshd_pid_alive 0; fi
out sshd_process_count "$(pgrep -x sshd 2>/dev/null | wc -l | tr -d ' ')"
flags=$(/sbin/ifconfig em0 2>/dev/null | head -n 1 | sed 's/.*<\(.*\)>.*/\1/')
case ",$flags," in *,UP,*,RUNNING,*|*,RUNNING,*,UP,*) out lan_nic_up_running 1 ;; *) out lan_nic_up_running 0 ;; esac
if /sbin/ifconfig em0 inet 2>/dev/null | grep -q 'inet 192.168.1.1 '; then out lan_address_present 1; else out lan_address_present 0; fi
if /sbin/pfctl -si 2>/dev/null | grep -q '^Status: Enabled'; then out pf_enabled 1; else out pf_enabled 0; fi
out pf_rule_lines "$(/sbin/pfctl -sr 2>/dev/null | wc -l | tr -d ' ')"
out newwanip_last_200_lines "$(count 'rc\.newwanip')"
out linkup_last_200_lines "$(count 'rc\.linkup')"
out filter_reload_last_200_lines "$(count 'filter_configure|filter reload')"
out openssh_last_200_lines "$(count 'openssh')"
out webgui_last_200_lines "$(count 'webgui')"
out load_1min_bucket "$(sysctl -n vm.loadavg 2>/dev/null | awk '{v=$2+0; if(v<1)b="lt1"; else if(v<2)b="1to2"; else if(v<4)b="2to4"; else b="ge4"; print b}')"
out nethub_lock_holder_lines "$(fstat /var/db/nethub-agent/reconcile.lock 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')"
out second_of_minute "$(date +%S | sed 's/^0//; s/^$/0/')"
printf 'NH_%s_END\n' WANID
true
"""


def validate(value):
    if (not isinstance(value, dict) or set(value) != {'version', 'collected', 'collection_failure'} | set(FIELDS)
            or type(value['version']) is not int or value['version'] != 1
            or type(value['collected']) is not bool):
        raise ValueError('Unexpected WAN identity console evidence')
    if not value['collected']:
        if (value['collection_failure'] not in COLLECTION_FAILURES
                or any(value[key] is not None for key in FIELDS)):
            raise ValueError('Unexpected uncollected WAN identity console evidence')
        return
    if (value['collection_failure'] is not None
            or any(type(value[key]) is not bool for key in BOOLS)
            or type(value['sshd_process_count']) is not int
            or not 0 <= value['sshd_process_count'] <= 64
            or any(type(value[key]) is not int or not 0 <= value[key] <= 999 for key in COUNTS[1:])
            or value['load_1min_bucket'] not in LOAD_BUCKETS
            or type(value['second_of_minute']) is not int or not 0 <= value['second_of_minute'] <= 59
            or value['second_near_cron_start'] != any(abs(value['second_of_minute'] - s) <= 5 for s in CRON_SECONDS)):
        raise ValueError('Unexpected collected WAN identity console evidence')


def uncollected(failure):
    value = dict.fromkeys(FIELDS)
    value.update(version=1, collected=False, collection_failure=failure)
    return value


def parse(output):
    """Accept only exact marker-delimited key/value lines; ignore all other console text."""
    if not isinstance(output, str):
        raise ValueError('Unexpected console observation')
    lines = [line.rstrip('\r') for line in output.split('\n')]
    if lines.count('NH_WANID_BEGIN') != 1 or lines.count('NH_WANID_END') != 1:
        raise ValueError('Unexpected console observation')
    begin, end = lines.index('NH_WANID_BEGIN'), lines.index('NH_WANID_END')
    if end <= begin or end - begin - 1 > 32:
        raise ValueError('Unexpected console observation')
    raw = {}
    for line in lines[begin + 1:end]:
        match = re.fullmatch(r'NHWANID ([a-z0-9_]{1,40})=([a-z0-9]{1,6})', line)
        if match is None or match[1] in raw:
            raise ValueError('Unexpected console observation')
        raw[match[1]] = match[2]
    names = {'private_sshd_pid_alive', 'sshd_process_count', 'lan_nic_up_running', 'lan_address_present',
             'pf_enabled', 'pf_rule_lines', 'load_1min_bucket', 'nethub_lock_holder_lines', 'second_of_minute'} | set(COUNTS[1:])
    if set(raw) != names:
        raise ValueError('Unexpected console observation')

    def number(key, maximum):
        if re.fullmatch(r'0|[1-9][0-9]{0,5}', raw[key]) is None:
            raise ValueError('Unexpected console observation')
        return min(int(raw[key]), maximum)

    def flag(key):
        if raw[key] not in ('0', '1'):
            raise ValueError('Unexpected console observation')
        return raw[key] == '1'

    second = number('second_of_minute', 99)
    if second > 59 or raw['load_1min_bucket'] not in _BUCKETS:
        raise ValueError('Unexpected console observation')
    value = {'version': 1, 'collected': True, 'collection_failure': None,
             'private_sshd_pid_alive': flag('private_sshd_pid_alive'),
             'sshd_process_count': number('sshd_process_count', 64),
             'lan_nic_up_running': flag('lan_nic_up_running'),
             'lan_address_present': flag('lan_address_present'),
             'pf_enabled': flag('pf_enabled'), 'pf_rules_present': number('pf_rule_lines', 999) > 0,
             'load_1min_bucket': _BUCKETS[raw['load_1min_bucket']],
             'nethub_lock_holder_present': number('nethub_lock_holder_lines', 999) > 0,
             'second_of_minute': second,
             'second_near_cron_start': any(abs(second - s) <= 5 for s in CRON_SECONDS)}
    for key in COUNTS[1:]:
        value[key] = number(key, 999)
    return value


def observe(guest):
    """Return a closed record; a diagnostic failure is a category, never an exception."""
    try:
        console = getattr(guest, 'console', None)
        process = getattr(guest, 'process', None)
        if console is None or process is None or process.poll() is not None:
            return uncollected('console_unavailable')
        try:
            output = console.command(SCRIPT, timeout=30)
        except Exception:
            return uncollected('console_error')
        try:
            value = parse(output)
            validate(value)
            return value
        except Exception:
            return uncollected('invalid_output')
    except Exception:
        return uncollected('console_error')


def retain(guest, evidence):
    """Write one private record atomically; never raise and never replace the original failure."""
    temp = None
    try:
        directory = Path(evidence)
        path = directory / FILENAME
        # Skip before any guest activity when the evidence cannot be recorded.
        if not directory.is_dir() or os.path.lexists(path):
            return
        console = getattr(guest, 'console', None)
        phase = getattr(console, 'phase', None)
        try:
            value = observe(guest)
        finally:
            # The diagnostic must not change Guest.diagnostics() serial_wait_phase.
            if console is not None:
                try:
                    console.phase = phase
                except Exception:
                    pass
        validate(value)
        data = (json.dumps(value, indent=2) + '\n').encode('utf-8')
        temp = directory / ('.%s.%d.tmp' % (FILENAME, os.getpid()))
        descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.link(temp, path)
    except Exception:
        pass
    finally:
        if temp is not None:
            try:
                os.unlink(temp)
            except Exception:
                pass
