"""Inspect signed recovery-guest repository connectivity without installing packages."""
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server/tests/recovery'))
from linux_guest import IMAGE_SHA256, LinuxGuest

GUEST = r'''
import json,os,pathlib,re,signal,socket,subprocess,sys,tempfile,time,urllib.error,urllib.parse,urllib.request
def allowed(url):
    value=urllib.parse.urlsplit(url)
    return (value.scheme in ('http','https') and value.hostname is not None
        and (value.hostname=='ubuntu.com' or value.hostname.endswith('.ubuntu.com'))
        and value.username is None and value.password is None
        and value.port in (None,80,443) and not value.query and not value.fragment)
def source_urls(text,deb822):
    lines=[]
    for line in text.splitlines():
        line=line.strip()
        if not line or line.startswith('#'): continue
        if (deb822 and line.startswith('URIs:')) or (not deb822 and line.startswith(('deb ','deb-src '))):
            lines.append(line.split('#',1)[0])
    return re.findall(r"https?://[^\s\"'<>]+",'\n'.join(lines))
def apt_probe():
    command=['apt-get','-o','Acquire::Retries=2','-o','Acquire::http::Timeout=20',
             '-o','Acquire::https::Timeout=20','-o','APT::Update::Error-Mode=any','update','-qq']
    markers={'dns':False,'connection':False,'lock':False,'http':False,'signature':False,'certificate':False}
    started=time.monotonic()
    timed_out=False
    with tempfile.TemporaryFile() as output:
        process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
        try:
            process.wait(timeout=120)
        except subprocess.TimeoutExpired:
            timed_out=True
        finally:
            if process.poll() is None:
                os.killpg(process.pid,signal.SIGKILL)
                process.wait(timeout=10)
        output.seek(0)
        data=output.read(131073)
    lowered=data[:131072].lower()
    markers['dns']=any(x in lowered for x in (b'temporary failure resolving',b'could not resolve',b'name or service not known'))
    markers['connection']=any(x in lowered for x in (b'could not connect',b'connection failed',b'connection timed out',b'network is unreachable'))
    markers['lock']=any(x in lowered for x in (b'could not get lock',b'waiting for cache lock',b'unable to acquire'))
    markers['http']=any(x in lowered for x in (b'403 forbidden',b'404 not found',b'502 bad gateway',b'503 service unavailable'))
    markers['signature']=any(x in lowered for x in (b'no_pubkey',b'not signed',b'signatures couldn',b'clearsigned file isn'))
    markers['certificate']=any(x in lowered for x in (b'certificate verification failed',b'certificate issuer is unknown'))
    return {'timed_out':timed_out,'exit_status':process.returncode,'elapsed_seconds':int(time.monotonic()-started),
            'process_reaped':process.poll() is not None,'output_truncated':len(data)>131072,'markers':markers}
urls=[]
for path in sorted(pathlib.Path('/etc/apt').glob('sources.list*')):
    files=sorted(path.glob('*.sources'))+sorted(path.glob('*.list')) if path.is_dir() else [path]
    for item in files:
        for url in source_urls(item.read_text(),item.suffix=='.sources'):
            if allowed(url) and url not in urls:
                urls.append(url)
urls=urls[:4]
targets=[('configured-'+str(i+1),u) for i,u in enumerate(urls)]
targets += [('official-http','http://archive.ubuntu.com/ubuntu'),
            ('official-https','https://archive.ubuntu.com/ubuntu')]
class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        if not allowed(newurl): raise ValueError('redirect refused')
        return super().redirect_request(req,fp,code,msg,headers,newurl)
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),Redirect())
results=[]
for label,url in targets:
    value=urllib.parse.urlsplit(url)
    port=value.port or (443 if value.scheme=='https' else 80)
    row={'label':label,'dns':'error','ipv4_tcp':'unavailable','ipv6_tcp':'unavailable','metadata':'unavailable'}
    try:
        code='import json,socket,sys; print(json.dumps(socket.getaddrinfo(sys.argv[1],int(sys.argv[2]),type=socket.SOCK_STREAM)))'
        addresses=json.loads(subprocess.check_output([sys.executable,'-c',code,value.hostname,str(port)],stderr=subprocess.DEVNULL,timeout=5))
        row['dns']='resolved'
    except subprocess.TimeoutExpired:
        row['dns']='timeout'; addresses=[]
    except Exception:
        addresses=[]
    for family,key in [(socket.AF_INET,'ipv4_tcp'),(socket.AF_INET6,'ipv6_tcp')]:
        selected=next((a for a in addresses if a[0]==family),None)
        if selected:
            try:
                with socket.socket(family,socket.SOCK_STREAM) as connection:
                    connection.settimeout(5); connection.connect(tuple(selected[4]))
                row[key]='connected'
            except socket.timeout: row[key]='timeout'
            except OSError: row[key]='error'
    if addresses:
        try:
            with opener.open(url.rstrip('/')+'/dists/noble/InRelease',timeout=8) as response:
                prefix=response.read(256)
                row['metadata']='index-header' if response.status==200 and prefix.startswith(b'-----BEGIN PGP SIGNED MESSAGE-----') else 'unexpected'
        except urllib.error.HTTPError: row['metadata']='http-error'
        except (TimeoutError,socket.timeout): row['metadata']='timeout'
        except Exception: row['metadata']='error'
    results.append(row)
print(json.dumps({'configured_source_count':len(urls),'probes':results,'apt_update':apt_probe()}))
'''


def validate(value):
    if not isinstance(value, dict) or set(value) != {'configured_source_count', 'probes', 'apt_update'}:
        raise ValueError('Closed network result required')
    count = value['configured_source_count']
    if type(count) is not int or not 0 <= count <= 4 or len(value['probes']) != count + 2:
        raise ValueError('Bounded network result required')
    labels = ['configured-' + str(i + 1) for i in range(count)] + ['official-http', 'official-https']
    for row, label in zip(value['probes'], labels):
        if set(row) != {'label', 'dns', 'ipv4_tcp', 'ipv6_tcp', 'metadata'} or row['label'] != label:
            raise ValueError('Closed network probe required')
        if row['dns'] not in ('resolved', 'timeout', 'error'):
            raise ValueError('Closed DNS result required')
        if any(row[k] not in ('unavailable', 'connected', 'timeout', 'error') for k in ('ipv4_tcp', 'ipv6_tcp')):
            raise ValueError('Closed transport result required')
        if row['metadata'] not in ('unavailable', 'index-header', 'unexpected', 'http-error', 'timeout', 'error'):
            raise ValueError('Closed repository result required')
    apt = value['apt_update']
    if not isinstance(apt, dict) or set(apt) != {'timed_out', 'exit_status', 'elapsed_seconds', 'process_reaped', 'output_truncated', 'markers'}:
        raise ValueError('Closed APT result required')
    if any(type(apt[k]) is not bool for k in ('timed_out', 'process_reaped', 'output_truncated')) or apt['process_reaped'] is not True:
        raise ValueError('APT cleanup required')
    if type(apt['exit_status']) is not int or not -64 <= apt['exit_status'] <= 255:
        raise ValueError('Closed APT exit status required')
    if type(apt['elapsed_seconds']) is not int or not 0 <= apt['elapsed_seconds'] <= 140:
        raise ValueError('Bounded APT observation required')
    if not isinstance(apt['markers'], dict) or set(apt['markers']) != {'dns', 'connection', 'lock', 'http', 'signature', 'certificate'} or any(type(v) is not bool for v in apt['markers'].values()):
        raise ValueError('Closed APT markers required')
    return value


def main():
    head = os.environ.get('NETHUB_SOURCE_HEAD', '')
    if not re.fullmatch('[a-f0-9]{40}', head):
        raise ValueError('Exact source required')
    root = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    evidence = root / 'recovery-network-evidence'
    evidence.mkdir(mode=0o700)
    private = Path(tempfile.mkdtemp(prefix='recovery-network-private-', dir=root))
    guest = None
    result = {'source_head': head, 'image_sha256': IMAGE_SHA256, 'network': None,
              'owned_guest_stopped': False, 'private_workspace_removed': False,
              'package_installation_or_recovery_accepted': False}
    try:
        guest = LinuxGuest(private / 'guest')
        with guest:
            raw = guest.ssh("python3 - <<'PY'\n" + GUEST + '\nPY\n', 'Closed guest network diagnosis', timeout=360)
            result['network'] = validate(json.loads(raw))
    finally:
        stopped = guest is not None and guest.process is not None and guest.process.poll() is not None
        result['owned_guest_stopped'] = stopped
        if stopped:
            shutil.rmtree(private)
            result['private_workspace_removed'] = not private.exists()
        (evidence / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        (evidence / 'result.json').chmod(0o644)
        evidence.chmod(0o755)
    if not result['owned_guest_stopped'] or not result['private_workspace_removed']:
        raise ValueError('Owned diagnosis cleanup incomplete')
    print('Closed recovery network and bounded APT diagnosis retained; no packages installed or recovery accepted')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Recovery network diagnosis failed; inspect closed evidence', file=sys.stderr)
        sys.exit(1)
