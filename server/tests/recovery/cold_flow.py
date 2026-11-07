"""Run full protected-host recovery only inside its independently guarded unit."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import time
import uuid

from cold_console import ColdConsole
from cold_route import check as route
from cold_witness import ColdWitness, private_json
from linux_guest import LinuxGuest, RecoveryError, invoke
from source_host import SourceHost
from target_host import TargetHost


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'agents/opnsense/acceptance'))
from bootstrap import install_current_package
from cold_native import ColdNative
from guest import Guest


PHASES = ('guard_admission', 'source_boot', 'source_prepare', 'console_login', 'native_boot',
          'native_install', 'native_enroll', 'witness_start', 'source_issuer', 'native_request',
          'native_baseline', 'original_route', 'checkpoint', 'source_stop', 'target_boot',
          'target_restore', 'target_route', 'timer_resume', 'issued_generation', 'native_application',
          'application_ack', 'issued_route', 'native_remove', 'witness_finish', 'owned_cleanup', 'completed')


def stage(name):
    if name not in PHASES:
        raise RecoveryError('Unknown cold recovery phase')
    print('NETHUB_COLD_PHASE=' + name, flush=True)


def admission(control):
    if (sys.platform != 'linux' or os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        raise RecoveryError('Fresh guarded hosted cold recovery required')
    parent = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    if (control != control.resolve(strict=True) or control.parent != parent
            or re.fullmatch('nethub-cold-recovery-[a-f0-9]{16}', control.name) is None):
        raise RecoveryError('New owned cold recovery control required')
    info = control.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise RecoveryError('Private cold recovery control required')
    nonce = control.name.removeprefix('nethub-cold-recovery-')
    guard = 'nethub-cold-recovery-guard-' + nonce
    for prop, expected in (('ActiveState', 'active'), ('Unit', guard + '.service')):
        actual = invoke(['/usr/bin/systemctl', 'show', guard + '.timer', '--property=' + prop, '--value'],
                        'Independent cold recovery cleanup guard').decode().strip()
        if actual != expected:
            raise RecoveryError('Independent cold recovery cleanup guard not active')


def ports():
    with ExitStack() as stack:
        fixed = stack.enter_context(socket.socket())
        fixed.bind(('127.0.0.1', 7000))
        values = []
        for _ in range(3):
            listener = stack.enter_context(socket.socket())
            listener.bind(('127.0.0.1', 0))
            values.append(listener.getsockname()[1])
        return values


def wait_route(native, port, roots, fingerprint, deadline):
    while not route(native.host, port, roots, fingerprint):
        if time.monotonic() >= deadline:
            raise RecoveryError('Original verified native route did not recover before deadline')
        time.sleep(1)


def grant(host, device):
    return host.query("SELECT host(source_ip)||'|'||expires_at::text||'|'||user_id::text "
                      "FROM device_access_grants WHERE device_id='" + device + "' ORDER BY source_ip,user_id")


def original_request(host, native):
    value = json.loads(host.query("SELECT jsonb_build_object('id',id,'host',assigned_host,'csr',csr_fingerprint,"
        "'key',encode(public.digest(decode(translate(gui_public_key,'-_','+/')||repeat('=',"
        "(4-length(gui_public_key)%4)%4),'base64'),'sha256'),'hex'))::text "
        "FROM gui_certificate_requests WHERE device_id='" + native.device + "'"))
    if (str(uuid.UUID(value['id'])) != value['id'] or value['host'] != native.host
            or value['csr'] != native.original_request['original_cached_csr_sha256']
            or value['key'] != native.original_request['enrollment_gui_key_fingerprint']):
        raise RecoveryError('Actual original server CSR and enrollment key binding differ')
    return value['id']


def issued(host, device, request):
    raw = host.query("SELECT jsonb_build_object('id',g.id,'leaf',g.leaf_fingerprint)::text "
        "FROM gui_certificate_generations g JOIN gui_certificate_jobs j ON j.id=g.job_id "
        "WHERE g.device_id='" + device + "' AND g.request_id='" + request + "' AND g.generation=1 AND j.state='issued'")
    if not raw:
        return None
    value = json.loads(raw)
    if str(uuid.UUID(value['id'])) != value['id'] or re.fullmatch('[a-f0-9]{64}', value['leaf']) is None:
        raise RecoveryError('Actual issued recovery generation differs')
    return value


def exercise(control, images, tags, witness_binary, sdk):
    control = Path(control)
    stage('guard_admission')
    admission(control)
    os.umask(0o077)
    private = control / 'private'
    private.mkdir(mode=0o700)
    console_port, route_port, ca_forward_port = ports()
    package = {}
    source_guest = target_guest = native_guest = witness = None
    with ExitStack() as owned:
        stage('source_boot')
        source_guest = owned.enter_context(LinuxGuest(private / 'source'))
        source = SourceHost(source_guest, ROOT)
        stage('source_prepare')
        source_prepared = source.bootstrap(images, tags)
        source.initialize_stack()
        source_address = source.entry_address()
        source_forward = owned.enter_context(ExitStack())
        source_forward.enter_context(source_guest.forward([
            ('127.0.0.1', console_port, source_address, 443), ('127.0.0.1', 7000, source_address, 7000),
            ('127.0.0.1', route_port, source_address, 8443)]))
        ca = source.console_ca()
        password = source.receive('admin-password')
        stage('console_login')
        console = ColdConsole(private / 'source-console', console_port, ca, password)
        original_actor = console.login()
        stage('native_boot')
        native_guest = owned.enter_context(Guest(private / 'appliance', console_port=console_port))
        stage('native_install')
        install_current_package(native_guest, source.work / 'source.tar', Path(sdk), package)
        native = ColdNative(native_guest, private / 'native-inputs', control / 'native-evidence')
        native.trust(ca)
        stage('native_enroll')
        native.enroll(console.enrollment_token())
        stage('witness_start')
        witness = owned.enter_context(ColdWitness(witness_binary, native.host, ca_forward_port,
                                                  ownership_record=control / 'witness.json'))
        stage('source_issuer')
        source.configure_issuer(witness.ready, native.host, witness_control=str(witness.control))
        native.trust(Path(witness.ready['certificate_roots_file']).read_bytes())
        stage('native_request')
        native.initial_request()
        stage('native_baseline')
        native.prepare_baseline()
        request = original_request(source, native)
        source_forward.enter_context(source_guest.forward([
            (witness.ready['forward_address'], ca_forward_port, source_address, 80)]))
        stage('original_route')
        opened = console.open_device(native.device)
        if opened.get('url') != 'https://' + native.host + ':8443':
            raise RecoveryError('Normal Open did not return the original assigned route')
        original_grant = grant(source, native.device)
        parts = original_grant.split('|')
        if len(parts) != 3 or parts[0] != source_address or parts[2] != original_actor:
            raise RecoveryError('Normal Open source does not match the actual owned forwarded peer')
        roots = native.write('route-roots.pem', (native.directory / 'fixture-ca.pem').read_bytes()
                             + Path(witness.ready['certificate_roots_file']).read_bytes())
        original_leaf = native.baseline['native_leaf_fingerprint']
        wait_route(native, route_port, roots, original_leaf, time.monotonic() + 30)
        stage('checkpoint')
        checkpoint_started = time.monotonic()
        metadata, payload = source.capture_checkpoint(native.device, request)
        stage('source_stop')
        source_forward.close()
        source_guest.__exit__(None, None, None)
        if source_guest.process.poll() is None or source_guest.stopped_monotonic is None:
            raise RecoveryError('Original source process was not reaped before target creation')
        stopped = source_guest.stopped_monotonic
        stage('target_boot')
        target_guest = owned.enter_context(LinuxGuest(private / 'target'))
        target = TargetHost(target_guest, ROOT, source_guest)
        stage('target_restore')
        restored = target.restore(images, tags, metadata, payload)
        target_address = target.entry_address()
        owned.enter_context(target_guest.forward([
            ('127.0.0.1', console_port, target_address, 443), ('127.0.0.1', 7000, target_address, 7000),
            ('127.0.0.1', route_port, target_address, 8443),
            (witness.ready['forward_address'], ca_forward_port, target_address, 80)]))
        recovered_console = ColdConsole(private / 'target-console', console_port, ca, password)
        recovered_console.login(original_actor=original_actor)
        if original_request(target, native) != request or grant(target, native.device) != original_grant:
            raise RecoveryError('Recovered original identity request or source grant differs')
        stage('target_route')
        wait_route(native, route_port, roots, original_leaf, time.monotonic() + 90)
        baseline_recovery_ms = round((time.monotonic() - stopped) * 1000)
        stage('timer_resume')
        resumed = target.resume_automation()
        stage('issued_generation')
        deadline = time.monotonic() + 120
        while (generation := issued(target, native.device, request)) is None:
            if time.monotonic() >= deadline:
                raise RecoveryError('Restored stock issuer did not finish the original initial job')
            time.sleep(1)
        stage('native_application')
        native.wait_application(generation['id'], generation['leaf'])
        stage('application_ack')
        if target.query("SELECT count(*) FROM gui_certificate_applications WHERE generation_id='" + generation['id']
                + "' AND device_id='" + native.device + "' AND request_id='" + request + "' AND generation=1 "
                "AND csr_fingerprint='" + native.baseline['original_cached_csr_sha256']
                + "' AND leaf_fingerprint='" + generation['leaf'] + "'") != '1':
            raise RecoveryError('Actual authenticated original native application acknowledgement absent')
        stage('issued_route')
        wait_route(native, route_port, roots, generation['leaf'], time.monotonic() + 15)
        if grant(target, native.device) != original_grant:
            raise RecoveryError('Original normal Open grant changed during recovery')
        complete_ms = round((time.monotonic() - stopped) * 1000)
        checkpoint_ms = round((time.monotonic() - checkpoint_started) * 1000)
        stage('native_remove')
        native.remove()
        if (target.query("SELECT count(*) FROM devices WHERE id='" + native.device + "' AND revoked") != '1'
                or route(native.host, route_port, roots, generation['leaf'])):
            raise RecoveryError('Normal native Remove did not revoke and close the original route')
        stage('witness_finish')
        witnessed = witness.finish()
        stage('owned_cleanup')
    if any(guest is None or guest.process.poll() is None for guest in (source_guest, target_guest, native_guest)):
        raise RecoveryError('Owned source target and native processes were not all reaped')
    cleanup = private_json(witness.control / 'cleanup.json')
    if cleanup != {'owned_CA_and_process_group_removed': True, 'temporary_witness_keys_removed': True,
                   'full_host_recovery_accepted': False}:
        raise RecoveryError('Independent witness cleanup not confirmed')
    stage('completed')
    return {'source_preparation': source_prepared, 'target_restoration': restored, 'timer_resumption': resumed,
            'actual_CA_HTTP01': witnessed, 'original_source_reaped_before_distinct_target': True,
            'original_native_enrollment_key_CSR_assignment_process_checks_alias_preserved': True,
            'original_registered_account_and_complete_database_restored': True,
            'same_original_initial_request_issued_and_native_applied_acknowledged': True,
            'original_normal_Open_grant_retained_without_SQL_creation_or_renewal': True,
            'same_route_verified_TLS_before_restore_and_after_actual_issuance': True,
            'normal_native_Remove_server_revocation_and_route_closure': True,
            'owned_guests_and_independent_CA_cleaned': True,
            'baseline_route_recovery_ms': baseline_recovery_ms, 'initial_issuance_recovery_ms': complete_ms,
            'checkpoint_start_to_native_issuance_ms': checkpoint_ms,
            'opnsense_version': package['opnsense_version'], 'installed': package['installed'],
            'public_operator_durable_custody_renewal_clock_or_full_goal_accepted': False}
