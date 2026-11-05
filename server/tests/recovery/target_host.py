"""Restore the complete owned checkpoint only after its source guest is reaped."""
import json
import math
from pathlib import Path

from host_checkpoint import valid_checkpoint
from host_layout import TRANSFER
from linux_guest import LinuxGuest, RecoveryError, sha256
from source_host import DeploymentHost


def ordered_handoff(source, target):
    if (type(source) is not LinuxGuest or type(target) is not LinuxGuest
            or source.process is None or target.process is None
            or source.process.poll() is None or target.process.poll() is not None):
        return False
    stopped, started = getattr(source, 'stopped_monotonic', None), getattr(target, 'started_monotonic', None)
    return (type(stopped) in (int, float) and type(started) in (int, float)
            and math.isfinite(stopped) and math.isfinite(started) and 0 < stopped <= started)


class TargetHost(DeploymentHost):
    def __init__(self, guest, repository, source):
        if not ordered_handoff(source, guest):
            raise RecoveryError('Original source must be reaped before target guest launch')
        super().__init__(guest, repository, role='target')
        self.source = source
        self.restored = False

    def restore(self, images, tags, metadata, payload):
        if self.restored or self.host_prepared or not ordered_handoff(self.source, self.guest):
            raise RecoveryError('New target and stopped original source required')
        metadata, payload = Path(metadata), Path(payload)
        value = json.loads(metadata.read_text())
        if (not valid_checkpoint(value) or value['source_head'] != self.head or value['tags'] != tags
                or value['source_machine_id'] != self.source.identity['machine_id']
                or value['source_boot_id'] != self.source.identity['boot_id']
                or value['payload']['sha256'] != sha256(payload)):
            raise RecoveryError('Original complete private checkpoint differs')
        prepared = self.prepare_images(images, tags)
        if (self.guest.identity['machine_id'] == value['source_machine_id']
                or self.guest.identity['boot_id'] == value['source_boot_id']):
            raise RecoveryError('Target machine and boot identities must both be distinct')
        self.guest.send(metadata, 'checkpoint.json')
        self.guest.send(payload, 'current-files.tar')
        for name in ('host_layout.py', 'database.py', 'payload.py', 'host_checkpoint.py'):
            self.send_module(name)
        expected = {'version': 1, 'machine_id': self.guest.identity['machine_id'],
                    'boot_id': self.guest.identity['boot_id'], 'source_head': self.head,
                    'checkpoint_sha256': sha256(metadata), 'payload_sha256': sha256(payload)}
        self.install_file((json.dumps(expected) + '\n').encode(), 'restore-input.json',
                          TRANSFER + '/restore-input.json', '0600')
        result = json.loads(self.remote(['python3', TRANSFER + '/host_checkpoint.py', 'restore'],
                                       'Distinct full protected-host recovery', timeout=420))
        if result != {'full_file_inventory_restored': True, 'complete_database_fingerprint_restored': True,
                      'same_tested_six_new_services_running': True, 'stock_issuer_units_restored_inactive': True,
                      'original_registered_account_lookup_verified': True,
                      'resumed_timer_issuance_or_complete_recovery_accepted': False}:
            raise RecoveryError('Distinct full protected-host recovery not confirmed')
        self.restored = True
        self.metadata = value
        return {'target': prepared, 'original_source_reaped_before_target_launch': True,
                **result, 'native_confirmation_or_full_goal_accepted': False}

    def resume_automation(self):
        if not self.restored or getattr(self, 'automation_resumed', False) or not ordered_handoff(self.source, self.guest):
            raise RecoveryError('Completed distinct target restore required before automation resumption')
        result = json.loads(self.remote(['python3', TRANSFER + '/host_checkpoint.py', 'resume'],
                                       'Fresh target cleanup and stock timer resumption', timeout=90))
        if result != {'fresh_independent_cleanup_executed_on_new_host': True,
                      'stock_timer_enabled_intent_restored_and_active': True,
                      'source_shutdown_native_issuance_or_complete_recovery_accepted': False}:
            raise RecoveryError('Fresh target cleanup and timer resumption not confirmed')
        self.automation_resumed = True
        return result
