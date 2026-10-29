"""Check only the new recovery host, without claiming a restored deployment."""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import sys

from linux_guest import IMAGE_SHA256, LinuxGuest, RecoveryError


def interrupted(*_):
    raise RecoveryError('Hosted recovery target interrupted')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', required=True)
    parser.add_argument('--evidence', required=True)
    args = parser.parse_args()
    head = os.environ.get('NETHUB_SOURCE_HEAD', '')
    if re.fullmatch('[0-9a-f]{40}', head) is None:
        raise RecoveryError('Exact source identity is required')
    os.umask(0o077)
    evidence = Path(args.evidence)
    if evidence.exists() or evidence.parent.resolve() != Path(os.environ['RUNNER_TEMP']).resolve():
        raise RecoveryError('New hosted evidence path is required')
    evidence.mkdir(mode=0o700)
    result = {'source_head': head, 'image_sha256': IMAGE_SHA256,
              'phase': 'boot', 'target_prepared': False, 'owned_guest_stopped': False,
              'canonical_signature_verified': False,
              'deployment_restored': False, 'native_reconnected': False,
              'off_host_custody': False, 'full_goal_complete': False}
    guest = None
    try:
        guest = LinuxGuest(args.directory)
        with guest:
            result['canonical_signature_verified'] = True
            result['phase'] = 'prepare'
            result['target'] = guest.prepare()
            result['target_prepared'] = True
        result['phase'] = 'complete'
    finally:
        result['owned_guest_stopped'] = (guest is not None and guest.process is not None
                                         and guest.process.poll() is not None)
        (evidence / 'target-result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    if not result['owned_guest_stopped']:
        raise RecoveryError('Owned recovery guest cleanup incomplete')
    print('Distinct empty hosted Linux recovery target prepared and stopped; restoration remains separate')


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, interrupted)
    try:
        main()
    except Exception:
        # HTTP, SSH, cloud-init and QEMU errors can contain private arguments/output.
        print('Recovery target preparation failed; inspect private runner state', file=sys.stderr)
        sys.exit(1)
