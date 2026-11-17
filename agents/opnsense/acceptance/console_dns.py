"""Provision native DNS before enrollment instead of patching generated hosts."""
from pathlib import Path

from guest import GuestError


def provision(guest, fixture):
    guest.put(Path(__file__).with_name('native-dns.php'), 'native-dns.php')
    result = fixture('console-dns')
    if not isinstance(result, dict) or set(result) != {'configured'} or result['configured'] is not True:
        raise GuestError('Native console DNS fixture unavailable')
    guest.ssh('set -eu\n/usr/local/sbin/configctl unbound restart\n'
              '/usr/local/sbin/pluginctl -c system_resolver_configure\n',
              'owned native console DNS activation and resolver regeneration')
