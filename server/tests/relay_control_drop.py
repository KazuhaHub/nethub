"""Temporarily drop one owned loopback control and verify exact rule restoration."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
import uuid

from relay_network_blip import drop_counters, owned_tuple


class ControlDrop:
    def __init__(self, binding, directory):
        if os.geteuid() != 0:
            raise ValueError('Owned root fixture required')
        self.rule = owned_tuple(binding)
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700)
        self.tool = shutil.which('iptables')
        if not self.tool:
            raise ValueError('Owned packet-loss fixture requires iptables')
        self.chain = 'nh-combo-' + uuid.uuid4().hex[:12]
        self.rule += ['-j', self.chain]
        self.attempted = self.interrupted = self.cleaning = self.restored = False
        self.prior = {}
        self.started = self.removed = None

    def command(self, arguments, name, required=True):
        if self.interrupted and not self.cleaning:
            raise SystemExit('Owned combined-fault fixture interrupted')
        result = subprocess.run([self.tool, '-w', '2', *arguments], capture_output=True, timeout=3)
        (self.directory / (name + '.log')).write_bytes(result.stdout + result.stderr)
        if required and result.returncode:
            raise ValueError('Owned combined-fault rule operation failed')
        return result

    def counters(self):
        return drop_counters(self.command(['-nvx', '-L', self.chain], 'counters').stdout)

    def interrupt(self, _number, _frame):
        # Finish an in-flight atomic command before inspecting its actual result.
        self.interrupted = True

    def __enter__(self):
        self.original = self.command(['-S', 'OUTPUT'], 'original-output').stdout
        if self.command(['-S', self.chain], 'absent-chain', required=False).returncode != 1:
            raise ValueError('Fresh owned fault chain required')
        self.prior = {sig: signal.signal(sig, self.interrupt) for sig in (signal.SIGTERM, signal.SIGINT)}
        try:
            self.attempted = True
            self.command(['-N', self.chain], 'create-chain')
            self.command(['-A', self.chain, '-j', 'DROP'], 'add-drop')
            if self.counters() != {'packets': 0, 'bytes': 0}:
                raise ValueError('Owned fault counters must start empty')
            self.started = time.monotonic()
            self.command(['-I', 'OUTPUT', '1', *self.rule], 'link-owned-rule')
            return self
        except BaseException:
            self.close()
            raise

    def close(self):
        self.cleaning = True
        try:
            if self.attempted:
                actual = self.command(['-S', self.chain], 'cleanup-chain', required=False)
                if actual.returncode not in (0, 1):
                    raise ValueError('Owned fault chain inspection failed')
                if actual.returncode == 0:
                    link = self.command(['-C', 'OUTPUT', *self.rule], 'cleanup-link', required=False)
                    if link.returncode not in (0, 1):
                        raise ValueError('Owned fault link inspection failed')
                    if link.returncode == 0:
                        self.command(['-D', 'OUTPUT', *self.rule], 'unlink-owned-rule')
                        self.removed = time.monotonic()
                    lines = actual.stdout.decode('ascii').splitlines()
                    if not lines or not set(lines) <= {'-N ' + self.chain, '-A ' + self.chain + ' -j DROP'}:
                        raise ValueError('Owned fault chain changed unexpectedly')
                    if '-A ' + self.chain + ' -j DROP' in lines:
                        self.command(['-D', self.chain, '-j', 'DROP'], 'remove-drop')
                    self.command(['-X', self.chain], 'delete-chain')
            if (self.command(['-S', 'OUTPUT'], 'restored-output').stdout != self.original
                    or self.command(['-S', self.chain], 'removed-chain', required=False).returncode != 1):
                raise ValueError('Original OUTPUT rules were not restored exactly')
            self.restored = True
        finally:
            for sig, handler in self.prior.items():
                signal.signal(sig, handler)

    def __exit__(self, kind, _error, _traceback):
        self.close()
        if kind is None and self.interrupted:
            raise SystemExit('Owned combined-fault fixture interrupted after cleanup')
