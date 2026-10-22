#!/usr/local/bin/python3.13
"""Bound a FreeBSD job without waiting for daemons after normal completion."""
import ctypes
import errno
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


class JobError(Exception):
    """A fixed diagnostic without child arguments or output."""


class Cancelled(Exception):
    def __init__(self, signum):
        self.signum = signum


class _Status(ctypes.Structure):
    _fields_ = [('flags', ctypes.c_uint), ('children', ctypes.c_uint),
                ('descendants', ctypes.c_uint), ('reaper', ctypes.c_int),
                ('pid', ctypes.c_int), ('reserved', ctypes.c_uint * 15)]


class _Kill(ctypes.Structure):
    _fields_ = [('signum', ctypes.c_int), ('flags', ctypes.c_uint),
                ('subtree', ctypes.c_int), ('killed', ctypes.c_uint),
                ('failed_pid', ctypes.c_int), ('reserved', ctypes.c_uint * 15)]


class Reaper:
    """Use the FreeBSD procctl ABI; never substitute process-group cleanup.

    A daemon may create a new session. It must survive a completed job, while
    remaining subject to recursive cleanup if that job exceeds its deadline.
    """

    def __init__(self):
        if not sys.platform.startswith('freebsd'):
            raise JobError('FreeBSD process reaping is required')
        self.call = ctypes.CDLL(None, use_errno=True).procctl
        self.call.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_int, ctypes.c_void_p]
        self.call.restype = ctypes.c_int

    def _call(self, operation, value=None, allow_missing=False):
        pointer = ctypes.byref(value) if value is not None else None
        if self.call(os.P_PID, os.getpid(), operation, pointer) != 0:
            if allow_missing and ctypes.get_errno() == errno.ESRCH:
                return
            raise JobError('Process reaper operation failed')

    def acquire(self):
        self._call(2)  # PROC_REAP_ACQUIRE

    def release(self):
        self._call(3)  # PROC_REAP_RELEASE

    def children(self):
        value = _Status()
        self._call(4, value)  # PROC_REAP_STATUS
        return value.children

    def signal(self, signum):
        value = _Kill(signum=signum)
        self._call(6, value, allow_missing=True)  # PROC_REAP_KILL, entire owned tree


def _drain(child, reaper, seconds):
    until = time.monotonic() + seconds
    while True:
        if child is None or child.poll() is not None:
            # Only reap adopted descendants after Popen has reaped its child.
            while True:
                try:
                    pid, _ = os.waitpid(-1, os.WNOHANG)
                except ChildProcessError:
                    break
                if pid == 0:
                    break
            if reaper.children() == 0:
                return True
        if time.monotonic() >= until:
            return False
        time.sleep(.02)


def _terminate(child, reaper):
    previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        reaper.signal(signal.SIGTERM)
        if not _drain(child, reaper, 2):
            reaper.signal(signal.SIGKILL)
            if not _drain(child, reaper, 2):
                raise JobError('Timed-out process cleanup did not finish')
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def run_bounded(command, seconds):
    if (not command or not Path(command[0]).is_absolute() or not math.isfinite(seconds)
            or not 0 < seconds <= 300):
        raise JobError('A bounded absolute command is required')
    reaper = Reaper()
    reaper.acquire()
    child = None
    previous = {}

    def cancelled(signum, frame):
        raise Cancelled(signum)

    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            previous[sig] = signal.signal(sig, cancelled)
        terminate = False
        try:
            child = subprocess.Popen(command, close_fds=True)
            result = child.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            terminate, result = True, 124
        except Cancelled as error:
            terminate, result = True, 128 + error.signum
        except BaseException:
            terminate = True
            raise
        finally:
            if terminate:
                _terminate(child, reaper)
        # Normal completion hands daemon descendants back to the outer reaper.
        # Waiting for them would turn a successful service start into a timeout.
        return result if result >= 0 else 128 - result
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        reaper.release()


def main(arguments=None):
    arguments = sys.argv[1:] if arguments is None else arguments
    try:
        if len(arguments) < 2:
            raise JobError('A duration and absolute command are required')
        return run_bounded(arguments[1:], float(arguments[0]))
    except (JobError, OSError, ValueError, AttributeError):
        print('Bounded job failed; inspect local process and recovery status', file=sys.stderr)
        return 125


if __name__ == '__main__':
    sys.exit(main())
