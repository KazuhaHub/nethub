"""Verify the shipped cleanup timer on explicitly owned disposable host paths."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys

if not __debug__:
    raise SystemExit("Cleanup acceptance requires enabled ownership assertions")


def fixture_paths(name):
    return {
        "library": Path("/usr/local/lib") / name,
        "public": Path("/srv") / name,
        "private": Path("/var/lib") / name,
        "config": Path("/etc") / (name + ".json"),
        "service": Path("/etc/systemd/system") / (name + ".service"),
        "timer": Path("/etc/systemd/system") / (name + ".timer"),
    }


def command(args, timeout=25, check=True):
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, check=check)


def write_state(control, state):
    path = control / "state.new"
    with path.open("x") as output:
        output.write(json.dumps(state, indent=2))
    path.chmod(0o600)
    path.replace(control / "state.json")


def restore(control):
    assert os.geteuid() == 0
    assert control.parent == Path("/run") and control.resolve() == control
    assert re.fullmatch(r"nethub-http01-test-[a-f0-9]{16}", control.name)
    assert control.stat().st_uid == 0 and control.stat().st_mode & 0o777 == 0o700
    lock = os.open(control / "cleanup.lock", os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(lock, "a") as lease:
        fcntl.flock(lease, fcntl.LOCK_EX)
        state = json.loads((control / "state.json").read_text())
        assert state["name"] == control.name
        paths = fixture_paths(state["name"])
        for path in paths.values():
            assert path.parent.resolve() == path.parent and not path.is_symlink()
        allowed = {str(paths["library"] / "nethub"), str(paths["service"]), str(paths["timer"])}
        assert set(state["hashes"]) <= allowed
        for value, digest in state["hashes"].items():
            path = Path(value)
            if path.exists():
                assert path.is_file() and not path.is_symlink()
                assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
        name = state["name"]
        command(["systemctl", "stop", name + ".timer", name + ".service"], check=False)
        for unit in (name + ".timer", name + ".service"):
            active = command(["systemctl", "show", unit, "--property=ActiveState", "--value"]).stdout.strip()
            assert active not in (b"active", b"activating", b"deactivating", b"reloading")
        for key in ("service", "timer", "config"):
            path = paths[key]
            if path.exists():
                info = path.lstat()
                assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                path.unlink()
        command(["systemctl", "daemon-reload"])
        for key in ("library", "public", "private"):
            path = paths[key]
            if path.exists():
                assert path.is_dir() and path.resolve() == path and path.stat().st_uid == 0
                shutil.rmtree(path)
        temporary = control / "tmp"
        if temporary.exists():
            assert temporary.resolve() == temporary and not temporary.is_symlink()
            shutil.rmtree(temporary)
        assert all(not path.exists() for path in paths.values())
        (control / "cleanup.json").write_text(json.dumps({"owned_units_and_paths_removed": True}))


def run(repository, cli, test, evidence):
    assert os.geteuid() == 0 and Path("/run/systemd/system").is_dir()
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    name = "nethub-http01-test-" + secrets.token_hex(8)
    paths = fixture_paths(name)
    for path in paths.values():
        assert not path.exists() and not path.is_symlink()
        assert path.parent.is_dir() and path.parent.resolve() == path.parent
    assert command(["systemctl", "show", name + ".service", "--property=LoadState", "--value"]).stdout.strip() == b"not-found"
    control = Path("/run") / name
    control.mkdir(mode=0o700)
    state = {"name": name, "hashes": {}}
    write_state(control, state)
    # Keep recovery outside the caller's temporary checkout so an interrupted
    # outer shell cannot delete the independently armed watchdog program.
    recovery = control / "restore.py"
    shutil.copyfile(Path(__file__).resolve(), recovery)
    recovery.chmod(0o600)
    guard = name + "-restore"
    command(["systemd-run", "--unit", guard, "--on-active=180s",
             "/usr/bin/python3", "-I", str(recovery), "restore", str(control)])
    command(["systemctl", "is-active", "--quiet", guard + ".timer"])
    code, failure = None, None
    try:
        paths["library"].mkdir(mode=0o755)
        binary = paths["library"] / "nethub"
        shutil.copyfile(cli, binary)
        binary.chmod(0o555)
        state["hashes"][str(binary)] = hashlib.sha256(binary.read_bytes()).hexdigest()
        service = (repository / "deploy/systemd/nethub-http01-cleanup.service").read_text()
        service = service.replace("/usr/local/libexec/nethub", str(binary))
        service = service.replace("/etc/nethub/http01.json", str(paths["config"]))
        service = service.replace("StateDirectory=nethub-http01", "StateDirectory=" + name)
        service = service.replace("ReadWritePaths=/srv/nethub-http01 /var/lib/nethub-http01",
                                  "ReadWritePaths=" + str(paths["public"]) + " " + str(paths["private"]))
        timer = (repository / "deploy/systemd/nethub-http01-cleanup.timer").read_text()
        timer = timer.replace("nethub-http01-cleanup.service", name + ".service")
        for key, text in (("service", service), ("timer", timer)):
            paths[key].write_text(text)
            paths[key].chmod(0o644)
            state["hashes"][str(paths[key])] = hashlib.sha256(paths[key].read_bytes()).hexdigest()
        write_state(control, state)
        command(["systemd-analyze", "verify", str(paths["service"]), str(paths["timer"])])
        command(["systemctl", "daemon-reload"])
        temporary = control / "tmp"
        temporary.mkdir(mode=0o700)
        env = dict(os.environ, TMPDIR=str(temporary), NETHUB_HTTP01_TEST_BINARY=str(binary),
                   NETHUB_HTTP01_SYSTEMD_TEST_NONCE=name.removeprefix("nethub-http01-test-"))
        with (evidence / "test.log").open("wb") as output:
            result = subprocess.run([str(test), "-test.v", "-test.run=^TestNativeHTTP01CleanupTimer$",
                                     "-test.timeout=120s"], env=env, stdout=output,
                                    stderr=subprocess.STDOUT, timeout=135)
            code = result.returncode
    except Exception as error:
        failure = type(error).__name__
    finally:
        restore(control)
        command(["systemctl", "stop", guard + ".timer", guard + ".service"], check=False)
        for suffix in (".timer", ".service"):
            active = command(["systemctl", "show", guard + suffix,
                              "--property=ActiveState", "--value"]).stdout.strip()
            assert active in (b"inactive", b"failed")
    log = (evidence / "test.log").read_text() if (evidence / "test.log").exists() else ""
    passed = code == 0 and failure is None and "Actual shipped systemd cleanup timer/service ran" in log
    result = {"passed": passed, "failure_type": failure, "owned_units_and_paths_removed": True,
              "guard_stopped_after_cleanup": True, "tested_files_sha256": state["hashes"]}
    (evidence / "result.json").write_text(json.dumps(result, indent=2))
    assert control.resolve() == control and control.parent == Path("/run")
    shutil.rmtree(control)
    print(json.dumps({key: value for key, value in result.items() if key != "tested_files_sha256"}))
    if not passed:
        raise SystemExit("Native cleanup timer acceptance failed; evidence retained")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "restore":
        restore(Path(sys.argv[2]))
    else:
        parser = argparse.ArgumentParser()
        parser.add_argument("repository", type=Path)
        parser.add_argument("cli", type=Path)
        parser.add_argument("test_binary", type=Path)
        parser.add_argument("evidence", type=Path)
        args = parser.parse_args()
        run(args.repository.resolve(strict=True), args.cli.resolve(strict=True),
            args.test_binary.resolve(strict=True), args.evidence.resolve())
