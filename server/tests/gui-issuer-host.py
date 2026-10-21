"""Run protected host issuance with an independent, nonce-owned cleanup guard."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import time

if not __debug__:
    raise SystemExit("Host acceptance requires enabled ownership assertions")


def command(args, timeout=25, check=True):
    if args[0] == "docker":
        args = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", *args[1:]]
    env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
           "HOME": "/root", "LANG": "C", "LC_ALL": "C"}
    return subprocess.run(args, env=env, capture_output=True, timeout=timeout, check=check)


def resources(nonce):
    ca = "nethub-acme-test-" + nonce
    project = "nethub-stack-test-" + nonce
    return [("container", ca + "-proxy", "caddy"), ("container", ca, "pebble"),
            ("container", project + "-postgres", "postgres"),
            ("network", ca + "-network", None),
            ("network", project + "_database", None),
            ("volume", project + "_database", None)]


def inspect(kind, name):
    result = command(["docker", kind, "inspect", name], check=False)
    if result.returncode:
        # A daemon failure is not evidence that the resource is absent.
        command(["docker", "info", "--format", "{{.ID}}"])
        assert b"no such" in result.stderr.lower() or b"not found" in result.stderr.lower()
        return None
    values = json.loads(result.stdout)
    assert len(values) == 1
    return values[0]


def units(nonce):
    name = "nethub-host-test-" + nonce
    return [name + "-issuer.service", name + ".timer", name + ".service"]


def restore(control):
    assert os.geteuid() == 0 and control.parent == Path("/run")
    assert re.fullmatch(r"nethub-host-issuer-test-[a-f0-9]{16}", control.name)
    assert control.resolve() == control and control.stat().st_uid == 0
    assert stat.S_IMODE(control.stat().st_mode) == 0o700
    with (control / "cleanup.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = json.loads((control / "state.json").read_text())
        nonce = control.name.removeprefix("nethub-host-issuer-test-")
        assert state["nonce"] == nonce
        process = control / "process.json"
        if process.exists():
            identity = json.loads(process.read_text())
            proc = Path("/proc") / str(identity["pid"])

            def same_process():
                try:
                    return (proc.joinpath("stat").read_text().split()[21] == identity["start"]
                            and str(control / "guiacme.test").encode() in proc.joinpath("cmdline").read_bytes())
                except FileNotFoundError:
                    return False

            if same_process():
                assert os.getpgid(identity["pid"]) == identity["pid"]
                os.killpg(identity["pid"], signal.SIGTERM)
                time.sleep(0.2)
                if same_process():
                    os.killpg(identity["pid"], signal.SIGKILL)
            # A timed-out test may exit before its CLI child. Verify that the
            # remaining group still contains this operation's executable before
            # signalling it; a reused, unrelated process group is preserved.
            owned = {str(control / "nethub"), str(control / "guiacme.test")}
            for candidate in Path("/proc").iterdir():
                if not candidate.name.isdecimal():
                    continue
                try:
                    group = int(candidate.joinpath("stat").read_text().split()[4])
                    executable = os.readlink(candidate / "exe")
                    if group == identity["pid"] and executable in owned:
                        os.killpg(group, signal.SIGKILL)
                except (FileNotFoundError, ProcessLookupError, PermissionError):
                    continue
        command(["systemctl", "stop", *units(nonce)], check=False)
        for unit in units(nonce):
            active = command(["systemctl", "show", unit, "--property=ActiveState", "--value"]).stdout.strip()
            assert active in (b"inactive", b"failed")
            path = Path("/run/systemd/system") / unit
            if path.exists() or path.is_symlink():
                info = path.lstat()
                assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                path.unlink()
        command(["systemctl", "daemon-reload"])
        project = "nethub-stack-test-" + nonce
        for kind, name, image in resources(nonce):
            value = inspect(kind, name)
            if value is None:
                continue
            labels = value.get("Config", {}).get("Labels", {}) if kind == "container" else value.get("Labels", {})
            if name.startswith(project):
                assert labels.get("com.docker.compose.project") == project
            else:
                assert labels.get("org.nethub.guiacme-test") == nonce
            if kind == "container":
                assert labels.get("org.nethub.guiacme-test") == nonce
                assert value["Image"] == state["images"][image]
                assert not value["HostConfig"].get("PortBindings")
                if image != "postgres":
                    assert value["HostConfig"]["ReadonlyRootfs"]
            command(["docker", kind, "rm", *(["--force"] if kind == "container" else []), name])
        assert all(inspect(kind, name) is None for kind, name, _ in resources(nonce))
        temporary = control / "tmp"
        if temporary.exists():
            assert temporary.resolve() == temporary and temporary.stat().st_uid == 0
            shutil.rmtree(temporary)
        (control / "cleanup.json").write_text(json.dumps({"owned_resources_and_units_removed": True,
                                                         "temporary_keys_removed": not temporary.exists()}))


def run(args):
    assert os.geteuid() == 0 and Path("/run/systemd/system").is_dir()
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    nonce = secrets.token_hex(8)
    control = Path("/run") / ("nethub-host-issuer-test-" + nonce)
    for kind, name, _ in resources(nonce):
        assert inspect(kind, name) is None
    for unit in units(nonce):
        assert command(["systemctl", "show", unit, "--property=LoadState", "--value"]).stdout.strip() == b"not-found"
        assert not (Path("/run/systemd/system") / unit).is_symlink()
    control.mkdir(mode=0o700)
    images = {}
    for name in ("postgres", "caddy", "pebble"):
        image = json.loads(command(["docker", "image", "inspect", getattr(args, name)]).stdout)
        assert len(image) == 1 and image[0]["Os"] == "linux" and image[0]["Architecture"] == "amd64"
        images[name] = image[0]["Id"]
    hashes = {}
    for source, name in ((args.cli, "nethub"), (args.test_binary, "guiacme.test"),
                         (args.repository / "deploy/systemd/nethub-gui-issuer.service", "issuer.service")):
        target = control / name
        shutil.copyfile(source, target)
        target.chmod(0o555 if name != "issuer.service" else 0o600)
        hashes[name] = hashlib.sha256(target.read_bytes()).hexdigest()
    (control / "state.json").write_text(json.dumps({"nonce": nonce, "images": images}))
    recovery = control / "restore.py"
    shutil.copyfile(Path(__file__).resolve(), recovery)
    recovery.chmod(0o600)
    guard = control.name + "-restore"
    command(["systemd-run", "--unit", guard, "--on-active=360s",
             "/usr/bin/python3", "-I", str(recovery), "restore", str(control)])
    command(["systemctl", "is-active", "--quiet", guard + ".timer"])
    temporary = control / "tmp"
    temporary.mkdir(mode=0o700)
    env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root",
           "LANG": "C", "LC_ALL": "C", "TMPDIR": str(temporary),
           "DOCKER_HOST": "unix:///var/run/docker.sock",
           "NETHUB_GUIACME_TEST_NONCE": nonce, "NETHUB_HOST_ISSUER_BINARY": str(control / "nethub"),
           "NETHUB_HOST_POSTGRES_IMAGE": args.postgres, "NETHUB_HOST_ISSUER_UNIT": str(control / "issuer.service"),
           "NETHUB_GUIACME_PEBBLE_IMAGE": args.pebble, "NETHUB_GUIACME_CADDY_IMAGE": args.caddy}
    code, failure = None, None
    try:
        with (args.evidence / "test.log").open("wb") as output:
            process = subprocess.Popen([str(control / "guiacme.test"), "-test.v",
                                        "-test.run=^TestPebbleProtectedHostIssuer$", "-test.timeout=180s"],
                                       env=env, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            start = (Path("/proc") / str(process.pid) / "stat").read_text().split()[21]
            (control / "process.json").write_text(json.dumps({"pid": process.pid, "start": start}))
            code = process.wait(timeout=210)
    except Exception as error:
        failure = type(error).__name__
    finally:
        restore(control)
        command(["systemctl", "stop", guard + ".timer", guard + ".service"], check=False)
        for suffix in (".timer", ".service"):
            assert command(["systemctl", "show", guard + suffix, "--property=ActiveState", "--value"]).stdout.strip() in (b"inactive", b"failed")
    log = (args.evidence / "test.log").read_text()
    passed = (code == 0 and failure is None and "--- PASS: TestPebbleProtectedHostIssuer" in log
              and "Protected host command passed genuine Compose database discovery" in log)
    result = {"passed": passed, "failure_type": failure, "tested_files_sha256": hashes,
              **json.loads((control / "cleanup.json").read_text()), "guard_stopped_after_cleanup": True}
    (args.evidence / "result.json").write_text(json.dumps(result, indent=2))
    assert control.resolve() == control and control.parent == Path("/run")
    shutil.rmtree(control)
    print(json.dumps({key: value for key, value in result.items() if key != "tested_files_sha256"}))
    if not passed:
        raise SystemExit("Protected host issuance acceptance failed; private evidence retained")


if __name__ == "__main__":
    os.umask(0o077)
    if len(sys.argv) == 3 and sys.argv[1] == "restore":
        restore(Path(sys.argv[2]))
    else:
        parser = argparse.ArgumentParser()
        for name in ("repository", "cli", "test_binary", "evidence"):
            parser.add_argument(name, type=Path)
        for name in ("postgres", "caddy", "pebble"):
            parser.add_argument(name)
        options = parser.parse_args()
        for name in ("repository", "cli", "test_binary"):
            setattr(options, name, getattr(options, name).resolve(strict=True))
        options.evidence = options.evidence.resolve()
        run(options)
