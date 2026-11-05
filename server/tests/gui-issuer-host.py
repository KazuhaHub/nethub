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
                    fields = candidate.joinpath("stat").read_text().rpartition(")")[2].split()
                    group = int(fields[2])
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


def acceptance_evidence(code, failure, log, *, diagnostic=False):
    completed = re.findall(r"^--- PASS: (TestPebbleProtectedHost(?:Issuer(?:Renewal)?|AccountProvisioning)) \([0-9]+(?:\.[0-9]+)?s\)$", log, re.MULTILINE)
    initial = (completed.count("TestPebbleProtectedHostIssuer") == 1 and
               "one original order/finalize POST; native application not claimed" in log)
    renewal = (completed.count("TestPebbleProtectedHostIssuerRenewal") == 1 and
               "Genuine host renewal passed original CSR/key, two distinct issued leaves" in log and
               "exactly two original orders/finalize POSTs; native application not claimed" in log)
    delivery = "Fresh compiled device enrollment, original CSR admission/initial queue, genuine CA issuance and authenticated original-key delivery passed" in log
    provisioning = (completed.count("TestPebbleProtectedHostAccountProvisioning") == 1 and
                    "Protected account commands passed offline initialization, verified immutable backup" in log and
                    "fresh terms review, outdated/missing-backup consent refusal, explicit private-CA registration retry and original-account recovery from pre-registration backup" in log)
    publication = log.count("Protected relay trust commands passed pending read, explicit initialization, exact retry, overlap CAS, stale/unsafe refusal and unchanged authority/runtime") == 1
    authority = log.count("Protected relay authority commands passed expected-root refusal, immutable preparation, independent backup verification and unchanged active authority/runtime/head") == 1
    lease = log.count("Protected shared relay lease refused publication and offline authority during contention, skipped renewal, then recovered without changing authority/runtime/head") == 1
    custody = log.count("Protected relay authority custody required explicit acknowledgement, preserved exact retry timestamp and refused a missing independent backup without changing active authority/runtime/head") == 1
    snapshot = log.count("Protected authority snapshot preserved all active files, staged independent successor backup and refused damaged copies and unresolved maintenance") == 1
    recovery = log.count("Authority file recovery passed real PostgreSQL rollback and lost-commit recovery, exact manifests and backups, retained maintenance, unchanged credentials and independently verified fixture TLS; no authz/frps reload or native application") == 1
    passed = (code == 0 and failure is None and initial and renewal and delivery and provisioning and publication and authority and lease and custody and snapshot and recovery and
              "Protected host command passed genuine Compose database discovery" in log)
    proofs = {"initial_issuance_verified": initial,
              "authenticated_delivery_verified": delivery,
              "renewal_verified": renewal,
              "account_provisioning_verified": provisioning,
              "relay_trust_publication_verified": publication,
              "relay_authority_preparation_verified": authority,
              "relay_operation_lease_verified": lease,
              "relay_authority_custody_verified": custody,
              "relay_authority_snapshot_verified": snapshot,
              "relay_authority_file_recovery_verified": recovery}
    if diagnostic:
        return {**proofs, "database_discovery_verified":
                "Protected host command passed genuine Compose database discovery" in log}
    return {"passed": passed, **{key: passed and value for key, value in proofs.items()}}


def process_metadata(control, phase, error):
    phases = {"log_open", "process_launch", "process_identity", "process_record", "process_wait", "process_complete"}
    result = {"version": 1, "phase": phase if phase in phases else "unclassified",
              "error_number": "unavailable", "executable_regular": "unavailable",
              "executable_root_owned": "unavailable", "executable_mode_valid": "unavailable",
              "executable_single_link": "unavailable", "filesystem_noexec": "unavailable"}
    number = error.errno if isinstance(error, OSError) else None
    if type(number) is int and 0 <= number <= 255:
        result["error_number"] = number
    try:
        info = (control / "guiacme.test").lstat()
        result.update(executable_regular=stat.S_ISREG(info.st_mode), executable_root_owned=info.st_uid == 0,
                      executable_mode_valid=stat.S_IMODE(info.st_mode) == 0o555,
                      executable_single_link=info.st_nlink == 1)
    except OSError:
        pass
    try:
        if hasattr(os, "ST_NOEXEC"):
            result["filesystem_noexec"] = bool(os.statvfs(control).f_flag & os.ST_NOEXEC)
    except OSError:
        pass
    return result


def run_host_process(control, log_path, env):
    code, failure, error = None, None, None
    phase = "log_open"
    try:
        with log_path.open("wb") as output:
            phase = "process_launch"
            process = subprocess.Popen([str(control / "guiacme.test"), "-test.v",
                "-test.run=^TestPebbleProtectedHost(Issuer(Renewal)?|AccountProvisioning)$", "-test.timeout=180s"],
                env=env, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            phase = "process_identity"
            start = (Path("/proc") / str(process.pid) / "stat").read_text().split()[21]
            phase = "process_record"
            (control / "process.json").write_text(json.dumps({"pid": process.pid, "start": start}))
            phase = "process_wait"
            code = process.wait(timeout=210)
            phase = "process_complete"
    except Exception as caught:
        error, failure = caught, type(caught).__name__
    return code, failure, process_metadata(control, phase, error)


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
    try:
        code, failure, process_diagnostic = run_host_process(control, args.evidence / "test.log", env)
    finally:
        restore(control)
        command(["systemctl", "stop", guard + ".timer", guard + ".service"], check=False)
        for suffix in (".timer", ".service"):
            assert command(["systemctl", "show", guard + suffix, "--property=ActiveState", "--value"]).stdout.strip() in (b"inactive", b"failed")
    log = (args.evidence / "test.log").read_text()
    evidence = acceptance_evidence(code, failure, log)
    result = {**evidence, "failure_type": failure, "host_process_diagnostic": process_diagnostic,
              "tested_files_sha256": hashes,
              **json.loads((control / "cleanup.json").read_text()), "guard_stopped_after_cleanup": True}
    (args.evidence / "result.json").write_text(json.dumps(result, indent=2))
    assert control.resolve() == control and control.parent == Path("/run")
    shutil.rmtree(control)
    print(json.dumps({key: value for key, value in result.items() if key != "tested_files_sha256"}))
    if not evidence["passed"]:
        # Fixed proof identifiers explain admission failure without exporting
        # private child output, certificates, paths or server responses.
        for key, value in acceptance_evidence(code, failure, log, diagnostic=True).items():
            if value is False:
                print("NETHUB_HOST_PROOF_MISSING=" + key)
        if code != 0 or failure is not None:
            print("NETHUB_HOST_TEST_EXIT=nonzero")
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
