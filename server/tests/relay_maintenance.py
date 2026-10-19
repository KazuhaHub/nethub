"""Exercise the real host renewal command while two official frpc clients run."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import time


def exercise(stage, project, assignments, check_tunnels):
    work = stage / "relay-maintenance"
    work.mkdir(mode=0o700)
    bundle = stage / "deployment"
    compose = ["docker", "compose", "--project-name", project,
               "--file", str(bundle / "docker-compose.yml"),
               "--file", str(bundle / "docker-compose.override.yml"),
               "--file", str(stage / "test.yml")]

    def command(args, label, timeout=40, env=None, success=True):
        result = subprocess.run(args, capture_output=True, timeout=timeout, env=env)
        (work / (label + ".log")).write_bytes(result.stdout + result.stderr)
        if success and result.returncode:
            sys.stderr.buffer.write(result.stderr[-4000:])
            raise RuntimeError(label + " failed; private diagnostic retained")
        return result

    def container(service):
        return command(compose + ["ps", "--quiet", service], service + "-id").stdout.decode().strip()

    unchanged = {name: container(name) for name in ("postgres", "nethub-web", "nethub-authz", "caddy")}
    host_binary = work / "nethub"
    command(["docker", "cp", unchanged["nethub-web"] + ":/nethub", str(host_binary)], "copy-host-command")
    host_binary.chmod(0o700)
    authority = bundle / "secrets/issuer"
    initial_key_hash = hashlib.sha256((authority / "ca-key.pem").read_bytes()).digest()
    command(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-noenc",
             "-keyout", str(work / "due-key.pem"), "-out", str(work / "due.csr"),
             "-subj", "/CN=console.example.com"], "due-csr")
    (work / "index").write_text("")
    (work / "serial").write_text("1000\n")
    (work / "ca.cnf").write_text(f"""[ca]
default_ca = fixture
[fixture]
database = {work}/index
serial = {work}/serial
new_certs_dir = {work}
certificate = {authority}/ca.pem
private_key = {authority}/ca-key.pem
default_md = sha256
policy = identity
x509_extensions = server
[identity]
commonName = supplied
[server]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:console.example.com
""")
    now = datetime.now(timezone.utc)
    command(["openssl", "ca", "-batch", "-notext", "-config", str(work / "ca.cnf"),
             "-in", str(work / "due.csr"), "-out", str(work / "due-cert.pem"),
             "-startdate", (now - timedelta(hours=2)).strftime("%y%m%d%H%M%SZ"),
             "-enddate", (now + timedelta(minutes=15)).strftime("%y%m%d%H%M%SZ")], "due-certificate")
    for source, target in (("due-cert.pem", "relay-cert.pem"), ("due-key.pem", "relay-key.pem")):
        (bundle / "runtime/relay" / target).write_bytes((work / source).read_bytes())
    command(compose + ["restart", "frps"], "load-due-fixture")
    check_tunnels()

    def observed():
        context = ssl.create_default_context(cafile=str(bundle / "runtime/trust/relay-ca.pem"))
        with socket.create_connection(("127.0.0.1", 7000), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=assignments[0]["server_name"]) as connection:
                return hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest()

    old = observed()
    wrapper = work / "bin"
    wrapper.mkdir(mode=0o700)
    real_docker = shutil.which("docker")
    assert real_docker
    marker = shlex.quote(str(work / "failed-once"))
    (wrapper / "docker").write_text(f"""#!/bin/sh
case " $* " in
  *" --force-recreate "*)
    if [ ! -e {marker} ]; then
      : > {marker}
      exit 23
    fi
    ;;
esac
exec {shlex.quote(real_docker)} "$@"
""")
    (wrapper / "docker").chmod(0o700)
    fault_env = dict(os.environ, PATH=str(wrapper) + os.pathsep + os.environ["PATH"])
    args = [str(host_binary), "certificates", "maintain-relay", "--directory", str(bundle),
            "--project-name", project, "--compose-file", str(stage / "test.yml")]

    def scheduled(label, path, expected_exit):
        unit = project + "-" + label
        output = work / (label + "-status.json")
        error = work / (label + "-error.log")
        try:
            command(["systemd-run", "--unit=" + unit, "--on-active=1s", "--timer-property=AccuracySec=100ms",
                     "--property=Type=oneshot", "--property=UMask=0077", "--property=NoNewPrivileges=yes",
                     "--property=TimeoutStartSec=180", "--property=TimeoutStopSec=45",
                     "--property=StandardOutput=file:" + str(output),
                     "--property=StandardError=file:" + str(error), "--setenv=PATH=" + path, *args], label + "-schedule")
            deadline = time.monotonic() + 110
            while time.monotonic() < deadline:
                status = subprocess.run(["systemctl", "show", unit + ".service", "--property=ActiveState", "--property=ExecMainStatus"],
                                        capture_output=True, text=True, timeout=5)
                fields = dict(line.split("=", 1) for line in status.stdout.splitlines() if "=" in line)
                if output.exists() and fields.get("ActiveState") in ("failed", "inactive"):
                    assert int(fields["ExecMainStatus"]) == expected_exit
                    return json.loads(output.read_text())
                time.sleep(0.2)
            raise RuntimeError("owned maintenance timer did not finish; cancelling it before cleanup")
        finally:
            command(["systemctl", "stop", unit + ".timer", unit + ".service"], label + "-stop", timeout=55, success=False)
            command(["systemctl", "reset-failed", unit + ".service"], label + "-reset", success=False)

    failed = command(args, "failed-apply", timeout=100, env=fault_env, success=False)
    assert failed.returncode == 1, "injected first recreation failure did not surface"
    state = json.loads(failed.stdout)
    assert state["phase"] == "waiting" and state["error_code"] == "apply_failed"
    assert state["last_good"] == old and state["candidate"] != old and observed() == old
    candidate = state["candidate"]
    check_tunnels()
    started = time.monotonic()
    applied = command(args + ["--retry"], "retry-issued-generation", timeout=100)
    state = json.loads(applied.stdout)
    assert state["phase"] == "idle" and state["last_good"] == candidate and not state["assessment"]["due"]
    assert state["recovery_known"] and observed() == candidate
    check_tunnels()
    interruption = round((time.monotonic() - started) * 1000)
    current_container = container("frps")
    again = json.loads(command(args, "unchanged-scan").stdout)
    assert again["last_good"] == candidate and container("frps") == current_container

    # Reinstall the still-valid due fixture, then let an actual host timer invoke
    # normal maintenance without an operator retry or a production clock bypass.
    for source, target in (("due-cert.pem", "relay-cert.pem"), ("due-key.pem", "relay-key.pem")):
        (bundle / "runtime/relay" / target).write_bytes((work / source).read_bytes())
    command(compose + ["restart", "frps"], "prepare-scheduled-renewal")
    check_tunnels()
    state = scheduled("scheduled-renewal", os.environ["PATH"], 0)
    assert state["phase"] == "idle" and state["last_good"] not in (old, candidate) and not state["assessment"]["due"]
    assert observed() == state["last_good"]
    check_tunnels()
    source_root = Path(__file__).resolve().parents[2]
    service_name = "nethub-relay-maintenance.service"
    service = (source_root / "deploy/systemd" / service_name).read_text()
    service = service.replace(next(line for line in service.splitlines() if line.startswith("ExecStart=")), "ExecStart=" + shlex.join(args))
    (work / service_name).write_text(service)
    shutil.copyfile(source_root / "deploy/systemd/nethub-relay-maintenance.timer", work / "nethub-relay-maintenance.timer")
    command(["systemd-analyze", "verify", "--man=no", str(work / service_name), str(work / "nethub-relay-maintenance.timer")], "verify-installed-unit-templates")
    assert all(container(name) == cid for name, cid in unchanged.items()), "maintenance changed an unrelated service"
    assert hashlib.sha256((authority / "ca-key.pem").read_bytes()).digest() == initial_key_hash
    for name in ("relay-cert.pem", "relay-key.pem"):
        info = (bundle / "runtime/relay" / name).stat()
        assert info.st_uid == 65532 and info.st_mode & 0o777 == 0o600
    # Ordinary doctor must still validate the live pair and unchanged backup.
    command([str(host_binary), "doctor", "--directory", str(bundle)], "doctor-after-renewal")
    (work / "result.json").write_text(json.dumps({"passed": True, "tunnels_recovered_ms": interruption,
        "rollback_verified": True, "issued_generation_reused": True, "unchanged_scan_suppressed": True,
        "actual_host_timer_passed": True, "unit_templates_verified": True}))
    print(f"Relay maintenance passed real due-leaf renewal, injected apply failure/verified rollback, issued-generation reuse, fresh TLS fingerprint and two-client recovery in {interruption} ms; unchanged scan did not restart frps; host timer and unit templates passed")
