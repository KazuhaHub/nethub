"""Exercise a generated external-proxy bundle without publishing its HTTP origins."""

import json
from pathlib import Path
import socket
import subprocess
import sys
import time


stage, root = Path(sys.argv[1]), Path(sys.argv[2])
runtime, postgres, caddy, frps = sys.argv[3:]
work = stage / "external-proxy"
work.mkdir(mode=0o700)
project = "nethub-external-" + stage.name.lower().replace(".", "-")
proxy = project + "-operator-proxy"


def run(args, label, data=None, timeout=45):
    result = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
    (work / (label + ".log")).write_bytes(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(label + " failed; diagnostic retained privately")
    return result.stdout


def unused_ports():
    held = []
    try:
        for _ in range(3):
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            held.append(listener)
        return [listener.getsockname()[1] for listener in held]
    finally:
        for listener in held:
            listener.close()


web_port, device_port, public_port = unused_ports()
bundle = work / "deployment"
compose = ["docker", "compose", "--project-name", project,
           "--file", str(bundle / "docker-compose.yml"),
           "--file", str(bundle / "docker-compose.override.yml"),
           "--file", str(work / "images.json")]
try:
    engine = run(["docker", "version", "--format", "{{.Server.Version}}"], "engine").decode().strip()
    assert int(engine.split(".")[0]) >= 28, "Loopback origin isolation requires Docker Engine 28 or newer"
    initialized = run(["docker", "run", "--rm", "-i", "--network", "none", "--user", "0",
         "-v", f"{root}:{root}:ro", "-v", f"{stage}:{stage}", runtime,
         "init", "--offline", "--proxy-mode", "external", "--web-port", str(web_port),
         "--device-port", str(device_port), "--source-directory", str(root),
         "--directory", str(bundle), "--backup-directory", str(work / "backup"),
         "--console-host", "console.example.com", "--device-domain", "router.example.com"],
        "init", b"I HAVE VERIFIED THE NETHUB SECRET BACKUP\n")
    assert b"docker compose build migrate postgres frps\n" in initialized and b"postgres frps caddy" not in initialized
    (work / "images.json").write_text(json.dumps({"services": {
        name: {"image": image} for name, image in {
            "postgres": postgres, "migrate": runtime, "admin-bootstrap": runtime,
            "nethub-web": runtime, "nethub-authz": runtime, "frps": frps}.items()}}))
    config = json.loads(run(compose + ["config", "--format", "json"], "config"))
    assert "caddy" not in config["services"]
    for name, port in (("nethub-web", web_port), ("nethub-authz", device_port)):
        ports = config["services"][name]["ports"]
        expected = {port: 8080 if name == "nethub-web" else 8081}
        if name == "nethub-authz":
            expected[9000] = 9000
        assert len(ports) == len(expected)
        assert {int(value["published"]): value["target"] for value in ports} == expected
        assert all(value["host_ip"] == "127.0.0.1" and value["protocol"] == "tcp" for value in ports)
        assert "172.30.87.1/32" in config["services"][name]["command"]
    run(compose + ["up", "--detach", "--no-build", "--wait", "--wait-timeout", "120"], "start", timeout=150)
    run(compose + ["run", "--rm", "-T", "admin-bootstrap", "--email", "external@example.com", "--password-stdin"],
        "admin", (stage / "admin-password").read_bytes())
    run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-noenc",
         "-keyout", str(work / "key.pem"), "-out", str(work / "cert.pem"), "-days", "1",
         "-subj", "/CN=external test proxy", "-addext", "subjectAltName=DNS:console.example.com"], "certificate")
    example = (bundle / "external-Caddyfile.example").read_text()
    assert example.count("console.example.com {") == 1
    front = example.replace("console.example.com {", f"https://console.example.com:{public_port} {{\n    bind 127.0.0.1\n    tls /fixture/cert.pem /fixture/key.pem", 1)
    (work / "Caddyfile").write_text("{\n    admin off\n    auto_https disable_redirects\n}\n" + front)
    run(["docker", "run", "--detach", "--name", proxy, "--network", "host", "--read-only", "--cap-drop", "ALL",
         "--tmpfs", "/data", "--tmpfs", "/config", "-v", f"{work}:/fixture:ro", caddy,
         "caddy", "run", "--config", "/fixture/Caddyfile", "--adapter", "caddyfile"], "operator-proxy")

    def request(path, payload=None, authenticated=False):
        args = ["curl", "--silent", "--show-error", "--noproxy", "*", "--max-time", "5",
                "--interface", "127.0.0.2", "--cacert", str(work / "cert.pem"),
                "--connect-to", f"console.example.com:443:127.0.0.1:{public_port}",
                "-H", "X-Forwarded-For: 203.0.113.99", "-H", "X-Real-IP: 203.0.113.99",
                "-H", "Forwarded: for=203.0.113.99;proto=http", "-w", "\n%{http_code}"]
        if payload is not None:
            data = work / "request.json"
            data.write_text(json.dumps(payload))
            args += ["-H", "Content-Type: application/json", "-H", "Origin: https://console.example.com", "--data-binary", "@" + str(data)]
        if path.endswith("/login"):
            args += ["-c", str(work / "cookies")]
        if authenticated:
            args += ["-b", str(work / "cookies")]
            if payload is not None:
                args += ["-H", "@" + str(work / "csrf-header")]
        result = subprocess.run(args + ["https://console.example.com" + path], capture_output=True, timeout=7)
        if result.returncode:
            return None, None
        body, status = result.stdout.rsplit(b"\n", 1)
        return int(status), body

    for _ in range(40):
        if request("/")[0] == 200:
            break
        time.sleep(0.25)
    else:
        startup = subprocess.run(["docker", "logs", proxy], capture_output=True, timeout=10)
        # No credential-bearing request has run at this point; retain startup
        # errors without printing any later authenticated proxy traffic.
        diagnostic = (startup.stdout + startup.stderr)[-16000:]
        (work / "proxy-startup-error.log").write_bytes(diagnostic)
        sys.stderr.buffer.write(diagnostic)
        raise RuntimeError("operator-owned TLS proxy did not become ready")
    for path in ("/healthz", "/api/v1/frp/hooks"):
        assert request(path)[0] == 404
    status, body = request("/api/v1/console/login", {"email": "external@example.com", "password": (stage / "admin-password").read_text().strip()})
    assert status == 200
    (work / "csrf-header").write_text("X-CSRF-Token: " + json.loads(body)["csrf_token"] + "\n")
    assert "#HttpOnly_" in (work / "cookies").read_text() and "\tTRUE\t" in (work / "cookies").read_text()
    status, body = request("/api/v1/console/enroll-tokens", {}, True)
    assert status == 201
    token = json.loads(body)["token"]
    status, body = request("/api/v1/devices/enroll", {
        "agent_protocol_version": "1.0.0", "enroll_token": token, "platform": "fixture",
        "platform_version": "lab", "agent_version": "0.0.2", "hostname": "external.example.com",
        "capabilities": ["remote.web"], "cluster_hint": False})
    assert status == 201 and json.loads(body)["server_name"] == "console.example.com"
    postgres_id = run(compose + ["ps", "--quiet", "postgres"], "postgres-id").decode().strip()
    audit = run(["docker", "exec", "-i", postgres_id, "sh", "-c",
                 'export PGPASSWORD="$(cat /run/secrets/pg_bootstrap)"; exec psql -h 127.0.0.1 -U postgres -d nethub -At'],
                "audit", b"SELECT payload->>'source_ip' FROM audit_log WHERE action='enroll_token.created';\n")
    assert audit.decode().strip() == "127.0.0.2", "Untrusted forwarded header changed the recorded client or proxy trust is incorrect"
    host_ips = json.loads(run(["ip", "-j", "addr"], "interfaces"))
    addresses = {entry["local"] for item in host_ips for entry in item.get("addr_info", [])
                 if entry["family"] == "inet" and entry["local"] != "127.0.0.1"}
    assert addresses
    for address in addresses:
        for port in (web_port, device_port, 9000):
            with socket.socket() as probe:
                probe.settimeout(0.5)
                assert probe.connect_ex((address, port)) != 0, "HTTP origin reachable through a non-loopback address"
    log = run(compose + ["logs", "--no-color"], "runtime").decode()
    assert token not in log and (stage / "admin-password").read_text().strip() not in log
    for key in ("frp_token", "device_secret", "domain_claim"):
        assert json.loads(body)[key] not in log
    print("External proxy: bundled TLS owner absent, loopback-only origins, verified host TLS, console/device routing, secure session and spoofed-source rejection passed")
finally:
    subprocess.run(["docker", "rm", "--force", proxy], capture_output=True, timeout=20)
    if (work / "images.json").exists():
        result = subprocess.run(compose + ["down", "--volumes", "--remove-orphans"], capture_output=True, timeout=40)
        (work / "cleanup.log").write_bytes(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError("external-proxy cleanup failed")
