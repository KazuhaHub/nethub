"""Use actual HTTPS enrollment, two official frpc clients and the deployed relay."""

import http.server
import json
from pathlib import Path
import ssl
import subprocess
import sys
import threading
import time

from relay_maintenance import exercise


stage, port = Path(sys.argv[1]), int(sys.argv[2])
work = stage / "relay-test"
work.mkdir(mode=0o700)
clients = []
logs = []
compose = ["docker", "compose", "--project-name", sys.argv[3],
           "--file", str(stage / "deployment/docker-compose.yml"),
           "--file", str(stage / "deployment/docker-compose.override.yml"),
           "--file", str(stage / "test.yml")]


def service_log(service, label):
    result = subprocess.run(compose + ["ps", "--quiet", service], capture_output=True, timeout=10)
    container = result.stdout.decode().strip()
    assert result.returncode == 0 and len(container) == 64 and all(c in "0123456789abcdef" for c in container)
    result = subprocess.run(["docker", "logs", container], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=10)
    assert result.returncode == 0 and len(result.stdout) < 8 * 1024 * 1024
    (work / (label + ".log")).write_bytes(result.stdout)
    return result.stdout


def hook_events(label):
    records = [json.loads(line) for line in service_log("nethub-authz", label).splitlines() if line.strip()]
    return [record for record in records if record.get("msg") == "Relay hook decision"]


def stop_client(client):
    if client.poll() is None:
        client.terminate()
        try:
            client.wait(timeout=5)
        except subprocess.TimeoutExpired:
            client.kill()
            client.wait(timeout=5)


def curl(path, payload=None, authenticated=False, expect_json=True):
    args = ["curl", "--silent", "--show-error", "--fail", "--noproxy", "*",
            "--max-time", "8", "--cacert", str(stage / "console-ca.pem"),
            "--connect-to", f"console.example.com:443:127.0.0.1:{port}"]
    if payload is not None:
        request = work / "request.json"
        request.write_text(json.dumps(payload), encoding="utf-8")
        args += ["-H", "Content-Type: application/json", "-H", "Origin: https://console.example.com",
                 "--data-binary", "@" + str(request)]
    if authenticated:
        args += ["-b", str(work / "cookies")]
        if payload is not None:
            args += ["-H", "@" + str(work / "csrf-header")]
    if path.endswith("/login"):
        args += ["-c", str(work / "cookies")]
    result = subprocess.run(args + ["https://console.example.com" + path], capture_output=True, timeout=10)
    if result.returncode != 0:
        raise RuntimeError("verified console request failed")
    return json.loads(result.stdout) if expect_json else result.stdout


class Backend(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        payload = self.headers.get("Host", "").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


def start_client(assignment, name, backend_port, corrupt=False, subdomain=None):
    claim = assignment["domain_claim"]
    if corrupt:
        # Change a signature byte without changing the claim's assigned identity.
        offset = claim.index(".") + 1
        claim = claim[:offset] + ("A" if claim[offset] != "A" else "B") + claim[offset + 1:]
    config = {
        "serverAddr": "127.0.0.1", "serverPort": assignment["server_port"],
        "loginFailExit": True, "auth": {"method": "token", "token": assignment["frp_token"]},
        "log": {"to": "console", "level": "warn"},
        "metadatas": {"device_id": assignment["device_id"], "domain_claim": claim},
        "transport": {"heartbeatInterval": 10, "heartbeatTimeout": 30,
                      "tls": {"enable": True, "serverName": assignment["server_name"],
                              "trustedCaFile": str(work / "relay-ca.pem")}},
        "proxies": [{"name": "nethub-" + assignment["device_id"] + "-web", "type": "https",
                     "localIP": "127.0.0.1", "localPort": backend_port,
                     "subdomain": assignment["subdomain"] if subdomain is None else subdomain}],
    }
    path = work / (name + ".json")
    path.write_text(json.dumps(config), encoding="utf-8")
    log = (work / (name + ".log")).open("wb")
    logs.append(log)
    client = subprocess.Popen([str(stage / "official/frpc"), "-c", str(path)], stdout=log, stderr=log)
    clients.append(client)
    return client


backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Backend)
try:
    issued = subprocess.run([
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-noenc",
        "-keyout", str(work / "backend-key.pem"), "-out", str(work / "backend-cert.pem"),
        "-days", "1", "-subj", "/CN=isolated router fixture",
        "-addext", "subjectAltName=DNS:*.router.example.com",
    ], capture_output=True, timeout=10)
    if issued.returncode != 0:
        raise RuntimeError("isolated backend certificate creation failed")
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(work / "backend-cert.pem", work / "backend-key.pem")
    backend.socket = tls.wrap_socket(backend.socket, server_side=True)
    threading.Thread(target=backend.serve_forever, daemon=True).start()

    login = curl("/api/v1/console/login", {"email": "compose-admin@example.com",
                 "password": (stage / "admin-password").read_text().strip()})
    (work / "csrf-header").write_text("X-CSRF-Token: " + login["csrf_token"] + "\n", encoding="utf-8")
    assignments = []
    for index in range(2):
        token = curl("/api/v1/console/enroll-tokens", {}, authenticated=True)["token"]
        request = {"agent_protocol_version": "1.0.0", "enroll_token": token, "platform": "opnsense",
                   "platform_version": "26.7.7", "agent_version": "0.0.2", "capabilities": ["remote.web"],
                   "hostname": f"router{index}.example.com", "cluster_hint": False}
        assignment = curl("/api/v1/devices/enroll", request)
        assert assignment["server_name"] == "console.example.com" and assignment["server_port"] == 7000
        (work / f"assignment{index}.json").write_text(json.dumps(assignment), encoding="utf-8")
        assignments.append(assignment)
    assert assignments[0]["device_id"] != assignments[1]["device_id"]
    assert assignments[0]["subdomain"] != assignments[1]["subdomain"]
    assert assignments[0]["relay_ca_pem"] == assignments[1]["relay_ca_pem"]
    assert assignments[0]["relay_ca_pem"].encode() == (stage / "deployment/runtime/trust/relay-ca.pem").read_bytes()
    (work / "relay-ca.pem").write_text(assignments[0]["relay_ca_pem"], encoding="utf-8")

    before = hook_events("before-invalid-claim-authz")
    frps_before = service_log("frps", "before-invalid-claim-frps")
    bad = start_client(assignments[0], "invalid-claim", backend.server_port, corrupt=True)
    try:
        assert bad.wait(timeout=10) != 0
    except subprocess.TimeoutExpired:
        raise RuntimeError("invalid claim was not rejected promptly") from None
    rejected = hook_events("after-invalid-claim-authz")[len(before):]
    assert any(e.get("operation") == "Login" and e.get("decision") == "invalid_claim" for e in rejected)
    assert not any(e.get("decision") == "allowed" for e in rejected)
    assert b"not_authorized" in (work / "invalid-claim.log").read_bytes()
    frps_after = service_log("frps", "after-invalid-claim-frps")
    assert frps_after.count(b"not_authorized") > frps_before.count(b"not_authorized")
    print("Tampered signature: Login invalid_claim; actual frpc and frps both recorded not_authorized")

    # Try the other enrolled device's subdomain before either route exists, so
    # an ordinary duplicate-route error cannot satisfy this rejection check.
    before = hook_events("before-cross-device-authz")
    frps_before = service_log("frps", "before-cross-device-frps")
    cross = start_client(assignments[0], "cross-device", backend.server_port,
                         subdomain=assignments[1]["subdomain"])
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            assert cross.poll() is None, "cross-device client lost its valid control connection"
            events = hook_events("after-cross-device-authz")[len(before):]
            decisions = [(e.get("operation"), e.get("decision")) for e in events]
            if ("NewProxy", "proxy_policy") in decisions:
                assert ("Login", "allowed") in decisions
                assert decisions.index(("Login", "allowed")) < decisions.index(("NewProxy", "proxy_policy"))
                assert ("NewProxy", "allowed") not in decisions
                if b"not_authorized" in (work / "cross-device.log").read_bytes():
                    break
            time.sleep(0.2)
        else:
            raise RuntimeError("cross-device proxy was not rejected by its authorization policy")
        frps_after = service_log("frps", "after-cross-device-frps")
        assert frps_after.count(b"not_authorized") > frps_before.count(b"not_authorized")
        print("Cross-device subdomain: Login allowed, NewProxy proxy_policy; actual frpc and frps both recorded not_authorized")
    finally:
        stop_client(cross)

    valid_clients = []
    for index, assignment in enumerate(assignments):
        valid_clients.append(start_client(assignment, f"client{index}", backend.server_port))
    def check_tunnels():
        deadline = time.monotonic() + 30
        for assignment in assignments:
            host = assignment["subdomain"] + ".router.example.com"
            while time.monotonic() < deadline:
                result = subprocess.run([
                    "curl", "--silent", "--fail", "--noproxy", "*", "--max-time", "2",
                    "--cacert", str(work / "backend-cert.pem"),
                    "--connect-to", f"{host}:443:127.0.0.1:8443", f"https://{host}/",
                ], capture_output=True, timeout=4)
                if result.returncode == 0 and result.stdout.decode() == host:
                    break
                time.sleep(0.2)
            else:
                raise RuntimeError("verified TLS passthrough did not become available")
        assert all(client.poll() is None for client in valid_clients)

    check_tunnels()
    for _ in range(90):
        devices = curl("/api/v1/console/devices", authenticated=True)["items"]
        observed = {device["id"] for device in devices if device["online"]}
        if observed == {assignment["device_id"] for assignment in assignments}:
            break
        time.sleep(0.25)
    else:
        raise RuntimeError("actual frps observations did not reach the console")
    assert all(client.poll() is None for client in valid_clients)
    print("Deployed relay passed verified HTTPS enrollment, tampered-claim denial, two simultaneous TLS tunnels and actual frps-to-console observations")
    print("Both legitimate assigned subdomains passed verified TLS after the operation-specific Login and NewProxy denials")
    exercise(stage, sys.argv[3], assignments, check_tunnels)
finally:
    for client in clients:
        stop_client(client)
    for log in logs:
        log.close()
    backend.server_close()
