"""Use actual HTTPS enrollment, two official frpc clients and the deployed relay."""

import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import uuid

from relay_maintenance import exercise
from relay_heartbeat import exercise_heartbeats
from relay_fleet import exercise_fleet
from relay_traffic import exercise_traffic
from relay_rotation import exercise_rotation
from relay_token_probe import exercise_token_probe
from relay_token_runtime import exercise_token_runtime


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
    startup = {b"Read-only relay observation enabled", b"Relay observation and anomaly confirmation enabled",
               b"Device enrollment API and internal relay hooks started"}
    events = []
    for line in service_log("nethub-authz", label).splitlines():
        if not line.strip() or line in startup:
            continue
        record = json.loads(line)
        assert isinstance(record, dict)
        if record.get("msg") == "Relay hook decision":
            events.append(record)
    return events


def stop_client(client):
    if client.poll() is None:
        client.terminate()
        try:
            client.wait(timeout=5)
        except subprocess.TimeoutExpired:
            client.kill()
            client.wait(timeout=5)


def curl(path, payload=None, authenticated=False, expect_json=True, method=None):
    args = ["curl", "--silent", "--show-error", "--fail", "--noproxy", "*",
            "--max-time", "8", "--cacert", str(stage / "console-ca.pem"),
            "--connect-to", f"console.example.com:443:127.0.0.1:{port}"]
    if payload is not None:
        request = work / "request.json"
        request.write_text(json.dumps(payload), encoding="utf-8")
        args += ["-H", "Content-Type: application/json", "-H", "Origin: https://console.example.com",
                 "--data-binary", "@" + str(request)]
    if method is not None:
        assert method == "PATCH"
        args += ["--request", method]
    if authenticated:
        args += ["-b", str(work / "cookies")]
        if payload is not None:
            args += ["-H", "@" + str(work / "csrf-header")]
    if path.endswith("/login"):
        args += ["-c", str(work / "cookies")]
    result = subprocess.run(args + ["--write-out", "\n%{http_code}", "https://console.example.com" + path], capture_output=True, timeout=10)
    body, _, status = result.stdout.rpartition(b"\n")
    if result.returncode != 0:
        print(json.dumps({"verified_console_failure": {"curl_exit": result.returncode,
            "http_code": int(status) if len(status) == 3 and status.isdigit() else 0}}), flush=True)
        (work / "last-console-request-error.log").write_bytes(result.stderr)
        raise RuntimeError("verified console request failed")
    return json.loads(body) if expect_json else body


class Backend(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        payload = b"x" * 65536 if self.path == "/traffic" else self.headers.get("Host", "").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


def start_client(assignment, name, backend_port, corrupt=False, subdomain=None, debug=False):
    claim = assignment["domain_claim"]
    if corrupt:
        # Change a signature byte without changing the claim's assigned identity.
        offset = claim.index(".") + 1
        claim = claim[:offset] + ("A" if claim[offset] != "A" else "B") + claim[offset + 1:]
    config = {
        "serverAddr": "127.0.0.1", "serverPort": assignment["server_port"],
        "loginFailExit": True, "auth": {"method": "token", "token": assignment["frp_token"]},
        "log": {"to": "console", "level": "debug" if debug else "warn"},
        "metadatas": {"device_id": assignment["device_id"], "domain_claim": claim},
        "transport": {"heartbeatInterval": 1, "heartbeatTimeout": 3, "tcpMux": True,
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
        (work / f"enrollment-request{index}.json").write_text(json.dumps(request), encoding="utf-8")
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
    # Console ingress crosses the fixture bridge; host-local relay probes can
    # undergo an additional source translation. Keep both observations explicit.
    caddy = subprocess.run(compose + ["ps", "--quiet", "caddy"],capture_output=True,timeout=10)
    assert caddy.returncode == 0
    inspection = subprocess.run(["docker", "inspect", caddy.stdout.decode().strip()],capture_output=True,timeout=10)
    assert inspection.returncode == 0
    networks = json.loads(inspection.stdout)[0]["NetworkSettings"]["Networks"]
    assert len(networks) == 1
    gateway = str(ipaddress.ip_address(next(iter(networks.values()))["Gateway"]))

    def sql(query,role="postgres",timeout=10,record=None):
        assert role in {"postgres","nethub_web"} and 1 <= timeout <= 120
        assert record in (None, 'fleet-pressure-seed')
        options = ['--set', 'VERBOSITY=sqlstate'] if record else []
        try:
            result = subprocess.run(compose + ["exec","-T","postgres","psql","-X","--set","ON_ERROR_STOP=1"] +
                options + ["-U",role,"-d","nethub","-tAc",query],capture_output=True,timeout=timeout)
        except subprocess.TimeoutExpired as error:
            if record is None:
                raise
            (work/(record+'.log')).write_bytes((error.stdout or b'')+(error.stderr or b''))
            raise RuntimeError('isolated fleet-pressure seed exceeded its caller budget') from None
        (work/("source-sql-"+role+".log")).write_bytes(result.stdout+result.stderr)
        if record:
            (work/(record+'.log')).write_bytes(result.stdout+result.stderr)
            if result.returncode:
                found = re.search(rb'\b(?:ERROR|FATAL):\s+([0-9A-Z]{5})\b', result.stderr)
                code = found[1].decode() if found else 'unclassified'
                if code not in {'23503','23505','23514','42601','57014','53100','53200','53300','40P01'}:
                    code = 'unclassified'
                raise RuntimeError('isolated fleet-pressure seed failed: '+code)
        assert result.returncode == 0, "isolated source-grant inspection failed"
        return result.stdout.decode().strip()

    # Docker can SNAT a host-local connection even when its source is bound.
    # Measure the actual peer independently; grant that local fixture source
    # through the same narrow web-role operation, retaining actor checks/audit.
    proof = os.urandom(32)
    with socket.socket() as listener,socket.socket() as client:
        listener.settimeout(2);client.settimeout(2)
        listener.bind((gateway,0));listener.listen(1)
        client.bind((gateway,0));client.connect(listener.getsockname());client.sendall(proof)
        connection,peer = listener.accept()
        with connection:
            connection.settimeout(2);received=b""
            while len(received)<len(proof):
                part=connection.recv(len(proof)-len(received));assert part
                received+=part
            assert received==proof
    local_source = str(ipaddress.ip_address(peer[0]))
    interfaces = subprocess.run(["ip","-j","addr"],capture_output=True,timeout=5)
    assert interfaces.returncode == 0
    owned_addresses = {entry["local"] for interface in json.loads(interfaces.stdout) for entry in interface.get("addr_info",[]) if entry["family"]=="inet"}
    assert local_source in owned_addresses
    print(json.dumps({"host_local_nat_source_measured":True,"local_tls_source_matches_console_source":local_source==gateway}))

    def grant_local_fixture_source(assignment):
        if local_source == gateway:
            return
        device=str(uuid.UUID(assignment["device_id"]));actor=str(uuid.UUID(login["user"]["id"]))
        tenant=str(uuid.UUID(sql("SELECT tenant_id FROM devices WHERE id='"+device+"';")))
        sql("BEGIN; SELECT set_config('app.tenant_id','"+tenant+"',true); SELECT append_audit('user','"+actor+"','device.access_granted','"+device+"',jsonb_build_object('source_ip','"+local_source+"','expires_at',opened.expires_at,'fixture_local_nat',true)) FROM (SELECT open_device('"+actor+"','"+device+"','"+local_source+"'::inet) AS expires_at) opened; COMMIT;",role="nethub_web")

    def probe(assignment,source):
        host = assignment["subdomain"] + ".router.example.com"
        destination = "127.0.0.1" if ipaddress.ip_address(source).is_loopback else gateway
        return subprocess.run(["curl","--silent","--fail","--noproxy","*","--max-time","2","--interface",source,
            "--cacert",str(work/"backend-cert.pem"),"--connect-to",f"{host}:443:{destination}:8443",f"https://{host}/"],capture_output=True,timeout=4)

    deadline = time.monotonic()+20
    while sum(event.get("operation")=="NewProxy" and event.get("decision")=="allowed" for event in hook_events("source-gate-ready")) < 2:
        assert time.monotonic()<deadline, "legitimate proxies did not register before source-gate controls"
        time.sleep(.1)
    denied_before = sum(event.get("operation")=="NewUserConn" and event.get("decision")=="device_denied" for event in hook_events("before-source-denial"))
    deadline = time.monotonic()+10
    while True:
        assert probe(assignments[0],gateway).returncode != 0, "missing source grant reached the backend"
        denied_after = sum(event.get("operation")=="NewUserConn" and event.get("decision")=="device_denied" for event in hook_events("after-source-denial"))
        if denied_after > denied_before:
            break
        assert time.monotonic()<deadline, "source denial was not observed through actual NewUserConn"
        time.sleep(.1)
    for assignment in assignments:
        device = str(uuid.UUID(assignment["device_id"]))
        opened = curl("/api/v1/console/devices/"+device+"/open",{},authenticated=True)
        assert opened["url"] == "https://"+assignment["subdomain"]+".router.example.com:8443" and opened["gate_expires_at"]
        actor = str(uuid.UUID(login["user"]["id"]))
        assert sql("SELECT host(source_ip) FROM device_access_grants WHERE device_id='"+device+"' AND user_id='"+actor+"';") == gateway
        grant_local_fixture_source(assignment)

    def check_tunnels():
        deadline = time.monotonic() + 30
        for assignment in assignments:
            host = assignment["subdomain"] + ".router.example.com"
            while time.monotonic() < deadline:
                result = subprocess.run([
                    "curl", "--silent", "--fail", "--noproxy", "*", "--max-time", "2",
                    "--interface", gateway,
                    "--cacert", str(work / "backend-cert.pem"),
                    "--connect-to", f"{host}:443:{gateway}:8443", f"https://{host}/",
                ], capture_output=True, timeout=4)
                if result.returncode == 0 and result.stdout.decode() == host:
                    break
                time.sleep(0.2)
            else:
                events = hook_events("failed-source-tunnel-authz")
                print(json.dumps({"last_tunnel_curl_exit":result.returncode,"newuserconn_decisions":{decision:sum(event.get("operation")=="NewUserConn" and event.get("decision")==decision for event in events) for decision in ("allowed","device_denied","unavailable","connection_policy")}}))
                raise RuntimeError("verified TLS passthrough did not become available")
        assert all(client.poll() is None for client in valid_clients)

    check_tunnels()
    other_source = "127.0.0.2" if local_source != "127.0.0.2" else "127.0.0.3"
    denied_before = sum(event.get("operation")=="NewUserConn" and event.get("decision")=="device_denied" for event in hook_events("before-wrong-source"))
    assert probe(assignments[0],other_source).returncode != 0, "another source reused the explicit grant"
    assert sum(event.get("operation")=="NewUserConn" and event.get("decision")=="device_denied" for event in hook_events("after-wrong-source")) > denied_before
    device = str(uuid.UUID(assignments[0]["device_id"]))
    sql("UPDATE device_access_grants SET granted_at=granted_at-interval '31 minutes',expires_at=expires_at-interval '31 minutes' WHERE device_id='"+device+"';")
    expired = sql("SELECT expires_at::text FROM device_access_grants WHERE device_id='"+device+"' ORDER BY source_ip;")
    denied_before = sum(event.get("operation")=="NewUserConn" and event.get("decision")=="device_denied" for event in hook_events("before-expired-source"))
    assert probe(assignments[0],gateway).returncode != 0, "expired source grant reached the backend"
    assert sum(event.get("operation")=="NewUserConn" and event.get("decision")=="device_denied" for event in hook_events("after-expired-source")) > denied_before
    assert sql("SELECT expires_at::text FROM device_access_grants WHERE device_id='"+device+"' ORDER BY source_ip;") == expired
    curl("/api/v1/console/devices/"+device+"/open",{},authenticated=True)
    grant_local_fixture_source(assignments[0])
    check_tunnels()
    print("Official frps NewUserConn denied absent, wrong-source and expired grants; explicit Open and scoped local-source grants restored verified TLS without traffic-based renewal")
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
    exercise_traffic(stage, port, assignments, gateway, curl, check_tunnels, sql)
    exercise(stage, sys.argv[3], assignments, check_tunnels)

    revocation_clients = {}

    def revocation_client(index):
        # The fleet cases finish at least a minute after their last token batch.
        # Use fresh ordinary tokens rather than letting the initial reservation
        # age through pressure preparation; never retry a timed revocation.
        if index == 1:
            time.sleep(60)
        token = curl("/api/v1/console/enroll-tokens", {}, authenticated=True)["token"]
        request = {"agent_protocol_version": "1.0.0", "enroll_token": token, "platform": "opnsense",
                   "platform_version": "26.7.7", "agent_version": "0.0.2", "capabilities": ["remote.web"],
                   "hostname": f"heartbeat-control-{index}.example.com", "cluster_hint": False}
        assignment = curl("/api/v1/devices/enroll", request)
        (work / f"heartbeat-only-assignment-{index}.json").write_text(json.dumps(assignment), encoding="utf-8")
        opened = curl("/api/v1/console/devices/" + assignment["device_id"] + "/open", {}, authenticated=True)
        assert opened["url"] == "https://" + assignment["subdomain"] + ".router.example.com:8443"
        grant_local_fixture_source(assignment)
        name = f"heartbeat-only-client-{index}"
        client = start_client(assignment, name, backend.server_port, debug=True)
        revocation_clients[index] = client
        return assignment, work / (name + ".log"), client

    def stop_revocation_client(index):
        if index in revocation_clients:
            stop_client(revocation_clients.pop(index))

    def fresh_revoked_login(assignment, index):
        name = f"heartbeat-revoked-fresh-login-{index}"
        fresh = start_client(assignment, name, backend.server_port)
        try:
            assert fresh.wait(timeout=10) != 0, 'revoked identity established a fresh official control'
            assert b'not_authorized' in (work / (name + '.log')).read_bytes(), 'fresh official Login lacked authorization refusal'
        except subprocess.TimeoutExpired:
            raise RuntimeError('fresh revoked official Login did not exit on refusal') from None
        finally:
            stop_client(fresh)

    def fleet_client(index):
        token = curl("/api/v1/console/enroll-tokens", {}, authenticated=True)["token"]
        assignment = curl("/api/v1/devices/enroll", {
            "agent_protocol_version": "1.0.0", "enroll_token": token,
            "platform": "opnsense", "platform_version": "26.7.7", "agent_version": "0.0.2",
            "capabilities": ["remote.web"], "hostname": f"fleet-control-{index}.example.com", "cluster_hint": False,
        })
        opened = curl("/api/v1/console/devices/" + assignment["device_id"] + "/open", {}, authenticated=True)
        assert opened["url"] == "https://" + assignment["subdomain"] + ".router.example.com:8443"
        grant_local_fixture_source(assignment)
        name = f"fleet-client-{index}"
        client = start_client(assignment, name, backend.server_port, debug=True)
        return assignment, work / (name + ".log"), client

    def revoke_fleet(owned):
        if owned:
            identifiers = ','.join("'" + str(uuid.UUID(item["device_id"])) + "'" for item in owned)
            sql("UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id IN (" + identifiers + ");")
            assert sql("SELECT count(*) FROM devices WHERE revoked AND id IN (" + identifiers + ");") == str(len(owned))

    def seed_fleet_pressure():
        # Only this owned database receives synthetic snapshot rows. Keep a
        # single deployment tenant and no additional active identities, so later
        # rotation/backup checks retain their original authority boundaries.
        initial = json.loads(sql("SELECT json_build_object('tenants',(SELECT count(*) FROM tenants),"
            "'revoked',(SELECT count(*) FROM devices WHERE revoked),"
            "'floors',(SELECT count(DISTINCT (tenant_id,device_id)) FROM device_rotations));"))
        assert initial['tenants'] == 1 and initial['revoked'] < 100 and initial['floors'] < 100
        original = str(uuid.UUID(assignments[0]['device_id']))
        marker = 'snapshot-' + uuid.uuid4().hex
        # These canonical synthetic IDs sort after the genuinely enrolled v4
        # identities. Do not displace the later ordinary UI fixtures from page1.
        assert sql("SELECT count(*) FROM devices WHERE id::text LIKE 'ffffffff-ffff-ffff-ffff-%';") == '0'
        started = time.monotonic()
        # One DO statement bounds all three mutations together; reserve a
        # separate ten-second commit bound inside the 120-second caller budget.
        sql("BEGIN; SET LOCAL statement_timeout='90s'; DO $fleet$ BEGIN "
            "INSERT INTO devices(id,tenant_id,owner_user_id,hostname,label,platform,device_secret_hash,subdomain,"
            "agent_protocol_version,domain_claim_issued_at,enrolled_at) "
            "SELECT ('ffffffff-ffff-ffff-ffff-'||lpad(to_hex(series.n),12,'0'))::uuid,"
            "d.tenant_id,d.owner_user_id,'Snapshot pressure fixture','" + marker + "','opnsense',"
            "'$argon2id$load-fixture-only-'||repeat('x',64),'snapshot-'||gen_random_uuid()::text,"
            "'1.6.0',date_trunc('microseconds',statement_timestamp()),statement_timestamp()-interval '1 day' "
            "FROM devices d CROSS JOIN generate_series(1,99000) AS series(n) WHERE d.id='" + original + "'; "
            "INSERT INTO device_rotations(tenant_id,device_id,operation_id,candidate_digest,credential_hash,issued_at,relay_ca_pem) "
            "SELECT tenant_id,id,gen_random_uuid(),decode(repeat('00',32),'hex'),device_secret_hash,domain_claim_issued_at,"
            "'fixture public CA' FROM devices WHERE label='" + marker + "'; "
            "UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE label='" + marker + "'; "
            "END $fleet$; SET LOCAL statement_timeout='10s'; COMMIT;",
            timeout=120, record='fleet-pressure-seed')
        value = json.loads(sql("SELECT json_build_object("
            "'synthetic_revoked_rows',(SELECT count(*) FROM devices WHERE label='" + marker + "' AND revoked),"
            "'synthetic_rotation_floors',(SELECT count(DISTINCT r.device_id) FROM device_rotations r "
            "JOIN devices d ON d.tenant_id=r.tenant_id AND d.id=r.device_id WHERE d.label='" + marker + "'),"
            "'global_revoked_rows',(SELECT count(*) FROM devices WHERE revoked),"
            "'global_rotation_floors',(SELECT count(DISTINCT (tenant_id,device_id)) FROM device_rotations),"
            "'tenants',(SELECT count(*) FROM tenants));"))
        assert value['synthetic_revoked_rows'] == value['synthetic_rotation_floors'] == 99000
        assert value['tenants'] == 1
        assert 99000 <= value['global_revoked_rows'] <= 100000 and 99000 <= value['global_rotation_floors'] <= 100000
        value.update(seed_ms=round((time.monotonic()-started)*1000),
                     signed_claims_or_enrollments_created=False, retained_until_owned_database_teardown=True)
        return value

    exercise_fleet(stage, compose, valid_clients, fleet_client, stop_client,
                   revoke_fleet, check_tunnels, probe, local_source, seed_fleet_pressure)
    exercise_heartbeats(stage, compose, assignments, valid_clients, gateway, sql,
                        check_tunnels, probe, local_source, hook_events, revocation_client,
                        stop_revocation_client, fresh_revoked_login)
    exercise_token_probe(stage, assignments, valid_clients, check_tunnels)
    exercise_rotation(stage, port, assignments, valid_clients, start_client, stop_client,
                      backend.server_port, local_source, probe, check_tunnels, hook_events, sql)
    exercise_token_runtime(stage, port, sys.argv[3], assignments, valid_clients, start_client, stop_client,
                           backend.server_port, check_tunnels, sql)
finally:
    for client in clients:
        stop_client(client)
    for log in logs:
        log.close()
    backend.server_close()
