"""Exercise the rebuilt nonroot frps image and its authenticated admin API."""

import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


stage, image, container = sys.argv[1:]
config = Path(stage) / "frps.toml"
user, password, token = (secrets.token_hex(32) for _ in range(3))
config.write_text(
    'bindAddr = "127.0.0.1"\nbindPort = 7000\n'
    'log.to = "console"\nlog.level = "warn"\n'
    'webServer.addr = "0.0.0.0"\nwebServer.port = 7500\n'
    f'webServer.user = "{user}"\nwebServer.password = "{password}"\n'
    f'auth.method = "token"\nauth.token = "{token}"\n',
    encoding="utf-8",
)
os.chmod(config, 0o600)
os.chown(config, 65532, 65532)
assert docker("run", "--rm", "--network", "none", image, "--version") == "0.71.1"
docker(
    "run", "--detach", "--name", container, "--read-only", "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges:true", "--network", "bridge",
    "--publish", "127.0.0.1::7500", "--volume", f"{config}:/etc/frps.toml:ro",
    image, "-c", "/etc/frps.toml",
)
try:
    info = json.loads(docker("inspect", container))[0]
    assert info["Config"]["User"] == "65532:65532"
    binding = info["NetworkSettings"]["Ports"]["7500/tcp"][0]
    assert binding["HostIp"] == "127.0.0.1"
    origin = f'http://127.0.0.1:{int(binding["HostPort"])}'
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(path, credentials=None):
        headers = {}
        if credentials is not None:
            headers["Authorization"] = "Basic " + base64.b64encode(credentials.encode()).decode()
        try:
            with opener.open(urllib.request.Request(origin + path, headers=headers), timeout=1) as response:
                return response.status, response.read(65537), response.headers
        except urllib.error.HTTPError as error:
            return error.code, error.read(65537), error.headers

    for attempt in range(60):
        try:
            if request("/healthz")[0] == 200:
                break
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.1)
    else:
        raise RuntimeError("frps did not become ready")
    assert request("/api/proxy/https")[0] == 401
    assert request("/api/proxy/https", f"{user}:invalid")[0] == 401
    status, body, headers = request("/api/proxy/https", f"{user}:{password}")
    assert status == 200 and headers.get_content_type() == "application/json"
    assert json.loads(body) == {"proxies": []}
    print("Rebuilt frps 0.71.1: nonroot startup, admin authentication and empty route response passed")
finally:
    docker("rm", "--force", container)
