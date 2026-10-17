#!/usr/bin/env python3
"""Boot an isolated, disposable OPNsense VM; this does not accept W0.

The release image is a live 26.7 installer. W0 still requires an installed
26.7.1_1-or-newer test device and the real-network experiments in RUNBOOK.md.
No credentials are provided and no NetHub package is installed.
"""

from __future__ import annotations

import argparse
import base64
import bz2
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import time
import urllib.request

BASE = "https://pkg.opnsense.org/releases/26.7/"
IMAGE = "OPNsense-26.7-serial-amd64.img"
IMAGE_SHA256 = "259b441646f1b0d77075a7281e368fe7f4c980360498ed6bc23740bd83c67e32"
KEY_SHA256 = "9f3b76ffef38fb6405595038b324b61043c9a2c375ae5c151d628508e9a845ce"
ANNOUNCEMENT = (
    "https://raw.githubusercontent.com/opnsense/changelog/"
    "fd539a8f722f56354e117faa5ab1495a4ad14d5b/community/26.7/26.7"
)


def download(url: str, destination: Path) -> None:
    with urllib.request.urlopen(url, timeout=60) as response:
        with destination.open("wb") as target:
            shutil.copyfileobj(response, target)


def sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def redact(text: str) -> str:
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP redacted]", text)
    text = re.sub(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b", "[MAC redacted]", text)
    text = re.sub(r"(?i)(?:[0-9a-f]{0,4}:){2,}[0-9a-f:%]+", "[IPv6 redacted]", text)
    return "\n".join(line for line in text.splitlines() if not re.search(r"password|credentials", line, re.I)) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    summary = {
        "scope": "Disposable live-image boot preflight; not W0 acceptance",
        "image": IMAGE,
        "compressed_sha256": IMAGE_SHA256,
        "announcement": ANNOUNCEMENT,
        "guest_memory_mib": 3072,
        "network": "Two restricted QEMU user-mode networks; no bridged adapter or published port",
        "credentials_supplied": False,
        "w0_accepted": False,
        "booted": False,
    }
    process = None
    serial = output / "serial.log"
    try:
        compressed = output / f"{IMAGE}.bz2"
        image = output / IMAGE
        key = output / "release.pub"
        signature = output / "image.sig"
        download(BASE + compressed.name, compressed)
        if sha256(compressed) != IMAGE_SHA256:
            raise RuntimeError("Compressed image checksum does not match the official announcement")
        download(BASE + "OPNsense-26.7.pub", key)
        if sha256(key) != KEY_SHA256:
            raise RuntimeError("Release public key checksum changed")
        with urllib.request.urlopen(ANNOUNCEMENT, timeout=30) as response:
            announcement = response.read().decode("utf-8")
        match = re.search(r"# -----BEGIN PUBLIC KEY-----.*?# -----END PUBLIC KEY-----", announcement, re.S)
        if match is None:
            raise RuntimeError("Pinned upstream announcement has no public key")
        published_key = "\n".join(line.removeprefix("# ") for line in match.group().splitlines())
        if published_key.strip() != key.read_text(encoding="ascii").strip():
            raise RuntimeError("Release key disagrees with the independent upstream announcement")
        if f"SHA256 ({compressed.name}) = {IMAGE_SHA256}" not in announcement:
            raise RuntimeError("Image checksum disagrees with the independent upstream announcement")
        with bz2.open(compressed, "rb") as source, image.open("wb") as target:
            shutil.copyfileobj(source, target)
        with urllib.request.urlopen(BASE + IMAGE + ".sig", timeout=30) as response:
            signature.write_bytes(base64.b64decode(response.read()))
        subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(key), "-signature", str(signature), str(image)],
            check=True, capture_output=True,
        )
        summary["signature_verified"] = True
        print("Image checksum, independent public key, and image signature verified.", flush=True)
        command = [
            "qemu-system-x86_64", "-accel", "kvm", "-cpu", "host",
            "-m", "3072", "-smp", "2", "-snapshot", "-no-reboot",
            "-drive", f"file={image},format=raw,if=virtio",
            "-display", "none", "-monitor", "none", "-serial", f"file:{serial}",
            "-netdev", "user,id=wan,restrict=on", "-device", "e1000,netdev=wan",
            "-netdev", "user,id=lan,restrict=on", "-device", "e1000,netdev=lan",
        ]
        start = time.monotonic()
        with (output / "qemu.log").open("w", encoding="utf-8") as log:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            until = start + 360
            while time.monotonic() < until:
                if process.poll() is not None:
                    raise RuntimeError("QEMU exited before the guest reached its login prompt")
                text = serial.read_text(encoding="utf-8", errors="replace") if serial.exists() else ""
                if "OPNsense" in text and re.search(r"(?:^|\n)[^\n]*login:\s*$", text):
                    summary["booted"] = True
                    summary["boot_seconds"] = round(time.monotonic() - start, 1)
                    print("The isolated OPNsense guest reached its login prompt.", flush=True)
                    break
                time.sleep(2)
            else:
                raise TimeoutError("Guest did not reach a login prompt within 360 seconds")
    except Exception as error:
        summary["error"] = str(error)
        raise
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if serial.exists():
            (output / "serial-redacted.log").write_text(redact(serial.read_text(encoding="utf-8", errors="replace")), encoding="utf-8")
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
