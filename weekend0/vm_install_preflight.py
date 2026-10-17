#!/usr/bin/env python3
"""Install OPNsense on a disposable guest disk and verify an installed boot.

This uses the vendor installer through a private serial socket. It does not
update firmware, provision SSH, expose a port, or accept any W0 experiment.
"""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
import re
import runpy
import socket
import subprocess
import sys
import time
import urllib.request

INSTALL_DOCS = "https://docs.opnsense.org/manual/install.html"


class SerialConsole:
    def __init__(self, connection: socket.socket, process: subprocess.Popen):
        self.connection = connection
        self.process = process
        self.buffer = ""
        self.transcript = bytearray()

    def expect(self, pattern: str, timeout: float = 60) -> str:
        until = time.monotonic() + timeout
        expression = re.compile(pattern, re.I | re.S)
        while time.monotonic() < until:
            self.buffer = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", self.buffer)
            match = expression.search(self.buffer)
            if match:
                text = self.buffer[:match.end()]
                self.buffer = self.buffer[match.end():]
                return text
            try:
                chunk = self.connection.recv(65536)
            except socket.timeout:
                if self.process.poll() is not None:
                    raise RuntimeError("Guest exited while waiting for a serial prompt") from None
                continue
            if not chunk:
                raise RuntimeError("Guest serial connection closed before the expected prompt")
            self.transcript.extend(chunk)
            self.buffer += chunk.decode("utf-8", errors="replace")
        raise TimeoutError("Guest did not reach the expected serial prompt")

    def send(self, text: str) -> None:
        self.connection.sendall(text.encode("utf-8"))


def installer_account() -> str:
    with urllib.request.urlopen(INSTALL_DOCS, timeout=30) as response:
        text = html.unescape(re.sub(r"<[^>]*>", " ", response.read().decode("utf-8")))
    text = re.sub(r"\s+", " ", text)
    match = re.search(r"log in with user installer and password ([\w-]+)\s*\.", text, re.I)
    if match is None:
        raise RuntimeError("Official installer-account documentation changed; refusing to guess credentials")
    return match.group(1)


def login(console: SerialConsole, password: str) -> None:
    console.expect(r"login:\s*$", timeout=180)
    console.send("root\n")
    console.expect(r"Password:\s*$")
    console.send(password + "\n")
    prompt = console.expect(r"(?:Enter an option:|[^\r\n]* #\s*$)")
    if "Enter an option:" in prompt:
        console.send("8\n")
        console.expect(r"[^\r\n]* #\s*$")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    disk = output / "installed.qcow2"
    if disk.exists():
        raise RuntimeError("The disposable installation disk already exists; use a fresh output directory")
    helper_path = Path(__file__).with_name("vm_preflight.py")
    helpers = runpy.run_path(str(helper_path), run_name="vm_helpers")
    summary = {
        "scope": "Disposable installed-system preflight; not W0 acceptance",
        "guest_disk_gib": 40,
        "guest_memory_mib": 3072,
        "network": "Two restricted user-mode networks; no bridge or published port",
        "installer_source": INSTALL_DOCS,
        "installation_completed": False,
        "installed_boot_verified": False,
        "firmware_updated": False,
        "ssh_provisioned": False,
        "w0_accepted": False,
    }
    password = ""
    process = None
    consoles: list[tuple[str, SerialConsole]] = []
    streams = []
    try:
        print("Verifying the official image with the existing boot preflight.", flush=True)
        subprocess.run([sys.executable, "-I", str(helper_path), "--output", str(output / "image")], check=True)
        image_summary = json.loads((output / "image/summary.json").read_text())
        if not image_summary.get("signature_verified") or not image_summary.get("booted"):
            raise RuntimeError("The signed-image boot preflight did not pass")
        image = output / "image" / helpers["IMAGE"]
        password = installer_account()
        subprocess.run(["qemu-img", "create", "-f", "qcow2", str(disk), "40G"], check=True, capture_output=True)

        def start_guest(name: str, live: bool) -> SerialConsole:
            nonlocal process
            serial_socket = output / f"{name}.sock"
            command = [
                "qemu-system-x86_64", "-accel", "kvm", "-cpu", "host", "-m", "3072", "-smp", "2",
                "-no-reboot", "-display", "none", "-monitor", "none",
                "-serial", f"unix:{serial_socket},server=on,wait=on",
                "-netdev", "user,id=wan,restrict=on", "-device", "e1000,netdev=wan",
                "-netdev", "user,id=lan,restrict=on", "-device", "e1000,netdev=lan",
            ]
            if live:
                command += ["-drive", f"file={image},format=raw,if=virtio,snapshot=on"]
            command += ["-drive", f"file={disk},format=qcow2,if=virtio"]
            stream = (output / f"{name}-qemu.log").open("wb")
            streams.append(stream)
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stream, stderr=stream)
            until = time.monotonic() + 20
            while not serial_socket.exists():
                if process.poll() is not None:
                    raise RuntimeError("QEMU exited before creating its private serial socket")
                if time.monotonic() >= until:
                    raise TimeoutError("QEMU did not create its private serial socket")
                time.sleep(0.1)
            connection = socket.socket(socket.AF_UNIX)
            connection.settimeout(1)
            connection.connect(str(serial_socket))
            console = SerialConsole(connection, process)
            consoles.append((name, console))
            return console

        summary["phase"] = "live login"
        console = start_guest("installer", live=True)
        login(console, password)
        print("Live-system serial login succeeded; starting the vendor installer.", flush=True)
        console.send("stty rows 40 cols 120; env BSDINSTALL_KEYMAP_DONE=1 opnsense-installer\n")
        console.expect(r"Choose one of the following tasks to perform\.")
        console.expect(r"Install \(UFS\)")
        console.send("\x1b[B\r")
        summary["phase"] = "select disposable disk"
        console.expect(r"Please select a disk to continue\.")
        console.expect(r"\bvtbd1\b")
        console.send("\r")
        console.expect(r"recommended swap partition")
        console.send("\t\r")
        confirmation = console.expect(r"Last Chance!.*?vtbd1")
        if re.search(r"\bvtbd0\b", confirmation):
            raise RuntimeError("Installer confirmation includes the installation media; refusing to continue")
        console.send("\x1b[D\r")
        summary["phase"] = "install system"
        print("Installing onto the dedicated virtual target disk.", flush=True)
        console.expect(r"Final Configuration", timeout=300)
        console.expect(r"Complete Install")
        console.send("\x1b[B\r")
        console.expect(r"Installation Complete", timeout=60)
        console.expect(r"Halt now")
        console.send("\x1b[B\r")
        process.wait(timeout=90)
        if process.returncode != 0:
            raise RuntimeError("Installer guest did not shut down cleanly")
        summary["installation_completed"] = True
        print("The vendor installer completed on the disposable target disk.", flush=True)

        summary["phase"] = "installed boot"
        console = start_guest("installed", live=False)
        login(console, password)
        if "running in live mode" in console.transcript.decode("utf-8", errors="replace"):
            raise RuntimeError("Guest still reports installation-media mode after removing the installer")
        console.send("stty -echo\n")
        console.expect(r"[^\r\n]* #\s*$")
        console.send("printf '\\nNH_VERSION='; opnsense-version -V; mount -p | awk '$2 == \"/\" {print \"NH_ROOT=\" $1; print \"NH_FSTYPE=\" $3}'; printf '\\nNH_CHECK_DONE\\n'\n")
        evidence = console.expect(r"NH_CHECK_DONE")
        version = re.search(r"NH_VERSION=([^\r\n]+)", evidence)
        if version is None or not version.group(1).startswith("26.7"):
            raise RuntimeError("Installed guest did not report the expected 26.7 release")
        if "NH_ROOT=/dev/gpt/rootfs" not in evidence or "NH_FSTYPE=ufs" not in evidence:
            raise RuntimeError("Guest root filesystem is not the newly installed UFS partition")
        summary["installed_version"] = version.group(1).strip()
        summary["installed_boot_verified"] = True
        summary["phase"] = "complete"
        console.send("/sbin/shutdown -p now\n")
        process.wait(timeout=60)
        print("Installed-system boot and the target root filesystem are verified.", flush=True)
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
        for name, console in consoles:
            text = console.transcript.decode("utf-8", errors="replace")
            if password:
                text = text.replace(password, "[installer credential redacted]")
            (output / f"{name}-redacted.log").write_text(helpers["redact"](text), encoding="utf-8")
            console.connection.close()
        for stream in streams:
            stream.close()
        (output / "install-summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
