"""Regression checks for the private serial protocol used by the installer."""

from pathlib import Path
import runpy
import socket
import threading
import unittest

module = runpy.run_path(
    str(Path(__file__).with_name("vm_install_preflight.py")),
    run_name="installer_protocol_tests",
)
SerialConsole = module["SerialConsole"]


class RunningGuest:
    def poll(self):
        return None


class SerialProtocolTests(unittest.TestCase):
    def setUp(self):
        self.client, self.guest = socket.socketpair()
        self.client.settimeout(0.05)
        self.guest.settimeout(1)
        self.console = SerialConsole(self.client, RunningGuest())

    def tearDown(self):
        self.client.close()
        self.guest.close()

    def test_terminal_size_query_and_cursor_mode_changes(self):
        replies = []

        def guest_query():
            self.guest.sendall(b"\x1b[?1h\x1b[999;999H\x1b[")
            self.guest.sendall(b"6nready")
            replies.append(self.guest.recv(32))

        sender = threading.Thread(target=guest_query)
        sender.start()
        self.console.expect("ready", timeout=1)
        sender.join(timeout=1)
        self.assertFalse(sender.is_alive())
        self.assertEqual(replies, [b"\x1b[40;120R"])
        self.console.arrow("down")
        self.assertEqual(self.guest.recv(3), b"\x1bOB")
        self.guest.sendall(b"\x1b[?1lready")
        self.console.expect("ready", timeout=1)
        self.console.arrow("left")
        self.assertEqual(self.guest.recv(3), b"\x1b[D")

    def test_cursor_query_reports_the_current_position(self):
        self.guest.sendall(b"\x1b[2;3H\x1b[6nready")
        self.console.expect("ready", timeout=1)
        self.assertEqual(self.guest.recv(32), b"\x1b[2;3R")

    def test_menu_text_can_be_reconstructed_from_cursor_updates(self):
        self.guest.sendall(b"\x1b[2J\x1b[1;1HChooxe one\x1b[1;5Hs")
        self.assertIn("Choose one", self.console.expect("Choose one", timeout=1, screen=True))

    def test_installer_menu_detection_tolerates_wrapped_help(self):
        self.guest.sendall(
            b"\x1b[2J\x1b[1;1HChoose one of the following tasks to"
            b"\x1b[2;1Hperform.\x1b[4;1HInstall (ZFS)  ZFS GPT/UEFI Hybrid"
            b"\x1b[5;1HInstall (UFS)  UFS GPT/UEFI Hybrid"
        )
        menu = self.console.expect(module["INSTALL_MENU_PATTERN"], timeout=1, screen=True)
        self.assertIn("Install (ZFS)", menu)
        self.assertIn("Install (UFS)", menu)

    def test_closed_serial_connection_fails(self):
        self.guest.close()
        with self.assertRaisesRegex(RuntimeError, "connection closed"):
            self.console.expect("not present", timeout=1)

    def test_install_disk_selection_moves_past_the_live_image(self):
        self.guest.sendall(
            b"\x1b[2J\x1b[1;1HUFS Configuration\r\n"
            b"vtbd0 <Unknown disk> (2GB)\r\n"
            b"vtbd1 <Unknown disk> (40GB)\r\n[OK] [Cancel]"
        )
        module["select_install_disk"](self.console)
        self.assertEqual(self.guest.recv(32), b"\x1b[B\r")

    def test_install_disk_selection_rejects_an_unexpected_layout(self):
        self.guest.sendall(
            b"\x1b[2J\x1b[1;1HUFS Configuration\r\n"
            b"vtbd0 <Unknown disk> (40GB)\r\n"
            b"vtbd1 <Unknown disk> (40GB)\r\n[OK] [Cancel]"
        )
        with self.assertRaisesRegex(RuntimeError, "disk menu differs"):
            module["select_install_disk"](self.console)

    def test_command_echo_cannot_satisfy_result_markers(self):
        command = module["INSTALLED_CHECK_COMMAND"]
        for marker in ("NH_VERSION=", "NH_ROOT=", "NH_FSTYPE=", "NH_CHECK_DONE"):
            self.assertNotIn(marker, command)
        self.guest.sendall(command.encode() + b"\r\nNH_VERSION=26.7\r\nNH_ROOT=/dev/gpt/rootfs\r\nNH_FSTYPE=ufs\r\nNH_CHECK_DONE\r\n")
        result = self.console.expect("NH_CHECK_DONE", timeout=1)
        self.assertIn("NH_VERSION=26.7", result)
        self.assertIn("NH_ROOT=/dev/gpt/rootfs", result)

    def test_missing_prompt_has_a_deadline(self):
        with self.assertRaises(TimeoutError):
            self.console.expect("not present", timeout=0.01)


if __name__ == "__main__":
    unittest.main()
