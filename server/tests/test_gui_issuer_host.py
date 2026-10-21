"""Check cleanup admission without starting Docker or changing host resources."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

# Windows can exercise parsing and command admission only. The production
# cleanup still imports and uses the real Linux flock implementation in CI.
modules = {"fcntl": types.ModuleType("fcntl")} if os.name == "nt" else {}
with patch.dict(sys.modules, modules):
    spec = importlib.util.spec_from_file_location("host_fixture", Path(__file__).with_name("gui-issuer-host.py"))
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)


class HostFixtureAdmission(unittest.TestCase):
    def test_alternate_daemon_and_credentials_do_not_enter_commands(self):
        with patch.dict(os.environ, {"DOCKER_HOST": "tcp://untrusted.example.test:2375",
                                     "PGPASSWORD": "fixture-private"}), patch.object(fixture.subprocess, "run") as run:
            fixture.command(["docker", "info"])
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "info"])
        self.assertNotIn("DOCKER_HOST", kwargs["env"])
        self.assertNotIn("PGPASSWORD", kwargs["env"])
        self.assertEqual(kwargs["env"]["LC_ALL"], "C")

    def test_absence_requires_a_healthy_daemon_and_explicit_not_found(self):
        absent = subprocess.CompletedProcess([], 1, b"[]", b"Error: get fixture: no such volume")
        healthy = subprocess.CompletedProcess([], 0, b"daemon-id", b"")
        with patch.object(fixture, "command", side_effect=[absent, healthy]) as run:
            self.assertIsNone(fixture.inspect("volume", "fixture"))
            self.assertEqual(run.call_args_list[1].args[0], ["docker", "info", "--format", "{{.ID}}"])
        with patch.object(fixture, "command", side_effect=[absent, subprocess.CalledProcessError(1, "docker")]):
            with self.assertRaises(subprocess.CalledProcessError):
                fixture.inspect("volume", "fixture")
        denied = subprocess.CompletedProcess([], 1, b"", b"permission denied")
        with patch.object(fixture, "command", side_effect=[denied, healthy]):
            with self.assertRaises(AssertionError):
                fixture.inspect("volume", "fixture")

    def test_ambiguous_inspection_cannot_authorize_cleanup(self):
        for response in (b"[]", b"[{},{}]", b"not-json"):
            with self.subTest(response=response), patch.object(fixture, "command", return_value=subprocess.CompletedProcess([], 0, response, b"")):
                with self.assertRaises((AssertionError, ValueError)):
                    fixture.inspect("container", "fixture")


if __name__ == "__main__":
    unittest.main()
