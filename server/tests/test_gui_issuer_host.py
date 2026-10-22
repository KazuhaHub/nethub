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
    def test_all_protected_flows_and_their_order_counts_are_required(self):
        lines = [
            "--- PASS: TestPebbleProtectedHostIssuer (12.34s)",
            "--- PASS: TestPebbleProtectedHostIssuerRenewal (23.45s)",
            "--- PASS: TestPebbleProtectedHostAccountProvisioning (12.34s)",
            "Actual coordinator passed one original order/finalize POST; native application not claimed",
            "Actual renewal coordinator passed exactly two original orders/finalize POSTs; native application not claimed",
            "Genuine host renewal passed original CSR/key, two distinct issued leaves",
            "Fresh compiled device enrollment, original CSR admission/initial queue, genuine CA issuance and authenticated original-key delivery passed",
            "Protected host command passed genuine Compose database discovery",
            "Protected relay trust commands passed pending read, explicit initialization, exact retry, overlap CAS, stale/unsafe refusal and unchanged authority/runtime",
            "Protected relay authority commands passed expected-root refusal, immutable preparation, independent backup verification and unchanged active authority/runtime/head",
            "Protected shared relay lease refused publication and offline authority during contention, skipped renewal, then recovered without changing authority/runtime/head",
            "Protected relay authority custody required explicit acknowledgement, preserved exact retry timestamp and refused a missing independent backup without changing active authority/runtime/head",
            "Protected authority snapshot preserved all active files, staged independent successor backup and refused damaged copies and unresolved maintenance",
            "Protected account commands passed offline initialization, verified immutable backup",
            "fresh terms review, outdated/missing-backup consent refusal, explicit private-CA registration retry and original-account recovery from pre-registration backup",
        ]
        log = "\n".join(lines)
        self.assertTrue(all(fixture.acceptance_evidence(0, None, log).values()))
        publication = next(line for line in lines if line.startswith("Protected relay trust commands"))
        self.assertFalse(fixture.acceptance_evidence(0, None, log + "\n" + publication)["passed"])
        authority = next(line for line in lines if line.startswith("Protected relay authority commands"))
        self.assertFalse(fixture.acceptance_evidence(0, None, log + "\n" + authority)["passed"])
        lease = next(line for line in lines if line.startswith("Protected shared relay lease"))
        self.assertFalse(fixture.acceptance_evidence(0, None, log + "\n" + lease)["passed"])
        custody = next(line for line in lines if line.startswith("Protected relay authority custody"))
        self.assertFalse(fixture.acceptance_evidence(0, None, log + "\n" + custody)["passed"])
        snapshot = next(line for line in lines if line.startswith("Protected authority snapshot"))
        self.assertFalse(fixture.acceptance_evidence(0, None, log + "\n" + snapshot)["passed"])
        for missing in lines:
            with self.subTest(missing=missing):
                self.assertFalse(any(fixture.acceptance_evidence(0, None, log.replace(missing, "")).values()))
        for code, failure in ((1, None), (0, "TimeoutExpired")):
            self.assertFalse(any(fixture.acceptance_evidence(code, failure, log).values()))
        for terminal in lines[:3]:
            for replacement in (terminal.replace("--- PASS:", "--- SKIP:"), terminal.replace(" (", "Other (")):
                self.assertFalse(fixture.acceptance_evidence(0, None, log.replace(terminal, replacement))["passed"])
            self.assertFalse(fixture.acceptance_evidence(0, None, log + "\n" + terminal)["passed"])

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
