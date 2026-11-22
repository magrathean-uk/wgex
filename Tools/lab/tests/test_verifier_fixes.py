# SPDX-License-Identifier: MIT
"""Verifier regressions. Transport replays never execute guest or host mutations."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[3]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "Tools/lab" / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class VerifierRegressions(unittest.TestCase):
    def test_sender_cannot_supply_receiver_coverage(self):
        verdict = module("coverage_verifier", "verdict.py")
        fixture = json.loads((ROOT / "Tools/lab/tests/fixtures/protected.json").read_text())
        fixture["receiverCoverage"] = fixture.get("receiverRecords", [{}])[0].get("receiverCoverage", [])
        table = json.loads((ROOT / "Tools/lab/leak-expectations.json").read_text())
        self.assertFalse(verdict.evaluate(fixture, table)["expectationsMet"])

    def test_import_label_is_read_from_mac_strings_and_matched_without_case_drift(self):
        live = module("catalogue_verifier", "verdict-live.py")
        source = ROOT / "Packages/WGEXUI/Sources/WGEXUI/Presentation/MacStrings+Import.swift"
        if not source.is_file():
            self.skipTest("M1-09 MacStrings catalogue is absent from this checkout; rerun after the rebase")
        label = re.search(r'static let importAndConnectAction = "([^"]+)"', source.read_text())[1]
        dump = f'AXButton | name={label} | desc= | id=wgex.importReview.importAndConnect | pos=10,20 size=40x20 en=true\n'
        self.assertEqual(live.control_position(dump, label.swapcase(), {}), (30, 30))
        accessibility = source.with_name("WGEXAccessibility.swift").read_text()
        self.assertIn('"wgex.main.tunnel"', accessibility)

    def test_replay_default_is_external_and_digest_names_are_gitleaks_clean(self):
        runner = module("report_verifier", "verdict-run.py")
        self.assertNotIn(ROOT, runner.report_root(True, None).resolve().parents)
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            self.assertEqual(runner.main(["M5.1-01", "--dry-run", "--report-root", directory]), 0)
            data = json.loads((Path(directory) / "M5.1-01/verdict.json").read_text())
            self.assertIn("pfTranscriptDigest:references-table", data["inputHashes"])
            self.assertTrue(data["familiesCovered"])
            result = subprocess.run(["gitleaks", "stdin", "--no-banner", "--redact", "--config", str(ROOT / ".gitleaks.toml")],
                                    input=json.dumps(data).encode(), capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, "sample verdict must pass gitleaks")
            digest = hashlib.sha256(b"fixture replay digest").hexdigest()
            bad = {"pfTranscript:references-with-" + "token": digest}
            rejected = subprocess.run(["gitleaks", "stdin", "--no-banner", "--redact", "--config", str(ROOT / ".gitleaks.toml")],
                                      input=json.dumps(bad).encode(), capture_output=True, check=False)
            self.assertEqual(rejected.returncode, 1, "regression sample must reproduce the old detector shape")

    def test_report_io_failure_is_handled(self):
        runner = module("io_verifier", "verdict-run.py")
        with patch.object(runner, "write_report", side_effect=OSError("fixture")):
            self.assertEqual(runner.main(["M5.1-01", "--dry-run"]), 2)

    def test_pcap_parser_requires_tail_dns_and_catches_ipv6_and_port53_markers(self):
        live = module("pcap_verifier", "verdict-live.py")
        record = dict(nonce="fixture-body", windows=[dict(start=10, end=20, state="protected")])
        tail = dict(nonce="fixture-tail", windows=[dict(start=30, end=40, state="unprotected")])
        text = ("15.000 IP 192.168.64.5.1234 > 192.168.64.1.53: UDP\nfixture-body-system\n"
                "16.000 IP6 fd77::2.1234 > fd77::1.8088: UDP\nWGEXLEAK fixture-body\n"
                "35.000 IP 192.168.64.5.1234 > 192.168.64.1.53: UDP\nfixture-tail-system\n")
        value = live.inspect_capture_text(text, [record, tail])
        self.assertEqual(value["port53Leaks"], 1)
        self.assertEqual(value["ipv6Leaks"], 1)
        self.assertTrue(value["tailSystemResolverObserved"])

    def test_clock_minimum_sample_allows_evaluator_bound_and_records_offset(self):
        live = module("clock_verifier", "verdict-live.py")
        samples = [dict(start=0, end=5, timestamp=2), dict(start=10, end=10.2, timestamp=11.6)]
        value = live.clock_measurement(samples)
        self.assertAlmostEqual(value["offsetSeconds"], 1.5)
        self.assertAlmostEqual(value["uncertaintySeconds"], 0.1)
        shifted = live.clock_measurement([dict(start=10, end=10.2, timestamp=21.6)])
        self.assertAlmostEqual(shifted["uncertaintySeconds"], 0.1)
        with self.assertRaises(ValueError):
            live.clock_measurement([dict(start=10, end=14.1, timestamp=12)])

    def test_packet_nonce_must_match_an_exact_label(self):
        live = module("nonce_verifier", "verdict-live.py")
        record = dict(nonce="fixture-w1", windows=[dict(start=10, end=20, state="protected")])
        tail = dict(nonce="fixture-tail", windows=[dict(start=30, end=40, state="unprotected")])
        text = ("15.000 IP 192.168.64.5.1234 > 192.168.64.1.53: UDP\nfixture-w10-system\n"
                "35.000 IP 192.168.64.5.1234 > 192.168.64.1.53: UDP\nfixture-tail-system-extra\n")
        value = live.inspect_capture_text(text, [record, tail])
        self.assertEqual(value["port53Leaks"], 0)
        self.assertFalse(value["tailSystemResolverObserved"])

    def test_relay_control_is_read_at_most_once_a_second_and_on_change(self):
        relay = module("poll_verifier", "tart/host/udp-relay.py")
        path = Mock()
        path.read_bytes.return_value = b'{"maxDatagram":1252}'
        path.stat.return_value.st_mtime_ns = 1
        path.stat.return_value.st_size = 20
        path.stat.return_value.st_ino = 100
        control = relay.RelayControl(path)
        value = Mock(max_datagram=None)
        for tick in range(1000):
            control.refresh(value, tick / 1000)
        self.assertEqual(path.read_bytes.call_count, 1)
        self.assertEqual(path.stat.call_count, 1)
        control.refresh(value, 1)
        self.assertEqual(path.read_bytes.call_count, 1, "unchanged control should not be read again")
        path.stat.return_value.st_mtime_ns = 2
        path.read_bytes.return_value = b'{"maxDatagram":null}'
        control.refresh(value, 2)
        self.assertEqual(path.read_bytes.call_count, 2)
        self.assertIsNone(value.max_datagram)
        path.read_bytes.side_effect = ValueError("malformed control")
        path.stat.return_value.st_mtime_ns = 3
        control.refresh(value, 3)
        self.assertIsNone(value.max_datagram)

    def test_relay_mtu_drops_only_large_datagrams(self):
        relay = module("mtu_verifier", "tart/host/udp-relay.py")
        front = Mock()
        front.recvfrom.return_value = (b"x" * 1253, ("192.168.64.5", 1111))
        value = relay.Relay(front, ("192.168.64.12", 51820), max_datagram=1252)
        with patch.object(relay.socket, "socket", side_effect=AssertionError("oversized packet forwarded")):
            value.receive_front(1)
        self.assertEqual(value.dropped_oversize, 1)

    def test_foreign_relay_listener_uses_only_its_owned_scratch_port(self):
        # Never consult the managed relay PID/state or the live vmnet port.
        listener = module("listener_verifier", "tart/host/relay-listener.py")
        for _ in range(10):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as scratch:
                scratch.bind(("127.0.0.1", 0))
                port = scratch.getsockname()[1]
                if port == 51820:
                    continue
                self.assertIn(os.getpid(), listener.listener_pids("127.0.0.1", port))
                return
        self.fail("unable to allocate a scratch port distinct from the relay")
