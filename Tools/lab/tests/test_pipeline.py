# SPDX-License-Identifier: MIT
"""M1-10: offline acceptance tests; no sockets, VMs, privileged tools or secrets."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


V = module("verdict", ROOT / "Tools/lab/verdict.py")
TABLE = json.loads((ROOT / "Tools/lab/leak-expectations.json").read_text())


class PipelineTests(unittest.TestCase):
    def fixture(self):
        return json.loads((ROOT / "Tools/lab/tests/fixtures/protected.json").read_text())

    def test_coverage_is_computed_and_cannot_be_asserted_by_sender(self):
        record = self.fixture()
        self.assertTrue(V.evaluate(record, TABLE, record.get("receiverRecords", []))["expectationsMet"])
        record["receiverRecords"] = []
        record["windows"][0]["receiversComplete"] = True
        self.assertFalse(V.evaluate(record, TABLE, record.get("receiverRecords", []))["expectationsMet"])

    def test_truncated_receiver_or_wrong_configuration_fails_closed(self):
        for field, value in [("end", 4), ("configurationSHA256", "wrong"), ("healthy", False)]:
            record = self.fixture()
            record["receiverRecords"][0]["receiverCoverage"][0][field] = value
            self.assertFalse(V.evaluate(record, TABLE, record.get("receiverRecords", []))["expectationsMet"])

    def test_captive_never_allows_arbitrary_web_destination(self):
        record = self.fixture()
        record["windows"][0]["state"] = "captiveWindow"
        record["receiverRecords"][0]["observations"].append(dict(timestamp=5, nonce=record["nonce"], kind="received", scope="outside_tunnel",
                                           family="ipv4", proto="http", address="203.0.113.88", port=80))
        result = V.evaluate(record, TABLE, record.get("receiverRecords", []))["states"][0]
        self.assertFalse(result["expectationMet"])
        self.assertEqual(len(result["offendingObservations"]), 1)

    def test_dry_run_pipeline_writes_bounded_evidence_and_is_not_live_acceptance(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            result = subprocess.run(["bash", "Tools/lab/verdict-run.sh", "M5.1-01", "--dry-run", "--report-root", directory],
                                    cwd=ROOT, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            report = Path(directory) / "M5.1-01"
            data = json.loads((report / "verdict.json").read_text())
            self.assertTrue(data["dryRun"])
            self.assertFalse(data["liveAcceptance"])
            self.assertTrue(data["expectationsMet"])
            self.assertEqual(data["exceptions"][0]["port"], 22)
            self.assertTrue((report / "README.md").is_file())
            self.assertTrue(all(path.stat().st_size <= 50000 for path in report.iterdir()))

    def test_catalogue_includes_every_requested_mac_row_and_explicit_gaps(self):
        rows = json.loads((ROOT / "Tools/lab/rows.json").read_text())["rows"]
        expected = [f"M5.1-{n:02d}" for n in range(1, 12)]
        expected += ["M5.2-01", "M5.2-03", "M5.2-04"]
        expected += [f"M5.3-{n:02d}" for n in [1, 2, 3, 7, 8, 9, 10]]
        expected += [f"M5.4-{n:02d}" for n in range(1, 8)]
        expected += ["RT-16", "RT-17", "RT-21", "RT-22", "CRASH-TERM", "CRASH-TOKEN", "CRASH-PF-DISABLE",
                     "REBOOT-INTENT", "REBOOT-LOCKDOWN", "DNS-TUNNEL", "IPERF3", "BOOT-SECRETS", "POWER-WAKE"]
        for row in expected:
            self.assertIn(row, rows)
            self.assertTrue(rows[row]["steps"])
            self.assertTrue(rows[row]["expected"])
        self.assertNotIn("gap", rows["POWER-WAKE"], "live since M1-47: an injected power event, with its limits stated in the row")
        self.assertIn("RT-21", rows)
        self.assertNotIn("gap", rows["RT-21"])
        self.assertNotIn("gap", rows["CRASH-PF-DISABLE"])

    def test_gui_coordinates_are_data_and_ambiguous_controls_refuse(self):
        live = module("live", ROOT / "Tools/lab/verdict-live.py")
        dump = 'AXButton | name=Connect | value= | desc= | pos=100,200 size=80x30 en=true\n'
        self.assertEqual(live.control_position(dump, "Connect", {}), (140, 215))
        with self.assertRaises(ValueError):
            live.control_position(dump + dump, "Connect", {})
        self.assertEqual(live.control_position("", "Connect", {"Connect": [101, 202]}), (101, 202))

    def test_log_summary_never_carries_event_messages(self):
        live = module("live", ROOT / "Tools/lab/verdict-live.py")
        data = '__WGEX_STATUS__\n{"phase":"active","protection":"protected"}\n__WGEX_LOG__\nevents=3; rawMessagesOmitted=1\n'
        parsed = live.parse_observations(data)
        self.assertEqual(parsed["status"], {"phase": "active", "protection": "protected"})
        self.assertEqual(parsed["logEvents"], 3)

    def test_every_row_has_a_replay_without_live_transport(self):
        runner = module("runner", ROOT / "Tools/lab/verdict-run.py")
        rows = json.loads((ROOT / "Tools/lab/rows.json").read_text())["rows"]
        for name, row in rows.items():
            if row.get("driver"):
                continue  # M03-T11: a driver row (AUTH-REAL) has no replay; verdict-run refuses --dry-run for it (test_auth_real).
            with self.subTest(row=name):
                self.assertTrue(runner.replay(row, TABLE, {})["expectationsMet"])

    def test_dns_replay_fails_without_the_system_resolver_receipt(self):
        runner = module("dns_runner", ROOT / "Tools/lab/verdict-run.py")
        row = json.loads((ROOT / "Tools/lab/rows.json").read_text())["rows"]["DNS-TUNNEL"]
        read = runner.read
        def missing_system(path, hashes, label):
            value = read(path, hashes, label)
            if label == "fixture:dns-protected":
                for receiver in value["receiverRecords"]:
                    receiver["observations"] = [o for o in receiver["observations"] if not o["nonce"].endswith("-system")]
            return value
        with patch.object(runner, "read", side_effect=missing_system):
            self.assertFalse(runner.replay(row, TABLE, {})["expectationsMet"])

    def test_unimplemented_row_never_loads_live_transport(self):
        runner = module("runner_gap", ROOT / "Tools/lab/verdict-run.py")
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            with patch.object(runner, "load_module", side_effect=AssertionError("live transport loaded")):
                self.assertEqual(runner.main(["M5.3-08", "--report-root", directory]), 1)
            result = json.loads((Path(directory) / "M5.3-08/verdict.json").read_text())
            self.assertFalse(result["expectationsMet"])
            self.assertTrue(result["gaps"])


if __name__ == "__main__":
    unittest.main()
