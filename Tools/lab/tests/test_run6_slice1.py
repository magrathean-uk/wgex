# SPDX-License-Identifier: MIT
"""Run 6 slice 1 regressions (M1-10e): split-profile leak rule, loss waits, public verdict digests. Never a VM."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import test_live_replay as replay

ROOT, LIVE, V, TABLE = replay.ROOT, replay.LIVE, replay.V, replay.TABLE
FIXTURES = replay.FIXTURES
RUN = replay.module("slice1_verdict_run", "verdict-run.py")
_lint_spec = importlib.util.spec_from_file_location("slice1_secret_shapes", ROOT / "Tools/lint/secret-shapes.py")
LINT = importlib.util.module_from_spec(_lint_spec)
_lint_spec.loader.exec_module(LINT)
SPLIT, FULL = ["default", "dns"], ["full4", "full4-name", "dual", "lockdown", "wrong-key"]


def fixture(name):
    return json.loads((FIXTURES / (name + ".json")).read_text())


def window(state, variant=None, extra=()):
    """One fixture window with the run 6 outside receipts at 192.168.64.1 (all four protocols) added."""
    record = fixture(state)
    receivers = record.pop("receiverRecords")
    outside = fixture("unprotected")["receiverRecords"][0]["observations"]
    if receivers:
        receivers[0]["observations"].extend(copy.deepcopy(outside) + [dict(item) for item in extra])
    else:
        receiver = fixture("unprotected")["receiverRecords"][0]
        receiver["observations"].extend(dict(item) for item in extra)
        receivers = [receiver]
    if variant:
        record["tunnelScope"] = V.tunnel_scope(variant)
    return V.evaluate(record, TABLE, receivers)["states"][0]


def ledger(result):
    return json.loads((Path(result["buildRoot"]) / "steps.json").read_text())


def shapes(text):
    return LINT.HEX.findall(text) + LINT.B64.findall(text)


class SplitProfileLeakRuleTests(unittest.TestCase):
    """Item 1: a split profile's probes to the underlay host and relay over en0 are expected, not leaks."""

    def test_variants_are_classified_from_allowed_ips_that_match_the_peer_generator(self):
        script = (ROOT / "Tools/lab/lima/peer-provision.sh").read_text()
        block = script[script.index("AllowedIPs = "):]
        generated = {}
        for names, value in re.findall(r"(?m)^\s+([a-z0-9| -]+)\) printf '([^']*)\\n' ;;$", block[:block.index("esac")]):
            for name in names.split("|"):
                generated[name.strip()] = value.split(", ")
        self.assertEqual(generated, V.PROFILE_ALLOWED_IPS)
        for name in SPLIT:
            self.assertTrue(V.split_tunnel(V.PROFILE_ALLOWED_IPS[name]), name)
            self.assertEqual(V.tunnel_scope(name)["underlayDestinations"], ["192.168.64.1"])
        for name in FULL:
            self.assertFalse(V.split_tunnel(V.PROFILE_ALLOWED_IPS[name]), name)
            self.assertEqual(V.tunnel_scope(name)["underlayDestinations"], [])
        self.assertFalse(V.split_tunnel(["0.0.0.0/0"]))
        self.assertFalse(V.split_tunnel(["::/1", "8000::/1"]))
        self.assertTrue(V.split_tunnel(["0.0.0.0/1"]))

    def test_split_protected_window_expects_underlay_receipts_and_full_tunnel_stays_strict(self):
        for name in SPLIT:
            result = window("protected", name)
            self.assertTrue(result.get("expectationMet"), (name, result["missing"], result["offendingObservations"]))
            self.assertEqual(result["splitTunnel"]["expectedUnderlayObservationCount"], 4)
        for name in FULL + [None]:
            result = window("protected", name)
            self.assertEqual(result["verdict"], "unprotected", name)
            self.assertEqual(len(result["offendingObservations"]), 4, name)

    def test_split_exemption_never_covers_system_dns_other_hosts_or_blocked_windows(self):
        system = dict(fixture("unprotected")["receiverRecords"][0]["observations"][0], nonce="m1-10-fixture-system")
        other = dict(fixture("unprotected")["receiverRecords"][0]["observations"][1], address="192.168.64.12")
        for extra in [system, other]:
            result = window("protected", "dns", [extra])
            self.assertEqual(result["verdict"], "unprotected", extra)
            self.assertEqual(result["offendingObservations"], [extra])
        self.assertEqual(window("blocked", "dns")["verdict"], "unprotected")

    def test_a_claimed_split_scope_is_recomputed_from_allowed_ips(self):
        record = fixture("protected")
        receivers = record.pop("receiverRecords")
        receivers[0]["observations"].extend(fixture("unprotected")["receiverRecords"][0]["observations"])
        record["tunnelScope"] = dict(V.tunnel_scope("full4"), variant="dns")
        self.assertEqual(V.evaluate(record, TABLE, receivers)["states"][0]["verdict"], "unprotected")
        # A routed (full-tunnel) or tunnel address can never be named exempt; such a scope fails closed.
        for scope in [dict(V.tunnel_scope("dns"), allowedIPs=["0.0.0.0/1", "128.0.0.0/1"]),
                      dict(V.tunnel_scope("dns"), underlayDestinations=["10.77.0.1"]),
                      dict(V.tunnel_scope("dns"), allowedIPs=["not a network"]), "dns"]:
            record["tunnelScope"] = scope
            with self.assertRaises(ValueError):
                V.evaluate(record, TABLE, receivers)

    def test_exempt_list_is_pinned_to_the_lab_underlay_host(self):
        """F1 (fix pass 1): only the underlay host/router, which is also the relay endpoint, can ever be exempt."""
        host = "192.168.64.1"
        sources = {
            "peer-provision.sh Endpoint": re.search(r"Endpoint = ([0-9.]+):51820", (ROOT / "Tools/lab/lima/peer-provision.sh").read_text())[1],
            "relay-manager.py listener": re.search(r'listener_pids\("([0-9.]+)", 51820\)', (ROOT / "Tools/lab/relay-manager.py").read_text())[1],
            "udp-relay.py listener": re.search(r'listen != \("([0-9.]+)", 51820\)', (ROOT / "Tools/lab/tart/host/udp-relay.py").read_text())[1],
            "verdict-run.py escape hatch": RUN.EXCEPTION["source"],
            "verdict-live.py outside target": re.search(r'dict\(address="([0-9.]+)", scope="outside_tunnel"', (ROOT / "Tools/lab/verdict-live.py").read_text())[1],
        }
        self.assertEqual(set(sources.values()), {host}, sources)
        record = fixture("protected")
        receivers = record.pop("receiverRecords")
        peer = dict(fixture("unprotected")["receiverRecords"][0]["observations"][1], address="192.168.64.12")
        receivers[0]["observations"].append(peer)
        for destinations in [["192.168.64.12"], [host, "192.168.64.12"], ["192.168.64.2"], [host, host + "0"]]:
            record["tunnelScope"] = dict(V.tunnel_scope("dns"), underlayDestinations=destinations)
            with self.assertRaises(ValueError, msg=destinations):
                V.evaluate(record, TABLE, receivers)
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            path = Path(directory) / "record.json"
            record["tunnelScope"] = dict(V.tunnel_scope("dns"), underlayDestinations=["192.168.64.12"])
            path.write_bytes(V.canonical(dict(record, receiverRecords=receivers)))
            result = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "Tools/lab/verdict.py"), str(path)],
                                           capture_output=True, check=False)
            self.assertEqual(result.returncode, 2, result.stdout)
            self.assertEqual(json.loads(result.stdout)["verdict"], "unknown")
        record["tunnelScope"] = V.tunnel_scope("dns")
        self.assertEqual(V.evaluate(record, TABLE, receivers)["states"][0]["offendingObservations"], [peer])
        self.assertEqual((V.UNDERLAY_HOST, V.RELAY_ENDPOINT, V.UNDERLAY_DESTINATIONS), (host, host, [host]))

    def test_dns_tunnel_row_passes_with_run6_underlay_receipts_and_full4_does_not(self):
        runner = replay.RecordedRunner()
        runner.underlay_receipts = True
        _, result = replay.LiveReplayTests().run_recorded("DNS-TUNNEL", runner)
        protected = [w for w in result["states"] if w["state"] == "protected"]
        self.assertTrue(protected and all(w["splitTunnel"]["expectedUnderlayObservationCount"] for w in protected))
        self.assertTrue(all(w["nameserverConfigured"] and w["systemResolverReceiptCount"] for w in protected))
        self.assertEqual(result["tunnelScope"]["variant"], "dns")
        runner = replay.RecordedRunner()
        runner.underlay_receipts = True
        _, result = replay.LiveReplayTests().run_recorded("M5.1-01", runner, accepted=False)
        self.assertTrue(any(w["verdict"] == "unprotected" for w in result["states"] if w["state"] == "protected"))

    def test_dns_tunnel_catalogue_names_the_split_expectation(self):
        row = replay.ROWS["DNS-TUNNEL"]
        text = " ".join(row["steps"] + row["expected"])
        for needle in ["split", "192.168.64.1", "<window>-system", "port 53"]:
            self.assertIn(needle, text)
        self.assertNotIn("no outside DNS", text)


class LossBlockedWaitTests(unittest.TestCase):
    """Item 2: blocked during loss is reasserting/blocked (failed accepted, not required), seen by a 250 ms status sequence."""

    def runner(self, **seams):
        runner = replay.RecordedRunner()
        runner.loss_model, runner.status_cost = True, 1.1
        for key, value in seams.items():
            setattr(runner, key, value)
        return runner

    def test_loss_rows_pass_on_reasserting_blocked_that_never_fails(self):
        for name in ["M5.1-01", "M5.1-08", "M5.1-09"]:
            runner, result = replay.LiveReplayTests().run_recorded(name, self.runner())
            waits = [entry for entry in ledger(result) if "lossBlocked" in entry]
            self.assertTrue(waits, name)
            for entry in waits:
                self.assertTrue(entry["met"], name)
                self.assertEqual(entry["statusSequence"][-1][:2], ["reasserting", "blocked"], name)
                self.assertNotIn("failed", [step[0] for step in entry["statusSequence"]], name)
            phases = [p for p in result["phasesDuringFault"] if p["label"].startswith("lossBlocked:")]
            self.assertEqual(len(phases), len(waits), name)
            self.assertTrue(all((p["phase"], p["protection"]) == ("reasserting", "blocked") for p in phases), name)

    def test_failed_blocked_is_still_accepted(self):
        _, result = replay.LiveReplayTests().run_recorded("M5.1-08")
        entry = next(e for e in ledger(result) if "lossBlocked" in e)
        self.assertEqual(entry["statusSequence"][-1][:2], ["failed", "blocked"])

    def test_status_stream_keeps_the_short_configuring_phase_that_polls_miss(self):
        stream = ["2026-10-29 07:51:39.734 status: phase=preparing protection=unknown reason=none", "2026-10-29 07:51:40.209 pf: token acquired",
                  "2026-10-29 07:51:40.811 status: phase=configuring protection=blocked reason=none",
                  "2026-10-29 07:51:41.279 status: phase=active protection=protected reason=none",
                  "2026-10-29 07:51:56.582 verifier: blocked",
                  "2026-10-29 07:51:56.582 status: phase=reasserting protection=blocked reason=endpointRotation"]
        runner = self.runner(diagnostics_tail=("\n".join(stream) + "\n").encode())
        _, result = replay.LiveReplayTests().run_recorded("M5.1-08", runner)
        entry = next(e for e in ledger(result) if "lossBlocked" in e)
        self.assertNotIn("configuring", [step[0] for step in entry["statusSequence"]])
        self.assertEqual([s[1:3] for s in entry["statusStream"]],
                         [["preparing", "unknown"], ["configuring", "blocked"], ["active", "protected"], ["reasserting", "blocked"]])
        self.assertEqual(entry["statusStream"][-1][3], "endpointRotation")
        self.assertNotIn("pf:", json.dumps(entry["statusStream"]))

    def test_polls_every_250_ms_and_records_each_transition(self):
        runner = self.runner(status_cost=0.0)
        runner.connected, runner.relay, runner.connect_at, runner.selected = True, False, runner.clock, (110, 110)
        session = LIVE.Session("fixture", {}, runner=runner)
        pauses = []
        with patch.object(session, "pause", side_effect=lambda seconds: (pauses.append(seconds), runner.sleep(seconds))):
            status = session.await_loss_blocked("fixture")
        self.assertEqual(LIVE.STATUS_POLL_SECONDS, 0.25)
        self.assertEqual(status, dict(phase="reasserting", protection="blocked"))
        self.assertTrue(pauses and all(seconds == 0.25 for seconds in pauses))
        entry = next(e for e in session.ledger if "lossBlocked" in e)
        self.assertEqual([s[0] for s in entry["statusSequence"]], ["preparing", "configuring", "active", "reasserting"])

    def test_window_covers_the_m1_05_cadence(self):
        self.assertGreaterEqual(LIVE.LOSS_BLOCKED_SECONDS, 29 + 60)
        _, result = replay.LiveReplayTests().run_recorded("M5.1-08", self.runner(loss_reassert_after=80))
        entry = next(e for e in ledger(result) if "lossBlocked" in e)
        self.assertGreater(entry["statusSequence"][-1][2], 75)

    def test_a_tunnel_that_never_blocks_fails_named_and_the_relay_returns(self):
        runner = self.runner(loss_reassert_after=1000)
        _, result = replay.LiveReplayTests().run_recorded("M5.1-08", runner, accepted=False)
        self.assertTrue(any(gap.startswith("loss blocked (blackhole)") for gap in result["gaps"]), result["gaps"])
        report = json.loads(Path(result["deadlineDiagnostics"][-1]["path"]).read_text())
        self.assertEqual(report["timeoutSeconds"], LIVE.LOSS_BLOCKED_SECONDS)
        entry = next(e for e in ledger(result) if "lossBlocked" in e)
        self.assertFalse(entry["met"])
        commands = [" ".join(c) for c in runner.commands]
        stop = next(i for i, c in enumerate(commands) if "lab relay stop" in c)
        self.assertTrue(any("lab relay start" in c for c in commands[stop + 1:]), "a wait deadline still restores the relay")

    def test_catalogue_loss_rows_accept_but_do_not_require_failed(self):
        for name in ["M5.1-01", "M5.1-08", "M5.1-09"]:
            text = " ".join(replay.ROWS[name]["steps"] + replay.ROWS[name]["expected"])
            self.assertIn("reasserting/blocked", text, name)
            self.assertIn("failed is accepted but not required", text, name)
            self.assertNotIn("After failed", text, name)
        self.assertFalse(re.search(r"await_phase\(", (ROOT / "Tools/lab/verdict-live.py").read_text()))


class PublicVerdictDigestTests(unittest.TestCase):
    """Item 3: the writer's verdict JSON and README carry no 64-hex token and no 43-character base64 run."""

    def test_writer_shapes_are_the_lint_shapes(self):
        self.assertEqual((RUN.HEX.pattern, RUN.B64.pattern), (LINT.HEX.pattern, LINT.B64.pattern))
        self.assertEqual(RUN.DIGEST_PREFIX_HEX, 12)

    def test_live_report_shortens_digests_and_redacts_base64_runs(self):
        full = hashlib.sha256(b"fixture record").hexdigest()
        token = "Daemon/WGEXDaemon/" + "SystemDaemonEngineFactory"
        self.assertEqual(len(token), 43)
        live = Mock()
        live.run.return_value = dict(states=[dict(verdict="protected", expectationMet=True, role="protected")], rowCompleted=True,
                                     prepareCompleted=True, expectationsMet=True, **replay.PROVENANCE, guestOS=dict(productVersion="26.1", buildVersion="25B12"), installed=replay.PROVENANCE["artefacts"], recordHashes={"host.json": full},
                                     observations=[dict(routes="route " + token + " here", rules="digest " + full.upper())],
                                     checks=[dict(name="fixture", met=True)], tailControl=dict(met=True))
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            with patch.object(RUN, "load_module", return_value=live), patch.object(RUN.PROVENANCE, "ancestor", return_value=True):
                self.assertEqual(RUN.main(["IPERF3", "--no-install", "--report-root", directory]), 0)
            report = Path(directory) / "IPERF3"
            files = sorted(report.iterdir())
            self.assertEqual([p.name for p in files], ["README.md", "verdict.json"])
            for path in files:
                self.assertEqual(shapes(path.read_text()), [], path.name)
            data = json.loads((report / "verdict.json").read_text())
        self.assertEqual(data["recordHashes"], {"host.json": full[:12]})
        catalogue = hashlib.sha256((ROOT / "Tools/lab/rows.json").read_bytes()).hexdigest()
        self.assertEqual(data["inputHashes"]["catalogue"], catalogue[:12])
        self.assertEqual(data["digestPrefixHex"], 12)
        self.assertEqual(data["observations"][0]["rules"], "digest " + full.upper()[:12])
        self.assertNotIn("SystemDaemonEngineFactory", json.dumps(data))
        self.assertTrue(data["liveAcceptance"])

    def test_json_escapes_cannot_lengthen_a_run_in_the_written_file(self):
        """F2 (fix pass 1): cleaning sees the serialised bytes, so an escape letter cannot complete a lint shape."""
        run42 = "Q" * 42
        hex63 = hashlib.sha256(b"escape").hexdigest()[1:]
        texts = ["line\n" + run42, "tab\t" + run42 + " end", "accent\u00e9" + "Q" * 38, "feed\f" + hex63, "kept\n" + "Q" * 20]
        self.assertTrue(all(shapes(text) == [] for text in texts[:2] + texts[3:]), "each run is one short of a shape before JSON escaping")
        live = Mock()
        live.run.return_value = dict(states=[dict(verdict="protected", expectationMet=True, role="protected")], rowCompleted=True,
                                     prepareCompleted=True, expectationsMet=True, **replay.PROVENANCE, guestOS=dict(productVersion="26.1", buildVersion="25B12"), installed=replay.PROVENANCE["artefacts"], observations=[dict(dns=text) for text in texts],
                                     checks=[], tailControl=dict(met=True))
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            with patch.object(RUN, "load_module", return_value=live), patch.object(RUN.PROVENANCE, "ancestor", return_value=True):
                self.assertEqual(RUN.main(["IPERF3", "--no-install", "--report-root", directory]), 0)
            raw = (Path(directory) / "IPERF3/verdict.json").read_text()
            self.assertEqual(shapes(raw), [])
            self.assertEqual(shapes((Path(directory) / "IPERF3/README.md").read_text()), [])
            data = json.loads(raw)
        written = [item["dns"] for item in data["observations"]]
        self.assertEqual(written[0], "line\n<redacted>")
        self.assertEqual(written[1], "tab\t<redacted> end")
        self.assertEqual(written[2], "accent\u00e9<redacted>")
        self.assertEqual(written[3], "feed\f" + hex63[:11])
        self.assertEqual(written[4], texts[4], "runs that stay short after escaping are kept")

    def test_recorded_live_rows_and_every_replay_write_no_secret_shapes(self):
        _, result = replay.LiveReplayTests().run_recorded("M5.1-08", LossBlockedWaitTests().runner())
        self.assertTrue(any(len(value) == 64 for value in result["recordHashes"].values()), "live digests are full until written")
        row = replay.ROWS["M5.1-08"]
        result.update(schemaVersion=1, row="M5.1-08", date="2026-10-29T00:00:00+00:00", dryRun=False, liveAcceptance=False,
                      inputHashes=dict(catalogue=hashlib.sha256(b"catalogue").hexdigest()), gaps=["gap " + hashlib.sha256(b"x").hexdigest()])
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            written = RUN.write_report(Path(directory) / "M5.1-08", result, row, keep_attempts=True)
            self.assertEqual(written.name, "verdict-1.json")
            for path in Path(directory, "M5.1-08").iterdir():
                self.assertEqual(shapes(path.read_text()), [], path.name)
            for name in (name for name, row in replay.ROWS.items() if not row.get("driver")):  # M03-T11: AUTH-REAL has no replay.
                self.assertIn(RUN.main([name, "--dry-run", "--report-root", directory]), (0, 1), name)
                for path in Path(directory, name).iterdir():
                    self.assertEqual(shapes(path.read_text()), [], (name, path.name))
                self.assertIn("pfTranscriptDigest:references-table", json.loads(Path(directory, name, "verdict.json").read_text())["inputHashes"])


if __name__ == "__main__":
    unittest.main()
