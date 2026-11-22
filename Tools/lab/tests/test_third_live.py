# SPDX-License-Identifier: MIT
"""Third-run recovery and diagnostic regressions; every guest command is recorded."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_live_replay as replay

LIVE, ROOT = replay.LIVE, replay.ROOT


class QuitRunner(replay.RecordedRunner):
    def __init__(self, succeeds="menu", menu_delay=0):
        super().__init__()
        self.succeeds, self.menu_delay, self.exited = succeeds, menu_delay, False

    def run(self, argv, **kwargs):
        result = super().run(argv, **kwargs)
        command = " ".join(argv)
        if "exists menu bar 1" in command:
            self.menu_delay -= 1
            return self.reply(argv, b"true" if self.menu_delay < 0 and self.succeeds == "menu" else b"false")
        if "exists menu item" in command:
            return self.reply(argv, b"true")
        if 'click menu item "Quit WGEX"' in command and self.succeeds == "menu":
            self.exited = True
        if 'tell application "WGEX" to quit' in command and self.succeeds == "apple-event":
            self.exited = True
        if "pkill -x WGEX" in command and self.succeeds == "pkill":
            self.exited = True
        if "pgrep -x WGEX" in command:
            return self.reply(argv, b"exited" if self.exited else b"running")
        return result


class ThirdLiveTests(unittest.TestCase):
    def test_post_restore_readiness_retries_with_backoff(self):
        class DelayedGuest(replay.RecordedRunner):
            failures = 2
            def run(self, argv, **kwargs):
                result = super().run(argv, **kwargs)
                if argv[:4] == ["just", "lab", "ssh", "--"] and argv[-1] == "true" and self.failures:
                    self.failures -= 1
                    return self.reply(argv, code=1, stderr=b"no guest address answers key-only SSH\n")
                return result
        runner, result = replay.LiveReplayTests().run_recorded("IPERF3", DelayedGuest())
        self.assertTrue(result["prepareCompleted"])
        self.assertEqual(sum(c[:4] == ["just", "lab", "ssh", "--"] and c[-1] == "true" for c in runner.commands), 3)

    def test_quit_waits_for_menu_and_records_each_fallback(self):
        for method in ["menu", "apple-event", "pkill"]:
            runner = QuitRunner(method, menu_delay=2)
            session = LIVE.Session("fixture", {}, runner=runner)
            session.quit_app()
            self.assertTrue(runner.exited)
            self.assertEqual(next(e for e in session.ledger if "quitPath" in e)["quitPath"], method)
            commands = [" ".join(c) for c in runner.commands]
            self.assertIn("gui activate WGEX", commands[0])
            if method == "menu":
                self.assertGreaterEqual(sum("exists menu bar 1" in c for c in commands), 3)
                self.assertFalse(any("pkill -x WGEX" in c for c in commands))

    def test_post_restore_failure_has_a_named_harness_readiness_deadline(self):
        class MissingGuest(replay.RecordedRunner):
            def run(self, argv, **kwargs):
                result = super().run(argv, **kwargs)
                if argv[:4] == ["just", "lab", "ssh", "--"] and argv[-1] == "true":
                    return self.reply(argv, code=1)
                return result
        runner = MissingGuest()
        session = LIVE.Session("fixture", {}, runner=runner)
        started = runner.clock
        with self.assertRaises(LIVE.PollDeadline):
            session.await_guest()
        budget = LIVE.HARNESS.seconds("READINESS")
        self.assertGreaterEqual(runner.clock - started, budget)
        self.assertLess(runner.clock - started, budget + 1)
        report = json.loads(Path(session.deadlines[-1]["path"]).read_text())
        self.assertEqual(report["timeoutSeconds"], budget)
        self.assertIn("post-restore", report["deadlineName"])

    def test_hung_menu_probe_still_uses_apple_event_fallback(self):
        class HungMenu(QuitRunner):
            def run(self, argv, **kwargs):
                if any("exists menu bar 1" in part for part in argv):
                    raise subprocess.TimeoutExpired(argv, 5)
                return super().run(argv, **kwargs)
        runner = HungMenu("apple-event")
        session = LIVE.Session("fixture", {}, runner=runner)
        session.quit_app()
        self.assertEqual(next(e for e in session.ledger if "quitPath" in e)["quitPath"], "apple-event")

    def test_status_query_does_not_outlive_its_poll_budget(self):
        runner = replay.RecordedRunner()
        session = LIVE.Session("fixture", {}, runner=runner)
        with patch.object(session, "ssh", return_value=b'{"phase":"idle","protection":"unprotected"}') as ssh:
            session.await_status("unprotected", timeout=2)
        self.assertLessEqual(ssh.call_args.kwargs["timeout"], 2)

    def test_status_deadline_retains_status_stream_tail_and_ledger(self):
        runner = replay.RecordedRunner()
        runner.connected = runner.blocked = True
        runner.fixture["blocked"]["recoveryFailureReason"] = 8
        session = LIVE.Session("fixture", {}, runner=runner)
        with self.assertRaises(LIVE.PollDeadline):
            session.await_status("protected", timeout=1)
        deadline = next(e for e in session.ledger if e.get("error") == "pollDeadline")
        report = json.loads(Path(deadline["diagnosticsPath"]).read_text())
        self.assertIn("protected", report["deadlineName"])
        self.assertEqual(report["lastStatus"]["recoveryFailureReason"], 8)
        self.assertEqual(len(report["daemonLogTail"]), 50)
        self.assertTrue(report["ledgerTail"])

    def test_observation_stdout_is_bounded_and_redacted_without_recording_stdin(self):
        runner = replay.RecordedRunner()
        session = LIVE.Session("fixture", {}, runner=runner)
        public = next(s for s in (ROOT / "Tests/Fixtures/keys/client1.pub").read_text().splitlines() if s and not s.startswith("#"))
        result = subprocess.CompletedProcess([], 0, ("PrivateKey = <omitted>\n" + public + "\n" + "x" * 70000).encode(), b"")
        with patch.object(runner, "run", return_value=result):
            session.command(["fixture"], data=b"omitted input", record_stdout=True)
        item = session.ledger[-1]
        self.assertLessEqual(len(item["stdout"].encode()), 65536)
        self.assertTrue(public not in item["stdout"], "encoded credential pattern must be removed")
        self.assertNotIn("omitted input", json.dumps(item))
        self.assertTrue(item["stdoutTruncated"])

    def test_cleared_full_tunnel_dns_and_iperf3_rows_reach_mocked_live_dispatch(self):
        runner = replay.module("third_dependency", "verdict-run.py")
        rows = json.loads((ROOT / "Tools/lab/rows.json").read_text())["rows"]
        for name in ["M5.1-01", "DNS-TUNNEL", "IPERF3"]:
            self.assertEqual(rows[name]["dependencies"], {}, name)
            with patch.object(runner, "load_module") as loader, patch.object(runner, "write_report") as writer, \
                    patch.object(runner.PROVENANCE, "ancestor", return_value=True):
                loader.return_value.run.return_value = dict(expectationsMet=True, **replay.PROVENANCE, guestOS=dict(productVersion="26.1", buildVersion="25B12"), installed=replay.PROVENANCE["artefacts"])
                self.assertEqual(runner.main([name]), 0)
            loader.assert_called_once()
            loader.return_value.run.assert_called_once()
            self.assertEqual(loader.return_value.run.call_args.args[:2], (name, rows[name]))
            self.assertEqual(writer.call_args.args[1]["gaps"], [])
            self.assertEqual(writer.call_args.args[1]["dependencies"], {})

    def test_stable_helpers_do_not_follow_build_or_scratch_root(self):
        first = LIVE.guest_binary_paths(Path("/fixture/internal/builds"))
        second = LIVE.guest_binary_paths(Path("/fixture/external/builds"))
        self.assertEqual(first, second)
        for path in first.values():
            self.assertIn(Path.home() / ".local/state/wgex-lab", path.parents)

    def test_stream_tail_is_allowlisted_before_persistence(self):
        helper = ROOT / "Tools/lab/tart/guest/daemon-log-tail.pl"
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            source = b"Filtering the log data\n" + b"start failed, type: DaemonPortError case: system code: 5\n" * 60
            source += b"password = <omitted>\narbitrary user payload must be omitted\n"
            result = subprocess.run(["perl", str(helper), directory], input=source, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, "stream fixture sanitizer failed")
            lines = (Path(directory) / "daemon-log-tail").read_text().splitlines()
            self.assertEqual(len(lines), 50)
            self.assertTrue(any("DaemonPortError" in line for line in lines))
            self.assertTrue(all("password" not in line and "arbitrary user" not in line for line in lines))

    def test_stream_tail_keeps_fixed_vocabulary_state_lines(self):
        helper = ROOT / "Tools/lab/tart/guest/daemon-log-tail.pl"
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            source = (
                b"2026-10-27 09:30:38.498 WGEXDaemon: status: phase=reasserting protection=blocked reason=endpointRotation\n"
                b"2026-10-27 09:30:38.499 WGEXDaemon: verifier: anchorMissing\n"
                b"2026-10-27 09:30:38.500 WGEXDaemon: pf: token recovered\n"
                b"2026-10-27 09:30:38.501 WGEXDaemon: status: phase=active protection=protected reason=none 10.77.0.2\n"
                b"2026-10-27 09:30:38.502 WGEXDaemon: status: phase=Active protection=secret reason=x\n"
                b"2026-10-27 09:30:38.503 WGEXDaemon: verifier: leaked key AAAA\n"
            )
            result = subprocess.run(["perl", str(helper), directory], input=source, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0)
            lines = (Path(directory) / "daemon-log-tail").read_text().splitlines()
            self.assertEqual(
                [line.split(" ", 2)[2] for line in lines],
                [
                    "status: phase=reasserting protection=blocked reason=endpointRotation",
                    "verifier: anchorMissing",
                    "pf: token recovered",
                    "status: phase=active protection=protected reason=none",
                    "<event omitted; non-diagnostic content>",
                    "verifier: leaked",
                ],
            )
            self.assertTrue(all("10.77" not in line and "AAAA" not in line for line in lines))
