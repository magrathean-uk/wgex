"""M1-57, lab harness diagnostics (run 9 F3, run 9b F2 and F3): a failed live step and an unhealthy receiver are named in
the gap. Recorded or synthetic inputs only; no socket, no VM, no subprocess."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import os
import time
import unittest
from unittest.mock import Mock, patch

import test_live_replay as replay

LIVE, V, TABLE = replay.LIVE, replay.V, replay.TABLE
SPEC = importlib.util.spec_from_file_location("receiver_m157", Path(__file__).resolve().parents[2] / "leakprobe/receiver.py")
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)


def raising_prepare(message):
    def prepare(self, profile, connect=True):
        raise RuntimeError(message)
    return patch.object(LIVE.Session, "prepare", prepare)


class LiveStepGapTests(unittest.TestCase):
    def gaps(self, message):
        with raising_prepare(message):
            _, result = replay.LiveReplayTests().run_recorded("M5.1-04", accepted=False)
        return result["gaps"]

    def test_a_multi_line_prepare_error_gives_only_its_first_line(self):
        gaps = self.gaps("engine: missing or stale XCFramework; run 'just engine' before building\nsecond line\nthird line")
        self.assertEqual(gaps[0], "Live step failed: RuntimeError: engine: missing or stale XCFramework; run 'just engine' "
                                  "before building; see build-root ledger")
        self.assertFalse(any("second line" in gap for gap in gaps))

    def test_a_message_with_a_secret_marker_is_withheld(self):
        for message in ("login failed WGEX_TOKEN=abc123", "CLAUDE_CODE_MESSAGING_TOKEN=x", "bad API_KEY=zz", "the SECRET is here",
                        "PASSWORD rejected", "Password rejected", "TOKEN=abc",
                        # M1-57 fix pass 1 (N4 M2e): lower case, which safe_stderr's own patterns do not catch.
                        "login failed wgex_token=abc123", "bad api_key=zz", "the secret is here", "token=abc"):
            with self.subTest(message=message):
                gap = self.gaps(message)[0]
                self.assertEqual(gap, "Live step failed: RuntimeError: (message withheld); see build-root ledger")

    def test_a_secret_on_a_later_line_never_reaches_the_gap(self):
        gap = self.gaps("prepare refused\nTOKEN=abc")[0]
        self.assertEqual(gap, "Live step failed: RuntimeError: prepare refused; see build-root ledger")

    def test_the_row_name_boot_secrets_is_not_a_secret_marker(self):
        gap = self.gaps("BOOT-SECRETS install mode refused")[0]
        self.assertEqual(gap, "Live step failed: RuntimeError: BOOT-SECRETS install mode refused; see build-root ledger")

    def test_an_empty_message_keeps_the_bare_text(self):
        for message in ("", "   \n  "):
            self.assertEqual(self.gaps(message)[0], "Live step failed: RuntimeError; see build-root ledger")

    def test_the_first_line_is_stripped_and_capped(self):
        gap = LIVE.live_step_gap(ValueError("   " + "x " * 250 + "   \nmore"))
        self.assertEqual(gap, "Live step failed: ValueError: " + "x " * 100 + "; see build-root ledger")

    def test_encoded_key_patterns_are_withheld(self):
        public = next(line.strip() for line in (replay.ROOT / "Tests/Fixtures/keys/client1.pub").read_text().splitlines()
                      if line and not line.startswith("#"))
        self.assertIn("(message withheld)", LIVE.live_step_gap(RuntimeError("peer key " + public)))

    # M1-57 fix pass 1 (VERIFY N2): `just lab *args` is not @-prefixed, so just echoes the recipe body line first and ends with its
    # own "error: Recipe ... failed" trailer; the cause is the tool's line between them (or a traceback's last line).
    ECHO = b'bash Tools/lab/tart/lab.sh "$@"\n'
    TRAILER = b"error: Recipe `lab` failed on line 148 with exit code 1\n"
    REFUSAL = b"engine: missing or stale XCFramework (engine source digest differs); run 'just engine' before building\n"

    def failed(self, stderr):
        runner = Mock()
        runner.now.return_value = 1
        runner.run.return_value = subprocess.CompletedProcess([], 1, b"", stderr)
        session = LIVE.Session("fixture", {}, runner=runner)
        with self.assertRaises(RuntimeError) as raised:
            session.command(["just", "lab", "build"])
        self.ledger = session.ledger
        return raised.exception

    def test_a_failed_just_command_names_the_tool_refusal_not_the_just_recipe_echo(self):
        for refusal in (self.REFUSAL, b"error: tool refused X\n", b"Host key verification failed.\n"):
            with self.subTest(refusal=refusal):
                error = self.failed(self.ECHO + refusal + self.TRAILER)
                self.assertEqual(LIVE.command_cause(LIVE.safe_stderr(self.ECHO + refusal + self.TRAILER)), refusal.decode().strip())
                self.assertEqual(LIVE.live_step_gap(error),
                                 "Live step failed: RuntimeError: command failed: " + refusal.decode().strip()
                                 + "; inspect step ledger; see build-root ledger")

    def test_new_secret_shapes_are_named_by_command_cause_but_withheld_from_the_gap(self):
        for shape, line in (("a-colon-marker", "token: synthetic"),
                            ("b-unpadded-base64", "A" * 43),
                            ("c-prefixed-hex", "0x" + "a" * 64),
                            ("d-quoted-colon", '"token": x'),
                            ("e-quoted-equals", "'key'= x"),
                            ("f-tab-before-colon", "token\t: x"),
                            ("g-space-before-equals", "api_key = x"),
                            ("h-cr-before-colon", "token\r: x"),
                            ("i-bearer", "bEaReR x"),
                            ("j-base64url", "A_" * 21 + "-"),
                            ("k-long-base64", "A" * 88),
                            ("l-long-hex", "a" * 128),
                            ("m-prefixed-long-hex", "0x" + "a" * 128),
                            ("n-padded-base64", "A" * 86 + "=="),
                            ("o-padded-key", "A" * 43 + "="),
                            ("p-bare-hex", "a" * 64)):
            with self.subTest(shape=shape):
                cause = line.replace("\r", " ")
                self.assertEqual(LIVE.live_step_gap(RuntimeError(cause)),
                                 "Live step failed: RuntimeError: (message withheld); see build-root ledger")
                stderr = self.ECHO + line.encode() + b"\n" + self.TRAILER
                error = self.failed(stderr)
                if "<redacted" in LIVE.safe_stderr(line):
                    self.assertEqual(str(error), "command failed; inspect step ledger")
                else:
                    self.assertEqual(LIVE.command_cause(LIVE.safe_stderr(stderr)), cause)
                    self.assertEqual(str(error), "command failed: " + cause + "; inspect step ledger")
                    self.assertEqual(LIVE.live_step_gap(error),
                                     "Live step failed: RuntimeError: (message withheld); see build-root ledger")

    def test_the_length_rule_withholds_runs_of_at_least_40_characters(self):
        for length in (39, 40, 41, 42, 43, 44, 64, 88, 128):
            with self.subTest(length=length):
                line = "Z" * length
                error = self.failed(self.ECHO + line.encode() + b"\n" + self.TRAILER)
                message = ("(message withheld)" if length >= 40 else "command failed: " + line + "; inspect step ledger")
                self.assertEqual(LIVE.live_step_gap(error), "Live step failed: RuntimeError: " + message + "; see build-root ledger")

    def test_a_failed_command_chooses_the_uncapped_cause_and_never_a_partial_value(self):
        prefix = self.ECHO + b"filler diagnostic\n" * 220
        prefix += b"." * (4096 - 20 - len(prefix) - 1) + b"\n"
        for kind, stderr, cause, message in (
                ("refusal-after-cap", self.ECHO + b"filler diagnostic\n" * 300 + self.REFUSAL + self.TRAILER,
                 self.REFUSAL.decode().strip(), None),
                ("value-straddles-cap", prefix + b"A" * 43 + b"\n" + self.TRAILER, "A" * 43, "(message withheld)")):
            with self.subTest(kind=kind):
                error = self.failed(stderr)
                self.assertEqual(str(error), "command failed: " + cause + "; inspect step ledger")
                self.assertEqual(self.ledger[0]["stderr"], LIVE.safe_stderr(stderr))
                self.assertEqual(len(self.ledger[0]["stderr"].encode()), 4096)
                message = message or "command failed: " + cause + "; inspect step ledger"
                self.assertEqual(LIVE.live_step_gap(error), "Live step failed: RuntimeError: " + message + "; see build-root ledger")

    def test_each_marker_after_250_filler_characters_is_withheld_before_capping(self):
        for kind, marker in (("key-word", '"token": x'), ("length", "A" * 40), ("bearer", "Bearer x"),
                             ("password", "PASSWORD rejected"), ("secret", "SECRET rejected"), ("redacted", "<redacted>")):
            with self.subTest(kind=kind):
                error = RuntimeError(". " * 125 + marker)
                self.assertEqual(LIVE.live_step_gap(error),
                                 "Live step failed: RuntimeError: (message withheld); see build-root ledger")

    def test_a_failed_command_names_a_tracebacks_exception_line(self):
        traceback = (b"Traceback (most recent call last):\n  File \"Tools/lab/x.py\", line 3, in <module>\n    run()\n"
                     b"ValueError: peer key digest differs\n")
        error = self.failed(self.ECHO + traceback + self.TRAILER)
        self.assertEqual(str(error), "command failed: ValueError: peer key digest differs; inspect step ledger")
        self.assertEqual(LIVE.live_step_gap(error),
                         "Live step failed: RuntimeError: command failed: ValueError: peer key digest differs; "
                         "inspect step ledger; see build-root ledger")

    def test_a_redacted_final_diagnostic_never_falls_back_to_progress(self):
        for ending in (b"authorization denied\n", b"authorization denied\n" + self.TRAILER + b"\n"):
            with self.subTest(trailer=ending.endswith(b"\n\n")):
                stderr = self.ECHO + b"lab: restoring snapshot ready10\n" + ending
                error = self.failed(stderr)
                self.assertEqual(str(error), "command failed; inspect step ledger")
                self.assertEqual(LIVE.command_cause(LIVE.safe_stderr(stderr, None)), "")
                self.assertEqual(LIVE.live_step_gap(error),
                                 "Live step failed: RuntimeError: command failed; inspect step ledger; see build-root ledger")
                self.assertEqual(self.ledger[0]["stderr"],
                                 (self.ECHO + b"lab: restoring snapshot ready10\n<redacted credential line>\n"
                                  + (self.TRAILER + b"\n" if ending.endswith(b"\n\n") else b"")).decode())

    def test_an_unredacted_final_refusal_after_a_redacted_line_is_still_selected(self):
        stderr = self.ECHO + b"authorization denied\nlab: restoring snapshot ready10\n" + self.REFUSAL + self.TRAILER
        error = self.failed(stderr)
        self.assertEqual(str(error), "command failed: " + self.REFUSAL.decode().strip() + "; inspect step ledger")
        self.assertEqual(self.ledger[0]["stderr"],
                         (self.ECHO + b"<redacted credential line>\nlab: restoring snapshot ready10\n"
                          + self.REFUSAL + self.TRAILER).decode())

    def test_redacted_only_stderr_keeps_the_bare_error_and_the_same_ledger(self):
        stderr = b"authorization denied\n"
        self.assertEqual(str(self.failed(stderr)), "command failed; inspect step ledger")
        self.assertEqual(self.ledger[0]["stderr"], "<redacted credential line>\n")

    def test_a_failed_command_never_names_a_credential_line_or_a_secret_marker(self):
        error = self.failed(self.ECHO + self.REFUSAL + b"PrivateKey = <omitted>\n" + self.TRAILER)
        self.assertEqual(str(error), "command failed; inspect step ledger")
        self.assertNotIn("PrivateKey", str(error))
        error = self.failed(self.ECHO + b"login failed WGEX_TOKEN=abc123\n" + self.TRAILER)
        self.assertEqual(LIVE.live_step_gap(error), "Live step failed: RuntimeError: (message withheld); see build-root ledger")

    def test_a_failed_command_with_only_just_lines_or_no_stderr_keeps_the_old_text(self):
        for stderr in (b"", self.ECHO + self.TRAILER):
            self.assertEqual(str(self.failed(stderr)), "command failed; inspect step ledger")


class ReceiverHealthCauseTests(unittest.TestCase):
    def receiver(self):
        receiver = R.Receiver.__new__(R.Receiver)
        receiver.bindings = [(None, "192.168.64.1", 8088, "http")]
        receiver.scope, receiver.digest = "outside_tunnel", "digest"
        receiver.start, receiver.config, receiver.observations = 1, {}, []
        receiver.selector = Mock()
        receiver.selector.select.return_value = []
        receiver.controls = set()
        receiver.healthy, receiver.last_poll = True, time.monotonic()
        return receiver

    def test_a_two_second_poll_gap_records_pollgap_with_its_size_and_time(self):
        receiver = self.receiver()
        receiver.last_poll = time.monotonic() - 2.0
        before = time.time()
        receiver.poll()
        record = receiver.record(9)
        self.assertEqual(record["healthCause"], "pollGap")
        self.assertAlmostEqual(record["healthPollGapSeconds"], 2.0, delta=0.2)
        self.assertGreaterEqual(record["healthPollGapAt"], before)
        self.assertLessEqual(record["healthPollGapAt"], time.time())
        self.assertTrue(all(item["healthy"] is False for item in record["receiverCoverage"]))

    def test_the_largest_gap_is_kept(self):
        receiver = self.receiver()
        for gap in (3.0, 2.0):
            receiver.last_poll = time.monotonic() - gap
            receiver.poll()
        self.assertAlmostEqual(receiver.record(9)["healthPollGapSeconds"], 3.0, delta=0.2)

    def test_a_gap_at_or_under_the_rule_changes_nothing(self):
        receiver = self.receiver()
        receiver.last_poll = time.monotonic() - 1.0
        receiver.poll()
        record = receiver.record(9)
        self.assertTrue(receiver.healthy)
        self.assertNotIn("healthCause", record)
        self.assertTrue(all(item["healthy"] is True for item in record["receiverCoverage"]))

    def test_a_failed_end_control_records_endcontrol(self):
        receiver = self.receiver()
        with patch.object(receiver, "control", return_value=False) as control:
            receiver.finish()
        control.assert_called_once_with("end")
        record = receiver.record(9)
        self.assertEqual(record["healthCause"], "endControl")
        self.assertNotIn("healthPollGapSeconds", record)
        self.assertFalse(receiver.healthy)

    def test_a_failed_start_control_records_startcontrol_and_forgets_start_phase_gaps(self):
        receiver = self.receiver()
        receiver.healthy = False

        def control(label):
            receiver.last_poll = time.monotonic() - 2.0
            receiver.poll()
            return False
        with patch.object(receiver, "control", side_effect=control):
            self.assertFalse(receiver.begin())
        record = receiver.record(9)
        self.assertEqual(record["healthCause"], "startControl")
        self.assertNotIn("healthPollGapSeconds", record)

    def test_a_healthy_receiver_has_no_cause_fields(self):
        receiver = self.receiver()
        with patch.object(receiver, "control", return_value=True):
            self.assertTrue(receiver.begin())
            receiver.finish()
        record = receiver.record(9)
        self.assertEqual({key for key in record if key.startswith("health")}, set())
        self.assertTrue(all(item["healthy"] is True for item in record["receiverCoverage"]))

    def test_an_unhealthy_receiver_skips_the_end_control_as_before(self):
        receiver = self.receiver()
        receiver.healthy = False
        with patch.object(receiver, "control", return_value=True) as control:
            receiver.finish()
        control.assert_not_called()
        self.assertFalse(receiver.healthy)

    def test_a_receiver_unhealthy_from_a_poll_gap_keeps_pollgap_through_finish(self):
        # M1-57 fix pass 1 (N3): the run 9b F2 ambiguity; a poll-gap receiver must not read endControl.
        receiver = self.receiver()
        receiver.last_poll = time.monotonic() - 2.0
        receiver.poll()
        self.assertFalse(receiver.healthy)
        with patch.object(receiver, "control", return_value=True) as control:
            receiver.finish()
        control.assert_not_called()
        record = receiver.record(9)
        self.assertEqual(record["healthCause"], "pollGap")
        self.assertAlmostEqual(record["healthPollGapSeconds"], 2.0, delta=0.2)

    def test_a_start_phase_gap_is_forgotten_by_a_successful_begin(self):
        # M1-57 fix pass 1 (N4 M6): a 3 s gap while the start exchange runs, then a 2 s gap in the main loop: 2.0, not 3.0.
        receiver = self.receiver()

        def control(label):
            receiver.last_poll = time.monotonic() - 3.0
            receiver.poll()
            return True
        with patch.object(receiver, "control", side_effect=control):
            self.assertTrue(receiver.begin())
        self.assertTrue(receiver.healthy)
        receiver.last_poll = time.monotonic() - 2.0
        receiver.poll()
        record = receiver.record(9)
        self.assertEqual(record["healthCause"], "pollGap")
        self.assertAlmostEqual(record["healthPollGapSeconds"], 2.0, delta=0.2)


class ReceiverMainTests(unittest.TestCase):
    """main() driven in process with a stubbed receiver socket layer and control exchange; nothing opens a socket and nothing
    waits (the stop file exists before the loop, --seconds 1)."""

    def run_main(self, start_control):
        receiver = ReceiverHealthCauseTests("test_a_healthy_receiver_has_no_cause_fields").receiver()
        receiver.close = Mock()
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            root = Path(directory)
            (root / "config.json").write_text("{}")
            (root / "stop").write_text("")
            argv = ["receiver.py", "--config", str(root / "config.json"), "--scope", "outside_tunnel", "--record", str(root / "host.json"),
                    "--ready", str(root / "host.ready"), "--stop", str(root / "stop"), "--seconds", "1"]
            with patch.object(R, "Receiver", Mock(return_value=receiver)), patch.object(sys, "argv", argv), \
                    patch.object(receiver, "control", return_value=start_control):
                try:
                    R.main()
                    raised = None
                except ValueError as error:
                    raised = error
            record = json.loads((root / "host.json").read_bytes()) if (root / "host.json").exists() else None
            return raised, record, (root / "host.ready").exists(), receiver

    def test_a_failed_start_control_writes_a_record_naming_it_and_never_readiness(self):
        # M1-57 fix pass 1 (N4 M11)
        raised, record, ready, receiver = self.run_main(False)
        self.assertEqual(str(raised), "receiver control failed")
        self.assertIsNotNone(record)
        self.assertEqual(record["healthCause"], "startControl")
        self.assertTrue(all(item["healthy"] is False for item in record["receiverCoverage"]))
        self.assertFalse(ready)
        receiver.close.assert_called_once_with()

    def test_a_healthy_run_writes_readiness_and_a_record_without_cause_fields(self):
        raised, record, ready, _ = self.run_main(True)
        self.assertIsNone(raised)
        self.assertTrue(ready)
        self.assertEqual({key for key in record if key.startswith("health")}, set())


class ReceiverHealthGapTests(unittest.TestCase):
    def coverage(self, healthy):
        return [dict(address="192.168.64.1", port=8088, proto="tcp", scope="outside_tunnel", start=1, end=9, healthy=healthy)]

    def test_each_cause_is_named_once_per_unhealthy_receiver(self):
        gaps = V.receiver_health_gaps([
            ("host", dict(receiverCoverage=self.coverage(False), healthCause="pollGap", healthPollGapSeconds=2.04, healthPollGapAt=1793857800)),
            ("peer", dict(receiverCoverage=self.coverage(False) * 8, healthCause="endControl"))])
        self.assertEqual(len(gaps), 2)
        self.assertIn("host receiver unhealthy: receiver poll gap of 2.0 s over the 1.5 s limit at 05:50:00 GMT", gaps[0])
        self.assertIn("peer receiver unhealthy: the end control exchange failed", gaps[1])
        self.assertIn("the start control exchange failed",
                      V.receiver_health_gaps([("host", dict(receiverCoverage=self.coverage(False), healthCause="startControl"))])[0])

    def test_a_record_without_the_field_says_the_cause_was_not_recorded(self):
        gaps = V.receiver_health_gaps([("host", dict(receiverCoverage=self.coverage(False)))])
        self.assertEqual(len(gaps), 1)
        self.assertIn("cause not recorded", gaps[0])
        self.assertEqual(V.receiver_health_gaps([("host", dict(receiverCoverage=self.coverage(False), healthCause="mystery"))])[0], gaps[0])

    def test_healthy_or_absent_coverage_adds_no_line(self):
        self.assertEqual(V.receiver_health_gaps([("host", dict(receiverCoverage=self.coverage(True))), ("peer", {})]), [])

    def test_a_pollgap_record_missing_its_numbers_does_not_raise(self):
        gaps = V.receiver_health_gaps([("host", dict(receiverCoverage=self.coverage(False), healthCause="pollGap"))])
        self.assertIn("receiver poll gap over the 1.5 s limit", gaps[0])

    def pollgap(self, seconds=2.04, at=1793857800):
        return V.receiver_health_gaps([("host", dict(receiverCoverage=self.coverage(False), healthCause="pollGap",
                                                   healthPollGapSeconds=seconds, healthPollGapAt=at))])[0]

    def test_out_of_range_or_invalid_times_drop_only_the_time(self):
        expected = "host receiver unhealthy: receiver poll gap of 2.0 s over the 1.5 s limit; its coverage cannot count"
        for index, at in enumerate((1e20, -1e20, 10**400, -10**400, -1, 4_000_000_000,
                                    float("inf"), float("nan"), True, "invalid", None)):
            with self.subTest(case=index):
                self.assertEqual(self.pollgap(at=at), expected)

    def test_huge_or_invalid_seconds_drop_only_the_duration(self):
        expected = "host receiver unhealthy: receiver poll gap over the 1.5 s limit at 05:50:00 GMT; its coverage cannot count"
        for index, seconds in enumerate((1e300, -1e300, 10**400, -10**400, -1, 86_400.1,
                                         float("inf"), float("nan"), True, "invalid", None)):
            with self.subTest(case=index):
                self.assertEqual(self.pollgap(seconds=seconds), expected)

    def test_ordinary_values_and_inclusive_duration_bounds_keep_their_format(self):
        for seconds, duration in ((0, "0.0"), (2.04, "2.0"), (86_400, "86400.0")):
            with self.subTest(seconds=seconds):
                self.assertEqual(self.pollgap(seconds=seconds), "host receiver unhealthy: receiver poll gap of " + duration
                                 + " s over the 1.5 s limit at 05:50:00 GMT; its coverage cannot count")
        self.assertIn(" at 00:00:00 GMT;", self.pollgap(at=0))
        self.assertIn(" at ", self.pollgap(at=3_999_999_999))

    def test_platform_time_conversion_errors_drop_only_the_time(self):
        expected = "host receiver unhealthy: receiver poll gap of 2.0 s over the 1.5 s limit; its coverage cannot count"
        for function in ("gmtime", "strftime"):
            for error in (OverflowError, OSError, ValueError):
                with self.subTest(function=function, error=error.__name__), patch.object(V.time, function, side_effect=error):
                    self.assertEqual(self.pollgap(), expected)


class UnhealthyReceiverRunTests(unittest.TestCase):
    """The live row with a receiver that recorded healthy false (run 9b attempt 2): coverage stays incomplete, the tail control
    still fails, and gaps now name the cause, one line per unhealthy receiver."""

    def run_with(self, cause, fail_generator=False):
        class Runner(replay.RecordedRunner):
            def receiver(self, scope):
                record = super().receiver(scope)
                for item in record["receiverCoverage"]:
                    item["healthy"] = False
                record.update(cause(scope))
                return record
        runner = Runner()
        runner.fail_generator = fail_generator
        return replay.LiveReplayTests().run_recorded("M5.1-04", runner, accepted=False)[1]

    def test_malformed_diagnostics_preserve_completed_and_incomplete_failure_dispositions(self):
        report = replay.module("m157_report", "verdict-run.py")
        for case, at in enumerate((1e20, -1e20, 10**400, -10**400, True, False, -0.05)):
            for fail_generator in (False, True):
                with self.subTest(case=case, incomplete=fail_generator):
                    result = self.run_with(lambda scope: dict(healthCause="pollGap", healthPollGapSeconds=1e300,
                                                             healthPollGapAt=at), fail_generator=fail_generator)
                    self.assertIs(result["rowCompleted"], not fail_generator)
                    self.assertFalse(result["expectationsMet"])
                    self.assertFalse(result["tailControl"]["met"])
                    self.assertEqual(result["familiesCovered"], [])
                    self.assertTrue(all(not state["coverage"]["complete"] for state in result["states"] if "coverage" in state))
                    health = [gap for gap in result["gaps"] if "receiver unhealthy" in gap]
                    self.assertEqual(len(health), 2)
                    self.assertTrue(all("receiver poll gap over the 1.5 s limit; its coverage cannot count" in gap for gap in health))
                    if fail_generator:
                        self.assertTrue(any("recorded generator failure" in gap for gap in result["gaps"]))
                    # Run the real report decision with the replay result; no report file or transport is opened.
                    scratch = Path(os.environ["TMPDIR"])
                    with patch.object(report, "load_module", return_value=Mock(run=Mock(return_value=result))), \
                            patch.object(report.PROVENANCE, "ancestor", return_value=True), \
                            patch.object(report.HARNESS, "host_load", return_value={}), \
                            patch.object(report.HARNESS, "warning", return_value=""), \
                            patch.object(report.STATE, "build_root", return_value=scratch), \
                            patch.object(report, "write_report", return_value=scratch / "verdict.json") as write, \
                            patch.object(sys, "stdout", Mock()), patch.object(sys, "stderr", Mock()), \
                            patch.object(subprocess, "run", side_effect=AssertionError("real command from report")), \
                            patch.object(subprocess, "Popen", side_effect=AssertionError("real process from report")):
                        self.assertEqual(report.main(["M5.1-04"]), 1)
                    write.assert_called_once()
                    written = write.call_args.args[1]
                    self.assertFalse(written["expectationsMet"])
                    self.assertFalse(written["liveAcceptance"])
                    self.assertEqual(written["reportDisposition"],
                                     "incomplete run; build root only" if fail_generator else "completed row")
                    self.assertTrue(write.call_args.kwargs["keep_attempts"])
                    if fail_generator:
                        self.assertEqual(write.call_args.args[0], scratch / "lab-verdict-failures" / "M5.1-04")

    def test_coverage_stays_incomplete_and_gaps_name_each_cause(self):
        result = self.run_with(lambda scope: dict(healthCause="pollGap", healthPollGapSeconds=2.0, healthPollGapAt=1793857800)
                               if scope == "outside_tunnel" else dict(healthCause="endControl"))
        self.assertFalse(result["expectationsMet"])
        self.assertFalse(result["tailControl"]["met"])
        self.assertTrue(all(not state["coverage"]["complete"] for state in result["states"] if "coverage" in state))
        host = [gap for gap in result["gaps"] if gap.startswith("host receiver unhealthy")]
        peer = [gap for gap in result["gaps"] if gap.startswith("peer receiver unhealthy")]
        self.assertEqual((len(host), len(peer)), (1, 1), result["gaps"])
        self.assertIn("poll gap of 2.0 s", host[0])
        self.assertIn("end control exchange failed", peer[0])

    def test_a_completed_row_with_unhealthy_receivers_stays_a_completed_row(self):
        # M1-57 fix pass 1 (VERIFY N1): the health lines are diagnostics; verdict-run keys the report destination on rowCompleted.
        result = self.run_with(lambda scope: dict(healthCause="pollGap", healthPollGapSeconds=2.0, healthPollGapAt=1793857800))
        self.assertIs(result["rowCompleted"], True)
        self.assertFalse(result["expectationsMet"])
        self.assertEqual(len([gap for gap in result["gaps"] if "receiver unhealthy" in gap]), 2, result["gaps"])

    def test_a_healthy_row_is_unchanged_completed_met_and_without_health_lines(self):
        _, result = replay.LiveReplayTests().run_recorded("M5.1-04")
        self.assertIs(result["rowCompleted"], True)
        self.assertTrue(result["expectationsMet"])
        self.assertEqual(result["gaps"], [])

    def test_the_poll_gap_time_carries_the_recorded_clock_offset(self):
        # M1-57 fix pass 1 (N4 M12): a runner whose guest clock is an hour ahead shifts the receiver stamps; the gap says 06:50.
        class Ahead(replay.RecordedRunner):
            def run(self, argv, data=None, timeout=100, env=None):
                result = super().run(argv, data=data, timeout=timeout, env=env)
                if argv[:4] == ["just", "lab", "ssh", "--clock"]:
                    sample = json.loads(result.stdout)
                    sample["timestamp"] += 3600
                    return self.reply(argv, V.canonical(sample))
                return result
        class Receivers(Ahead):
            def receiver(self, scope):
                record = super().receiver(scope)
                for item in record["receiverCoverage"]:
                    item["healthy"] = False
                record.update(healthCause="pollGap", healthPollGapSeconds=2.0, healthPollGapAt=1793857800)
                return record
        result = replay.LiveReplayTests().run_recorded("M5.1-04", Receivers(), accepted=False)[1]
        self.assertAlmostEqual(result["clockMeasurement"]["offsetSeconds"], 3600.1, delta=0.01)
        host = [gap for gap in result["gaps"] if gap.startswith("host receiver unhealthy")]
        self.assertEqual(len(host), 1, result["gaps"])
        self.assertIn("at 06:50:00 GMT", host[0])

    def test_an_older_record_without_the_field_still_verifies_and_says_so(self):
        result = self.run_with(lambda scope: {})
        self.assertFalse(result["expectationsMet"])
        self.assertEqual(len([gap for gap in result["gaps"] if "cause not recorded" in gap]), 2, result["gaps"])


if __name__ == "__main__":
    unittest.main()
