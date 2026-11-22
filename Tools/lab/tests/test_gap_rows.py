# SPDX-License-Identifier: MIT
"""M03-T02: synthetic pass/fail rows, guarded injections and public telemetry. No VM or network operation."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
LAB = ROOT / "Tools/lab"
GUEST = LAB / "tart/guest"


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


V = module("gap_verdict", LAB / "verdict.py")
RUN = module("gap_replay", LAB / "verdict-run.py")
LIVE = module("gap_live", LAB / "verdict-live.py")
ROWS = json.loads((LAB / "rows.json").read_text())["rows"]
TABLE = json.loads((LAB / "leak-expectations.json").read_text())
KEPT = {"M5.3-09": "logout", "M5.4-04": "dns-edit", "M5.4-07": "pf-disable", "RT-21": "rt21",
        "RT-22": "rt22", "CRASH-TOKEN": "token", "CRASH-PF-DISABLE": "pf-disable"}


def fixture(kind):
    return json.loads((LAB / "tests/fixtures/rows" / (kind + ".json")).read_text())


def error_policy_first(observation):
    return next(c["met"] for c in V.row_checks("rt22", observation) if c["name"] == "errorPolicyFirst")


def run_exec_filter(data):
    return subprocess.run(["perl", str(GUEST / "pf-execs.pl"), "282"], input=data, capture_output=True, check=False)


class RowTests(unittest.TestCase):
    def test_all_kept_rows_replay_with_every_expectation_covered_by_a_failing_fixture(self):
        for name, kind in KEPT.items():
            with self.subTest(row=name), patch.object(RUN, "load_module", side_effect=AssertionError("live import")):
                self.assertNotIn("gap", ROWS[name])
                self.assertEqual(ROWS[name]["action"], kind)
                result = RUN.replay(ROWS[name], TABLE, {})
                self.assertTrue(result["expectationsMet"], result)
                self.assertFalse(result["failingFixturesUncovered"])
                self.assertTrue(result["failingFixtures"])
                self.assertTrue(all(c["rejected"] for c in result["failingFixtures"]))
                self.assertTrue(all(c["met"] for c in result["checks"]))
                self.assertLess((LAB / "tests/fixtures/rows" / (kind + ".json")).stat().st_size, 50000)

    def test_missing_telemetry_and_missing_first_restart_observation_fail_closed(self):
        for kind in ("token", "rt22"):
            for key in ("sequence", "measuredAt", "journalPolicy", "ownerPFTokenHash", "ownerPFTokenPresent"):
                observation = fixture(kind)["pass"]
                observation["baseline"].pop(key)
                with self.subTest(kind=kind, field=key):
                    self.assertFalse(all(c["met"] for c in V.row_checks(kind, observation)))
        for key in ("sequence", "measuredAt", "journalPolicy", "protection"):
            observation = fixture("rt22")["pass"]
            for sample in observation["samples"]:
                sample["startup"].pop(key)
            with self.subTest(startup=key):
                self.assertFalse(error_policy_first(observation))
        observation = fixture("rt22")["pass"]
        for sample in observation["samples"]:
            sample.pop("startup")
        self.assertFalse(error_policy_first(observation))

    def test_rt22_reads_the_startup_record_instead_of_racing_for_the_first_live_sample(self):
        """DEC-018: no restarted live sample is sequence 1; the kept record is, and a later first read still sees it."""
        observation = fixture("rt22")["pass"]
        self.assertTrue(all(s["sequence"] > 1 for s in observation["samples"]))
        self.assertTrue(error_policy_first(observation))
        observation["samples"].pop(0)
        self.assertTrue(error_policy_first(observation))
        # A first live sample that is sequence 1 but carries no record is not evidence.
        observation = fixture("rt22")["pass"]
        observation["samples"][0].update(sequence=1, journalPolicy="error", protection="blocked")
        observation["samples"][0].pop("startup")
        self.assertFalse(error_policy_first(observation))
        # The record of the run before the restart (no newer than the baseline) is rejected.
        observation = fixture("rt22")["pass"]
        for sample in observation["samples"]:
            sample["startup"]["measuredAt"] = observation["baseline"]["measuredAt"]
        self.assertFalse(error_policy_first(observation))

    def test_stale_measurements_and_unknown_after_recovery_cannot_pass(self):
        observation = fixture("pf-disable")["pass"]
        observation["samples"][1]["measuredAt"] = observation["baseline"]["measuredAt"]
        self.assertFalse(all(c["met"] for c in V.row_checks("pf-disable", observation)))
        observation = fixture("pf-disable")["pass"]
        observation["samples"].reverse()
        self.assertFalse(all(c["met"] for c in V.row_checks("pf-disable", observation)))

    def test_rule_order_and_global_or_foreign_state_kills_are_rejected(self):
        control = dict(pid=282, daemonPfctlExecs=57)
        for args in ([], ["-F", "states"], ["-F", "all"], ["-i", "utun8", "-F", "states"], ["-k", "0.0.0.0/0"]):
            observation = fixture("rt21")["pass"]
            observation["pfExecs"] = [dict(arguments=args), control]
            self.assertFalse(V.GAP_ROWS.rt21_checks(observation)[-1]["met"])
        observation = fixture("rt21")["pass"]
        observation["rulesBefore"] = "pass quick on en0 from any to 169.254.0.0/16\n" + observation["rulesBefore"]
        self.assertFalse(V.GAP_ROWS.rt21_checks(observation)[0]["met"])

    def test_no_state_kill_passes_only_with_the_observers_positive_control(self):
        # The daemon kills states on blocking entry only (M1-05), so a steady wake may run none; silence from an observer that
        # saw no daemon pfctl at all proves nothing.
        kill = dict(pid=282, arguments=["-i", "en0", "-F", "states"])
        for execs, met in (([dict(pid=282, daemonPfctlExecs=57)], True),
                           ([kill, dict(pid=282, daemonPfctlExecs=57)], True),
                           ([], False),
                           ([dict(pid=282, daemonPfctlExecs=0)], False),
                           ([kill], False),
                           ([kill, dict(pid=282, daemonPfctlExecs=0)], False),
                           ([kill, kill, dict(pid=282, daemonPfctlExecs=1)], False),
                           ([dict(pid=282, daemonPfctlExecs=57), dict(pid=282, daemonPfctlExecs=57)], False),
                           ([dict(pid=282, daemonPfctlExecs="57")], False),
                           ([dict(pid=282, daemonPfctlExecs=57), dict(pid=282, other=1)], False)):
            observation = fixture("rt21")["pass"]
            observation["pfExecs"] = execs
            with self.subTest(execs=execs):
                self.assertEqual(V.GAP_ROWS.rt21_checks(observation)[-1]["met"], met)

    def test_exec_filter_ends_with_the_count_of_daemon_pfctl_children(self):
        events = [dict(event=dict(exec=dict(target=dict(executable=dict(path="/sbin/pfctl"), ppid=ppid), args=args)))
                  for ppid, args in ((282, ["pfctl", "-a", "com.apple/wgex", "-vsr"]), (282, ["pfctl", "-i", "en0", "-F", "states"]),
                                     (77, ["pfctl", "-vsr"]))]
        result = run_exec_filter("\n".join(json.dumps(e) for e in events).encode() + b"\n")
        lines = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(lines[-1], dict(pid=282, daemonPfctlExecs=2), "a foreign parent is not counted")
        self.assertEqual([line["arguments"] for line in lines[:-1]], [["-i", "en0", "-F", "states"]])
        silent = [json.loads(line) for line in run_exec_filter(b"").stdout.splitlines()]
        self.assertEqual(silent, [dict(pid=282, daemonPfctlExecs=0)])

    def test_empty_observations_never_pass(self):
        for kind in set(KEPT.values()):
            self.assertFalse(all(c["met"] for c in V.row_checks(kind, {})), kind)


class GuardTests(unittest.TestCase):
    def test_host_refusal_happens_before_every_new_guest_operation_with_commands_stubbed(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            root = Path(directory)
            log = root / "calls"
            for name, reply in (("sw_vers", "27.0"), ("sysctl", "0")):
                path = root / name
                path.write_text('#!/bin/sh\nprintf "%s\\n" "' + reply + '"\n')
                path.chmod(0o700)
            for name in ("pfctl", "networksetup", "scutil", "sudo", "osascript", "wgex", "eslogger"):
                path = root / name
                path.write_text('#!/bin/sh\nprintf called >> "$CALLS"\nexit 97\n')
                path.chmod(0o700)
            for action in ("dns-edit", "dns-check", "dns-restore", "boot-intent-set", "logout", "console-user",
                           "rt21-start", "rt21-watch", "rt21-stop", "fault token", "fault pf-disable", "fault rt22"):
                with self.subTest(action=action):
                    result = subprocess.run(["bash", str(GUEST / "gap-actions.sh"), *action.split()],
                                            env=dict(os.environ, PATH=str(root) + ":/usr/bin:/bin", CALLS=str(log)),
                                            capture_output=True, timeout=5, check=False)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(b"VM required", result.stderr)
                    self.assertFalse(log.exists(), "an injection command ran before the host guard")

    def test_token_fault_telemetry_check_accepts_scalar_and_object_fields_and_refuses_a_missing_one(self):
        # Guest run 10: `plutil -extract sequence json` is invalid for a scalar, so CRASH-TOKEN died before the injection.
        text = (GUEST / "gap-actions.sh").read_text()
        start = text.index("      for field in sequence measuredAt journalPolicy; do")
        block = text[start:text.index("      done", start) + len("      done")]
        status = dict(sequence=2, measuredAt="2001-01-01T00:00:01Z", journalPolicy={"error": {}}, ownerPFToken="1")
        for missing in (None, "sequence", "measuredAt", "journalPolicy"):
            with self.subTest(missing=missing):
                value = {key: item for key, item in status.items() if key != missing}
                result = subprocess.run(["bash", "-c", 'set -euo pipefail\nstatus="$1"\n' + block, "bash", json.dumps(value)],
                                        capture_output=True, timeout=5, check=False)
                self.assertEqual(result.returncode == 0, missing is None, result.stderr)

    def test_status_filter_uses_owner_identity_and_never_emits_the_token(self):
        token = "123456789"
        status = dict(sequence=2, measuredAt="2001-01-01T00:00:01Z", journalPolicy={"error": {}}, ownerPFToken=token,
                      phase="failed", protection="blocked")
        result = subprocess.run(["perl", str(GUEST / "gap-status.pl"), "1001", "200",
                                 "200 pfctl " + token + " 0 days 00:00:00", "Status: Enabled"],
                                input=json.dumps(status).encode(), capture_output=True, check=True)
        value = json.loads(result.stdout)
        self.assertTrue(V.GAP_ROWS.telemetry(value))
        self.assertNotIn(token.encode(), result.stdout)
        status.pop("ownerPFToken")
        result = subprocess.run(["perl", str(GUEST / "gap-status.pl"), "1001", "200", "", "Status: Enabled"],
                                input=json.dumps(status).encode(), capture_output=True, check=True)
        self.assertFalse(V.GAP_ROWS.telemetry(json.loads(result.stdout)))

    def test_status_filter_passes_the_startup_record_through_so_rt22_keeps_error_policy_first(self):
        """DEC-018: the live collector reduces `startup` to sequence, measuredAt, journalPolicy and protection, never the token."""
        observation = fixture("rt22")["pass"]
        tokens = {}

        def collect(sample, startup=True):
            token = tokens.setdefault(sample["pid"], str(4660 + len(tokens)))
            status = dict(sequence=sample["sequence"], measuredAt=sample["measuredAt"], journalPolicy=sample["journalPolicy"],
                          phase=sample["phase"], protection=sample["protection"], ownerPFToken=token, activeProfileID=None)
            if startup:
                record = sample.get("startup")
                # As `wgex status --json` prints it: every publication field, the Lab token included.
                status["startup"] = None if record is None else dict(
                    record, journalPolicy={record["journalPolicy"]: {}}, ownerPFToken=token, phase="failed",
                    activeProfileID="00000000-0000-0000-0000-000000000001", measuredAtContinuous=12.5, operationInFlight=False)
            references = f"{sample['pid']} pfctl {token} 0 days 00:00:00" if sample["referenceCount"] == 1 else ""
            result = subprocess.run(["perl", str(GUEST / "gap-status.pl"), str(sample["at"]), str(sample["pid"]), references,
                                     "Status: Enabled" if sample["pfEnabled"] else "Status: Disabled"],
                                    input=json.dumps(status).encode(), capture_output=True, check=True)
            for secret in tokens.values():
                self.assertNotIn(secret.encode(), result.stdout)
            return json.loads(result.stdout)

        collected = dict(observation, baseline=collect(observation["baseline"]),
                         samples=[collect(s) for s in observation["samples"]])
        for sample, source in zip(collected["samples"], observation["samples"]):
            self.assertEqual(sample["startup"], source["startup"])
            self.assertEqual(set(sample["startup"]), {"sequence", "measuredAt", "journalPolicy", "protection"})
            self.assertIs(type(sample["startup"]["sequence"]), int)
        self.assertIsNone(collected["baseline"]["startup"])
        self.assertTrue(error_policy_first(collected))
        self.assertTrue(all(c["met"] for c in V.row_checks("rt22", collected)))
        # A collector that drops the record leaves RT-22 without evidence: it fails closed.
        dropped = dict(observation, baseline=collect(observation["baseline"]),
                       samples=[collect(s, startup=False) for s in observation["samples"]])
        self.assertFalse(error_policy_first(dropped))

    def test_exec_filter_accepts_only_daemon_children_and_records_unsafe_state_kills_for_rejection(self):
        events = []
        for executable, parent, args in (("/sbin/pfctl", 282, ["pfctl", "-i", "en0", "-F", "states"]),
                                         ("/sbin/pfctl", 282, ["pfctl", "-F", "states"]),
                                         ("/sbin/pfctl", 77, ["pfctl", "-i", "en0", "-F", "states"]),
                                         ("/bin/echo", 282, ["withheld"])):
            events.append(dict(event=dict(exec=dict(target=dict(executable=dict(path=executable), ppid=parent), args=args))))
        result = subprocess.run(["perl", str(GUEST / "pf-execs.pl"), "282"],
                                input="\n".join(json.dumps(e) for e in events).encode(), capture_output=True, check=True)
        values = [json.loads(line) for line in result.stdout.splitlines() if b"arguments" in line]
        self.assertEqual([v["arguments"] for v in values], [["-i", "en0", "-F", "states"], ["-F", "states"]])
        self.assertNotIn(b"withheld", result.stdout)


    def test_exec_filter_drops_an_event_cut_off_by_the_stop_but_fails_a_corrupt_stream(self):
        kill = json.dumps(dict(event=dict(exec=dict(target=dict(executable=dict(path="/sbin/pfctl"), ppid=282),
                                                    args=["pfctl", "-i", "en0", "-F", "states"]))))
        # The stop cut the last event short mid-write: no newline, never a complete event. It must not fail the observer.
        cut = run_exec_filter((kill + "\n" + kill[:40]).encode())
        self.assertEqual(cut.returncode, 0, cut.stderr)
        self.assertEqual(len([line for line in cut.stdout.splitlines() if b"arguments" in line]), 1, "the complete event before the cut is kept")
        # The same cut inside a long event stream, after earlier complete events.
        self.assertEqual(run_exec_filter((kill + "\n" + kill + "\n" + kill[:5]).encode()).returncode, 0)
        # A newline-terminated line that leaves the event incomplete is a corrupt stream: fail closed.
        corrupt = run_exec_filter((kill + "\n" + kill[:40] + "\n").encode())
        self.assertNotEqual(corrupt.returncode, 0)
        self.assertIn(b"incomplete exec event", corrupt.stderr)
        # An unterminated final line that is a complete event is still read.
        whole = run_exec_filter(kill.encode())
        self.assertEqual((whole.returncode, len([line for line in whole.stdout.splitlines() if b"arguments" in line])), (0, 1))
        # Garbage is a syntax error, not a silent pass.
        self.assertNotEqual(run_exec_filter(b"not json\n").returncode, 0)

    def test_exec_filter_failures_print_a_fixed_diagnostic_and_never_echo_the_input(self):
        marker = "SECRET!MARKER=hunter2"
        kill = json.dumps(dict(event=dict(exec=dict(target=dict(executable=dict(path="/sbin/pfctl"), ppid=282),
                                                    args=["pfctl", "-F", "states", marker]))))
        cases = {
            "garbage": ("garbage " + marker + "\n").encode(),
            "garbage after a valid event": (kill.replace(marker, "x") + "\n{\"a\": " + marker + "}\n").encode(),
            "unsafe arguments": (kill + "\n").encode(),
            "a non-object event": ("[\"" + marker + "\"]\n").encode(),
            "a string event": ("\"" + marker + "\"\n").encode(),
            "an incomplete event": (kill[:40] + marker + "\n").encode(),
        }
        fixed = {"malformed exec event stream", "invalid pf exec arguments", "incomplete exec event"}
        for name, data in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as tmp:
                diagnostic = Path(tmp) / "pf-execs.err"
                result = subprocess.run(["perl", str(GUEST / "pf-execs.pl"), "282", str(diagnostic)], input=data,
                                        capture_output=True, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(result.stderr.decode().strip(), fixed)
                self.assertEqual(diagnostic.read_text(), "pf-execs: " + result.stderr.decode().strip() + "\n")
                for leaked in (result.stdout, result.stderr, diagnostic.read_bytes()):
                    self.assertNotIn(marker.encode(), leaked)
                    self.assertNotIn(b"hunter2", leaked)
        # An argument the filter cannot accept still fails with only the fixed words.
        result = subprocess.run(["perl", str(GUEST / "pf-execs.pl"), "not-a-pid-" + marker], input=b"",
                                capture_output=True, check=False)
        self.assertEqual((result.returncode, result.stderr), (1, b"daemon PID required\n"))

    def test_the_guest_script_never_stores_or_prints_raw_filter_stderr(self):
        text = (GUEST / "gap-actions.sh").read_text()
        filter_line = next(line for line in text.splitlines() if "pf-execs.pl" in line and "perl" in line)
        self.assertIn('"$stage/pf-execs.err" <', filter_line, "the filter writes its own fixed diagnostic")
        self.assertTrue(filter_line.rstrip().endswith("2>/dev/null &"), filter_line)
        stop_line = next(line for line in text.splitlines() if "rt21-stop: done=" in line)
        self.assertIn("grep -E '^pf-execs: ", stop_line, "only a diagnostic of the fixed shape is printed")


class DriverTests(unittest.TestCase):
    def test_logout_driver_runs_both_settings_and_requires_console_relogin(self):
        session = object.__new__(LIVE.Session)
        session.row_observation, session.profile_ids = {}, {"full4": "00000000-0000-4000-8000-000000000001"}
        calls, console = [], iter([b"logged-out", b"lab", b"logged-out", b"lab"])
        session.runner = type("Clock", (), dict(monotonic=lambda self: 1000))()
        def action(name, *args):
            calls.append((name, args))
            return next(console) if name == "console-user" else b""
        session.gap_action = action
        session.set_startup_off = lambda identity: calls.append(("startup", ("off",)))
        session.set_startup_boot = lambda identity: calls.append(("startup", ("boot",)))
        session.boot_intent = lambda identity: [c[1][-1] for c in calls if c[0] == "startup"][-1:] == ["boot"]
        session.await_status = lambda *args, **kw: None
        session.status = lambda: dict(phase="active", protection="protected")
        session.lab = lambda *args: None
        session.connect = lambda profile: None
        session.observe = lambda: dict(status=dict(protection="protected" if session.boot_intent("") else "unprotected"),
                                       referenceCount=1 if session.boot_intent("") else 0)
        session.generate = lambda state, **kw: dict(state=state, **kw)
        records = session.logout_row("full4")
        self.assertEqual(len(records), 4)
        self.assertEqual([c[1][-1] for c in calls if c[0] == "startup"], ["off", "boot"])
        self.assertEqual([c for c in calls if c[0] == "boot-intent-set"], [], "the guest CLI is refused; Settings sets the intent")
        self.assertTrue(all(c["met"] for c in V.row_checks("logout", session.row_observation)))


    def test_the_off_setting_fails_named_when_the_registry_keeps_start_before_login(self):
        session = object.__new__(LIVE.Session)
        clock = iter(range(0, 10000, 5))
        session.runner = type("Clock", (), dict(monotonic=lambda self: next(clock)))()
        session.ledger, pressed = [], []
        session.open_settings = lambda: "1"
        session.select_settings_tab = lambda window, tab: None
        session.select_startup_option = lambda window, option: pressed.append(option)
        session.close_settings = lambda window: None
        session.pause = lambda seconds: None
        session.boot_intent = lambda identity: True
        with self.assertRaises(LIVE.RowFailure) as raised:
            session.set_startup_off("00000000-0000-4000-8000-000000000001")
        self.assertEqual(pressed, ["off"])
        self.assertIn("bootIntentNotApplied", str(raised.exception.args))
        self.assertEqual(session.ledger[-1]["bootIntentReported"], True)

class DetectionWindowTests(unittest.TestCase):
    """DEC-028: the window from the injection to the first sample with enforcement restored is `unknown`, at most 7 s (DEC-028 amendment: one 5 s canary poll plus up to 2 s for the check)."""
    TOLERANCE = 0.05
    INJECTED = 100.0

    @staticmethod
    def sample(offset, protection, recovered, sequence):
        return {"at": 100.0 + offset, "pid": 200, "sequence": sequence, "measuredAt": "2001-01-01T00:00:%02dZ" % (sequence - 90),
                "journalPolicy": "connected", "phase": "active", "protection": protection, "referenceCount": 1 if recovered else 0,
                "pfEnabled": recovered, "ownerPFTokenPresent": recovered, "ownerPFTokenHash": "222222222222" if recovered else None,
                "rulesDigest": "aaaaaaaaaaaa" if recovered else None, "ownerInReferences": recovered}

    def observation(self, unknown_at=3.02, recovered_at=3.6):
        base = fixture("token")["pass"]
        samples = [self.sample(0.1, "protected", False, 91)]
        if unknown_at is not None:
            samples.append(self.sample(unknown_at, "unknown", False, 92))
        if recovered_at is not None:
            samples.append(self.sample(recovered_at, "protected", True, 93))
        samples.sort(key=lambda item: item["at"])
        return {"baseline": base["baseline"], "injectedAt": self.INJECTED, "samples": samples}

    def record(self, observation, receipts=(), probes=(98.5, 110.0), end=125.0):
        record = json.loads((LAB / "tests/fixtures/blocked.json").read_text())
        receiver = record.pop("receiverRecords")
        for item in receiver[0]["receiverCoverage"]:
            item["start"], item["end"] = 90, 130
        sent = [item for item in record["observations"] if item["scope"] == "outside_tunnel"]
        record["observations"] = [{**item, "timestamp": at} for item in sent for at in probes]
        record["clockToleranceSeconds"] = self.TOLERANCE
        window = {"state": "blocked", "start": 97.0, "end": end, "requiredFamilies": ["ipv4"], "allowLAN": False}
        record["windows"] = V.GAP_ROWS.split_detection_window([window], observation, "detectionWindow", self.TOLERANCE)
        for at in receipts:
            receiver[0]["observations"].append({"timestamp": at, "nonce": record["nonce"], "kind": "received", "scope": "outside_tunnel",
                                                "family": "ipv4", "proto": "http", "address": "192.168.64.1", "port": 8088})
        return record, receiver

    def windows(self, observation, **kwargs):
        record, receiver = self.record(observation, **kwargs)
        return V.evaluate(record, TABLE, receiver)["states"]

    def test_the_catalogue_carries_the_window_and_its_bound_for_the_three_rows_and_only_those(self):
        bound = TABLE["states"]["detectionWindow"]
        self.assertEqual((bound["claim"], bound["maxSeconds"], bound["denyOutside"], bound["source"]),
                         ("unknown", 7, False, "docs/architecture.md:457"))
        for name, row in ROWS.items():
            if name in ("CRASH-TOKEN", "CRASH-PF-DISABLE", "M5.4-07"):
                self.assertEqual(row["detectionWindow"], {"state": "detectionWindow", "maxSeconds": 7, "source": "docs/architecture.md:457"})
            else:
                self.assertNotIn("detectionWindow", row, name)

    def test_the_window_ends_at_the_first_sample_with_enforcement_restored_not_at_the_unknown_report(self):
        self.assertAlmostEqual(V.GAP_ROWS.detection_end(self.observation()), 103.6)
        self.assertAlmostEqual(V.GAP_ROWS.detection_end(self.observation(unknown_at=None)), 103.6)
        # A stale recovered sample (no newer than the baseline) is not recovery evidence.
        observation = self.observation()
        observation["samples"][-1]["sequence"] = observation["baseline"]["sequence"]
        self.assertIsNone(V.GAP_ROWS.detection_end(observation))
        self.assertIsNone(V.GAP_ROWS.detection_end(self.observation(unknown_at=None, recovered_at=None)))
        self.assertIsNone(V.GAP_ROWS.detection_end(self.observation(recovered_at=None)))

    def test_windows_tile_the_run_with_the_tolerance_taken_off_the_outer_ones(self):
        record, _ = self.record(self.observation())
        self.assertEqual([(w["phase"], w["state"], round(w["start"], 3), round(w["end"], 3)) for w in record["windows"]],
                         [("pre", "blocked", 97.0, 99.95), ("detection", "detectionWindow", 100.0, 103.6), ("post", "blocked", 103.65, 125.0)])

    def test_leaks_inside_the_window_are_recorded_not_failed(self):
        windows = self.windows(self.observation(), receipts=(100.07, 100.3, 100.5))
        self.assertTrue(all(w["expectationMet"] for w in windows), windows)
        detection = next(w for w in windows if w["phase"] == "detection")
        self.assertEqual((detection["verdict"], detection["recordedOutsideObservationCount"], detection["boundSeconds"]), ("unknown", 3, 7))

    def test_a_leak_before_the_injection_or_after_the_window_fails(self):
        for at, phase in ((98.0, "pre"), (110.0, "post")):
            with self.subTest(at=at):
                windows = self.windows(self.observation(), receipts=(at,))
                self.assertEqual([w["phase"] for w in windows if not w.get("expectationMet")], [phase])

    def test_a_leak_one_tolerance_either_side_of_each_boundary_fails_only_where_it_belongs(self):
        for at, failing in ((99.99, ["pre"]), (100.01, []), (103.59, []), (103.61, ["post"])):
            with self.subTest(at=at):
                windows = self.windows(self.observation(), receipts=(at,))
                self.assertEqual([w["phase"] for w in windows if not w.get("expectationMet")], failing)

    def test_a_window_longer_than_7_s_fails_even_without_a_leak(self):
        for unknown_at, recovered_at in ((3.0, 8.0), (None, 9.0), (3.0, None), (None, None)):
            with self.subTest(unknown_at=unknown_at, recovered_at=recovered_at):
                windows = self.windows(self.observation(unknown_at, recovered_at))
                detection = next(w for w in windows if w["phase"] == "detection")
                self.assertFalse(detection["expectationMet"])
                self.assertTrue(any("longer than 7 s" in item for item in detection["missing"]), detection)

    def test_the_5_44_s_live_detection_passes_under_the_7_s_bound(self):
        windows = self.windows(self.observation(unknown_at=5.44, recovered_at=5.63))
        self.assertTrue(all(w["expectationMet"] for w in windows), windows)

    def test_a_leak_between_the_unknown_report_and_the_restored_enforcement_is_recorded_not_failed(self):
        # Live run: unknown at +1.57 s, pf back at +2.01 s, receivers saw markers at +1.85 s.
        windows = self.windows(self.observation(unknown_at=1.57, recovered_at=2.01), receipts=(101.85,))
        self.assertTrue(all(w["expectationMet"] for w in windows), windows)
        detection = next(w for w in windows if w["phase"] == "detection")
        self.assertEqual(detection["recordedOutsideObservationCount"], 1)
        windows = self.windows(self.observation(unknown_at=1.57, recovered_at=2.01), receipts=(102.3,))
        self.assertEqual([w["phase"] for w in windows if not w.get("expectationMet")], ["post"])

    def test_the_unknown_check_allows_7_s_and_rejects_more(self):
        for kind, name in (("token", "unknownWithin7s"), ("pf-disable", "unknownWithin7s")):
            for offset, met in ((5.44, True), (7.0, True), (7.5, False)):
                with self.subTest(kind=kind, offset=offset):
                    observation = fixture(kind)["pass"]
                    observation["samples"][0]["at"] = observation["injectedAt"] + offset
                    observation["samples"][1]["at"] = observation["injectedAt"] + offset + 0.5
                    checks = {c["name"]: c["met"] for c in V.row_checks(kind, observation)}
                    self.assertEqual(checks[name], met, checks)

    def test_a_window_of_exactly_the_bound_passes_and_the_post_window_still_needs_probes(self):
        self.assertTrue(all(w["expectationMet"] for w in self.windows(self.observation(unknown_at=3.0, recovered_at=7.0))))
        windows = self.windows(self.observation(), probes=(98.5,))
        self.assertEqual([w["phase"] for w in windows if not w.get("expectationMet")], ["post"])

    def test_a_reference_without_the_anchor_rules_is_not_restored(self):
        # Review item 1: pf on, one reference and a protected report are not enough; the anchor's rules must equal the baseline's.
        for digest in (None, "bbbbbbbbbbbb", ""):
            with self.subTest(digest=digest):
                observation = self.observation()
                observation["samples"][-1]["rulesDigest"] = digest
                self.assertIsNone(V.GAP_ROWS.detection_end(observation))
                checks = {c["name"]: c["met"] for c in V.row_checks("token", observation)}
                self.assertFalse(checks["enforcementRestored"], checks)
                windows = self.windows(observation)
                detection = next(w for w in windows if w["phase"] == "detection")
                self.assertFalse(detection["expectationMet"])
                self.assertTrue(any("insufficient observation" in item for item in detection["missing"]), detection)
        # A baseline without a digest has nothing to compare against.
        observation = self.observation()
        observation["baseline"]["rulesDigest"] = None
        self.assertIsNone(V.GAP_ROWS.detection_end(observation))
        self.assertFalse({c["name"]: c["met"] for c in V.row_checks("pf-disable", observation)}["ownerTelemetry"])

    def test_the_verdict_carries_the_baseline_digest_and_that_of_every_sample_counted_as_restored(self):
        # Review item 1: the evidence is in the checks themselves (so in verdict.json), and the row passes only when each equals the baseline.
        for kind in ("token", "pf-disable"):
            with self.subTest(kind=kind):
                observation = self.observation(unknown_at=1.0, recovered_at=2.0)
                observation["samples"].append(self.sample(3.0, "protected", True, 94))
                check = {c["name"]: c for c in V.row_checks(kind, observation)}["rulesDigestRestored"]
                self.assertTrue(check["met"], check)
                self.assertEqual(check["baselineRulesDigest"], "aaaaaaaaaaaa")
                self.assertEqual(check["recoveryRulesDigests"],
                                 [{"offsetSeconds": 2.0, "sequence": 93, "rulesDigest": "aaaaaaaaaaaa"},
                                  {"offsetSeconds": 3.0, "sequence": 94, "rulesDigest": "aaaaaaaaaaaa"}])
        for baseline, recovered in ((None, "aaaaaaaaaaaa"), ("aaaaaaaaaaaa", "bbbbbbbbbbbb"), ("aaaaaaaaaaaa", None), ("", "")):
            with self.subTest(baseline=baseline, recovered=recovered):
                observation = self.observation()
                observation["baseline"]["rulesDigest"] = baseline
                observation["samples"][-1]["rulesDigest"] = recovered
                check = {c["name"]: c for c in V.row_checks("token", observation)}["rulesDigestRestored"]
                self.assertFalse(check["met"], check)
        # No recovered sample: nothing to show, so the check is not met.
        check = {c["name"]: c for c in V.row_checks("token", self.observation(recovered_at=None))}["rulesDigestRestored"]
        self.assertFalse(check["met"])
        self.assertEqual(check["recoveryRulesDigests"], [])
        # The other fault kinds carry no such check.
        self.assertNotIn("rulesDigestRestored", {c["name"] for c in V.row_checks("rt22", fixture("rt22")["pass"])})

    def test_an_injection_outside_the_generator_coverage_fails(self):
        # Review item 2: injection at 100, generator end at 99.9, recovery at 103.6 saw neither the window nor post-recovery traffic.
        observation = self.observation()
        windows = self.windows(observation, end=99.9)
        detection = next(w for w in windows if w["phase"] == "detection")
        self.assertFalse(detection["expectationMet"], windows)
        self.assertTrue(any("after the generator stopped" in item for item in detection["missing"]), detection)
        # The same injection with a generator that started after it.
        late = V.GAP_ROWS.split_detection_window([{"state": "blocked", "start": 101.0, "end": 125.0, "requiredFamilies": ["ipv4"]}],
                                                 observation, "detectionWindow", self.TOLERANCE)
        detection = next(w for w in late if w["phase"] == "detection")
        self.assertIn("before the generator started", detection["shortfall"])
        # Exactly at the generator's end is outside it too; just inside is covered (and then fails for the post window instead).
        for end, shortfall in ((100.0, "after the generator stopped"), (100.5, "insufficient")):
            with self.subTest(end=end):
                detection = next(w for w in V.GAP_ROWS.split_detection_window(
                    [{"state": "blocked", "start": 97.0, "end": end, "requiredFamilies": ["ipv4"]}], observation, "detectionWindow", self.TOLERANCE)
                    if w["phase"] == "detection")
                self.assertIn(shortfall, detection["shortfall"])

    def test_restored_enforcement_with_the_baseline_rules_is_found_and_the_first_such_sample_ends_the_window(self):
        observation = self.observation(unknown_at=1.0, recovered_at=2.0)
        # Reference back at 1.5 s but no rules yet: still exposed until 2.0 s.
        observation["samples"].insert(2, {**self.sample(1.5, "protected", True, 92), "rulesDigest": None})
        observation["samples"].sort(key=lambda item: item["at"])
        self.assertAlmostEqual(V.GAP_ROWS.detection_end(observation), 102.0)

    def test_the_whole_exposure_is_measured_not_the_part_inside_the_generator_window(self):
        # Review item 2: injection at 100, generator end at 106, recovery at 108 is an 8 s exposure, not 6 s.
        for end in (106.0, 107.5):
            with self.subTest(end=end):
                windows = self.windows(self.observation(unknown_at=3.0, recovered_at=8.0), end=end)
                detection = next(w for w in windows if w["phase"] == "detection")
                self.assertEqual((detection["start"], detection["end"]), (100.0, 108.0))
                self.assertFalse(detection["expectationMet"])
                self.assertTrue(any("longer than 7 s" in item for item in detection["missing"]), detection)
                self.assertTrue(any("insufficient observation" in item for item in detection["missing"]), detection)

    def test_a_generator_that_stops_before_the_restored_sample_is_insufficient_observation_even_inside_the_bound(self):
        windows = self.windows(self.observation(unknown_at=3.0, recovered_at=6.5), end=106.0)
        detection = next(w for w in windows if w["phase"] == "detection")
        self.assertFalse(detection["expectationMet"])
        self.assertEqual([w["phase"] for w in windows], ["pre", "detection"])
        self.assertTrue(any("insufficient observation" in item for item in detection["missing"]), detection)
        windows = self.windows(self.observation(unknown_at=3.0, recovered_at=None), end=105.0)
        detection = next(w for w in windows if w["phase"] == "detection")
        self.assertFalse(detection["expectationMet"])
        self.assertTrue(any("insufficient observation" in item for item in detection["missing"]), detection)

    def test_the_driver_extension_of_the_window_end_does_not_count_as_generator_coverage(self):
        windows = [{"state": "blocked", "start": 97.0, "end": 125.0, "generatorEnd": 107.0, "requiredFamilies": ["ipv4"]}]
        split = V.GAP_ROWS.split_detection_window(windows, self.observation(unknown_at=3.0, recovered_at=6.0), "detectionWindow", self.TOLERANCE)
        detection = next(w for w in split if w["phase"] == "detection")
        self.assertIn("insufficient coverage", detection["shortfall"])
        self.assertEqual(max(w["end"] for w in split), 107.0)

    def test_less_than_5_s_of_observation_after_restoration_is_insufficient_coverage(self):
        # Review item 2: the post window may not shrink below the requirement unnoticed.
        for end, passes in ((108.5, False), (108.99, False), (109.0, True), (125.0, True)):
            with self.subTest(end=end):
                windows = self.windows(self.observation(unknown_at=3.0, recovered_at=4.0), end=end)
                detection = next(w for w in windows if w["phase"] == "detection")
                self.assertEqual(detection["expectationMet"], passes, detection)
                if not passes:
                    self.assertTrue(any("insufficient coverage" in item for item in detection["missing"]), detection)

    def test_the_guest_sample_records_a_digest_of_the_anchor_rules_and_never_the_rules(self):
        script = (GUEST / "gap-status.pl").read_text()
        self.assertIn("rulesDigest", script)
        status = json.dumps({"ownerPFToken": "123", "sequence": 5, "measuredAt": "2001-01-01T00:00:00Z", "journalPolicy": "connected",
                             "protection": "protected", "phase": "active"})
        def run(rules):
            out = subprocess.run(["perl", str(GUEST / "gap-status.pl"), "1000.5", "200", "1 x 123 3 days", "Status: Enabled", rules],
                                 input=status, capture_output=True, text=True, check=True).stdout
            return json.loads(out)
        first, second, empty = run("block drop quick all"), run("block drop quick all\npass out"), run("")
        self.assertRegex(first["rulesDigest"], r"^[a-f0-9]{12}$")
        self.assertNotEqual(first["rulesDigest"], second["rulesDigest"])
        self.assertEqual(first["rulesDigest"], run("block drop quick all")["rulesDigest"])
        self.assertIsNone(empty["rulesDigest"])
        self.assertNotIn("block", json.dumps(first))

    def test_the_guest_collector_reads_the_anchor_and_samples_until_14_s_after_the_injection(self):
        text = (GUEST / "gap-actions.sh").read_text()
        self.assertIn("pfctl -a com.apple/wgex -sr", text)
        self.assertIn('+ 14', text)

    def test_the_generator_covers_the_lead_the_bound_and_the_post_observation(self):
        text = (LAB / "verdict-live.py").read_text()
        self.assertIn("rounds = 2 * (3 + VERDICT.GAP_ROWS.DETECTION_BOUND_SECONDS + VERDICT.GAP_ROWS.POST_OBSERVATION_SECONDS + 5) if detection else 24", text)
        self.assertIn('window["generatorEnd"] = window["end"]', text)

    def test_without_a_valid_injection_time_the_generator_windows_are_left_whole(self):
        observation = self.observation()
        observation["injectedAt"] = None
        windows = [{"state": "blocked", "start": 1.0, "end": 9.0}]
        self.assertEqual(V.GAP_ROWS.split_detection_window(windows, observation, "detectionWindow", 0.05), windows)

    def test_the_driver_splits_only_rows_that_carry_the_window_and_leads_the_injection(self):
        text = (LAB / "verdict-live.py").read_text()
        self.assertIn('detection = row.get("detectionWindow")', text)
        self.assertIn("lead=3 if detection else 1", text)
        self.assertIn("split_detection_window(record[\"windows\"]", text)


if __name__ == "__main__":
    unittest.main()
