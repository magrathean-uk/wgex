# SPDX-License-Identifier: MIT
"""M1-10u: reboot and restart verdicts count only the post-restart daemon (run 8g BOOT-SECRETS false PASS).

The run 8g fixture is the scrubbed row observation of the false PASS; legacy_first_protected below is the pre-M1-10u
formula, so the first test shows the fixture reproduces the defect and the rest show the new logic rejects it. The
degenerate cases are the fixtures/restart/degenerate.json beside the other row fixtures. Never a VM."""
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import unittest

import test_run8_rows as run8

ROOT, V = run8.ROOT, run8.V
FIXTURES = ROOT / "Tools/lab/tests/fixtures/restart"
# M1-10v: the relaunch prevention BOOT-SECRETS records before the reboot (verdict.relaunch_prevented_check).
PREVENTED = dict(mechanism="loginwindow-reopen-state", userMatch=True, savesLogoutState=False, relaunchesApps=False, savedRelaunchEntries=0,
                 savedRelaunchEntriesBefore=1, savedListHeldWGEX=True, duplicateKeys=[], applied=True)
RUN_8G = json.loads((FIXTURES / "run8g-boot-secrets.json").read_text())["pass"]
CASES = json.loads((FIXTURES / "degenerate.json").read_text())["cases"]
OLD_DAEMON_LAST_PROTECTED = 1793447312.312   # pid 282, the pre-reboot daemon's shutdown-time line
NEW_DAEMON_FIRST_PROTECTED = 1793447404.498  # pid 336, after its first attempt failed at configureInterface


def legacy_first_protected(boot):
    """The pre-M1-10u formula: every status line since boot, and every poll, from any daemon."""
    protected = [item[0] for item in boot.get("timeline", []) + boot.get("statusSamples", []) if item[2] == "protected"]
    return min(protected) if protected else None


def legacy_held(boot):
    first, app = legacy_first_protected(boot), boot.get("appStartedAt")
    return first is not None and (boot.get("appRunningAfterBoot") is False or (app is not None and first < app))


def without_pids(observation):
    value = copy.deepcopy(observation)
    value["boot"].pop("daemonPid", None)
    value["boot"]["timeline"] = [item[:3] for item in value["boot"]["timeline"]]
    return value


def checks_by_name(kind, observation):
    return {check["name"]: check for check in V.row_checks(kind, observation)}


class Run8gFalsePassTests(unittest.TestCase):
    def test_the_fixture_reproduces_the_defect_under_the_legacy_formula(self):
        boot = RUN_8G["boot"]
        self.assertEqual(legacy_first_protected(boot), OLD_DAEMON_LAST_PROTECTED)
        self.assertTrue(legacy_held(boot), "the old logic passed daemonSecretsBeforeApp")
        # The impossibility the report names: "first protected" earlier than the only daemon's own start.
        self.assertLess(OLD_DAEMON_LAST_PROTECTED, boot["daemonStartedAt"])

    def test_only_the_post_restart_daemon_counts_and_the_excluded_line_is_an_observation(self):
        for label, observation in (("with pids", RUN_8G), ("stored capture shape, no pids", without_pids(RUN_8G))):
            with self.subTest(label):
                view = V.restart_timeline(observation["boot"])
                self.assertEqual(view["diagnostics"], [])
                self.assertEqual(view["observations"]["excludedPreRestartStatusLines"], 1)
                self.assertEqual(len(view["lines"]), len(observation["boot"]["timeline"]) - 1)
                self.assertEqual(min(item[0] for item in view["lines"]), 1793447332.341)
                report = V.boot_report(observation["boot"])
                self.assertEqual(report["firstProtectedAt"], NEW_DAEMON_FIRST_PROTECTED)
                self.assertEqual(report["postRestartTimeline"]["excludedPreRestartStatusLines"], 1)
                self.assertTrue(report["postRestartTimelineConsistent"])
                self.assertFalse(report["protectedBeforeAppSeen"])
                self.assertIsNone(report["daemonDrivenReconnect"], "timing only: causation not measured")

    def test_run8g_is_not_a_pass_it_carries_protectedonlyafterappseen_with_both_times_and_the_delta(self):
        for label, observation in (("with pids", RUN_8G), ("stored capture shape, no pids", without_pids(RUN_8G))):
            with self.subTest(label):
                checks = checks_by_name("boot-secrets", observation)
                held = checks["daemonSecretsBeforeApp"]
                self.assertFalse(held["met"])
                self.assertEqual(held["firstProtectedAt"], NEW_DAEMON_FIRST_PROTECTED)
                self.assertEqual(held["appStartedAt"], 1793447332.938)
                value = held["protectedOnlyAfterAppSeen"]
                self.assertEqual((value["firstProtectedAt"], value["appStartedAt"], value["deltaSeconds"]),
                                 (NEW_DAEMON_FIRST_PROTECTED, 1793447332.938, 71.56))
                self.assertTrue(held["gap"].startswith("protectedOnlyAfterAppSeen: "), held["gap"])
                self.assertIn("1793447404.498", held["gap"])
                self.assertIn("1793447332.938", held["gap"])
                self.assertIn("71.56 s", held["gap"])
                self.assertFalse(all(check["met"] for check in checks.values()), "the row is not a PASS")
                # What really happened stays visible: protected from 04:50:04.5, one reference, never `unprotected`.
                self.assertTrue(checks["protectedAfterBoot"]["met"])
                self.assertTrue(checks["postRestartTimelineConsistent"]["met"])
                self.assertTrue(checks["neverUnprotectedAfterBoot"]["met"])

    def test_failed_and_unknown_samples_are_measured_and_never_counted_as_protected(self):
        checks = checks_by_name("boot-secrets", RUN_8G)
        unprotected = checks["neverUnprotectedAfterBoot"]
        timeline = V.restart_timeline(RUN_8G["boot"])["lines"]
        polls = RUN_8G["boot"]["statusSamples"]
        self.assertEqual(unprotected["unprotectedCount"], 0)
        self.assertEqual(unprotected["statusCount"], len(timeline) + len(polls))
        self.assertEqual(unprotected["unknownProtectionCount"], 3)   # idle/unknown at start, failed/unknown twice
        self.assertEqual(unprotected["failedPhaseCount"], 3)         # failed/unknown twice, failed/blocked
        self.assertEqual(unprotected["excludedPreRestartStatusLines"], 1)
        window = checks["zeroReceiptsBeforeFirstStatus"]["window"]
        self.assertEqual(window["daemonFirstStatusAt"], 1793447312.312, "the stored window predates the fix; the live driver now passes the post-restart lines")
        recomputed = V.never_open_window(window["start"], window["end"], V.restart_timeline(RUN_8G["boot"])["lines"], strict=False,
                                         probed_from=window["probedFrom"])
        self.assertEqual(recomputed["daemonFirstStatusAt"], 1793447332.341)
        self.assertEqual((recomputed["unknownProtectionSamples"], recomputed["failedPhaseSamples"]), (2, 3))
        # Unknown is not protected: a timeline whose only protected line is a failed/unknown one yields no first protected.
        boot = copy.deepcopy(RUN_8G["boot"])
        boot["timeline"] = [item for item in boot["timeline"] if item[2] != "protected"]
        boot["statusSamples"] = []
        self.assertIsNone(V.boot_report(boot)["firstProtectedAt"])

    def test_early_boot_capture_dates_enforcement_from_the_post_restart_daemon(self):
        early = V.boot_report(RUN_8G["boot"])["earlyBootCapture"]
        self.assertEqual(early["firstEnforcingStatusAt"], 1793447333.396)
        self.assertEqual(early["unenforcedSeconds"], 22.396, "not the 1.312 s the old daemon's line gave")


class DegenerateTimelineTests(unittest.TestCase):
    def test_every_degenerate_case_matches_its_expectation(self):
        for case in CASES:
            with self.subTest(case["name"]):
                boot, expect = case["boot"], case["expect"]
                view = V.restart_timeline(boot)
                self.assertEqual(sorted({name for name, _ in view["diagnostics"]}), sorted(expect["diagnostics"]), view["diagnostics"])
                self.assertEqual((len(view["lines"]), len(view["excluded"])), (expect["counted"], expect["excluded"]))
                report = V.boot_report(boot)
                self.assertEqual(report["postRestartTimelineConsistent"], expect["consistent"])
                for key in ("firstProtectedAt", "timelineAvailable"):
                    if key in expect:
                        self.assertEqual(report[key], expect[key], key)
                if "samePidLinesBeforeStart" in expect:
                    self.assertEqual(view["observations"]["samePidLinesBeforeStart"], expect["samePidLinesBeforeStart"])
                # An inconsistent timeline is never daemon-driven and never a pass on any boot row.
                if not expect["consistent"]:
                    self.assertIsNone(report["daemonDrivenReconnect"])
                    self.assertFalse(V.timeline_consistency_check(boot)["met"])
                    self.assertTrue(V.timeline_consistency_check(boot)["gap"].startswith("postRestartTimelineInconsistent: "))
                    for kind, extra in (("reboot-lockdown", dict(lockdownBeforeReboot=True, allowLANBeforeReboot=False,
                                                                 statusBeforeReboot=dict(phase="idle", protection="blocked"))),
                                        ("boot-secrets", dict(bootIntentBeforeReboot=True))):
                        observation = dict(extra, boot=boot)
                        checks = checks_by_name(kind, observation)
                        self.assertFalse(checks["postRestartTimelineConsistent"]["met"], kind)
                        if kind == "boot-secrets":
                            self.assertFalse(checks["daemonSecretsBeforeApp"]["met"])
                            self.assertTrue(checks["daemonSecretsBeforeApp"]["gap"].startswith("timelineInconsistent: "))

    def test_an_empty_timeline_stays_unknown_with_the_boot_timeline_gap(self):
        case = next(case for case in CASES if case["name"] == "empty timeline")
        report = V.boot_report(case["boot"])
        self.assertFalse(report["timelineAvailable"])
        self.assertEqual(report["gap"], V.BOOT_TIMELINE_GAP)
        self.assertIsNot(report["daemonDrivenReconnect"], False)
        observation = dict(bootIntentBeforeReboot=True, boot=case["boot"])
        self.assertFalse(checks_by_name("boot-secrets", observation)["neverUnprotectedAfterBoot"]["met"])

    def test_a_row_with_no_restart_counts_every_line_as_before(self):
        case = next(case for case in CASES if case["name"] == "no restart")
        boot = case["boot"]
        view = V.restart_timeline(boot)
        self.assertEqual(view["lines"], boot["timeline"])
        self.assertEqual(view["observations"]["excludedPreRestartStatusLines"], 0)
        self.assertEqual(V.boot_report(boot)["firstProtectedAt"], legacy_first_protected(boot))
        self.assertTrue(V.boot_report(boot)["protectedBeforeAppSeen"])
        self.assertIsNone(V.boot_report(boot)["daemonDrivenReconnect"])
        # M1-10v fix pass 1: both boot samples read, the last after the first protected status, no app log line (the no-app window).
        window = dict(bootObserveSamples=2, bootObservePlanned=2, appLogLinesSamples=[0, 0],
                      lastBootSampleAt=max(item[0] for item in boot["timeline"] + boot.get("statusSamples", [])) + 30)
        observation = dict(bootIntentBeforeReboot=True, boot=dict(boot, **window), relaunchPrevention=PREVENTED)
        self.assertTrue(all(check["met"] for check in V.row_checks("boot-secrets", observation)))

    def test_the_committed_row_fixtures_are_unchanged_by_the_filter(self):
        for name, kind in (("boot-secrets", "boot-secrets"), ("reboot-lockdown", "reboot-lockdown")):
            observation = json.loads((ROOT / "Tools/lab/tests/fixtures/rows" / (name + ".json")).read_text())["pass"]
            view = V.restart_timeline(observation["boot"])
            with self.subTest(name):
                self.assertEqual(view["lines"], observation["boot"]["timeline"])
                self.assertEqual(view["diagnostics"], [])
                measured = [check for check in V.row_checks(kind, observation) if check.get("measured") is not False]
                self.assertTrue(all(check["met"] for check in measured))

    def test_a_driver_poll_before_the_daemon_started_is_inconsistent(self):
        boot = copy.deepcopy(next(case for case in CASES if case["name"] == "no restart")["boot"])
        boot["statusSamples"] = [[boot["daemonStartedAt"] - 5, "active", "protected"]]
        names = [name for name, _ in V.restart_timeline(boot)["diagnostics"]]
        self.assertEqual(names, ["firstProtectedBeforeDaemonStart"])


class GuestShapeTests(unittest.TestCase):
    SCRIPT = (ROOT / "Tools/lab/tart/guest/verdict-actions.sh").read_text()
    LOG = ("Timestamp               Ty Process[PID:TID]\n"
           "2026-10-31 04:48:32.312 Df WGEXDaemon[282:156d] [com.magrathean.WGEXApp.lab:daemon] status: phase=active protection=protected reason=none\n"
           "2026-10-31 04:48:51.342 A  WGEXDaemon[336:710] (libsystem_info.dylib) Retrieve User by ID\n"
           "2026-10-31 04:48:52.341 Df WGEXDaemon[336:86a] [com.magrathean.WGEXApp.lab:daemon] status: phase=idle protection=unknown reason=none\n"
           "2026-10-31 04:49:59.033 Df WGEXDaemon[336:86a] [com.magrathean.WGEXApp.lab:daemon] status: phase=failed protection=unknown reason=backendUnavailable\n")

    def test_the_guest_filter_writes_each_status_line_with_its_pid_and_nothing_else(self):
        block = self.SCRIPT[self.SCRIPT.index("  boot-observe)"):self.SCRIPT.index("  anchor-rules)")]
        program = re.search(r"perl -ne '([^']+)'", block)[1]
        out = subprocess.run(["perl", "-ne", program], input=self.LOG, capture_output=True, text=True, check=True).stdout.splitlines()
        self.assertEqual(out, ["2026-10-31 04:48:32.312 status: phase=active protection=protected reason=none pid=282",
                               "2026-10-31 04:48:52.341 status: phase=idle protection=unknown reason=none pid=336",
                               "2026-10-31 04:49:59.033 status: phase=failed protection=unknown reason=backendUnavailable pid=336",
                               "statuslinesdropped=0"])
        self.assertIn("daemonpid=%s", block)

    def test_the_parser_reads_the_pid_header_and_per_line_pids(self):
        text = ("now=1793447430.500\ntz=-0700\nboot=1793447311\napp=01:35\ndaemon=01:42\ndaemonpid=336\nruns=1\n__TIMELINE__\n"
                "2026-10-31 04:48:32.312 status: phase=active protection=protected reason=none pid=282\n"
                "2026-10-31 04:48:52.341 status: phase=idle protection=unknown reason=none\n")
        value = V.parse_boot_observe(text)
        self.assertEqual(value["daemonPid"], 336)
        self.assertEqual([item[3] for item in value["timeline"]], [282, None])
        self.assertEqual([item[4] for item in value["timeline"]], [0, 1], "the position in the log is kept")
        self.assertEqual(value["timeline"][0][3], 282)
        self.assertIsNone(V.parse_boot_observe(text.replace("daemonpid=336\n", ""))["daemonPid"])
        self.assertIsNone(V.parse_boot_observe(text.replace("daemonpid=336", "daemonpid=0"))["daemonPid"])


class LiveDriverTests(unittest.TestCase):
    """The live driver through the recorded runner: the previous daemon's pid 282 line is in the log since boot."""

    def test_boot_secrets_excludes_the_previous_daemons_line_and_records_it(self):
        runner = run8.BootSecretsTests().runner()
        _, result = run8.run_row("BOOT-SECRETS", runner)
        observation = result["bootObservation"]
        self.assertEqual(observation["postRestartTimeline"]["excludedPreRestartStatusLines"], 1)
        self.assertEqual(observation["postRestartTimeline"]["postRestartDaemonPid"], 336)
        self.assertEqual(observation["postRestartTimeline"]["diagnostics"], [])
        self.assertTrue(run8.check(result, "postRestartTimelineConsistent")["met"])
        self.assertTrue(run8.check(result, "daemonSecretsBeforeApp")["met"])
        stored = json.loads((Path(result["buildRoot"]) / "row-observation.json").read_text())["boot"]
        self.assertEqual((stored["daemonPid"], stored["daemonPidSamples"]), (336, [336, 336]))
        self.assertEqual(stored["timeline"][0][3], 282, "the raw timeline is kept; the verdict filters it")

    def test_reboot_intent_carries_the_consistency_check(self):
        _, result = run8.run_row("REBOOT-INTENT")
        self.assertTrue(run8.check(result, "postRestartTimelineConsistent")["met"])
        self.assertEqual(result["bootObservation"]["postRestartTimeline"]["excludedPreRestartStatusLines"], 1)


if __name__ == "__main__":
    unittest.main()
