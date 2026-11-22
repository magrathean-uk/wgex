# SPDX-License-Identifier: MIT
"""M1-10u fix pass 1: the post-restart timeline fails closed on clock steps, unattributed lines and replaced daemons.

Every case here is a verifier probe (VERIFY A L1-L3, VERIFY B M1-M4, L1-L3, N1) that the M1-10u verdict logic passed or judged
by time alone; each test fails on lab-track 25b6b1d and passes after the fix. The probes are rebuilt from the verifier
reports as raw boot-observe text (so the parser and the live driver's merge run too), never from a guest. Never a VM."""
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import types
import unittest

import test_run8_rows as run8
import test_restart_timeline as restart

ROOT, V, LIVE = run8.ROOT, run8.V, run8.LIVE
FIXTURES = ROOT / "Tools/lab/tests/fixtures/restart"
SCRIPT = (ROOT / "Tools/lab/tart/guest/verdict-actions.sh").read_text()
D = 1793500000.0   # the post-restart daemon's start; the probes are offsets from it


def observe_loop():
    """The per-process loop of the guest's boot-observe action, verbatim."""
    start = SCRIPT.index("    for name in WGEX WGEXDaemon; do")
    end = SCRIPT.find("    # M1-10v fix pass 1 (VERIFY B M1)", start)   # the app-log count that follows the loop is tested in test_reboot_followups
    return SCRIPT[start:end if end >= 0 else SCRIPT.index("    plists=(", start)]


def stamp(epoch):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(epoch)) + f".{int(round((epoch % 1) * 1000)):03d}"


def etime(seconds):
    return f"{int(seconds) // 60:02d}:{int(seconds) % 60:02d}"


def observe(lines, *, pid=336, daemon=60, app=56, now=D + 60, runs=1, head=(), tail=(), applog=0):
    """Raw boot-observe text: `lines` are (epoch, phase, protection, pid) in LOG order. The daemon started at now - daemon and the
    app at now - app, so the earliest-possible starts are D-1 and D+3 by default."""
    out = [f"now={now:.3f}", "tz=+0000", f"boot={int(D - 30)}", f"app={etime(app) if app else 'none'}",
           f"daemon={etime(daemon) if daemon else 'none'}", *head]
    if pid and daemon:
        out.append(f"daemonpid={pid}")
    if applog is not None:   # M1-10v fix pass 1: the guest's count of the app's own unified-log lines since the daemon's start
        out.append(f"appLogLines={applog}")
    out += [f"runs={runs}", "__TIMELINE__"]
    for epoch, phase, protection, line_pid in lines:
        out.append(f"{stamp(epoch)} status: phase={phase} protection={protection} reason=none" + (f" pid={line_pid}" if line_pid else ""))
    return "\n".join(out + list(tail)) + "\n"


def summary(*texts, pre=None, polls=(), clock=None):
    """The live driver's merge (Session.boot_summary) of one or more boot-observe samples."""
    # M1-10v fix pass 1: the row takes two boot samples (at SSH return and after protection was restored) and the relaunch check needs
    # both, so one text stands for both; pass two texts (or None for a lost sample) to say otherwise.
    texts = texts * 2 if len(texts) == 1 else texts
    samples = [V.parse_boot_observe(text) if text is not None else None for text in texts]
    if clock:
        for sample in filter(None, samples):
            sample.update(clock)
    fake = types.SimpleNamespace(sample_log=[list(item) for item in polls], pre_restart_daemon_pid=pre)
    return LIVE.Session.boot_summary(fake, samples, dict(phase="active", protection="protected")) | dict(referenceCount=1, outsideReceiptsBeforeFirstStatus=0)


def names(boot):
    return [name for name, _ in V.restart_timeline(boot)["diagnostics"]]


# M1-10v: BOOT-SECRETS records the relaunch prevention it applied before the reboot; every observation built here carries it, so a
# passing timeline is a pass through the whole check list (the relaunchPrevented check has its own tests in test_reboot_followups).
PREVENTED = dict(mechanism="loginwindow-reopen-state", userMatch=True, savesLogoutState=False, relaunchesApps=False, savedRelaunchEntries=0,
                 savedRelaunchEntriesBefore=1, savedListHeldWGEX=True, duplicateKeys=[], applied=True)


def secrets(boot):
    return {check["name"]: check for check in V.row_checks("boot-secrets", dict(bootIntentBeforeReboot=True, relaunchPrevention=PREVENTED, boot=boot))}


def passes(boot):
    return all(check["met"] for check in secrets(boot).values())


def clean_lines(pid=336):
    return [(D + 1, "idle", "unknown", pid), (D + 2, "idle", "blocked", pid), (D + 3, "preparing", "blocked", pid),
            (D + 4, "configuring", "blocked", pid), (D + 5, "active", "protected", pid)]


class ControlTests(unittest.TestCase):
    def test_a_clean_single_daemon_timeline_is_a_pass_through_the_whole_chain(self):
        boot = summary(observe(clean_lines(), app=None, tail=()))
        self.assertEqual(names(boot), [])
        self.assertTrue(passes(boot), secrets(boot))


class ClockStepTests(unittest.TestCase):
    A1 = [(D + 1, "idle", "unknown", 336), (D + 2, "idle", "blocked", 336), (D + 6, "preparing", "blocked", 336),
          (D + 8, "configuring", "blocked", 336), (D + 2.5, "active", "protected", 336)]   # stepped back 8 s at D+9, real D+10.5
    A1B = [(D + 1, "idle", "unknown", 336), (D + 2, "idle", "blocked", 336), (D + 3, "preparing", "blocked", 336),
           (D + 4, "configuring", "blocked", 336), (D - 2, "active", "protected", 336)]    # the step lands within 7 s of the start

    def test_a1_a_step_back_after_the_start_is_not_a_pass_and_names_clockStepped(self):
        boot = summary(observe(self.A1))
        self.assertEqual(boot["appStartedAt"], D + 3)
        self.assertIn("clockStepped", names(boot))
        checks = secrets(boot)
        self.assertFalse(checks["postRestartTimelineConsistent"]["met"])
        self.assertIn("clockStepped", checks["postRestartTimelineConsistent"]["gap"])
        self.assertFalse(passes(boot))
        self.assertFalse(checks["daemonSecretsBeforeApp"]["met"])
        self.assertIsNone(V.boot_report(boot)["daemonDrivenReconnect"])

    def test_a1_keeps_the_raw_log_order_through_parsing(self):
        value = V.parse_boot_observe(observe(self.A1))
        self.assertEqual([item[4] for item in value["timeline"]], [0, 1, 4, 2, 3], "sorted by stamp, each item keeps its log index")
        self.assertEqual([item[0] for item in sorted(value["timeline"], key=lambda item: item[4])], [D + 1, D + 2, D + 6, D + 8, D + 2.5])

    def test_a1_as_a_stored_capture_without_the_log_index_still_fails_on_the_impossible_attempt_order(self):
        boot = summary(observe(self.A1))
        boot["timeline"] = [item[:4] for item in boot["timeline"]]   # the stored shape: sorted, no log index
        found = names(boot)
        self.assertNotIn("clockStepped", found)
        self.assertEqual(found, ["activeBeforeAttemptSteps"])
        self.assertFalse(passes(boot))
        self.assertFalse(V.restart_timeline(boot)["observations"]["logOrderRecorded"])

    def test_a1b_a_step_landing_near_the_start_still_fails_closed_and_also_names_the_step(self):
        boot = summary(observe(self.A1B))
        found = names(boot)
        self.assertIn("postRestartLineBeforeDaemonStart", found)
        self.assertIn("clockStepped", found)
        self.assertFalse(passes(boot))

    def test_a_pid_less_line_group_is_checked_in_log_order_too(self):
        boot = summary(observe([(D + 1, "idle", "unknown", None), (D + 6, "preparing", "blocked", None), (D + 2.5, "active", "protected", None)],
                               pid=None, daemon=0, head=()))
        boot["daemonStartedAt"], boot["daemonPid"] = D - 1, None
        self.assertIn("clockStepped", names(boot))

    def test_log_order_inversions_of_another_daemon_are_not_this_daemons_step(self):
        lines = [(D - 20, "active", "protected", 282), (D - 25, "idle", "blocked", 282)] + clean_lines()
        self.assertNotIn("clockStepped", names(summary(observe(lines))))

    def test_a_guest_stamp_that_drifts_from_host_time_plus_offset_is_named_clockDrift(self):
        base = dict(sampledAt=D + 60, hostStartedAt=D + 60 - 0.2, hostReturnedAt=D + 61, offsetSeconds=0.0, uncertaintySeconds=0.05)
        for label, edit, expected in (("within the uncertainty plus 0.5 s", dict(sampledAt=D + 60 - 0.5), []),
                                      ("guest 9 s behind host plus offset", dict(sampledAt=D + 51), ["clockDrift"]),
                                      ("guest far ahead of the whole call", dict(sampledAt=D + 70), ["clockDrift"])):
            with self.subTest(label):
                boot = summary(observe(clean_lines(), app=None))
                boot["clockSamples"] = [dict(base, **edit)]
                self.assertEqual(names(boot), expected)
                self.assertEqual(V.restart_timeline(boot)["observations"]["clockDrift"]["measured"], True)

    def test_the_offset_changing_between_the_boot_samples_is_named_clockDrift(self):
        boot = summary(observe(clean_lines(), app=None))
        sample = dict(sampledAt=D + 60, hostStartedAt=D + 59.9, hostReturnedAt=D + 60.5, uncertaintySeconds=0.05)
        boot["clockSamples"] = [dict(sample, offsetSeconds=-7.7), dict(sample, offsetSeconds=0.3)]
        self.assertTrue(any("offset" in text for name, text in V.restart_timeline(boot)["diagnostics"] if name == "clockDrift"))

    def test_a_stored_capture_without_host_stamps_says_clock_drift_not_measured_and_never_passes_silently(self):
        boot = summary(observe(clean_lines(), app=None))
        boot.pop("clockSamples", None)
        view = V.restart_timeline(boot)
        self.assertEqual(view["diagnostics"], [])
        self.assertEqual(view["observations"]["clockDrift"], dict(measured=False, note="clock drift not measured"))
        check = V.timeline_consistency_check(boot)
        self.assertTrue(check["met"])
        self.assertEqual(check["clockDrift"]["note"], "clock drift not measured")
        self.assertEqual(V.boot_report(boot)["postRestartTimeline"]["clockDrift"]["note"], "clock drift not measured")

    def test_the_live_driver_records_host_stamps_and_samples_the_offset_at_both_ends_of_the_boot_phase(self):
        runner = run8.BootSecretsTests().runner()
        _, result = run8.run_row("BOOT-SECRETS", runner)
        stored = json.loads((Path(result["buildRoot"]) / "row-observation.json").read_text())["boot"]
        self.assertEqual(len(stored["clockSamples"]), 2)
        for sample in stored["clockSamples"]:
            self.assertLessEqual(sample["hostStartedAt"], sample["hostReturnedAt"])
            self.assertIn("offsetSeconds", sample)
            self.assertIn("uncertaintySeconds", sample)
        self.assertEqual(result["bootObservation"]["postRestartTimeline"]["clockDrift"]["measured"], True)
        lines = run8.commands(runner)
        boot = [i for i, c in enumerate(lines) if "verdict-actions.sh boot-observe" in c]
        clocks = [i for i, c in enumerate(lines) if "ssh --clock" in c]
        self.assertTrue(any(boot[0] < i < boot[1] for i in clocks), "offset sampled after the first boot sample")
        self.assertTrue(any(i > boot[1] for i in clocks), "and again after the last one, at the end of the boot phase")

    def test_a_guest_clock_far_from_host_time_plus_offset_fails_the_row_in_the_live_driver(self):
        runner = run8.BootSecretsTests().runner()
        runner.skew = -9.0
        _, result = run8.run_row("BOOT-SECRETS", runner, accepted=False)
        self.assertIn("clockDrift", result["bootObservation"]["postRestartTimeline"]["diagnostics"])
        self.assertFalse(run8.check(result, "postRestartTimelineConsistent")["met"])
        self.assertFalse(result["rowCompleted"])


class UnattributedLineTests(unittest.TestCase):
    def a5(self):
        lines = [(D + 1, "idle", "unknown", 336), (D + 2, "idle", "blocked", 336), (D + 0.5, "active", "protected", None)]
        return sorted(lines, key=lambda item: item[0]) + [(D + 3, "preparing", "blocked", 336)]

    def test_a5_one_line_without_a_pid_while_the_pid_is_known_is_a_named_failure(self):
        boot = summary(observe(self.a5()))
        self.assertIn("postRestartLineUnattributed", names(boot))
        self.assertFalse(passes(boot))
        self.assertIn("postRestartLineUnattributed", secrets(boot)["postRestartTimelineConsistent"]["gap"])

    def test_a6_no_line_carries_a_pid_while_the_pid_is_known_is_the_same_failure_not_a_fallback(self):
        boot = summary(observe([(t, p, q, None) for t, p, q, _ in clean_lines()]))
        self.assertEqual(boot["daemonPid"], 336)
        self.assertIn("postRestartLineUnattributed", names(boot))
        self.assertFalse(passes(boot))

    def test_a_stored_capture_with_no_recorded_daemon_pid_is_not_affected(self):
        boot = summary(observe([(t, p, q, None) for t, p, q, _ in clean_lines()], pid=None, daemon=0))
        boot["daemonStartedAt"], boot["daemonPid"] = D - 1, None
        self.assertEqual(names(boot), [])

    def test_an_unattributed_line_before_the_start_is_named_too_not_excluded_silently(self):
        boot = summary(observe([(D - 4.2, "active", "unprotected", None)] + clean_lines()))
        self.assertIn("postRestartLineUnattributed", names(boot))


class ReplacedDaemonTests(unittest.TestCase):
    A4 = [(D - 20, "active", "protected", 282), (D + 1, "idle", "unknown", 336), (D + 3, "active", "unprotected", 336),
          (D + 11, "idle", "blocked", 401), (D + 12, "preparing", "blocked", 401), (D + 13, "configuring", "blocked", 401),
          (D + 14, "active", "protected", 401)]

    def boot(self, runs=2, pre=282):
        # pgrep -o after the restart sees only pid 401 (started D+10, etime 50 s) in both samples.
        text = observe(self.A4, pid=401, daemon=50, app=None, runs=runs)
        return summary(text, text, pre=pre)

    def test_a4_a_replaced_daemon_is_named_postRestartDaemonReplaced_with_the_recorded_pre_restart_pid(self):
        boot = self.boot()
        self.assertEqual(boot["preRestartDaemonPid"], 282)
        self.assertEqual(V.restart_timeline(boot)["observations"]["excludedPids"], [282, 336])
        self.assertIn("postRestartDaemonReplaced", names(boot))
        detail = dict(V.restart_timeline(boot)["diagnostics"])["postRestartDaemonReplaced"]
        self.assertIn("336", detail)
        self.assertNotIn("282", detail.split("pre-restart")[0])

    def test_a4r_with_a_launchd_runs_count_that_misreports_one_the_row_is_still_not_a_pass(self):
        boot = self.boot(runs=1)
        self.assertEqual(boot["daemonRuns"], 1)
        self.assertIn("postRestartDaemonReplaced", names(boot))
        self.assertFalse(passes(boot))
        self.assertFalse(secrets(boot)["postRestartTimelineConsistent"]["met"])

    def test_a_stored_capture_without_the_pre_restart_pid_fails_when_more_than_one_pid_is_excluded(self):
        boot = self.boot(pre=None)
        self.assertIsNone(boot["preRestartDaemonPid"])
        found = dict(V.restart_timeline(boot)["diagnostics"])
        self.assertIn("postRestartDaemonReplaced", found)
        self.assertIn("not recorded", found["postRestartDaemonReplaced"])

    def test_a_single_excluded_pid_the_recorded_previous_daemon_is_not_a_failure(self):
        text = observe([(D - 20, "active", "protected", 282)] + clean_lines())
        boot = summary(text, text, pre=282)
        self.assertEqual(names(boot), [])
        self.assertEqual(names(dict(boot, preRestartDaemonPid=None)), [], "one excluded pid, pre-restart pid not recorded: still fine")

    def test_a_recorded_pre_restart_pid_that_is_not_the_excluded_one_names_the_excluded_pid(self):
        text = observe([(D - 20, "active", "protected", 282)] + clean_lines())
        boot = summary(text, text, pre=999)
        self.assertIn("postRestartDaemonReplaced", names(boot))

    def test_reboot_intent_carries_the_launchd_runs_check_and_the_replaced_daemon_failure(self):
        boot = self.boot(runs=2)
        checks = {check["name"]: check for check in V.reboot_intent_checks(boot)}
        self.assertEqual(sorted(checks), ["noRestartLoop", "postRestartTimelineConsistent"])
        self.assertFalse(checks["noRestartLoop"]["met"])
        self.assertFalse(checks["postRestartTimelineConsistent"]["met"])
        ok = summary(observe(clean_lines(), app=None))
        self.assertTrue(all(check["met"] for check in V.reboot_intent_checks(ok)))

    def test_the_live_driver_records_the_pre_restart_pid_before_the_reboot_and_reboot_intent_fails_on_a_replacement(self):
        runner = run8.Run8Runner()
        _, result = run8.run_row("REBOOT-INTENT", runner)
        lines = run8.commands(runner)
        pid = next(i for i, c in enumerate(lines) if c.endswith("verdict-actions.sh daemon-pid"))
        reboot = next(i for i, c in enumerate(lines) if c.endswith("verdict-actions.sh reboot"))
        self.assertLess(pid, reboot)
        self.assertEqual(result["bootObservation"]["postRestartTimeline"]["preRestartDaemonPid"], 282)
        self.assertTrue(run8.check(result, "noRestartLoop")["met"])
        runner = run8.Run8Runner()
        runner.replaced_pid = 401
        _, result = run8.run_row("REBOOT-INTENT", runner, accepted=False)
        self.assertIn("postRestartDaemonReplaced", result["bootObservation"]["postRestartTimeline"]["diagnostics"])
        self.assertFalse(run8.check(result, "postRestartTimelineConsistent")["met"])
        runner = run8.Run8Runner()
        runner.daemon_runs = 2
        _, result = run8.run_row("REBOOT-INTENT", runner, accepted=False)
        self.assertFalse(run8.check(result, "noRestartLoop")["met"])
        self.assertTrue(any(gap.startswith("noRestartLoop:") for gap in result["gaps"]), result["gaps"])


class StartUnknownTests(unittest.TestCase):
    LINES = [(D - 20, "active", "protected", 282)] + clean_lines()

    def test_b4_a_daemon_whose_etime_never_parsed_is_named_postRestartDaemonStartUnknown(self):
        text = observe(self.LINES, pid=None, daemon=0, app=None, head=("daemonstart=unknown",))
        boot = summary(text, text)
        self.assertIsNone(boot["daemonPid"])
        self.assertIsNone(boot["daemonStartedAt"])
        found = names(boot)
        self.assertIn("postRestartDaemonStartUnknown", found)
        self.assertNotIn("pidSetContradictsRestart", found)
        self.assertNotIn("postRestartDaemonUnidentified", found)
        self.assertFalse(passes(boot))

    def test_b4_with_a_known_pid_and_an_unknown_start_does_not_blame_the_pid_set(self):
        boot = summary(observe(self.LINES))
        boot["daemonStartedAt"] = None
        found = names(boot)
        self.assertEqual(found, ["postRestartDaemonStartUnknown"])

    def test_the_guest_prints_daemonpid_only_when_etime_parsed_for_that_pid(self):
        loop = observe_loop()
        def run(stub):
            program = "set -euo pipefail\n" + stub + "\n" + loop
            return subprocess.run(["bash", "-c", program], capture_output=True, text=True, env=dict(os.environ, LC_ALL="C", TZ="UTC")).stdout
        pgrep = 'pgrep() { case "$*" in *WGEXDaemon*) echo 336 ;; *) echo 512 ;; esac; }\n'
        ok = run(pgrep + 'ps() { case "$*" in *etime*) echo "  01:05" ;; *lstart*) echo "Sat Oct 31 04:49:31 2026" ;; esac; }')
        self.assertIn("daemon=01:05\n", ok)
        self.assertIn("daemonpid=336\n", ok)
        self.assertNotIn("daemonstart", ok)
        dying = run(pgrep + 'ps() { return 1; }')
        self.assertIn("daemon=none\n", dying)
        self.assertNotIn("daemonpid", dying, "ps failed on that pid: no pid is printed")
        self.assertIn("daemonstart=unknown\n", dying)
        absent = run('pgrep() { return 1; }\nps() { return 1; }')
        self.assertNotIn("daemonpid", absent)
        self.assertNotIn("daemonstart", absent, "no daemon at all is not an unknown start")

    def test_the_guest_prints_the_app_ps_lstart_as_an_epoch_when_it_parses(self):
        loop = observe_loop()
        stub = ('pgrep() { echo 512; }\nps() { case "$*" in *etime*) echo "01:05" ;; *lstart*) echo "Sat Oct  3 04:49:31 2026" ;; esac; }\n')
        out = subprocess.run(["bash", "-c", "set -euo pipefail\n" + stub + loop], capture_output=True, text=True,
                             env=dict(os.environ, LC_ALL="C", TZ="UTC")).stdout
        self.assertIn("applstart=1791002971\n", out)   # 2026-10-03 04:49:31 UTC
        broken = subprocess.run(["bash", "-c", "set -euo pipefail\n" + stub.replace("Sat Oct  3 04:49:31 2026", "garbage") + loop],
                                capture_output=True, text=True, env=dict(os.environ, LC_ALL="C", TZ="UTC")).stdout
        self.assertNotIn("applstart", broken)
        value = V.parse_boot_observe("now=1793447430.5\ntz=+0000\nboot=1793447311\napp=01:35\napplstart=1793447334\ndaemon=01:42\ndaemonpid=336\nruns=1\n__TIMELINE__\n")
        self.assertEqual(value["appStartedAtPs"], 1793447334.0)
        self.assertIsNone(V.parse_boot_observe("now=1793447430.5\ntz=+0000\nboot=1793447311\napp=01:35\ndaemon=01:42\nruns=1\n__TIMELINE__\n")["appStartedAtPs"])


class GuestFilterTests(unittest.TestCase):
    BLOCK = SCRIPT[SCRIPT.index("  boot-observe)"):SCRIPT.index("  anchor-rules)")]
    PROGRAM = re.search(r"perl -ne '([^']+)'", BLOCK)[1]

    def filtered(self, text):
        return subprocess.run(["perl", "-ne", self.PROGRAM], input=text, capture_output=True, text=True, check=True).stdout.splitlines()

    def test_all_33_run8g_status_lines_are_extracted_with_the_right_pids(self):
        pids = []
        for name, count in (("boundary", 21), ("after-boot", 12)):
            lines = [line for line in self.filtered((FIXTURES / f"run8g-status-lines-{name}.txt").read_text()) if " status: phase=" in line]
            self.assertEqual(len(lines), count, name)
            pids += [int(re.search(r" pid=(\d+)$", line)[1]) for line in lines]
        self.assertEqual((len(pids), pids.count(282), pids.count(336)), (33, 2, 31))

    def test_a_status_text_inside_another_message_is_not_a_status_line(self):
        forged = ("2026-10-31 04:48:40.000 Df WGEXDaemon[336:1451] [com.magrathean.WGEXApp.lab:daemon] relay said status: phase=active protection=protected reason=none\n"
                  "2026-10-31 04:48:41.000 Df WGEXDaemon[336:1451] [com.magrathean.WGEXApp.lab:daemon] relay said [x] status: phase=active protection=protected reason=none\n"
                  "2026-10-31 04:48:42.000 Df WGEXDaemon[336:1451] [com.magrathean.WGEXApp.lab:daemon] status: phase=idle protection=unknown reason=none\n")
        out = [line for line in self.filtered(forged) if " status: phase=" in line]
        self.assertEqual(out, ["2026-10-31 04:48:42.000 status: phase=idle protection=unknown reason=none pid=336"])

    def test_the_guest_reports_status_lines_past_the_cap_instead_of_dropping_them_unnamed(self):
        line = "2026-10-31 04:48:42.000 Df WGEXDaemon[336:1451] [com.magrathean.WGEXApp.lab:daemon] status: phase=idle protection=unknown reason=none\n"
        out = self.filtered(line * 405)
        self.assertEqual(len([item for item in out if " status: phase=" in item]), 400)
        self.assertEqual(out[-1], "statuslinesdropped=5")
        self.assertEqual(self.filtered("")[-1], "statuslinesdropped=0")

    def test_the_verdict_records_and_names_dropped_status_lines_when_non_zero(self):
        text = observe(clean_lines(), app=None, tail=("statuslinesdropped=0",))
        self.assertEqual(V.parse_boot_observe(text)["statusLinesDropped"], 0)
        self.assertEqual(names(summary(text)), [])
        boot = summary(observe(clean_lines(), app=None, tail=("statuslinesdropped=7",)))
        self.assertEqual(boot["statusLinesDropped"], 7)
        self.assertEqual(names(boot), ["statusLinesDropped"])
        self.assertEqual(V.restart_timeline(boot)["observations"]["statusLinesDropped"], 7)
        self.assertFalse(passes(boot))
        self.assertIsNone(V.parse_boot_observe(observe(clean_lines(), app=None))["statusLinesDropped"], "an older script reports no count")

    def test_the_guest_read_no_longer_starts_at_the_guests_kern_boottime_second(self):
        window = re.search(r'start="\$\(date -r "([^"]+)"', self.BLOCK)[1]
        self.assertNotEqual(window, "$boot", "the read starts a fixed margin before kern.boottime; the host filters by pid and start")
        self.assertRegex(window, r"boot - \d{3}")


class NeutralWordingTests(unittest.TestCase):
    PS_LSTART = 1793447404.498 - 69.6

    def test_the_gap_is_protectedOnlyAfterAppSeen_with_both_app_starts_and_the_delta(self):
        observation = copy.deepcopy(restart.RUN_8G)
        observation["boot"]["appStartedAtPs"] = self.PS_LSTART
        held = restart.checks_by_name("boot-secrets", observation)["daemonSecretsBeforeApp"]
        self.assertFalse(held["met"])
        self.assertNotIn("appAssisted", held)
        value = held["protectedOnlyAfterAppSeen"]
        self.assertEqual((value["firstProtectedAt"], value["appStartedAt"], value["deltaSeconds"]), (1793447404.498, 1793447332.938, 71.56))
        self.assertEqual((value["appStartedAtPsLstart"], value["deltaSecondsVsPsLstart"]), (self.PS_LSTART, 69.6))
        self.assertIn("earliest possible", value["appStartedAtSource"])
        self.assertTrue(held["gap"].startswith("protectedOnlyAfterAppSeen: "), held["gap"])
        self.assertIn("causation not measured", held["gap"])
        self.assertNotIn("assist", held["gap"].lower())
        report = V.boot_report(observation["boot"])
        self.assertNotIn("appAssisted", report)
        self.assertEqual(report["protectedOnlyAfterAppSeen"], value)

    def test_without_ps_lstart_only_the_earliest_estimate_is_recorded(self):
        value = restart.checks_by_name("boot-secrets", restart.RUN_8G)["daemonSecretsBeforeApp"]["protectedOnlyAfterAppSeen"]
        self.assertNotIn("appStartedAtPsLstart", value)

    def test_daemonDrivenReconnect_is_not_measured_unless_a_causal_signal_exists_in_the_capture(self):
        for observation in (restart.RUN_8G, restart.without_pids(restart.RUN_8G)):
            self.assertIsNone(V.boot_report(observation["boot"])["daemonDrivenReconnect"])
        clean = summary(observe(clean_lines(), app=None))
        report = V.boot_report(clean)
        self.assertTrue(report["protectedBeforeAppSeen"], "the timing result stays, under its neutral name")
        self.assertIsNone(report["daemonDrivenReconnect"])
        self.assertIn("not measured", report["daemonDrivenReconnectBasis"])
        self.assertIs(V.boot_report(dict(clean, appMutatingRequestBeforeFirstProtected=False))["daemonDrivenReconnect"], True)
        self.assertIs(V.boot_report(dict(clean, appMutatingRequestBeforeFirstProtected=True))["daemonDrivenReconnect"], False)

    def test_timing_still_fails_boot_secrets_when_protection_follows_the_app(self):
        boot = summary(observe(clean_lines(), app=4))      # app started at D+55
        self.assertTrue(secrets(boot)["daemonSecretsBeforeApp"]["met"], "the timing rule alone still holds")
        self.assertFalse(passes(boot), "M1-10v: BOOT-SECRETS now also needs no app process at all (relaunchPrevented)")
        self.assertFalse(secrets(boot)["relaunchPrevented"]["met"])
        self.assertTrue(passes(summary(observe(clean_lines(), app=None))))
        late = summary(observe(clean_lines(), app=58))     # app earliest start D+1, protected D+5
        self.assertFalse(passes(late))
        self.assertTrue(secrets(late)["daemonSecretsBeforeApp"]["gap"].startswith("protectedOnlyAfterAppSeen: "))

    def test_a7_a_driver_poll_inside_the_clock_uncertainty_of_the_app_start_is_not_a_protected_before_app(self):
        lines = [(D + 1, "idle", "unknown", 336), (D + 2, "idle", "blocked", 336), (D + 3, "preparing", "blocked", 336)]
        poll = [[D + 19 - 0.4, "active", "protected"]]   # stamped 0.4 s before the app's earliest start by offset error
        boot = summary(observe(lines, app=40), polls=poll)
        self.assertEqual(boot["appStartedAt"], D + 19)
        self.assertFalse(passes(boot))
        held = secrets(boot)["daemonSecretsBeforeApp"]
        self.assertFalse(held["met"])
        self.assertIn("pollClockMarginSeconds", held["protectedOnlyAfterAppSeen"])
        far = [[D + 10, "active", "protected"]]
        self.assertTrue(secrets(summary(observe(lines, app=40), polls=far))["daemonSecretsBeforeApp"]["met"], "a poll well before the app start still counts")


class ReevalTests(unittest.TestCase):
    REEVAL = ROOT / "Tools/lab/verdict-reeval.py"

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"])
        self.addCleanup(self.directory.cleanup)
        self.scratch = Path(self.directory.name).resolve()

    def capture(self, row="BOOT-SECRETS", observation=None, name="lab-fixture"):
        path = self.scratch / "captures" / row / name
        path.mkdir(parents=True)
        if observation is not None:
            (path / "row-observation.json").write_text(json.dumps(observation))
        return path

    def run_reeval(self, *args, tmpdir=None):
        env = {key: value for key, value in os.environ.items() if key != "TMPDIR"}
        env["TMPDIR"] = str(self.scratch / "tmp") if tmpdir is None else tmpdir
        Path(self.scratch / "tmp").mkdir(exist_ok=True)
        return subprocess.run([sys.executable, "-I", "-B", str(self.REEVAL), *map(str, args)], capture_output=True, text=True, env=env)

    def test_the_output_is_marked_an_offline_re_evaluation_not_a_verdict(self):
        capture = self.capture(observation=restart.RUN_8G)
        out = self.scratch / "tmp" / "out.json"
        result = self.run_reeval(capture, "--out", out)
        self.assertEqual(result.returncode, 1, result.stderr)
        document = json.loads(result.stdout)
        self.assertIs(document["offlineReevaluation"], True)
        self.assertEqual(document["notice"], "offline re-evaluation, not a verdict")
        self.assertIn("offline re-evaluation, not a verdict", result.stderr)
        self.assertEqual(json.loads(out.read_text()), document)
        self.assertEqual(document["results"][0]["checks"][-1]["name"], "daemonSecretsBeforeApp")
        self.assertIn("protectedOnlyAfterAppSeen", result.stdout)
        self.assertNotIn("appAssisted", result.stdout)

    def test_errors_are_exit_2_distinct_from_not_pass(self):
        (self.scratch / "tmp").mkdir(exist_ok=True)
        missing = self.run_reeval(self.scratch / "captures/BOOT-SECRETS/lab-nope")
        self.assertEqual(missing.returncode, 2, missing.stdout)
        empty = self.capture("REBOOT-INTENT", name="lab-empty")
        self.assertEqual(self.run_reeval(empty).returncode, 2, "a reboot row capture without row-observation.json")
        crash = self.capture("CRASH-KILL-APP", name="lab-crash")
        self.assertEqual(self.run_reeval(crash).returncode, 0, "crash rows build no status timeline: unchanged")
        good = self.capture(observation=restart.RUN_8G)
        directory = self.scratch / "tmp" / "outdir"
        directory.mkdir()
        self.assertEqual(self.run_reeval(good, "--out", directory).returncode, 2)
        malformed = copy.deepcopy(restart.RUN_8G)
        malformed["boot"]["statusSamples"] = [[1793447428.9, "active"]]
        bad = self.capture(observation=malformed, name="lab-malformed")
        result = self.run_reeval(bad)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("malformed", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_tmpdir_must_be_absolute_and_not_root_and_out_is_refused_under_a_capture(self):
        good = self.capture(observation=restart.RUN_8G)
        for label, tmpdir in (("root", "/"), ("relative", "."), ("empty", "")):
            with self.subTest(label):
                result = self.run_reeval(good, "--out", self.scratch / "tmp" / "x.json", tmpdir=tmpdir)
                self.assertEqual(result.returncode, 2, result.stdout)
        under = self.scratch / "tmp" / "inside"
        result = self.run_reeval(self.scratch / "tmp", "--out", under / "x.json")   # not a capture layout: still refused before any work
        self.assertEqual(result.returncode, 2)
        # a capture copy placed under $TMPDIR cannot be overwritten through --out
        copy_dir = self.scratch / "tmp" / "captures" / "BOOT-SECRETS" / "lab-copy"
        copy_dir.mkdir(parents=True)
        (copy_dir / "row-observation.json").write_text(json.dumps(restart.RUN_8G))
        refused = self.run_reeval(copy_dir, "--out", copy_dir / "row-observation.json")
        self.assertEqual(refused.returncode, 2, refused.stdout)
        self.assertEqual(json.loads((copy_dir / "row-observation.json").read_text()), restart.RUN_8G)

    def test_neverOpenWindow_is_recomputed_from_the_post_restart_lines_not_carried(self):
        capture = self.capture(observation=restart.RUN_8G)
        result = self.run_reeval(capture)
        window = json.loads(result.stdout)["results"][0]["neverOpenWindow"]
        self.assertEqual(window["daemonFirstStatusAt"], 1793447332.341)
        self.assertEqual((window["unknownProtectionSamples"], window["failedPhaseSamples"]), (2, 3))
        self.assertEqual(restart.RUN_8G["boot"]["neverOpenWindow"]["daemonFirstStatusAt"], 1793447312.312, "the stored one is the stale one")

    def test_unattributed_lines_are_not_waivable_in_a_re_evaluation(self):
        # M1-10v: the opt-out flag is gone (test_reboot_followups.ReevalOptOutTests); the strict result is the only result.
        observation = copy.deepcopy(restart.RUN_8G)
        observation["boot"]["timeline"] = [item[:3] for item in observation["boot"]["timeline"]]   # daemonPid kept, no pids on lines
        capture = self.capture(observation=observation)
        strict = self.run_reeval(capture)
        self.assertIn("postRestartLineUnattributed", strict.stdout)
        self.assertNotIn("optOuts", strict.stdout)

    def test_reboot_intent_recomputes_the_launchd_runs_check_as_well(self):
        observation = copy.deepcopy(restart.RUN_8G)
        observation["boot"]["daemonRuns"] = 2
        capture = self.capture("REBOOT-INTENT", observation=observation, name="lab-intent")
        result = json.loads(self.run_reeval(capture).stdout)["results"][0]
        self.assertEqual([check["name"] for check in result["checks"]], ["postRestartTimelineConsistent", "noRestartLoop"])
        self.assertFalse(result["checks"][1]["met"])


if __name__ == "__main__":
    unittest.main()
