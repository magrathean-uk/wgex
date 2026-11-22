# SPDX-License-Identifier: MIT
"""M1-10o, guest run 8e (wgex-plan/evidence/run8e/REPORT-2026-10-30.txt sections 4-6 and the build-root steps): rows never
turn lockdown off (turning it off raised the SecurityAgent administrator prompt "WGEX wants to make changes." and the app
disabled its controls), GUI timing is measured from the press, not from before its element search (manualEndCloses
counted a 116 s walk), evidence is collected before any cleanup step (offlineEn0Capture's tail never ran), and element
searches use the helper's targeted walk (a complete walk of the connected main window took 142-161 s, longer than
GUI_SEARCH). Recorded replies only; never a VM, never osascript."""
import json
from pathlib import Path
import re
import shlex
import unittest
from unittest.mock import patch

import test_gui_element as element
import test_live_replay as replay
import test_run8_rows as run8

LIVE, ROOT, GUEST = element.LIVE, element.ROOT, element.GUEST
LOCKDOWN = element.LOCKDOWN
END = "wgex.protection.endCaptiveWindow"
CONFIRM = "wgex.protection.confirmCaptiveWindow"
SEARCH = LIVE.HARNESS.seconds("GUI_SEARCH")
# Run 8e's main window (probe-dump1.txt): the window line and the lockdown toggle; here the toggle sits inside the window.
WINDOW = "AXWindow | name=wgex-lab-full4 – Connected, last handshake 15 s ago | value= | desc= | id= | pos=0,30 size=1024x752\n"
TOGGLE = f"AXCheckBox | name=missing value | value=0 | desc=checkbox | id={LOCKDOWN} | pos=286,600 size=82x16 en=true\n"


def observation(result):
    return json.loads((Path(result["buildRoot"]) / "row-observation.json").read_text())


def steps(result):
    return json.loads((Path(result["buildRoot"]) / "steps.json").read_text())


class SlowEndRunner(run8.Run8Runner):
    """Run 8e's manual End: the first dump after the second confirm (the End control's search) costs one 116 s walk, the
    press command `press` seconds, and the daemon closes the window `close` seconds after the press returned."""

    def __init__(self, press=2.0, close=8.0):
        super().__init__()
        self.press_cost, self.close, self.confirms, self.charged = press, close, 0, False

    def run(self, argv, data=None, timeout=100, env=None):
        args = argv[2:] if argv[:1] == ["just"] else []
        if args[:2] == ["gui", "dump"] and self.confirms == 2 and not self.charged:
            self.charged = True
            self.clock += 116
        result = super().run(argv, data, timeout, env)
        if args[:2] == ["gui", "press"] and CONFIRM in args:
            self.confirms += 1
        if args[:2] == ["gui", "press"] and END in args:
            self.clock += self.press_cost
            self.captive_until = self.clock + self.close
        return result


class KillStampRunner(run8.Run8Runner):
    """kill-app-process prints the guest-clock instant of its SIGKILL, as the M1-10o guest script does."""

    def run(self, argv, data=None, timeout=100, env=None):
        args = argv[2:] if argv[:1] == ["just"] else []
        if args[:2] == ["ssh", "--"] and "verdict-actions.sh kill-app-process" in args[2]:
            self.killed_at = round(self.clock - 0.5, 3)
            return self.handled(argv, env, f"killedAt={self.killed_at:.3f}\n".encode())
        return super().run(argv, data, timeout, env)


class LockdownOffTests(unittest.TestCase):
    """Item 1: no row presses lockdown off; the need is read from the journal and kept as the gap lockdownOffNeedsAdmin."""

    def test_the_driver_never_calls_set_lockdown_false(self):
        source = (ROOT / "Tools/lab/verdict-live.py").read_text()
        self.assertNotIn("set_lockdown(False)", source)
        self.assertEqual(len(re.findall(r"set_lockdown\(True\)", source)), 3, "lockdown on: M5.3-10, REBOOT-LOCKDOWN and ONDEMAND-ETH")

    def test_lockdown_on_keeps_the_gap_without_any_gui_step(self):
        runner = run8.Run8Runner()
        runner.lockdown = True
        live = LIVE.Session("fixture", {}, runner=runner)
        self.assertFalse(live.lockdown_off_needed("the unprotected tail"))
        self.assertTrue(live.lockdown_gap.startswith("lockdownOffNeedsAdmin: the unprotected tail needs lockdown off and the daemon "
                                                     "journal reports lockdown True"), live.lockdown_gap)
        self.assertIn('SecurityAgent "WGEX wants to make changes."', live.lockdown_gap)
        lines = run8.commands(runner)
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].endswith("verdict-actions.sh lockdown-state"))
        self.assertEqual(live.ledger[-1], dict(lockdownOffNeeded="the unprotected tail", lockdownReported=True, togglePressed=False))

    def test_lockdown_already_off_runs_the_step(self):
        live = LIVE.Session("fixture", {}, runner=run8.Run8Runner())
        self.assertTrue(live.lockdown_off_needed("the unprotected tail"))
        self.assertIsNone(live.lockdown_gap)

    def test_an_unreadable_journal_is_not_off(self):
        runner = run8.Run8Runner()
        live = LIVE.Session("fixture", {}, runner=runner)
        live.journal_lockdown = lambda: None
        self.assertFalse(live.lockdown_off_needed("the unprotected tail"))
        self.assertIn("reports lockdown None", live.lockdown_gap)

    def test_the_captive_row_keeps_its_blocked_windows_and_never_types(self):
        runner, result = run8.run_row("M5.3-10")
        self.assertEqual([w["role"] for w in result["states"]], ["unprotectedLead", "afterExpiry", "afterEnd", "afterAppKill"],
                         "the measured windows stand; run 8e lost them to the ValueError")
        self.assertFalse(any("keystroke" in c and "minute" not in c and '","' not in c and '"w"' not in c
                             for c in run8.commands(runner)), "only the Settings keys the row always sent")
        self.assertTrue(all(c["met"] for c in result["checks"]), result["checks"])


class LeadDropRunner(run8.Run8Runner):
    """Run8Runner whose host receiver never sees the first unprotected window (the lead control): a dead guest path at the
    row's start must fail the row, never pass on the later blocked windows."""

    def __init__(self):
        super().__init__()
        self.lead_nonce = None

    def start(self, argv, env=None):
        words = shlex.split(argv[-1]) if argv[:3] == ["just", "lab", "ssh"] else []
        if self.lead_nonce is None and "generate" in words and words[words.index("--state") + 1] == "unprotected":
            self.lead_nonce = words[words.index("--nonce") + 1]
        return super().start(argv, env)

    def receiver(self, scope):
        value = super().receiver(scope)
        value["observations"] = [o for o in value["observations"] if o.get("nonce") != self.lead_nonce]
        return value


class LeadControlTests(unittest.TestCase):
    """Fix pass: the lockdown rows' positive control leads, before the lockdown press, and stands in for the skipped tail."""

    def test_both_lockdown_rows_pass_on_the_lead_control(self):
        for row in ("M5.3-10", "REBOOT-LOCKDOWN"):
            with self.subTest(row=row):
                _, result = run8.run_row(row)
                self.assertEqual((result["tailControlPosition"], result["tailControl"]["met"]), ("lead", True))
                self.assertEqual(result["tailControl"]["trailSkipped"], "lockdownOffNeedsAdmin")
                lead = [w for w in result["states"] if w["role"] == "unprotectedLead"]
                self.assertEqual(len(lead), 1)
                self.assertTrue(lead[0]["expectationMet"])
                self.assertTrue(run8.check(result, "offlineEn0Capture")["tailSystemResolverObserved"])
                self.assertEqual(result["gaps"], [])
                ledger = [item for item in steps(result) if "lockdownOffNeeded" in item]
                self.assertEqual(ledger, [dict(lockdownOffNeeded="the unprotected tail", lockdownReported=True, togglePressed=False)])

    def test_missing_lead_receipts_fail_the_row(self):
        for row in ("M5.3-10", "REBOOT-LOCKDOWN"):
            with self.subTest(row=row):
                runner = LeadDropRunner()
                _, result = run8.run_row(row, runner, accepted=False)
                self.assertIsNotNone(runner.lead_nonce)
                self.assertEqual((result["tailControlPosition"], result["tailControl"]["met"]), ("lead", False))
                lead = next(w for w in result["states"] if w["role"] == "unprotectedLead")
                self.assertIsNot(lead.get("expectationMet"), True)
                self.assertIn("received:outside_tunnel:ipv4:dns", lead["missing"])
                self.assertEqual(result["familiesCovered"], [])

    def test_the_resolver_observation_comes_from_the_lead_window_only(self):
        text = "1793294005.200 IP 192.168.64.96.50000 > 192.168.64.1.53: query trail-nonce-system\n"
        records = [dict(nonce="lead-nonce", role="unprotectedLead", windows=[dict(state="unprotected", start=1793294000, end=1793294010)]),
                   dict(nonce="trail-nonce", role="unprotectedTail", windows=[dict(state="unprotected", start=1793294000, end=1793294010)])]
        self.assertTrue(LIVE.inspect_capture_text(text, records)["tailSystemResolverObserved"])
        self.assertFalse(LIVE.inspect_capture_text(text, records, control_roles=("unprotectedLead",))["tailSystemResolverObserved"])
        self.assertTrue(LIVE.inspect_capture_text(text.replace("trail-nonce", "lead-nonce"), records,
                                                  control_roles=("unprotectedLead",))["tailSystemResolverObserved"])

    def test_without_a_lead_control_the_skipped_tail_is_the_gap(self):
        """A lockdown row whose lead control did not run (here: no lead kinds) keeps lockdownOffNeedsAdmin as its gap and
        its tail control unmet: the trailing tail is never silently dropped."""
        with patch.object(LIVE, "LEAD_CONTROL_KINDS", ()):
            runner, result = run8.run_row("REBOOT-LOCKDOWN", accepted=False)
        self.assertFalse(any(" generate " in c and "--state unprotected" in c for c in run8.commands(runner)))
        self.assertEqual(len(result["gaps"]), 1, result["gaps"])
        self.assertTrue(result["gaps"][0].startswith("lockdownOffNeedsAdmin: the unprotected tail needs lockdown off"), result["gaps"])
        self.assertIn('SecurityAgent "WGEX wants to make changes."', result["gaps"][0])
        self.assertEqual((result["tailControlPosition"], result["tailControl"]["met"]), ("trail", False))
        self.assertFalse(run8.check(result, "offlineEn0Capture")["met"])


class PressTimingTests(unittest.TestCase):
    """Item 2: endClickedAt is the End press as issued, after its element search; killedAt is the guest's SIGKILL stamp."""

    def test_manual_end_is_measured_from_the_press_not_from_before_the_search(self):
        runner, result = run8.run_row("M5.3-10", SlowEndRunner())
        end = next(item for item in observation(result)["scenarios"] if item["name"] == "manualEnd")
        self.assertGreaterEqual(end["endClickedAt"] - end["openedAt"], 116, "the stamp follows the 116 s search")
        self.assertAlmostEqual(end["endPressReturnedAt"] - end["endClickedAt"], 2.0, delta=0.1)
        took = run8.check(result, "manualEndCloses")["secondsAfterEnd"]
        self.assertTrue(10 <= took <= LIVE.VERDICT.CAPTIVE_END_SECONDS, took)
        self.assertTrue(run8.check(result, "manualEndCloses")["met"])
        press = next(item for item in steps(result) if item.get("argv", [])[:4] == ["just", "lab", "gui", "press"] and END in item["argv"])
        self.assertAlmostEqual(end["endClickedAt"], press["start"] + result["clockMeasurement"]["offsetSeconds"], delta=0.05)

    def test_a_slow_daemon_still_fails_manual_end(self):
        _, result = run8.run_row("M5.3-10", SlowEndRunner(close=20.0), accepted=False)
        self.assertFalse(run8.check(result, "manualEndCloses")["met"])

    def test_the_confirm_press_stamps_open_clicked_at(self):
        _, result = run8.run_row("M5.3-10")
        presses = [item for item in steps(result) if item.get("argv", [])[:4] == ["just", "lab", "gui", "press"] and CONFIRM in item["argv"]]
        offset = result["clockMeasurement"]["offsetSeconds"]
        opened = [item["openClickedAt"] for item in observation(result)["scenarios"]]
        self.assertEqual(len(opened), 3)
        for stamp, press in zip(opened, presses):
            self.assertAlmostEqual(stamp, press["start"] + offset, delta=0.05)

    def test_the_app_kill_uses_the_guest_stamp_and_an_older_script_the_return(self):
        runner = KillStampRunner()
        _, result = run8.run_row("M5.3-10", runner)
        kill = next(item for item in observation(result)["scenarios"] if item["name"] == "appKill")
        self.assertEqual((kill["killedAt"], kill["killedAtSource"]), (runner.killed_at, "guest"))
        self.assertTrue(run8.check(result, "appKillCannotExtend")["met"])
        _, result = run8.run_row("M5.3-10")
        kill = next(item for item in observation(result)["scenarios"] if item["name"] == "appKill")
        self.assertEqual(kill["killedAtSource"], "return")

    def test_the_guest_script_prints_the_kill_instant_after_the_signal(self):
        script = (GUEST / "verdict-actions.sh").read_text()
        block = script[script.index("  kill-app-process)"):script.index(";;", script.index("  kill-app-process)"))]
        self.assertLess(block.index('kill -KILL "$pid"'), block.index('killed_at="$(now)"'))
        self.assertIn("printf 'killedAt=%s\\n' \"$killed_at\"", block)
        self.assertTrue(LIVE.re.fullmatch(r"killedAt=(\d{9,11}\.\d{1,6})\s*", "killedAt=1793294010.250\n"))


class FailingStepRunner(replay.RecordedRunner):
    """RecordedRunner whose guest commands matching `failing` (a predicate on one argument) exit 1."""

    def __init__(self, failing):
        super().__init__()
        self.failing = failing

    def run(self, argv, data=None, timeout=100, env=None):
        if argv[:3] == ["just", "lab", "ssh"] and any(self.failing(arg) for arg in argv):
            self.commands.append(list(argv))
            return self.reply(argv, code=1)
        return super().run(argv, data, timeout, env)


class EvidenceBeforeCleanupTests(unittest.TestCase):
    """Item 3: captures, receivers and the capture inspection come before any cleanup step; cleanup failures are warnings."""

    def test_captures_and_receivers_are_collected_before_the_fixture_cleanup(self):
        runner, _ = replay.LiveReplayTests().run_recorded("M5.1-04")
        lines = [" ".join(argv) for argv in runner.commands]
        stop = next(i for i, c in enumerate(lines) if "stop-capture.sh" in c)
        peer_stop = next(i for i, c in enumerate(lines) if c.endswith("/peer.stop"))
        cleanup = [i for i, c in enumerate(lines) if c.endswith("verdict-actions.sh diagnostics-stop") or "peer-fault.sh cleanup" in c]
        self.assertTrue(cleanup)
        self.assertLess(max(stop, peer_stop), cleanup[-1])
        self.assertLess(stop, next(i for i, c in enumerate(lines) if c.endswith("verdict-actions.sh diagnostics-stop")))

    def test_a_failed_cleanup_step_is_a_ledger_warning_not_a_gap(self):
        runner = FailingStepRunner(lambda arg: "verdict-actions.sh diagnostics-stop" in arg)
        _, result = replay.LiveReplayTests().run_recorded("M5.1-04", runner)
        self.assertEqual(result["gaps"], [])
        self.assertTrue(run8.check(result, "offlineEn0Capture")["met"])
        warnings = [item for item in steps(result) if "cleanupWarning" in item]
        self.assertEqual(len(warnings), 1, warnings)
        self.assertIn("row fixture cleanup failed (RuntimeError)", warnings[0]["cleanupWarning"])

    def test_a_failed_capture_collection_stays_a_gap(self):
        runner = FailingStepRunner(lambda arg: arg.startswith("bash ") and arg.endswith("/stop-capture.sh"))
        _, result = replay.LiveReplayTests().run_recorded("M5.1-04", runner, accepted=False)
        self.assertIn("en0 capture collection failed; see build-root ledger", result["gaps"])
        self.assertFalse(run8.check(result, "offlineEn0Capture")["met"])

    def test_a_failed_capture_inspection_is_a_gap_and_cleanup_still_runs(self):
        class Runner(replay.RecordedRunner):
            def run(self, argv, data=None, timeout=100, env=None):
                if argv[:1] == ["tcpdump"]:
                    self.commands.append(list(argv))
                    return self.reply(argv, code=1)
                return super().run(argv, data, timeout, env)
        runner, result = replay.LiveReplayTests().run_recorded("M5.1-04", Runner(), accepted=False)
        self.assertIn("en0 capture inspection failed; see build-root ledger", result["gaps"])
        lines = [" ".join(argv) for argv in runner.commands]
        tcpdump = max(i for i, c in enumerate(lines) if c.startswith("tcpdump "))
        self.assertTrue(any(c.endswith("verdict-actions.sh diagnostics-stop") for c in lines[tcpdump:]), "inspection before cleanup")


class TargetedWalkTests(unittest.TestCase):
    """Item 4: identifier-only element searches read the helper's targeted walk; the walk mode and duration are recorded."""

    def test_the_walk_line_carries_the_target_outcome(self):
        self.assertEqual(LIVE.dump_walk("ax-walk: elements=31 truncated=0 errors=0 target=found\n"),
                         dict(elements=31, truncated=False, errors=0, target="found"))
        self.assertEqual(LIVE.dump_walk("ax-walk: elements=159 truncated=0 errors=0\n"), dict(elements=159, truncated=False, errors=0))
        self.assertFalse(LIVE.dump_incomplete(WINDOW + "ax-walk: elements=159 truncated=0 errors=0 target=missing\n"))
        self.assertIsNone(LIVE.dump_walk("ax-walk: elements=1 truncated=0 errors=0 target=maybe\n"))

    def test_click_id_reads_the_targeted_walk_and_records_its_duration(self):
        runner, live = element.session(WINDOW + TOGGLE + "ax-walk: elements=31 truncated=0 errors=0 target=found\n")
        self.assertEqual(live.click_id(LOCKDOWN), "element")
        self.assertEqual(element.gui(runner, "dump"), [["dump", "WGEX", "1", LOCKDOWN]])
        entry = next(item for item in live.ledger if item.get("argv", [])[:4] == ["just", "lab", "gui", "dump"])
        self.assertEqual((entry["dumpMode"], entry["walk"]), ("target", dict(elements=31, truncated=False, errors=0, target="found")))
        self.assertIsInstance(entry["walkSeconds"], float)

    def test_a_second_targeted_read_fits_the_search_bound_at_run_8e_cost(self):
        class Runner(element.DumpRunner):
            def run(self, argv, data=None, timeout=100, env=None):
                if argv[:4] == ["just", "lab", "gui", "dump"]:
                    self.clock += 40  # a targeted walk of the 159-element window; run 8e's full walk took 142-161 s
                return super().run(argv, data, timeout, env)
        missing = WINDOW + "ax-walk: elements=159 truncated=0 errors=0 target=missing\n"
        runner = Runner([missing, WINDOW + TOGGLE + "ax-walk: elements=31 truncated=0 errors=0 target=found\n"])
        live = LIVE.Session("fixture", {}, runner=runner)
        started = runner.clock
        self.assertEqual(live.click_id(LOCKDOWN), "element")
        self.assertEqual(len(element.gui(runner, "dump")), 2)
        self.assertLess(runner.clock - started, SEARCH)
        self.assertEqual([item["walkSeconds"] for item in live.ledger if item.get("dumpMode") == "target"], [40.01, 40.01])

    def test_label_targets_prefix_identifiers_and_post_scroll_lookups_keep_the_full_dump(self):
        runner, live = element.session(element.STARTUP)
        live.click(LIVE.BOOT_STARTUP_LABEL, LIVE.BOOT_STARTUP_GROUP)
        self.assertEqual(element.gui(runner, "dump"), [["dump", "WGEX", "1"]])
        runner, live = element.session(element.OFFSCREEN, scroll=b"scroll=none\n")
        live.click_id(LOCKDOWN)
        self.assertEqual(element.gui(runner, "dump"), [["dump", "WGEX", "1", LOCKDOWN], ["dump", "WGEX", "1"]],
                         "the post-scroll lookup must see every match (F3 ambiguity)")
        self.assertEqual([item.get("dumpMode") for item in live.ledger if item.get("argv", [])[:4] == ["just", "lab", "gui", "dump"]],
                         ["target", "full"])

    def test_the_helper_and_gui_sh_carry_the_targeted_mode(self):
        source = element.GUEST.joinpath("ax-dump.applescript").read_text()
        code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("--"))
        self.assertIn("if (count of argv) > 2 then set targetIdent to item 3 of argv", code)
        self.assertIn('return walkOut & "ax-walk: elements=" & walkCount & " truncated=" & walkTruncated & " errors=" & walkErrors & '
                      '" target=" & targetWord', code)
        self.assertIn('return walkOut & "ax-walk: elements=" & walkCount & " truncated=" & walkTruncated & " errors=" & walkErrors\nend run',
                      code, "the full dump's summary line is unchanged")
        match = code[code.index("on matchElement(e)"):code.index("end matchElement")]
        self.assertIn('value of attribute "AXIdentifier" of e as text', match)
        self.assertIn("considering case", match)
        self.assertIn("my describeElement(e)", match)
        walk = code[code.index("on walkChildren("):code.index("end walkChildren")]
        self.assertEqual(walk.count("if targetFound then return"), 2, "after the match and after a subtree that held it")
        gui_sh = (ROOT / "Tools/lab/tart/gui.sh").read_text()
        dump = gui_sh[gui_sh.index("  dump)\n"):gui_sh.index("  click)\n")]
        self.assertIn('if (($# == 3)); then check_element "$app" "$window" "$3"; fi', dump)
        self.assertIn('"$guest_dir/ax-dump.applescript" "$app" "$window" "${@:3}"', dump)



# M1-10o fix pass 2 (VERIFY F1-F7). Run 8e's End sequence (build-root-failures/M5.3-10-attempt1-steps.json step 400,
# verdict-7 clockMeasurement): guest clock offset -0.6735 s, the End press command 4.93 s (the helper's own walk and the
# AXPress), status and anchor reads about 1.0 s and 0.9 s each.
# M1-10q fix pass 1 (M1-10o FIX2-VERIFY N4): the close as the run 8e ledger shows it, not the old after-anchor stamp
# (10.68 s): the status read that observed blocked (step 408) started 8.59 s and completed 9.66 s after the End command
# returned (1793373879.938 on the guest clock), the read before it (step 406) still saw captiveWindow. 9.66 s is the
# latest instant the close can have happened; the fixture's read completing at or after it is the first to see blocked.
RUN8E_OFFSET = -0.6735
RUN8E_PRESS = 4.93
RUN8E_CLOSE = 9.66
# Run 8e's real ledger under the read-completion rule from the issue instant (step 408 end minus step 400 start).
RUN8E_LEDGER_FROM_ISSUE = 1793373889.598 - 1793373875.010
# Inference for the fixture: the helper's walk is most of the 4.93 s, so its delivery stamp falls 0.40 s before return.
RUN8E_STAMP_BEFORE_RETURN = 0.40


class Run8eEndRunner(SlowEndRunner):
    """SlowEndRunner at run 8e's End numbers: the guest clock offset, a 4.93 s End press whose helper reports pressedAt
    (stamp=False: an older helper without it), the close `close` seconds after return, and from the End press until the
    next confirm a 1.0 s status read and a 0.9 s anchor read (run 8e's 2.9 s poll cycle with the 1 s pause)."""

    def __init__(self, close=RUN8E_CLOSE, stamp=True, drift=0.0, end_clock_fails=False):
        super().__init__(press=RUN8E_PRESS, close=close)
        self.stamp, self.measuring, self.pressed_at = stamp, False, None
        # M1-10o FIX2-VERIFY N2: from the manualEnd confirm on, the guest clock runs `drift` seconds ahead of the offset
        # sampled at prepare (its clock samples and the helper's stamp both carry it); end_clock_fails: those samples
        # are unusable (round trip beyond the evaluator bound).
        self.drift, self.end_clock_fails = drift, end_clock_fails

    def guest_drift(self):
        return self.drift if self.confirms >= 2 else 0.0

    def run(self, argv, data=None, timeout=100, env=None):
        args = argv[2:] if argv[:1] == ["just"] else []
        if args[:2] == ["ssh", "--clock"]:
            self.commands.append(list(argv))
            self.environments.append(env)
            self.clock += 0.01
            rtt = 5.0 if self.end_clock_fails and self.confirms >= 2 else 0.04
            sample = dict(start=self.clock, end=self.clock + rtt, timestamp=self.clock + rtt / 2 + RUN8E_OFFSET + self.guest_drift())
            return self.reply(argv, run8.V.canonical(sample))
        if self.measuring and args[:2] == ["ssh", "--"]:
            if args[2].endswith(" status --json"):
                self.clock += 1.0
            elif "verdict-actions.sh anchor-rules" in args[2]:
                self.clock += 0.9
        result = super().run(argv, data, timeout, env)
        if args[:2] == ["gui", "press"] and CONFIRM in args and self.confirms == 3:
            self.measuring = False
        if args[:2] == ["gui", "press"] and END in args:
            self.measuring = True
            if self.stamp:
                self.pressed_at = round(self.clock - RUN8E_STAMP_BEFORE_RETURN + RUN8E_OFFSET + self.guest_drift(), 3)
                return self.reply(argv, f"pressedAt={self.pressed_at:.3f}\npath=element\n".encode())
        return result


def manual_end(result):
    return next(item for item in observation(result)["scenarios"] if item["name"] == "manualEnd")


class DeliveryStampTests(unittest.TestCase):
    """F1 and F7: manualEndCloses is measured from the helper's in-guest delivery stamp to the completion of the status
    read that observed the close (M1-10q fix pass 1); run 8e's ledger End numbers pass, a 30 s close fails, and an older
    helper keeps the issue bound."""

    def test_run_8e_end_timing_passes_on_the_guest_delivery_stamp(self):
        runner, result = run8.run_row("M5.3-10", Run8eEndRunner())
        self.assertAlmostEqual(result["clockMeasurement"]["offsetSeconds"], RUN8E_OFFSET, places=6)
        end = manual_end(result)
        self.assertEqual((end["endClickedAt"], end["endClickedAtSource"]), (runner.pressed_at, "guest"))
        self.assertAlmostEqual(end["endPressReturnedAt"] - end["endPressIssuedAt"], RUN8E_PRESS + 0.01, delta=0.02)
        check = run8.check(result, "manualEndCloses")
        took = check["secondsAfterEnd"]
        # Never faster than the real close (9.66 s after return plus the 0.40 s stamp lead), at most one 2.92 s poll late.
        self.assertTrue(RUN8E_CLOSE + RUN8E_STAMP_BEFORE_RETURN <= took <= RUN8E_CLOSE + RUN8E_STAMP_BEFORE_RETURN + 2.95, took)
        self.assertLess(took, LIVE.VERDICT.CAPTIVE_END_SECONDS)
        self.assertTrue(check["met"], check)
        self.assertEqual(check["endClickedAtSource"], "guest")

    def test_without_the_guest_stamp_run_8e_ledger_timing_passes_from_the_issue(self):
        """An older helper (no pressedAt line): the issue instant stands, charging the 4.93 s command to the daemon. At the
        run 8e ledger's real close that still passes (the ledger itself reads 14.59 s), never faster than the ledger."""
        _, result = run8.run_row("M5.3-10", Run8eEndRunner(stamp=False))
        end = manual_end(result)
        self.assertEqual((end["endClickedAt"], end["endClickedAtSource"]), (end["endPressIssuedAt"], "issued"))
        check = run8.check(result, "manualEndCloses")
        self.assertAlmostEqual(RUN8E_LEDGER_FROM_ISSUE, 14.588, places=3)
        self.assertTrue(RUN8E_LEDGER_FROM_ISSUE <= check["secondsAfterEnd"] <= LIVE.VERDICT.CAPTIVE_END_SECONDS, check)
        self.assertTrue(check["met"], check)

    def test_without_the_guest_stamp_a_close_one_poll_later_fails_from_the_issue(self):
        """The old fixture close (10.68 s after return) is read one poll later than the ledger's, and from the issue
        instant that is over 15 s: the fallback stays conservative."""
        _, result = run8.run_row("M5.3-10", Run8eEndRunner(close=10.68, stamp=False), accepted=False)
        check = run8.check(result, "manualEndCloses")
        self.assertEqual(check["endClickedAtSource"], "issued")
        self.assertGreater(check["secondsAfterEnd"], LIVE.VERDICT.CAPTIVE_END_SECONDS)
        self.assertFalse(check["met"])

    def test_a_close_just_over_15_seconds_never_reads_as_a_pass(self):
        """M1-10o FIX2-VERIFY N1's replay: a true close 15.3 s after the stamp read 14.48 s from the poll start, a false
        PASS. From the read's completion it can never read faster than the close itself."""
        close = 15.3 - RUN8E_STAMP_BEFORE_RETURN
        _, result = run8.run_row("M5.3-10", Run8eEndRunner(close=close), accepted=False)
        check = run8.check(result, "manualEndCloses")
        self.assertGreaterEqual(check["secondsAfterEnd"], 15.3 - 0.01, check)
        self.assertFalse(check["met"], check)

    def test_a_30_second_close_still_fails(self):
        _, result = run8.run_row("M5.3-10", Run8eEndRunner(close=30.0), accepted=False)
        self.assertFalse(run8.check(result, "manualEndCloses")["met"])
        self.assertTrue(any(gap.startswith("captiveNotClosed: manualEnd: still captiveWindow") for gap in result["gaps"]), result["gaps"])

    def test_closed_at_is_the_completion_of_the_status_read_that_observed_blocked(self):
        _, result = run8.run_row("M5.3-10", Run8eEndRunner())
        end, offset = manual_end(result), result["clockMeasurement"]["offsetSeconds"]
        polls = [(item["start"] + offset, item["end"] + offset) for item in steps(result)
                 if any(arg.endswith(" status --json") for arg in item.get("argv", [])) and "end" in item]
        read = next((poll for poll in polls if abs(poll[0] - end["closedPollStartedAt"]) < 0.001), None)
        self.assertIsNotNone(read, "closedPollStartedAt is a status poll's start")
        self.assertAlmostEqual(end["closedAt"], read[1], delta=0.001, msg="closedAt is that read's completion")
        self.assertEqual(end["closedAtSource"], "statusReadCompleted")
        self.assertAlmostEqual(end["closedAt"] - end["closedPollStartedAt"], 1.0 + 0.01, delta=0.005, msg="one status read")
        self.assertAlmostEqual(end["closedConfirmedAt"] - end["closedAt"], 0.9 + 0.01, delta=0.005, msg="then the anchor read")
        self.assertEqual(run8.check(result, "manualEndCloses")["closedAtSource"], "statusReadCompleted")

    def test_end_and_its_close_share_the_guest_clock_measured_before_end(self):
        """M1-10o FIX2-VERIFY N2: a guest clock 0.9 s ahead of the prepare offset by the End press. The stamp (guest clock)
        and the close are on the clock measured right before End, so secondsAfterEnd is the undrifted value, not 0.9 s
        faster; the drift is recorded."""
        _, still = run8.run_row("M5.3-10", Run8eEndRunner())
        _, drifted = run8.run_row("M5.3-10", Run8eEndRunner(drift=0.9))
        end = manual_end(drifted)
        self.assertEqual((end["endClockSource"], end["endClickedAtSource"]), ("remeasuredBeforeEnd", "guest"))
        self.assertAlmostEqual(end["endClockDriftSeconds"], 0.9, places=3)
        self.assertAlmostEqual(manual_end(still)["endClockDriftSeconds"], 0.0, places=6)
        took = run8.check(drifted, "manualEndCloses")
        self.assertAlmostEqual(took["secondsAfterEnd"], run8.check(still, "manualEndCloses")["secondsAfterEnd"], delta=0.05)
        self.assertAlmostEqual(took["endClockDriftSeconds"], 0.9, places=3)
        self.assertAlmostEqual(drifted["clockMeasurement"]["offsetSeconds"], RUN8E_OFFSET, places=6, msg="the row's offset is kept")
        self.assertTrue(end["closedAt"] - end["endPressReturnedAt"] >= RUN8E_CLOSE - 0.01, "the close is on the End clock too")

    def test_a_failed_clock_measurement_before_end_keeps_the_row_offset_and_says_so(self):
        _, result = run8.run_row("M5.3-10", Run8eEndRunner(end_clock_fails=True))
        end = manual_end(result)
        self.assertEqual((end["endClockSource"], end["endClockDriftSeconds"]), ("rowClockMeasurementFailed", 0.0))
        self.assertTrue(run8.check(result, "manualEndCloses")["met"])

    def test_the_open_stamps_carry_their_source(self):
        _, result = run8.run_row("M5.3-10", Run8eEndRunner())
        self.assertEqual([item["openClickedAtSource"] for item in observation(result)["scenarios"]], ["issued"] * 3,
                         "the recorded confirm replies carry no stamp")

    def test_the_parsers_read_the_stamp_and_keep_the_fixed_reports(self):
        stamped = b"pressedAt=1793373879.512\npath=element\n"
        self.assertEqual((LIVE.action_path(stamped), LIVE.press_stamp(stamped), LIVE.press_reply(stamped)), ("element", 1793373879.512, "element"))
        self.assertEqual(LIVE.action_path(b"pressedAt=1793373879.512\npath=coordinate\n"), "coordinate")
        self.assertEqual(LIVE.action_path(b"pressedAt=1793373879.512\npath=element-timeout\n"), "element-timeout")
        self.assertEqual((LIVE.action_path(b"path=element\n"), LIVE.press_stamp(b"path=element\n")), ("element", None))
        self.assertEqual(LIVE.press_error(b"path=error number=-25200\n"), -25200)
        self.assertIsNone(LIVE.action_path(b"pressedAt=1793373879.512\n"), "a stamp without a path is no press")
        self.assertIsNone(LIVE.action_path(b"pressedAt=17933x\npath=element\n"), "a malformed stamp line voids the report")
        self.assertIsNone(LIVE.press_stamp(b"pressedAt=17933x\npath=element\n"))

    def test_an_impossible_stamp_falls_back_to_the_issue_instant(self):
        live = LIVE.Session("fixture", {}, runner=run8.Run8Runner())
        issued = live.guest_now()
        live.pressed(issued, "element", f"pressedAt={issued + 0.2:.3f}\npath=element\n".encode())
        self.assertEqual(live.last_press["pressedAtSource"], "guest")
        self.assertAlmostEqual(live.last_press["pressedAt"], issued + 0.2, places=3)
        for stamp in (issued - 5, issued + 5):
            live.pressed(issued, "element", f"pressedAt={stamp:.3f}\npath=element\n".encode())
            self.assertEqual((live.last_press["pressedAt"], live.last_press["pressedAtSource"]), (issued, "issued"))
            self.assertAlmostEqual(live.ledger[-1]["pressedAtRejected"], stamp, places=3)
        live.pressed(issued, "coordinate")
        self.assertEqual((live.last_press["pressedAt"], live.last_press["pressedAtSource"]), (issued, "issued"))

    def test_the_helper_stamps_immediately_before_every_delivery(self):
        source = (GUEST / "ax-action.applescript").read_text()
        code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("--"))
        self.assertEqual(code.count("set pressStamp to my stampNow()"), 3)
        # Nothing but the popup's `ignoring application responses` sits between the stamp and the delivery it stamps.
        for delivery, between in (("perform action actionName of found\n          end ignoring", "ignoring application responses"),
                                  ("perform action actionName of found\n          return my pressResult", ""),
                                  ('tell application "System Events" to click at {pointX, pointY}', "")):
            at = code.index(delivery)
            stamp = code.rindex("set pressStamp to my stampNow()", 0, at)
            self.assertEqual(" ".join(code[stamp + len("set pressStamp to my stampNow()"):at].split()), between, delivery)
        stamp = code[code.index("on stampNow()"):code.index("end stampNow")]
        self.assertIn("do shell script \"/usr/bin/perl -MTime::HiRes=time -e 'printf q(%.3f), time'\"", stamp)
        self.assertIn('return "pressedAt=" & pressStamp & linefeed & pathText', code)
        miss = code[code.index("if pointX is missing value then"):code.index("end if", code.index("if pointX is missing value then"))]
        self.assertNotIn("pressResult", miss, "a press-only miss or error carries no stamp")

    def test_gui_sh_passes_the_stamp_line_and_drops_a_malformed_one(self):
        gui_sh = (ROOT / "Tools/lab/tart/gui.sh").read_text()
        pattern = re.search(r'if \[\[ "\$line" =~ (\^pressedAt=\S+\$) \|\|', gui_sh)[1]
        for line, ok in (("pressedAt=1793373879.512", True), ("pressedAt=1793373879", False), ("pressedAt=17933x.5", False),
                         ("pressedAt=1793373879.512; id", False), ("path=element", False)):
            code = LIVE.subprocess.run(["bash", "-c", f'[[ "$1" =~ {pattern} ]]', "fixture", line], check=False).returncode
            self.assertEqual(code == 0, ok, line)
        self.assertIn('done <<<"$path_line"', gui_sh)


class LockdownToggleRunner(run8.Run8Runner):
    """Run8Runner whose daemon journal confirms a landed lockdown press `lag` seconds late (never when lag is None), whose
    first `misses` presses do not land, and whose main window dump shows the toggle's value (unreadable: no value)."""

    def __init__(self, lag=0.0, misses=0, unreadable=False):
        super().__init__()
        self.lag, self.misses, self.unreadable, self.journal_at = lag, misses, unreadable, None

    def dump(self):
        value = "" if self.unreadable else "1" if self.lockdown else "0"
        return [line.replace(f"value= | desc= | id={LOCKDOWN} |", f"value={value} | desc= | id={LOCKDOWN} |") for line in super().dump()]

    def run(self, argv, data=None, timeout=100, env=None):
        args = argv[2:] if argv[:1] == ["just"] else []
        if args[:2] == ["gui", "press"] and LOCKDOWN in args and self.misses:
            self.misses -= 1
            self.toggle_works = False
        result = super().run(argv, data, timeout, env)
        if args[:2] == ["gui", "press"] and LOCKDOWN in args:
            if self.toggle_works and self.lockdown:
                self.journal_at = None if self.lag is None else self.clock + self.lag
            self.toggle_works = True
        if args[:2] == ["ssh", "--"] and "verdict-actions.sh lockdown-state" in args[2] and self.lockdown:
            if self.journal_at is None or self.clock < self.journal_at:
                return self.reply(argv, b"lockdown=false\n")
        return result


def lockdown_presses(runner):
    return sum(1 for argv in runner.commands if argv[:4] == ["just", "lab", "gui", "press"] and LOCKDOWN in argv)


class LockdownSecondPressTests(unittest.TestCase):
    """F3: a lockdown press the journal confirms late is never followed by a second press that would turn lockdown off."""

    CONFIRM_SECONDS = LIVE.HARNESS.seconds("LOCKDOWN_CONFIRM")

    def test_a_late_journal_with_the_toggle_on_gets_more_time_and_no_second_press(self):
        runner = LockdownToggleRunner(lag=self.CONFIRM_SECONDS + 5)
        live = LIVE.Session("fixture", {}, runner=runner)
        self.assertTrue(live.set_lockdown(True))
        self.assertEqual(lockdown_presses(runner), 1)
        self.assertTrue(runner.lockdown)
        self.assertEqual(live.ledger[-1], dict(lockdownRequested=True, lockdownReported=True, togglePresses=1))
        read = next(item for item in live.ledger if "lockdownToggle" in item)
        self.assertEqual(read, dict(lockdownToggleBeforePress=2, lockdownToggle=True, lockdownReported=False))
        dump = next(item for item in reversed(live.ledger) if item.get("argv", [])[:4] == ["just", "lab", "gui", "dump"])
        self.assertEqual((dump["argv"][-1], dump["dumpMode"]), (LOCKDOWN, "target"))

    def test_a_journal_that_never_confirms_is_lockdown_not_applied_after_one_press(self):
        runner = LockdownToggleRunner(lag=None)
        live = LIVE.Session("fixture", {}, runner=runner)
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.set_lockdown(True)
        self.assertEqual(raised.exception.reason, "lockdownNotApplied")
        self.assertIn("after 1 press(es) of wgex.protection.lockdown (toggle value True)", str(raised.exception))
        self.assertEqual(lockdown_presses(runner), 1)
        self.assertTrue(runner.lockdown, "lockdown was never pressed off")

    def test_a_press_that_did_not_land_is_pressed_again(self):
        runner = LockdownToggleRunner(misses=1)
        live = LIVE.Session("fixture", {}, runner=runner)
        self.assertTrue(live.set_lockdown(True))
        self.assertEqual(lockdown_presses(runner), 2)
        self.assertEqual(next(item for item in live.ledger if "lockdownToggle" in item)["lockdownToggle"], False)

    def test_an_unreadable_toggle_is_never_pressed_blind(self):
        runner = LockdownToggleRunner(misses=1, unreadable=True)
        live = LIVE.Session("fixture", {}, runner=runner)
        with self.assertRaises(LIVE.RowFailure):
            live.set_lockdown(True)
        self.assertEqual(lockdown_presses(runner), 1)
        runner = LockdownToggleRunner()
        live = LIVE.Session("fixture", {}, runner=runner)
        live.journal_lockdown = lambda: None
        with self.assertRaises(LIVE.RowFailure):
            live.set_lockdown(True)
        reads = [(item["lockdownToggleBeforePress"], item["lockdownToggle"]) for item in live.ledger if "lockdownToggle" in item]
        self.assertEqual(reads, [(1, False), (2, True)], "an unreadable journal reads the toggle before the first press too")
        self.assertEqual(lockdown_presses(runner), 1, "pressed only while the toggle read off")
        self.assertTrue(runner.lockdown)

    def test_the_rows_still_pass_with_a_prompt_journal(self):
        for row in ("M5.3-10", "REBOOT-LOCKDOWN"):
            with self.subTest(row=row):
                runner, result = run8.run_row(row, LockdownToggleRunner())
                self.assertEqual(lockdown_presses(runner), 1)
                self.assertFalse(any("lockdownToggle" in item for item in steps(result)))


class ReplayLeadTests(unittest.TestCase):
    """F2: the dry runs of the lockdown rows replay the lead control the live driver runs, never a trailing tail."""

    RUNNER = replay.module("lead_replay", "verdict-run.py")

    def test_the_replay_mirrors_the_live_lead_kinds(self):
        self.assertEqual(self.RUNNER.LEAD_CONTROL_KINDS, LIVE.LEAD_CONTROL_KINDS)

    def test_lockdown_rows_replay_the_lead_control(self):
        for row in ("M5.3-10", "REBOOT-LOCKDOWN", "ONDEMAND-ETH"):
            with self.subTest(row=row):
                result = self.RUNNER.replay(run8.ROWS[row], run8.TABLE, {})
                scenarios = [window["scenario"] for window in result["states"]]
                self.assertEqual(scenarios[0], "unprotectedLead")
                self.assertNotIn("unprotectedTail", scenarios)
                self.assertEqual(result["tailControlPosition"], "lead")
                self.assertEqual((result["tailControl"]["met"], result["tailControl"]["trailSkipped"]), (True, "lockdownOffNeedsAdmin"))
                self.assertTrue(result["expectationsMet"])

    def test_other_rows_keep_the_trailing_tail(self):
        result = self.RUNNER.replay(run8.ROWS["M5.1-04"], run8.TABLE, {})
        self.assertEqual((result["states"][-1]["scenario"], result["tailControlPosition"]), ("unprotectedTail", "trail"))
        self.assertNotIn("trailSkipped", result["tailControl"])

    def test_a_lead_fixture_without_receipts_fails_the_lockdown_replay(self):
        read = self.RUNNER.read
        def silent(path, hashes, label):
            value = read(path, hashes, label)
            if label == "fixture:unprotected":
                for receiver in value["receiverRecords"]:
                    receiver["observations"] = []
            return value
        with patch.object(self.RUNNER, "read", side_effect=silent):
            result = self.RUNNER.replay(run8.ROWS["M5.3-10"], run8.TABLE, {})
        self.assertFalse(result["tailControl"]["met"])
        self.assertFalse(result["expectationsMet"])


class VerdictSummaryTests(unittest.TestCase):
    """F4, F5, F6: the row's GUI time, its cleanup warnings and its utun capture coverage reach the verdict."""

    def test_gui_seconds_is_the_sum_of_the_gui_commands(self):
        _, result = run8.run_row("M5.3-10", SlowEndRunner())
        gui = [item["end"] - item["start"] for item in steps(result) if item.get("argv", [])[:3] == ["just", "lab", "gui"] and "end" in item]
        self.assertGreater(result["guiSeconds"], 116, "the 116 s End search is GUI time")
        self.assertAlmostEqual(result["guiSeconds"], sum(gui), places=3)

    def test_the_row_limitations_recommend_a_4200_second_alarm(self):
        self.assertTrue(any(text.startswith("Operator alarm: allow 4200 s for this row") for text in run8.ROWS["M5.3-10"]["limitations"]))

    def test_cleanup_warnings_are_named_in_the_verdict(self):
        runner = FailingStepRunner(lambda arg: "verdict-actions.sh diagnostics-stop" in arg)
        _, result = replay.LiveReplayTests().run_recorded("M5.1-04", runner)
        self.assertEqual(len(result["cleanupWarnings"]), 1, result["cleanupWarnings"])
        self.assertTrue(result["cleanupWarnings"][0].startswith("diagnostics-stop: row fixture cleanup failed (RuntimeError)"))
        self.assertEqual([item["operation"] for item in steps(result) if "cleanupWarning" in item], ["diagnostics-stop"])
        runner = FailingStepRunner(lambda arg: arg.endswith("verdict-actions.sh remove-resolver"))
        # The recorded scutil output lacks the custom resolver, so the row itself is unmet; only the warning matters here.
        _, result = replay.LiveReplayTests().run_recorded("M5.4-03", runner, accepted=False)
        self.assertEqual([warning.split(":", 1)[0] for warning in result["cleanupWarnings"]], ["remove-resolver"])
        _, result = replay.LiveReplayTests().run_recorded("M5.1-04")
        self.assertEqual(result["cleanupWarnings"], [])

    def test_the_utun_capture_restarts_after_the_lead_reconnect(self):
        class Runner(run8.Run8Runner):
            def run(self, argv, data=None, timeout=100, env=None):
                if argv[:3] == ["just", "lab", "ssh"] and argv[-1] == "/sbin/ifconfig":
                    return self.handled(argv, env, self.fixture["ifconfig"].encode())
                return super().run(argv, data, timeout, env)
        runner, result = run8.run_row("M5.3-10", Runner())
        lines = run8.commands(runner)
        starts = [(i, c.split()[-2:]) for i, c in enumerate(lines) if "start-capture.sh " in c]
        self.assertEqual([args for _, args in starts], [["en0", "M5-3-10"], ["utun4", "M5-3-10"], ["utun4", "M5-3-10-reconnect"]])
        connect = max(i for i, c in enumerate(lines) if "gui press" in c and "wgex.main.action" in c and i < starts[-1][0])
        lead = next(i for i, c in enumerate(lines) if "--state unprotected" in c)
        self.assertLess(lead, connect)
        self.assertEqual(result["utunCaptureCoverage"], dict(beforeLead=["utun4"], afterReconnect=["utun4"], gap=None))

    def test_a_missing_tunnel_interface_is_the_recorded_coverage_gap(self):
        _, result = run8.run_row("M5.3-10")
        coverage = result["utunCaptureCoverage"]
        self.assertEqual((coverage["afterReconnect"], coverage["gap"].startswith("no interface carries 10.77.0.2")), ([], True))
        self.assertEqual(result["gaps"], [], "evidence only, never a row gap")
        _, result = run8.run_row("REBOOT-LOCKDOWN")
        self.assertIsNone(result["utunCaptureCoverage"], "REBOOT-LOCKDOWN never reconnects")

    def test_start_capture_replaces_only_a_record_whose_tcpdump_ended(self):
        script = (ROOT / "Tools/lab/tart/capture/start-capture.sh").read_text()
        guard = script[script.index('if [[ -e "$state/$iface.pid"'):script.index("stamp=")]
        self.assertIn('kill -0 "$previous" 2>/dev/null; then', guard)
        self.assertIn("echo 'capture already recorded; stop first' >&2", guard)
        self.assertLess(guard.index("exit 1"), guard.index('rm -f "$state/$iface.pid"'))


if __name__ == "__main__":
    unittest.main()
