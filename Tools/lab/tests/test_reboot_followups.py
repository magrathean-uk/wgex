# SPDX-License-Identifier: MIT
"""M1-10v: BOOT-SECRETS without the login relaunch, and the M1-10u fix pass 1 follow-ups (FIX1-VERIFY N-1, N-2, N-3, N-5, N-7).

Each test fails on lab-track a1787eb and passes after the change. Fixtures are rebuilt as raw boot-observe text through the parser and
the live driver's own merge (test_restart_fail_closed helpers), never from a guest. The relaunch-prevention action is run here only
against stubbed `defaults`, `pgrep` and `grep` input; it has never run on a guest. Never a VM."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

import test_restart_fail_closed as base
import test_run8_rows as run8

ROOT, V, LIVE = base.ROOT, base.V, base.LIVE
D, observe, summary, names, secrets, passes, clean_lines = base.D, base.observe, base.summary, base.names, base.secrets, base.passes, base.clean_lines
SCRIPT = base.SCRIPT
ROWS_TEXT = (ROOT / "Tools/lab/rows.json").read_text()
GOOD = base.PREVENTED


def prevention_block():
    return SCRIPT[SCRIPT.index("  prevent-relaunch)"):SCRIPT.index("  boot-observe)")]


def boot_secrets(boot, prevention=GOOD):
    observation = dict(bootIntentBeforeReboot=True, boot=boot)
    if prevention is not None:
        observation["relaunchPrevention"] = prevention
    return {check["name"]: check for check in V.row_checks("boot-secrets", observation)}


class PreventRelaunchGuestTests(unittest.TestCase):
    """The guest action: the loginwindow reopen-state keys, written for the console user and read back, refused while the app runs."""

    def run_block(self, *, app_running=False, write_works=True, listed=0, savesstate="0", relaunch="0", console="labuser", ssh="labuser",
                  clears=False, wgex_listed=False):
        scratch = tempfile.mkdtemp(dir=os.environ["TMPDIR"])
        self.addCleanup(subprocess.run, ["rm", "-rf", scratch])
        log, deleted = Path(scratch) / "defaults.log", Path(scratch) / "deleted"
        entries = "".join('    { BundleID = "com.example.app%d"; },\n' % number for number in range(listed))
        if wgex_listed:
            entries += '    { BundleID = "com.magrathean.WGEXApp"; },\n'
        count = listed + (1 if wgex_listed else 0)
        list_reply = "printf '(\\n%s)\\n' " + shlex.quote(entries) if count else "return 1"
        if clears:   # the saved list is gone once the action has deleted it
            list_reply = f"if [[ -e {deleted} ]]; then return 1; fi; " + list_reply
        pgrep_reply, write_reply = "echo 512" if app_running else "return 1", "return 0" if write_works else "return 1"
        stub = f'''
pgrep() {{ {pgrep_reply}; }}
stat() {{ echo {console}; }}
id() {{ echo {ssh}; }}
defaults() {{
  printf '%s\\n' "$*" >>{log}
  case "$*" in
    *write*) {write_reply} ;;
    *delete*) touch {deleted}; return 0 ;;
    *TALLogoutSavesState*) echo {savesstate} ;;
    *LoginwindowLaunchesRelaunchApps*) echo {relaunch} ;;
    *TALAppsToRelaunchAtLogin*) {list_reply} ;;
  esac
}}
'''
        program = f'set -euo pipefail\naction=prevent-relaunch\n{stub}\ncase "$action" in\n{prevention_block()}\nesac\n'
        result = subprocess.run(["bash", "-c", program], capture_output=True, text=True, env=dict(os.environ, LC_ALL="C"))
        return result, log.read_text() if log.exists() else ""

    def test_the_action_exists_and_writes_the_three_loginwindow_keys_in_the_user_and_the_current_host_domain(self):
        self.assertIn("  prevent-relaunch)", SCRIPT)
        result, calls = self.run_block()
        self.assertEqual(result.returncode, 0, result.stderr)
        for scope in ("", "-currentHost "):
            self.assertIn(f"{scope}write com.apple.loginwindow TALLogoutSavesState -bool false", calls)
            self.assertIn(f"{scope}write com.apple.loginwindow LoginwindowLaunchesRelaunchApps -bool false", calls)
            self.assertIn(f"{scope}delete com.apple.loginwindow TALAppsToRelaunchAtLogin", calls)
        self.assertEqual(result.stdout.splitlines(), ["mechanism=loginwindow-reopen-state", "usermatch=yes", "relaunchlistbefore=0", "relaunchlistwgex=no",
                                                      "savesstate=false", "relaunchapps=false", "relaunchlist=0", "app=none"])

    def test_it_never_touches_the_app_the_daemon_launchd_or_the_network(self):
        block = prevention_block()
        for word in ("launchctl", "ifconfig", "route", "pfctl", "networksetup", "scutil", "kill", "WGEXDaemon", "LaunchDaemons", "sudo", "rm "):
            self.assertNotIn(word, block, word)

    def test_it_refuses_while_the_app_is_running(self):
        result, calls = self.run_block(app_running=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, "", "nothing is written while the app still runs")
        self.assertIn("app=running", result.stdout)

    def test_l1_the_saved_relaunch_list_is_counted_before_it_is_deleted_and_whether_it_held_wgex_with_fixed_tokens_only(self):
        result, _ = self.run_block(listed=2, wgex_listed=True, clears=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        lines = result.stdout.splitlines()
        self.assertIn("relaunchlistbefore=3", lines)
        self.assertIn("relaunchlistwgex=yes", lines)
        self.assertIn("relaunchlist=0", lines, "the count after the delete is read separately and is 0")
        for text in ("com.example", "com.magrathean", "BundleID", "/"):
            self.assertNotIn(text, result.stdout, "no bundle id, path or list text leaves the guest")
        other, _ = self.run_block(listed=2, clears=True)
        self.assertIn("relaunchlistbefore=2", other.stdout.splitlines())
        self.assertIn("relaunchlistwgex=no", other.stdout.splitlines())
        self.assertEqual(self.run_block(clears=True)[0].stdout.splitlines()[2:4], ["relaunchlistbefore=0", "relaunchlistwgex=no"])

    def test_l6_it_refuses_unless_the_console_user_is_the_ssh_user_and_writes_nothing(self):
        for label, kwargs in (("another user", dict(console="someoneelse")), ("nobody at the console", dict(console="root")),
                              ("empty", dict(console=""))):
            with self.subTest(label):
                result, calls = self.run_block(**kwargs)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, "", "nothing is read or written for another user")
                self.assertEqual(result.stdout.splitlines(), ["mechanism=loginwindow-reopen-state", "usermatch=no", "app=none"])
        match, _ = self.run_block()
        self.assertIn("usermatch=yes", match.stdout.splitlines())
        self.assertIn("stat -f %Su /dev/console", prevention_block())
        self.assertIn("id -un", prevention_block())

    def test_a_key_that_reads_back_wrong_is_reported_not_assumed(self):
        for label, kwargs, expected in (("saves state still on", dict(savesstate="1"), "savesstate=unconfirmed"),
                                        ("relaunch still on", dict(relaunch="1"), "relaunchapps=unconfirmed"),
                                        ("saved list not empty", dict(listed=2), "relaunchlist=2")):
            with self.subTest(label):
                result, _ = self.run_block(**kwargs)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(expected, result.stdout)

    def test_a_failed_write_fails_the_action(self):
        result, _ = self.run_block(write_works=False)
        self.assertNotEqual(result.returncode, 0)


class ParsePreventionTests(unittest.TestCase):
    OK = ("mechanism=loginwindow-reopen-state\nusermatch=yes\nrelaunchlistbefore=1\nrelaunchlistwgex=yes\nsavesstate=false\nrelaunchapps=false\n"
          "relaunchlist=0\napp=none\n")

    def test_a_clean_reply_is_applied_and_records_the_list_before_the_delete(self):
        value = V.parse_relaunch_prevention(self.OK)
        self.assertEqual(value, dict(mechanism="loginwindow-reopen-state", userMatch=True, savesLogoutState=False, relaunchesApps=False, savedRelaunchEntries=0,
                                     savedRelaunchEntriesBefore=1, savedListHeldWGEX=True, duplicateKeys=[], applied=True))

    def test_anything_else_is_not_applied(self):
        for label, text in (("empty", ""), ("unconfirmed", self.OK.replace("savesstate=false", "savesstate=unconfirmed")),
                            ("list not empty", self.OK.replace("relaunchlist=0", "relaunchlist=3")),
                            ("app running", self.OK.replace("app=none", "app=running")),
                            ("no mechanism", self.OK.replace("mechanism=loginwindow-reopen-state\n", "")),
                            ("another mechanism name", self.OK.replace("loginwindow-reopen-state", "something-else")),
                            ("another console user", self.OK.replace("usermatch=yes", "usermatch=no")),
                            ("no usermatch line", self.OK.replace("usermatch=yes\n", ""))):
            with self.subTest(label):
                self.assertIs(V.parse_relaunch_prevention(text)["applied"], False)

    def test_l1_the_list_state_before_the_delete_is_recorded_and_garbage_is_none_not_a_guess(self):
        none = V.parse_relaunch_prevention(self.OK.replace("relaunchlistbefore=1", "relaunchlistbefore=many").replace("relaunchlistwgex=yes", "relaunchlistwgex=maybe"))
        self.assertIsNone(none["savedRelaunchEntriesBefore"])
        self.assertIsNone(none["savedListHeldWGEX"])
        self.assertIs(none["applied"], True, "the before-state is evidence, not part of the applied decision")
        no = V.parse_relaunch_prevention(self.OK.replace("relaunchlistwgex=yes", "relaunchlistwgex=no").replace("relaunchlistbefore=1", "relaunchlistbefore=0"))
        self.assertEqual((no["savedRelaunchEntriesBefore"], no["savedListHeldWGEX"]), (0, False))

    def test_n2_a_key_printed_twice_is_refused_whichever_value_comes_last(self):
        for label, text in (("app running then none", "app=running\n" + self.OK), ("app none then running", self.OK + "app=running\n"),
                            ("savesstate unconfirmed then false", "savesstate=unconfirmed\n" + self.OK),
                            ("two mechanism lines", self.OK + "mechanism=loginwindow-reopen-state\n")):
            with self.subTest(label):
                value = V.parse_relaunch_prevention(text)
                self.assertIs(value["applied"], False)
                self.assertTrue(value["duplicateKeys"], value)
        self.assertEqual(V.parse_relaunch_prevention("app=running\n" + self.OK)["duplicateKeys"], ["app"])


class RelaunchPreventedCheckTests(unittest.TestCase):
    def boot(self, *, app=None, **keys):
        return summary(observe(clean_lines(), app=app, **keys))

    def test_prevention_applied_and_no_app_process_after_boot_passes_the_whole_row(self):
        boot = self.boot()
        checks = boot_secrets(boot)
        self.assertTrue(checks["relaunchPrevented"]["met"], checks["relaunchPrevented"])
        self.assertEqual(checks["relaunchPrevented"]["mechanism"], "loginwindow-reopen-state")
        self.assertTrue(all(check["met"] for check in checks.values()), [name for name, check in checks.items() if not check["met"]])

    def test_an_app_process_that_appears_anyway_is_relaunchNotPrevented_even_when_protected_first(self):
        boot = self.boot(app=56)          # app earliest start D+3, protected D+5: protected after, so both checks fail
        checks = boot_secrets(boot)
        self.assertFalse(checks["relaunchPrevented"]["met"])
        self.assertTrue(checks["relaunchPrevented"]["gap"].startswith("relaunchNotPrevented:"), checks["relaunchPrevented"])
        self.assertIn("loginwindow-reopen-state", checks["relaunchPrevented"]["gap"])
        self.assertFalse(checks["daemonSecretsBeforeApp"]["met"])
        self.assertIn("protectedOnlyAfterAppSeen", checks["daemonSecretsBeforeApp"]["gap"], "the named gap for runs where the app appears is kept")
        late = summary(observe(clean_lines(), app=5))   # app earliest start D+54, long after protected at D+5
        late_checks = boot_secrets(late)
        self.assertTrue(late_checks["daemonSecretsBeforeApp"]["met"], "timing alone would pass this run")
        self.assertFalse(late_checks["relaunchPrevented"]["met"])
        self.assertFalse(all(check["met"] for check in late_checks.values()))

    def test_an_app_process_with_an_unreadable_start_fails_closed(self):
        boot = self.boot()
        boot.update(appRunningAfterBoot=True, appStartedAt=None)
        self.assertFalse(boot_secrets(boot)["relaunchPrevented"]["met"])
        boot.update(appRunningAfterBoot=None, appStartedAt=None)
        check = boot_secrets(boot)["relaunchPrevented"]
        self.assertFalse(check["met"])
        self.assertIn("no readable post-boot process sample", check["gap"])

    def test_no_recorded_prevention_is_not_a_pass_and_says_so(self):
        for label, value in (("missing", None), ("not applied", dict(GOOD, applied=False)), ("no mechanism", dict(GOOD, mechanism="")),
                             ("applied asserted, another mechanism", dict(GOOD, mechanism="anything")),
                             ("applied asserted, logout state saved", dict(GOOD, savesLogoutState=True)),
                             ("applied asserted, relaunch apps on", dict(GOOD, relaunchesApps=True)),
                             ("applied asserted, entries left", dict(GOOD, savedRelaunchEntries=2)),
                             ("applied asserted, entries unknown", dict(GOOD, savedRelaunchEntries=None)),
                             ("applied asserted, another console user", dict(GOOD, userMatch=False)),
                             ("applied asserted, no user match recorded", {key: item for key, item in GOOD.items() if key != "userMatch"}),
                             ("applied asserted, a key printed twice", dict(GOOD, duplicateKeys=["app"]))):
            with self.subTest(label):
                check = boot_secrets(self.boot(), value)["relaunchPrevented"]
                self.assertFalse(check["met"])
                self.assertTrue(check["gap"].startswith("relaunchPreventionNotApplied:"), check)

    def test_l2_applied_is_recomputed_from_the_facts_and_never_asserted_alone(self):
        record = dict(GOOD)
        self.assertTrue(boot_secrets(self.boot(), record)["relaunchPrevented"]["met"])
        self.assertFalse(boot_secrets(self.boot(), dict(record, applied=True, savesLogoutState=True))["relaunchPrevented"]["met"])
        self.assertFalse(boot_secrets(self.boot(), {key: item for key, item in record.items() if key != "applied"})["relaunchPrevented"]["met"],
                         "the facts alone do not stand in for the recorded confirmation either")

    def test_l_b_one_app_log_count_per_required_sample(self):
        """M1-10v FIX1-VERIFY L-B (M1-10t): a count list shorter than the required samples is a named gap, never a pass."""
        control = self.boot()
        self.assertEqual(control["appLogLinesSamples"], [0, 0])
        self.assertTrue(boot_secrets(control)["relaunchPrevented"]["met"])
        for label, counts in (("one of two", [0]), ("none", []), ("not a list", "00"), ("absent", None)):
            with self.subTest(label):
                boot = self.boot()
                boot["appLogLinesSamples"] = counts
                check = boot_secrets(boot)["relaunchPrevented"]
                self.assertFalse(check["met"], check)
                self.assertIn("relaunchNotPrevented not excluded", check["gap"])
        boot = self.boot()
        boot["appLogLinesSamples"] = [0]
        self.assertIn("1 app log count(s) recorded for 2 required boot samples", boot_secrets(boot)["relaunchPrevented"]["gap"])
        planned = self.boot()
        planned.update(bootObserveSamples=3, bootObservePlanned=3, appLogLinesSamples=[0, 0])
        self.assertFalse(boot_secrets(planned)["relaunchPrevented"]["met"], "three planned samples need three counts")
        planned["appLogLinesSamples"] = [0, 0, 0]
        self.assertTrue(boot_secrets(planned)["relaunchPrevented"]["met"])

    def test_m3_no_running_app_but_an_app_start_time_on_record_is_not_met(self):
        boot = self.boot()
        boot.update(appRunningAfterBoot=False, appStartedAt=D + 3)
        check = boot_secrets(boot)["relaunchPrevented"]
        self.assertFalse(check["met"])
        self.assertTrue(check["gap"].startswith("relaunchNotPrevented:"), check)

    def test_h1_one_readable_boot_sample_is_not_a_pass_and_names_the_uncovered_window(self):
        for label, texts in (("the second sample lost", (observe(clean_lines(), app=None), None)),
                             ("the first sample lost", (None, observe(clean_lines(), app=None)))):
            with self.subTest(label):
                boot = summary(*texts)
                self.assertEqual((boot["bootObserveSamples"], boot["bootObservePlanned"]), (1, 2))
                self.assertIs(boot["appRunningAfterBoot"], False, "the one readable sample saw no app: the old verdict passed this")
                checks = boot_secrets(boot)
                self.assertFalse(checks["relaunchPrevented"]["met"])
                self.assertEqual(checks["relaunchPrevented"]["gap"].split(",")[0], "no-app window not covered: 1 of 2 boot samples readable")
                self.assertFalse(all(check["met"] for check in checks.values()))
                self.assertTrue(checks["daemonSecretsBeforeApp"]["met"], "every other check still holds on the one sample")

    def test_h1_a_single_planned_sample_and_no_sample_at_all_are_not_a_pass(self):
        boot = summary(observe(clean_lines(), app=None), observe(clean_lines(), app=None))
        boot.update(bootObserveSamples=1, bootObservePlanned=1)
        check = boot_secrets(boot)["relaunchPrevented"]
        self.assertFalse(check["met"])
        self.assertIn("1 of 2 boot samples readable", check["gap"])
        boot = summary(None, None)
        self.assertEqual((boot["bootObserveSamples"], boot["appRunningAfterBoot"]), (0, None))
        self.assertIn("no readable post-boot process sample", boot_secrets(boot)["relaunchPrevented"]["gap"])

    def test_h1_the_last_sample_must_be_at_or_after_the_first_protected_status(self):
        early = summary(observe(clean_lines(), app=None, now=D + 4), observe(clean_lines(), app=None, now=D + 4.5))
        check = boot_secrets(early)["relaunchPrevented"]
        self.assertFalse(check["met"])
        self.assertIn("last boot sample", check["gap"])
        exact = summary(observe(clean_lines(), app=None, now=D + 5), observe(clean_lines(), app=None, now=D + 5))
        self.assertTrue(boot_secrets(exact)["relaunchPrevented"]["met"], "a sample at the first protected stamp reaches it")
        boot = self.boot()
        boot["lastBootSampleAt"] = None
        self.assertFalse(boot_secrets(boot)["relaunchPrevented"]["met"])

    def test_m1_app_log_lines_with_no_app_process_at_either_sample_is_not_a_pass(self):
        for label, texts in (("3 lines at the end sample", (observe(clean_lines(), app=None, applog=0), observe(clean_lines(), app=None, applog=3))),
                             ("3 lines at the first sample only", (observe(clean_lines(), app=None, applog=3), observe(clean_lines(), app=None, applog=0)))):
            with self.subTest(label):
                boot = summary(*texts)
                self.assertIs(boot["appRunningAfterBoot"], False)
                self.assertIsNone(boot["appStartedAt"])
                checks = boot_secrets(boot)
                self.assertFalse(checks["relaunchPrevented"]["met"])
                self.assertTrue(checks["relaunchPrevented"]["gap"].startswith("relaunchNotPrevented: app log activity during the window: 3 "), checks["relaunchPrevented"])
                self.assertFalse(all(check["met"] for check in checks.values()))

    def test_m1_an_unread_app_log_count_is_never_zero(self):
        for label, texts in (("unknown at the end", (observe(clean_lines(), app=None), observe(clean_lines(), app=None, applog="unknown"))),
                             ("absent (an older guest script)", (observe(clean_lines(), app=None, applog=None), observe(clean_lines(), app=None, applog=None)))):
            with self.subTest(label):
                boot = summary(*texts)
                check = boot_secrets(boot)["relaunchPrevented"]
                self.assertFalse(check["met"])
                self.assertIn("app log lines", check["gap"])
                self.assertIn("not read", check["gap"])
        # M1-10t part 3 (VERIFY L-3): unknown at the first sample only is a gap too; every required count must be readable.
        known = summary(observe(clean_lines(), app=None, applog="unknown"), observe(clean_lines(), app=None, applog=0))
        check = boot_secrets(known)["relaunchPrevented"]
        self.assertFalse(check["met"], "unknown at the first sample only: every count up to the required samples must be readable")
        self.assertIn("not read at boot sample(s) 1 of 2", check["gap"])

    def test_l5_the_wording_names_what_is_known_and_not_the_cause(self):
        gap = boot_secrets(self.boot(app=56))["relaunchPrevented"]["gap"]
        self.assertIn("an app process appeared despite the recorded prevention", gap)
        self.assertIn("what started it was not measured", gap)
        self.assertNotIn("started by something that mechanism does not cover", gap)


class DriverTests(unittest.TestCase):
    def runner(self):
        runner = run8.BootSecretsTests().runner()
        return runner

    def observation(self, result):
        return json.loads((Path(result["buildRoot"]) / "row-observation.json").read_text())

    def test_boot_secrets_prevents_the_relaunch_after_the_quit_and_before_the_reboot_and_records_the_mechanism(self):
        runner = self.runner()
        _, result = run8.run_row("BOOT-SECRETS", runner)
        lines = run8.commands(runner)
        quit_at = max(i for i, c in enumerate(lines) if "System Events" in c and "Quit WGEX" in c)
        prevent = next(i for i, c in enumerate(lines) if c.endswith("verdict-actions.sh prevent-relaunch"))
        pid = next(i for i, c in enumerate(lines) if c.endswith("verdict-actions.sh daemon-pid"))
        reboot = next(i for i, c in enumerate(lines) if c.endswith("verdict-actions.sh reboot"))
        self.assertLess(quit_at, prevent)
        self.assertLess(prevent, reboot)
        self.assertLess(prevent, pid)
        stored = self.observation(result)["relaunchPrevention"]
        self.assertEqual(stored["mechanism"], "loginwindow-reopen-state")
        self.assertIs(stored["applied"], True)
        self.assertTrue(run8.check(result, "relaunchPrevented")["met"])
        self.assertIs(result["bootObservation"]["appRunningAfterBoot"], False)
        self.assertIsNone(result["bootObservation"]["appStartedAt"])

    def test_an_app_that_appears_after_the_prevention_fails_the_row_naming_relaunchNotPrevented(self):
        runner = self.runner()
        runner.app_after_boot = "00:20"
        _, result = run8.run_row("BOOT-SECRETS", runner, accepted=False)
        self.assertFalse(run8.check(result, "relaunchPrevented")["met"])
        self.assertTrue(any(gap.startswith("relaunchNotPrevented:") for gap in result["gaps"]), result["gaps"])
        self.assertFalse(result["rowCompleted"])

    def test_a_prevention_that_fails_stops_the_row_before_the_reboot_with_a_named_gap(self):
        runner = self.runner()
        runner.relaunch_prevention = "failed"
        _, result = run8.run_row("BOOT-SECRETS", runner, accepted=False)
        self.assertTrue(any(gap.startswith("relaunchPreventionFailed:") for gap in result["gaps"]), result["gaps"])
        self.assertFalse(any(c.endswith("verdict-actions.sh reboot") for c in run8.commands(runner)))
        runner = self.runner()
        runner.relaunch_prevention = "silent"
        _, result = run8.run_row("BOOT-SECRETS", runner, accepted=False)
        self.assertTrue(any(gap.startswith("relaunchPreventionFailed:") for gap in result["gaps"]), result["gaps"])

    def test_h1_a_second_boot_observe_that_fails_is_a_named_not_pass_on_both_failure_paths(self):
        for label, mode in (("RuntimeError: the SSH call fails", "runtime"), ("ValueError: a reply the parser rejects", "value")):
            with self.subTest(label):
                runner = self.runner()
                runner.boot_observe_failures = {2: mode}
                _, result = run8.run_row("BOOT-SECRETS", runner, accepted=False)
                self.assertEqual(runner.boot_observe_calls, 2)
                found = run8.check(result, "relaunchPrevented")
                self.assertFalse(found["met"])
                self.assertEqual((found["bootObserveSamples"], found["bootObserveRequired"]), (1, 2))
                self.assertTrue(any(gap.startswith("no-app window not covered: 1 of 2 boot samples readable") for gap in result["gaps"]), result["gaps"])
                self.assertIs(result["bootObservation"]["appRunningAfterBoot"], False, "the sample that was read saw no app: the old verdict passed this")
                self.assertFalse(result["rowCompleted"])

    def test_h1_the_first_sample_lost_is_the_same_gap(self):
        runner = self.runner()
        runner.boot_observe_failures = {1: "runtime"}
        _, result = run8.run_row("BOOT-SECRETS", runner, accepted=False)
        self.assertTrue(any(gap.startswith("no-app window not covered: 1 of 2 boot samples readable") for gap in result["gaps"]), result["gaps"])

    def test_m1_app_log_lines_with_the_app_absent_at_both_samples_fail_the_row_naming_relaunchNotPrevented(self):
        runner = self.runner()
        runner.app_log_lines = 3
        _, result = run8.run_row("BOOT-SECRETS", runner, accepted=False)
        self.assertIs(result["bootObservation"]["appRunningAfterBoot"], False)
        self.assertTrue(any(gap.startswith("relaunchNotPrevented: app log activity during the window: 3 ") for gap in result["gaps"]), result["gaps"])
        self.assertFalse(result["rowCompleted"])
        runner = self.runner()
        runner.app_log_lines = None
        _, result = run8.run_row("BOOT-SECRETS", runner, accepted=False)
        self.assertFalse(run8.check(result, "relaunchPrevented")["met"], "an unread count is never zero")

    def test_l1_the_list_state_before_the_delete_reaches_the_row_observation(self):
        runner = self.runner()
        _, result = run8.run_row("BOOT-SECRETS", runner)
        stored = self.observation(result)["relaunchPrevention"]
        self.assertEqual((stored["savedRelaunchEntriesBefore"], stored["savedListHeldWGEX"], stored["userMatch"]), (1, True, True))

    def test_l6_a_console_user_mismatch_stops_the_row_before_the_reboot_with_relaunchPreventionFailed(self):
        runner = self.runner()
        runner.relaunch_prevention = "usermismatch"
        _, result = run8.run_row("BOOT-SECRETS", runner, accepted=False)
        self.assertTrue(any(gap.startswith("relaunchPreventionFailed:") for gap in result["gaps"]), result["gaps"])
        self.assertFalse(any(c.endswith("verdict-actions.sh reboot") for c in run8.commands(runner)))

    def test_the_other_reboot_rows_keep_their_behaviour_and_never_prevent_the_relaunch(self):
        for row in ("REBOOT-INTENT", "REBOOT-LOCKDOWN"):
            with self.subTest(row):
                runner = run8.Run8Runner()
                runner.app_after_boot = "00:20"
                run8.run_row(row, runner)
                self.assertFalse(any("prevent-relaunch" in c for c in run8.commands(runner)))

    def test_no_boot_secrets_step_after_the_reboot_uses_the_app_gui(self):
        runner = self.runner()
        run8.run_row("BOOT-SECRETS", runner)
        lines = run8.commands(runner)
        reboot = next(i for i, c in enumerate(lines) if c.endswith("verdict-actions.sh reboot"))
        after = lines[reboot:]
        self.assertFalse(any(c.startswith("just lab gui") or "open -a WGEX" in c or "System Events" in c for c in after), "the tail runs through the CLI over SSH")


class ReadmeAndWordingTests(unittest.TestCase):

    def test_the_boot_secrets_row_states_the_prevention_and_the_timing_only_rule(self):
        row = json.loads(ROWS_TEXT)["rows"]["BOOT-SECRETS"]
        text = json.dumps(row)
        self.assertIn("loginwindow-reopen-state", text)
        self.assertIn("relaunchNotPrevented", text)
        self.assertIn("protectedOnlyAfterAppSeen", text)


class InstallModeTests(unittest.TestCase):
    """N-1: install mode kickstarts the daemon, so the snapshot daemon S logs shortly before the installed one I, both before the reboot."""
    S, I = 250, 282
    LINES = [(D - 40, "active", "protected", 250), (D - 30, "active", "protected", 250), (D - 20, "active", "protected", 282)] + clean_lines()

    def test_the_kickstarted_snapshot_daemon_is_not_a_replacement_when_the_recorded_pre_restart_pid_logged_after_it(self):
        text = observe(self.LINES, app=None)
        boot = summary(text, text, pre=self.I)
        found = names(boot)
        self.assertNotIn("postRestartDaemonReplaced", found)
        self.assertEqual(found, [])
        self.assertTrue(passes(boot), secrets(boot))
        self.assertEqual(V.restart_timeline(boot)["observations"]["excludedPids"], [250, 282])
        intent = {check["name"]: check for check in V.reboot_intent_checks(boot)}
        self.assertTrue(intent["postRestartTimelineConsistent"]["met"])

    def test_a4_a_daemon_that_logs_after_the_recorded_pre_restart_pid_is_still_a_replacement(self):
        boot = base.ReplacedDaemonTests().boot()
        self.assertIn("postRestartDaemonReplaced", names(boot))

    def test_an_excluded_pid_dated_after_the_last_line_of_the_recorded_pre_restart_pid_is_a_replacement(self):
        lines = [(D - 40, "active", "protected", 250), (D - 20, "active", "protected", 282), (D - 19, "active", "unprotected", 250)] + clean_lines()
        text = observe(lines)
        boot = summary(text, text, pre=self.I)
        self.assertIn("postRestartDaemonReplaced", names(boot))
        self.assertFalse(passes(boot))

    def test_a_recorded_pre_restart_pid_that_logged_nothing_does_not_excuse_other_excluded_pids(self):
        text = observe([(D - 40, "active", "protected", 250)] + clean_lines())
        boot = summary(text, text, pre=282)
        self.assertIn("postRestartDaemonReplaced", names(boot))

    def test_with_the_pre_restart_pid_unrecorded_two_excluded_pids_still_fail_closed(self):
        text = observe(self.LINES)
        boot = summary(text, text, pre=None)
        found = dict(V.restart_timeline(boot)["diagnostics"])
        self.assertIn("postRestartDaemonReplaced", found)
        self.assertIn("not recorded", found["postRestartDaemonReplaced"])

    def test_m6_an_excluded_pid_with_a_line_at_exactly_the_recorded_pids_last_stamp_is_a_replacement_fail_closed(self):
        text = observe([(D - 30, "active", "protected", 401), (D - 20, "active", "protected", 282), (D - 20, "active", "unprotected", 401)] + clean_lines())
        boot = summary(text, text, pre=self.I)
        self.assertIn("postRestartDaemonReplaced", names(boot), "a tie is not 'before': >=, fail closed")
        self.assertFalse(passes(boot))
        before = observe([(D - 30, "active", "protected", 401), (D - 20, "active", "protected", 282), (D - 20.001, "active", "unprotected", 401)] + clean_lines())
        self.assertEqual(names(summary(before, before, pre=self.I)), [], "strictly before the recorded pid's last line stays an install-mode snapshot daemon")

    def test_l4_the_relaxation_leans_on_noRestartLoop_and_a_readable_runs_count(self):
        """The run 8g early-boot clock dates a post-restart daemon (401) 10 s before the recorded pre-restart pid's (282) last line."""
        lines = [(D - 30, "active", "protected", 401), (D - 20, "active", "protected", 282)] + clean_lines()
        one = observe(lines, runs=1, app=None)
        self.assertEqual(names(summary(one, one, pre=self.I)), [], "no diagnostic on the early-boot pattern")
        self.assertTrue(passes(summary(one, one, pre=self.I)))
        for label, runs in (("launchd started the daemon twice", 2), ("runs unreadable", "unknown")):
            with self.subTest(label):
                text = observe(lines, runs=runs, app=None)
                boot = summary(text, text, pre=self.I)
                self.assertFalse(secrets(boot)["noRestartLoop"]["met"])
                self.assertFalse(passes(boot))
        source = (ROOT / "Tools/lab/verdict.py").read_text()
        self.assertIn("leans on noRestartLoop", source)
        self.assertIn("run 8g early-boot clock", source)
        self.assertIn("daemonRuns None", source)

    def test_the_one_excluded_pid_cases_are_unchanged(self):
        text = observe([(D - 20, "active", "protected", 282)] + clean_lines())
        for pre in (282, None):
            self.assertEqual(names(summary(text, text, pre=pre)), [])


class UnknownAppStartTests(unittest.TestCase):
    """N-2: an app pid whose etime did not parse is app=unknown, which reads as running with no start time (fails closed)."""
    LOOP = base.observe_loop()

    def run_loop(self, stub):
        return subprocess.run(["bash", "-c", "set -euo pipefail\n" + stub + "\n" + self.LOOP], capture_output=True, text=True,
                              env=dict(os.environ, LC_ALL="C", TZ="UTC")).stdout

    def test_the_guest_prints_app_unknown_when_the_app_pid_exists_but_its_etime_does_not_parse(self):
        pgrep = 'pgrep() { case "$*" in *WGEXDaemon*) echo 336 ;; *) echo 567 ;; esac; }\n'
        out = self.run_loop(pgrep + 'ps() { case "$*" in *"-p 336"*"etime"*) echo "01:05" ;; *) return 1 ;; esac; }')
        self.assertIn("app=unknown\n", out)
        self.assertNotIn("app=none", out)
        self.assertNotIn("applstart", out)
        garbled = self.run_loop(pgrep + 'ps() { case "$*" in *"-p 336"*"etime"*) echo "01:05" ;; *"-p 567"*"etime"*) echo "soon" ;; *) return 1 ;; esac; }')
        self.assertIn("app=unknown\n", garbled)

    def test_no_app_process_stays_app_none_and_a_parsed_etime_is_unchanged(self):
        out = self.run_loop('pgrep() { case "$*" in *WGEXDaemon*) echo 336 ;; *) return 1 ;; esac; }\nps() { echo "01:05"; }')
        self.assertIn("app=none\n", out)
        ok = self.run_loop('pgrep() { echo 512; }\nps() { case "$*" in *etime*) echo "01:05" ;; *lstart*) echo "Sat Oct  3 04:49:31 2026" ;; esac; }')
        self.assertIn("app=01:05\n", ok)

    def test_unknown_is_running_with_no_start_and_the_verdict_fails_closed(self):
        text = observe(clean_lines(), app=None, head=())
        text = text.replace("app=none", "app=unknown")
        value = V.parse_boot_observe(text)
        self.assertIs(value["appRunning"], True)
        self.assertIsNone(value["appStartedAt"])
        boot = summary(text, text)
        self.assertIs(boot["appRunningAfterBoot"], True)
        self.assertIsNone(boot["appStartedAt"])
        self.assertFalse(V.boot_report(boot)["protectedBeforeAppSeen"])
        self.assertFalse(passes(boot))
        self.assertFalse(boot_secrets(boot)["daemonSecretsBeforeApp"]["met"])
        self.assertFalse(boot_secrets(boot)["relaunchPrevented"]["met"])


class AppLogCountGuestTests(unittest.TestCase):
    """M1 (VERIFY B): the guest's count of the app's own unified-log lines since the post-restart daemon's start. `/usr/bin/log` is
    replaced by a stub function of the same arguments (a path cannot be stubbed); everything else in the block is the real text."""
    BLOCK = SCRIPT[SCRIPT.index("  boot-observe)"):SCRIPT.index("  anchor-rules)")]
    NOW = 1793500060

    def run_block(self, *, daemon="01:00", app_lines=3, log_works=True):
        scratch = tempfile.mkdtemp(dir=os.environ["TMPDIR"])
        self.addCleanup(subprocess.run, ["rm", "-rf", scratch])
        calls = Path(scratch) / "log.calls"
        body = ('printf "Filtering the log data using \\"process == WGEX\\"\\nTimestamp               Ty Process[PID:TID]\\n"\n'
                + "".join(f'  printf "2026-11-01 10:00:0{n}.000 Df WGEX[777:1] [com.magrathean.WGEXApp:app] PRIVATE-LINE-TEXT-{n}\\n"\n' for n in range(app_lines))
                + '  printf "continuation line without a stamp\\n"\n')
        stub = f'''
now() {{ echo {self.NOW}.250; }}
sysctl() {{ echo "{{ sec = {self.NOW - 90}, usec = 0 }} Sat Nov  1 10:00:00 2026"; }}
pgrep() {{ case "$*" in *WGEXDaemon*) echo 336 ;; *) return 1 ;; esac; }}
ps() {{ if [[ "{daemon}" == none ]]; then return 1; fi; echo " {daemon}"; }}
logstub() {{
  printf '%s\\n' "$*" >>{calls}
  {"return 1" if not log_works else ""}
  case "$*" in
    *'process == "WGEX"'*)
{body}      ;;
  esac
}}
'''
        block = self.BLOCK.replace("/usr/bin/log show", "logstub")
        program = f'set -euo pipefail\naction=boot-observe\n{stub}\ncase "$action" in\n{block}\nesac\n'
        result = subprocess.run(["bash", "-c", program], capture_output=True, text=True, env=dict(os.environ, LC_ALL="C", TZ="UTC"))
        return result, calls.read_text() if calls.exists() else ""

    def test_the_guest_prints_only_the_count_of_stamped_app_lines_never_their_content(self):
        result, calls = self.run_block(app_lines=3)
        self.assertIn("appLogLines=3\n", result.stdout)
        self.assertNotIn("PRIVATE-LINE-TEXT", result.stdout)
        self.assertNotIn("continuation line", result.stdout)
        self.assertNotIn("Filtering the log data", result.stdout)
        self.assertEqual(self.run_block(app_lines=0)[0].stdout.count("appLogLines=0\n"), 1, "header lines and unstamped lines are not counted")

    def test_the_predicate_matches_the_apps_own_process_exactly_and_the_window_starts_at_the_daemons_start(self):
        _, calls = self.run_block(daemon="01:00")
        app_call = next(line for line in calls.splitlines() if 'process == "WGEX"' in line)
        self.assertNotIn("WGEXDaemon", app_call)
        self.assertNotIn("CONTAINS", app_call.upper())
        self.assertNotIn("BEGINSWITH", app_call.upper())
        self.assertNotIn("[c]", app_call)
        expected = subprocess.run(["date", "-r", str(self.NOW - 60 - 5), "+%Y-%m-%d %H:%M:%S"], capture_output=True, text=True, env=dict(os.environ, TZ="UTC")).stdout.strip()
        self.assertIn(f"--start {expected} ", app_call + " ", "daemon start (etime) minus the 5 s margin, not the 300 s margin before boottime")
        self.assertIn("--info", app_call)
        days, _ = self.run_block(daemon="1-00:00:05")
        expected_days = subprocess.run(["date", "-r", str(self.NOW - 86405 - 5), "+%Y-%m-%d %H:%M:%S"], capture_output=True, text=True, env=dict(os.environ, TZ="UTC")).stdout.strip()
        self.assertIn(expected_days, "".join(self.run_block(daemon="1-00:00:05")[1]))

    def test_no_daemon_start_or_an_unreadable_log_is_unknown_never_zero(self):
        none, calls = self.run_block(daemon="none")
        self.assertIn("appLogLines=unknown\n", none.stdout)
        self.assertNotIn('process == "WGEX"', calls, "no window can be named without the daemon's start")
        garbled = self.run_block(daemon="soon")[0]
        self.assertIn("appLogLines=unknown\n", garbled.stdout)
        failed = self.run_block(log_works=False)[0]
        self.assertIn("appLogLines=unknown\n", failed.stdout)

    def test_the_count_is_in_the_head_the_parser_reads_and_unknown_parses_to_none(self):
        self.assertEqual(V.parse_boot_observe(observe(clean_lines(), applog=3))["appLogLines"], 3)
        self.assertIsNone(V.parse_boot_observe(observe(clean_lines(), applog="unknown"))["appLogLines"])
        self.assertIsNone(V.parse_boot_observe(observe(clean_lines(), applog=None))["appLogLines"])
        self.assertIsNone(V.parse_boot_observe(observe(clean_lines(), applog="-1"))["appLogLines"])

    def test_the_process_name_is_the_apps_executable_not_the_daemons_or_the_clis(self):
        project = (ROOT / "project.yml").read_text()
        for target, name in (("WGEXMac", "WGEX"), ("WGEXDaemon", "WGEXDaemon"), ("WGEXCLI", "wgex")):
            body = project[project.index(f"  {target}:\n"):]
            self.assertIn(f"PRODUCT_NAME: {name}\n", body[:body.index("\n\n")], target)


class ExplicitRestartTests(unittest.TestCase):
    """N-5: a daemon already active may be restarted by an explicit start (Lifecycle.swift:38-39, :106): active/protected is directly
    followed by the preparing of a new attempt with no status in between. With the log order recorded that order is legitimate; the
    impossible-order failure stays where the log order disagrees with the stamps or is absent (stored captures)."""
    RESTART = clean_lines() + [(D + 7, "preparing", "blocked", 336), (D + 8, "configuring", "blocked", 336), (D + 9, "active", "protected", 336)]

    def test_a_legitimate_explicit_restart_from_active_is_not_a_failure_when_the_log_order_agrees_with_the_stamps(self):
        boot = summary(observe(self.RESTART, app=None))
        self.assertEqual(names(boot), [])
        self.assertTrue(V.restart_timeline(boot)["observations"]["logOrderRecorded"])
        self.assertTrue(passes(boot), secrets(boot))
        intent = {check["name"]: check for check in V.reboot_intent_checks(boot)}
        self.assertTrue(intent["postRestartTimelineConsistent"]["met"])

    def test_a1_with_the_log_order_recorded_still_names_both_the_step_and_the_impossible_attempt_order(self):
        boot = summary(observe(base.ClockStepTests.A1, app=None))
        found = names(boot)
        self.assertIn("clockStepped", found)
        self.assertIn("activeBeforeAttemptSteps", found, "the log shows the attempt lines before the active line that the stamps place first")
        self.assertFalse(passes(boot))

    def test_a1x_a_step_back_after_the_attempt_lines_is_not_a_pass(self):
        lines = [(D + 1, "idle", "unknown", 336), (D + 2, "idle", "blocked", 336), (D + 3, "preparing", "blocked", 336),
                 (D + 4, "configuring", "blocked", 336), (D + 0.5, "active", "protected", 336)]   # real D+6, stepped back 5.5 s
        boot = summary(observe(lines, app=None))
        self.assertIn("clockStepped", names(boot))
        self.assertFalse(passes(boot))

    def test_a_stored_capture_without_a_log_order_keeps_the_failure(self):
        boot = summary(observe(self.RESTART, app=None))
        boot["timeline"] = [item[:4] for item in boot["timeline"]]
        self.assertEqual(names(boot), ["activeBeforeAttemptSteps"])
        self.assertFalse(passes(boot))

    def test_an_explicit_restart_whose_attempt_line_is_logged_before_the_active_line_is_still_flagged(self):
        lines = clean_lines()[:4] + [(D + 7, "preparing", "blocked", 336), (D + 5, "active", "protected", 336)]
        boot = summary(observe(lines, app=None))
        found = names(boot)
        self.assertIn("activeBeforeAttemptSteps", found)
        self.assertIn("clockStepped", found)


class ReevalOptOutTests(unittest.TestCase):
    """N-7: verdict-reeval has no way to waive postRestartLineUnattributed (A5 stays closed offline as well)."""
    REEVAL = ROOT / "Tools/lab/verdict-reeval.py"

    def test_the_flag_is_gone(self):
        text = self.REEVAL.read_text()
        self.assertNotIn("allow-unattributed-lines", text)
        self.assertNotIn("unattributedLinesAllowed", text)
        self.assertNotIn("unattributedLinesAllowed", (ROOT / "Tools/lab/verdict.py").read_text())
        scratch = tempfile.mkdtemp(dir=os.environ["TMPDIR"])
        self.addCleanup(subprocess.run, ["rm", "-rf", scratch])
        capture = Path(scratch) / "BOOT-SECRETS" / "lab-x"
        capture.mkdir(parents=True)
        result = subprocess.run([base.sys.executable, "-I", "-B", str(self.REEVAL), str(capture), "--allow-unattributed-lines"],
                                capture_output=True, text=True, env=dict(os.environ, TMPDIR=scratch))
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("unrecognized arguments", result.stderr)

    def test_a_stored_unattributedLinesAllowed_has_no_effect(self):
        boot = summary(observe([(t, p, q, None) for t, p, q, _ in clean_lines()]))
        boot["unattributedLinesAllowed"] = True
        self.assertIn("postRestartLineUnattributed", names(boot))
        self.assertNotIn("unattributedLinesAllowed", V.restart_timeline(boot)["observations"])


class ReevalWindowTests(unittest.TestCase):
    """H1 through verdict-reeval: a crafted capture with one readable boot sample is not a PASS offline either."""
    REEVAL = ROOT / "Tools/lab/verdict-reeval.py"

    def reevaluate(self, boot, prevention=GOOD):
        scratch = tempfile.mkdtemp(dir=os.environ["TMPDIR"])
        self.addCleanup(subprocess.run, ["rm", "-rf", scratch])
        capture = Path(scratch) / "BOOT-SECRETS" / "lab-crafted"
        capture.mkdir(parents=True)
        (capture / "row-observation.json").write_text(json.dumps(dict(bootIntentBeforeReboot=True, relaunchPrevention=prevention, boot=boot)))
        result = subprocess.run([base.sys.executable, "-I", "-B", str(self.REEVAL), str(capture), "--out", str(Path(scratch) / "out.json")],
                                capture_output=True, text=True, env=dict(os.environ, TMPDIR=scratch))
        return result, json.loads(result.stdout)["results"][0]

    def test_two_readable_samples_pass_offline_as_the_control(self):
        result, report = self.reevaluate(summary(observe(clean_lines(), app=None)))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(report["rowPassOnRecomputedChecks"])

    def test_one_readable_sample_is_not_a_pass_offline(self):
        result, report = self.reevaluate(summary(observe(clean_lines(), app=None), None))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertFalse(report["rowPassOnRecomputedChecks"])
        check = next(item for item in report["checks"] if item["name"] == "relaunchPrevented")
        self.assertFalse(check["met"])

    def test_a_short_app_log_count_list_is_not_a_pass_offline(self):
        for counts in ([0], []):
            boot = summary(observe(clean_lines(), app=None))
            boot["appLogLinesSamples"] = counts
            result, report = self.reevaluate(boot)
            self.assertEqual(result.returncode, 1, result.stdout)
            check = next(item for item in report["checks"] if item["name"] == "relaunchPrevented")
            self.assertFalse(check["met"])
            self.assertIn("required boot samples", check["gap"])

    def test_app_log_lines_and_an_asserted_applied_are_not_a_pass_offline(self):
        result, report = self.reevaluate(summary(observe(clean_lines(), app=None, applog=0), observe(clean_lines(), app=None, applog=3)))
        self.assertEqual(result.returncode, 1, result.stdout)
        result, report = self.reevaluate(summary(observe(clean_lines(), app=None)), dict(GOOD, mechanism="anything"))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertFalse(report["rowPassOnRecomputedChecks"])


if __name__ == "__main__":
    unittest.main()
