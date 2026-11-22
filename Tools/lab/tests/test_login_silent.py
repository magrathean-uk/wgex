# SPDX-License-Identifier: MIT
"""M03-T07 LOGIN-SILENT (DEC-021): the catalogue entry, the checks, the driver's sequence with the GUI steps stubbed, the Hide Dock
icon compare-and-press, and the three guest actions run against stubbed tools. The row has not run on a guest yet; never a VM."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_live_replay as replay

ROOT, LIVE, V = replay.ROOT, replay.LIVE, replay.V
L = V.LOGIN_SILENT
ROWS = json.loads((ROOT / "Tools/lab/rows.json").read_text())["rows"]
FIXTURE = json.loads((ROOT / "Tools/lab/tests/fixtures/rows/login-silent.json").read_text())
SCRIPT = (ROOT / "Tools/lab/tart/guest/gap-actions.sh").read_text()
PROFILE = "00000000-0000-4000-8000-000000000001"
SILENT = "sampledAt=1.0\nprocess=running\nstandardWindows=0\notherWindows=0\nmenuBarItem=true\ndockItem=false\nappType=UIElement\n"


def window(dock):
    return ("sampledAt=2.0\nprocess=running\nstandardWindows=1\notherWindows=0\nmenuBarItem=true\n"
            f"dockItem={'true' if dock else 'false'}\nappType={'Foreground' if dock else 'UIElement'}\n")


class CatalogueTests(unittest.TestCase):
    def test_the_row_is_in_the_catalogue_its_mirror_and_the_v2_scope(self):
        row = ROWS["LOGIN-SILENT"]
        self.assertEqual((row["action"], row["checks"], row["profile"], row["state"]), ("login-silent", "login-silent", "full4", "protected"))
        scope = (ROOT / "Tools/lab/scope-v2.txt").read_text().splitlines()
        self.assertEqual(scope.index("LOGIN-SILENT"), scope.index("M5.3-09") + 1)
        self.assertIn("login-silent", V.ROW_CHECKS)

    def test_every_check_has_a_failing_fixture_and_the_recorded_pass_meets_all(self):
        checks = V.row_checks("login-silent", FIXTURE["pass"])
        self.assertTrue(all(item["met"] for item in checks), [item["name"] for item in checks if not item["met"]])
        names = {item["name"] for item in checks}
        self.assertEqual(names, {case["expectation"] for case in FIXTURE["failing"]})
        self.assertEqual(len(names), 11)


class ParseTests(unittest.TestCase):
    def test_a_full_sample_is_readable_and_typed(self):
        sample = L.parse_presentation(SILENT)
        self.assertEqual(sample, dict(readable=True, sampledAt=1.0, process="running", standardWindows=0, otherWindows=0, menuBarItem=True,
                                      dockItem=False, appType="UIElement"))
        self.assertTrue(L.silent(sample))

    def test_an_absent_process_is_readable_but_neither_silent_nor_a_window(self):
        sample = L.parse_presentation("sampledAt=1.0\nprocess=absent\n")
        self.assertTrue(sample["readable"])
        self.assertFalse(L.silent(sample))
        self.assertFalse(L.window_shown(sample, True))

    def test_failed_partial_and_malformed_replies_are_unreadable(self):
        for text in ("", "process=running\n", SILENT + "presentation=failed\n", SILENT.replace("standardWindows=0", "standardWindows=-1"),
                     SILENT.replace("dockItem=false", "dockItem=missing value"), SILENT.replace("process=running", "process=maybe")):
            with self.subTest(text=text):
                sample = L.parse_presentation(text)
                self.assertFalse(sample["readable"])
                self.assertFalse(L.silent(sample))

    def test_an_unknown_app_type_is_kept_as_unknown_and_never_judged(self):
        sample = L.parse_presentation(SILENT.replace("appType=UIElement", "appType=Weird"))
        self.assertEqual(sample["appType"], "unknown")
        self.assertFalse(L.silent(sample))
        self.assertFalse(L.window_shown(L.parse_presentation(window(False).replace("appType=UIElement", "appType=")), False))

    def test_a_visible_window_of_any_kind_fails_a_silent_sample(self):
        for count in ("1", "2"):
            with self.subTest(otherWindows=count):
                sample = L.parse_presentation(SILENT.replace("otherWindows=0", "otherWindows=" + count))
                self.assertTrue(sample["readable"])
                self.assertFalse(L.silent(sample), "a non-standard or unclassified WGEX window is not silent")
        self.assertFalse(L.silent(L.parse_presentation(SILENT.replace("otherWindows=0\n", ""))), "an unmeasured window count is not silent")

    def test_a_failed_dock_read_is_an_unreadable_sample_never_a_missing_dock_item(self):
        sample = L.parse_presentation("sampledAt=1.0\npresentation=failed\nappType=UIElement\n")
        self.assertFalse(sample["readable"])
        self.assertNotIn("dockItem", sample)
        self.assertFalse(L.silent(sample))

    def test_login_item_state_reads_true_false_and_unset(self):
        self.assertEqual(L.parse_login_item_state("autoConnectAtLogin=true\nhideDockIcon=false\n"), dict(autoConnectAtLogin=True, hideDockIcon=False))
        self.assertEqual(L.parse_login_item_state("autoConnectAtLogin=unset\nhideDockIcon=1\n"), dict(autoConnectAtLogin=None, hideDockIcon=None))
        self.assertEqual(L.parse_login_item_state(""), dict(autoConnectAtLogin=None, hideDockIcon=None))


class SeriesTests(unittest.TestCase):
    def checks(self, observation):
        return {item["name"]: item for item in V.row_checks("login-silent", observation)}

    def test_an_other_window_in_one_after_login_sample_fails_the_silent_check(self):
        observation = json.loads(json.dumps(FIXTURE["pass"]))
        observation["loginSilent"]["variants"]["hideDockOn"]["afterLogin"][1]["otherWindows"] = 1
        checks = self.checks(observation)
        self.assertFalse(checks["silentAfterLogin:hideDockOn"]["met"])
        self.assertTrue(checks["silentAfterLogin:hideDockOff"]["met"])

    def test_two_valid_samples_and_one_malformed_sample_fail_every_series(self):
        series = (("ordinaryLaunchShowsWindowOnce", ("ordinaryLaunch", "samples")),
                  ("silentAfterLogin:hideDockOff", ("variants", "hideDockOff", "afterLogin")),
                  ("windowFromMenu:hideDockOn", ("variants", "hideDockOn", "fromMenu")))
        for malformed in ("presentation=failed", None, 7, ["process=running"]):
            for name, path in series:
                with self.subTest(malformed=malformed, check=name):
                    observation = json.loads(json.dumps(FIXTURE["pass"]))
                    holder = observation["loginSilent"]
                    for key in path[:-1]:
                        holder = holder[key]
                    holder[path[-1]] = holder[path[-1]][:2] + [malformed]
                    self.assertEqual(len(holder[path[-1]]), 3)
                    item = self.checks(observation)[name]
                    self.assertFalse(item["met"], "the malformed sample is kept and fails the series")
                    self.assertEqual(len(item["samples"]), 3, "the malformed sample is never dropped from the evidence")
                    self.assertEqual(item["samples"][2], malformed)


class Guest:
    """The guest side for the driver tests: the app's files, the console and the presentation the login launch shows."""

    def __init__(self):
        self.auto_login, self.hide_dock, self.console, self.running = False, False, "lab", True
        self.relogin, self.login_launch, self.menu_works = True, True, True
        self.window_open = True
        self.calls = []

    def action(self, action, *args, check=True, **kw):
        self.calls.append((action,) + args)
        if action == "login-item-state":
            return f"autoConnectAtLogin={'true' if self.auto_login else 'false'}\nhideDockIcon={'true' if self.hide_dock else 'false'}\n".encode()
        if action == "logout":
            self.console, self.running, self.window_open = "logged-out", False, False
            return b""
        if action == "console-user":
            reply = self.console
            if self.console == "logged-out" and self.relogin:
                self.console = "lab"
                self.running = self.login_launch
            return (reply + "\n").encode()
        if action == "presentation":
            if not self.running:
                return b"sampledAt=1.0\nprocess=absent\n"
            return (window(not self.hide_dock) if self.window_open else SILENT).encode()
        if action == "menu-open":
            return b"menu=opened\n" if self.menu_works else b""
        raise AssertionError("unexpected guest action " + action)


def driven(guest, **overrides):
    runner = replay.RecordedRunner()
    live = LIVE.Session("fixture", {}, runner=runner)
    live.profile_ids["full4"] = PROFILE
    order = []

    def startup(window, option):
        order.append(("startup", option))
        guest.auto_login = True

    def hide(identity, wanted):
        order.append(("hideDock", wanted))
        guest.hide_dock = wanted

    def prevent():
        order.append(("prevent",))
        live.row_observation["relaunchPrevention"] = dict(FIXTURE["pass"]["relaunchPrevention"])

    def click(identifier, window="1", timeout=None):
        order.append(("click", identifier, window))
        if identifier == LIVE.MENU_OPEN_WINDOW:
            guest.window_open = True

    def lab(*args, **kw):
        order.append(("lab",) + args)
        if args[:4] == ("gui", "run", "open", "-a"):
            guest.running = guest.window_open = True
        return b""

    def quit_app():
        order.append(("quit",))
        guest.running = guest.window_open = False

    patches = dict(gap_action=guest.action, app_running=lambda: guest.running, open_settings=lambda: "1", select_settings_tab=lambda *a: None,
                   close_settings=lambda *a: None, select_startup_option=startup, set_hide_dock=hide, quit_app=quit_app,
                   prevent_relaunch=prevent, click_id=click, lab=lab, status=lambda **kw: dict(phase="active", protection="protected"),
                   await_status=lambda *a, **kw: None, connect=lambda *a: order.append(("connect",)),
                   generate=lambda state, **kw: dict(state=state, role=kw.get("role")), settle_guest=lambda stage: order.append(("settle", stage)))
    patches.update(overrides)
    with patch.multiple(live, **patches):
        records = live.login_silent_row("full4")
    return live, order, records


class DriverTests(unittest.TestCase):
    def test_the_row_runs_the_ordinary_launch_then_both_variants_through_logout_login_and_the_menu(self):
        live, order, records = driven(Guest())
        names = [step[0] for step in order]
        self.assertEqual(records, [dict(state="protected", role="afterLoginLaunch")])
        self.assertLess(order.index(("hideDock", False)), order.index(("lab", "gui", "run", "open", "-a", "WGEX")))
        self.assertLess(order.index(("lab", "gui", "run", "open", "-a", "WGEX")), order.index(("startup", "login")))
        self.assertEqual(names.count("prevent"), 1, "the reopen-state prevention is applied once, before the first logout")
        self.assertEqual(order.count(("hideDock", True)), 1)
        self.assertEqual([step for step in order if step[0] == "click"], [("click", LIVE.MENU_OPEN_WINDOW, "1")] * 2)
        self.assertEqual(order.count(("settle", "login")), 2, "the login's load settles once per login, before the menu opens")
        row = live.row_observation["loginSilent"]
        self.assertEqual(sorted(row["variants"]), ["hideDockOff", "hideDockOn"])
        observation = dict(live.row_observation)
        checks = {item["name"]: item for item in V.row_checks("login-silent", observation)}
        self.assertTrue(all(item["met"] for item in checks.values()), [name for name, item in checks.items() if not item["met"]])
        self.assertTrue(row["protectedWithoutAction"])

    def test_each_variant_quits_before_its_logout_and_prevention_precedes_the_first_logout(self):
        guest = Guest()
        live, order, _ = driven(guest)
        logouts = [index for index, call in enumerate(guest.calls) if call[0] == "logout"]
        self.assertEqual(len(logouts), 2)
        self.assertEqual(order.count(("quit",)), 3, "the ordinary launch and each variant quit first")

    def test_no_console_login_is_the_named_gap(self):
        guest = Guest()
        guest.relogin = False
        with self.assertRaises(LIVE.RowFailure) as raised:
            driven(guest)
        self.assertEqual(raised.exception.reason, "consoleReloginMissing")

    def test_no_app_after_login_is_the_named_gap(self):
        guest = Guest()
        guest.login_launch = False
        with self.assertRaises(LIVE.RowFailure) as raised:
            driven(guest)
        self.assertEqual(raised.exception.reason, "loginLaunchMissing")

    def test_a_menu_that_does_not_open_records_no_window_and_fails_the_check(self):
        guest = Guest()
        guest.menu_works = False
        live, order, _ = driven(guest)
        self.assertFalse(any(step[0] == "click" for step in order), "no press without the menu")
        checks = {item["name"]: item for item in V.row_checks("login-silent", live.row_observation)}
        self.assertFalse(checks["windowFromMenu:hideDockOff"]["met"])
        self.assertTrue(checks["silentAfterLogin:hideDockOff"]["met"])

    def test_a_window_shown_at_login_fails_the_silent_check(self):
        guest = Guest()
        original = guest.action

        def loud(action, *args, **kw):
            reply = original(action, *args, **kw)
            if action == "console-user" and guest.console == "lab" and guest.running:
                guest.window_open = True
            return reply
        live, _, _ = driven(guest, gap_action=loud)
        checks = {item["name"]: item for item in V.row_checks("login-silent", live.row_observation)}
        self.assertFalse(checks["silentAfterLogin:hideDockOff"]["met"])
        self.assertFalse(checks["silentAfterLogin:hideDockOn"]["met"])

    def test_protection_that_does_not_come_back_is_reconnected_and_recorded(self):
        def deadline(*args, **kw):
            raise LIVE.PollDeadline("status protection=protected deadline")
        calls = []
        live, order, _ = driven(Guest(), await_status=lambda *a, **kw: calls.append(a) or (deadline() if len(calls) == 1 else None))
        self.assertIn(("connect",), order)
        self.assertFalse(live.row_observation["loginSilent"]["protectedWithoutAction"])


class HideDockTests(unittest.TestCase):
    def session(self, values, preference):
        runner = replay.RecordedRunner()
        live = LIVE.Session("fixture", {}, runner=runner)
        state = dict(pref=preference, presses=0)
        dumps = list(values)

        def read_dump(window, **kw):
            value = dumps.pop(0) if len(dumps) > 1 else dumps[0]
            return "" if value is None else f"AXCheckBox | name=Hide Dock icon | value={value} | desc= | id={LIVE.HIDE_DOCK_TOGGLE} | pos=1,1 size=2x2 en=true\n"

        def click(identifier, window="1", timeout=None):
            self.assertEqual(live.toggle_expected[0], identifier, "the press is pinned to the value read")
            state["presses"] += 1
            state["pref"] = not state["pref"]

        patches = dict(open_settings=lambda: "2", select_settings_tab=lambda *a: None, close_settings=lambda *a: None, read_dump=read_dump,
                       click_id=click, login_item_state=lambda identity: dict(autoConnectAtLogin=True, hideDockIcon=state["pref"]))
        return live, state, patches

    def test_the_opposite_value_is_pressed_once_and_read_back(self):
        live, state, patches = self.session(["0"], False)
        with patch.multiple(live, **patches):
            live.set_hide_dock(PROFILE, True)
        self.assertEqual(state["presses"], 1)
        self.assertIsNone(live.toggle_expected)

    def test_an_already_set_preference_is_not_pressed(self):
        live, state, patches = self.session(["1"], True)
        with patch.multiple(live, **patches):
            live.set_hide_dock(PROFILE, True)
        self.assertEqual(state["presses"], 0)

    def test_an_unreadable_toggle_is_never_pressed_blind(self):
        live, state, patches = self.session([None], False)
        with patch.multiple(live, **patches), self.assertRaises(LIVE.RowFailure) as raised:
            live.set_hide_dock(PROFILE, True)
        self.assertEqual(raised.exception.reason, "hideDockIconNotApplied")
        self.assertEqual(state["presses"], 0)

    def test_a_press_that_never_reaches_the_preference_stops_after_two(self):
        live, state, patches = self.session(["0"], False)
        def dead(identifier, window="1", timeout=None):
            state["presses"] += 1
        patches["click_id"] = dead
        with patch.multiple(live, **patches), self.assertRaises(LIVE.RowFailure):
            live.set_hide_dock(PROFILE, True)
        self.assertEqual(state["presses"], 2)


def block(name):
    start = SCRIPT.index(f"  {name})")
    end = SCRIPT.index("\n    ;;\n", start) + len("\n    ;;\n")
    return SCRIPT[start:end]


class GuestActionTests(unittest.TestCase):
    def run_action(self, name, *args, stub="", home=None):
        program = (f'set -euo pipefail\nlab_user=labuser\nnow() {{ echo 1.000; }}\n{stub}\nset -- {name} {" ".join(args)}\n'
                   f'case "$1" in\n{block(name)}\nesac\n')
        env = dict(os.environ, LC_ALL="C", HOME=home or os.environ["TMPDIR"])
        return subprocess.run(["bash", "-c", program], capture_output=True, text=True, env=env)

    def test_login_item_state_reads_the_profile_and_the_preference(self):
        home = tempfile.mkdtemp(dir=os.environ["TMPDIR"])
        self.addCleanup(subprocess.run, ["rm", "-rf", home])
        support = Path(home) / "Library/Application Support/WGEX"
        (support / "profiles").mkdir(parents=True)
        (support / "profiles" / (PROFILE.lower() + ".json")).write_text(json.dumps(dict(profile=dict(macOptions=dict(autoConnectAtLogin=True)))))
        result = self.run_action("login-item-state", PROFILE, home=home)
        self.assertEqual(result.stdout, "autoConnectAtLogin=true\nhideDockIcon=unset\n", result.stderr)
        (support / "mac-preferences.json").write_text(json.dumps(dict(hideDockIcon=True)))
        self.assertEqual(self.run_action("login-item-state", PROFILE, home=home).stdout, "autoConnectAtLogin=true\nhideDockIcon=true\n")
        (support / "mac-preferences.json").write_text(json.dumps(dict(onboardingComplete=True)))
        self.assertEqual(self.run_action("login-item-state", PROFILE, home=home).stdout, "autoConnectAtLogin=true\nhideDockIcon=false\n",
                         "an absent key is the app's default, off")
        other = "00000000-0000-4000-8000-000000000009"
        self.assertEqual(self.run_action("login-item-state", other, home=home).stdout, "autoConnectAtLogin=unset\nhideDockIcon=false\n")
        self.assertNotEqual(self.run_action("login-item-state", "not-a-uuid", home=home).returncode, 0)

    def stubs(self, console="labuser", running=True, osascript="process=running", app_type='"ApplicationType"="UIElement"'):
        return f'''
id() {{ if [[ "$1" == -un ]]; then echo labuser; else echo 501; fi; }}
stat() {{ echo {console}; }}
pgrep() {{ {"return 0" if running else "return 1"}; }}
sudo() {{
  case "$*" in
    *osascript*) printf '%b\\n' {json.dumps(osascript)} ;;
    *lsappinfo*) printf '%s\\n' {json.dumps(app_type)} ;;
    *) echo "unexpected sudo $*" >&2; return 9 ;;
  esac
}}
'''

    def test_presentation_prints_the_osascript_lines_and_the_app_type(self):
        result = self.run_action("presentation", stub=self.stubs(osascript="process=running\nstandardWindows=0"))
        self.assertEqual(result.stdout, "sampledAt=1.000\nprocess=running\nstandardWindows=0\nappType=UIElement\n", result.stderr)

    def test_presentation_without_the_app_says_absent_and_never_runs_system_events(self):
        result = self.run_action("presentation", stub=self.stubs(running=False, osascript="SHOULD NOT RUN"))
        self.assertEqual(result.stdout, "sampledAt=1.000\nprocess=absent\n")

    def test_presentation_marks_a_failed_osascript_and_an_unreadable_type(self):
        stub = self.stubs(app_type="nothing") + 'sudo() { case "$*" in *osascript*) return 1 ;; *) echo junk ;; esac; }\n'
        result = self.run_action("presentation", stub=stub)
        self.assertEqual(result.stdout, "sampledAt=1.000\npresentation=failed\nappType=unknown\n")

    def test_presentation_reports_a_failed_dock_read_and_the_checks_reject_it(self):
        stub = self.stubs(osascript="presentation=failed")
        result = self.run_action("presentation", stub=stub)
        self.assertEqual(result.stdout, "sampledAt=1.000\npresentation=failed\nappType=UIElement\n", result.stderr)
        sample = L.parse_presentation(result.stdout)
        self.assertFalse(sample["readable"])
        self.assertFalse(L.silent(sample))

    def test_the_dock_reads_fail_the_sample_and_never_default_to_no_dock_item(self):
        text = block("presentation")
        dock = text[text.index('tell process "Dock"'):text.index("end tell\nend tell")]
        self.assertIn("UI elements of list 1", dock)
        self.assertIn('attribute "AXIsApplicationRunning"', dock)
        self.assertEqual(dock.count("    try\n"), 2, "one guarded read for the Dock list and one for the running state")
        for guarded in dock.split("    try\n")[1:]:
            handler = guarded[:guarded.index("end try")]
            self.assertIn("on error", handler)
            self.assertIn('return "presentation=failed"', handler.split("on error", 1)[1], "a failed read fails the sample")
        self.assertIn('else if runningState is not false then\n        return "presentation=failed"', dock,
                      "a running state other than true or false fails the sample")
        self.assertEqual(dock.count("set docked to true"), 1)

    def test_the_applescript_variables_are_not_system_events_process_properties(self):
        # Live (M03-T07 phase B): `set kind to "unknown"` inside tell process "WGEX" tried to set the process's own kind
        # property (-10006), so every presentation sample was unreadable.
        text = block("presentation")
        script = text[text.index('tell application "System Events"'):text.index("APPLESCRIPT", text.index('tell application "System Events"'))]
        reserved = {"kind", "name", "title", "visible", "frontmost", "id", "file", "class", "description", "value", "role",
                    "subrole", "position", "size", "enabled", "focused", "selected", "displayed name", "unix id"}
        assigned = set(re.findall(r"^\s*set ([A-Za-z][A-Za-z ]*?) to ", script, re.M))
        self.assertTrue(assigned, "the presentation script assigns its counters")
        self.assertEqual(assigned & reserved, set(), "an assignment to a process property acts on the process, not a variable")
        self.assertIn("set subroleName to value of attribute \"AXSubrole\" of w", script)

    def test_the_session_actions_refuse_another_console_user(self):
        for name in ("presentation", "menu-open"):
            with self.subTest(name):
                self.assertNotEqual(self.run_action(name, stub=self.stubs(console="root")).returncode, 0)

    def test_menu_open_clicks_the_menu_bar_item_in_the_console_session(self):
        stub = self.stubs() + 'sudo() { printf "%s\\n" "$*" >&2; }\n'
        result = self.run_action("menu-open", stub=stub)
        self.assertEqual(result.stdout, "menu=opened\n")
        self.assertIn("launchctl asuser 501 osascript -e", result.stderr)
        self.assertIn("click menu bar item 1 of menu bar 2", result.stderr)

    def test_the_actions_never_touch_the_network_launchd_jobs_or_the_daemon(self):
        for name in ("login-item-state", "presentation", "menu-open"):
            text = block(name)
            for word in ("pfctl", "route ", "networksetup", "kill", "bootout", "kickstart", "WGEXDaemon", "defaults write"):
                self.assertNotIn(word, text, name)


if __name__ == "__main__":
    unittest.main()
