# SPDX-License-Identifier: MIT
"""M1-10m: Settings detection without wgex.settings.surface, the guest-load settle before GUI steps, and press-only's
lookup miss told apart from a swallowed AXPress error. Guest run 8d (30 Oct 2026, wgex-plan/evidence/run8d report
sections 7 and 10): BOOT-SECRETS stopped at open_settings because macOS 26 exposed neither wgex.settings.surface nor
any wgex.settings.tab.* identifier, although the Settings window was open and readable; every row's own restore left
the guest at load 19-52 when its GUI started; press-only answered path=none both for a miss and for an AXPress error.
The Settings fixture (fixtures/ax/run8d-settings-general.txt) is rebuilt from that report's quotes, the operator's raw
dump being gone: window "General" at 62,30 900x738, an outer group with an empty identifier, the
wgex.settings.showStatusInMenuBar and wgex.settings.hideDockIcon toggles, the wgex.protection.defaultTunnel popup and a
toolbar of eight tab buttons without identifiers; the toolbar and button frames are illustrative. Never a VM."""
import json
from pathlib import Path
import re
import subprocess
import unittest

import test_gui_element as element
import test_live_replay as replay
import test_run8_rows as run8

LIVE, ROOT, AX, GUEST = element.LIVE, element.ROOT, element.AX, element.GUEST
H = LIVE.HARNESS
GENERAL = (AX / "run8d-settings-general.txt").read_text()
MAIN = (AX / "run8d-main-complete.txt").read_text()
SERVICE_PRESS = ["press", "WGEX", "2", "-", "press", "476", "56", "AXToolbar", "Service"]
NO_WINDOW = "ax-dump=failed exit=1\n"


class PerWindowRunner(element.DumpRunner):
    """Serves AX dumps per window index (the last of each list repeats; a missing index is gui.sh's failure line) and
    press replies in order (the last repeats). selects (M1-10n): after a press the helper reports as pressed, or a
    click, of a verb in switches, every later dump's AXWindow line carries that title, as macOS titles the Settings
    window with the selected tab; None keeps the title (a press that did not switch the tab)."""

    def __init__(self, windows, presses=(b"path=element\n",), selects=None, switches=("press", "click")):
        super().__init__([NO_WINDOW])
        self.windows, self.presses = {key: list(value) for key, value in windows.items()}, list(presses)
        self.selects, self.switches, self.selected = selects, switches, None

    def run(self, argv, data=None, timeout=100, env=None):
        args = argv[2:] if argv[:1] == ["just"] else []
        if args[:2] == ["gui", "dump"]:
            self.commands.append(list(argv))
            self.clock += 0.01
            queue = self.windows.get(args[3], [NO_WINDOW])
            dump = queue.pop(0) if len(queue) > 1 else queue[0]
            if self.selected:
                dump = re.sub(r"(?m)^AXWindow \| name=[^|]*\|", f"AXWindow | name={self.selected} |", dump)
            return self.reply(argv, dump.encode())
        if args[:2] == ["gui", "press"]:
            self.commands.append(list(argv))
            self.clock += 0.01
            output = self.presses.pop(0) if len(self.presses) > 1 else self.presses[0]
            if "press" in self.switches and LIVE.action_path(output) in LIVE.PRESSED_PATHS:
                self.selected = self.selects
            return self.reply(argv, output, code=0 if output.startswith(b"path=") else 1)
        if args[:2] == ["gui", "click"] and "click" in self.switches:
            self.selected = self.selects
        return super().run(argv, data, timeout, env)


def session(windows, **kw):
    runner = PerWindowRunner(windows, **kw)
    return runner, LIVE.Session("fixture", {}, runner=runner)


def gui(runner, verb):
    return element.gui(runner, verb)


def loadavg(load1):
    return f"{{ {load1:.2f} 3.00 4.00 }}\n".encode()


def steps(result):
    return json.loads((Path(result["buildRoot"]) / "steps.json").read_text())


class SettingsDetectionTests(unittest.TestCase):
    def test_the_run8d_general_tab_has_no_surface_and_no_tab_identifiers(self):
        self.assertFalse(LIVE.dump_carries(GENERAL, LIVE.SETTINGS_SURFACE))
        self.assertNotIn("wgex.settings.tab.", GENERAL)
        self.assertEqual(LIVE.window_title(GENERAL), "General")
        self.assertEqual(LIVE.window_frame(GENERAL), (62, 30, 900, 738))

    def test_settings_evidence_prefers_the_surface_then_the_title_then_a_general_identifier(self):
        self.assertEqual(LIVE.settings_evidence(GENERAL), "title:General")
        surface = GENERAL.replace("desc=group | id= | pos=62,30", "desc=group | id=wgex.settings.surface | pos=62,30", 1)
        self.assertEqual(LIVE.settings_evidence(surface), "identifier:wgex.settings.surface", "a build exposing it is still found by it")
        retitled = GENERAL.replace("AXWindow | name=General |", "AXWindow | name=missing value |")
        self.assertEqual(LIVE.settings_evidence(retitled), "identifier:wgex.settings.showStatusInMenuBar")
        only_dock = "\n".join(line for line in retitled.splitlines() if "showStatusInMenuBar" not in line)
        self.assertEqual(LIVE.settings_evidence(only_dock), "identifier:wgex.settings.hideDockIcon")
        for title in LIVE.SETTINGS_TAB_TITLES:
            self.assertEqual(LIVE.settings_evidence(f"AXWindow | name={title} | value= | desc= | id= |\n"), "title:" + title)
        self.assertIsNone(LIVE.settings_evidence(MAIN), "the main window is not Settings")
        self.assertIsNone(LIVE.settings_evidence(NO_WINDOW))

    def test_open_settings_finds_the_run8d_window_by_title(self):
        runner, live = session({"1": [MAIN], "2": [GENERAL]})
        self.assertEqual(live.open_settings(), "2")
        self.assertEqual(gui(runner, "dump"), [["dump", "WGEX", "1"], ["dump", "WGEX", "2"]], "found on the first pass")
        self.assertEqual(live.ledger[-1], dict(settingsWindow="2", settingsEvidence="title:General", windowTitle="General"))

    def test_open_settings_still_names_the_gap_when_no_window_shows_settings(self):
        runner, live = session({"1": [MAIN], "2": [NO_WINDOW]})
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.open_settings()
        self.assertEqual(raised.exception.reason, "settingsUnavailable")
        self.assertIn("a Settings tab title", str(raised.exception))


class ServiceTabTests(unittest.TestCase):
    def test_the_service_tab_is_found_by_title_inside_the_toolbar(self):
        self.assertEqual(LIVE.titled_control(GENERAL, "Service"), (440, 32, 72, 48))
        with self.assertRaises(ValueError):
            LIVE.titled_control(GENERAL.replace("AXToolbar |", "AXGroup |"), "Service")
        with self.assertRaises(ValueError):
            LIVE.titled_control(GENERAL, "Network Extension")

    def test_the_service_tab_is_pressed_by_title_through_the_element_path(self):
        runner, live = session({"2": [GENERAL]}, selects="Service")
        self.assertEqual(live.select_settings_tab("2", "Service"), "element")
        self.assertEqual(gui(runner, "press"), [SERVICE_PRESS], "identifier -, the toolbar role, the title; the point only as fallback")
        self.assertEqual(gui(runner, "click") + gui(runner, "scroll"), [])
        entry = next(item for item in live.ledger if item.get("controlContainer") == "AXToolbar")
        self.assertEqual((entry["controlLabel"], entry["controlContainer"], entry["actionPath"], entry["elementFrame"], entry["windowFrame"]),
                         ("Service", "AXToolbar", "element", [440, 32, 72, 48], [62, 30, 900, 738]))
        self.assertEqual(live.ledger[-1], dict(settingsTab="Service", settingsTabChoice=1, windowTitle="Service"), "the press is confirmed by title")

    def test_the_guest_side_coordinate_fallback_is_reported(self):
        runner, live = session({"2": [GENERAL]}, presses=[b"path=coordinate\n"], selects="Service")
        self.assertEqual(live.select_settings_tab("2", "Service"), "coordinate")
        self.assertEqual(gui(runner, "press"), [SERVICE_PRESS])

    def test_a_tab_identifier_from_a_future_build_is_still_the_first_choice(self):
        tabbed = GENERAL.replace("desc=Service | id= |", "desc=Service | id=wgex.settings.tab.service |")
        runner, live = session({"2": [tabbed]}, selects="Service")
        live.select_settings_tab("2", "Service")
        self.assertEqual(gui(runner, "press"), [["press", "WGEX", "2", "wgex.settings.tab.service", "press", "476", "56", "AXButton"]])

    def test_a_toolbar_outside_the_window_is_never_pressed_or_clicked(self):
        outside = GENERAL.replace("AXWindow | name=General | value= | desc= | id= | pos=62,30 size=900x738",
                                  "AXWindow | name=General | value= | desc= | id= | pos=62,90 size=900x678")
        runner, live = session({"2": [outside]})
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.select_settings_tab("2", "Service")
        self.assertEqual(raised.exception.reason, "guiTargetOffscreen:Service")
        self.assertEqual(gui(runner, "press") + gui(runner, "click"), [])

    def test_a_failed_title_press_falls_through_to_the_label_click_inside_the_window(self):
        runner, live = session({"2": [GENERAL]}, presses=[b"ax-action=failed exit=1\n"], selects="Service")
        live.select_settings_tab("2", "Service")
        self.assertEqual(gui(runner, "press"), [SERVICE_PRESS])
        self.assertEqual(gui(runner, "click"), [["click", "476", "56"]], "the existing label click, inside the window")
        self.assertEqual([entry["actionPath"] for entry in live.ledger if entry.get("controlContainer") == "AXToolbar"], [None])

    def test_a_press_that_leaves_the_general_title_falls_through_to_the_label_click(self):
        # M1-10m verify F1: AXPress answers path=element but the tab does not switch; the label click does.
        runner, live = session({"2": [GENERAL]}, selects="Service", switches=("click",))
        self.assertIsNone(live.select_settings_tab("2", "Service"), "the label click's path")
        self.assertEqual(gui(runner, "press"), [SERVICE_PRESS])
        self.assertEqual(gui(runner, "click"), [["click", "476", "56"]])
        self.assertEqual([(entry["settingsTabChoice"], entry["windowTitle"]) for entry in live.ledger if "settingsTab" in entry],
                         [(1, "General"), (2, "Service")])
        presses = [i for i, argv in enumerate(runner.commands) if argv[:4] == ["just", "lab", "gui", "press"]]
        self.assertEqual(runner.commands[presses[0] + 1][:4], ["just", "lab", "gui", "dump"], "the window is re-dumped after the press")

    def test_a_tab_that_never_shows_is_the_named_gap_with_the_observed_title(self):
        runner, live = session({"2": [GENERAL]})
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.select_settings_tab("2", "Service")
        self.assertEqual(raised.exception.reason, "settingsTabNotSelected:Service")
        self.assertIn("titled 'General'", str(raised.exception))
        self.assertEqual(gui(runner, "press"), [SERVICE_PRESS])
        self.assertEqual(gui(runner, "click"), [["click", "476", "56"]], "the label click is tried before the gap")
        self.assertEqual([(entry["settingsTabChoice"], entry["windowTitle"]) for entry in live.ledger if "settingsTab" in entry],
                         [(1, "General"), (2, "General")])

    def test_a_truncated_re_dump_still_confirms_the_tab_by_its_first_line(self):
        truncated = "\n".join(GENERAL.splitlines()[:3]) + "\nax-walk: elements=3 truncated=1 errors=0\n"
        runner, live = session({"2": [GENERAL]}, selects="Service")
        served = runner.run

        def run(argv, *args, **kw):
            if runner.selected:
                runner.windows["2"] = [truncated]
            return served(argv, *args, **kw)

        runner.run = run
        self.assertEqual(live.select_settings_tab("2", "Service"), "element")
        self.assertEqual(live.ledger[-1], dict(settingsTab="Service", settingsTabChoice=1, windowTitle="Service"))
        press = max(i for i, argv in enumerate(runner.commands) if argv[:4] == ["just", "lab", "gui", "press"])
        self.assertEqual([argv[3] for argv in runner.commands[press + 1:] if argv[:3] == ["just", "lab", "gui"]], ["dump"],
                         "one re-dump, no retries: the title is on its first line")


class ToolbarRoleTests(unittest.TestCase):
    """M1-10m verify F2: a toolbar whose items repeat the title on an enabled wrapper group and a static text."""

    WRAPPED = GENERAL.replace(
        "AXButton | name=Service | value=missing value | desc=Service | id= | pos=440,32 size=72x48 en=true",
        "AXGroup | name=Service | value=missing value | desc=Service | id= | pos=438,30 size=76x52 en=true\n"
        "AXButton | name=Service | value=missing value | desc=Service | id= | pos=440,32 size=72x48 en=true\n"
        "AXStaticText | name=Service | value=Service | desc=Service | id= | pos=452,62 size=48x14 en=true")

    def test_the_button_is_preferred_over_a_wrapper_group_and_a_static_text_with_the_same_title(self):
        self.assertIn("AXGroup | name=Service", self.WRAPPED)
        with self.assertRaises(ValueError, msg="without the preference the wrapper group makes the title ambiguous"):
            LIVE.control_frame("\n".join(line for line in self.WRAPPED.splitlines() if "Service" in line), "Service")
        self.assertEqual(LIVE.titled_control(self.WRAPPED, "Service"), (440, 32, 72, 48))

    def test_radio_button_then_toggle_then_any_role(self):
        for role, frame in (("AXRadioButton", (440, 32, 72, 48)), ("AXToggle", (440, 32, 72, 48))):
            with self.subTest(role=role):
                dump = self.WRAPPED.replace("AXButton | name=Service", role + " | name=Service")
                self.assertEqual(LIVE.titled_control(dump, "Service"), frame)
        only_group = "\n".join(line for line in self.WRAPPED.splitlines() if not line.startswith("AXButton | name=Service"))
        self.assertEqual(LIVE.titled_control(only_group, "Service"), (438, 30, 76, 52), "no preferred role: the old lookup")
        both = self.WRAPPED.replace("AXGroup | name=Service", "AXRadioButton | name=Service")
        self.assertEqual(LIVE.titled_control(both, "Service"), (440, 32, 72, 48), "AXButton before AXRadioButton")
        twice = self.WRAPPED.replace("AXGroup | name=Service", "AXButton | name=Service")
        with self.assertRaises(ValueError, msg="two buttons so titled are ambiguous"):
            LIVE.titled_control(twice, "Service")

    def test_the_crafted_toolbar_presses_the_button_centre(self):
        runner, live = session({"2": [self.WRAPPED]}, selects="Service")
        self.assertEqual(live.select_settings_tab("2", "Service"), "element")
        self.assertEqual(gui(runner, "press"), [SERVICE_PRESS])
        self.assertEqual(gui(runner, "click"), [])


class Run8dSettingsRunner(run8.Run8Runner):
    """Run8Runner whose Settings tree is the run 8d one: no wgex.settings.surface, tab buttons without identifiers inside a
    toolbar, and the General tab's hideDockIcon toggle."""

    def dump(self):
        lines = []
        for line in super().dump():
            if "id=wgex.settings.surface" in line:
                continue
            if "id=wgex.settings.tab." in line:
                line = re.sub(r"id=wgex\.settings\.tab\.[a-z]+", "id=", line)
            lines.append(line)
        lines.append("AXCheckBox | name=Hide Dock icon | value=0 | desc=Hide Dock icon | id=wgex.settings.hideDockIcon | pos=500,500 size=42x24 en=true")
        lines.append("AXToolbar | name=missing value | value=missing value | desc=toolbar | id= | pos=330,290 size=200x40 en=missing value")
        return lines


class BootSecretsTests(unittest.TestCase):
    def test_boot_secrets_reaches_the_startup_radio_group_through_the_service_tab_title(self):
        runner = Run8dSettingsRunner()
        runner.boot_secret_mode = True
        runner, result = run8.run_row("BOOT-SECRETS", runner)
        self.assertNotIn("settingsUnavailable", " ".join(result["gaps"]))
        presses = gui(runner, "press")
        service = next(i for i, argv in enumerate(presses) if argv[3:4] == ["-"])
        self.assertEqual(presses[service][4:], ["press", "350", "310", "AXToolbar", "Service"])
        startup = next(i for i, argv in enumerate(presses) if argv[3] == LIVE.BOOT_STARTUP_GROUP)
        self.assertLess(service, startup, "the Service tab first, then the startup radio group")
        self.assertEqual(gui(runner, "click"), [])
        self.assertTrue(runner.boot_intent)
        ledger = steps(result)
        found = [(entry["settingsWindow"], entry["settingsEvidence"]) for entry in ledger if "settingsEvidence" in entry]
        self.assertEqual(found, [("1", "identifier:wgex.settings.hideDockIcon")])

    def test_m5_3_10_selects_the_protection_tab_by_title(self):
        runner, result = run8.run_row("M5.3-10", Run8dSettingsRunner())
        presses = gui(runner, "press")
        self.assertIn(["press", "WGEX", "1", "-", "press", "360", "310", "AXToolbar", "Protection"], presses)
        self.assertEqual(gui(runner, "click"), [])


class GuestSettleTests(unittest.TestCase):
    def test_threshold_and_bound_come_from_the_harness_file(self):
        self.assertEqual(H.threshold("GUEST_SETTLE_LOAD"), 2.0)
        self.assertEqual(H.BASES["HARNESS_GUEST_SETTLE"], 75)
        self.assertIn("GUEST_SETTLE", H.names())
        self.assertNotIn("GUEST_SETTLE_LOAD", H.names(), "a load threshold is never scaled")
        with self.assertRaises(ValueError):
            H.threshold("GUEST_SETTLE")
        self.assertIsNone(LIVE.guest_load1(b"Load Avg: 1.0\n"))
        self.assertEqual(LIVE.guest_load1(b"{ 19.38 25.10 30.02 }\n"), 19.38)

    def test_the_guest_load_action_is_read_only(self):
        source = (GUEST / "verdict-actions.sh").read_text()
        self.assertIn("  guest-load) /usr/sbin/sysctl -n vm.loadavg ;;\n", source)

    def test_prepare_waits_for_a_falling_load_before_the_first_gui_step(self):
        runner = replay.RecordedRunner()
        runner.guest_loads = [loadavg(52.0), loadavg(19.4), loadavg(6.3), loadavg(1.7), loadavg(0.9)]
        runner, result = replay.LiveReplayTests().run_recorded("M5.1-04", runner)
        commands = [" ".join(argv) for argv in runner.commands]
        loads = [i for i, c in enumerate(commands) if c.endswith("verdict-actions.sh guest-load")]
        self.assertEqual(len(loads), 4, "stops at the first reading below the threshold")
        staged = max(i for i, c in enumerate(commands) if "/verdict-actions.sh" in c and "cat >" in c)
        first_gui = next(i for i, c in enumerate(commands) if c.startswith("just lab gui"))
        self.assertLess(staged, loads[0])
        self.assertLess(loads[-1], first_gui)
        self.assertIn("open -a WGEX", next(c for c in commands if c.startswith("just lab gui run open")))
        self.assertEqual(len([c for c in commands if c.endswith("verdict-actions.sh guest-load")]), 4, "no settle after prepare")
        entry = next(item for item in steps(result) if "guestSettle" in item)
        self.assertEqual([reading["load1"] for reading in entry["readings"]], [52.0, 19.4, 6.3, 1.7])
        self.assertEqual((entry["guestSettle"], entry["settled"], entry["thresholdLoad1"], entry["boundSeconds"]),
                         ("restore", True, 2.0, H.seconds("GUEST_SETTLE")))
        self.assertEqual(entry["waitedSeconds"] >= 3 * LIVE.GUEST_SETTLE_POLL_SECONDS, True)
        self.assertNotIn("warning", entry)
        self.assertEqual(result["guestLoadAtGUIStart"], [dict(stage="restore", load1=1.7, settled=True, thresholdLoad1=2.0,
                                                              waitedSeconds=entry["waitedSeconds"], readings=4)])

    def test_a_load_that_never_falls_continues_with_a_ledger_warning_and_no_gap(self):
        for replies, final in (([loadavg(19.0)], 19.0), ([b""], None), ([loadavg(8.0), b"garbage\n"], 8.0)):
            with self.subTest(final=final):
                runner = replay.RecordedRunner()
                runner.guest_loads = replies
                runner, result = replay.LiveReplayTests().run_recorded("M5.1-04", runner)
                self.assertTrue(result["rowCompleted"])
                self.assertFalse([gap for gap in result["gaps"] if "load" in gap.lower()])
                entry = next(item for item in steps(result) if "guestSettle" in item)
                self.assertFalse(entry["settled"])
                self.assertIn("GUI steps start anyway", entry["warning"])
                self.assertIn("unreadable" if final is None else str(final), entry["warning"])
                bound = H.seconds("GUEST_SETTLE")
                self.assertEqual(len(entry["readings"]), bound // LIVE.GUEST_SETTLE_POLL_SECONDS, "one reading per poll within the bound")
                self.assertLessEqual(entry["waitedSeconds"], bound + 1)
                self.assertEqual(result["guestLoadAtGUIStart"][0]["load1"], final)
                self.assertFalse(result["guestLoadAtGUIStart"][0]["settled"])

    def test_a_reboot_settles_again_before_its_first_gui_step_and_never_inside_the_never_open_window(self):
        """M1-10o: REBOOT-LOCKDOWN no longer opens the app after its reboot (it never turns lockdown off), so like
        BOOT-SECRETS it has no GUI step there and no second settle; the reboot settle itself still runs before the next GUI
        step of a session whose reboot left it pending."""
        runner = run8.Run8Runner()
        runner, result = run8.run_row("REBOOT-LOCKDOWN", runner)
        commands = [" ".join(argv) for argv in runner.commands]
        boot = next(i for i, c in enumerate(commands) if c.endswith("verdict-actions.sh reboot"))
        loads = [i for i, c in enumerate(commands) if c.endswith("verdict-actions.sh guest-load")]
        self.assertEqual(len(loads), 1, "one settle after the restore; no GUI step after the reboot")
        self.assertLess(loads[0], boot)
        self.assertFalse(any(c.startswith("just lab gui") for c in commands[boot:]))
        self.assertEqual([item["stage"] for item in result["guestLoadAtGUIStart"]], ["restore"])
        live = LIVE.Session("fixture", {}, runner=run8.Run8Runner())
        live.gui_settle = "reboot"
        live.lab("gui", "activate", "WGEX")
        lines = [" ".join(argv) for argv in live.runner.commands]
        self.assertTrue(lines[0].endswith("verdict-actions.sh guest-load"), lines[:2])
        self.assertTrue(lines[-1].startswith("just lab gui activate"))
        self.assertEqual([item["stage"] for item in live.guest_loads], ["reboot"])

    def test_boot_secrets_has_no_gui_step_after_its_reboot_so_no_second_settle(self):
        runner = run8.Run8Runner()
        runner.boot_secret_mode = True
        runner, result = run8.run_row("BOOT-SECRETS", runner)
        self.assertEqual([item["stage"] for item in result["guestLoadAtGUIStart"]], ["restore"])


class PressOnlyOutcomeTests(unittest.TestCase):
    def test_the_helper_reports_parse_to_miss_and_error_with_its_number(self):
        self.assertEqual(LIVE.action_path(b"path=miss\n"), "miss")
        self.assertEqual(LIVE.action_path(b"path=error number=-25200\n"), "error")
        self.assertEqual(LIVE.press_error(b"path=error number=-25200\n"), -25200)
        self.assertIsNone(LIVE.press_error(b"path=miss\n"))
        self.assertEqual(LIVE.press_reply(b"path=error number=-1728\n"), "error")
        self.assertIsNone(LIVE.action_path(b"path=error number=x\n"))
        self.assertEqual(LIVE.press_outcome("miss"), "lookup miss")
        self.assertEqual(LIVE.press_outcome("error", -25200), "AXPress error -25200")

    def test_gui_sh_passes_only_the_fixed_reports(self):
        pattern = re.search(r'\|\| "\$line" =~ (\^path=\(element\|element-timeout.*?\$) \]\]', (ROOT / "Tools/lab/tart/gui.sh").read_text())[1]
        for line, ok in (("path=miss", True), ("path=error number=-25200", True), ("path=element", True), ("path=none", False),
                         ("path=error number=", False), ("path=error number=-1;id", False), ("path=error", False)):
            code = subprocess.run(["bash", "-c", f'[[ "$1" =~ {pattern} ]]', "fixture", line], check=False).returncode
            self.assertEqual(code == 0, ok, line)

    def test_press_only_records_a_miss_and_an_error_apart_and_names_both_in_the_gap(self):
        runner, live = session({"1": [element.OFFSCREEN]}, presses=[b"path=miss\n", b"path=error number=-25200\n", b"path=miss\n"])
        runner.scroll = b"scroll=none\n"
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.click_id(element.LOCKDOWN)
        self.assertEqual(raised.exception.reason, "guiTargetOffscreen:" + element.LOCKDOWN)
        self.assertIn("3 failed press-only AXPress attempts (lookup miss; AXPress error -25200; lookup miss)", str(raised.exception))
        attempts = [entry for entry in live.ledger if "pressOnlyAttempt" in entry]
        self.assertEqual([(entry["pressOnly"], entry.get("pressOnlyErrorNumber")) for entry in attempts],
                         [("miss", None), ("error", -25200), ("miss", None)])
        self.assertEqual(live.ledger[-1]["pressOnlyOutcomes"], ["lookup miss", "AXPress error -25200", "lookup miss"])

    def test_both_outcomes_are_retried(self):
        for first in (b"path=miss\n", b"path=error number=-25200\n"):
            with self.subTest(first=first):
                runner, live = session({"1": [element.OFFSCREEN]}, presses=[first, b"path=element\n"])
                runner.scroll = b"scroll=none\n"
                self.assertEqual(live.click_id(element.LOCKDOWN), "element")
                self.assertEqual(len(gui(runner, "press")), 2)

    def test_a_press_with_a_point_never_counts_a_miss_or_an_error_as_pressed(self):
        for reply in (b"path=miss\n", b"path=error number=-25200\n"):
            with self.subTest(reply=reply):
                runner, live = session({"1": [element.VISIBLE]}, presses=[reply])
                with self.assertRaises(LIVE.RowFailure) as raised:
                    live.click_id(element.LOCKDOWN)
                self.assertEqual(raised.exception.reason, "guiActionFailed:" + element.LOCKDOWN)

    def test_the_helper_returns_miss_without_an_element_and_error_with_the_number(self):
        helper = (GUEST / "ax-action.applescript").read_text()
        self.assertIn('if pointX is missing value then\n    if pressError is missing value then return "path=miss"\n'
                      '    return "path=error number=" & ((pressError as integer) as text)\n  end if', helper)
        self.assertIn('perform action actionName of found\n          return my pressResult("path=element", pressStamp)\n'
                      '        on error errorText number errorNumber\n          set pressError to errorNumber', helper)
        self.assertIn('if errorNumber is -1712 then return my pressResult("path=element-timeout", pressStamp)\n'
                      '          set pressError to errorNumber', helper)
        self.assertIn('if ident is "-" or (value of attribute "AXIdentifier" of e as text) is ident then', helper)
        self.assertNotIn('return "path=none"', helper)

    def test_gui_sh_refuses_identifier_dash_without_a_role_or_a_label(self):
        gui_sh = (ROOT / "Tools/lab/tart/gui.sh").read_text()
        self.assertIn("[[ \"$role\" != - ]] || lab_die 'identifier - needs an AX role'", gui_sh)
        self.assertIn("(($# == label_index)) || lab_die 'identifier - needs a label or a frame'", gui_sh)


if __name__ == "__main__":
    unittest.main()
