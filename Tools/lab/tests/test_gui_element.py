# SPDX-License-Identifier: MIT
"""M1-10j: GUI targets are actioned by accessibility element, never by a coordinate outside the visible window.
Guest runs 8 and 8b clicked wgex.protection.lockdown at its AX centre (327,842) below the main window's content
(0,30 1024x752, bottom 782) and System Events answered -25200. Fixtures are that run 8b dump verbatim and the same
tree with the detail pane scrolled by 300 points. Fix pass 1 (verify F1-F5): an element still outside after the scroll
is pressed press-only, a frameless window line takes the content group plus toolbars, negative origins are off-screen,
the helper matches identifier plus role, and popups are pressed ignoring application responses. Never a VM."""
import re
import shutil
import subprocess
import unittest

import test_live_replay as replay
import test_run8_rows as run8

ROOT, LIVE = replay.ROOT, replay.LIVE
GUEST = ROOT / "Tools/lab/tart/guest"
AX = ROOT / "Tools/lab/tests/fixtures/ax"
OFFSCREEN = (AX / "run8b-main-lockdown-offscreen.txt").read_text()
VISIBLE = (AX / "run8b-main-lockdown-visible.txt").read_text()
# The verifier's crafted Settings dump (F2): the AXWindow line has no frame, the Service tab sits in the toolbar above
# the first group.
SETTINGS = (AX / "settings-service-frameless-window.txt").read_text()
LOCKDOWN = "wgex.protection.lockdown"
TOGGLE = "pos=286,834 size=82x16"
STARTUP_WINDOW = "AXWindow | name=Service | value= | desc= | id= | pos=200,100 size=600x500\n"
STARTUP = (STARTUP_WINDOW +
           f"AXRadioGroup | name=missing value | value= | desc=Connection at startup | id={LIVE.BOOT_STARTUP_GROUP} | pos=300,200 size=260x60 en=true\n"
           "AXRadioButton | name=missing value | value=0 | desc=Off | id=missing value | pos=300,200 size=200x20 en=true\n"
           f"AXRadioButton | name=missing value | value=0 | desc={LIVE.BOOT_STARTUP_LABEL} | id=missing value | pos=300,240 size=240x20 en=true\n")


class DumpRunner(replay.RecordedRunner):
    """Serves AX dumps in order (the last one repeats) and records gui press, scroll and click replies."""

    def __init__(self, dumps, press=b"path=element\n", scroll=b"scroll=action\n"):
        super().__init__()
        self.dumps, self.press, self.scroll = list(dumps), press, scroll

    def run(self, argv, data=None, timeout=100, env=None):
        args = argv[2:] if argv[:1] == ["just"] else []
        if args[:2] == ["gui", "dump"]:
            self.commands.append(list(argv))
            self.clock += 0.01
            return self.reply(argv, (self.dumps.pop(0) if len(self.dumps) > 1 else self.dumps[0]).encode())
        if args[:2] in (["gui", "press"], ["gui", "scroll"]):
            self.commands.append(list(argv))
            self.clock += 0.01
            output = self.press if args[1] == "press" else self.scroll
            return self.reply(argv, output, code=0 if output else 1)
        return super().run(argv, data, timeout, env)


def session(*dumps, **kw):
    runner = DumpRunner(dumps, **kw)
    return runner, LIVE.Session("fixture", {}, runner=runner)


def gui(runner, verb):
    return [argv[3:] for argv in runner.commands if argv[:4] == ["just", "lab", "gui", verb]]


PRESS_ONLY = ["press", "WGEX", "1", LOCKDOWN, "press-only", "AXCheckBox"]


class ElementPathTests(unittest.TestCase):
    def test_a_toggle_still_below_the_content_bottom_is_pressed_press_only_and_never_clicked(self):
        runner, live = session(OFFSCREEN, scroll=b"scroll=none\n")
        self.assertEqual(live.click_id(LOCKDOWN), "element")
        commands = [argv[3] for argv in runner.commands if argv[:3] == ["just", "lab", "gui"]]
        self.assertEqual(commands, ["dump", "scroll", "dump", "press"], "one scroll, a re-dump, then AXPress with no point")
        self.assertEqual(gui(runner, "press"), [PRESS_ONLY])
        self.assertEqual(gui(runner, "click"), [])
        entry = live.ledger[-1]
        self.assertEqual((entry["actionPath"], entry["pressOnly"], entry["elementFrame"], entry["windowFrame"]),
                         ("element-offscreen", "element", [286, 834, 82, 16], [0, 30, 1024, 752]))

    def test_a_toggle_below_the_content_bottom_whose_press_only_fails_is_a_named_gap_and_never_clicked(self):
        runner, live = session(OFFSCREEN, press=b"path=none\n")
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.click_id(LOCKDOWN)
        self.assertEqual(raised.exception.reason, "guiTargetOffscreen:" + LOCKDOWN)
        message = str(raised.exception)
        self.assertIn("286,834 82x16", message)
        self.assertIn("0,30 1024x752", message)
        self.assertIn("after scrolling", message)
        self.assertNotIn("-25200", message)
        self.assertEqual(gui(runner, "scroll"), [["scroll", "WGEX", "1", LOCKDOWN]], "one scroll to the element, then a re-dump")
        self.assertEqual(len(gui(runner, "dump")), 2)
        self.assertEqual(gui(runner, "press"), [PRESS_ONLY] * LIVE.PRESS_ONLY_ATTEMPTS, "only press-only attempts, never a point")
        self.assertEqual(gui(runner, "click"), [], "no click outside the window")
        entry = live.ledger[-1]
        self.assertEqual((entry["elementFrame"], entry["windowFrame"], entry["pressOnly"], entry["error"]),
                         ([286, 834, 82, 16], [0, 30, 1024, 752], "none", "target outside the window"))

    def test_an_unreadable_press_only_reply_is_the_same_named_gap(self):
        runner, live = session(OFFSCREEN, press=b"")
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.click_id(LOCKDOWN)
        self.assertEqual(raised.exception.reason, "guiTargetOffscreen:" + LOCKDOWN)
        self.assertIsNone(live.ledger[-1]["pressOnly"])

    def test_a_toggle_above_the_screen_top_takes_the_scroll_path(self):
        above = OFFSCREEN.replace(TOGGLE, "pos=286,-40 size=82x16")
        self.assertEqual(LIVE.control_frame(above, None, LOCKDOWN), (286, -40, 82, 16))
        runner, live = session(above)
        live.click_id(LOCKDOWN)
        self.assertEqual(gui(runner, "scroll"), [["scroll", "WGEX", "1", LOCKDOWN]])
        self.assertEqual(gui(runner, "press"), [PRESS_ONLY])
        self.assertEqual(live.ledger[-1]["elementFrame"], [286, -40, 82, 16])
        runner, live = session(above, press=b"path=none\n")
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.click_id(LOCKDOWN)
        self.assertEqual(raised.exception.reason, "guiTargetOffscreen:" + LOCKDOWN)
        self.assertIn("286,-40 82x16", str(raised.exception))

    def test_a_container_repeating_the_identifier_is_not_the_pressed_role(self):
        container = ("AXGroup | name=missing value | value=missing value | desc=group | id=wgex.protection.lockdown | "
                     "pos=280,530 size=400x40 en=missing value\n")
        dump = VISIBLE.replace("AXCheckBox | name=missing value | value=0 | desc=checkbox | id=" + LOCKDOWN,
                               container + "AXCheckBox | name=missing value | value=0 | desc=checkbox | id=" + LOCKDOWN)
        self.assertEqual(LIVE.element_role(dump, LOCKDOWN), "AXGroup", "the container comes first in the dump")
        self.assertEqual(LIVE.element_role(dump, LOCKDOWN, (286, 534, 82, 16)), "AXCheckBox")
        runner, live = session(dump)
        live.click_id(LOCKDOWN)
        self.assertEqual(gui(runner, "press"), [["press", "WGEX", "1", LOCKDOWN, "press", "327", "542", "AXCheckBox"]])
        self.assertEqual(live.ledger[-1]["controlRole"], "AXCheckBox")

    def test_a_popup_press_records_an_apple_event_timeout_without_a_coordinate_click(self):
        popup = (STARTUP_WINDOW + "AXPopUpButton | name=missing value | value=5 minutes | desc=Captive window | "
                 "id=wgex.settings.captiveWindow | pos=360,300 size=120x20 en=true\n")
        runner, live = session(popup, press=b"path=element-timeout\n")
        self.assertEqual(live.click_id("wgex.settings.captiveWindow", window="2"), "element-timeout")
        self.assertEqual(gui(runner, "press"), [["press", "WGEX", "2", "wgex.settings.captiveWindow", "press", "420", "310", "AXPopUpButton"]])
        self.assertEqual(gui(runner, "click"), [])
        self.assertEqual((live.ledger[-1]["actionPath"], live.ledger[-1]["popupTimedOut"]), ("element-timeout", True))
        runner, live = session(popup)
        live.click_id("wgex.settings.captiveWindow", window="2")
        self.assertIs(live.ledger[-1]["popupTimedOut"], False)

    def test_the_captive_duration_ledger_records_whether_the_popup_press_timed_out(self):
        settings = (STARTUP_WINDOW +
                    "AXGroup | name=missing value | value=missing value | desc=group | id=wgex.settings.surface | pos=200,100 size=600x500 en=true\n"
                    "AXButton | name=Protection | value=missing value | desc=Protection | id=wgex.settings.tab.protection | pos=300,110 size=60x40 en=true\n"
                    "AXPopUpButton | name=missing value | value=1 minute | desc=Captive window | id=wgex.settings.captiveWindow | pos=360,300 size=120x20 en=true\n")
        for reply, timed_out in ((b"path=element-timeout\n", True), (b"path=element\n", False)):
            with self.subTest(reply=reply):
                # M1-10n: the window shows the Protection title after the tab press (DumpRunner repeats its last dump).
                runner, live = session(settings, settings.replace("AXWindow | name=Service |", "AXWindow | name=Protection |"), press=reply)
                self.assertEqual(live.set_captive_duration(), (60, True), "best-effort duration handling is unchanged")
                entry = live.ledger[-1]
                self.assertEqual((entry["captiveSecondsReadBack"], entry["captivePopupTimedOut"]), (60, timed_out))
                self.assertEqual(gui(runner, "click"), [], "no coordinate click on the popup or its open menu")

    def test_a_toggle_inside_the_window_is_pressed_by_element(self):
        runner, live = session(VISIBLE)
        live.click_id(LOCKDOWN)
        self.assertEqual(gui(runner, "press"), [["press", "WGEX", "1", LOCKDOWN, "press", "327", "542", "AXCheckBox"]])
        self.assertEqual(gui(runner, "click") + gui(runner, "scroll"), [])
        self.assertEqual(live.ledger[-1]["actionPath"], "element")

    def test_an_offscreen_toggle_is_scrolled_into_view_then_pressed(self):
        runner, live = session(OFFSCREEN, VISIBLE)
        live.click_id(LOCKDOWN)
        commands = [argv[3] for argv in runner.commands if argv[:3] == ["just", "lab", "gui"]]
        self.assertEqual(commands, ["dump", "scroll", "dump", "press"])
        self.assertEqual(gui(runner, "press")[0][4:], ["press", "327", "542", "AXCheckBox"])
        self.assertEqual([entry.get("scroll") for entry in live.ledger if "scroll" in entry], ["action"])

    def test_the_rescan_after_a_scroll_survives_an_exhausted_search_budget(self):
        runner, live = session(OFFSCREEN, press=b"path=none\n")
        with self.assertRaises(LIVE.RowFailure):
            live.click_id(LOCKDOWN, timeout=0.005)
        self.assertEqual(len(gui(runner, "dump")), 2, "the re-dump after a scroll is never skipped")

    def test_the_guest_coordinate_fallback_is_reported(self):
        runner, live = session(VISIBLE, press=b"path=coordinate\n")
        live.click_id(LOCKDOWN)
        self.assertEqual(live.ledger[-1]["actionPath"], "coordinate")

    def test_a_failed_action_and_fallback_is_named_not_a_raw_error(self):
        runner, live = session(VISIBLE, press=b"")
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.click_id(LOCKDOWN)
        self.assertEqual(raised.exception.reason, "guiActionFailed:" + LOCKDOWN)
        self.assertIn("327,542", str(raised.exception))

    def test_a_radio_button_without_identifier_is_pressed_through_its_group(self):
        runner, live = session(STARTUP)
        live.click(LIVE.BOOT_STARTUP_LABEL, LIVE.BOOT_STARTUP_GROUP, window="2")
        self.assertEqual(gui(runner, "press"), [["press", "WGEX", "2", LIVE.BOOT_STARTUP_GROUP, "press", "420", "250", "AXRadioGroup",
                                                 LIVE.BOOT_STARTUP_LABEL]])

    def test_label_only_targets_keep_the_centre_click_inside_the_window_and_are_named_outside(self):
        runner, live = session(STARTUP)
        live.click(LIVE.BOOT_STARTUP_LABEL)
        self.assertEqual(gui(runner, "click"), [["click", "420", "250"]])
        runner, live = session(STARTUP.replace("pos=300,240 size=240x20", "pos=300,640 size=240x20"))
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.click(LIVE.BOOT_STARTUP_LABEL)
        self.assertEqual(raised.exception.reason, "guiTargetOffscreen:" + LIVE.BOOT_STARTUP_LABEL)
        self.assertEqual(gui(runner, "click") + gui(runner, "scroll"), [])

    def test_settings_tabs_in_the_toolbar_of_a_frameless_window_are_pressed(self):
        runner, live = session(SETTINGS)
        live.click_first([(None, "wgex.settings.tab.service"), ("Service", None)], window="2")
        self.assertEqual(gui(runner, "press"), [["press", "WGEX", "2", "wgex.settings.tab.service", "press", "430", "156", "AXButton"]])
        self.assertEqual(gui(runner, "scroll") + gui(runner, "click"), [])
        runner, live = session(SETTINGS.replace("id=wgex.settings.tab.service", "id="))
        live.click_first([(None, "wgex.settings.tab.service"), ("Service", None)], window="2")
        self.assertEqual(gui(runner, "click"), [["click", "430", "156"]], "the label fallback lies inside too")

    def test_click_first_moves_on_after_a_named_gap(self):
        tab = "AXButton | name=missing value | value=missing value | desc=tab | id=wgex.settings.tab.service | pos=400,900 size=60x52 en=true\n"
        label = "AXButton | name=Service | value=missing value | desc=Service | id= | pos=400,130 size=60x52 en=true\n"
        runner, live = session("".join(SETTINGS.splitlines(keepends=True)[:3]) + tab + label, press=b"path=none\n")
        live.click_first([(None, "wgex.settings.tab.service"), ("Service", None)], window="2")
        self.assertEqual([argv[4] for argv in gui(runner, "press")], ["press-only"] * LIVE.PRESS_ONLY_ATTEMPTS)
        self.assertEqual(gui(runner, "click"), [["click", "430", "156"]], "the gap on the identifier falls through to the label")
        runner, live = session("".join(SETTINGS.splitlines(keepends=True)[:3]) + tab, press=b"path=none\n")
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.click_first([(None, "wgex.settings.tab.service")], window="2")
        self.assertEqual(raised.exception.reason, "guiTargetOffscreen:wgex.settings.tab.service", "the last choice still raises")

    def test_calibrated_label_positions_are_unchanged(self):
        runner = DumpRunner([OFFSCREEN])
        live = LIVE.Session("fixture", {"Connect": [101, 202]}, runner=runner)
        live.click("Connect")
        self.assertEqual(gui(runner, "click"), [["click", "101", "202"]])


class DumpGeometryTests(unittest.TestCase):
    def test_window_frame_prefers_the_window_line_and_falls_back_to_the_content_group(self):
        self.assertEqual(LIVE.window_frame(VISIBLE), (0, 30, 1024, 752))
        self.assertEqual(LIVE.window_frame(OFFSCREEN), (0, 30, 1024, 752), "run 8b dumps carry the frame on the first group")
        self.assertIsNone(LIVE.window_frame("AXWindow | name=x | value= | desc= | id= |\n"))
        self.assertEqual(LIVE.window_frame(SETTINGS), (132, 130, 760, 702), "frameless window: first group plus toolbar")
        self.assertTrue(LIVE.frame_inside(LIVE.element_target(SETTINGS, "wgex.settings.tab.service")[0], LIVE.window_frame(SETTINGS)))
        self.assertFalse(LIVE.frame_inside((0, 0, 1, 1), None))

    def test_the_run8b_toggle_lies_below_the_content_bottom(self):
        frame, child = LIVE.element_target(OFFSCREEN, LOCKDOWN)
        self.assertEqual((frame, child), ((286, 834, 82, 16), False))
        self.assertFalse(LIVE.frame_inside(frame, LIVE.window_frame(OFFSCREEN)))
        self.assertTrue(LIVE.frame_inside(LIVE.element_target(VISIBLE, LOCKDOWN)[0], LIVE.window_frame(VISIBLE)))

    def test_the_window_title_selector_keeps_the_en_dash_form(self):
        for dump in (OFFSCREEN, VISIBLE):
            title = LIVE.window_title(dump)
            self.assertEqual(title, "wgex-lab-full4 – Connected, last handshake 1 min ago")
            self.assertTrue(LIVE.title_form(title, "wgex-lab-full4"))

    def test_helper_reports_parse_to_fixed_values_only(self):
        self.assertEqual(LIVE.action_path(b"path=element\n"), "element")
        self.assertEqual(LIVE.action_path(b"path=coordinate"), "coordinate")
        self.assertIsNone(LIVE.action_path(b"execution error: -25200"))
        self.assertEqual(LIVE.action_path(b"path=element-timeout\n"), "element-timeout")
        self.assertEqual(LIVE.action_path(b"path=none\n"), "none")
        self.assertEqual(LIVE.action_path(b"scroll=bar\n", "scroll", ("action", "bar", "none")), "bar")


class TargetCoverageTests(unittest.TestCase):
    """Every M1-10h row target with an identifier is actioned by element: no coordinate click remains."""

    def test_run8_rows_never_click_by_coordinate(self):
        for row, runner in [("M5.3-10", run8.Run8Runner()), ("REBOOT-LOCKDOWN", run8.Run8Runner()), ("BOOT-SECRETS", None)]:
            with self.subTest(row=row):
                if runner is None:
                    runner = run8.Run8Runner()
                    runner.boot_secret_mode = True
                runner, _ = run8.run_row(row, runner)
                self.assertEqual(gui(runner, "click"), [])
                pressed = {argv[6] for argv in runner.commands if argv[:4] == ["just", "lab", "gui", "press"]}
                expected = {"M5.3-10": {LOCKDOWN, "wgex.settings.tab.protection", "wgex.settings.captiveWindow", "wgex.main.openCaptiveWindow",
                                        "wgex.protection.confirmCaptiveWindow", "wgex.protection.endCaptiveWindow"},
                            "REBOOT-LOCKDOWN": {LOCKDOWN, "wgex.protection.allowLocalNetwork"},
                            "BOOT-SECRETS": {"wgex.settings.tab.service", LIVE.BOOT_STARTUP_GROUP}}[row]
                self.assertTrue(expected <= pressed, sorted(expected - pressed))

    def test_import_and_connect_use_the_element_path(self):
        runner, _ = replay.LiveReplayTests().run_recorded("M5.1-08")
        pressed = [argv[6] for argv in runner.commands if argv[:4] == ["just", "lab", "gui", "press"]]
        self.assertIn("wgex.main.action", pressed, "Connect is the toolbar wgex.main.action")
        runner, _ = replay.LiveReplayTests().run_recorded("M5.1-04")
        pressed = [argv[6] for argv in runner.commands if argv[:4] == ["just", "lab", "gui", "press"]]
        self.assertEqual(pressed[:2], ["wgex.main.sidebarImport", "wgex.importReview.importAndConnect"])


class HelperShapeTests(unittest.TestCase):
    def test_the_element_helper_is_static_and_acts_by_identifier(self):
        helper = (GUEST / "ax-action.applescript").read_text()
        for needle in ['perform action actionName of found', '"AXPress"', '"AXConfirm"', '"AXScrollToVisible"', '"AXIdentifier"',
                       '"AXVerticalOrientation"', "item 3 of argv", 'return my pressResult("path=element", pressStamp)',
                       'return my pressResult("path=coordinate", pressStamp)',
                       'modeName is "press-only"', 'roleName is "-" or (role of e as text) is roleName', 'foundRole is "AXPopUpButton"',
                       "ignoring application responses",
                       'if errorNumber is -1712 then return my pressResult("path=element-timeout", pressStamp)']:
            self.assertIn(needle, helper)
        # M1-10o fix pass 2 (F1): the only shell is the fixed guest-clock read before a press; no argument reaches a shell.
        self.assertEqual(re.findall(r"do shell script .*", helper),
                         ["do shell script \"/usr/bin/perl -MTime::HiRes=time -e 'printf q(%.3f), time'\""])
        self.assertLess(helper.index('if pointX is missing value then\n    if pressError is missing value then return "path=miss"'),
                        helper.index("click at {pointX, pointY}"), "press-only (no point) returns before any coordinate click")
        gui_sh = (ROOT / "Tools/lab/tart/gui.sh").read_text()
        self.assertIn('"$LAB_DIR/guest/ax-action.applescript"', gui_sh)
        self.assertIn("^path=(element|element-timeout|coordinate|miss|error\\ number=-?[0-9]{1,10})$", gui_sh)
        dump = (GUEST / "ax-dump.applescript").read_text()
        self.assertIn("position of window winIdx", dump)
        self.assertIn('"AXWindow | name=" & t & " | value= | desc= | id= |" & frame', dump)

    def test_the_applescripts_compile_without_running(self):
        if shutil.which("osacompile") is None:
            self.skipTest("osacompile unavailable")
        for name in ["ax-action.applescript", "ax-dump.applescript"]:
            with self.subTest(name=name):
                result = subprocess.run(["osacompile", "-o", "/dev/null", str(GUEST / name)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace")[:400])


if __name__ == "__main__":
    unittest.main()
