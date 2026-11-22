# SPDX-License-Identifier: MIT
"""M1-10r, guest run 8f (wgex-plan/evidence/run8f/REPORT-2026-10-31.txt section 6): in the Settings Service tab every
startup radio button exposes the group's label "Connection at startup" as its name and carries no title or identifier of
its own, so BOOT-SECRETS's label lookup never matched. The driver now selects the option by position inside
wgex.main.startupOption (the order of MacStartupOption), presses it by role and exact frame, and confirms
the radio values before the daemon state. Separately (M1-10q FIX1-VERIFY N1), the Allow LAN toggle is never pressed a
second time without reading its value. M1-10t (M1-10r VERIFY N1 and VERIFY-B L1-L4, N6, N8): the position step is always
press-only, an immediate gap on a press miss, a row or column layout check before any press, capped and filtered gap lines,
a named gap when the dump fails; Allow LAN is set by compare-and-press with the value read before every press, each press
journalled and capped over the whole Session. The fixture is the run 8f Service-tab dump (BOOT-SECRETS-settings-service-dump.txt,
no home path in it). Recorded replies only; never a VM, never osascript."""
import re
import unittest
from unittest.mock import patch

import test_gui_element as element
import test_run8_rows as run8
from test_run8e_driver import steps

LIVE, ROOT = element.LIVE, element.ROOT
SERVICE = (element.AX / "run8f-settings-service.txt").read_text()
GROUP = LIVE.BOOT_STARTUP_GROUP
OFF, LOGIN, BOOT = (466, 744, 40, 16), (522, 744, 120, 16), (659, 744, 195, 16)
BOOT_FRAME = "frame=659,744,195x16"
BOOT_PRESS = ["press", "WGEX", "1", "-", "press-only", "AXRadioButton", BOOT_FRAME]
ALLOW_LAN = LIVE.ALLOW_LAN_TOGGLE
BUTTON = re.compile(r"(AXRadioButton \| name=Connection at startup \| value=)([01])( \| desc=radio button \| id= \| pos=\d+,\d+ )")


def with_values(dump, values):
    """The run 8f dump with the three radio values set, in x order (the fixture lists them in x order)."""
    it = iter(values)
    return BUTTON.sub(lambda m: m[1] + next(it) + m[3], dump)


SELECTED = with_values(SERVICE, "001")


def presses(runner):
    return element.gui(runner, "press")


class StartupOrderTests(unittest.TestCase):
    def test_the_option_order_is_the_app_source_order(self):
        source = (ROOT / "Packages/WGEXUI/Sources/WGEXUI/Screens/Mac/MacPreferences.swift").read_text()
        self.assertIn("case off, login, boot\n", source)
        # The restyle moved the start-up choice from onboarding to the tunnel page's start-up sheet (DEC-135).
        view = (ROOT / "Packages/WGEXUI/Sources/WGEXUI/Screens/Mac/MacTunnelPage.swift").read_text()
        self.assertIn("ForEach(MacStartupOption.allCases) { option in", view)
        self.assertIn('.wgexControl(.main, "startupOption"', view)
        self.assertIn(f'"{LIVE.BOOT_STARTUP_GROUP}"', (ROOT / "Packages/WGEXUI/Sources/WGEXUI/Presentation/WGEXAccessibility.swift").read_text())
        self.assertEqual(LIVE.STARTUP_OPTIONS, ("off", "login", "boot"))
        strings = (ROOT / "Packages/WGEXUI/Sources/WGEXUI/Presentation/MacStrings+Onboarding.swift").read_text()
        self.assertIn(f'static let connectAtBootBeforeLogin = "{LIVE.BOOT_STARTUP_LABEL}"', strings)


class PositionParserTests(unittest.TestCase):
    def test_the_run_8f_label_lookup_cannot_match(self):
        with self.assertRaises(ValueError):
            LIVE.element_target(SERVICE, GROUP, LIVE.BOOT_STARTUP_LABEL)
        with self.assertRaises(ValueError):
            LIVE.control_frame(SERVICE, LIVE.BOOT_STARTUP_LABEL)

    def test_the_run_8f_group_has_three_buttons_in_x_order(self):
        options = LIVE.radio_options(SERVICE, GROUP)
        self.assertEqual([option["frame"] for option in options], [OFF, LOGIN, BOOT])
        self.assertEqual([option["value"] for option in options], ["1", "0", "0"])
        self.assertTrue(all(option["enabled"] for option in options))
        lines = LIVE.group_lines(SERVICE, GROUP)
        self.assertEqual([line.split(" |", 1)[0] for line in lines],
                         ["AXRadioGroup", "AXStaticText", "AXRadioButton", "AXRadioButton", "AXRadioButton"])

    def test_x_order_wins_over_dump_order(self):
        lines = SERVICE.splitlines()
        first = next(i for i, line in enumerate(lines) if line.startswith("AXRadioButton"))
        lines[first], lines[first + 2] = lines[first + 2], lines[first]
        self.assertEqual([option["frame"] for option in LIVE.radio_options("\n".join(lines), GROUP)], [OFF, LOGIN, BOOT])

    def test_selected_needs_the_chosen_value_1_and_every_other_value_0(self):
        index = LIVE.STARTUP_OPTIONS.index("boot")
        self.assertFalse(LIVE.option_selected(LIVE.radio_options(SERVICE, GROUP), index, 3))
        self.assertTrue(LIVE.option_selected(LIVE.radio_options(SELECTED, GROUP), index, 3))
        self.assertFalse(LIVE.option_selected(LIVE.radio_options(with_values(SERVICE, "101"), GROUP), index, 3))
        self.assertFalse(LIVE.option_selected(LIVE.radio_options(SELECTED, GROUP)[1:], index - 1, 3))

    def test_a_missing_or_repeated_group_has_no_options(self):
        self.assertEqual(LIVE.radio_options(SERVICE.replace(GROUP, "wgex.onboarding.other"), GROUP), [])
        repeated = SERVICE + f"AXGroup | name=x | value= | desc= | id={GROUP} | pos=0,0 size=10x10 en=true\n"
        self.assertEqual(LIVE.radio_options(repeated, GROUP), [])


class SelectByPositionTests(unittest.TestCase):
    def test_the_boot_option_is_pressed_by_role_and_frame_and_confirmed_by_its_value(self):
        runner, live = element.session(SERVICE, SELECTED)
        self.assertEqual(live.select_startup_option("1", "boot"), "element")
        self.assertEqual(presses(runner), [BOOT_PRESS], "press-only: no point, never a click (run 8g pressed by element)")
        self.assertEqual(element.gui(runner, "click"), [])
        pressed = next(item for item in live.ledger if item.get("controlGroup") == GROUP and "actionPath" in item)
        self.assertEqual((pressed["startupOptionIndex"], pressed["elementFrame"], pressed["pressOnly"]), (2, list(BOOT), True))
        self.assertEqual(pressed["startupLayout"], "row")
        self.assertTrue(live.ledger[-1]["startupOptionSelected"])
        self.assertEqual(live.last_press["path"], "element")

    def test_a_value_that_lags_the_press_is_read_again(self):
        runner, live = element.session(SERVICE, SERVICE, SELECTED)
        self.assertEqual(live.select_startup_option("1", "boot"), "element")
        self.assertEqual(len(presses(runner)), 1)

    def test_values_that_never_change_are_the_named_gap_with_the_group_lines(self):
        runner, live = element.session(SERVICE)
        started = runner.clock
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.select_startup_option("1", "boot")
        self.assertEqual(raised.exception.reason, "startupOptionNotSelected")
        message = str(raised.exception)
        self.assertIn("radio button 3 of 3 (boot)", message)
        self.assertIn(f"id={GROUP} | pos=170,744 size=684x16", message)
        self.assertIn("AXRadioButton | name=Connection at startup | value=1 | desc=radio button | id= | pos=466,744", message)
        self.assertNotIn("Lockdown", message, "only the group's own lines")
        self.assertEqual(len(presses(runner)), 1, "one press; the gap never presses again")
        self.assertLess(runner.clock - started, LIVE.HARNESS.seconds("BOOT_INTENT_CONFIRM") + 2)
        self.assertFalse(live.ledger[-1]["startupOptionSelected"])

    def test_a_frame_below_the_window_is_pressed_press_only_and_never_clicked(self):
        short = SERVICE.replace("pos=62,30 size=900x738", "pos=62,30 size=900x700", 1)
        runner, live = element.session(short, with_values(short, "001"))
        self.assertEqual(live.select_startup_option("1", "boot"), "element")
        self.assertEqual(presses(runner), [BOOT_PRESS])
        self.assertEqual(element.gui(runner, "click"), [])

    def test_a_group_without_three_buttons_is_the_named_gap_without_a_press(self):
        two = "\n".join(line for line in SERVICE.splitlines() if "pos=522,744" not in line) + "\n"
        runner, live = element.session(two)
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.select_startup_option("1", "boot")
        self.assertEqual(raised.exception.reason, "startupOptionNotSelected")
        self.assertIn("did not show 3 radio buttons", str(raised.exception))
        self.assertEqual(presses(runner), [])

    def test_a_disabled_option_is_never_pressed(self):
        disabled = SERVICE.replace("pos=659,744 size=195x16 en=true", "pos=659,744 size=195x16 en=false")
        runner, live = element.session(disabled)
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.select_startup_option("1", "boot")
        self.assertEqual(raised.exception.reason, "startupOptionNotSelected")
        self.assertEqual(presses(runner), [])


WIDE = SERVICE.replace(f"id={GROUP} | pos=170,744 size=684x16", f"id={GROUP} | pos=170,744 size=684x40")


def with_frames(dump, frames):
    """The run 8f dump with the three radio buttons at these (x, y) positions, in dump order (the group is made 40 high)."""
    it = iter(frames)
    return re.sub(r"(AXRadioButton \| name=Connection at startup \| value=[01] \| desc=radio button \| id= \| pos=)\d+,744",
                  lambda m: m[1] + "%d,%d" % next(it), WIDE if dump is SERVICE else dump)


class PressOutcomeTests(unittest.TestCase):
    """M1-10r VERIFY N1: a press that did not act is the gap at once, not after BOOT_INTENT_CONFIRM."""

    def refused(self, press):
        runner, live = element.session(SERVICE, press=press)
        started = runner.clock
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.select_startup_option("1", "boot")
        self.assertEqual(raised.exception.reason, "startupOptionNotSelected")
        self.assertLess(runner.clock - started, 5, "no BOOT_INTENT_CONFIRM wait")
        self.assertEqual(presses(runner), [BOOT_PRESS], "one press, never repeated")
        self.assertEqual(len(element.gui(runner, "dump")), 1, "no confirmation re-dump")
        self.assertIsNone(live.last_press)
        return str(raised.exception)

    def test_a_lookup_miss_is_named_at_once(self):
        message = self.refused(b"path=miss\n")
        self.assertIn("lookup miss", message)
        self.assertIn("radio button 3 of 3 (boot)", message)
        self.assertIn("was not pressed", message)

    def test_an_axpress_error_is_named_at_once(self):
        self.assertIn("AXPress error -25200", self.refused(b"path=error number=-25200\n"))

    def test_a_helper_failure_and_an_empty_reply_are_named_at_once(self):
        self.assertIn("helper failed", self.refused(b"ax-action=failed exit=1\n"))
        self.assertIn("no path reported", self.refused(b""))


class LayoutTests(unittest.TestCase):
    """M1-10r VERIFY-B L1: only a row (or a column) in dump order means "the Nth option"; nothing else is pressed."""

    def refused(self, dump):
        runner, live = element.session(dump)
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.select_startup_option("1", "boot")
        self.assertEqual(raised.exception.reason, "startupOptionNotSelected")
        self.assertEqual(presses(runner), [], "nothing is pressed in an ambiguous layout")
        self.assertEqual(len(element.gui(runner, "dump")), 1, "refused at once, not after the search deadline")
        self.assertIn("neither in one row nor in one column", str(raised.exception))
        return live

    def test_the_run_8f_row_is_a_row(self):
        self.assertEqual(LIVE.radio_layout(LIVE.radio_options(SERVICE, GROUP)), "row")

    def test_a_wrapped_group_is_refused(self):
        live = self.refused(with_frames(SERVICE, [(466, 744), (522, 744), (466, 760)]))
        self.assertEqual(live.ledger[-1]["error"], "ambiguous radio layout")
        self.assertEqual(live.ledger[-1]["startupOptionFrames"], [[466, 744, 40, 16], [466, 760, 195, 16], [522, 744, 120, 16]])

    def test_a_mirrored_group_is_refused(self):
        """Right to left: the dump keeps the logical order (Off, login, boot), the x values run backwards."""
        self.refused(with_frames(SERVICE, [(814, 744), (692, 744), (466, 744)]))

    def test_a_diagonal_group_is_refused(self):
        self.refused(with_frames(SERVICE, [(466, 744), (522, 750), (659, 756)]))

    def test_a_column_in_dump_order_is_pressed_by_its_bottom_button(self):
        column = with_frames(SERVICE, [(466, 744), (466, 760), (466, 776)]).replace("pos=170,744 size=684x40", "pos=170,744 size=684x80")
        options = LIVE.radio_options(column, GROUP)
        self.assertEqual(LIVE.radio_layout(options), "column")
        runner, live = element.session(column, with_values(column, "001"))
        self.assertEqual(live.select_startup_option("1", "boot"), "element")
        self.assertEqual(presses(runner), [["press", "WGEX", "1", "-", "press-only", "AXRadioButton", "frame=466,776,195x16"]])
        self.assertEqual(live.ledger[-3]["startupLayout"], "column")

    def test_fewer_than_two_options_have_no_layout(self):
        self.assertIsNone(LIVE.radio_layout([]))
        self.assertIsNone(LIVE.radio_layout(LIVE.radio_options(SERVICE, GROUP)[:1]))


class GapLineTests(unittest.TestCase):
    """M1-10r VERIFY-B N6: no unbounded or credential-bearing dump text in a gap or the ledger."""

    def test_gap_lines_are_capped_in_count_and_width_and_filtered(self):
        lines = [f"AXStaticText | name=line {n} " + "x" * 400 for n in range(20)]
        lines[1] = "AXTextField | name=Private key | value=" + "A" * 43 + "= | id=x"
        lines[2] = "AXStaticText | name=ctrl\x07char\x1b[31m | id=y"
        shown = LIVE.gap_lines(lines)
        self.assertEqual(len(shown), LIVE.GAP_LINES + 1)
        self.assertEqual(shown[-1], f"(+{20 - LIVE.GAP_LINES} more lines)")
        self.assertTrue(all(len(line) <= LIVE.GAP_LINE_WIDTH for line in shown[:-1]))
        self.assertTrue(shown[0].endswith("..."))
        self.assertEqual(shown[1], "<redacted credential line>")
        self.assertNotIn("\x07", shown[2])
        self.assertNotIn("\x1b", shown[2])
        self.assertEqual(LIVE.gap_lines(["a", "b"]), ["a", "b"])
        self.assertEqual(LIVE.gap_lines([]), [])

    def test_a_group_as_big_as_the_window_cannot_dump_the_window_into_a_verdict(self):
        huge = SERVICE.replace(f"id={GROUP} | pos=170,744 size=684x16", f"id={GROUP} | pos=0,0 size=1024x2000")
        secret = "AXStaticText | name=wrapping key reminder | value=x | desc=text | id= | pos=10,10 size=10x10 en=true\n"
        huge += secret + "".join(f"AXStaticText | name=filler {n} | value=v | desc=text | id= | pos={n},20 size=10x10 en=true\n" for n in range(40))
        runner, live = element.session(huge)
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.select_startup_option("1", "boot")
        message = str(raised.exception)
        self.assertGreater(len(LIVE.group_lines(huge, GROUP)), 40, "the group frame holds the whole dump")
        group_dump = message.split("group dump: ", 1)[1]
        self.assertLessEqual(len(group_dump.split(" / ")), LIVE.GAP_LINES + 1)
        self.assertIn("more lines)", group_dump)
        self.assertNotIn("wrapping key", message)
        recorded = live.ledger[-1]["startupGroupLines"]
        self.assertLessEqual(len(recorded), LIVE.GAP_LINES + 1)
        self.assertTrue(all(len(line) <= LIVE.GAP_LINE_WIDTH for line in recorded))


class FailingDumpRunner(element.DumpRunner):
    """DumpRunner whose gui dump fails with exit status 1 (an osascript or SSH failure that gui.sh does not swallow)."""

    def run(self, argv, data=None, timeout=100, env=None):
        if argv[2:4] == ["gui", "dump"]:
            self.commands.append(list(argv))
            self.clock += 0.01
            return self.reply(argv, b"", code=1)
        return super().run(argv, data, timeout, env)


class DumpFailureTests(unittest.TestCase):
    """M1-10r VERIFY-B N8: a failing accessibility dump is a named gap, and no longer skips the position step."""

    def test_a_failing_dump_is_the_named_gap_after_the_search_without_a_press(self):
        runner = FailingDumpRunner([SERVICE])
        live = LIVE.Session("fixture", {}, runner=runner)
        started = runner.clock
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.select_startup_option("1", "boot")
        self.assertEqual(raised.exception.reason, "startupOptionNotSelected")
        self.assertIn("accessibility dump of window 1 failed", str(raised.exception))
        self.assertIn("nothing was pressed", str(raised.exception))
        self.assertEqual(presses(runner), [])
        search = LIVE.HARNESS.seconds("GUI_SEARCH")
        self.assertTrue(search <= runner.clock - started < search + 2)
        self.assertEqual(live.ledger[-1]["error"], "accessibility dump failed")

    def test_a_dump_that_recovers_is_used(self):
        class Flaky(FailingDumpRunner):
            def __init__(self, *dumps):
                super().__init__(dumps)
                self.failures = 2

            def run(self, argv, data=None, timeout=100, env=None):
                if argv[2:4] == ["gui", "dump"] and self.failures:
                    self.failures -= 1
                    return FailingDumpRunner.run(self, argv, data, timeout, env)
                return element.DumpRunner.run(self, argv, data, timeout, env)

        runner = Flaky(SERVICE, SELECTED)
        live = LIVE.Session("fixture", {}, runner=runner)
        self.assertEqual(live.select_startup_option("1", "boot"), "element")
        self.assertEqual(presses(runner), [BOOT_PRESS])

    def test_a_dump_failure_in_the_label_search_still_reaches_the_position_step(self):
        runner = FailingDumpRunner([SERVICE])
        live = LIVE.Session("fixture", {}, runner=runner)
        with patch.object(live, "open_settings", return_value="1"), patch.object(live, "select_settings_tab"), \
                patch.object(live, "close_settings"), patch.object(live, "boot_intent", return_value=True):
            with self.assertRaises(LIVE.RowFailure) as raised:
                live.set_startup_boot("00000000-0000-0000-0000-000000000000")
        self.assertEqual(raised.exception.reason, "startupOptionNotSelected", "a named gap, not a bare RuntimeError")


class SetStartupBootTests(unittest.TestCase):
    def run_boot(self, *dumps):
        runner, live = element.session(*dumps)
        with patch.object(live, "open_settings", return_value="1"), patch.object(live, "select_settings_tab"), \
                patch.object(live, "close_settings"), patch.object(live, "boot_intent", return_value=True):
            self.assertTrue(live.set_startup_boot("00000000-0000-0000-0000-000000000000"))
        return runner, live

    def test_run_8f_falls_back_from_the_label_to_the_position_and_then_reads_the_daemon(self):
        runner, live = self.run_boot(SERVICE, SERVICE, SERVICE, SELECTED)
        self.assertEqual(presses(runner), [BOOT_PRESS])
        labels = [item for item in live.ledger if item.get("controlLabel") == LIVE.BOOT_STARTUP_LABEL]
        self.assertEqual([item["controlIdentifier"] for item in labels], [GROUP, None], "the label lookup still runs first")
        self.assertEqual((live.ledger[-1]["startupChoice"], live.ledger[-1]["bootIntentReported"]), ("position", True))

    def test_a_build_with_distinct_labels_keeps_the_label_path(self):
        runner, live = self.run_boot(element.STARTUP)
        self.assertEqual(presses(runner), [["press", "WGEX", "1", GROUP, "press", "420", "250", "AXRadioGroup", LIVE.BOOT_STARTUP_LABEL]])
        self.assertEqual(live.ledger[-1]["startupChoice"], "label")

    def test_the_daemon_still_has_to_agree(self):
        runner, live = element.session(SELECTED)
        with patch.object(live, "open_settings", return_value="1"), patch.object(live, "select_settings_tab"), \
                patch.object(live, "close_settings"), patch.object(live, "boot_intent", return_value=False):
            with self.assertRaises(LIVE.RowFailure) as raised:
                live.set_startup_boot("00000000-0000-0000-0000-000000000000")
        self.assertEqual(raised.exception.reason, "bootIntentNotApplied")


class AllowLANToggleRunner(run8.Run8Runner):
    """Run8Runner whose daemon journal confirms a landed Allow LAN press `lag` seconds late (never when lag is None),
    whose first `misses` presses do not land, and whose main window dump shows the toggle's value (unreadable: none).
    daemon_backed (M1-10t, M1-10r VERIFY-B L3): the toggle reads on until the journal confirms off, as the app's does (its
    value is the daemon-confirmed cache), and a press proposes the opposite of what the toggle shows, as SwiftUI's Toggle
    does, so a second press while it still reads on re-sends off. shown: a fixed AX value. sequence: the values the next
    dumps of the toggle show, the last one repeating (a toggle that changes between the read and the press-time dump)."""

    def __init__(self, lag=0.0, misses=0, unreadable=False, daemon_backed=False, shown=None, sequence=None):
        super().__init__()
        self.lag, self.misses, self.unreadable, self.journal_at = lag, misses, unreadable, None
        self.daemon_backed, self.shown, self.sequence = daemon_backed, shown, list(sequence or [])

    def toggle_shown(self):
        if self.unreadable:
            return ""
        if self.sequence:
            return self.sequence.pop(0) if len(self.sequence) > 1 else self.sequence[0]
        if self.shown is not None:
            return self.shown
        if self.daemon_backed:
            return "1" if self.allow_lan or self.journal_at is None or self.clock < self.journal_at else "0"
        return super().toggle_shown()

    def run(self, argv, data=None, timeout=100, env=None):
        args = argv[2:] if argv[:1] == ["just"] else []
        pressing = args[:2] == ["gui", "press"] and ALLOW_LAN in args
        shown_before = self.toggle_shown() if pressing and self.daemon_backed else None
        was_on = self.allow_lan
        if pressing and self.misses:
            self.misses -= 1
            self.allow_lan_works = False
        result = super().run(argv, data, timeout, env)
        if pressing:
            if self.daemon_backed and self.allow_lan_works:
                self.allow_lan = shown_before == "0"
            if self.allow_lan_works and was_on and not self.allow_lan:
                self.journal_at = None if self.lag is None else self.clock + self.lag
            self.allow_lan_works = True
        if args[:2] == ["ssh", "--"] and "verdict-actions.sh allow-lan-state" in args[2] and not self.allow_lan:
            if self.journal_at is None or self.clock < self.journal_at:
                return self.reply(argv, b"allowLAN=true\n")
        return result


def allow_lan_presses(runner):
    return sum(1 for argv in runner.commands if argv[:4] == ["just", "lab", "gui", "press"] and ALLOW_LAN in argv)


def toggle_reads(live):
    return [(item["toggleBeforePress"], item["toggleValue"]) for item in live.ledger if "toggleValue" in item]


class AllowLANSecondPressTests(unittest.TestCase):
    """M1-10q FIX1-VERIFY N1: a late first press is never followed by a second that turns Allow LAN back on. M1-10t: the
    toggle is read before every press, the first included."""

    CONFIRM_SECONDS = LIVE.HARNESS.seconds("LOCKDOWN_CONFIRM")

    def test_a_late_journal_with_the_toggle_off_gets_more_time_and_no_second_press(self):
        runner = AllowLANToggleRunner(lag=self.CONFIRM_SECONDS + 5)
        live = LIVE.Session("fixture", {}, runner=runner)
        self.assertIs(live.set_allow_lan_off(), False)
        self.assertEqual(allow_lan_presses(runner), 1)
        self.assertFalse(runner.allow_lan, "never pressed back on")
        self.assertEqual(toggle_reads(live), [(1, True), (2, False)])
        read = [item for item in live.ledger if "toggleValue" in item][1]
        self.assertEqual(read, dict(toggleIdentifier=ALLOW_LAN, toggleBeforePress=2, toggleValue=False, journalReported=True))
        dump = next(item for item in reversed(live.ledger) if item.get("argv", [])[:4] == ["just", "lab", "gui", "dump"])
        self.assertEqual((dump["argv"][-1], dump["dumpMode"]), (ALLOW_LAN, "target"))
        self.assertEqual(live.ledger[-1], dict(allowLANRequested=False, allowLANReported=False, togglePresses=1))

    def test_a_journal_that_never_confirms_is_allow_lan_not_applied_after_one_press(self):
        runner = AllowLANToggleRunner(lag=None)
        live = LIVE.Session("fixture", {}, runner=runner)
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.set_allow_lan_off()
        self.assertEqual(raised.exception.reason, "allowLANNotApplied")
        self.assertIn(f"after 1 press(es) of {ALLOW_LAN} (toggle value False)", str(raised.exception))
        self.assertEqual(allow_lan_presses(runner), 1)
        self.assertFalse(runner.allow_lan, "Allow LAN was never pressed back on")

    def test_a_press_that_did_not_land_is_pressed_again(self):
        runner = AllowLANToggleRunner(misses=1)
        live = LIVE.Session("fixture", {}, runner=runner)
        self.assertIs(live.set_allow_lan_off(), False)
        self.assertEqual(allow_lan_presses(runner), 2)
        self.assertEqual(toggle_reads(live), [(1, True), (2, True)])

    def test_an_unreadable_toggle_is_never_pressed_blind_not_even_the_first_time(self):
        runner = AllowLANToggleRunner(misses=1, unreadable=True)
        live = LIVE.Session("fixture", {}, runner=runner)
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.set_allow_lan_off()
        self.assertEqual(raised.exception.reason, "allowLANNotApplied")
        self.assertEqual(allow_lan_presses(runner), 0, "the journal reads on and the toggle cannot be read: no press")
        self.assertEqual(toggle_reads(live), [(1, None)])
        runner = AllowLANToggleRunner()
        live = LIVE.Session("fixture", {}, runner=runner)
        live.journal_allow_lan = lambda: None
        with self.assertRaises(LIVE.RowFailure):
            live.set_allow_lan_off()
        self.assertEqual(toggle_reads(live), [(1, True), (2, False)], "an unreadable journal reads the toggle before the first press too")
        self.assertEqual(allow_lan_presses(runner), 1, "pressed only while the toggle read on")
        self.assertFalse(runner.allow_lan)

    def test_reboot_lockdown_still_passes_with_one_press_after_one_read(self):
        runner, result = run8.run_row("REBOOT-LOCKDOWN", AllowLANToggleRunner())
        self.assertEqual(allow_lan_presses(runner), 1)
        reads = [item for item in steps(result) if "toggleValue" in item]
        self.assertEqual([(item["toggleBeforePress"], item["toggleValue"]) for item in reads], [(1, True)], "one read before the one press")


class CompareAndPressTests(unittest.TestCase):
    """M1-10r VERIFY-B L2 and L4: the value is read before the first press whatever the journal says, and the press is taken
    from a dump that must show the same value."""

    def test_a_stale_toggle_that_reads_off_is_not_pressed_although_the_journal_says_on(self):
        runner = AllowLANToggleRunner(shown="0")
        live = LIVE.Session("fixture", {}, runner=runner)
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.set_allow_lan_off()
        self.assertEqual(raised.exception.reason, "allowLANNotApplied")
        self.assertEqual(allow_lan_presses(runner), 0, "a press on a toggle that reads off would propose on, a loosening change")
        self.assertEqual(toggle_reads(live), [(1, False)])

    def test_a_toggle_that_changes_between_the_read_and_the_press_is_not_pressed(self):
        runner = AllowLANToggleRunner(sequence=["1", "0"])
        live = LIVE.Session("fixture", {}, runner=runner)
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.set_allow_lan_off()
        self.assertEqual(raised.exception.reason, "allowLANNotApplied")
        self.assertEqual(allow_lan_presses(runner), 0)
        moved = next(item for item in live.ledger if "toggleSeen" in item)
        self.assertEqual((moved["controlIdentifier"], moved["toggleExpected"], moved["toggleSeen"]), (ALLOW_LAN, True, False))
        self.assertEqual(toggle_reads(live), [(1, True), (1, False)], "read again after the refusal; off needs no press")
        self.assertEqual(live.toggle_journal[ALLOW_LAN], [])

    def test_a_toggle_that_keeps_changing_is_given_up_after_two_refusals(self):
        runner = AllowLANToggleRunner(sequence=["1", "0", "1", "0", "1", "0"])
        live = LIVE.Session("fixture", {}, runner=runner)
        with self.assertRaises(LIVE.RowFailure):
            live.set_allow_lan_off()
        self.assertEqual(allow_lan_presses(runner), 0)
        self.assertEqual(len(element.gui(runner, "dump")), 4, "read, refused, read, refused: no third attempt")

    def test_the_compare_is_made_in_the_dump_the_press_is_taken_from(self):
        runner = AllowLANToggleRunner()
        live = LIVE.Session("fixture", {}, runner=runner)
        live.set_allow_lan_off()
        order = [argv[3] for argv in runner.commands if argv[:3] == ["just", "lab", "gui"] and argv[3] in ("dump", "press")]
        self.assertEqual(order[:3], ["dump", "dump", "press"], "the read, the press-time dump, then the press")
        self.assertIsNone(live.toggle_expected, "the expectation never outlives the press")


class DaemonBackedToggleTests(unittest.TestCase):
    """M1-10r VERIFY-B L3: the app's toggle follows the daemon-confirmed value. With a slow daemon it still reads on after the
    confirm wait; the second press then re-sends off (a tightening change), never turns Allow LAN back on."""

    CONFIRM_SECONDS = LIVE.HARNESS.seconds("LOCKDOWN_CONFIRM")

    def test_a_slow_daemon_gets_a_second_press_with_the_toggle_reading_on(self):
        runner = AllowLANToggleRunner(lag=self.CONFIRM_SECONDS + 5, daemon_backed=True)
        live = LIVE.Session("fixture", {}, runner=runner)
        self.assertIs(live.set_allow_lan_off(), False)
        self.assertEqual(allow_lan_presses(runner), 2)
        self.assertFalse(runner.allow_lan, "both presses proposed off; Allow LAN never came back on")
        self.assertEqual(toggle_reads(live), [(1, True), (2, True)])
        self.assertEqual(live.toggle_journal[ALLOW_LAN], [dict(press=1, valueBefore=True), dict(press=2, valueBefore=True)])
        self.assertEqual([item["togglePress"] for item in live.ledger if "togglePress" in item], [1, 2])
        self.assertEqual(live.ledger[-1], dict(allowLANRequested=False, allowLANReported=False, togglePresses=2))

    def test_the_press_limit_holds_over_a_retry_after_a_failure(self):
        runner = AllowLANToggleRunner(lag=None, daemon_backed=True)
        live = LIVE.Session("fixture", {}, runner=runner)
        for attempt in (1, 2):
            with self.assertRaises(LIVE.RowFailure) as raised:
                live.set_allow_lan_off()
            self.assertEqual(raised.exception.reason, "allowLANNotApplied")
            self.assertEqual(allow_lan_presses(runner), LIVE.TOGGLE_PRESS_LIMIT, f"attempt {attempt}: never more than the limit in total")
        self.assertEqual(len(live.toggle_journal[ALLOW_LAN]), LIVE.TOGGLE_PRESS_LIMIT)
        self.assertEqual(live.ledger[-1], dict(allowLANRequested=False, allowLANReported=True, togglePresses=0))


if __name__ == "__main__":
    unittest.main()
