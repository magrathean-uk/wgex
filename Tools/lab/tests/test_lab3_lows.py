# SPDX-License-Identifier: MIT
"""M1-10t part 4 (LAB2-VERIFY F-1, F-2; lab lows from part 3's verify). Recorded replies and fixtures only; no subprocess, never a
VM, never osascript.

F-1: an ambiguous post-scroll dump that carries the remembered frame is compared on the line with that frame, the line the press
     targets, never on the first line that carries the identifier.
F-2: press_sent is set before the press command, so a press that lands and whose runner then raises (a deadline, an interrupt) is
     journalled as an attempt; BaseException, not Exception, so a KeyboardInterrupt counts too."""
import subprocess
import unittest

import test_gui_element as element
import test_gui_post_scroll as post
import test_lab2_lows as lows
import test_startup_position as position

LIVE = element.LIVE
ALLOW_LAN = lows.ALLOW_LAN
REMEMBERED_FRAME = "frame=584,834,138x16"


def line_at(value, y):
    """The run 8b Allow LAN dump line (584,834 value=1) moved to 584,y with this value."""
    return lows.ALLOW_LAN_LINE.replace("pos=584,834", f"pos=584,{y}").replace("value=1", f"value={value}")


def ambiguous_dump(first, second):
    """The off-screen Allow LAN dump (the lockdown line dropped) with its single Allow LAN line replaced by two enabled
    AXCheckBox lines in this order, each (value, y)."""
    return lows.allow_lan_offscreen(1).replace(lows.ALLOW_LAN_LINE, line_at(*first) + line_at(*second))


class AmbiguousPostScrollCompareTests(unittest.TestCase):
    """F-1. Pre-scroll the toggle sits below the window at 584,834 showing on (value=1); the caller read on, so toggle_expected is
    (id, True). A press while the toggle shows off proposes on, a loosening change."""

    def attempt(self, after):
        runner, live = post.session([lows.allow_lan_offscreen(1)], {"1": [after]})
        live.toggle_expected = (ALLOW_LAN, True)
        return runner, live

    def test_a_first_line_showing_on_never_stands_in_for_the_remembered_frame_showing_off(self):
        runner, live = self.attempt(ambiguous_dump((1, 600), (0, 834)))
        with self.assertRaises((LIVE.ToggleMoved, LIVE.RowFailure)):
            live.click_id(ALLOW_LAN)
        self.assertEqual(lows.press_only_calls(runner), [], "the remembered 584,834 shows off; a press would propose on")
        self.assertEqual(element.gui(runner, "press"), [])

    def test_control_the_remembered_line_first_is_not_pressed_either(self):
        runner, live = self.attempt(ambiguous_dump((0, 834), (1, 600)))
        with self.assertRaises((LIVE.ToggleMoved, LIVE.RowFailure)):
            live.click_id(ALLOW_LAN)
        self.assertEqual(element.gui(runner, "press"), [])

    def test_the_remembered_frame_still_showing_on_is_pressed_whatever_the_other_line_shows(self):
        for order in (((0, 600), (1, 834)), ((1, 834), (0, 600))):
            with self.subTest(order=order):
                runner, live = self.attempt(ambiguous_dump(*order))
                self.assertEqual(live.click_id(ALLOW_LAN), "element")
                self.assertEqual(element.gui(runner, "press"), [["press", "WGEX", "1", ALLOW_LAN, "press-only", "AXCheckBox", REMEMBERED_FRAME]])

    def test_the_value_read_belongs_to_the_line_with_the_frame(self):
        dump = ambiguous_dump((1, 600), (0, 834))
        self.assertIs(LIVE.dump_toggle_value(dump, ALLOW_LAN), True, "unchanged: the first line without a frame")
        self.assertIs(LIVE.dump_toggle_value(dump, ALLOW_LAN, (584, 834, 138, 16)), False)
        self.assertIs(LIVE.dump_toggle_value(dump, ALLOW_LAN, (584, 600, 138, 16)), True)
        self.assertIsNone(LIVE.dump_toggle_value(dump, ALLOW_LAN, (1, 2, 3, 4)), "no such line: no value")


class RaisingAfterLandingMixin:
    """Lets the Allow LAN `gui press` land (the inherited runner records it and applies its effect), then raises."""
    error = None

    def run(self, argv, data=None, timeout=100, env=None):
        args = argv[2:] if argv[:1] == ["just"] else []
        result = super().run(argv, data, timeout, env)
        if args[:2] == ["gui", "press"] and ALLOW_LAN in args:
            raise self.error(argv, timeout) if self.error is subprocess.TimeoutExpired else self.error()
        return result


class OnScreenRaisingRunner(RaisingAfterLandingMixin, position.AllowLANToggleRunner):
    def __init__(self, error):
        super().__init__(lag=None, daemon_backed=True)
        self.error = error


class OffScreenRaisingRunner(RaisingAfterLandingMixin, post.WindowDumpRunner):
    def __init__(self, error):
        super().__init__([lows.allow_lan_offscreen(1)], {"1": [lows.allow_lan_offscreen(1)]})
        self.error = error


class PressSentPlacementTests(unittest.TestCase):
    """F-2: the flag precedes the command. The existing tests answer with replies that return, which count either way."""

    def journalled(self, runner, error_type):
        live = LIVE.Session("fixture", {}, runner=runner)
        with self.assertRaises(error_type):
            live.toggle_until(ALLOW_LAN, lambda: True, False)
        self.assertFalse(live.press_sent, "cleared afterwards")
        self.assertIsNone(live.toggle_expected)
        return live

    def test_an_onscreen_press_that_lands_and_then_times_out_is_journalled(self):
        runner = OnScreenRaisingRunner(subprocess.TimeoutExpired)
        live = self.journalled(runner, RuntimeError)
        self.assertEqual(live.toggle_journal[ALLOW_LAN], [dict(press=1, valueBefore=True)])
        self.assertEqual(position.allow_lan_presses(runner), 1)
        self.assertEqual([argv[7] for argv in runner.commands if argv[:4] == ["just", "lab", "gui", "press"] and ALLOW_LAN in argv], ["press-only"],
                         "M1-38: a compared on-screen press is the pinned press-only, never `press` with a point")
        self.assertEqual([item["pressOutcome"] for item in live.ledger if "pressOutcome" in item], ["raised"])

    def test_an_offscreen_press_only_that_lands_and_then_times_out_is_journalled(self):
        runner = OffScreenRaisingRunner(subprocess.TimeoutExpired)
        live = self.journalled(runner, RuntimeError)
        self.assertEqual(live.toggle_journal[ALLOW_LAN], [dict(press=1, valueBefore=True)])
        self.assertEqual(element.gui(runner, "press"), [["press", "WGEX", "1", ALLOW_LAN, "press-only", "AXCheckBox", "frame=584,834,138x16"]],
                         "press_only on the compared frame (M1-36), never a coordinate")
        self.assertEqual([item["pressOutcome"] for item in live.ledger if "pressOutcome" in item], ["raised"])

    def test_a_keyboard_interrupt_after_the_press_landed_is_journalled_too(self):
        for label, runner in (("on-screen", OnScreenRaisingRunner(KeyboardInterrupt)), ("off-screen", OffScreenRaisingRunner(KeyboardInterrupt))):
            with self.subTest(label):
                live = self.journalled(runner, KeyboardInterrupt)
                self.assertEqual(live.toggle_journal[ALLOW_LAN], [dict(press=1, valueBefore=True)], "BaseException, not Exception")


if __name__ == "__main__":
    unittest.main()
