# SPDX-License-Identifier: MIT
"""M1-36 (LAB3-VERIFY G-1 shapes a-c, G-2, G-3, N-1): the press lands on exactly the element the compare read. Recorded replies and
fixtures only; no subprocess, never a VM, never osascript.

While toggle_expected names the identifier, every press of that toggle (press_inside on-screen, press_inside after a scroll,
press_only still off-screen) passes frame= to the helper, and the compare reads only the lines of the press role (AXCheckBox for
Allow LAN) at that frame, whatever their enabled state. More than one such line is ToggleMoved: nothing is pressed.

M1-38 (M1-36 VERIFY H-1, H-2): a compared toggle is pressed press-only (frame-pinned) at every site, so a frame that drifted between
the dump and the helper's walk is a retry or the named gap guiActionFailed:<identifier>, never the helper's coordinate click; and the
enabled half of element_role(controls=True) is pinned (M70a-c).

Safety bar used by every shape below (check_presses): each press that was sent is frame-pinned, names AXCheckBox, and the one
AXCheckBox line at that frame shows toggle_expected. A shape that refuses sends no press at all."""
import re
import unittest

import test_gui_element as element
import test_gui_post_scroll as post
import test_lab2_lows as lows

LIVE = element.LIVE
ALLOW_LAN = lows.ALLOW_LAN
ROLE = "AXCheckBox"


def line(value, y, role=ROLE, enabled=True, size=(138, 16)):
    """The run 8b Allow LAN dump line (584,834 138x16 value=1, AXCheckBox, enabled) moved, resized and re-valued."""
    text = lows.ALLOW_LAN_LINE.replace("AXCheckBox |", role + " |", 1).replace("value=1", f"value={value}")
    text = text.replace("pos=584,834 size=138x16", f"pos=584,{y} size={size[0]}x{size[1]}")
    return text if enabled else text.replace("en=true", "en=false")


def dump_with(*lines):
    """The off-screen Allow LAN dump (lockdown line dropped, window content 0,30 1024x752) with its one Allow LAN line replaced."""
    return lows.allow_lan_offscreen(1).replace(lows.ALLOW_LAN_LINE, "".join(lines))


def frame_of(argv):
    """The (x, y, w, h) of the helper's frame= argument in a recorded `gui press` argv, else None."""
    for item in argv:
        match = re.fullmatch(r"frame=(-?\d+),(-?\d+),(\d+)x(\d+)", item)
        if match:
            return tuple(map(int, match.groups()))
    return None


def shown_at(dump, frame, role=ROLE):
    """The values of the Allow LAN lines of this role at exactly this frame."""
    pattern = r"^" + role + r" \|[^\n]*?\| value=([^|\n]*?)\s*\|[^\n]*?\| id=" + re.escape(ALLOW_LAN) + r" \|[^\n]*?pos=(-?\d+),(-?\d+) size=(\d+)x(\d+)"
    return [value for value, x, y, w, h in re.findall(pattern, dump, re.M) if (int(x), int(y), int(w), int(h)) == frame]


class PinnedPressCase(unittest.TestCase):
    """Runs click_id with toggle_expected (Allow LAN, expected) against one recorded dump and checks the press bar."""

    def attempt(self, before, after, expected):
        runner, live = post.session([before], {"1": [after]})
        live.toggle_expected = (ALLOW_LAN, expected)
        return runner, live

    def check_presses(self, runner, dump, expected):
        for argv in element.gui(runner, "press"):
            frame = frame_of(argv)
            self.assertIsNotNone(frame, f"a toggle press must be frame-pinned: {argv}")
            self.assertIn(ROLE, argv, "the press role is the control's, never a static text's")
            self.assertEqual(shown_at(dump, frame), [str(int(expected))], f"the pinned frame must show {expected} on exactly one {ROLE} line: {argv}")

    def refused(self, before, after, expected=True):
        runner, live = self.attempt(before, after, expected)
        with self.assertRaises(LIVE.ToggleMoved):
            live.click_id(ALLOW_LAN)
        self.assertEqual(element.gui(runner, "press"), [])
        return runner

    def pinned(self, before, after, expected, frame, command):
        runner, live = self.attempt(before, after, expected)
        self.assertEqual(live.click_id(ALLOW_LAN), "element")
        presses = element.gui(runner, "press")
        self.assertEqual(len(presses), 1)
        self.assertEqual(presses[0][4], command)
        self.assertEqual(frame_of(presses[0]), frame)
        self.check_presses(runner, after, expected)
        return presses[0]


class ItemOnePinTests(PinnedPressCase):
    """Item 1: the three press sites pass the compared frame whenever toggle_expected names the identifier."""

    def test_an_onscreen_press_is_frame_pinned(self):
        dump = dump_with(line(1, 700))
        argv = self.pinned(dump, dump, True, (584, 700, 138, 16), "press-only")
        self.assertEqual(argv[5:], [ROLE, "frame=584,700,138x16"])

    def test_a_press_after_a_scroll_that_brought_it_inside_is_frame_pinned(self):
        after = dump_with(line(1, 700))
        argv = self.pinned(lows.allow_lan_offscreen(1), after, True, (584, 700, 138, 16), "press-only")
        self.assertEqual(argv[5:], [ROLE, "frame=584,700,138x16"])

    def test_a_press_only_that_is_still_outside_is_frame_pinned(self):
        after = lows.allow_lan_offscreen(1)
        argv = self.pinned(lows.allow_lan_offscreen(1), after, True, (584, 834, 138, 16), "press-only")
        self.assertEqual(argv[5:], [ROLE, "frame=584,834,138x16"])

    def test_a_target_nobody_read_keeps_the_unpinned_press(self):
        dump = dump_with(line(1, 700))
        for expected in (None, ("wgex.protection.lockdown", True)):
            with self.subTest(expected=expected):
                runner, live = post.session([dump], {"1": [dump]})
                live.toggle_expected = expected
                self.assertEqual(live.click_id(ALLOW_LAN), "element")
                self.assertEqual(element.gui(runner, "press"), [["press", "WGEX", "1", ALLOW_LAN, "press", "653", "708", ROLE]])


class G1ShapeTests(PinnedPressCase):
    """G-1 shapes a-c: a second line sharing the identifier (and the frame) never decides which element is pressed."""

    def test_shape_a_a_static_text_line_then_the_checkbox_at_the_same_frame(self):
        dump = dump_with(line(1, 700, role="AXStaticText"), line(0, 700))
        self.refused(dump, dump, True)
        runner, live = self.attempt(dump, dump, False)
        self.assertEqual(live.click_id(ALLOW_LAN), "element")
        self.assertEqual(frame_of(element.gui(runner, "press")[0]), (584, 700, 138, 16))
        self.assertEqual(element.gui(runner, "press")[0][4], "press-only")
        self.check_presses(runner, dump, False)

    def test_shape_a_after_a_scroll_the_checkbox_behind_the_static_text_is_the_element(self):
        after = dump_with(line(1, 834, role="AXStaticText"), line(0, 834))
        self.refused(lows.allow_lan_offscreen(1), after, True)
        self.pinned(lows.allow_lan_offscreen(0), after, False, (584, 834, 138, 16), "press-only")

    def test_shape_b_a_disabled_checkbox_then_an_enabled_one_at_the_same_frame(self):
        for y in (700, 834):
            with self.subTest(y=y):
                dump = dump_with(line(1, y, enabled=False), line(0, y))
                runner = self.refused(lows.allow_lan_offscreen(1) if y == 834 else dump, dump)
                self.assertEqual(element.gui(runner, "press"), [])

    def test_shape_c_two_enabled_checkboxes_at_the_same_frame_one_then_zero(self):
        runner = self.refused(lows.allow_lan_offscreen(1), dump_with(line(1, 834), line(0, 834)))
        self.assertEqual(element.gui(runner, "press"), [])

    def test_shape_c_the_other_order_is_refused_too(self):
        self.refused(lows.allow_lan_offscreen(1), dump_with(line(0, 834), line(1, 834)))


class G2MirrorTests(PinnedPressCase):
    """G-2: an earlier disabled line at another frame, in-window, never steers the helper's first identifier+role match."""

    def test_disabled_off_at_600_then_enabled_on_at_700_is_pressed_on_the_700_line_only(self):
        dump = dump_with(line(0, 600, enabled=False), line(1, 700))
        argv = self.pinned(dump, dump, True, (584, 700, 138, 16), "press-only")
        self.assertEqual(argv[-1], "frame=584,700,138x16")

    def test_the_mirror_disabled_on_at_600_then_enabled_off_at_700_is_refused(self):
        dump = dump_with(line(1, 600, enabled=False), line(0, 700))
        self.refused(dump, dump)

    def test_the_post_scroll_pair_is_pinned_the_same_way(self):
        after = dump_with(line(0, 600, enabled=False), line(1, 700))
        self.pinned(lows.allow_lan_offscreen(1), after, True, (584, 700, 138, 16), "press-only")
        self.refused(lows.allow_lan_offscreen(1), dump_with(line(1, 600, enabled=False), line(0, 700)))


class G3SizeTests(PinnedPressCase):
    """G-3: the width and height are part of the frame equality (the helper matches the exact size, ax-action.applescript)."""

    def test_a_line_one_point_taller_showing_on_never_stands_in_for_the_remembered_line_showing_off(self):
        self.refused(lows.allow_lan_offscreen(1), dump_with(line(1, 834, size=(138, 17)), line(0, 834)))
        self.refused(lows.allow_lan_offscreen(1), dump_with(line(0, 834), line(1, 834, size=(138, 17))))

    def test_the_remembered_size_showing_on_is_pressed_pinned_to_that_size_whatever_the_other_size_shows(self):
        for order in ((line(1, 834), line(0, 834, size=(138, 17))), (line(0, 834, size=(138, 17)), line(1, 834))):
            with self.subTest(order=order):
                self.pinned(lows.allow_lan_offscreen(1), dump_with(*order), True, (584, 834, 138, 16), "press-only")

    def test_a_single_line_of_another_size_is_the_found_element_and_is_pinned_to_its_own_size(self):
        after = dump_with(line(1, 834, size=(138, 17)))
        argv = self.pinned(lows.allow_lan_offscreen(1), after, True, (584, 834, 138, 17), "press-only")
        self.assertEqual(argv[-1], "frame=584,834,138x17")


class DumpToggleValueTests(unittest.TestCase):
    """The compare's unit: role filter, exact frame, duplicates refused (None)."""

    FRAME = (584, 700, 138, 16)

    def test_only_lines_of_the_press_role_are_read(self):
        dump = dump_with(line(1, 700, role="AXStaticText"), line(0, 700))
        self.assertIs(LIVE.dump_toggle_value(dump, ALLOW_LAN, self.FRAME, ROLE), False)
        self.assertIs(LIVE.dump_toggle_value(dump, ALLOW_LAN, self.FRAME, "AXStaticText"), True)
        self.assertIsNone(LIVE.dump_toggle_value(dump, ALLOW_LAN, self.FRAME, "AXSwitch"), "no line of that role: no value")

    def test_a_disabled_line_of_the_role_is_read_whatever_its_enabled_state(self):
        self.assertIs(LIVE.dump_toggle_value(dump_with(line(1, 700, enabled=False)), ALLOW_LAN, self.FRAME, ROLE), True)

    def test_two_lines_of_the_role_at_the_frame_are_no_value_at_all(self):
        for first, second in ((1, 0), (0, 1), (1, 1), (0, 0)):
            with self.subTest(first=first, second=second):
                dump = dump_with(line(first, 700), line(second, 700, enabled=False))
                self.assertIsNone(LIVE.dump_toggle_value(dump, ALLOW_LAN, self.FRAME, ROLE))

    def test_the_size_is_part_of_the_frame(self):
        dump = dump_with(line(1, 700, size=(138, 17)), line(0, 700))
        self.assertIs(LIVE.dump_toggle_value(dump, ALLOW_LAN, self.FRAME, ROLE), False)
        self.assertIs(LIVE.dump_toggle_value(dump, ALLOW_LAN, (584, 700, 138, 17), ROLE), True)

    def test_without_a_frame_and_role_the_first_line_is_still_read(self):
        dump = dump_with(line(1, 600), line(0, 700))
        self.assertIs(LIVE.dump_toggle_value(dump, ALLOW_LAN), True, "toggle_value's targeted read, unchanged")

    def test_the_role_that_feeds_the_press_is_the_control_not_a_static_text_ahead_of_it(self):
        dump = dump_with(line(1, 700, role="AXStaticText"), line(0, 700))
        self.assertEqual(LIVE.element_role(dump, ALLOW_LAN, self.FRAME), "AXStaticText", "unchanged without controls")
        self.assertEqual(LIVE.element_role(dump, ALLOW_LAN, self.FRAME, controls=True), ROLE)


class DriftRunner(post.WindowDumpRunner):
    """Answers a gui press as the helper does when the pinned frame matches nothing (the element moved between the dump and the
    helper's walk): `press` with a point clicks it and says path=coordinate, `press-only` has no point and says path=miss. After
    `drifts` such replies the helper finds the element (path=element). Recorded replies only; no subprocess."""

    def __init__(self, before, after, drifts, miss=b"path=miss\n"):
        super().__init__(before, after)
        self.drifts, self.miss = drifts, miss

    def run(self, argv, data=None, timeout=100, env=None):
        args = argv[2:] if argv[:1] == ["just"] else []
        if args[:2] == ["gui", "press"]:
            self.commands.append(list(argv))
            self.clock += 0.01
            if self.drifts > 0:
                self.drifts -= 1
                return self.reply(argv, b"path=coordinate\n" if args[5] == "press" else self.miss)
            return self.reply(argv, b"path=element\n")
        return super().run(argv, data, timeout, env)


class FrameDriftTests(unittest.TestCase):
    """M1-38 item 1 (VERIFY H-2): drift between the dump and the helper's walk is a retry or a named gap, never a blind click."""

    def drift(self, before, after, drifts):
        runner = DriftRunner([before], {"1": [after]}, drifts)
        live = LIVE.Session("fixture", {}, runner=runner)
        live.toggle_expected = (ALLOW_LAN, True)
        return runner, live

    def assert_never_clicked(self, runner, live):
        modes = [argv[4] for argv in element.gui(runner, "press")]
        self.assertEqual(set(modes), {"press-only"}, "a compared press carries no point the helper could click")
        self.assertEqual(element.gui(runner, "click"), [])
        self.assertIsNone(live.last_press, "no press is counted as pressed")
        self.assertFalse([entry for entry in live.ledger if entry.get("actionPath") in LIVE.PRESSED_PATHS])

    def test_in_window_drift_on_every_attempt_is_the_named_gap_and_nothing_counts_as_pressed(self):
        dump = dump_with(line(1, 700))
        runner, live = self.drift(dump, dump, 99)
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.click_id(ALLOW_LAN)
        self.assertEqual(raised.exception.reason, "guiActionFailed:" + ALLOW_LAN)
        self.assertIn(f"{LIVE.PRESS_ONLY_ATTEMPTS} failed press-only", str(raised.exception))
        self.assertEqual(len(element.gui(runner, "press")), LIVE.PRESS_ONLY_ATTEMPTS)
        self.assertEqual({frame_of(argv) for argv in element.gui(runner, "press")}, {(584, 700, 138, 16)})
        self.assert_never_clicked(runner, live)

    def test_in_window_drift_once_is_a_retry_on_the_same_pinned_frame(self):
        dump = dump_with(line(1, 700))
        runner, live = self.drift(dump, dump, 1)
        self.assertEqual(live.click_id(ALLOW_LAN), "element")
        presses = element.gui(runner, "press")
        self.assertEqual([argv[4:] for argv in presses], [["press-only", ROLE, "frame=584,700,138x16"]] * 2)
        self.assertEqual(live.last_press["path"], "element")
        self.assertEqual(element.gui(runner, "click"), [])

    def test_post_scroll_in_window_drift_is_the_named_gap_and_nothing_counts_as_pressed(self):
        runner, live = self.drift(lows.allow_lan_offscreen(1), dump_with(line(1, 700)), 99)
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.click_id(ALLOW_LAN)
        self.assertEqual(raised.exception.reason, "guiActionFailed:" + ALLOW_LAN)
        self.assertEqual({frame_of(argv) for argv in element.gui(runner, "press")}, {(584, 700, 138, 16)})
        self.assert_never_clicked(runner, live)

    def test_post_scroll_in_window_drift_once_is_a_retry(self):
        runner, live = self.drift(lows.allow_lan_offscreen(1), dump_with(line(1, 700)), 1)
        self.assertEqual(live.click_id(ALLOW_LAN), "element")
        self.assertEqual(len(element.gui(runner, "press")), 2)
        self.assertEqual(element.gui(runner, "click"), [])

    def test_a_reply_that_may_have_landed_is_the_gap_at_once_and_never_pressed_again(self):
        # A second AXPress after an error, an older helper's path=none or a failed reply could turn Allow LAN back on.
        dump = dump_with(line(1, 700))
        for reply in (b"path=error number=-25200\n", b"path=none\n", b"ax-action=failed exit=255\n", b""):
            with self.subTest(reply=reply):
                runner = DriftRunner([dump], {"1": [dump]}, 99, miss=reply)
                live = LIVE.Session("fixture", {}, runner=runner)
                live.toggle_expected = (ALLOW_LAN, True)
                with self.assertRaises(LIVE.RowFailure) as raised:
                    live.click_id(ALLOW_LAN)
                self.assertEqual(raised.exception.reason, "guiActionFailed:" + ALLOW_LAN)
                self.assertIn("1 failed press-only AXPress attempt (", str(raised.exception))
                self.assertEqual(len(element.gui(runner, "press")), 1)
                self.assert_never_clicked(runner, live)

    def test_a_target_nobody_read_keeps_the_point_and_the_helper_click_fallback(self):
        dump = dump_with(line(1, 700))
        runner = DriftRunner([dump], {"1": [dump]}, 1)
        live = LIVE.Session("fixture", {}, runner=runner)
        self.assertEqual(live.click_id(ALLOW_LAN), "coordinate")
        self.assertEqual(element.gui(runner, "press"), [["press", "WGEX", "1", ALLOW_LAN, "press", "653", "708", ROLE]])


class OffscreenCompareLandingTests(unittest.TestCase):
    """M1-38 fix pass 1 (VERIFY F-1): the landing guard covers every compared press_only, the off-screen one included. A reply that
    may have landed (error, path=none, a failed reply, nothing) is the gap guiTargetOffscreen at once, with exactly one press; only
    path=miss, which acted on nothing, is retried. A press nobody compared (lockdown, F3) keeps the M1-10m retry. N-3: a gap after
    nothing but path=miss replies is not a press for the toggle journal. Recorded replies only; no subprocess."""

    MAY_HAVE_LANDED = (b"path=error number=-1712\n", b"path=error number=-25200\n", b"path=none\n", b"ax-action=failed exit=255\n", b"")

    def outside(self, drifts, reply, expected=(ALLOW_LAN, True)):
        """Run 8b geometry: Allow LAN at 584,834, below the content bottom 782, still there after the scroll (scroll=none)."""
        dump = lows.allow_lan_offscreen(1)
        runner = DriftRunner([dump], {"1": [dump]}, drifts, miss=reply)
        live = LIVE.Session("fixture", {}, runner=runner)
        live.toggle_expected = expected
        return runner, live

    def test_a_compared_press_still_outside_after_a_reply_that_may_have_landed_is_one_press_then_the_gap(self):
        for reply in self.MAY_HAVE_LANDED:
            with self.subTest(reply=reply):
                runner, live = self.outside(99, reply)
                with self.assertRaises(LIVE.RowFailure) as raised:
                    live.click_id(ALLOW_LAN)
                self.assertEqual(raised.exception.reason, "guiTargetOffscreen:" + ALLOW_LAN)
                self.assertIn("1 failed press-only AXPress attempt (", str(raised.exception))
                presses = element.gui(runner, "press")
                self.assertEqual([argv[4:] for argv in presses], [["press-only", ROLE, "frame=584,834,138x16"]], "one pinned press, never a second")
                self.assertEqual(element.gui(runner, "click"), [])
                self.assertIsNone(live.last_press, "nothing is counted as pressed")
                self.assertFalse([entry for entry in live.ledger if entry.get("actionPath") in LIVE.PRESSED_PATHS])

    def test_a_compared_press_still_outside_retries_path_miss_and_then_names_the_gap(self):
        runner, live = self.outside(99, b"path=miss\n")
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.click_id(ALLOW_LAN)
        self.assertEqual(raised.exception.reason, "guiTargetOffscreen:" + ALLOW_LAN)
        self.assertEqual({frame_of(argv) for argv in element.gui(runner, "press")}, {(584, 834, 138, 16)})
        self.assertEqual(len(element.gui(runner, "press")), LIVE.PRESS_ONLY_ATTEMPTS)
        self.assertIsNone(live.last_press)

    def test_a_compared_press_still_outside_that_missed_once_is_retried_and_pressed(self):
        runner, live = self.outside(1, b"path=miss\n")
        self.assertEqual(live.click_id(ALLOW_LAN), "element")
        self.assertEqual(len(element.gui(runner, "press")), 2)
        self.assertEqual(live.last_press["path"], "element")

    def test_the_real_geometry_with_a_clean_reply_is_pressed_once(self):
        runner, live = self.outside(0, b"path=miss\n")
        self.assertEqual(live.click_id(ALLOW_LAN), "element")
        self.assertEqual([argv[4:] for argv in element.gui(runner, "press")], [["press-only", ROLE, "frame=584,834,138x16"]])
        self.assertEqual(live.last_press["path"], "element")
        self.assertEqual([entry["actionPath"] for entry in live.ledger if "actionPath" in entry], ["element-offscreen"])

    def test_a_press_nobody_compared_keeps_the_retry_after_an_error(self):
        # M1-10m: lockdown and the F3 presses are not toggle_expected presses, so path=error is still retried.
        for expected in (None, ("wgex.protection.lockdown", True)):
            with self.subTest(expected=expected):
                runner, live = self.outside(99, b"path=error number=-1712\n", expected)
                with self.assertRaises(LIVE.RowFailure) as raised:
                    live.click_id(ALLOW_LAN)
                self.assertEqual(raised.exception.reason, "guiTargetOffscreen:" + ALLOW_LAN)
                self.assertEqual(len(element.gui(runner, "press")), LIVE.PRESS_ONLY_ATTEMPTS)

    def test_an_ambiguous_f3_press_only_nobody_compared_keeps_the_retry_after_an_error(self):
        # The F3 press carries match_frame too, so the guard is keyed on toggle_compared, not on the frame pin.
        runner, live = post.session([post.RUN8C], {"1": [post.RUN8C + post.AmbiguousPostScrollTests.MOVED]},
                                    press=b"path=error number=-1712\n")
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.click_id(post.LOCKDOWN)
        self.assertEqual(raised.exception.reason, "guiTargetOffscreen:" + post.LOCKDOWN)
        presses = element.gui(runner, "press")
        self.assertEqual(len(presses), LIVE.PRESS_ONLY_ATTEMPTS)
        self.assertEqual({tuple(argv[-1:]) for argv in presses}, {(post.AmbiguousPostScrollTests.FRAME,)}, "every attempt is frame-pinned")

    def journal(self, runner_args, dump):
        runner = DriftRunner([dump], {"1": [dump]}, 99, **runner_args)
        live = LIVE.Session("fixture", {}, runner=runner)
        with self.assertRaises(LIVE.RowFailure):
            live.toggle_until(ALLOW_LAN, lambda: True, False)
        return live

    def test_n3_a_gap_after_nothing_but_misses_is_not_a_journalled_press(self):
        for name, dump in (("outside", lows.allow_lan_offscreen(1)), ("inside", dump_with(line(1, 700)))):
            with self.subTest(dump=name):
                live = self.journal(dict(miss=b"path=miss\n"), dump)
                self.assertEqual(live.toggle_journal[ALLOW_LAN], [], "every attempt acted on nothing")
                self.assertFalse([entry for entry in live.ledger if entry.get("pressOutcome") == "raised"])

    def test_n3_a_gap_after_nothing_but_misses_restores_the_value_on_entry_not_false(self):
        # VERIFY N-A (M1-38 fix pass 1): the restore is to press_sent as it was on entry, so it can never un-count an earlier press.
        dump = lows.allow_lan_offscreen(1)
        runner = DriftRunner([dump], {"1": [dump]}, 99)
        live = LIVE.Session("fixture", {}, runner=runner)
        live.toggle_expected = (ALLOW_LAN, True)
        live.press_sent = True
        record = dict(controlIdentifier=ALLOW_LAN, controlRole=ROLE, elementFrame=[584, 834, 138, 16],
                      windowFrame=list(LIVE.window_frame(dump)), postScrollDumps=[dict(window="1", lines=1, matches=[ALLOW_LAN])])
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.press_only(record, "1", [], "still outside its window", match_frame=(584, 834, 138, 16))
        self.assertEqual(raised.exception.reason, "guiTargetOffscreen:" + ALLOW_LAN)
        self.assertEqual(len(element.gui(runner, "press")), LIVE.PRESS_ONLY_ATTEMPTS, "path=miss on every attempt")
        self.assertTrue(live.press_sent, "an earlier press stays counted")

    def test_n_b_the_in_window_gap_says_nothing_was_clicked_only_after_nothing_but_misses(self):
        dump = dump_with(line(1, 700))
        for reply, said in ((b"path=miss\n", "nothing was clicked"), *((reply, "the press may have landed") for reply in self.MAY_HAVE_LANDED)):
            with self.subTest(reply=reply):
                runner = DriftRunner([dump], {"1": [dump]}, 99, miss=reply)
                live = LIVE.Session("fixture", {}, runner=runner)
                live.toggle_expected = (ALLOW_LAN, True)
                with self.assertRaises(LIVE.RowFailure) as raised:
                    live.click_id(ALLOW_LAN)
                self.assertEqual(raised.exception.reason, "guiActionFailed:" + ALLOW_LAN)
                self.assertTrue(str(raised.exception).endswith("; " + said), str(raised.exception))
                # M1-57 (M1-51 ADV-VERIFY A-1): the inside ledger entry says the same as the RowFailure beside it.
                entry = next(item for item in live.ledger if item.get("pressOnlyOutcomes"))
                self.assertEqual(entry["error"], "pinned press-only failed; " + ("not clicked" if reply == b"path=miss\n" else "the press may have landed"))

    def test_n3_a_gap_after_a_reply_that_may_have_landed_is_still_a_journalled_press(self):
        for name, dump in (("outside", lows.allow_lan_offscreen(1)), ("inside", dump_with(line(1, 700)))):
            for reply in self.MAY_HAVE_LANDED:
                with self.subTest(dump=name, reply=reply):
                    live = self.journal(dict(miss=reply), dump)
                    self.assertEqual(live.toggle_journal[ALLOW_LAN], [dict(press=1, valueBefore=True)])


class EnabledControlRoleTests(PinnedPressCase):
    """M1-38 item 2 (VERIFY H-1; mutants M70a-c): element_role(controls=True) skips a disabled control-role line at the frame, so a
    disabled AXSwitch (or AXButton) carrying the identifier never becomes the press role the compare reads."""

    def test_m70a_a_disabled_switch_showing_on_ahead_of_the_enabled_checkbox_showing_off_is_toggle_moved(self):
        for role in ("AXSwitch", "AXButton"):
            with self.subTest(role=role):
                dump = dump_with(line(1, 700, role=role, enabled=False), line(0, 700))
                self.refused(dump, dump)

    def test_m70b_the_same_pair_after_a_scroll_is_toggle_moved(self):
        after = dump_with(line(1, 834, role="AXSwitch", enabled=False), line(0, 834))
        self.refused(lows.allow_lan_offscreen(1), after)

    def test_m70c_the_press_role_stays_the_checkbox_when_it_shows_the_expected_value(self):
        dump = dump_with(line(0, 700, role="AXSwitch", enabled=False), line(1, 700))
        argv = self.pinned(dump, dump, True, (584, 700, 138, 16), "press-only")
        self.assertEqual(argv[5:], [ROLE, "frame=584,700,138x16"])

    def test_m70c_after_a_scroll_too(self):
        after = dump_with(line(0, 700, role="AXSwitch", enabled=False), line(1, 700))
        argv = self.pinned(lows.allow_lan_offscreen(1), after, True, (584, 700, 138, 16), "press-only")
        self.assertEqual(argv[5:], [ROLE, "frame=584,700,138x16"])

    def test_the_role_helper_skips_a_disabled_control_ahead_of_the_enabled_one(self):
        frame = (584, 700, 138, 16)
        dump = dump_with(line(1, 700, role="AXSwitch", enabled=False), line(0, 700))
        self.assertEqual(LIVE.element_role(dump, ALLOW_LAN, frame), "AXSwitch", "unchanged without controls")
        self.assertEqual(LIVE.element_role(dump, ALLOW_LAN, frame, controls=True), ROLE)
        self.assertEqual(LIVE.element_role(dump_with(line(1, 700, role="AXSwitch", enabled=False)), ALLOW_LAN, frame, controls=True),
                         "AXSwitch", "no enabled control line: the first line's role, as before")


if __name__ == "__main__":
    unittest.main()
