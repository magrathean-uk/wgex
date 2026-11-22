# SPDX-License-Identifier: MIT
"""M1-10k: the post-scroll lookup always reaches press-only on the element found before the scroll. Guest run 8c (30 Oct
2026, M5.3-10 step ledger entries 67-81): the driver found wgex.protection.lockdown (AXCheckBox 286,834 82x16) outside
the main window (0,30 1024x752) in one dump, `gui scroll` answered scroll=none, and the five re-dumps of window 1 that
followed carried no single enabled AXCheckBox line with that identifier, so the search loop ran out its budget and
raised the generic ValueError before press-only. The pre-scroll fixture is the operator's dump of the same window four
minutes later (attempt1-scratch/10-axdump.log, AX lines verbatim; its last line is cut short in the operator's log).
Post-scroll dumps are that dump, a Settings window, gui.sh's ax-dump=failed line (no such window: osascript fails) and
the tree without the toggle. Fix pass 1 (verify F1-F3): press-only is retried within GUI_SEARCH_SHORT, an unreadable
or deadline dump is summarised as such, and an ambiguous dump presses the remembered frame. Never a VM."""
import subprocess
import unittest

import test_gui_element as element

LIVE, AX, GUEST, ROOT = element.LIVE, element.AX, element.GUEST, element.ROOT
RUN8C = (AX / "run8c-main-lockdown-offscreen.txt").read_text()
SETTINGS = element.SETTINGS
LOCKDOWN = element.LOCKDOWN
TOGGLE_LINE = next(line for line in RUN8C.splitlines(keepends=True) if "id=" + LOCKDOWN + " |" in line)
VANISHED = RUN8C.replace(TOGGLE_LINE, "")
DISABLED = RUN8C.replace(TOGGLE_LINE, TOGGLE_LINE.replace("en=true", "en=false"))
# gui.sh dump for a window that does not exist since fix pass 1: osascript fails, the fixed marker line is printed.
NO_WINDOW = "ax-dump=failed exit=1\n"
EMPTY = ""
SHORT = LIVE.HARNESS.seconds("GUI_SEARCH_SHORT")


class WindowDumpRunner(element.DumpRunner):
    """Serves AX dumps per window index: `before` for window 1 until the scroll, then `after[index]` (the last dump of
    each list repeats; a missing index is gui.sh's ax-dump=failed line, as for a window that does not exist). A post-scroll
    dump of a window in `deadlines` hits the command deadline. `presses`: press replies in order (the last repeats),
    each costing `press_cost` seconds."""

    def __init__(self, before, after, press=b"path=element\n", scroll=b"scroll=none\n", deadlines=(), presses=None, press_cost=0.01):
        super().__init__([NO_WINDOW], press=press, scroll=scroll)
        self.before, self.after, self.scrolled = list(before), {key: list(value) for key, value in after.items()}, False
        self.deadlines, self.presses, self.press_cost = set(deadlines), list(presses or []), press_cost

    def run(self, argv, data=None, timeout=100, env=None):
        args = argv[2:] if argv[:1] == ["just"] else []
        if args[:2] == ["gui", "scroll"]:
            self.scrolled = True
        if args[:2] == ["gui", "dump"]:
            self.commands.append(list(argv))
            self.clock += 0.01
            if self.scrolled and args[3] in self.deadlines:
                raise subprocess.TimeoutExpired(argv, timeout)
            queue = self.after.get(args[3], [NO_WINDOW]) if self.scrolled else self.before
            return self.reply(argv, (queue.pop(0) if len(queue) > 1 else queue[0]).encode())
        if args[:2] == ["gui", "press"] and self.presses:
            self.commands.append(list(argv))
            self.clock += self.press_cost
            output = self.presses.pop(0) if len(self.presses) > 1 else self.presses[0]
            return self.reply(argv, output, code=0 if output.startswith(b"path=") else 1)
        return super().run(argv, data, timeout, env)


def session(before, after, **kw):
    runner = WindowDumpRunner(before, after, **kw)
    return runner, LIVE.Session("fixture", {}, runner=runner)


def gui(runner, verb):
    return element.gui(runner, verb)


def press_only(window):
    return ["press", "WGEX", window, LOCKDOWN, "press-only", "AXCheckBox"]


class Run8cSequenceTests(unittest.TestCase):
    def test_the_run8c_dump_places_the_toggle_below_the_window(self):
        frame, child = LIVE.element_target(RUN8C, LOCKDOWN)
        self.assertEqual((frame, child), ((286, 834, 82, 16), False))
        self.assertEqual(LIVE.window_frame(RUN8C), (0, 30, 1024, 752), "the AXWindow line carries the frame since M1-10j")
        self.assertFalse(LIVE.frame_inside(frame, LIVE.window_frame(RUN8C)))
        self.assertEqual(LIVE.element_role(RUN8C, LOCKDOWN, frame), "AXCheckBox")
        self.assertEqual(LIVE.title_form(LIVE.window_title(RUN8C), "wgex-lab-full4"), "statusSuffix")

    def test_the_run8c_sequence_reaches_press_only_after_the_search_budget_is_spent(self):
        # Entries 67-73: six dumps without the toggle, then the one that found it; 74-75 scroll=none; 76-80 re-dumps without it.
        runner, live = session([VANISHED] * 6 + [RUN8C], {"1": [VANISHED], "2": [NO_WINDOW]})
        self.assertEqual(live.click_id(LOCKDOWN, timeout=1.3), "element")
        verbs = [argv[3] for argv in runner.commands if argv[:3] == ["just", "lab", "gui"]]
        self.assertEqual(verbs, ["dump"] * 7 + ["scroll", "dump", "dump", "press"], "one bounded post-scroll pass, then press-only")
        self.assertGreater(runner.monotonic(), 1000.0 + 1.3, "the search budget was spent before the post-scroll pass")
        self.assertEqual([argv[2] for argv in gui(runner, "dump")[7:]], ["1", "2"], "window 1 again, then every other window")
        self.assertEqual(gui(runner, "press"), [press_only("1")])
        self.assertEqual(gui(runner, "click"), [])
        entry = live.ledger[-1]
        self.assertEqual((entry["actionPath"], entry["pressOnly"], entry["pressOnlyWindow"], entry["postScrollWindow"], entry["postScroll"]),
                         ("element-offscreen", "element", "1", None, "not found in any post-scroll dump"))
        self.assertEqual((entry["elementFrame"], entry["windowFrame"], entry["controlRole"]), ([286, 834, 82, 16], [0, 30, 1024, 752], "AXCheckBox"))
        self.assertEqual([(item["window"], item["matches"]) for item in entry["postScrollDumps"]], [("1", []), ("2", [])])
        self.assertEqual(entry["postScrollDumps"][0]["windowTitle"], "wgex-lab-full4 – Connected, last handshake 1 min ago")
        self.assertNotIn("error", entry)

    def test_a_disabled_toggle_after_the_scroll_is_summarised_and_pressed_press_only(self):
        runner, live = session([RUN8C], {"1": [DISABLED]})
        self.assertEqual(live.click_id(LOCKDOWN), "element")
        self.assertEqual(gui(runner, "press"), [press_only("1")])
        self.assertEqual(live.ledger[-1]["postScrollDumps"][0]["matches"], [dict(role="AXCheckBox", enabled="false", frame=[286, 834, 82, 16])])


class PostScrollWindowTests(unittest.TestCase):
    def test_settings_as_window_1_after_the_scroll_presses_the_remembered_element(self):
        runner, live = session([RUN8C], {"1": [SETTINGS], "2": [NO_WINDOW]})
        self.assertEqual(live.click_id(LOCKDOWN), "element")
        self.assertEqual(gui(runner, "press"), [press_only("1")], "no window still names the profile: the dumped index")
        self.assertEqual(gui(runner, "click"), [])
        self.assertEqual(live.ledger[-1]["postScrollDumps"][0]["windowTitle"], "Service")

    def test_no_window_after_the_scroll_presses_the_remembered_element(self):
        runner, live = session([RUN8C], {})
        self.assertEqual(live.click_id(LOCKDOWN), "element")
        self.assertEqual(gui(runner, "press"), [press_only("1")])
        self.assertEqual([item["dump"] for item in live.ledger[-1]["postScrollDumps"]], ["unreadable", "unreadable"])

    def test_the_main_window_moved_to_index_2_is_reselected_by_its_title(self):
        runner, live = session([RUN8C], {"1": [SETTINGS], "2": [RUN8C]})
        self.assertEqual(live.click_id(LOCKDOWN), "element")
        self.assertEqual(gui(runner, "press"), [press_only("2")], "found in window 2, still outside: press-only there")
        entry = live.ledger[-1]
        self.assertEqual((entry["postScrollWindow"], entry["postScroll"]), ("2", "still outside its window"))

    def test_the_title_reselects_the_window_even_when_its_tree_lacks_the_toggle(self):
        later = VANISHED.replace("last handshake 1 min ago |", "last handshake 2 min ago |", 1)
        self.assertNotEqual(LIVE.window_title(later), LIVE.window_title(RUN8C), "the status suffix moved on")
        runner, live = session([RUN8C], {"1": [SETTINGS], "2": [later]})
        self.assertEqual(live.click_id(LOCKDOWN), "element")
        self.assertEqual(gui(runner, "press"), [press_only("2")], "the en dash selector form names the profile window")

    def test_a_control_scrolled_inside_window_2_takes_the_ordinary_element_press(self):
        visible = RUN8C.replace("pos=286,834 size=82x16", "pos=286,534 size=82x16")
        runner, live = session([RUN8C], {"1": [SETTINGS], "2": [visible]})
        self.assertEqual(live.click_id(LOCKDOWN), "element")
        self.assertEqual(gui(runner, "press"), [["press", "WGEX", "2", LOCKDOWN, "press", "327", "542", "AXCheckBox"]])

    def test_a_post_scroll_container_repeating_the_identifier_is_not_the_element(self):
        container = TOGGLE_LINE.replace("AXCheckBox | name=missing value | value=0 | desc=checkbox", "AXGroup | name=missing value | value=missing value | desc=group")
        runner, live = session([RUN8C], {"1": [VANISHED + container]})
        self.assertEqual(live.click_id(LOCKDOWN), "element")
        self.assertEqual(gui(runner, "press"), [press_only("1")], "identifier plus the remembered role, never the container")


class StillOffscreenTests(unittest.TestCase):
    def test_a_toggle_still_off_screen_after_the_scroll_is_pressed_press_only(self):
        runner, live = session([RUN8C], {"1": [RUN8C]})
        self.assertEqual(live.click_id(LOCKDOWN), "element")
        verbs = [argv[3] for argv in runner.commands if argv[:3] == ["just", "lab", "gui"]]
        self.assertEqual(verbs, ["dump", "scroll", "dump", "press"], "found in window 1: no other window is dumped")
        self.assertEqual(gui(runner, "press"), [press_only("1")])
        self.assertEqual(live.ledger[-1]["postScroll"], "still outside its window")


class VanishedTests(unittest.TestCase):
    def test_a_vanished_toggle_is_the_named_gap_never_value_error(self):
        runner, live = session([RUN8C], {"1": [VANISHED], "2": [NO_WINDOW]}, press=b"path=none\n")
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.click_id(LOCKDOWN)
        self.assertEqual(raised.exception.reason, "guiTargetOffscreen:" + LOCKDOWN)
        message = str(raised.exception)
        for needle in ("286,834 82x16", "0,30 1024x752", "after scrolling", "not found in any post-scroll dump", "window 1: 51 lines, 0 identifier lines",
                       "window 2: unreadable", "3 failed press-only AXPress attempts"):
            self.assertIn(needle, message)
        self.assertEqual(gui(runner, "press"), [press_only("1")] * 3)
        self.assertEqual(gui(runner, "click"), [])
        entry = live.ledger[-1]
        self.assertEqual((entry["pressOnly"], entry["error"]), ("none", "target outside the window"))

    def test_a_vanished_toggle_in_click_first_moves_on_as_a_named_gap(self):
        runner, live = session([RUN8C], {"1": [VANISHED]}, press=b"")
        with self.assertRaises(LIVE.RowFailure):
            live.click_first([(None, LOCKDOWN)])

    def test_an_unscrollable_missing_toggle_never_reaches_value_error_in_the_row(self):
        for scroll in (b"scroll=none\n", b"scroll=missing\n", b""):
            with self.subTest(scroll=scroll):
                runner, live = session([RUN8C], {"1": [VANISHED]}, press=b"path=none\n", scroll=scroll)
                with self.assertRaises(LIVE.RowFailure):
                    live.click_id(LOCKDOWN, timeout=0.0001)
                self.assertEqual([entry["scroll"] for entry in live.ledger if "scroll" in entry], [{b"scroll=none\n": "none", b"scroll=missing\n": "missing", b"": None}[scroll]])

    def test_a_pre_scroll_miss_still_records_the_last_dump(self):
        runner, live = session([VANISHED], {})
        with self.assertRaises(ValueError) as caught:
            live.click_id(LOCKDOWN, timeout=0.5)
        # M07-T15: the error names the identifier it searched for and the candidates the window offered.
        self.assertIn(f"searched id={LOCKDOWN!r}", str(caught.exception))
        self.assertIn("exact matches 0", str(caught.exception))
        self.assertEqual(gui(runner, "scroll"), [], "never found: nothing was scrolled")
        entry = live.ledger[-1]
        self.assertEqual(entry["candidates"]["exact"], 0)
        self.assertEqual((entry["error"], entry["lastDump"]["lines"], entry["lastDump"]["matches"]), ("missing or ambiguous accessible control", 51, []))


class PressOnlyRetryTests(unittest.TestCase):
    """Fix pass 1, F1: press-only is retried while the helper answers path=none, nothing or ax-action=failed."""

    def test_a_press_only_miss_is_retried_and_the_second_attempt_presses(self):
        runner, live = session([RUN8C], {"1": [VANISHED]}, presses=[b"path=none\n", b"path=element\n"])
        self.assertEqual(live.click_id(LOCKDOWN), "element")
        self.assertEqual(gui(runner, "press"), [press_only("1")] * 2, "the same press-only call again, after a settle")
        attempts = [(entry["pressOnlyAttempt"], entry["pressOnly"]) for entry in live.ledger if "pressOnlyAttempt" in entry]
        self.assertEqual(attempts, [(1, "none"), (2, "element")])
        entry = live.ledger[-1]
        self.assertEqual((entry["actionPath"], entry["pressOnlyAttempts"]), ("element-offscreen", 2))

    def test_three_failed_attempts_of_every_kind_are_the_named_gap(self):
        runner, live = session([RUN8C], {"1": [VANISHED], "2": [NO_WINDOW]},
                               presses=[b"path=none\n", b"", b"ax-action=failed exit=1\n", b"path=element\n"])
        start = runner.monotonic()
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.click_id(LOCKDOWN)
        self.assertEqual(raised.exception.reason, "guiTargetOffscreen:" + LOCKDOWN)
        self.assertIn("3 failed press-only AXPress attempts", str(raised.exception))
        self.assertEqual(gui(runner, "press"), [press_only("1")] * 3, "never a fourth attempt")
        self.assertEqual([entry["pressOnly"] for entry in live.ledger if "pressOnlyAttempt" in entry], ["none", None, "failed"])
        self.assertEqual((live.ledger[-1]["pressOnly"], live.ledger[-1]["pressOnlyAttempts"]), ("failed", 3))
        self.assertGreaterEqual(runner.monotonic() - start, 2 * LIVE.PRESS_ONLY_SETTLE_SECONDS, "a settle between attempts")
        self.assertEqual(gui(runner, "click"), [])

    def test_attempts_stay_within_gui_search_short(self):
        runner, live = session([RUN8C], {"1": [VANISHED]}, presses=[b"path=none\n"], press_cost=SHORT * 0.6)
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.click_id(LOCKDOWN)
        self.assertEqual(len(gui(runner, "press")), 2, "a third attempt would start after the GUI_SEARCH_SHORT deadline")
        self.assertIn("2 failed press-only AXPress attempts", str(raised.exception))

    def test_a_successful_first_attempt_is_not_repeated(self):
        runner, live = session([RUN8C], {"1": [RUN8C]})
        live.click_id(LOCKDOWN)
        self.assertEqual(gui(runner, "press"), [press_only("1")])
        self.assertEqual(live.ledger[-1]["pressOnlyAttempts"], 1)


class UnreadableDumpTests(unittest.TestCase):
    """Fix pass 1, F1 and F2: a dump gui.sh marks failed, an empty dump and a dump deadline are named, never "0 lines"."""

    def test_the_failure_marker_and_an_empty_dump_are_unreadable(self):
        self.assertEqual(LIVE.dump_summary(NO_WINDOW, LOCKDOWN)["dump"], "unreadable")
        self.assertEqual(LIVE.dump_summary(EMPTY, LOCKDOWN)["dump"], "unreadable")
        self.assertEqual(LIVE.dump_summary(RUN8C + "ax-dump=failed exit=255\n", LOCKDOWN)["dump"], "unreadable", "a trailing marker wins")
        self.assertEqual(LIVE.dump_summary(VANISHED, LOCKDOWN)["dump"], "ok")
        self.assertEqual(LIVE.press_reply(b"ax-action=failed exit=1\n"), "failed")
        self.assertIsNone(LIVE.press_reply(b""))
        self.assertEqual(LIVE.press_reply(b"path=none\n"), "none")

    def test_an_unreadable_post_scroll_dump_is_named_in_the_gap(self):
        runner, live = session([RUN8C], {"1": [EMPTY], "2": [NO_WINDOW]}, press=b"path=none\n")
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.click_id(LOCKDOWN)
        self.assertIn("window 1: unreadable; window 2: unreadable", str(raised.exception))

    def test_a_pre_scroll_miss_records_an_unreadable_last_dump(self):
        runner, live = session([NO_WINDOW], {})
        with self.assertRaises(ValueError):
            live.click_id(LOCKDOWN, timeout=0.05)
        self.assertEqual(live.ledger[-1]["lastDump"]["dump"], "unreadable")

    def test_a_post_scroll_dump_deadline_moves_on_to_the_next_window(self):
        runner, live = session([RUN8C], {"2": [RUN8C]}, deadlines={"1"})
        self.assertEqual(live.click_id(LOCKDOWN), "element")
        self.assertEqual(gui(runner, "press"), [press_only("2")], "window 2 still carries the toggle off-screen")
        self.assertEqual([(item["window"], item["dump"]) for item in live.ledger[-1]["postScrollDumps"]], [("1", "deadline"), ("2", "ok")])
        self.assertEqual([entry.get("error") for entry in live.ledger if entry.get("argv", [])[:4] == ["just", "lab", "gui", "dump"]][-2:],
                         ["deadline", None], "the command ledger keeps the deadline too")

    def test_dump_deadlines_in_every_window_still_reach_press_only(self):
        runner, live = session([RUN8C], {}, deadlines={"1", "2"}, press=b"path=none\n")
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.click_id(LOCKDOWN)
        self.assertEqual(raised.exception.reason, "guiTargetOffscreen:" + LOCKDOWN)
        self.assertIn("window 1: deadline; window 2: deadline", str(raised.exception))
        self.assertEqual(gui(runner, "press"), [press_only("1")] * 3)


class AmbiguousPostScrollTests(unittest.TestCase):
    """Fix pass 1, F3: two enabled lines with the identifier and role are not "not found"."""
    MOVED = TOGGLE_LINE.replace("pos=286,834 size=82x16", "pos=286,400 size=82x16")
    OTHER = TOGGLE_LINE.replace("pos=286,834 size=82x16", "pos=286,600 size=82x16")
    FRAME = "frame=286,834,82x16"

    def test_ambiguity_is_seen(self):
        with self.assertRaises(ValueError):
            LIVE.element_target(RUN8C + self.MOVED, LOCKDOWN)
        self.assertEqual(LIVE.identifier_frames(RUN8C + self.MOVED, LOCKDOWN, "AXCheckBox"), [(286, 834, 82, 16), (286, 400, 82, 16)])
        self.assertEqual(LIVE.frame_argument((286, -40, 82, 16)), "frame=286,-40,82x16")

    def test_the_line_with_the_remembered_frame_is_the_element_and_press_only_matches_it(self):
        runner, live = session([RUN8C], {"1": [RUN8C + self.MOVED]})
        self.assertEqual(live.click_id(LOCKDOWN), "element")
        self.assertEqual(gui(runner, "press"), [press_only("1") + [self.FRAME]], "never the first identifier match by tree order")
        entry = live.ledger[-1]
        self.assertEqual((entry["postScroll"], entry["postScrollAmbiguous"], entry["postScrollWindow"], entry["elementFrame"]),
                         ("still outside its window", 2, "1", [286, 834, 82, 16]))

    def test_without_the_remembered_frame_the_helper_matches_it(self):
        runner, live = session([RUN8C], {"1": [VANISHED + self.MOVED + self.OTHER]})
        self.assertEqual(live.click_id(LOCKDOWN), "element")
        self.assertEqual(gui(runner, "press"), [press_only("1") + [self.FRAME]])
        self.assertEqual(gui(runner, "dump")[1:], [["dump", "WGEX", "1"]], "no further window is searched")
        self.assertIn("ambiguous", live.ledger[-1]["postScroll"])

    def test_the_remembered_frame_inside_a_taller_window_takes_the_element_press_with_the_frame(self):
        first, rest = RUN8C.split("\n", 1)
        taller = first.replace("size=1024x752", "size=1024x900") + "\n" + rest
        runner, live = session([RUN8C], {"1": [taller + self.MOVED]})
        self.assertEqual(live.click_id(LOCKDOWN), "element")
        self.assertEqual(gui(runner, "press"), [["press", "WGEX", "1", LOCKDOWN, "press", "327", "842", "AXCheckBox", self.FRAME]])

    def test_one_line_of_the_remembered_role_among_other_roles_is_the_element(self):
        button = TOGGLE_LINE.replace("AXCheckBox | name=missing value | value=0 | desc=checkbox", "AXButton | name=missing value | value= | desc=button")
        button = button.replace("pos=286,834 size=82x16", "pos=100,100 size=20x20")
        visible = VANISHED + button + TOGGLE_LINE.replace("pos=286,834 size=82x16", "pos=286,534 size=82x16")
        with self.assertRaises(ValueError):
            LIVE.element_target(visible, LOCKDOWN)
        runner, live = session([RUN8C], {"1": [visible]})
        live.click_id(LOCKDOWN)
        self.assertEqual(gui(runner, "press"), [["press", "WGEX", "1", LOCKDOWN, "press", "327", "542", "AXCheckBox"]])


class ScrollHelperShapeTests(unittest.TestCase):
    def test_the_scroll_branch_never_changes_window_order_or_focus(self):
        helper = (GUEST / "ax-action.applescript").read_text()
        branch = helper[helper.index('if modeName is "scroll" then\n      if not haveFound'):helper.index('return "scroll=bar"')]
        for forbidden in ("activate", "frontmost", "AXRaise", "AXMain", "AXFocused", "click", "keystroke", "key code", "AXPress", "open "):
            self.assertNotIn(forbidden, branch)
        self.assertIn('if not haveFound then return "scroll=missing"', branch)
        self.assertIn('return "scroll=none"', branch)
        gui_sh = (ROOT / "Tools/lab/tart/gui.sh").read_text()
        scroll = gui_sh[gui_sh.index("  scroll)\n"):gui_sh.index("  keys)\n")]
        self.assertIn("^scroll=(action|bar|missing|none)$", scroll)
        self.assertNotIn("activate", scroll.replace("No activate", ""))
        self.assertEqual(LIVE.action_path(b"scroll=missing\n", "scroll", LIVE.SCROLL_PATHS), "missing")


if __name__ == "__main__":
    unittest.main()
