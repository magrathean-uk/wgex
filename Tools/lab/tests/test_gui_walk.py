# SPDX-License-Identifier: MIT
"""M1-10l: the AX helpers walk the window themselves, bounded and by index, and the driver tells a complete read from a
partial one. Guest run 8d (30 Oct 2026, M5.3-10 attempts 1 and 2): most dumps of the main window came back in 5-7 s with
the tree cut after the first sidebar outline row (AXRow 8,82 240x19), and `gui scroll` (scroll=missing) and press-only
(path=none) failed in the same way; about one read in seven took 43-58 s and was complete. Fixtures are the operator's
two dumps of that window, AX lines verbatim with the command header, the host's arp warning and the footer dropped:
run8d-main-truncated.txt (11-axdump.log, 20:36:51, 5 AX lines) and run8d-main-complete.txt (10-axdump.log, 20:21:33,
68 AX lines: the AXWindow line and 67 elements, 43 wgex.* identifiers, the lockdown toggle at 286,834 82x16 below the window bottom 782). Both predate the
walk line; the tests add the line the new helper would print. Never a VM, never osascript."""
import re
import subprocess
import unittest

import test_gui_element as element
import test_gui_post_scroll as post

LIVE, AX, GUEST, ROOT = element.LIVE, element.AX, element.GUEST, element.ROOT
LOCKDOWN = element.LOCKDOWN
TRUNCATED = (AX / "run8d-main-truncated.txt").read_text()
COMPLETE = (AX / "run8d-main-complete.txt").read_text()
TRUNCATED_WALK = TRUNCATED + "ax-walk: elements=5 truncated=1 errors=0\n"
ERRORS_WALK = TRUNCATED + "ax-walk: elements=212 truncated=0 errors=3\n"
COMPLETE_WALK = COMPLETE + "ax-walk: elements=412 truncated=0 errors=0\n"
# Verify F1 (M1-10l fix pass 1): a complete walk with one unread element (a live subtree such as the event list mutating
# mid-walk) still carries the toggle at 286,834.
COMPLETE_ERRORS_WALK = COMPLETE + "ax-walk: elements=412 truncated=0 errors=1\n"
NO_WINDOW = post.NO_WINDOW
SEARCH = LIVE.HARNESS.seconds("GUI_SEARCH")


def helper(name):
    return (GUEST / name).read_text()


def code(source):
    """AppleScript without its comment lines."""
    return "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("--"))


def press_only(window):
    return ["press", "WGEX", window, LOCKDOWN, "press-only", "AXCheckBox"]


class SlowWindowRunner(post.WindowDumpRunner):
    """WindowDumpRunner whose post-scroll dumps each take `walk` seconds (a slow AX walk on the guest)."""

    def __init__(self, before, after, walk, **kw):
        super().__init__(before, after, **kw)
        self.walk = walk

    def run(self, argv, data=None, timeout=100, env=None):
        if self.scrolled and argv[:4] == ["just", "lab", "gui", "dump"]:
            self.clock += self.walk
        return super().run(argv, data, timeout, env)


class DeadlineRunner(element.DumpRunner):
    """DumpRunner whose dumps after the first `reads` hit the command deadline."""

    def __init__(self, dumps, reads):
        super().__init__(dumps)
        self.reads = reads

    def run(self, argv, data=None, timeout=100, env=None):
        if argv[:4] == ["just", "lab", "gui", "dump"] and len(element.gui(self, "dump")) >= self.reads:
            self.commands.append(list(argv))
            raise subprocess.TimeoutExpired(argv, timeout)
        return super().run(argv, data, timeout, env)


class FixtureTests(unittest.TestCase):
    def test_the_fixtures_are_the_operator_dumps(self):
        self.assertEqual(len(TRUNCATED.splitlines()), 5)
        self.assertEqual(TRUNCATED.splitlines()[-1].split(" |")[0], "AXRow")
        self.assertIn("pos=8,82 size=240x19", TRUNCATED.splitlines()[-1])
        self.assertEqual(len(COMPLETE.splitlines()), 68)
        self.assertEqual(len(re.findall(r"\| id=wgex\.", COMPLETE)), 43)
        self.assertEqual(COMPLETE.splitlines()[1:5], TRUNCATED.splitlines()[1:5], "the complete walk continues from the row the short one stopped at")


class CompleteDumpTests(unittest.TestCase):
    def test_the_complete_dump_parses_to_the_same_frames_with_the_walk_line(self):
        for dump in (COMPLETE, COMPLETE_WALK):
            with self.subTest(walk=dump is COMPLETE_WALK):
                self.assertEqual(LIVE.element_target(dump, LOCKDOWN), ((286, 834, 82, 16), False))
                self.assertEqual(LIVE.window_frame(dump), (0, 30, 1024, 752))
                self.assertEqual(LIVE.element_role(dump, LOCKDOWN, (286, 834, 82, 16)), "AXCheckBox")
                self.assertEqual(LIVE.identifier_frames(dump, LOCKDOWN, "AXCheckBox"), [(286, 834, 82, 16)])
                self.assertEqual(LIVE.control_frame(dump, None, "wgex.protection.allowLocalNetwork"), (584, 834, 138, 16))
                self.assertEqual(LIVE.sidebar_rows(dump), ["00000000-0000-4000-8000-000000000105"])
                self.assertEqual(LIVE.title_form(LIVE.window_title(dump), "wgex-lab-full4"), "statusSuffix")
        every_frame = [[LIVE.DUMP_FRAME.search(line).groups() for line in dump.splitlines() if LIVE.DUMP_FRAME.search(line)]
                       for dump in (COMPLETE, COMPLETE_WALK)]
        self.assertEqual(every_frame[0], every_frame[1])
        self.assertEqual(len(every_frame[0]), 68, "the AXWindow line and 67 element lines; the walk line has no frame")

    def test_a_complete_walk_is_an_ok_summary_with_its_counts(self):
        summary = LIVE.dump_summary(COMPLETE_WALK, LOCKDOWN)
        self.assertEqual((summary["dump"], summary["lines"], summary["walk"]), ("ok", 68, dict(elements=412, truncated=False, errors=0)))
        self.assertEqual(summary["matches"], [dict(role="AXCheckBox", enabled="true", frame=[286, 834, 82, 16])])
        self.assertEqual(LIVE.dump_summary(COMPLETE, LOCKDOWN), {key: value for key, value in summary.items() if key != "walk"},
                         "a dump without the walk line (an older helper) keeps the M1-10k summary")
        self.assertFalse(LIVE.dump_incomplete(COMPLETE_WALK))
        self.assertFalse(LIVE.dump_incomplete(COMPLETE))


class TruncatedDumpTests(unittest.TestCase):
    def test_a_truncated_or_erroring_walk_is_summarised_as_unreadable(self):
        for dump, walk in [(TRUNCATED_WALK, dict(elements=5, truncated=True, errors=0)), (ERRORS_WALK, dict(elements=212, truncated=False, errors=3))]:
            with self.subTest(walk=walk):
                summary = LIVE.dump_summary(dump, LOCKDOWN)
                self.assertEqual((summary["dump"], summary["lines"], summary["matches"], summary["walk"]), ("unreadable", 5, [], walk))
                self.assertTrue(LIVE.dump_incomplete(dump))
        text = LIVE.dump_summary_text(dict(window="1", **LIVE.dump_summary(TRUNCATED_WALK, LOCKDOWN)))
        self.assertEqual(text, "window 1: unreadable (ax-walk elements=5 truncated=1 errors=0)")
        self.assertEqual(LIVE.dump_summary(TRUNCATED, LOCKDOWN)["dump"], "ok", "without the walk line the short tree cannot be told apart")
        self.assertIsNone(LIVE.dump_walk(NO_WINDOW))
        self.assertEqual(LIVE.dump_summary(NO_WINDOW, LOCKDOWN)["dump"], "unreadable")

    def test_a_truncated_dump_is_read_again_and_the_complete_read_is_used(self):
        runner, live = element.session(TRUNCATED_WALK, ERRORS_WALK, COMPLETE_WALK)
        self.assertEqual(live.read_dump("1"), COMPLETE_WALK)
        self.assertEqual(len(element.gui(runner, "dump")), 3)
        retries = [entry for entry in live.ledger if "dumpRetry" in entry]
        self.assertEqual([(entry["dumpWindow"], entry["dumpRetry"], entry["walk"]["truncated"], entry["walk"]["errors"]) for entry in retries],
                         [("1", 1, True, 0), ("1", 2, False, 3)])

    def test_retries_stop_after_three_and_the_last_read_stands_as_unreadable(self):
        runner, live = element.session(TRUNCATED_WALK)
        dump = live.read_dump("1")
        self.assertEqual(LIVE.DUMP_RETRIES, 3)
        self.assertEqual(len(element.gui(runner, "dump")), 4, "the first read and three re-reads")
        self.assertEqual(LIVE.dump_summary(dump, LOCKDOWN)["dump"], "unreadable")

    def test_retries_stay_within_the_deadline(self):
        runner, live = element.session(TRUNCATED_WALK)
        live.read_dump("1", deadline=runner.monotonic() + 0.3)
        self.assertEqual(len(element.gui(runner, "dump")), 1, "no re-read when the settle would pass the deadline")
        runner, live = element.session(TRUNCATED_WALK)
        start = runner.monotonic()
        live.read_dump("1")
        self.assertLess(runner.monotonic() - start, SEARCH, "the default bound is GUI_SEARCH")

    def test_a_dump_without_the_walk_line_or_with_the_failure_marker_is_never_retried(self):
        for dump in (TRUNCATED, NO_WINDOW, COMPLETE_WALK):
            with self.subTest(dump=dump[:40]):
                runner, live = element.session(dump)
                live.read_dump("1")
                self.assertEqual(len(element.gui(runner, "dump")), 1)

    def test_a_re_read_that_hits_its_deadline_returns_the_previous_read(self):
        runner = DeadlineRunner([TRUNCATED_WALK], reads=1)
        live = LIVE.Session("fixture", {}, runner=runner)
        self.assertEqual(live.read_dump("1"), TRUNCATED_WALK)
        self.assertEqual(len(element.gui(runner, "dump")), 2)
        self.assertEqual([entry.get("error") for entry in live.ledger if entry.get("argv", [])[:4] == ["just", "lab", "gui", "dump"]],
                         [None, "deadline"], "the command ledger keeps the deadline")
        runner = DeadlineRunner([TRUNCATED_WALK], reads=0)
        live = LIVE.Session("fixture", {}, runner=runner)
        with self.assertRaises(RuntimeError, msg="the first read still raises"):
            live.read_dump("1", check=False)


class BestReadTests(unittest.TestCase):
    """Verify F1: read_dump keeps the best read, not the last, and stops once a read carries the caller's target."""

    def test_the_verifier_input_finds_the_toggle_in_the_first_read_with_no_extra_walk(self):
        # First read complete with errors=1 and the toggle present; every later read (any window) truncated.
        runner, live = element.session(COMPLETE_ERRORS_WALK, TRUNCATED_WALK)
        self.assertEqual(live.click_id(LOCKDOWN), "element")
        verbs = [argv[3] for argv in runner.commands if argv[:3] == ["just", "lab", "gui"]]
        self.assertEqual(verbs[:2], ["dump", "scroll"], "the toggle is found in the first read: no re-read before the scroll")
        self.assertEqual(verbs[-1], "press")
        self.assertEqual(element.gui(runner, "press"), [press_only("1")])
        scrolled = next(entry for entry in live.ledger if "scroll" in entry and "controlIdentifier" in entry)
        self.assertEqual((scrolled["elementFrame"], scrolled["controlRole"]), ([286, 834, 82, 16], "AXCheckBox"))

    def test_with_the_target_the_first_read_stands_and_without_it_the_best_read_is_kept(self):
        runner, live = element.session(COMPLETE_ERRORS_WALK, TRUNCATED_WALK)
        self.assertEqual(live.read_dump("1", identifier=LOCKDOWN, role="AXCheckBox"), COMPLETE_ERRORS_WALK)
        self.assertEqual(len(element.gui(runner, "dump")), 1, "the read carries the toggle: no re-read")
        runner, live = element.session(COMPLETE_ERRORS_WALK, TRUNCATED_WALK)
        self.assertEqual(live.read_dump("1", identifier=LOCKDOWN, role="AXButton"), COMPLETE_ERRORS_WALK,
                         "another role is not the target: re-read, and the worse truncated reads never replace the first")
        self.assertEqual(len(element.gui(runner, "dump")), 4)
        runner, live = element.session(COMPLETE_ERRORS_WALK, TRUNCATED_WALK)
        self.assertEqual(live.read_dump("1"), COMPLETE_ERRORS_WALK)
        self.assertEqual(len(element.gui(runner, "dump")), 4, "no target: the retries run, the best read is returned")

    def test_a_truncated_first_read_followed_by_a_complete_one_yields_the_complete_one(self):
        for identifier in (None, LOCKDOWN):
            with self.subTest(identifier=identifier):
                runner, live = element.session(TRUNCATED_WALK, COMPLETE_WALK, TRUNCATED_WALK)
                self.assertEqual(live.read_dump("1", identifier=identifier), COMPLETE_WALK)
                self.assertEqual(len(element.gui(runner, "dump")), 2)

    def test_the_rank_orders_complete_then_lines_then_errors_and_failed_reads_last(self):
        ranked = sorted([NO_WINDOW, "", TRUNCATED_WALK, ERRORS_WALK, COMPLETE_ERRORS_WALK, COMPLETE_WALK], key=LIVE.dump_rank)
        self.assertEqual(ranked[2:], [TRUNCATED_WALK, ERRORS_WALK, COMPLETE_ERRORS_WALK, COMPLETE_WALK])
        self.assertEqual({LIVE.dump_rank(NO_WINDOW), LIVE.dump_rank("")}, {(0, 0, 0, 0)})
        self.assertGreater(LIVE.dump_rank(COMPLETE_ERRORS_WALK), LIVE.dump_rank(ERRORS_WALK), "more element lines beat fewer errors")
        runner, live = element.session(TRUNCATED_WALK, NO_WINDOW)
        self.assertEqual(live.read_dump("1", check=False), TRUNCATED_WALK, "a failed re-read never replaces a readable one")
        self.assertEqual(len(element.gui(runner, "dump")), 2, "and it ends the retries")

    def test_the_read_that_carries_the_target_is_the_one_returned(self):
        # M1-10l fix verify G1: read 1 is complete with one unread element (the toggle's own); read 2 is cut after the toggle.
        first = COMPLETE.replace(next(line for line in COMPLETE.splitlines() if LOCKDOWN in line) + "\n", "")
        first += "ax-walk: elements=411 truncated=0 errors=1\n"
        second = TRUNCATED + next(line for line in COMPLETE.splitlines() if LOCKDOWN in line) + "\nax-walk: elements=6 truncated=1 errors=0\n"
        self.assertFalse(LIVE.dump_carries(first, LOCKDOWN))
        self.assertGreater(LIVE.dump_rank(first), LIVE.dump_rank(second), "without the target the complete read ranks first")
        for role in ("-", "AXCheckBox"):
            with self.subTest(role=role):
                runner, live = element.session(first, second, TRUNCATED_WALK)
                read = live.read_dump("1", identifier=LOCKDOWN, role=role)
                self.assertEqual(read, second)
                self.assertTrue(LIVE.dump_carries(read, LOCKDOWN, role))
                self.assertEqual(len(element.gui(runner, "dump")), 2)
        runner, live = element.session(first, second, TRUNCATED_WALK)
        self.assertEqual(live.read_dump("1"), first, "no target: the rank alone decides and the retries run")
        self.assertEqual(len(element.gui(runner, "dump")), 4)

    def test_dump_carries_matches_identifier_and_role(self):
        self.assertTrue(LIVE.dump_carries(COMPLETE_ERRORS_WALK, LOCKDOWN))
        self.assertTrue(LIVE.dump_carries(COMPLETE_ERRORS_WALK, LOCKDOWN, "AXCheckBox"))
        self.assertFalse(LIVE.dump_carries(COMPLETE_ERRORS_WALK, LOCKDOWN, "AXButton"))
        self.assertFalse(LIVE.dump_carries(TRUNCATED_WALK, LOCKDOWN))
        self.assertFalse(LIVE.dump_carries(COMPLETE_ERRORS_WALK, "wgex.protection"), "the identifier matches exactly")


class PostScrollDeadlineTests(unittest.TestCase):
    """Verify F5: a post-scroll window is re-read only within GUI_SEARCH_SHORT of its first read."""

    def test_one_incomplete_post_scroll_window_costs_at_most_the_short_deadline_plus_one_walk(self):
        short = LIVE.HARNESS.seconds("GUI_SEARCH_SHORT")
        walk = short / 2 + 1
        self.assertLess(walk * (LIVE.DUMP_RETRIES + 1), SEARCH, "under the old GUI_SEARCH bound all four reads would fit")
        runner = SlowWindowRunner([COMPLETE_WALK], {"1": [TRUNCATED_WALK], "2": [NO_WINDOW]}, walk)
        live = LIVE.Session("fixture", {}, runner=runner)
        self.assertEqual(live.click_id(LOCKDOWN), "element")
        windows = [argv[2] for argv in element.gui(runner, "dump")]
        self.assertEqual(windows, ["1"] + ["1", "1"] + ["2"], "before the scroll one read; window 1 after it: the first read "
                         "and one re-read started inside the short deadline, a third would start after it")
        self.assertEqual(element.gui(runner, "press"), [press_only("1")])


class Run8dSequenceTests(unittest.TestCase):
    def test_the_run8d_sequence_retries_the_short_reads_then_presses_press_only_with_the_targeted_lookup(self):
        # Before the scroll: one read and three re-reads all short (unreadable, the search goes on), then the complete
        # read finds the toggle below the window. After the scroll: a short read of window 1, then a complete one.
        runner, live = post.session([TRUNCATED_WALK] * 4 + [COMPLETE_WALK], {"1": [TRUNCATED_WALK, COMPLETE_WALK]})
        self.assertEqual(live.click_id(LOCKDOWN), "element")
        verbs = [argv[3] for argv in runner.commands if argv[:3] == ["just", "lab", "gui"]]
        self.assertEqual(verbs, ["dump"] * 5 + ["scroll", "dump", "dump", "press"])
        self.assertEqual(element.gui(runner, "press"), [press_only("1")], "press-only: identifier and role, no point")
        entry = live.ledger[-1]
        self.assertEqual((entry["actionPath"], entry["pressOnly"], entry["postScroll"], entry["postScrollWindow"]),
                         ("element-offscreen", "element", "still outside its window", "1"))
        self.assertEqual([(item["window"], item["dump"], item["lines"]) for item in entry["postScrollDumps"]], [("1", "ok", 68)])
        self.assertEqual([entry["dumpRetry"] for entry in live.ledger if "dumpRetry" in entry], [1, 2, 3, 1])

    def test_a_post_scroll_window_that_stays_truncated_is_named_unreadable_in_the_gap(self):
        runner, live = post.session([COMPLETE_WALK], {"1": [TRUNCATED_WALK], "2": [NO_WINDOW]}, press=b"path=none\n")
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.click_id(LOCKDOWN)
        self.assertEqual(raised.exception.reason, "guiTargetOffscreen:" + LOCKDOWN)
        self.assertIn("window 1: unreadable (ax-walk elements=5 truncated=1 errors=0); window 2: unreadable)", str(raised.exception))
        self.assertEqual([argv[2] for argv in element.gui(runner, "dump")], ["1"] + ["1"] * 4 + ["2"], "window 1 read four times, window 2 once")
        self.assertEqual(element.gui(runner, "press"), [press_only("1")] * 3)


class WalkHelperShapeTests(unittest.TestCase):
    def test_neither_helper_uses_entire_contents_or_system_events_specifiers(self):
        for name in ("ax-dump.applescript", "ax-action.applescript"):
            with self.subTest(name=name):
                source = code(helper(name))
                self.assertNotIn("entire contents", source)
                self.assertNotIn("contents of e", source, "a specifier System Events returns names the window by its title")
                self.assertIn("a reference to window winIdx", source)
                self.assertIn("a reference to UI element i of parentRef", source)
                self.assertIn("property WALK_DEPTH_LIMIT : 16", source)
                self.assertIn("property WALK_ELEMENT_BUDGET : 4000", source)
                self.assertIn("if walkCount is greater than or equal to WALK_ELEMENT_BUDGET then", source)
                self.assertIn("if walkDepth is less than WALK_DEPTH_LIMIT then", source)
                window = source.index("set childCount to count of UI elements of window winIdx")
                self.assertNotIn("try", source[source.rindex("\n", 0, window - 1):window], "a missing window still fails the helper")

    def test_the_dump_walk_keeps_the_line_format_and_ends_with_its_summary(self):
        source = code(helper("ax-dump.applescript"))
        self.assertIn('set walkOut to walkOut & r & " | name=" & n & " | value=" & v & " | desc=" & d & " | id=" & ident & " | pos=" & '
                      '(item 1 of p) & "," & (item 2 of p) & " size=" & (item 1 of s) & "x" & (item 2 of s) & " en=" & en & linefeed', source)
        self.assertIn('return walkOut & "ax-walk: elements=" & walkCount & " truncated=" & walkTruncated & " errors=" & walkErrors', source)
        describe = source[source.index("on describeElement(e)"):source.index("end describeElement")]
        self.assertEqual(describe.count("set walkErrors to walkErrors + 1"), 2, "a failed role read and a failed line are counted")
        walk = source[source.index("on walkChildren("):source.index("end walkChildren")]
        self.assertLess(walk.index("my describeElement(e)"), walk.index("my walkChildren(e, kids, walkDepth + 1)"), "pre-order, as before")
        self.assertIn("set walkTruncated to 1", walk)
        sample = "ax-walk: elements=5 truncated=1 errors=0"
        self.assertTrue(LIVE.WALK_LINE.fullmatch(sample))
        dump_filter = re.search(r"grep -v -E '([^']+)'", (ROOT / "Tools/lab/tart/gui.sh").read_text())[1]
        self.assertIsNone(re.search(dump_filter, sample), "gui.sh passes the walk line through")

    def test_press_only_and_scroll_use_the_targeted_walk_and_stop_at_the_first_match(self):
        source = code(helper("ax-action.applescript"))
        find = source[source.index("on findChildren("):source.index("end findChildren")]
        self.assertIn("if my elementMatches(e) then\n      set walkFound to e\n      set walkMatched to true\n      set walkDone to true\n      return", find)
        self.assertIn("if walkDone then return", find)
        matches = source[source.index("on elementMatches(e)"):source.index("end elementMatches")]
        self.assertIn('roleName is "-" or (role of e as text) is roleName', matches)
        self.assertIn("frameX is not missing value", matches)
        walk = source.index("my findChildren(windowRef, childCount, 1)")
        for later in ('if modeName is "scroll" then\n      if not haveFound', 'return "scroll=missing"', "perform action actionName of found", 'return "path=miss"'):
            self.assertLess(walk, source.index(later), later)
        self.assertEqual(source.count("my findChildren(windowRef"), 1, "one lookup serves press, confirm, press-only and scroll")

    def test_the_scroll_fallback_uses_the_walks_own_parent_references_and_cannot_fail_outside_a_try(self):
        # Verify F2 (M1-10l fix pass 1): no AXParent, no list or contents System Events returns; the scroll area is an
        # ancestor reference of the match, kept as the walk unwinds, and its bar and document are taken by index.
        source = code(helper("ax-action.applescript"))
        for forbidden in ('"AXParent"', "contents of", "in (UI elements", "repeat with c in"):
            self.assertNotIn(forbidden, source)
        find = source[source.index("on findChildren("):source.index("end findChildren")]
        unwind = find[find.index("my findChildren(e, kids, walkDepth + 1)"):]
        self.assertIn("if walkMatched and wantArea and not walkAreaFound then", unwind)
        self.assertIn('if areaRole is "AXScrollArea" then\n              set walkArea to e', unwind)
        self.assertIn("set c to a reference to UI element i of scrollArea", source)
        branch = source[source.index('if modeName is "scroll" then\n      if not haveFound'):source.index('    if haveFound then\n      set foundRole')]
        geometry = branch[branch.index("if not (haveBar and haveDocument) then"):]
        self.assertLess(geometry.index("try"), geometry.index("position of found"))
        self.assertLess(geometry.index('set value of attribute "AXValue" of barElement to fraction'), geometry.index("end try"))
        self.assertIn('return "scroll=bar"\n      end try\n      return "scroll=none"', geometry, "a failed read or write: scroll=none")

    def test_the_match_is_a_boolean_never_a_reference_comparison(self):
        # Verify F3: comparing a reference with missing value makes AppleScript get it, outside any try block.
        source = code(helper("ax-action.applescript"))
        for forbidden in ("found is not missing value", "found is missing value", "barElement is missing value",
                          "documentElement is missing value", "scrollArea is missing value"):
            self.assertNotIn(forbidden, source)
        self.assertIn("set haveFound to walkMatched", source)
        self.assertIn('if not haveFound then return "scroll=missing"', source)
        self.assertIn("    if haveFound then\n      set foundRole", source)


if __name__ == "__main__":
    unittest.main()
