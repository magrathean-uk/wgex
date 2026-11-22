# SPDX-License-Identifier: MIT
"""M1-10t part 3 (VERIFY L-1, L-2, L-3, N-1; lab lows before the BOOT-SECRETS rerun). Recorded replies and fixtures only; no
subprocess, never a VM, never osascript.

L-1: a toggle press whose helper reply raises after the press command was sent is journalled, so TOGGLE_PRESS_LIMIT counts attempts.
L-2: the press-time compare after the scroll (expect_toggle in after_scroll) is tested with an off-screen Allow LAN fixture whose
     post-scroll dump shows the opposite value.
L-3: every app log count up to the required samples is readable, or relaunchPrevented is a named gap.
N-1: an after-scroll press-only on a toggle the caller read is a named gap, never a press against an uncompared value."""
import unittest

import test_gui_element as element
import test_gui_post_scroll as post
import test_reboot_followups as followups
import test_startup_position as position

LIVE, V = element.LIVE, followups.V
ALLOW_LAN = LIVE.ALLOW_LAN_TOGGLE
DUMP = element.OFFSCREEN.splitlines(keepends=True)
LOCKDOWN_LINE = next(line for line in DUMP if "id=wgex.protection.lockdown " in line)
ALLOW_LAN_LINE = next(line for line in DUMP if "id=" + ALLOW_LAN + " " in line)
assert "pos=584,834 size=138x16" in ALLOW_LAN_LINE and "value=1" in ALLOW_LAN_LINE


def allow_lan_offscreen(value):
    """The run 8b main window dump (content bottom 782) with Allow LAN (584,834, below it) showing value and the lockdown line
    dropped, so the identifier is unique."""
    line = ALLOW_LAN_LINE.replace("value=1", f"value={value}")
    return element.OFFSCREEN.replace(LOCKDOWN_LINE, "").replace(ALLOW_LAN_LINE, line)


def press_only_calls(runner):
    return element.gui(runner, "press")


class FirstReplyFailsRunner(position.AllowLANToggleRunner):
    """A daemon-backed toggle whose first Allow LAN press lands (the toggle proposes off, as always) but whose helper reply is
    "ax-action=failed exit=255" (VERIFY L-1's probe)."""

    def __init__(self, **kw):
        super().__init__(lag=None, daemon_backed=True, **kw)
        self.replied_failed = False

    def run(self, argv, data=None, timeout=100, env=None):
        args = argv[2:] if argv[:1] == ["just"] else []
        pressing = args[:2] == ["gui", "press"] and ALLOW_LAN in args
        result = super().run(argv, data, timeout, env)
        if pressing and not self.replied_failed:
            self.replied_failed = True
            return self.reply(argv, b"ax-action=failed exit=255\n", code=1)
        return result


class PressAttemptJournalTests(unittest.TestCase):
    def test_a_press_whose_reply_raises_still_counts_against_the_session_cap(self):
        runner = FirstReplyFailsRunner()
        live = LIVE.Session("fixture", {}, runner=runner)
        reasons = []
        for _ in range(3):
            with self.assertRaises(LIVE.RowFailure) as raised:
                live.set_allow_lan_off()
            reasons.append(raised.exception.reason)
        self.assertEqual(position.allow_lan_presses(runner), LIVE.TOGGLE_PRESS_LIMIT, "at most the limit in total, the failed reply included")
        self.assertEqual(reasons, ["guiActionFailed:" + ALLOW_LAN, "allowLANNotApplied", "allowLANNotApplied"])
        self.assertEqual([item["press"] for item in live.toggle_journal[ALLOW_LAN]], [1, 2])
        raised_entries = [item for item in live.ledger if item.get("pressOutcome") == "raised"]
        self.assertEqual([(item["togglePress"], item["toggleValueBefore"]) for item in raised_entries], [(1, True)])

    def test_an_offscreen_press_only_that_fails_counts_as_an_attempt_too(self):
        runner, live = post.session([allow_lan_offscreen(1)], {"1": [allow_lan_offscreen(1)]}, press=b"path=error number=-25205\n")
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.toggle_until(ALLOW_LAN, lambda: True, False)
        self.assertEqual(raised.exception.reason, "guiTargetOffscreen:" + ALLOW_LAN)
        self.assertEqual(live.toggle_journal[ALLOW_LAN], [dict(press=1, valueBefore=True)])
        self.assertTrue(press_only_calls(runner), "the helper was called")

    def test_a_toggle_moved_refusal_is_not_a_press_attempt(self):
        runner = position.AllowLANToggleRunner(sequence=["1", "0"])
        live = LIVE.Session("fixture", {}, runner=runner)
        with self.assertRaises(LIVE.RowFailure):
            live.set_allow_lan_off()
        self.assertEqual(live.toggle_journal[ALLOW_LAN], [], "nothing was sent to the helper, so nothing is journalled")
        self.assertEqual(position.allow_lan_presses(runner), 0)

    def test_a_missing_control_before_any_press_is_not_a_press_attempt(self):
        runner = position.AllowLANToggleRunner(unreadable=True)
        live = LIVE.Session("fixture", {}, runner=runner)
        with self.assertRaises(LIVE.RowFailure):
            live.set_allow_lan_off()
        self.assertEqual(live.toggle_journal[ALLOW_LAN], [])


class PostScrollCompareTests(unittest.TestCase):
    def test_an_offscreen_toggle_that_changed_during_the_scroll_is_not_pressed(self):
        runner, live = post.session([allow_lan_offscreen(1)], {"1": [allow_lan_offscreen(0)]})
        live.toggle_expected = (ALLOW_LAN, True)
        with self.assertRaises(LIVE.ToggleMoved):
            live.click_id(ALLOW_LAN)
        self.assertEqual(press_only_calls(runner), [], "the post-scroll dump shows off; a press would propose on")
        self.assertEqual(element.gui(runner, "scroll"), [["scroll", "WGEX", "1", ALLOW_LAN]], "the scroll did happen first")
        moved = next(item for item in live.ledger if "toggleSeen" in item)
        self.assertEqual((moved["toggleExpected"], moved["toggleSeen"]), (True, False))

    def test_the_same_fixture_with_an_unchanged_value_is_pressed_press_only(self):
        runner, live = post.session([allow_lan_offscreen(1)], {"1": [allow_lan_offscreen(1)]})
        live.toggle_expected = (ALLOW_LAN, True)
        self.assertEqual(live.click_id(ALLOW_LAN), "element")
        self.assertEqual(press_only_calls(runner), [["press", "WGEX", "1", ALLOW_LAN, "press-only", "AXCheckBox", "frame=584,834,138x16"]],
                         "M1-36: a toggle the caller read is pressed on the compared frame")

    def test_an_unreadable_post_scroll_value_is_not_pressed_either(self):
        unreadable = allow_lan_offscreen(1).replace("value=1", "value=missing value")
        runner, live = post.session([allow_lan_offscreen(1)], {"1": [unreadable]})
        live.toggle_expected = (ALLOW_LAN, True)
        with self.assertRaises(LIVE.ToggleMoved):
            live.click_id(ALLOW_LAN)
        self.assertEqual(press_only_calls(runner), [])


class UncomparedPostScrollPressTests(unittest.TestCase):
    """N-1: the toggle read before the press cannot be compared once the post-scroll dumps do not carry the element (not found) or
    carry it ambiguously with the remembered frame absent, so there is no press at all (a named gap)."""
    LOCKDOWN = post.LOCKDOWN
    MOVED = post.AmbiguousPostScrollTests.MOVED
    OTHER = post.AmbiguousPostScrollTests.OTHER

    def attempt(self, after, expected=True):
        runner, live = post.session([post.RUN8C], {"1": [after]})
        if expected:
            live.toggle_expected = (self.LOCKDOWN, False)
        return runner, live

    def test_not_found_after_the_scroll_is_a_gap_and_nothing_is_pressed_for_a_read_toggle(self):
        runner, live = self.attempt(post.VANISHED)
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.click_id(self.LOCKDOWN)
        self.assertEqual(raised.exception.reason, "guiTargetOffscreen:" + self.LOCKDOWN)
        self.assertIn("not found in any post-scroll dump", str(raised.exception))
        self.assertIn("no value to compare", str(raised.exception))
        self.assertEqual(press_only_calls(runner), [])

    def test_ambiguous_without_the_remembered_frame_is_a_gap_for_a_read_toggle(self):
        runner, live = self.attempt(post.VANISHED + self.MOVED + self.OTHER)
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.click_id(self.LOCKDOWN)
        self.assertEqual(raised.exception.reason, "guiTargetOffscreen:" + self.LOCKDOWN)
        self.assertIn("no value to compare", str(raised.exception))
        self.assertEqual(press_only_calls(runner), [])

    def test_a_target_nobody_read_keeps_the_press_only_path(self):
        runner, live = self.attempt(post.VANISHED, expected=False)
        self.assertEqual(live.click_id(self.LOCKDOWN), "element")
        self.assertEqual(len(press_only_calls(runner)), 1)
        runner, live = self.attempt(post.VANISHED + self.MOVED + self.OTHER, expected=False)
        self.assertEqual(live.click_id(self.LOCKDOWN), "element")
        self.assertEqual(len(press_only_calls(runner)), 1)


class UnreadableAppLogCountTests(unittest.TestCase):
    def relaunch(self, counts, **boot_changes):
        boot = followups.RelaunchPreventedCheckTests().boot()
        boot["appLogLinesSamples"] = counts
        boot.update(boot_changes)
        return followups.boot_secrets(boot)["relaunchPrevented"]

    def test_an_unreadable_count_in_a_non_final_sample_is_a_named_gap(self):
        for label, counts in (("None", [None, 0]), ("string", ["x", 0]), ("negative", [-1, 0]), ("bool", [True, 0]), ("float", [0.0, 0])):
            with self.subTest(label):
                check = self.relaunch(counts)
                self.assertFalse(check["met"], check)
                self.assertIn("app log lines since the post-restart daemon's start was not read at boot sample(s) 1 of 2", check["gap"])
                self.assertIn("never zero", check["gap"])

    def test_every_count_up_to_required_must_be_readable(self):
        check = self.relaunch([0, 0, None], bootObserveSamples=3, bootObservePlanned=3)
        self.assertFalse(check["met"])
        self.assertIn("boot sample(s) 3 of 3", check["gap"])
        check = self.relaunch([None, 0, None], bootObserveSamples=3, bootObservePlanned=3)
        self.assertIn("boot sample(s) 1, 3 of 3", check["gap"])

    def test_the_end_count_gap_is_still_named(self):
        check = self.relaunch([0, None])
        self.assertFalse(check["met"])
        self.assertIn("not read at boot sample(s) 2 of 2", check["gap"])

    def test_good_samples_with_prevention_are_still_met(self):
        self.assertTrue(self.relaunch([0, 0])["met"])
        self.assertTrue(self.relaunch([0, 0, 0], bootObserveSamples=3, bootObservePlanned=3)["met"])


if __name__ == "__main__":
    unittest.main()
