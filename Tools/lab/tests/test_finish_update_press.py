# SPDX-License-Identifier: MIT
"""M03-T07 phase B: M5.3-07 stopped at the Finish update press with "missing or ambiguous accessible control" although the
Service tab dump carried exactly one enabled AXButton with id wgex.service.finishUpdate; its dumped title did not match the
label "Finish update". The press now goes by identifier only, as every other identified press. Never a VM."""
import unittest

import test_gui_element as element

LIVE = element.LIVE
WINDOW = "AXWindow | name=Service | value= | desc= | id= | pos=62,30 size=900x738\n"
# The live match (ledger lastDump): AXButton, enabled, frame 170,391 105x24; the title is not the label.
BUTTON = ("AXButton | name=missing value | value= | desc= | id=" + LIVE.FINISH_UPDATE
          + " | pos=170,391 size=105x24 en=true\n")


class FinishUpdatePressTests(unittest.TestCase):
    def press(self, dump):
        runner, live = element.session(dump)
        live.open_settings = lambda keep_probing=None: "1"
        live.select_settings_tab = lambda window, tab, keep_probing=None: None
        live.press_finish_update()
        return runner, live

    def test_the_button_is_pressed_by_identifier_whatever_its_dumped_title(self):
        runner, live = self.press(WINDOW + BUTTON)
        pressed = element.gui(runner, "press")
        self.assertEqual(len(pressed), 1)
        self.assertEqual(pressed[0][:4], ["press", "WGEX", "1", LIVE.FINISH_UPDATE])
        self.assertEqual(element.gui(runner, "click"), [])
        self.assertEqual(live.ledger[-1]["actionPath"], "element")

    def test_a_titled_button_is_still_pressed_by_identifier(self):
        runner, _ = self.press(WINDOW + BUTTON.replace("name=missing value", "name=Finish update"))
        self.assertEqual([argv[3] for argv in element.gui(runner, "press")], [LIVE.FINISH_UPDATE])


# M03-T17: M5.3-07 lost 1.6 s and 4 s of hand-off probe coverage because the next generator started only once the Settings
# window was open and its tab selected, and the tab selection alone took about 46 s (six failed lookups before the title press).
GENERATOR_SECONDS = LIVE.UPDATE_PROBE_ROUNDS * 0.5 - 0.5   # the generator's real window is about 59.7 s


class SlowTabTests(unittest.TestCase):
    """The real open_settings, select_settings_tab and press_finish_update on a fake clock where every console step is slow."""

    def slow_session(self):
        runner, live = element.session(WINDOW + BUTTON)
        starts = []
        live.start_probe = lambda state, role: starts.append(runner.monotonic()) or dict(started=runner.monotonic())
        real_click, real_lab = live.click, live.lab

        def click(label, identifier=None, window="1", timeout=None):
            if identifier == LIVE.FINISH_UPDATE:
                return real_click(label, identifier, window=window, timeout=timeout)
            runner.clock += 18                      # a lookup that spends its search and then fails
            if label is None:
                raise ValueError("missing or ambiguous accessible control")
            return None

        def press_title(title, window="1", timeout=None, container_role="AXToolbar"):
            runner.clock += 18
            raise ValueError("missing or ambiguous accessible control")

        def lab(*args, **kw):
            runner.clock += 12 if args[:2] == ("gui", "activate") else 1   # a slow window activation
            return real_lab(*args, **kw)

        live.click, live.press_title, live.lab = click, press_title, lab
        return runner, live, starts

    def keep_probing(self, runner, live, starts):
        probes = []

        def keep_probing(force=False):
            if force or runner.monotonic() - probes[-1] >= LIVE.UPDATE_PROBE_STEP_SECONDS:
                live.start_probe("blocked", "update:handoff")
                probes.append(starts[-1])

        keep_probing(force=True)
        return keep_probing

    def test_a_slow_tab_selection_opens_no_gap_between_generator_windows(self):
        runner, live, starts = self.slow_session()
        began = runner.monotonic()
        live.press_finish_update(self.keep_probing(runner, live, starts))
        self.assertGreater(runner.monotonic() - began, 40, "the fixture really is as slow as M5.3-07 was")
        self.assertGreater(len(starts), 1)
        for earlier, later in zip(starts, starts[1:]):
            self.assertLessEqual(later - earlier, GENERATOR_SECONDS)
        self.assertLessEqual(runner.monotonic() - starts[-1], GENERATOR_SECONDS, "the press itself lies inside a window")

    def test_without_the_hook_the_same_slow_path_does_leave_a_gap(self):
        runner, live, starts = self.slow_session()
        live.start_probe("blocked", "update:handoff")
        live.press_finish_update()
        self.assertGreater(runner.monotonic() - starts[-1], GENERATOR_SECONDS, "the fixture would catch the old behaviour")

    def test_a_failed_tab_selection_still_ticks_before_it_raises(self):
        runner, live, starts = self.slow_session()
        live.walk_read = lambda window, **kw: WINDOW.replace("name=Service", "name=General")
        keep_probing = self.keep_probing(runner, live, starts)
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.select_settings_tab("1", "Service", keep_probing)
        self.assertEqual(raised.exception.reason, "settingsTabNotSelected:Service")
        self.assertLessEqual(runner.monotonic() - starts[-1], GENERATOR_SECONDS)
        for earlier, later in zip(starts, starts[1:]):
            self.assertLessEqual(later - earlier, GENERATOR_SECONDS)


if __name__ == "__main__":
    unittest.main()
