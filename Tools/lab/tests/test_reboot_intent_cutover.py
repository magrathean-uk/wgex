# SPDX-License-Identifier: MIT
"""M03-T07: REBOOT-INTENT records the cutover state before the reboot, refuses an armed (or any other non-none, non-confirmed) trial
before the reboot, and passes only when the persisted intent is active and protected again after it. Recorded replies only; never a VM."""
import unittest
import unittest.mock

import test_run8_rows as run8

V, LIVE = run8.V, run8.LIVE
PROFILE = "00000000-0000-4000-8000-000000000001"


def status(phase="active", protection="protected", profile=PROFILE, cutover=None):
    return dict(phase=phase, protection=protection, activeProfileID=profile, cutover=cutover if cutover is not None else dict(state="none"))


class IntentSnapshotTests(unittest.TestCase):
    def test_the_snapshot_keeps_phase_protection_profile_and_cutover_state(self):
        snap = V.intent_snapshot(status(cutover=dict(state="rolledBack", reason="aborted")))
        self.assertEqual(snap, dict(phase="active", protection="protected", activeProfileID=PROFILE, cutoverState="rolledBack", cutoverReason="aborted"))

    def test_a_missing_or_malformed_cutover_object_is_unreadable(self):
        for value in (None, "armed", dict(), dict(state=""), dict(state=3)):
            with self.subTest(value=value):
                raw = status()
                raw["cutover"] = value
                self.assertEqual(V.intent_snapshot(raw)["cutoverState"], "unreadable")
        self.assertEqual(V.intent_snapshot(dict(redacted=True))["cutoverState"], "unreadable")
        self.assertIsNone(V.intent_snapshot(status(profile=""))["activeProfileID"])
        self.assertIsNone(V.intent_snapshot(None)["activeProfileID"])


class CutoverCheckTests(unittest.TestCase):
    def test_none_and_confirmed_are_met(self):
        for state in ("none", "confirmed"):
            check = V.cutover_before_reboot_check(V.intent_snapshot(status(cutover=dict(state=state))))
            self.assertTrue(check["met"], state)
            self.assertEqual(check["cutoverState"], state)
            self.assertNotIn("gap", check)

    def test_armed_rolled_back_and_unreadable_are_not_met_and_carry_a_gap(self):
        armed = V.cutover_before_reboot_check(V.intent_snapshot(status(cutover=dict(state="armed", deadline="2030-01-01T00:00:00Z"))))
        self.assertFalse(armed["met"])
        self.assertTrue(armed["gap"].startswith("cutoverArmedBeforeReboot:"))
        self.assertIn("M03-T08", armed["gap"])
        for state in ("rolledBack", "unreadable"):
            check = V.cutover_before_reboot_check(dict(cutoverState=state))
            self.assertFalse(check["met"])
            self.assertIn(state, check["gap"])
        self.assertFalse(V.cutover_before_reboot_check(None)["met"])


class IntentRestoredCheckTests(unittest.TestCase):
    def test_the_same_profile_active_and_protected_is_met(self):
        before = V.intent_snapshot(status())
        check = V.intent_restored_check(before, V.intent_snapshot(status()))
        self.assertTrue(check["met"])
        self.assertEqual(check["intendedProfileBeforeReboot"], PROFILE)

    def test_any_other_outcome_is_a_named_gap(self):
        before = V.intent_snapshot(status())
        cases = [status(phase="failed", protection="blocked"), status(phase="idle", protection="unprotected", profile=None),
                 status(profile="00000000-0000-4000-8000-000000000009"), status(phase="reasserting", protection="blocked"), None]
        for after in cases:
            with self.subTest(after=after):
                check = V.intent_restored_check(before, V.intent_snapshot(after))
                self.assertFalse(check["met"])
                self.assertTrue(check["gap"].startswith("intentNotRestored:"))
        lost = V.intent_restored_check(V.intent_snapshot(status(profile=None)), V.intent_snapshot(status()))
        self.assertFalse(lost["met"], "no intended profile before the reboot is never a pass")
        self.assertIn("no intended profile", lost["gap"])


class DriverTests(unittest.TestCase):
    def test_the_row_records_the_cutover_state_before_the_reboot_and_the_restored_intent(self):
        _, result = run8.run_row("REBOOT-INTENT")
        cutover = run8.check(result, "cutoverStateBeforeReboot")
        self.assertTrue(cutover["met"])
        self.assertEqual(cutover["cutoverState"], "none")
        restored = run8.check(result, "intentRestoredAfterBoot")
        self.assertTrue(restored["met"])
        self.assertEqual(restored["statusAfterBoot"], dict(phase="active", protection="protected", activeProfileID=PROFILE))

    def test_a_confirmed_trial_is_accepted(self):
        runner = run8.Run8Runner()
        runner.cutover_state = "confirmed"
        _, result = run8.run_row("REBOOT-INTENT", runner)
        self.assertEqual(run8.check(result, "cutoverStateBeforeReboot")["cutoverState"], "confirmed")

    def test_an_armed_trial_stops_the_row_before_the_reboot(self):
        runner = run8.Run8Runner()
        runner.cutover_state = "armed"
        _, result = run8.run_row("REBOOT-INTENT", runner, accepted=False)
        self.assertFalse(any(c.endswith("verdict-actions.sh reboot") for c in run8.commands(runner)), "never rebooted while armed")
        self.assertFalse(result["rowCompleted"])
        self.assertTrue(any("cutoverStateBeforeReboot" in gap for gap in result["gaps"]), result["gaps"])

    def test_an_intent_that_does_not_come_back_fails_the_row(self):
        runner = run8.Run8Runner()
        runner.boot_restores_protected = False
        with unittest.mock.patch.object(LIVE, "INTENT_RESTORE_WAIT_SECONDS", 5):
            _, result = run8.run_row("REBOOT-INTENT", runner, accepted=False)
        restored = run8.check(result, "intentRestoredAfterBoot")
        self.assertFalse(restored["met"])
        self.assertIn(restored["gap"], result["gaps"])

    def test_the_other_reboot_rows_carry_neither_check(self):
        for row in ("REBOOT-LOCKDOWN", "BOOT-SECRETS"):
            with self.subTest(row):
                _, result = run8.run_row(row, run8.Run8Runner() if row == "REBOOT-LOCKDOWN" else run8.BootSecretsTests().runner())
                names = [item["name"] for item in result["checks"]]
                self.assertNotIn("cutoverStateBeforeReboot", names)
                self.assertNotIn("intentRestoredAfterBoot", names)

if __name__ == "__main__":
    unittest.main()
