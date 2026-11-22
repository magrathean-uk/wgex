#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""M03-T08: the live cutover rehearsal's producer (cutover-live.py) and its entry points, offline; nothing contacts a VM."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "Tools/lab/cutover-rehearsal.sh"
PROFILE = "00000000-0000-4000-8000-000000000101"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


LIVE = load("test_cutover_live_module", ROOT / "Tools/lab/cutover-live.py")
CHECKS = load("test_cutover_live_checks", ROOT / "Tools/lab/check-verdicts.py")


def status(**changes):
    value = dict(phase="idle", protection="unprotected", policyEnforcing=False, activeProfileID=None,
                 cutover=dict(state="rolledBack", reason="aborted"), cutoverRollbackFailures=[], operationInFlight=False)
    value.update(changes)
    return LIVE.status_summary(value)


class ContractTests(unittest.TestCase):
    def test_rehearsal_and_name_row_use_the_resolvable_lab_name(self):
        self.assertEqual(LIVE.PROFILE, "full4-name")
        rows = json.loads((ROOT / "Tools/lab/rows.json").read_text())["rows"]
        self.assertEqual(rows["M04-T13-NAME"]["profile"], LIVE.PROFILE)

    def test_the_producer_writes_exactly_the_reader_keys(self):
        self.assertEqual(LIVE.SCENARIOS + LIVE.SUPPLEMENTS, CHECKS.REHEARSAL_CHECKS)
        self.assertEqual(len(set(LIVE.SCENARIOS + LIVE.SUPPLEMENTS)), 14)

    def test_rolled_back_end_state(self):
        self.assertTrue(LIVE.rolled_back_unprotected(status(), "aborted"))
        bad = [status(cutover=dict(state="rolledBack", reason="timeout")), status(protection="blocked"), status(protection="unknown"),
               status(phase="failed"), status(policyEnforcing=True), status(activeProfileID=PROFILE),
               status(cutoverRollbackFailures=["deleteSecrets"]), status(recoveryFailureReason="reconciliationFailed"),
               status(cutover=dict(state="armed")), status(cutover=dict(state="confirmed"))]
        for summary in bad:
            self.assertFalse(LIVE.rolled_back_unprotected(summary, "aborted"), summary)

    def test_a_recovered_rollback_may_keep_only_the_names_it_was_made_to_fail(self):
        history = status(cutoverRollbackFailures=["deleteSecrets", "deleteSecrets"])
        self.assertTrue(LIVE.rolled_back_unprotected(history, "aborted", LIVE.BLOCKED_STEP))
        self.assertFalse(LIVE.rolled_back_unprotected(history, "aborted"), "a clean rollback lists no failure")
        other = status(cutoverRollbackFailures=["deleteSecrets", "removeRoutes"])
        self.assertFalse(LIVE.rolled_back_unprotected(other, "aborted", LIVE.BLOCKED_STEP))
        self.assertFalse(LIVE.rolled_back_unprotected(status(cutoverRollbackFailures=None), "aborted", LIVE.BLOCKED_STEP))

    def test_restored_intent_needs_the_profile_active_protected_and_confirmed(self):
        good = status(phase="active", protection="protected", activeProfileID=PROFILE, cutover=dict(state="confirmed"))
        self.assertTrue(LIVE.restored_intent(good, PROFILE))
        for change in (dict(phase="reasserting"), dict(protection="blocked"), dict(activeProfileID=None), dict(cutover=dict(state="armed"))):
            raw = dict(dict(phase="active", protection="protected", activeProfileID=PROFILE, cutover=dict(state="confirmed")), **change)
            self.assertFalse(LIVE.restored_intent(status(**raw), PROFILE), change)


def result(accepted=True):
    value = dict(schemaVersion=1, row="cutover-rehearsal", date="2026-01-01T00:00:00+00:00", dryRun=False, guest="macos26-wgex",
                 guestOS=dict(productVersion="26.6.2", buildVersion="25G83"), liveAcceptance=accepted, gaps=[] if accepted else ["x: y"],
                 checks={key: dict(met=accepted, summary="evidence") for key in CHECKS.REHEARSAL_CHECKS}, leakWindows=[])
    value.update(dict.fromkeys(CHECKS.REHEARSAL_CHECKS, accepted))
    return value


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(dir=os.environ.get("TMPDIR")))
        self.addCleanup(shutil.rmtree, self.directory)

    def test_an_accepted_run_writes_one_verdict_and_a_readme_listing_every_key(self):
        LIVE.write_report(self.directory, result())
        self.assertEqual(sorted(path.name for path in self.directory.iterdir()), ["README.md", "verdict.json"])
        readme = (self.directory / "README.md").read_text()
        for key in CHECKS.REHEARSAL_CHECKS:
            self.assertIn(f"| {key} | true |", readme)
        self.assertTrue(json.loads((self.directory / "verdict.json").read_text())["liveAcceptance"])

    def test_the_readme_says_old_client_is_the_foreign_utun_stand_in(self):
        """DEC-030: the row names the stand-in, what it proves and that the official app is checked at the maintainer's sitting."""
        for accepted in (True, False):
            row = next(line for line in LIVE.readme(result(accepted)).splitlines() if line.startswith("| oldGuestClientAvailable |"))
            self.assertIn("foreign-utun stand-in", row)
            self.assertIn("another client's utun, address and routes survive cutover and rollback", row)
            self.assertIn("official app's reconnection is checked at the maintainer's sitting", row)
            self.assertIn("DEC-030", row)
        other = next(line for line in LIVE.readme(result()).splitlines() if line.startswith("| abort |"))
        self.assertNotIn("stand-in", other)

    def test_the_old_client_note_claims_proof_only_when_the_check_was_met(self):
        """A failed or unreached oldGuestClientAvailable states what the check is meant to establish, never that it proved it."""
        def row(value):
            return next(line for line in LIVE.readme(value).splitlines() if line.startswith("| oldGuestClientAvailable |"))
        self.assertIn(": proves another client's utun", row(result()))
        failed = row(result(False))
        unreached = result(False)
        del unreached["checks"]["oldGuestClientAvailable"]
        unreached_row = row(unreached)
        self.assertIn("| false | not reached;", unreached_row)
        for line in (failed, unreached_row):
            self.assertIn("| false |", line)
            self.assertNotIn("proves", line)
            self.assertIn("is meant to establish that another client's utun, address and routes survive cutover and rollback", line)

    def test_the_readme_names_the_macos27_commands_for_a_macos27_guest(self):
        text = LIVE.readme(dict(result(True), guest="macos27-wgex"))
        self.assertIn("bash Tools/lab/cutover-rehearsal.sh --report-root Tests/Reports/v2/macos27 macos27-wgex", text)
        self.assertIn("--root Tests/Reports/v2/macos27 --guest-os 27 --since M02 --rehearsal cutover-rehearsal", text)
        self.assertNotIn("macos26", text)
        text = LIVE.readme(result(True))
        self.assertIn("--report-root Tests/Reports/v2 macos26-wgex", text)
        self.assertIn("--root Tests/Reports/v2 --guest-os 26 --since M02", text)

    def test_a_failed_run_keeps_every_attempt(self):
        LIVE.write_report(self.directory, result(False))
        LIVE.write_report(self.directory, result(False))
        names = sorted(path.name for path in self.directory.iterdir())
        self.assertEqual(names, ["README.md", "verdict-1.json", "verdict-2.json", "verdict.json"])
        self.assertEqual(json.loads((self.directory / "verdict.json").read_text())["attempt"], 2)
        self.assertIn("Not verified:", (self.directory / "README.md").read_text())

    def test_reports_stay_under_50_kb(self):
        value = result()
        value["leakWindows"] = [dict(role="armedTrial", offendingObservations=[dict(note="x" * 200, n=n) for n in range(400)])]
        LIVE.write_report(self.directory, value)
        written = json.loads((self.directory / "verdict.json").read_text())
        self.assertLess((self.directory / "verdict.json").stat().st_size, 50000)
        self.assertEqual(written["leakWindows"][0]["offendingObservationCount"], 400)
        self.assertEqual(len(written["leakWindows"][0]["offendingObservations"]), 4)


class FakeSession:
    def __init__(self):
        self.ledger, self.cleanups, self.quits = [], [], 0
        self.stage = "/Users/tester/lab/verdict-lab-test"

    def quit_app(self):
        self.quits += 1


class Scripted(LIVE.Rehearsal):
    """Scenario steps, supplement actions and status reads answer from scripts; every call is recorded."""

    def __init__(self, scenarios=None, sups=None, statuses=()):
        super().__init__(FakeSession(), "macos26-wgex")
        self.profile = PROFILE
        self.scenarios, self.sups, self.statuses, self.calls = dict(scenarios or {}), dict(sups or {}), list(statuses), []

    def scenario(self, step, check=True):
        codes = self.scenarios.get(step, [0])
        code = codes.pop(0) if len(codes) > 1 else codes[0]
        self.calls.append(("scenario", step, code))
        if check and code:
            raise LIVE.StepFailure(f"scenario step {step} exited {code}")
        return code, b""

    def sup(self, action, *args, check=True):
        self.calls.append(("sup", action))
        answers = self.sups.get(action, [""])
        return answers.pop(0) if len(answers) > 1 else answers[0]

    def status(self):
        return self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]

    def unrelated_check(self, after):
        self.calls.append(("unrelated", after))

    def boot_session(self):
        self.calls.append(("boot",))
        return f"{len([c for c in self.calls if c == ('boot',)]):08d}-0000-4000-8000-000000000000"


PENDING = status(phase="failed", cutoverRollbackFailures=["deleteSecrets", "deleteSecrets"], recoveryFailureReason="reconciliationFailed")


class FailedStopTests(unittest.TestCase):
    def test_a_blocked_rollback_stays_pending_and_the_retry_completes_it(self):
        rehearsal = Scripted(scenarios={"abort-attempt": [12, 0]},
                             sups={"journal-cutover": ["rollbackPending=true reason=aborted", "rollbackPending=false reason=aborted"]},
                             statuses=[PENDING, status(cutoverRollbackFailures=["deleteSecrets", "deleteSecrets"])])
        rehearsal.run_check("failedStopRetry", rehearsal.failed_stop_retry)
        self.assertTrue(rehearsal.checks["failedStopRetry"]["met"], rehearsal.checks["failedStopRetry"])
        steps = [call[1] for call in rehearsal.calls if call[0] in ("scenario", "sup")]
        self.assertEqual(steps, ["start", "secrets-lock", "abort-attempt", "journal-cutover", "secrets-unlock", "abort-attempt", "assert-aborted",
                                 "journal-cutover"])
        self.assertNotIn("abort", steps, "the retry never re-remembers: the unrelated reference would be the sole pfctl row")

    def test_a_lock_that_does_not_fail_the_rollback_is_not_a_failed_stop(self):
        rehearsal = Scripted(scenarios={"abort-attempt": [0]}, sups={"journal-cutover": ["rollbackPending=false reason=aborted"]},
                             statuses=[status()])
        rehearsal.run_check("failedStopRetry", rehearsal.failed_stop_retry)
        self.assertFalse(rehearsal.checks["failedStopRetry"]["met"])
        self.assertIn("did not stay pending", rehearsal.gaps[0])
        # Recovery after a failed check: the flag is cleared and one abort is attempted.
        self.assertEqual(rehearsal.calls[-2:], [("sup", "secrets-unlock"), ("scenario", "abort-attempt", 0)])

    def test_a_retry_that_fails_again_fails_the_check(self):
        rehearsal = Scripted(scenarios={"abort-attempt": [12, 12]}, sups={"journal-cutover": ["rollbackPending=true reason=aborted"]},
                             statuses=[PENDING])
        rehearsal.run_check("failedStopRetry", rehearsal.failed_stop_retry)
        self.assertFalse(rehearsal.checks["failedStopRetry"]["met"])
        self.assertIn("retried abort exited 12", rehearsal.gaps[0])

    def test_restart_during_rollback_needs_the_startup_to_finish_it(self):
        rehearsal = Scripted(scenarios={"abort-attempt": [12]},
                             sups={"journal-cutover": ["rollbackPending=true reason=aborted", "rollbackPending=false reason=aborted"]},
                             statuses=[status(cutoverRollbackFailures=["deleteSecrets", "deleteSecrets"])])
        rehearsal.run_check("restartDuringRollback", rehearsal.restart_during_rollback)
        self.assertTrue(rehearsal.checks["restartDuringRollback"]["met"], rehearsal.checks["restartDuringRollback"])
        steps = [call[1] for call in rehearsal.calls if call[0] in ("scenario", "sup")]
        self.assertLess(steps.index("restart-daemon"), steps.index("settle-aborted"))
        self.assertEqual(steps.count("abort-attempt"), 1, "no second abort: the restarted daemon completes the rollback")


class AppAndRebootTests(unittest.TestCase):
    def test_app_absent_refuses_and_present_arms(self):
        armed = status(phase="active", protection="protected", activeProfileID=PROFILE, cutover=dict(state="armed"))
        refused = status(cutover=dict(state="rolledBack", reason="aborted"))
        rehearsal = Scripted(scenarios={"start": [3, 0]}, sups={"app-state": ["app=absent", "app=running"], "bundle-state": ["bundle=absent"]},
                             statuses=[refused, armed, status()])
        rehearsal.run_check("appAbsentAndPresent", rehearsal.app_absent_and_present)
        self.assertTrue(rehearsal.checks["appAbsentAndPresent"]["met"], rehearsal.checks["appAbsentAndPresent"])
        self.assertEqual(rehearsal.session.quits, 2)

    def test_a_start_that_arms_without_the_app_fails_the_check(self):
        armed = status(phase="active", protection="protected", activeProfileID=PROFILE, cutover=dict(state="armed"))
        rehearsal = Scripted(scenarios={"start": [0]}, sups={"app-state": ["app=absent"], "bundle-state": ["bundle=present"]}, statuses=[armed])
        rehearsal.run_check("appAbsentAndPresent", rehearsal.app_absent_and_present)
        self.assertFalse(rehearsal.checks["appAbsentAndPresent"]["met"])

    def test_the_armed_reboot_is_judged_on_the_post_boot_daemon(self):
        rehearsal = Scripted(statuses=[status(cutover=dict(state="rolledBack", reason="daemonRestart"))])
        rehearsal.after_reboot = lambda before: None
        rehearsal.ensure_app = lambda: None
        LIVE.time.sleep, sleep = (lambda seconds: None), LIVE.time.sleep
        try:
            rehearsal.run_check("rebootWhileArmedRollback", rehearsal.armed_reboot)
            self.assertTrue(rehearsal.checks["rebootWhileArmedRollback"]["met"])
            self.assertTrue(rehearsal.checks["rebootWindowUnprotectedRecoveryNotBlocked"]["met"])
            blocked = status(phase="failed", protection="blocked", policyEnforcing=True, cutover=dict(state="rolledBack", reason="daemonRestart"))
            rehearsal = Scripted(statuses=[blocked, status(cutover=dict(state="rolledBack", reason="daemonRestart"))])
            rehearsal.after_reboot = lambda before: None
            rehearsal.ensure_app = lambda: None
            rehearsal.run_check("rebootWhileArmedRollback", rehearsal.armed_reboot)
            self.assertTrue(rehearsal.checks["rebootWhileArmedRollback"]["met"], "the final state is rolled back")
            self.assertFalse(rehearsal.checks["rebootWindowUnprotectedRecoveryNotBlocked"]["met"], "but one post-boot sample was blocked")
        finally:
            LIVE.time.sleep = sleep

    def test_an_unchanged_boot_session_is_not_a_reboot(self):
        rehearsal = Scripted()
        rehearsal.boot_session = lambda: "SAME"
        with self.assertRaisesRegex(LIVE.StepFailure, "did not reboot"):
            rehearsal.after_reboot("SAME")


class UnrelatedTests(unittest.TestCase):
    def test_every_rollback_must_keep_the_fixtures(self):
        rehearsal = Scripted()
        rehearsal.unrelated = [dict(after="expiry", fixtures="unrelated route=present reference=present", foreignClientRoutes=True, met=True),
                               dict(after="abort", fixtures="unrelated route=absent reference=present", foreignClientRoutes=True, met=False)]
        rehearsal.run_check("unrelatedRoutesAndReferencesPreserved", rehearsal.unrelated_preserved)
        self.assertFalse(rehearsal.checks["unrelatedRoutesAndReferencesPreserved"]["met"])
        self.assertIn("abort: unrelated route=absent", rehearsal.gaps[0])
        rehearsal = Scripted()
        rehearsal.unrelated = []
        rehearsal.run_check("unrelatedRoutesAndReferencesPreserved", rehearsal.unrelated_preserved)
        self.assertFalse(rehearsal.checks["unrelatedRoutesAndReferencesPreserved"]["met"], "no observation is no pass")


class EntryPointTests(unittest.TestCase):
    def run_script(self, *args, env=None):
        environment = {k: v for k, v in os.environ.items() if not k.startswith("WGEX_")}
        environment.update(env or {})
        return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, check=False, cwd=ROOT, env=environment)

    def test_report_root_needs_a_directory_and_a_lab_guest(self):
        for args in (["--report-root"], ["--report-root", "/tmp/x"], ["--report-root", "/tmp/x", "macos26-wgex", "extra"]):
            result = self.run_script(*args)
            self.assertEqual(result.returncode, 2, args)
            self.assertIn(b"usage: cutover-rehearsal.sh --report-root DIR GUEST", result.stderr)
        for guest in ("macos13-agent", "macos26-wgex;id", "../macos26-wgex"):
            result = self.run_script("--report-root", "/tmp/x", guest)
            self.assertEqual(result.returncode, 2, guest)
            self.assertIn(b"GUEST must be", result.stderr)

    def test_live_entry_refuses_mock_injection(self):
        result = self.run_script("--report-root", "/tmp/x", "macos26-wgex", env=dict(WGEX_LAB_TEST_BIN="/tmp"))
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"mock injection requires --dry-run", result.stderr)

    def test_scenario_steps_are_a_closed_set(self):
        result = self.run_script("--scenario", "reboot-host", PROFILE)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"unknown scenario step: reboot-host", result.stderr)
        result = self.run_script("--scenario", "abort")
        self.assertIn(b"usage: cutover-rehearsal.sh --scenario STEP PROFILE-UUID", result.stderr)
        result = self.run_script()
        self.assertIn(b"usage: cutover-rehearsal.sh --report-root DIR GUEST | --scenario STEP PROFILE-UUID | --dry-run", result.stderr)
        result = self.run_script("--dry-run", PROFILE)
        self.assertIn(b"usage: cutover-rehearsal.sh --dry-run", result.stderr)

    def test_the_live_driver_reads_the_guest_from_the_entry_point(self):
        text = SCRIPT.read_text()
        self.assertIn('WGEX_LAB_VM="$3" exec python3 -I -B "$base/cutover-live.py" --report-root "$2"', text)


if __name__ == "__main__":
    unittest.main()
