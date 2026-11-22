# SPDX-License-Identifier: MIT
"""First live-run regressions, replayed without VM commands or secret values."""
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch

import test_live_replay as replay

LIVE, RecordedRunner, ROOT, module = replay.LIVE, replay.RecordedRunner, replay.ROOT, replay.module


def catalogue_with_dependency(runner, row):
    """Inject an unmet dependency into one fixture row without changing the source catalogue."""
    read = runner.read

    def reader(path, hashes, label):
        value = read(path, hashes, label)
        if label == "catalogue":
            value["rows"][row].setdefault("dependencies", {})["fixturePrerequisite"] = "Fixture prerequisite remains unmet"
        return value
    return patch.object(runner, "read", side_effect=reader)


class PrepareTests(unittest.TestCase):
    def test_install_refresh_import_and_short_probe_deadlines(self):
        runner, result = replay.LiveReplayTests().run_recorded("M5.1-04")
        commands = [" ".join(c) for c in runner.commands]
        ordered = ["lab restore ready", "lab build", "lab install", "verdict-actions.sh refresh-install", "lab profile full4"]
        indices = [next(i for i, c in enumerate(commands) if text in c) for text in ordered]
        self.assertEqual(indices, sorted(indices))
        path = "/Users/" + LIVE.GUEST_USER + "/lab/wgex-lab-full4.conf"
        self.assertTrue(any("open -a WGEX " + path in c for c in commands))
        self.assertFalse(any('keystroke "i"' in c or 'keystroke "g"' in c for c in commands))
        self.assertTrue(result["prepareCompleted"] and result["rowCompleted"])
        self.assertEqual(result["installation"]["mode"], "build-and-install")
        self.assertTrue(all(result["installation"][key] for key in ["buildCompleted", "installCompleted", "daemonRefreshed"]))
        for command, env in zip(runner.commands, runner.environments):
            if command[:4] == ["just", "lab", "ssh", "--"]:
                # Harness deadlines (M1-10i) come from harness-deadlines.sh through LIVE.HARNESS.
                if command[-1].endswith(" status --json"):
                    self.assertLessEqual(int(env["WGEX_LAB_SSH_DEADLINE"]), LIVE.HARNESS.seconds("SSH_COMMAND"))
                    continue
                # M1-10m: a guest-load reading is bounded by what is left of the settle, never the SSH default.
                if command[-1].endswith("verdict-actions.sh guest-load"):
                    self.assertLessEqual(int(env["WGEX_LAB_SSH_DEADLINE"]), LIVE.HARNESS.seconds("GUEST_SETTLE"))
                    continue
                expected = str(600 if "verdict-actions.sh observe" in command[-1] else LIVE.HARNESS.seconds("READINESS_ATTEMPT")
                               if command[-1] == "true" else LIVE.HARNESS.seconds("SSH_COMMAND"))
                self.assertEqual(env["WGEX_LAB_SSH_DEADLINE"], expected)

    def test_owner_asserted_snapshot_skips_build_install_and_refresh(self):
        runner, result = replay.LiveReplayTests().run_recorded("M5.1-04", no_install=True)
        commands = [" ".join(c) for c in runner.commands]
        self.assertFalse(any("lab build" in c or "lab install" in c or "refresh-install" in c for c in commands))
        self.assertTrue(any("lab profile full4" in c for c in commands))
        self.assertEqual(result["installation"]["mode"], "snapshot-owner-asserted")

    def test_installed_binary_mismatch_refuses_both_install_and_snapshot_modes(self):
        class DifferentInstalledCLI(RecordedRunner):
            def run(self, argv, **kwargs):
                result = super().run(argv, **kwargs)
                if "sw_vers -productVersion; sw_vers -buildVersion" in argv[-1]:
                    result.stdout = result.stdout.replace(("d" * 40).encode(), ("e" * 40).encode())
                return result
        for no_install in (False, True):
            _, result = replay.LiveReplayTests().run_recorded("M5.1-04", DifferentInstalledCLI(), accepted=False, no_install=no_install)
            self.assertFalse(result["prepareCompleted"] or result["rowCompleted"])
            self.assertTrue(any("installedArtefactsMismatch" in gap for gap in result["gaps"]))
            self.assertNotEqual(result["artefacts"], result["installed"])

    def test_control_identifiers_are_exact_and_independent_of_labels(self):
        dump = 'AXButton | name=changed label | desc= | id=wgex.main.sidebarImport | pos=10,20 size=40x20 en=true\n'
        self.assertEqual(LIVE.control_position(dump, None, {}, "wgex.main.sidebarImport"), (30,30))
        with self.assertRaises(ValueError):
            LIVE.control_position(dump.replace("sidebarImport", "sidebarImportExtra"), None, {}, "wgex.main.sidebarImport")
        source = (ROOT / "Packages/WGEXUI/Sources/WGEXUI/Presentation/WGEXAccessibility.swift").read_text()
        for identifier in ["wgex.main.sidebarImport", "wgex.importReview.importAndConnect", "wgex.importReview.importLabel"]:
            self.assertIn('"' + identifier + '"', source)

    def test_existing_import_is_replaced_before_import_and_connect(self):
        runner = RecordedRunner()
        runner.review_delay = 2
        runner.fixture["controls"].extend([
            ["Duplicate", "wgex.importReview.duplicate", 60, 10],
            ["Replace", "", 70, 10],
        ])
        runner, _ = replay.LiveReplayTests().run_recorded("M5.1-04", runner)
        clicks = replay.actuations(runner.commands)
        self.assertLess(clicks.index(["80", "20"]), clicks.index(["35", "20"]))

    def test_refresh_install_requires_guest_guard_before_privileged_steps(self):
        source = (ROOT / "Tools/lab/tart/guest/verdict-actions.sh").read_text()
        self.assertLess(source.index("guest_guard"), source.index("sudo -n chown -R root:wheel"))
        self.assertIn('sudo -n launchctl kickstart -k "system/$label"', source)
        self.assertIn('WGEXApp(\\.dev)?\\.daemon', source)

    def test_failed_prepare_has_actionable_stderr_and_no_completed_row(self):
        runner = RecordedRunner()
        runner.fail_prepare = True
        _, result = replay.LiveReplayTests().run_recorded("M5.1-04", runner, accepted=False)
        self.assertFalse(result["prepareCompleted"] or result["rowCompleted"])
        ledger = json.loads((Path(result["buildRoot"]) / "steps.json").read_text())
        failed = next(step for step in ledger if step.get("exitCode") == 1)
        self.assertIn("peer up --adopt", failed["stderr"])

    def test_stderr_is_bounded_and_credential_lines_are_redacted(self):
        public = next(line.strip() for line in (ROOT / "Tests/Fixtures/keys/client1.pub").read_text().splitlines() if line and not line.startswith("#"))
        runner = Mock()
        runner.now.return_value = 1
        runner.run.return_value = subprocess.CompletedProcess([], 1, b"", ("peer: ownership missing\nPrivateKey = <omitted>\n" + public + "\n" + "x" * 6000).encode())
        session = LIVE.Session("fixture", {}, runner=runner)
        with self.assertRaises(RuntimeError):
            session.command(["fixture"])
        stderr = session.ledger[-1]["stderr"]
        self.assertIn("ownership missing", stderr)
        self.assertTrue(public not in stderr, "encoded credential pattern must be removed")
        self.assertNotIn("PrivateKey", stderr)
        self.assertLessEqual(len(stderr.encode()), 4096)

    def test_failed_prepare_cannot_publish_even_with_a_source_report_root(self):
        runner = module("failed_prepare_report", "verdict-run.py")
        live = Mock()
        live.run.return_value = dict(states=[], prepareCompleted=False, rowCompleted=False, expectationsMet=False)
        with patch.object(runner, "load_module", return_value=live), patch.object(runner, "write_report") as writer:
            self.assertEqual(runner.main(["IPERF3", "--report-root", str(ROOT / "Tests/Reports/M1/M1-10")]), 1)
        live.run.assert_called_once()
        self.assertEqual(writer.call_args.args[1]["dependencies"], {})
        destination = writer.call_args.args[0]
        self.assertNotIn(ROOT, destination.parents)

    def test_completed_failure_can_publish_and_no_install_is_forwarded(self):
        runner = module("completed_report", "verdict-run.py")
        live = Mock()
        live.run.return_value = dict(states=[dict(verdict="unprotected")], rowCompleted=True, prepareCompleted=True, expectationsMet=False)
        with patch.object(runner, "load_module", return_value=live), patch.object(runner, "write_report") as writer:
            self.assertEqual(runner.main(["IPERF3", "--no-install"]), 1)
        live.run.assert_called_once()
        self.assertEqual(writer.call_args.args[1]["dependencies"], {})
        self.assertTrue(writer.call_args.kwargs["keep_attempts"], "completed failures keep every attempt")
        self.assertEqual(writer.call_args.args[0], ROOT / "Tests/Reports/M1/M1-10/IPERF3")
        self.assertTrue(live.run.call_args.kwargs["no_install"])

    def test_manual_command_default_is_600_and_override_survives(self):
        library = str(ROOT / "Tools/lab/tart/lib.sh")
        for override, expected in [(None, b"600"), ("200", b"200")]:
            env = dict(os.environ)
            env.pop("WGEX_LAB_SSH_DEADLINE", None)
            if override:
                env["WGEX_LAB_SSH_DEADLINE"] = override
            result = subprocess.run(["bash", "-c", 'source "$1"; printf %s "$LAB_DEADLINE"', "fixture", library], env=env, capture_output=True, check=True)
            self.assertEqual(result.stdout, expected)
