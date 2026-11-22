# SPDX-License-Identifier: MIT
"""M03-T10: the macos27-ready snapshot driver offline: environment guard, doctor and preference reads, and main() run
through fake lab modules (REV-M03-T10 item 2): snapshot taken, failure before the snapshot, teardown on both paths."""
import argparse
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "Tools/lab/ready-snapshot.py"
spec = importlib.util.spec_from_file_location("ready_snapshot_under_test", SCRIPT)
READY = importlib.util.module_from_spec(spec)
spec.loader.exec_module(READY)
GOOD = dict(WGEX_LAB_VM="macos27-wgex", WGEX_LAB_USER="admin", WGEX_LAB_SNAPSHOT_PREFIX="macos27-")


class Failure(Exception):
    pass


class RowFailure(RuntimeError):
    pass


class FakeSession:
    """Records every `just lab` and guest command; `fail` maps a lab subcommand to the error it raises."""

    def __init__(self, fail=None):
        self.calls, self.cleanups, self.fail = [], [], dict(fail or {})
        self.stage, self.output, self.provenance = "/tmp/stage", Path("/tmp/fake-output"), dict(guestOS="27.0")
        self.cleaned = False

    def lab(self, *args, **kw):
        self.calls.append(("lab",) + args)
        if args[0] in self.fail:
            raise self.fail[args[0]]
        return b"wrapping key provisioned and escrowed\n"

    def ssh(self, command, **kw):
        self.calls.append(("ssh", command))
        if command.startswith("csrutil"):
            return b"System Integrity Protection status: disabled.\n"
        if command.startswith("date"):
            return b"2026-01-01 00:00:00\n"
        if command.startswith("cat "):
            return b'{"onboardingComplete":true}'
        if "secure-install-status" in command:
            return b'{"secureInstall":"verified"}\n'
        return b""

    def await_guest(self):
        self.calls.append(("await",))

    def guest_file(self, data, name):
        self.calls.append(("file", name))

    def measure_provenance(self):
        self.calls.append(("provenance",))

    def cleanup(self):
        # Session.cleanup's contract: registered operations in reverse order, then the step ledger.
        for operation in reversed(self.cleanups):
            operation()
        self.cleaned = True
        return []

    def labs(self):
        return [call[1:] for call in self.calls if call[0] == "lab"]


class FakeProbe:
    def __init__(self, session, live):
        self.session, self.approval, self.console_step, self.start_clock = session, dict(item="WGEX"), None, None

    def stage(self):
        self.session.calls.append(("stage",))

    def read_right(self):
        # No right in the base; the daemon writes it once the app is installed.
        return dict(identifier="com.magrathean.wgex.daemon") if ("lab", "install") in self.session.calls else None

    def wait(self, what, seconds, probe, interval=2):
        return probe()

    def try_press(self, identifier):
        return True

    def press(self, identifier, window="1"):
        self.session.calls.append(("press", identifier))

    def approve_background_item(self):
        self.session.calls.append(("approve",))

    def daemon_running(self):
        return "pid 42"


def run_main(session, out, *extra):
    live = types.SimpleNamespace(Session=lambda name, controls: session, RowFailure=RowFailure, GUEST_USER="admin",
                                 wrapping_key_outcome=lambda text: "provisioned and escrowed")
    auth = types.SimpleNamespace(AuthReal=FakeProbe, Failure=Failure)
    modules = {"ready_snapshot_live": live, "ready_snapshot_auth": auth}
    stdout = mock.patch.object(READY.sys, "stdout", new_callable=lambda: __import__("io").StringIO())
    with mock.patch.dict(os.environ, GOOD), mock.patch.object(READY, "load_module", lambda name, path: modules[name]), \
            stdout as written:
        code = READY.main(["--out", str(out), *extra])
    record = __import__("json").loads((out / "ready-snapshot.json").read_text())
    return code, record, written.getvalue()


class Orchestration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name) / "out"

    def test_snapshot_taken_then_guest_stopped(self):
        session = FakeSession()
        code, record, written = run_main(session, self.out)
        self.assertEqual(code, 0, written)
        labs = session.labs()
        self.assertEqual(labs[0], ("restore", "base"))
        self.assertIn(("snapshot", "ready"), labs)
        # snapshot.sh restarts the guest after the clone: the run's last lab command stops it.
        self.assertEqual(labs[-1], ("down",))
        self.assertLess(labs.index(("snapshot", "ready")), labs.index(("down",)))
        self.assertTrue(session.cleaned)
        self.assertTrue(record["snapshotTaken"])
        self.assertTrue(record["guestStopped"])
        self.assertNotIn("teardownFailed", record)
        self.assertEqual([step["step"] for step in record["steps"]][-1], "snapshot")
        self.assertEqual(written.strip(), "macos27-ready taken")

    def test_given_snapshot_name_is_taken_and_reported(self):
        session = FakeSession()
        code, record, written = run_main(session, self.out, "--snapshot", "ready-final")
        self.assertEqual(code, 0, written)
        labs = session.labs()
        self.assertEqual(labs[0], ("restore", "base"))
        self.assertIn(("snapshot", "ready-final"), labs)
        self.assertNotIn(("snapshot", "ready"), labs)
        self.assertEqual(labs[-1], ("down",))
        self.assertEqual(record["snapshot"], "macos27-ready-final")
        self.assertEqual(record["steps"][-1]["snapshot"], "macos27-ready-final")
        self.assertEqual(written.strip(), "macos27-ready-final taken")

    def test_default_snapshot_name_is_ready(self):
        session = FakeSession()
        code, record, written = run_main(session, self.out)
        self.assertEqual(code, 0, written)
        self.assertEqual(record["snapshot"], "macos27-ready")
        self.assertEqual(record["steps"][-1]["snapshot"], "macos27-ready")

    def test_failure_names_the_given_snapshot(self):
        session = FakeSession(fail={"build": RuntimeError("x")})
        code, record, written = run_main(session, self.out, "--snapshot", "ready2")
        self.assertEqual(code, 1)
        self.assertIn("macos27-ready2 NOT taken", written)
        self.assertNotIn(("snapshot", "ready2"), session.labs())

    def test_failure_before_snapshot_still_stops_the_guest(self):
        session = FakeSession(fail={"build": RuntimeError("command failed: xcodebuild; inspect step ledger")})
        code, record, written = run_main(session, self.out)
        self.assertEqual(code, 1)
        labs = session.labs()
        self.assertNotIn(("snapshot", "ready"), labs)
        self.assertEqual(labs[-1], ("down",))
        self.assertFalse(record["snapshotTaken"])
        self.assertTrue(record["guestStopped"])
        self.assertEqual(record["stopped"], "RuntimeError: see steps.json")
        self.assertIn("NOT taken", written)
        self.assertNotIn("guest NOT stopped", written)

    def test_driver_failure_is_reported_and_guest_stopped(self):
        session = FakeSession()
        with mock.patch.object(FakeProbe, "read_right", lambda self: dict(identifier="leftover")):
            code, record, written = run_main(session, self.out)
        self.assertEqual(code, 1)
        self.assertIn("not clean", record["stopped"])
        self.assertEqual(session.labs()[-1], ("down",))
        self.assertTrue(record["guestStopped"])

    def test_teardown_failure_after_snapshot_fails_the_run(self):
        session = FakeSession(fail={"down": RuntimeError("command failed: guest did not stop; inspect step ledger")})
        code, record, written = run_main(session, self.out)
        self.assertEqual(code, 1)
        self.assertTrue(record["snapshotTaken"])
        self.assertFalse(record["guestStopped"])
        self.assertIn("guest did not stop", record["teardownFailed"])
        self.assertIn("macos27-ready taken; guest NOT stopped", written)
        self.assertTrue(session.cleaned)

    def test_teardown_failure_keeps_the_run_failure(self):
        session = FakeSession(fail={"install": OSError("no route"), "down": OSError("tart missing")})
        code, record, written = run_main(session, self.out)
        self.assertEqual(code, 1)
        self.assertEqual(record["stopped"], "OSError: see steps.json")
        self.assertFalse(record["guestStopped"])
        self.assertEqual(record["teardownFailed"], "tart missing")
        self.assertIn("NOT taken: OSError", written)
        self.assertIn("guest NOT stopped: tart missing", written)

    def test_unexpected_error_still_stops_the_guest(self):
        session = FakeSession(fail={"restore": KeyboardInterrupt()})
        with self.assertRaises(KeyboardInterrupt):
            run_main(session, self.out)
        self.assertEqual(session.labs(), [("restore", "base"), ("down",)])


class Environment(unittest.TestCase):
    def test_macos27_parameters_pass(self):
        READY.check_environment(GOOD)

    def test_each_wrong_or_missing_parameter_refuses(self):
        for key in GOOD:
            for value in (None, "macos26-wgex", "labuser", "macos26-"):
                environ = dict(GOOD)
                if value is None:
                    del environ[key]
                else:
                    environ[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(SystemExit):
                    READY.check_environment(environ)

    def test_the_script_refuses_before_any_guest_contact(self):
        env = {key: value for key, value in os.environ.items() if not key.startswith("WGEX_")}
        env.update(WGEX_LAB_VM="macos26-wgex", WGEX_LAB_USER="labuser")
        done = subprocess.run([sys.executable, "-I", "-B", str(SCRIPT), "--out", "/tmp/ready-snapshot-test"], env=env,
                              capture_output=True, timeout=60, check=False)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn(b"WGEX_LAB_VM=macos27-wgex", done.stderr)
        self.assertFalse(Path("/tmp/ready-snapshot-test").exists())


class SnapshotName(unittest.TestCase):
    def test_valid_names(self):
        for name in ("ready", "ready2", "R1", "a_b-c", "9x"):
            with self.subTest(name=name):
                self.assertEqual(READY.snapshot_name(name), name)

    def test_invalid_and_reserved_names_refuse(self):
        for name in ("", "-x", "_x", "a b", "a/b", "../x", "a.b", "x;y", "a\n", "base", "wgex"):
            with self.subTest(name=name), self.assertRaises(argparse.ArgumentTypeError):
                READY.snapshot_name(name)

    def test_the_script_refuses_a_bad_name_before_any_guest_contact(self):
        env = {key: value for key, value in os.environ.items() if not key.startswith("WGEX_")}
        env.update(GOOD)
        for name in ("../foreign", "base"):
            with self.subTest(name=name):
                done = subprocess.run([sys.executable, "-I", "-B", str(SCRIPT), "--out", "/tmp/ready-snapshot-test", "--snapshot", name],
                                      env=env, capture_output=True, timeout=60, check=False)
                self.assertEqual(done.returncode, 2)
                self.assertIn(b"--snapshot", done.stderr)
                self.assertFalse(Path("/tmp/ready-snapshot-test").exists())


class Steps(unittest.TestCase):
    def test_every_step_call_in_the_driver_records(self):
        # Live run 1 stopped after the snapshot on step("snapshot", name=...), a clash with step's own parameter.
        ready = READY.Ready.__new__(READY.Ready)
        ready.record = dict(steps=[])
        for match in re.finditer(r'self\.step\("([^"]+)"((?:, \w+=)[^)]*)?\)', SCRIPT.read_text()):
            keys = re.findall(r", (\w+)=", match[2] or "")
            ready.step(match[1], **dict.fromkeys(keys, "x"))
        self.assertGreaterEqual(len(ready.record["steps"]), 5)


class Reads(unittest.TestCase):
    def test_secure_install_state(self):
        self.assertEqual(READY.secure_install_state('noise\n{"daemonReachable":true,"secureInstall":"verified"}\n'), "verified")
        self.assertEqual(READY.secure_install_state('{"secureInstall":"needsAttention(wrappingKeyUnavailable)"}'),
                         "needsAttention(wrappingKeyUnavailable)")
        for text in ("", "not json", "[]", '{"secureInstall":3}', "{}"):
            with self.subTest(text=text):
                self.assertEqual(READY.secure_install_state(text), "unreadable")

    def test_onboarding_complete(self):
        self.assertTrue(READY.onboarding_complete('{"onboardingComplete":true,"x":1}'))
        for text in ("", "{}", '{"onboardingComplete":false}', '{"onboardingComplete":"true"}', "[]", "cat: no such file"):
            with self.subTest(text=text):
                self.assertFalse(READY.onboarding_complete(text))


if __name__ == "__main__":
    unittest.main()
