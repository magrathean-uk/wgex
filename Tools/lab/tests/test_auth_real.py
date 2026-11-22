# SPDX-License-Identifier: MIT
"""M03-T11 AUTH-REAL: the recorded rightDefinition against the M01-T02 read-back fixture, and the driver's offline parts."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
LAB = ROOT / "Tools/lab"
RIGHT = "com.magrathean.WGEXApp.manage-protection.dev"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


AUTH = load("auth_real_under_test", LAB / "auth-real.py")


class Differences(unittest.TestCase):
    def setUp(self):
        self.fixture = AUTH.fixture_right()

    def test_fixture_shape(self):
        self.assertEqual(AUTH.COMPARED_KEYS, ("class", "rule", "shared", "timeout"))
        self.assertEqual(self.fixture["class"], "rule")
        self.assertEqual(self.fixture["rule"], ["authenticate-admin-nonshared"])
        self.assertNotIn("shared", self.fixture)
        self.assertNotIn("timeout", self.fixture)

    def test_equal_and_metadata_ignored(self):
        observed = dict(self.fixture, created=1.0, modified=2.0, identifier="other", requirement="cdhash H\"1\"", comment="x", version=3)
        self.assertEqual(AUTH.right_differences(observed, self.fixture), [])

    def test_each_compared_key_differs(self):
        cases = [("class", "user"), ("rule", ["authenticate-admin"]), ("rule", "authenticate-admin-nonshared"),
                 ("shared", False), ("shared", True), ("timeout", 30), ("timeout", 0)]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                differences = AUTH.right_differences(dict(self.fixture, **{key: value}), self.fixture)
                self.assertEqual([item["key"] for item in differences], [key])
                self.assertEqual(differences[0]["observed"], value)

    def test_missing_key_differs(self):
        for key in ("class", "rule"):
            observed = {name: value for name, value in self.fixture.items() if name != key}
            self.assertEqual(AUTH.right_differences(observed, self.fixture), [dict(key=key, fixture=self.fixture[key], observed="absent")])

    def test_not_an_object(self):
        self.assertEqual(AUTH.right_differences(None, self.fixture)[0]["key"], "rightDefinition")
        self.assertEqual(AUTH.right_differences([], self.fixture)[0]["key"], "rightDefinition")


AUTHD = """\
2026-11-10 15:07:30.001 Df authd[208:13ee] [com.apple.Authorization:authd] Succeeded authorizing right 'config.add.{right}' by client '/Applications/WGEX.app/Contents/MacOS/WGEXDaemon' [700] for authorization created by '/Applications/WGEX.app/Contents/MacOS/WGEXDaemon' [700] (100002,0) (engine 20)
2026-11-10 15:07:33.612 Df authd[208:13ee] [com.apple.Authorization:authd] Validating shared credential admin (501) for {right} (engine 25)
2026-11-10 15:07:33.612 Df authd[208:13ee] [com.apple.Authorization:authd] Shared credential 501 (does NOT satisfy rule) (engine 25)
2026-11-10 15:07:33.613 Df authd[208:13ee] [com.apple.Authorization:authd] session owner 501 is member of group admin (does satisfy rule) (engine 25)
2026-11-10 15:07:33.700 Df authd[208:13ee] [com.apple.Authorization:authd] engine 25: some other phrase with a value 1234
2026-11-10 15:07:33.950 Df authd[208:13ee] [com.apple.Authorization:authd] engine 25: running mechanism builtin:authenticate (1 of 3)
2026-11-10 15:07:34.000 Df authd[208:474] [com.apple.xpc:connection] [0x74af0e1f40] invalidated because the client process (pid 291) either cancelled the connection or exited
2026-11-10 15:07:35.950 Df authd[208:13ee] [com.apple.Authorization:authd] engine 26: running mechanism builtin:authenticate (1 of 3)
2026-11-10 15:07:35.951 Df authd[208:13ee] [com.apple.Authorization:authd] Validating shared credential admin (501) for system.preferences (engine 26)
2026-11-10 15:08:17.133 E  authd[208:13ee] [com.apple.Authorization:authd] Evaluate cancelled or failed -60006 (engine 25)
2026-11-10 15:08:17.133 Df authd[208:13ee] [com.apple.Authorization:authd] Failed to authorize right '{right}' by client '/Applications/WGEX.app/Contents/MacOS/WGEX' [928] for authorization created by '/Applications/WGEX.app/Contents/MacOS/WGEX' [928] (3,0) (-60006) (engine 25)
"""


class AuthdLines(unittest.TestCase):
    """The guest filter keeps only allowlisted authd phrases of the engines that named the WGEX right."""

    def filter(self, text, right=RIGHT):
        return subprocess.run(["perl", str(LAB / "tart/guest/authd-lines.pl"), right], input=text.encode(),
                              capture_output=True, timeout=30, check=False)

    def test_keeps_the_right_engines_allowlisted_lines(self):
        result = self.filter(AUTHD.format(right=RIGHT))
        self.assertEqual(result.returncode, 0)
        lines = result.stdout.decode().splitlines()
        self.assertEqual(lines[-1], "authd-lines: kept=7 engines=20,25")
        kept = "\n".join(lines[:-1])
        self.assertIn("config.add." + RIGHT, kept)
        self.assertIn("engine 25: running mechanism builtin:authenticate (1 of 3)", kept)
        self.assertIn("(-60006) (engine 25)", kept)
        self.assertNotIn("other phrase", kept)
        self.assertNotIn("engine 26", kept)
        self.assertNotIn("xpc", kept)
        self.assertNotIn("Df authd", kept)

    def test_other_right_selects_nothing(self):
        result = self.filter(AUTHD.format(right="system.preferences.security"))
        self.assertEqual(result.stdout.decode().splitlines(), ["authd-lines: kept=0 engines="])

    def test_refuses_another_right(self):
        for right in ("system.preferences", RIGHT + "x", "com.magrathean.WGEXApp.manage-protection.devx"):
            with self.subTest(right=right):
                self.assertNotEqual(self.filter(AUTHD.format(right=RIGHT), right).returncode, 0)

    def test_at_most_forty_lines(self):
        line = ("2026-11-10 15:07:33.{:03d} Df authd[208:13ee] [com.apple.Authorization:authd] Validating shared credential admin "
                f"(501) for {RIGHT} (engine 25)\n")
        lines = self.filter("".join(line.format(index) for index in range(60))).stdout.decode().splitlines()
        self.assertEqual(len(lines), 41)
        self.assertEqual(lines[-1], "authd-lines: kept=40 engines=25")

    def test_sheet_evidence(self):
        lines = self.filter(AUTHD.format(right=RIGHT)).stdout.decode().splitlines()
        engines, cancelled = AUTH.sheet_evidence(lines)
        self.assertEqual(engines, [25])
        self.assertEqual(cancelled, [dict(engine=25, client="/Applications/WGEX.app/Contents/MacOS/WGEX")])
        self.assertEqual(AUTH.sheet_evidence([]), ([], []))


class Driver(unittest.TestCase):
    def test_catalogue_row_and_mirror(self):
        rows = json.loads((LAB / "rows.json").read_text())["rows"]
        self.assertEqual(rows["AUTH-REAL"]["driver"], "auth-real")

    def test_verdict_run_refuses_driver_row_outside_its_driver(self):
        run = load("verdict_run_for_auth_real", LAB / "verdict-run.py")
        self.assertEqual(run.DRIVERS, {"auth-real": "auth-real.py"})
        for argv in (["AUTH-REAL", "--dry-run"], ["AUTH-REAL"], ["AUTH-REAL", "--no-install", "--report-root", "/tmp/x"]):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit) as raised:
                run.main(argv)
            self.assertEqual(raised.exception.code, 2)
            self.assertIn("runs through its own driver", err.getvalue())

    def test_driver_refuses_another_guest(self):
        env = {key: value for key, value in __import__("os").environ.items() if not key.startswith("WGEX_")}
        result = subprocess.run([sys.executable, "-I", "-B", str(LAB / "auth-real.py"), "--report-root", "/nonexistent"],
                                env=dict(env, WGEX_LAB_VM="macos26-wgex", WGEX_LAB_USER="labuser"), capture_output=True, timeout=60, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"macos27-wgex", result.stderr)

    def test_approve_script_presses_only_and_avoids_reserved_words(self):
        # Live run 1: a variable named "before" (an AppleScript reserved word) failed to compile (-2741).
        script = (LAB / "tart/guest/approve-item.applescript").read_text()
        self.assertNotIn("keystroke", script)
        self.assertIn('perform action "AXPress"', script)
        for word in ("before", "after", "result", "it", "me", "every", "some", "contains", "starts"):
            with self.subTest(word=word):
                self.assertNotRegex(script, r"(?m)^\s*set " + word + r" to ")

    def test_report_bound(self):
        payload = AUTH.bounded(dict(row="AUTH-REAL", authdLines=["x" * 100] * 30))
        self.assertLess(len(payload), AUTH.REPORT_LIMIT)
        with self.assertRaises(ValueError):
            AUTH.bounded(dict(row="AUTH-REAL", other="x" * AUTH.REPORT_LIMIT))


class ApprovalSheet(unittest.TestCase):
    """Live run 5: the background-item switch raised a password sheet on System Settings, not SecurityAgent."""

    class Live:
        class RowFailure(RuntimeError):
            pass

    class Session:
        stage = "/Users/admin/lab/verdict-lab-test"

        def __init__(self, fills=()):
            self.labs, self.ssh_calls, self.fills = [], [], list(fills)

        def lab(self, *args, **kw):
            self.labs.append(args)

        def ssh(self, command, data=None, check=True, deadline=None):
            self.ssh_calls.append((command, data))
            reply = self.fills.pop(0) if self.fills else "fill=error"
            if isinstance(reply, Exception):
                raise reply
            return reply.encode()

    def probe(self, replies, fail=(), fills=()):
        probe = AUTH.AuthReal(self.Session(fills), self.Live)
        probe.start_clock = "2026-11-11 08:22:20"
        probe.calls = []

        def act(action, *args, check=True, deadline=None):
            probe.calls.append(action)
            if action in fail:
                raise RuntimeError(action)
            queue = replies.get(action, [""])
            return queue.pop(0) if len(queue) > 1 else queue[0]
        probe.act = act
        return probe

    def setUp(self):
        self.sleep, AUTH.time.sleep = AUTH.time.sleep, lambda seconds: None

    def tearDown(self):
        AUTH.time.sleep = self.sleep

    def test_sources(self):
        cases = [("agent=running windows=1", "settings-sheet=0 la=absent", "SecurityAgent"),
                 ("agent=absent", "settings-sheet=1 la=running", "System Settings"),
                 ("agent=absent", "settings-sheet=2 la=absent", "System Settings"),
                 ("agent=absent", "settings-sheet=0 la=running", None),
                 ("agent=running windows=0", "settings-sheet=unreadable la=running", None),
                 ("agent=absent", "", None)]
        for agent, settings, expected in cases:
            with self.subTest(agent=agent, settings=settings):
                probe = self.probe({"agent-state": [agent], "settings-sheet": [settings]})
                probe.approval = {}
                self.assertEqual(probe.approval_sheet(), expected)

    def approve(self, probe, line="item=background-switch-WGEX was=0 pressed=yes"):
        probe.wait = lambda what, seconds, check, interval=2: AUTH.AuthReal.wait(probe, what, seconds, check, interval) \
            if what != "WGEX background item" else line
        probe.approve_background_item()

    def test_unidentified_settings_sheet_is_cancelled_and_stops_the_row(self):
        # No authd line for the Login Items right: not the sheet DEC-034 covers, so nothing is entered.
        probe = self.probe({"agent-state": ["agent=absent"],
                            "settings-sheet": ["settings-sheet=0 la=absent", "settings-sheet=1 la=running", "settings-sheet=0 la=absent"],
                            "settings-sheet-cancel": ["cancel=sent"], "btm-state": ["WGEX: [disabled, allowed, not notified]"]})
        with self.assertRaises(AUTH.Failure) as raised:
            self.approve(probe)
        self.assertIn("password sheet (System Settings; cancelled); a console step for the maintainer", str(raised.exception))
        self.assertEqual(probe.console_step, "background-item approval: System Settings")
        self.assertIn("settings-sheet-cancel", probe.calls)
        self.assertNotIn("agent-cancel", probe.calls)
        self.assertEqual((probe.approval["sheet"], probe.approval["sheetClosed"]), ("System Settings", True))
        self.assertNotIn(("gui", "activate", "WGEX"), probe.session.labs)
        self.assertEqual(probe.session.ssh_calls, [])

    def test_security_agent_sheet_uses_its_own_cancel(self):
        probe = self.probe({"agent-state": ["agent=running windows=1", "agent=absent"], "settings-sheet": ["settings-sheet=0 la=absent"]})
        with self.assertRaises(AUTH.Failure):
            self.approve(probe)
        self.assertIn("agent-cancel", probe.calls)
        self.assertEqual(probe.approval["sheet"], "SecurityAgent")
        self.assertEqual(probe.session.ssh_calls, [])

    def test_cancel_failure_still_records_the_console_step(self):
        probe = self.probe({"agent-state": ["agent=absent"], "settings-sheet": ["settings-sheet=1 la=running"]}, fail=("settings-sheet-cancel",))
        with self.assertRaises(AUTH.Failure):
            self.approve(probe)
        self.assertEqual((probe.approval["sheetClosed"], probe.approval["cancelError"]), (False, "RuntimeError"))
        self.assertIsNotNone(probe.console_step)

    def test_sheet_that_never_closes(self):
        probe = self.probe({"agent-state": ["agent=absent"], "settings-sheet": ["settings-sheet=1 la=running"]})
        clock = iter(range(0, 10000, 5))
        monotonic, AUTH.time.monotonic = AUTH.time.monotonic, lambda: next(clock)
        try:
            with self.assertRaises(AUTH.Failure):
                self.approve(probe)
        finally:
            AUTH.time.monotonic = monotonic
        self.assertIs(probe.approval["sheetClosed"], False)

    def test_no_sheet_goes_on_to_wgex(self):
        probe = self.probe({"agent-state": ["agent=absent"], "settings-sheet": ["settings-sheet=0 la=absent"]})
        clock = iter(range(0, 10000, 5))
        monotonic, AUTH.time.monotonic = AUTH.time.monotonic, lambda: next(clock)
        try:
            self.approve(probe)
        finally:
            AUTH.time.monotonic = monotonic
        self.assertIsNone(probe.console_step)
        self.assertIn(("gui", "activate", "WGEX"), probe.session.labs)

    def test_switch_already_on_skips_the_sheet_wait(self):
        probe = self.probe({})
        self.approve(probe, "item=background-switch-WGEX was=1 pressed=no")
        self.assertEqual(probe.calls, [])
        self.assertIn(("gui", "activate", "WGEX"), probe.session.labs)

    def test_report_destination(self):
        self.assertEqual(AUTH.report_destination(True, None, "/r", "/b"), Path("/r").resolve())
        self.assertEqual(AUTH.report_destination(False, "background-item approval: System Settings", "/r", "/b"), Path("/r").resolve())
        self.assertEqual(AUTH.report_destination(False, None, "/r", "/b"), Path("/b/lab-verdict-failures").resolve())

    def test_sheet_cancel_is_a_press_not_a_keystroke(self):
        script = (LAB / "tart/guest/auth-real.sh").read_text()
        block = script[script.index("  settings-sheet-cancel)"):script.index("  approval-log)")]
        self.assertIn('perform action "AXPress" of last button of group 1 of sheet 1 of window 1', block)
        self.assertNotIn("key code", block)
        self.assertNotIn("keystroke", block)

    def test_readme_names_the_console_step(self):
        text = AUTH.readme(dict(guest="macos27-wgex", consoleStep="background-item approval: System Settings",
                                approval=dict(sheetClosed=True), gaps=["row stopped: x"]))
        self.assertIn("Console step: background-item approval: System Settings (sheet closed after cancel: true)", text)


APPROVAL_LINE = ("2026-11-11 08:48:17.682 Df authd[202:1fbd] [com.apple.Authorization:authd] Validating shared credential admin "
                 "(501) for com.apple.backgroundtaskmanagement.manage-daemons (engine 34)")
SECRET = b"sample-guest-secret-4"


class PasswordFile(unittest.TestCase):
    """DEC-034 and follow-up B3: the password comes from a 0600 one-line file under TMPDIR, removed after reading."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, data, mode=0o600, name="pw"):
        path = self.root / name
        path.write_bytes(data)
        path.chmod(mode)
        return path

    def refused(self, path, tmpdir=None):
        with self.assertRaises(AUTH.Failure) as raised:
            AUTH.read_guest_password(str(path) if path else path, str(tmpdir or self.root))
        self.assertNotIn(SECRET.decode(), str(raised.exception))
        return str(raised.exception)

    def test_reads_strips_one_newline_and_removes(self):
        path = self.write(SECRET + b"\n")
        self.assertEqual(AUTH.read_guest_password(str(path), str(self.root)), SECRET)
        self.assertFalse(path.exists())
        path = self.write(SECRET)
        self.assertEqual(AUTH.read_guest_password(str(path), str(self.root)), SECRET)

    def test_unset_and_no_tmpdir(self):
        self.assertIn("is not set", self.refused(None))
        self.assertIn("is not set", self.refused(""))
        with self.assertRaises(AUTH.Failure):
            AUTH.read_guest_password(str(self.write(SECRET)), "")

    def test_outside_tmpdir_or_relative(self):
        path = self.write(SECRET)
        with tempfile.TemporaryDirectory() as other:
            self.assertIn("under TMPDIR", self.refused(path, other))
        self.assertIn("under TMPDIR", self.refused("pw"))
        self.assertTrue(path.exists())

    def test_mode_link_and_missing(self):
        self.assertIn("0600", self.refused(self.write(SECRET, 0o644)))
        self.assertIn("0600", self.refused(self.write(SECRET, 0o400, name="ro")))
        target = self.write(SECRET, name="target")
        (self.root / "link").symlink_to(target)
        self.refused(self.root / "link")
        self.assertTrue(target.exists())
        self.assertIn("names no file", self.refused(self.root / "absent"))

    def test_content_must_be_one_line(self):
        for data in (b"", b"\n", SECRET + b"\nsecond", SECRET + b"\r\n", b"a\0b", b"x" * (AUTH.PASSWORD_LIMIT + 1)):
            with self.subTest(data=data[:12]):
                path = self.write(data)
                self.assertIn("one non-empty line", self.refused(path))
                self.assertFalse(path.exists())

    def test_redact_and_fill_outcome(self):
        self.assertEqual(AUTH.redact("x " + SECRET.decode() + " y", SECRET), "x <redacted> y")
        self.assertEqual(AUTH.redact("x", None), "x")
        for line in ("fill=entered mode=set field=secure pressed=modify", "fill=entered mode=keys field=default-focus pressed=no",
                     "fill=no-field mode=set", "fill=no-sheet", "fill=error mode=keys field=secure", "fill=empty"):
            self.assertEqual(AUTH.fill_outcome(line), line)
        for line in ("fill=entered " + SECRET.decode(), "fill=entered mode=set\nextra", "", "fill=error RuntimeError <redacted>"):
            self.assertEqual(AUTH.fill_outcome(line), "fill=unrecognised")


class ApprovalFill(ApprovalSheet):
    """Follow-up B3: the Login Items sheet (authd's manage-daemons line, LocalAuthenticationRemoteService) is filled;
    AXValue first, key events second, cancel and stop when neither closes it."""

    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.environ = dict(os.environ)
        os.environ["TMPDIR"] = self.tmp.name
        path = Path(self.tmp.name) / "guest-pw"
        path.write_bytes(SECRET + b"\n")
        path.chmod(0o600)
        os.environ[AUTH.PASSWORD_FILE_ENV] = str(path)
        self.path = path
        self.clock = iter(range(0, 100000, 5))
        self.monotonic, AUTH.time.monotonic = AUTH.time.monotonic, lambda: next(self.clock)

    def tearDown(self):
        AUTH.time.monotonic = self.monotonic
        os.environ.clear()
        os.environ.update(self.environ)
        self.tmp.cleanup()
        super().tearDown()

    def replies(self, settings):
        return {"agent-state": ["agent=absent"], "settings-sheet": settings, "approval-log": [APPROVAL_LINE],
                "settings-sheet-cancel": ["cancel=sent"], "btm-state": ["WGEXDaemon: [enabled, allowed, notified] (0xb)"]}

    def assert_secret_kept_out(self, probe):
        for command, data in probe.session.ssh_calls:
            self.assertNotIn(SECRET.decode(), command)
            self.assertIn("settings-sheet-fill", command)
            self.assertEqual(data, SECRET)
        self.assertNotIn(SECRET.decode(), json.dumps(probe.approval))
        self.assertNotIn(SECRET.decode(), AUTH.readme(dict(approval=probe.approval, checks=probe.checks)))
        self.assertFalse(self.path.exists())

    def test_axvalue_fill_closes_the_sheet_and_goes_on(self):
        probe = self.probe(self.replies(["settings-sheet=1 la=running", "settings-sheet=0 la=running"]),
                           fills=["fill=entered mode=set field=secure pressed=modify"])
        self.approve(probe)
        self.assertEqual([command.split()[-1] for command, _ in probe.session.ssh_calls], ["set"])
        self.assertEqual(probe.approval["passwordEntered"], "mode set")
        self.assertIs(probe.approval["sheetClosed"], True)
        self.assertIn(AUTH.APPROVAL_RIGHT, probe.approval["sheet"])
        self.assertNotIn("settings-sheet-cancel", probe.calls)
        self.assertIsNone(probe.console_step)
        self.assertIn(("gui", "activate", "WGEX"), probe.session.labs)
        self.assert_secret_kept_out(probe)
        self.assertIn("filled with the image's public default", AUTH.readme(dict(approval=probe.approval)))

    def test_key_events_when_axvalue_leaves_the_sheet_up(self):
        probe = self.probe(self.replies(["settings-sheet=1 la=running"] * 12 + ["settings-sheet=0 la=running"]),
                           fills=["fill=entered mode=set field=secure pressed=modify", "fill=entered mode=keys field=secure pressed=modify"])
        self.approve(probe)
        self.assertEqual([item["mode"] for item in probe.approval["fill"]], ["set", "keys"])
        self.assertEqual([item["sheetClosed"] for item in probe.approval["fill"]], [False, True])
        self.assertEqual(probe.approval["passwordEntered"], "mode keys")
        self.assert_secret_kept_out(probe)

    def test_no_field_then_keys(self):
        probe = self.probe(self.replies(["settings-sheet=1 la=running", "settings-sheet=0 la=running"]),
                           fills=["fill=no-field mode=set", "fill=entered mode=keys field=default-focus pressed=modify"])
        self.approve(probe)
        self.assertEqual(probe.approval["passwordEntered"], "mode keys")
        self.assertNotIn("sheetClosed", probe.approval["fill"][0])

    def test_refused_synthetic_input_cancels_and_stops(self):
        probe = self.probe(self.replies(["settings-sheet=1 la=running"] * 40 + ["settings-sheet=0 la=running"]),
                           fills=["fill=entered mode=set field=secure pressed=modify", RuntimeError("command deadline")])
        with self.assertRaises(AUTH.Failure) as raised:
            self.approve(probe)
        self.assertIn("VM console route", str(raised.exception))
        self.assertIn("fill=unrecognised", str(raised.exception))
        self.assertIn("settings-sheet-cancel", probe.calls)
        self.assertEqual(probe.console_step, "background-item approval: System Settings")
        self.assertNotIn("passwordEntered", probe.approval)
        self.assertNotIn(("gui", "activate", "WGEX"), probe.session.labs)
        self.assert_secret_kept_out(probe)

    def test_echoed_secret_is_redacted(self):
        probe = self.probe(self.replies(["settings-sheet=1 la=running"] * 40 + ["settings-sheet=0 la=running"]),
                           fills=["fill=entered " + SECRET.decode(), "fill=error mode=keys field=secure"])
        with self.assertRaises(AUTH.Failure) as raised:
            self.approve(probe)
        self.assertNotIn(SECRET.decode(), str(raised.exception))
        self.assert_secret_kept_out(probe)

    def test_missing_password_file_cancels_and_stops(self):
        self.path.unlink()
        probe = self.probe(self.replies(["settings-sheet=1 la=running", "settings-sheet=0 la=running"]))
        with self.assertRaises(AUTH.Failure) as raised:
            self.approve(probe)
        self.assertIn("needs the guest password", str(raised.exception))
        self.assertIn("settings-sheet-cancel", probe.calls)
        self.assertEqual(probe.session.ssh_calls, [])

    def test_sheet_not_drawn_by_local_authentication_is_cancelled(self):
        probe = self.probe(self.replies(["settings-sheet=1 la=absent", "settings-sheet=0 la=absent"]))
        with self.assertRaises(AUTH.Failure):
            self.approve(probe)
        self.assertEqual(probe.session.ssh_calls, [])
        self.assertTrue(self.path.exists())


class FillHelpers(unittest.TestCase):
    """The guest side of the fill never echoes, logs or passes the password as an argument."""

    def test_shell_block(self):
        script = (LAB / "tart/guest/auth-real.sh").read_text()
        block = script[script.index("  settings-sheet-fill)"):script.index("  approval-log)")]
        self.assertIn("umask 077", block)
        self.assertIn('trap \'rm -f "$secret"\' EXIT', block)
        self.assertIn('head -c 256 >"$secret"', block)
        self.assertIn('fill-sheet.applescript" "$secret" "$2" 2>/dev/null', block)
        self.assertNotRegex(block, r"cat \"?\$secret|printf '%s\\n' \"\$secret")
        self.assertIn("fill=unrecognised", block)

    def test_shell_output_filter(self):
        script = (LAB / "tart/guest/auth-real.sh").read_text()
        block = script[script.index("  settings-sheet-fill)"):script.index("  approval-log)")]
        pattern = re.search(r'\[\[ "\$out" =~ (.+) \]\]; then', block)[1].replace("\\ ", " ")
        for line in ("fill=entered mode=set field=secure pressed=modify", "fill=no-sheet", "fill=error mode=keys"):
            self.assertRegex(line, "^(?:" + pattern.strip("^$") + ")$")
        for line in ("fill=entered " + SECRET.decode(), "fill=entered mode=set extra"):
            self.assertNotRegex(line, "^(?:" + pattern.strip("^$") + ")$")

    def test_applescript_returns_fixed_lines_only(self):
        script = (LAB / "tart/guest/fill-sheet.applescript").read_text()
        returns = re.findall(r"(?m)^\s*(?:if .* then )?return (.+)$", script)
        self.assertTrue(returns)
        for value in returns:
            with self.subTest(value=value):
                self.assertNotIn("secretText", value)
        self.assertNotRegex(script, r"\b(log|display dialog|do shell script)\b")
        self.assertIn('perform action "AXPress" of first button of group 1 of sheet 1 of window 1', script)
        self.assertIn('if fillMode is not in {"set", "keys"} then return "fill=error"', script)
        for word in ("before", "after", "result", "it", "me", "every", "some", "contains", "starts", "mode", "field"):
            with self.subTest(word=word):
                self.assertNotRegex(script, r"(?m)^\s*set " + word + r" to ")

    def test_staged(self):
        self.assertIn("fill-sheet.applescript", AUTH.HELPERS)


AUTHD_27 = """\
2026-11-11 11:34:00.264 Df authd[206:27bc] [com.apple.Authorization:authd] Succeeded authorizing right 'config.add.{right}' by client '/Applications/WGEX.app/Contents/MacOS/WGEXDaemon' [2241] for authorization created by '/Applications/WGEX.app/Contents/MacOS/WGEXDaemon' [2241] (3,0) (engine 37)
2026-11-11 11:34:28.471 I  authd[206:37a4] [com.apple.Authorization:authd] Process /Applications/WGEX.app (PID 1332) evaluates 1 rights with flags 00000003 (engine 43, token 28): (
2026-11-11 11:34:28.471 Df authd[206:37a4] [com.apple.Authorization:authd] Validating shared credential admin (501) for authenticate-admin-nonshared (engine 43)
2026-11-11 11:34:28.471 Df authd[206:37a4] [com.apple.Authorization:authd] credential 501 expired '212.181114 > 30' (does NOT satisfy rule) (engine 43)
2026-11-11 11:34:28.471 Df authd[206:37a4] [com.apple.Authorization:authd] Validating session owner admin (501) for authenticate-admin-nonshared (engine 43)
2026-11-11 11:34:28.472 Df authd[206:37a4] [com.apple.Authorization:authd] session owner 501 is member of group admin (does satisfy rule) (engine 43)
2026-11-11 11:34:28.703 Df authd[206:37a4] [com.apple.Authorization:authd] engine 43: running mechanism builtin:authenticate (1 of 3)
2026-11-11 11:34:30.000 Df authd[206:37a4] [com.apple.Authorization:authd] engine 44: running mechanism builtin:authenticate (1 of 3)
2026-11-11 11:34:37.928 E  authd[206:37a4] [com.apple.Authorization:authd] Evaluate cancelled or failed -60006 (engine 43)
2026-11-11 11:34:37.928 Df authd[206:37a4] [com.apple.Authorization:authd] Failed to authorize right '{right}' by client '/Applications/WGEX.app' [1332] for authorization created by '/Applications/WGEX.app' [1332] (3,0) (-60006) (engine 43)
"""


class AuthdLines27(unittest.TestCase):
    """Live run 7 (macOS 27.2): the engine's earlier lines name the rule, and the right appears first in the Failed line."""

    def test_two_passes_keep_the_engines_earlier_lines(self):
        result = subprocess.run(["perl", str(LAB / "tart/guest/authd-lines.pl"), RIGHT], input=AUTHD_27.format(right=RIGHT).encode(),
                                capture_output=True, timeout=30, check=False)
        lines = result.stdout.decode().splitlines()
        self.assertEqual(lines[-1], "authd-lines: kept=8 engines=37,43")
        kept = "\n".join(lines[:-1])
        self.assertIn("engine 43: running mechanism builtin:authenticate (1 of 3)", kept)
        self.assertIn("credential 501 expired '212.181114 > 30' (does NOT satisfy rule) (engine 43)", kept)
        self.assertNotIn("engine 44", kept)
        self.assertNotIn("evaluates", kept)
        doubled = "".join(line + "\n" + line + "\n" for line in AUTHD_27.format(right=RIGHT).splitlines())
        again = subprocess.run(["perl", str(LAB / "tart/guest/authd-lines.pl"), RIGHT], input=doubled.encode(),
                               capture_output=True, timeout=30, check=False).stdout.decode().splitlines()
        self.assertEqual(again, lines)
        engines, cancelled = AUTH.sheet_evidence(lines)
        self.assertEqual(engines, [43])
        self.assertEqual(cancelled, [dict(engine=43, client="/Applications/WGEX.app")])


class SheetShown(unittest.TestCase):
    def test_needs_the_window_and_an_engine(self):
        self.assertIs(AUTH.sheet_shown("agent=running windows=1", [98])["met"], True)
        self.assertIs(AUTH.sheet_shown("agent=running windows=1", [])["met"], False)
        self.assertIs(AUTH.sheet_shown("agent=absent", [98])["met"], False)

    def test_read_after_the_cancel(self):
        # Live run 8: the engine is known only from the Failed line written at the cancel.
        script = (LAB / "auth-real.py").read_text()
        run = script[script.index("        self.press(SECURE_INSTALL)"):script.index("    def try_press")]
        self.assertLess(run.index('self.act("agent-cancel")'), run.index("self.fail_closed(agent)"))
        self.assertNotIn("authd-log", run)
        lines = subprocess.run(["perl", str(LAB / "tart/guest/authd-lines.pl"), RIGHT], input=AUTHD_27.format(right=RIGHT).encode(),
                               capture_output=True, timeout=30, check=False).stdout.decode().splitlines()
        engines, _ = AUTH.sheet_evidence(lines)
        self.assertIs(AUTH.sheet_shown("agent=running windows=1", engines)["met"], True)


ROUTES = """\
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.64.1       UGScg                 en0
127                127.0.0.1          UCS                   lo0
169.254            link#6             UCS                   en0      !
192.168.64         link#6             UCS                   en0      !
192.168.64.1       aa:bb:cc:dd:ee:01  UHLWIir               en0   1165
224.0.0/4          link#6             UmCS                  en0      !

Internet6:
Destination                             Gateway                                 Flags               Netif Expire
default                                 fe80::%utun0                            UGcIg               utun0
::1                                     ::1                                     UHL                   lo0
fd5c:4882:e9c6:cb79:818:13b4:fcd6:aa83  aa:bb:cc:dd:ee:02                       UHL                   lo0
"""

DNS = """\
DNS configuration

resolver #1
  nameserver[0] : 192.168.64.1
  if_index : 6 (en0)
  flags    : Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)
  order    : 200000

resolver #2
  domain   : local
  options  : mdns
  timeout  : 5
  flags    : Request A records
  reach    : 0x00000000 (Not Reachable)
  order    : 300000

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.168.64.1
  if_index : 6 (en0)
  flags    : Scoped, Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)
"""

REFERENCES = """\
TOKENS:
PID      Process Name                TOKEN                 TIMESTAMP
1256     pfctl                       1844674407            0 days 00:02:46
"""


def net_text(**changes):
    """auth-real.sh net-state output with the given sections replaced: name=(exit, text)."""
    sections = dict(sudo=(0, ""), utun=(0, "lo0 gif0 stf0 en0 utun0 utun1"), routes=(0, ROUTES), dns=(0, DNS),
                    resolver=(0, ""), pf=(0, "Status: Disabled for 0 days 00:00:02           Debug: Urgent\n"),
                    pfReferences=(0, REFERENCES), wgexAnchorRules=(1, ""), wgexAnchors=(0, "  com.apple/250.ApplicationFirewall\n"))
    sections.update(changes)
    return "".join(f"==wgex-net {name} {rc}\n{text}" + ("" if not text or text.endswith("\n") else "\n")
                   for name, (rc, text) in sections.items())


class NetState(unittest.TestCase):
    """Review finding 1: the comparison is on normalised contents, and an unreadable source fails it."""

    def compare(self, **changes):
        return AUTH.net_comparison(AUTH.parse_net_state(net_text()), AUTH.parse_net_state(net_text(**changes)))

    def test_parsed_records(self):
        state = AUTH.parse_net_state(net_text())
        self.assertEqual(set(state), set(AUTH.NET_KEYS))
        self.assertTrue(all(value["status"] == "ok" for value in state.values()))
        self.assertEqual(state["utun"]["records"], ["utun0", "utun1"])
        self.assertIn("inet default 192.168.64.1 UGScg en0", state["routes"]["records"])
        self.assertFalse(any("UHLWIir" in item for item in state["routes"]["records"]), "cloned cache rows are dropped")
        self.assertIn("inet6 fd5c:4882:e9c6:cb79:818:13b4:fcd6:aa83 <lladdr> UHL lo0", state["routes"]["records"])
        self.assertIn("DNS configuration | resolver #1 | nameserver[0] : 192.168.64.1", state["dns"]["records"])
        self.assertFalse(any(" reach " in item for item in state["dns"]["records"]))
        self.assertEqual(state["resolver"]["records"], [])
        self.assertEqual(state["pf"]["records"], ["Disabled"])
        self.assertEqual(state["pfReferences"]["records"], ["1256 pfctl 1844674407"])
        self.assertEqual(state["wgexAnchorRules"]["records"], ["exit=1"])
        self.assertEqual(state["wgexAnchors"]["records"], [])
        self.assertEqual(self.compare(), ([], [], {}))

    def test_volatile_columns_do_not_count(self):
        routes = ROUTES.replace("UHLWIir               en0   1165", "UHLWIir               en0   1020").replace("en0      !", "en0       ")
        dns = DNS.replace("0x00020002 (Reachable,Directly Reachable Address)", "0x00000002 (Reachable)")
        references = REFERENCES.replace("0 days 00:02:46", "0 days 00:19:03")
        pf = "Status: Disabled for 0 days 00:21:40           Debug: Urgent\n"
        self.assertEqual(self.compare(routes=(0, routes), dns=(0, dns), pfReferences=(0, references), pf=(0, pf)), ([], [], {}))

    def test_contents_change_with_counts_equal(self):
        cases = dict(
            routes=ROUTES.replace("default            192.168.64.1       UGScg                 en0",
                                  "default            10.77.0.1          UGScg               utun4"),
            dns=DNS.replace("  nameserver[0] : 192.168.64.1\n  if_index : 6 (en0)\n  flags    : Request A",
                            "  nameserver[0] : 10.77.0.1\n  if_index : 6 (en0)\n  flags    : Request A"),
            resolver=("==wgex-file example.test\nnameserver 192.0.2.53\n", "==wgex-file example.test\nnameserver 192.0.2.54\n"),
            pfReferences=REFERENCES.replace("1256     pfctl                       1844674407",
                                            "1301     WGEXDaemon                  1844674407"),
            wgexAnchors=("  com.apple/wgex\n", "  com.apple/wgex-other\n"),
            utun=("lo0 en0 utun0 utun1", "lo0 en0 utun0 utun4"),
        )
        for key, value in cases.items():
            with self.subTest(key=key):
                before, after = value if isinstance(value, tuple) else (None, value)
                old = AUTH.parse_net_state(net_text() if before is None else net_text(**{key: (0, before)}))
                new = AUTH.parse_net_state(net_text(**{key: (0, after)}))
                self.assertEqual(len(old[key]["records"]), len(new[key]["records"]), "the count stays equal")
                changed, unreadable, diff = AUTH.net_comparison(old, new)
                self.assertEqual((changed, unreadable), ([key], []))
                self.assertTrue(diff[key]["added"] and diff[key]["removed"])

    def test_anchor_rules_appearing(self):
        changed, unreadable, diff = self.compare(wgexAnchorRules=(0, "block drop out quick all\n"))
        self.assertEqual((changed, unreadable), (["wgexAnchorRules"], []))
        self.assertEqual(diff["wgexAnchorRules"], dict(added=["block drop out quick all"], removed=["exit=1"]))

    def test_resolver_file_content_normalised(self):
        old = AUTH.parse_net_state(net_text(resolver=(0, "==wgex-file a.test\nnameserver 192.0.2.53 # comment\n\n")))
        new = AUTH.parse_net_state(net_text(resolver=(0, "==wgex-file a.test\n  nameserver   192.0.2.53\n")))
        self.assertEqual(old["resolver"]["records"], ["a.test:", "a.test: nameserver 192.0.2.53"])
        self.assertEqual(AUTH.net_comparison(old, new), ([], [], {}))
        self.assertEqual(AUTH.parse_net_state(net_text(resolver=(0, "nameserver 192.0.2.53\n")))["resolver"]["status"], "unreadable")

    def test_unreadable_observations_fail(self):
        cases = dict(
            routes=(1, ""), dns=(0, "garbage"), resolver=(1, "==wgex-file a.test\n"), utun=(0, ""), pf=(0, "Status unknown\n"),
            wgexAnchors=(1, ""), pfReferences=(1, ""),
        )
        for key, value in cases.items():
            with self.subTest(key=key):
                changed, unreadable, _ = self.compare(**{key: value})
                self.assertEqual((changed, unreadable), ([], [key]))
        self.assertEqual(AUTH.parse_net_state(net_text(routes=(0, "Routing tables\n")))["routes"]["status"], "unreadable")
        self.assertEqual(AUTH.parse_net_state(net_text(routes=(0, "default 192.168.64.1\n")))["routes"]["status"], "unreadable")

    def test_sudo_refused_makes_every_pf_source_unreadable(self):
        changed, unreadable, _ = self.compare(sudo=(1, ""))
        self.assertEqual((changed, unreadable), ([], list(AUTH.NET_PF_KEYS)))
        before = AUTH.parse_net_state(net_text(sudo=(1, "")))
        self.assertEqual(AUTH.net_comparison(before, before)[1], list(AUTH.NET_PF_KEYS), "unreadable on both sides still fails")

    def test_malformed_reply(self):
        for text in ("", net_text() + "==wgex-net routes 0\n", net_text().replace("==wgex-net dns 0\n", ""),
                     "stray\n" + net_text(), net_text() + "==wgex-net extra 0\n"):
            with self.subTest(text=text[:30]), self.assertRaises(ValueError):
                AUTH.parse_net_state(text)

    def test_digest_and_summary(self):
        state = AUTH.parse_net_state(net_text())
        digest = AUTH.net_digest(state)
        self.assertEqual(digest["pf"]["records"], 1)
        self.assertEqual(len(digest["pf"]["digest"]), 16)
        other = AUTH.net_digest(AUTH.parse_net_state(net_text(pf=(0, "Status: Enabled for 0 days 00:00:01\n"))))
        self.assertNotEqual(digest["pf"]["digest"], other["pf"]["digest"])
        summary = AUTH.fail_closed_summary([1], "unverified", {}, ["dns"], ["pf"])
        self.assertIn("network records unreadable: pf; changed: dns", summary)
        self.assertIn("network records unchanged", AUTH.fail_closed_summary([1], "unverified", {}, [], []))

    def test_guest_helper_emits_every_section(self):
        script = (LAB / "tart/guest/auth-real.sh").read_text()
        block = script[script.index("  net-state)"):script.index("  agent-state)")]
        for name in AUTH.NET_SECTIONS:
            with self.subTest(name=name):
                self.assertRegex(block, r"(?m)^\s+net_section " + name + " ")
        self.assertNotIn("wc -l", block)
        self.assertNotIn("grep -c", block)

    def test_report_drops_baseline_records_before_failing(self):
        closed = dict(met=True, netRecords=dict(routes=["x" * 100] * 600), netBefore={})
        payload = AUTH.bounded(dict(row="AUTH-REAL", checks=dict(cancelFailsClosed=closed)))
        record = json.loads(payload)
        self.assertNotIn("netRecords", record["checks"]["cancelFailsClosed"])
        self.assertIs(record["checks"]["cancelFailsClosed"]["netRecordsDropped"], True)


RECOVERING = ("Service is recovering. Protection cannot be verified while the service recovers. Wait for recovery to "
              "finish, check the current protection state and try again.")


def window_dump(control, message=False):
    """A full window dump: the switch's own line, and the recovery copy under the form when message is set."""
    lines = [f"AXCheckBox | name=Allow local network | value=0 | desc=switch | id={control} | pos=10,10 size=40x20 en=true",
             "AXStaticText | name=Details | value=Details | desc=text | id= | pos=10,40 size=40x20 en=true",
             "AXStaticText | name=Service is recovering | value=Service is recovering | desc=text | id=wgex.settings.details.status "
             "| pos=10,60 size=40x20 en=true"]
    if message:
        lines.append(f"AXStaticText | name={RECOVERING} | value={RECOVERING} | desc=text | id= | pos=10,90 size=400x20 en=true")
    return "\n".join(lines)


class SettingsWrite(unittest.TestCase):
    """Live run 7: in the daemon's startup recovery the tightening write is accepted by design; the loosening one decides.
    Review finding 2: on is requested only after a fresh read shows the switch off, and the refusal must be seen."""

    class Live:
        class RowFailure(RuntimeError):
            pass

        @staticmethod
        def dump_toggle_value(dump, identifier):
            return {"on": True, "off": False}.get(dump)

    class Session:
        def __init__(self, toggles, journals, windows=()):
            # toggles: the main window switch's successive reads (a list), or None for the Settings path, whose targeted
            # reads come from the same list after the first None; windows: successive full dumps (exceptions raise).
            self.toggles, self.journals, self.windows, self.clicks = list(toggles), list(journals), list(windows), []

        def lab(self, *args, **kw):
            pass

        def next_toggle(self):
            reply = self.toggles.pop(0) if len(self.toggles) > 1 else self.toggles[0]
            if isinstance(reply, Exception):
                raise reply
            return reply

        def toggle_value(self, identifier):
            value = self.next_toggle()
            return {"on": True, "off": False}.get(value) if isinstance(value, str) else value

        def open_settings(self):
            return "2"

        def select_settings_tab(self, window, tab):
            pass

        def read_dump(self, window, check=True, identifier=None, targeted=False, **kw):
            if targeted:
                return self.next_toggle()
            reply = self.windows.pop(0) if self.windows else ""
            if isinstance(reply, Exception):
                raise reply
            return reply

        def click_id(self, identifier, window="1"):
            self.clicks.append((identifier, window))

        def guest_action(self, action, check=True):
            return (self.journals.pop(0) if len(self.journals) > 1 else self.journals[0]).encode()

    def setUp(self):
        self.sleep, AUTH.time.sleep = AUTH.time.sleep, lambda seconds: None
        self.clock = iter(range(0, 100000, 5))
        self.monotonic, AUTH.time.monotonic = AUTH.time.monotonic, lambda: next(self.clock)

    def tearDown(self):
        AUTH.time.sleep, AUTH.time.monotonic = self.sleep, self.monotonic

    def write(self, toggles, journals, agents=("agent=absent",), windows=None, control=AUTH.ALLOW_LAN):
        if windows is None:
            windows = [window_dump(control), window_dump(control, message=True)]
        probe = AUTH.AuthReal(self.Session(toggles, journals, windows), self.Live)
        queue = list(agents)
        probe.calls = []

        def act(action, *args, check=True, deadline=None):
            probe.calls.append(action)
            if action == "agent-state":
                return queue.pop(0) if len(queue) > 1 else queue[0]
            return "cancel=sent"
        probe.act = act
        return probe, probe.settings_write()

    def test_tightening_accepted_loosening_refused(self):
        probe, record = self.write([True, False], ["allowLAN=true", "allowLAN=false"])
        self.assertEqual(record["tightening"]["journal"], "allowLAN=false")
        loosening = record["loosening"]
        self.assertEqual((loosening["switchBefore"], loosening["pressed"], loosening["journal"]), (False, True, "allowLAN=false"))
        self.assertEqual(loosening["refusal"]["messageBefore"], [])
        self.assertEqual(loosening["refusal"]["messageAfter"], [RECOVERING])
        self.assertIs(loosening["refusal"]["recoveryMessage"], True)
        self.assertIs(loosening["refusal"]["switchAfter"], False)
        self.assertIs(record["refused"], True)
        self.assertEqual(len(probe.session.clicks), 2)
        summary = AUTH.fail_closed_summary([1], "unverified", record, [])
        self.assertIn("loosening write (Allow local network on) refused (switch False", summary)
        self.assertIn("refusal shown: recoveryMessage", summary)

    def test_loosening_sheet_is_cancelled(self):
        control = AUTH.ALLOW_LAN
        probe, record = self.write([True, False], ["allowLAN=true", "allowLAN=false"],
                                   agents=["agent=absent"] * 6 + ["agent=running windows=1", "agent=absent"],
                                   windows=[window_dump(control), window_dump(control)])
        self.assertEqual(record["loosening"]["sheet"], "agent=running windows=1")
        self.assertIs(record["loosening"]["sheetCancelled"], True)
        self.assertIn("agent-cancel", probe.calls)
        self.assertIs(record["loosening"]["refusal"]["recoveryMessage"], False)
        self.assertIs(record["refused"], True)

    def test_loosening_accepted_is_not_refused(self):
        _, record = self.write([True, False], ["allowLAN=true", "allowLAN=false", "allowLAN=false", "allowLAN=true"])
        self.assertIs(record["refused"], False)
        self.assertIn("not refused", AUTH.fail_closed_summary([1], "unverified", record, []))

    def test_press_with_no_refusal_seen_is_not_refused(self):
        # A press the app swallowed (busy) leaves the journal false too; without the recovery copy or a cancelled sheet
        # nothing shows the request was refused.
        control = AUTH.ALLOW_LAN
        _, record = self.write([True, False], ["allowLAN=true", "allowLAN=false"], windows=[window_dump(control), window_dump(control)])
        self.assertIs(record["loosening"]["pressed"], True)
        self.assertIs(record["refused"], False)

    def test_recovery_copy_already_shown_is_not_fresh_evidence(self):
        control = AUTH.ALLOW_LAN
        _, record = self.write([True, False], ["allowLAN=true", "allowLAN=false"],
                               windows=[window_dump(control, message=True), window_dump(control, message=True)])
        self.assertEqual(record["loosening"]["refusal"]["messageBefore"], [RECOVERING])
        self.assertIs(record["refused"], False)

    def test_unreadable_window_dump_is_no_evidence(self):
        control = AUTH.ALLOW_LAN
        for windows in ([RuntimeError("dump"), window_dump(control, message=True)], ["", window_dump(control, message=True)]):
            with self.subTest(first=type(windows[0]).__name__):
                _, record = self.write([True, False], ["allowLAN=true", "allowLAN=false"], windows=windows)
                self.assertIsNone(record["loosening"]["refusal"]["messageBefore"])
                self.assertIs(record["refused"], False)

    def test_tightening_refused_leaves_nothing_to_loosen(self):
        probe, record = self.write([True, True], ["allowLAN=true"])
        self.assertEqual(record["tightening"]["journal"], "allowLAN=true")
        self.assertIs(record["loosening"]["pressed"], False)
        self.assertIs(record["refused"], False)
        self.assertEqual(len(probe.session.clicks), 1)

    def test_switch_already_off_goes_straight_to_loosening(self):
        probe, record = self.write([False], ["allowLAN=false"])
        self.assertIs(record["tightening"]["pressed"], False)
        self.assertIs(record["refused"], True)
        self.assertEqual(len(probe.session.clicks), 1)

    def test_stale_switch_is_not_pressed_again(self):
        # Regression (review finding 2): the tightening write reached the journal but the switch still reads on, so a
        # press would be another tightening request; nothing is pressed and the write is not refused.
        probe, record = self.write([True], ["allowLAN=true", "allowLAN=false"])
        self.assertEqual(record["tightening"]["journal"], "allowLAN=false")
        self.assertEqual((record["loosening"]["switchBefore"], record["loosening"]["pressed"]), (True, False))
        self.assertEqual(record["loosening"]["notPressed"], "switch not confirmed off")
        self.assertEqual(len(probe.session.clicks), 1)
        self.assertIs(record["refused"], False)
        self.assertIn("not pressed: switch not confirmed off", AUTH.fail_closed_summary([1], "unverified", record, []))

    def test_unreadable_switch_after_tightening_is_not_pressed(self):
        probe, record = self.write([True] + [None] * AUTH.TOGGLE_READS, ["allowLAN=true", "allowLAN=false"])
        self.assertEqual((record["loosening"]["switchBefore"], record["loosening"]["pressed"]), (None, False))
        self.assertEqual(record["loosening"]["notPressed"], "switch unreadable")
        self.assertEqual(len(probe.session.clicks), 1)
        self.assertIs(record["refused"], False)

    def test_unreadable_switch_with_false_journal_presses_nothing(self):
        # Regression (review finding 2): the journal alone said allowLAN=false while the Settings switch was never read;
        # the old driver pressed it anyway.
        probe, record = self.write([None] + ["unreadable"] * (2 * AUTH.TOGGLE_READS), ["allowLAN=false"],
                                   control=AUTH.ALLOW_LAN_SETTINGS)
        self.assertEqual((record["toggleBefore"], record["loosening"]["switchBefore"]), (None, None))
        self.assertEqual(probe.session.clicks, [])
        self.assertIs(record["refused"], False)

    def test_switch_read_again_until_off(self):
        probe, record = self.write([True, None, True, False], ["allowLAN=true", "allowLAN=false"])
        self.assertIs(record["loosening"]["switchBefore"], False)
        self.assertIs(record["refused"], True)

    def test_settings_window_fallback(self):
        control = AUTH.ALLOW_LAN_SETTINGS
        probe, record = self.write([None, "on", "off"], ["allowLAN=true", "allowLAN=false"], control=control)
        self.assertEqual((record["control"], record["window"]), (control, "2"))
        self.assertEqual(probe.session.clicks, [(control, "2")] * 2)
        self.assertEqual(record["toggleReads"], 1)
        self.assertIs(record["refused"], True)

    def test_settings_toggle_is_read_again(self):
        # Live run 9: the first targeted read failed in System Events.
        control = AUTH.ALLOW_LAN_SETTINGS
        probe, record = self.write([None, "unreadable", RuntimeError("dump"), "on", "off"], ["allowLAN=true", "allowLAN=false"],
                                   control=control)
        self.assertEqual((record["toggleBefore"], record["toggleReads"]), (True, 3))
        self.assertIs(record["refused"], True)

    def test_settings_toggle_never_read_presses_nothing(self):
        probe, record = self.write([None] + ["unreadable"] * (2 * AUTH.TOGGLE_READS), ["allowLAN=true"], control=AUTH.ALLOW_LAN_SETTINGS)
        self.assertEqual((record["toggleBefore"], record["toggleReads"]), (None, AUTH.TOGGLE_READS))
        self.assertEqual(probe.session.clicks, [])
        self.assertIs(record["refused"], False)

    def test_readme_names_loosening_writes(self):
        text = AUTH.readme(dict(checks={}, guestOS={}))
        self.assertIn("\"Settings writes refused\" means loosening writes", text)
        self.assertIn("by design", text)


if __name__ == "__main__":
    unittest.main()
