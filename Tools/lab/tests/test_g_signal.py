# SPDX-License-Identifier: MIT
"""M03-T07 phase B session 2: the driver writes one `WGEX-G` stderr line at each console moment (the logout, the start of the
console login wait with its deadline, the login, the start of the administrator approval wait with its deadline, the new
daemon), so the person running the row can tell the maintainer when to act. Never a VM."""
import contextlib
import io
import os
import re
import tempfile
import unittest

import test_gap_rows as gap
import test_login_silent as silent
import test_update_corpus as corpus

LIVE = gap.LIVE
LINE = re.compile(r"WGEX-G (logged-out|login-wait|logged-in|approval-wait|approval-seen) at=\d\d:\d\d:\d\dZ( deadline=\d\d:\d\d:\d\dZ)?")


def events(text):
    lines = text.splitlines()
    for line in lines:
        assert LINE.fullmatch(line), line
    return [line.split()[1] + (" deadline" if "deadline=" in line else "") for line in lines]


class FormatTests(unittest.TestCase):
    def test_a_wait_line_carries_its_utc_deadline_and_is_flushed(self):
        stream = io.StringIO()
        stream.flush = lambda: stream.write("<flushed>")
        line = LIVE.g_signal("login-wait", 480, now=86400 + 15 * 3600 + 42 * 60, stream=stream)
        self.assertEqual(line, "WGEX-G login-wait at=15:42:00Z deadline=15:50:00Z")
        self.assertEqual(stream.getvalue(), line + "\n<flushed>")

    def test_a_moment_line_has_no_deadline_and_an_unknown_event_is_refused(self):
        self.assertEqual(LIVE.g_signal("logged-out", now=0, stream=io.StringIO()), "WGEX-G logged-out at=00:00:00Z")
        with self.assertRaises(ValueError):
            LIVE.g_signal("password", now=0, stream=io.StringIO())


class DriverSignalTests(unittest.TestCase):
    def test_m53_09_signals_the_login_wait_only_after_the_logged_out_measurement(self):
        session = object.__new__(LIVE.Session)
        session.row_observation, session.profile_ids = {}, {"full4": "00000000-0000-4000-8000-000000000001"}
        order, console = [], iter([b"logged-out", b"lab", b"logged-out", b"lab"])
        session.runner = type("Clock", (), dict(monotonic=lambda self: 1000))()
        stderr = io.StringIO()
        stderr.write = lambda text, _write=stderr.write: (order.append(("signal", text.split()[1])), _write(text))[1]

        def action(name, *args):
            return next(console) if name == "console-user" else b""
        session.gap_action = action
        session.set_startup_off = session.set_startup_boot = lambda identity: None
        intents = iter([False, True])
        session.boot_intent = lambda identity: next(intents)
        session.await_status = lambda *args, **kw: None
        session.status = lambda: dict(phase="active", protection="protected")
        session.lab = lambda *args: None
        session.connect = lambda profile: None
        session.observe = lambda: (order.append(("observe",)), dict(status=dict(protection="unprotected"), referenceCount=0))[1]
        session.generate = lambda state, **kw: dict(state=state, **kw)
        with contextlib.redirect_stderr(stderr):
            session.logout_row("full4")
        self.assertEqual(events(stderr.getvalue()), ["logged-out", "login-wait deadline", "logged-in"] * 2)
        flat = [item[-1] for item in order]
        # The logged-out measurement (observe) comes before each login-wait line: a login on that line cannot spoil it.
        self.assertEqual(flat, ["logged-out", "observe", "login-wait", "logged-in"] * 2)
        deadline = re.search(r"login-wait at=(\S+) deadline=(\S+)", stderr.getvalue())
        to_seconds = lambda clock: sum(int(part) * unit for part, unit in zip(clock[:-1].split(":"), (3600, 60, 1)))
        self.assertEqual((to_seconds(deadline[2]) - to_seconds(deadline[1])) % 86400, LIVE.HARNESS.seconds("CONSOLE_RELOGIN"))

    def test_login_silent_signals_each_of_its_two_logins(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            silent.driven(silent.Guest())
        self.assertEqual(events(stderr.getvalue()), ["logged-out", "login-wait deadline", "logged-in"] * 2)

    def test_a_missed_login_still_signalled_the_wait(self):
        guest = silent.Guest()
        guest.relogin = False
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(silent.LIVE.RowFailure) as failure:
            silent.driven(guest)
        self.assertEqual(failure.exception.reason, "consoleReloginMissing")
        self.assertEqual(events(stderr.getvalue()), ["logged-out", "login-wait deadline"])

    def test_m53_07_signals_the_approval_wait_after_the_press_and_the_new_daemon(self):
        for swap_after, expected in ((2, ["approval-wait deadline", "approval-seen"]), (10 ** 6, ["approval-wait deadline"])):
            with self.subTest(swap_after=swap_after), tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
                session, _, _ = corpus.DriverTests.update_session(None, directory, swap_after=swap_after)
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr), contextlib.suppress(corpus.LIVE.RowFailure):
                    session.update_row("full4")
                self.assertEqual(events(stderr.getvalue()), expected)
                if swap_after > 2:
                    self.assertEqual(session.row_observation["update"]["finishPressed"], True)


if __name__ == "__main__":
    unittest.main()
