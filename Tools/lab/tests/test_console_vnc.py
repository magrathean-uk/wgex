# SPDX-License-Identifier: MIT
"""M03-T07 phase B (DEC-034): the self-driven guest console. The stdlib RFB client (DES challenge, handshake, raw
framebuffer, key events), console.py's secret handling and timing, the driver's console steps at the logout and
administrator-approval moments, and gap-actions' agent-state read. Never a VM, never a real password."""
import contextlib
import io
import json
import os
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

import test_gap_rows as gap
import test_login_silent as silent
import test_update_corpus as corpus

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB / "console"))
import console  # noqa: E402
import rfb  # noqa: E402

LIVE = gap.LIVE
SECRET = "Xy345678"  # a made-up value of the lab password's shape (letters and digits)


def private(directory, name, text, mode=0o600):
    path = Path(directory) / name
    path.write_text(text)
    os.chmod(path, mode)
    return str(path)


class DesTests(unittest.TestCase):
    def test_des_matches_the_fips_vector(self):
        self.assertEqual(rfb.des_encrypt_block(bytes.fromhex("133457799BBCDFF1"), bytes.fromhex("0123456789ABCDEF")).hex(),
                         "85e813540f0ab405")

    def test_vnc_response_reverses_key_bits_and_matches_openssl(self):
        # openssl enc -des-ecb -nopad -K <bit-reversed "password"> over bytes 0..15 gives this value.
        self.assertEqual(rfb.vnc_auth_response("password", bytes(range(16))).hex(), "b866924125c8eebb9debc1db61c538e2")
        # Only the first 8 bytes count; a short password is zero padded.
        self.assertEqual(rfb.vnc_auth_response("password-extra", bytes(range(16))), rfb.vnc_auth_response("password", bytes(range(16))))
        self.assertNotEqual(rfb.vnc_auth_response("pass", bytes(16)), rfb.vnc_auth_response("pass\0x", bytes(16)))
        with self.assertRaises(ValueError):
            rfb.vnc_auth_response("password", bytes(15))


class KeystrokeTests(unittest.TestCase):
    def test_uppercase_and_shifted_symbols_hold_shift_and_digits_do_not(self):
        self.assertEqual(rfb.keystrokes("aB1!"), [(0x61, False), (0x42, True), (0x31, False), (0x21, True)])

    def test_characters_that_differ_between_us_and_british_layouts_are_refused(self):
        for char in '@"#~\\|`£\n\t':
            with self.subTest(char=char), self.assertRaises(ValueError):
                rfb.keystrokes("a" + char)


class FakeServer:
    """One end of a socket pair speaking the server side of RFB 3.8 with VNC authentication."""

    def __init__(self, password, version=b"RFB 003.008\n", types=(2,), fail_auth=False, size=(4, 2)):
        self.client_end, self.server_end = socket.socketpair()
        self.password, self.version, self.types, self.fail_auth, self.size = password, version, types, fail_auth, size
        self.received, self.response_ok, self.error = bytearray(), None, None
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def recv(self, count):
        data = bytearray()
        while len(data) < count:
            chunk = self.server_end.recv(count - len(data))
            if not chunk:
                raise EOFError
            data += chunk
        return bytes(data)

    def serve(self):
        try:
            s = self.server_end
            s.sendall(self.version)
            self.recv(12)
            s.sendall(bytes([len(self.types), *self.types]))
            chosen = self.recv(1)[0]
            if chosen == 2:
                challenge = bytes(range(100, 116))
                s.sendall(challenge)
                self.response_ok = self.recv(16) == rfb.vnc_auth_response(self.password, challenge)
                if self.fail_auth or not self.response_ok:
                    s.sendall(struct.pack(">I", 1) + struct.pack(">I", 6) + b"denied")
                    return
            s.sendall(struct.pack(">I", 0))
            self.recv(1)
            width, height = self.size
            s.sendall(struct.pack(">HH", width, height) + bytes(16) + struct.pack(">I", 4) + b"wgex")
            self.received += self.recv(20)  # SetPixelFormat
            self.received += self.recv(12)  # SetEncodings with two encodings
            while True:
                kind = self.recv(1)
                if kind == b"\x03":
                    self.recv(9)
                    s.sendall(b"\x02")  # a Bell first: skipped by the client
                    pixels = bytes([10, 20, 30, 0] * (width * height))
                    s.sendall(struct.pack(">BxH", 0, 2) + struct.pack(">HHHHi", 0, 0, width, height, -223)
                              + struct.pack(">HHHHi", 0, 0, width, height, 0) + pixels)
                elif kind == b"\x04":
                    self.received += kind + self.recv(7)
                elif kind == b"\x05":
                    self.received += kind + self.recv(5)
                else:
                    return
        except (EOFError, OSError) as error:
            self.error = error

    def keys(self):
        """(down, keysym) for each key event the client sent."""
        events, data, index = [], bytes(self.received), 32
        while index < len(data):
            if data[index] == 4:
                down, keysym = struct.unpack(">BxxI", data[index + 1:index + 8])
                events.append((down, keysym))
                index += 8
            else:
                index += 6
        return events


class ClientTests(unittest.TestCase):
    def connect(self, server, password=SECRET):
        self.addCleanup(server.server_end.close)
        self.addCleanup(server.client_end.close)
        return rfb.Client("127.0.0.1", 0, password, sock=server.client_end, key_delay=0)

    def test_handshake_authenticates_and_requests_raw_32_bit_pixels(self):
        server = FakeServer(SECRET)
        client = self.connect(server)
        self.assertTrue(server.response_ok)
        self.assertEqual((client.width, client.height, client.name), (4, 2, "wgex"))
        width, height, pixels = client.refresh()
        self.assertEqual((width, height, pixels[:4]), (4, 2, bytes([10, 20, 30, 0])))
        client.close()
        server.thread.join(5)
        pixel_format = bytes(server.received[:20])
        self.assertEqual(pixel_format[0], 0)
        self.assertEqual(pixel_format[4:8], bytes([32, 24, 0, 1]))
        self.assertEqual(struct.unpack(">BxHii", bytes(server.received[20:32])), (2, 2, 0, -223))

    def test_typing_sends_press_and_release_with_shift_around_capitals(self):
        server = FakeServer(SECRET)
        client = self.connect(server)
        client.type_text("aB")
        client.tap("Return")
        client.close()
        server.thread.join(5)
        shift = rfb.KEYSYMS["Shift"]
        self.assertEqual(server.keys(), [(1, 0x61), (0, 0x61), (1, shift), (1, 0x42), (0, 0x42), (0, shift),
                                         (1, 0xFF0D), (0, 0xFF0D)])

    def test_a_wrong_password_or_unknown_security_type_is_refused(self):
        server = FakeServer("other-pw")
        with self.assertRaisesRegex(rfb.RFBError, "authentication failed"):
            self.connect(server)
        server = FakeServer(SECRET, types=(16,))
        with self.assertRaisesRegex(rfb.RFBError, "no supported security type"):
            self.connect(server)
        server = FakeServer(SECRET, version=b"XYZ 003.008\n")
        with self.assertRaisesRegex(rfb.RFBError, "not an RFB server"):
            self.connect(server)

    def test_png_is_rgb_from_bgrx(self):
        data = rfb.png_bytes(2, 1, bytes([1, 2, 3, 0, 4, 5, 6, 0]))
        self.assertTrue(data.startswith(b"\x89PNG\r\n\x1a\n"))
        start = data.index(b"IDAT") + 4
        length = struct.unpack(">I", data[start - 8:start - 4])[0]
        self.assertEqual(zlib.decompress(data[start:start + length]), bytes([0, 3, 2, 1, 6, 5, 4]))


class ConsoleFileTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(dir=os.environ["TMPDIR"])
        self.addCleanup(subprocess.run, ["rm", "-rf", self.dir])

    def test_vnc_endpoint_reads_tarts_line_on_loopback_only(self):
        path = private(self.dir, "vnc.txt", "VNC server is running at vnc://:able-baker-charlie-delta@127.0.0.1:60057\n")
        self.assertEqual(console.vnc_endpoint(path), (60057, "able-baker-charlie-delta"))
        path = private(self.dir, "remote.txt", "VNC server is running at vnc://:pw@192.0.2.1:5900\n")
        with self.assertRaisesRegex(console.ConsoleError, "no vnc:// address"):
            console.vnc_endpoint(path)

    def test_secret_files_must_be_private_regular_files(self):
        loose = private(self.dir, "loose.txt", "user: labuser\npassword: x\n", mode=0o644)
        with self.assertRaisesRegex(console.ConsoleError, "0600"):
            console.login_secret(loose, "labuser")
        link = Path(self.dir) / "link.txt"
        link.symlink_to(private(self.dir, "target.txt", "user: labuser\npassword: x\n"))
        with self.assertRaisesRegex(console.ConsoleError, "0600"):
            console.login_secret(str(link), "labuser")
        with self.assertRaisesRegex(console.ConsoleError, "unreadable"):
            console.login_secret(str(Path(self.dir) / "missing"), "labuser")

    def test_login_secret_needs_the_matching_user_and_a_password(self):
        good = private(self.dir, "login.txt", f"user: labuser\npassword: {SECRET}\n")
        self.assertEqual(console.login_secret(good, "labuser"), SECRET)
        with self.assertRaisesRegex(console.ConsoleError, "another user") as raised:
            console.login_secret(good, "admin")
        self.assertNotIn(SECRET, str(raised.exception))
        with self.assertRaisesRegex(console.ConsoleError, "no password"):
            console.login_secret(private(self.dir, "nopw.txt", "user: labuser\n"), "labuser")


class FakeClient:
    instances = []

    def __init__(self, host, port, password, deadline=None):
        self.host, self.port, self.vnc_password, self.events, self.closed = host, port, password, [], False
        self.deadline = deadline
        FakeClient.instances.append(self)

    def refresh(self):
        self.events.append(("refresh",))
        return 2, 1, bytes(8)

    def tap(self, name, shift=False):
        self.events.append(("tap", name))

    def type_text(self, text):
        self.events.append(("type", text))

    def close(self):
        self.closed = True


class ConsoleMainTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(dir=os.environ["TMPDIR"])
        self.addCleanup(subprocess.run, ["rm", "-rf", self.dir])
        self.vnc = private(self.dir, "vnc.txt", "VNC server is running at vnc://:able-baker@127.0.0.1:60057\n")
        self.login = private(self.dir, "login.txt", f"user: labuser\npassword: {SECRET}\n")
        FakeClient.instances = []
        sleeps = patch.object(console.time, "sleep", lambda seconds: None)
        sleeps.start()
        self.addCleanup(sleeps.stop)

    def run_main(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = console.main(list(argv), factory=FakeClient)
        self.assertNotIn(SECRET, out.getvalue())
        return code, out.getvalue().strip()

    def test_login_types_escape_the_password_and_return_and_keeps_captures_private(self):
        shots = Path(self.dir) / "shots"
        code, line = self.run_main("login", "--vnc-file", self.vnc, "--login-file", self.login, "--shots", str(shots),
                                   "--deadline", str(time.time() + 60))
        self.assertEqual((code, line), (0, "console=login result=typed"))
        client = FakeClient.instances[0]
        self.assertEqual((client.host, client.port, client.vnc_password, client.closed), ("127.0.0.1", 60057, "able-baker", True))
        typed = [event for event in client.events if event[0] != "refresh"]
        self.assertEqual(typed, [("tap", "Escape"), ("type", SECRET), ("tap", "Return")])
        files = sorted(shots.iterdir())
        self.assertEqual([path.name for path in files], ["login-01-before.png", "login-02-after.png"])
        self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in files))

    def test_approve_types_the_password_and_return_only(self):
        code, line = self.run_main("approve", "--vnc-file", self.vnc, "--login-file", self.login)
        self.assertEqual((code, line), (0, "console=approve result=typed"))
        typed = [event for event in FakeClient.instances[0].events if event[0] != "refresh"]
        self.assertEqual(typed, [("type", SECRET), ("tap", "Return")])

    def test_nothing_is_typed_after_the_deadline_or_for_another_user(self):
        code, line = self.run_main("login", "--vnc-file", self.vnc, "--login-file", self.login, "--deadline", str(time.time() - 1))
        self.assertEqual((code, line), (1, "console=login result=failed reason=deadline passed before typing"))
        self.assertEqual(FakeClient.instances, [])
        code, line = self.run_main("login", "--vnc-file", self.vnc, "--login-file", self.login, "--user", "admin")
        self.assertEqual((code, line), (1, "console=login result=failed reason=login file names another user"))
        self.assertEqual([event for event in FakeClient.instances[0].events if event[0] != "refresh"], [])
        self.assertTrue(FakeClient.instances[0].closed)

    def test_typing_waits_for_not_before(self):
        clock = [1000.0]
        waited = []
        console.wait_until(1030.0, clock=lambda: clock[0], sleep=lambda s: (waited.append(s), clock.__setitem__(0, clock[0] + s)))
        self.assertEqual(clock[0], 1030.0)
        self.assertTrue(all(step <= 1.0 for step in waited))

    def test_connect_retries_until_tart_publishes_then_fails_by_name(self):
        empty = private(self.dir, "empty.txt", "")
        with patch.object(console.time, "time", side_effect=[0, 1, 99999]):
            with self.assertRaisesRegex(console.ConsoleError, "VNC connect failed: no vnc:// address"):
                console.connect(empty, 10, FakeClient)

    def test_the_cli_never_takes_a_password_argument(self):
        source = (LAB / "console" / "console.py").read_text()
        self.assertNotIn("--password", source)
        self.assertNotIn("print(secret", source)


class Clock:
    """A fake epoch clock for console.py and rfb.py (both read time.time)."""

    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now


class SlowClient(FakeClient):
    """Connect, refresh or the post-Escape pause takes `delay` seconds of the fake clock at the named step."""
    clock, slow_step, delay = None, None, 0.0

    def __init__(self, host, port, password, deadline=None):
        if self.slow_step == "connect":
            self.clock.now += self.delay
        super().__init__(host, port, password, deadline)

    def refresh(self):
        if self.slow_step == "refresh":
            self.clock.now += self.delay
        return super().refresh()


class ConsoleDeadlineTests(unittest.TestCase):
    """REV-M03-T07 b4 item 2: the typing deadline holds across connect retries, authentication and the framebuffer
    capture, and is checked again right before the password goes out in both paths."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(dir=os.environ["TMPDIR"])
        self.addCleanup(subprocess.run, ["rm", "-rf", self.dir])
        self.vnc = private(self.dir, "vnc.txt", "VNC server is running at vnc://:able-baker@127.0.0.1:60057\n")
        self.login = private(self.dir, "login.txt", f"user: labuser\npassword: {SECRET}\n")
        self.clock = Clock()
        FakeClient.instances = []
        SlowClient.clock = self.clock
        for target, value in ((console.time, "time"), (rfb.time, "time")):
            patcher = patch.object(target, value, self.clock)
            patcher.start()
            self.addCleanup(patcher.stop)
        sleeps = patch.object(console.time, "sleep", lambda seconds: setattr(self.clock, "now", self.clock.now + seconds))
        sleeps.start()
        self.addCleanup(sleeps.stop)

    def run_slow(self, action, step, delay, window=60.0):
        SlowClient.slow_step, SlowClient.delay = step, delay
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = console.main([action, "--vnc-file", self.vnc, "--login-file", self.login,
                                 "--deadline", str(self.clock.now + window)], factory=SlowClient)
        self.assertNotIn(SECRET, out.getvalue())
        return code, out.getvalue().strip()

    def typed(self):
        return [event for client in FakeClient.instances for event in client.events if event[0] == "type"]

    def test_a_delayed_connect_types_nothing_after_expiry_in_both_paths(self):
        for action in ("login", "approve"):
            with self.subTest(action=action):
                FakeClient.instances = []
                code, line = self.run_slow(action, "connect", 61.0)
                self.assertEqual((code, line), (1, f"console={action} result=failed reason=deadline passed before typing"))
                self.assertEqual(self.typed(), [])
                self.assertTrue(FakeClient.instances[0].closed)

    def test_a_delayed_refresh_types_nothing_after_expiry_in_both_paths(self):
        for action in ("login", "approve"):
            with self.subTest(action=action):
                FakeClient.instances = []
                code, line = self.run_slow(action, "refresh", 61.0)
                self.assertEqual((code, line), (1, f"console={action} result=failed reason=deadline passed before typing"))
                self.assertEqual(self.typed(), [])
                self.assertEqual([event for event in FakeClient.instances[0].events if event[0] == "tap"], [])

    def test_the_login_pause_after_escape_is_checked_before_the_password(self):
        # 0.5 s of window left after the capture: Escape goes out, the 1 s pause expires it, the password does not.
        code, line = self.run_slow("login", "refresh", 59.5)
        self.assertEqual((code, line), (1, "console=login result=failed reason=deadline passed before typing"))
        self.assertEqual([event for event in FakeClient.instances[0].events if event[0] != "refresh"], [("tap", "Escape")])

    def test_within_the_window_the_password_is_typed_and_the_closing_capture_is_not_bound(self):
        code, line = self.run_slow("approve", "refresh", 10.0, window=15.0)
        self.assertEqual((code, line), (0, "console=approve result=typed"))
        client = FakeClient.instances[0]
        self.assertEqual(self.typed(), [("type", SECRET)])
        self.assertIsNone(client.deadline)

    def test_connect_hands_the_deadline_to_each_attempt_and_stops_retrying_at_it(self):
        empty = private(self.dir, "empty.txt", "")
        with self.assertRaisesRegex(console.ConsoleError, "VNC connect failed: no vnc:// address"):
            console.connect(empty, self.clock.now + 5, FakeClient)
        self.assertLessEqual(self.clock.now, 1005.0 + 1e-9)
        client = console.connect(self.vnc, self.clock.now + 5, FakeClient)
        self.assertEqual(client.deadline, self.clock.now + 5)


class StallingServer:
    """Speaks RFB 3.8 with no authentication up to `stall` ("banner" or "refresh"), then goes silent."""

    def __init__(self, stall):
        self.client_end, self.server_end = socket.socketpair()
        self.stall = stall
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        s = self.server_end
        try:
            if self.stall == "banner":
                s.recv(1)
                return
            s.sendall(b"RFB 003.008\n")
            s.recv(12)
            s.sendall(bytes([1, 1]))
            s.recv(1)
            s.sendall(struct.pack(">I", 0))
            s.recv(1)
            s.sendall(struct.pack(">HH", 2, 1) + bytes(16) + struct.pack(">I", 0))
            s.recv(1024)
            s.recv(1)
        except OSError:
            pass


class ClientDeadlineTests(unittest.TestCase):
    """The RFB client stops waiting at the deadline on a server that stalls in the handshake or the refresh."""

    def session(self, stall, window):
        server = StallingServer(stall)
        self.addCleanup(server.server_end.close)
        self.addCleanup(server.client_end.close)
        return server, time.time() + window

    def test_a_stalled_handshake_fails_at_the_deadline(self):
        server, deadline = self.session("banner", 0.4)
        started = time.monotonic()
        with self.assertRaisesRegex(rfb.RFBError, "deadline passed|timed out"):
            rfb.Client("127.0.0.1", 0, SECRET, sock=server.client_end, key_delay=0, deadline=deadline)
        self.assertLess(time.monotonic() - started, 5)

    def test_a_stalled_refresh_fails_at_the_deadline_and_later_keys_are_refused(self):
        server, deadline = self.session("refresh", 0.6)
        client = rfb.Client("127.0.0.1", 0, SECRET, sock=server.client_end, key_delay=0, deadline=deadline)
        started = time.monotonic()
        with self.assertRaisesRegex(rfb.RFBError, "deadline passed|timed out"):
            client.refresh()
        self.assertLess(time.monotonic() - started, 5)
        while time.time() < deadline:
            time.sleep(0.05)
        with self.assertRaisesRegex(rfb.RFBError, "deadline passed"):
            client.type_text("a")


class PrivateOutputTests(unittest.TestCase):
    """REV-M03-T07 b4 item 1: the VNC file Tart writes its one-time password into is validated through the open
    descriptor (lib.sh lab_private_output) before anything is written; umask alone never changed an existing file."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=os.environ["TMPDIR"]))
        self.addCleanup(subprocess.run, ["rm", "-rf", str(self.dir)])

    def open_private(self, path):
        script = 'source "$1"; lab_private_output "$2"; printf "vnc://:secret-pw@127.0.0.1:5900\\n" >&9'
        return subprocess.run(["bash", "-c", script, "_", str(LAB / "tart" / "lib.sh"), str(path)],
                              capture_output=True, text=True, timeout=60)

    def test_an_existing_0644_file_is_restricted_and_emptied_before_the_write(self):
        path = self.dir / "vnc.txt"
        path.write_text("stale line from an earlier run\n")
        os.chmod(path, 0o644)
        result = self.open_private(path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(path.read_text(), "vnc://:secret-pw@127.0.0.1:5900\n")

    def test_a_missing_file_is_created_0600(self):
        path = self.dir / "new.txt"
        result = self.open_private(path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(console.vnc_endpoint(str(path)), (5900, "secret-pw"))

    def test_non_regular_targets_are_refused_and_never_written(self):
        target = self.dir / "target.txt"
        target.write_text("untouched\n")
        os.chmod(target, 0o644)
        link = self.dir / "link.txt"
        link.symlink_to(target)
        hard = self.dir / "hard.txt"
        os.link(target, hard)
        directory = self.dir / "dir"
        directory.mkdir()
        fifo = self.dir / "fifo"
        os.mkfifo(fifo, 0o600)
        cases = {link: "is a link", directory: "not a regular file", fifo: "not a regular file",
                 hard: "not a private regular file", self.dir / "missing" / "vnc.txt": "directory missing",
                 Path("relative.txt"): "absolute path"}
        for path, reason in cases.items():
            with self.subTest(path=path.name):
                result = self.open_private(path)
                self.assertEqual(result.returncode, 1)
                self.assertIn(reason, result.stderr)
                self.assertNotIn("secret-pw", result.stderr + result.stdout)
        self.assertEqual(target.read_text(), "untouched\n")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)
        self.assertFalse((self.dir / "missing").exists())
        self.assertFalse(Path("relative.txt").exists())

    def test_snapshot_starts_tart_on_the_validated_descriptor_only(self):
        # The headless start with the VNC console moved into lab_start (DEC-112); snapshot.sh calls it.
        self.assertIn("\nlab_start\nlab_wait_ready", (LAB / "tart" / "snapshot.sh").read_text())
        source = (LAB / "tart" / "lib.sh").read_text()
        block = source[source.index("lab_start() {"):source.index("\n}\n", source.index("lab_start() {"))]
        self.assertIn('lab_private_output "$file"', block)
        self.assertIn(">&9 2>&1 9>&- &", block)
        self.assertIn("exec 9>&-", block)
        self.assertNotIn('>"$file"', block)
        self.assertNotIn("umask", block)


class FakeProcess:
    def __init__(self, out=b"console=login result=typed\n", hang=False, code=0):
        self.out, self.hang, self.returncode, self.killed = out, hang, code, False

    def communicate(self, timeout=None):
        if self.hang and not self.killed:
            raise subprocess.TimeoutExpired("console.py", timeout)
        return self.out, b""

    def kill(self):
        self.killed, self.returncode = True, -9


class ConsoleDriverTests(unittest.TestCase):
    def driver(self, process):
        calls = []

        def popen(argv, **kw):
            calls.append((argv, kw))
            return process
        return LIVE.ConsoleDriver("/tmp/vnc.txt", shots="/tmp/shots", popen=popen, clock=lambda: 0), calls

    def test_off_without_the_variable_and_refuses_a_relative_path(self):
        self.assertIsNone(LIVE.ConsoleDriver.from_environment("lab-x", {}))
        with self.assertRaises(ValueError):
            LIVE.ConsoleDriver.from_environment("lab-x", {"WGEX_LAB_VNC_FILE": "vnc.txt"})
        driver = LIVE.ConsoleDriver.from_environment("lab-x", {"WGEX_LAB_VNC_FILE": "/t/vnc.txt", "TMPDIR": "/t/tmp"})
        self.assertEqual((driver.vnc_file, driver.shots), ("/t/vnc.txt", "/t/tmp/wgex-console/lab-x"))

    def test_start_passes_files_and_times_never_a_password_and_finish_records_the_result(self):
        driver, calls = self.driver(FakeProcess())
        driver.start("login", 30, 120)
        argv, kw = calls[0]
        self.assertEqual(argv[1:4], ["-I", str(LIVE.CONSOLE_SCRIPT), "login"])
        self.assertIn("--vnc-file", argv)
        self.assertNotIn("--login-file", argv)
        self.assertEqual(argv[argv.index("--not-before") + 1], "30.000")
        self.assertEqual(kw["stdin"], subprocess.DEVNULL)
        item = driver.finish()
        self.assertEqual((item["action"], item["result"], item["exitCode"], item["notBefore"]), ("login", "typed", 0, "1970-01-01T00:00:30Z"))
        self.assertIsNone(driver.finish())

    def test_a_hung_step_is_killed_and_a_failure_keeps_its_reason(self):
        driver, _ = self.driver(FakeProcess(hang=True))
        driver.start("approve", 0, 300)
        self.assertEqual(driver.finish(timeout=0)["result"], "killed")
        driver, _ = self.driver(FakeProcess(out=b"console=login result=failed reason=VNC connect failed: x\n", code=1))
        driver.start("login", 0, 1)
        item = driver.finish()
        self.assertEqual((item["result"], item["reason"], item["exitCode"]), ("failed", "VNC connect failed: x", 1))
        driver, _ = self.driver(FakeProcess(out=b"Traceback\n"))
        driver.start("login", 0, 1)
        self.assertEqual(driver.finish()["result"], "unreadable")


class RecordingConsole:
    def __init__(self):
        self.events, self.log = [], []

    def start(self, action, not_before, deadline):
        self.events.append(("start", action, not_before, deadline))

    def finish(self, timeout=None):
        self.events.append(("finish",))
        return dict(action="login", result="typed")


class DriverStepTests(unittest.TestCase):
    def test_login_silent_starts_one_login_per_logout_30_s_after_it_and_reaps_it(self):
        recorder = RecordingConsole()
        with patch.object(LIVE.time, "time", lambda: 5000.0), contextlib.redirect_stderr(io.StringIO()):
            live, _, _ = silent.driven(silent.Guest(), console=recorder)
        self.assertEqual([event[:2] for event in recorder.events], [("start", "login"), ("finish",)] * 2)
        self.assertEqual(recorder.events[0][2:], (5000.0 + LIVE.CONSOLE_LOGIN_SETTLE_SECONDS,
                                                  5000.0 + LIVE.CONSOLE_LOGIN_SETTLE_SECONDS + LIVE.CONSOLE_LOGIN_TYPE_SECONDS))
        self.assertEqual(sum("consoleStep" in item for item in live.ledger), 2)

    def test_a_missed_login_still_reaps_the_console_step(self):
        guest = silent.Guest()
        guest.relogin = False
        recorder = RecordingConsole()
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(silent.LIVE.RowFailure):
            silent.driven(guest, console=recorder)
        self.assertEqual([event[:2] for event in recorder.events], [("start", "login"), ("finish",)])

    def test_without_a_console_nothing_is_started(self):
        with contextlib.redirect_stderr(io.StringIO()):
            live, _, _ = silent.driven(silent.Guest())
        self.assertIsNone(live.console)
        self.assertFalse(any("consoleStep" in item for item in live.ledger))

    def test_m53_09_types_each_login_only_after_the_logged_out_measurement(self):
        recorder = RecordingConsole()
        order = []
        session = object.__new__(LIVE.Session)
        session.row_observation, session.profile_ids, session.ledger = {}, {"full4": "00000000-0000-4000-8000-000000000001"}, []
        session.console = type("Console", (), dict(start=lambda self, *a: order.append("start"), finish=lambda self: order.append("finish")))()
        console_states = iter([b"logged-out", b"lab", b"logged-out", b"lab"])
        session.runner = type("Clock", (), dict(monotonic=lambda self: 1000))()
        session.gap_action = lambda name, *a, **kw: next(console_states) if name == "console-user" else b""
        session.set_startup_off = session.set_startup_boot = lambda identity: None
        intents = iter([False, True])
        session.boot_intent = lambda identity: next(intents)
        session.await_status = lambda *a, **kw: None
        session.status = lambda: dict(phase="active", protection="protected")
        session.lab = session.connect = lambda *a: None
        session.observe = lambda: (order.append("observe"), dict(status=dict(protection="unprotected"), referenceCount=0))[1]
        session.generate = lambda state, **kw: dict(state=state, **kw)
        with contextlib.redirect_stderr(io.StringIO()):
            session.logout_row("full4")
        self.assertEqual(order, ["observe", "start", "finish"] * 2)

    def test_m53_07_types_the_approval_only_once_securityagent_shows_its_window(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            session, calls, _ = corpus.DriverTests.update_session(None, directory, swap_after=4)
            recorder = RecordingConsole()
            session.console, session.ledger = recorder, []
            replies = iter([b"agent=absent\n", b"agent=running windows=0\n", b"agent=running windows=1\n"])
            reads = []
            session.gap_action = lambda name, *a, **kw: (reads.append(name), next(replies))[1]
            with contextlib.redirect_stderr(io.StringIO()):
                session.update_row("full4")
        self.assertEqual(reads, ["agent-state"] * 3)
        self.assertEqual([event[:2] for event in recorder.events], [("start", "approve"), ("finish",)])

    def test_m53_07_failure_still_reaps_the_approval_step(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            session, _, _ = corpus.DriverTests.update_session(None, directory, swap_after=10 ** 6)
            recorder = RecordingConsole()
            session.console, session.ledger = recorder, []
            session.gap_action = lambda name, *a, **kw: b"agent=running windows=1\n"
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(corpus.LIVE.RowFailure):
                session.update_row("full4")
        self.assertEqual([event[:2] for event in recorder.events], [("start", "approve"), ("finish",)])


class AgentStateActionTests(unittest.TestCase):
    def run_state(self, running, osascript_reply="1", osascript_ok=True):
        stub = f'''
id() {{ echo 501; }}
pgrep() {{ {"echo 777" if running else "return 1"}; }}
sudo() {{ case "$*" in *osascript*) {"printf '%s\\n' " + json.dumps(osascript_reply) if osascript_ok else "return 1"} ;; *) return 9 ;; esac; }}
'''
        return silent.GuestActionTests.run_action(None, "agent-state", stub=stub)

    def test_agent_state_prints_fixed_words(self):
        self.assertEqual(self.run_state(False).stdout, "agent=absent\n")
        self.assertEqual(self.run_state(True).stdout, "agent=running windows=1\n")
        self.assertEqual(self.run_state(True, osascript_ok=False).stdout, "agent=running windows=unreadable\n")
        self.assertEqual(self.run_state(True, osascript_reply="1; injected").stdout, "agent=running windows=unreadable\n")


if __name__ == "__main__":
    unittest.main()
