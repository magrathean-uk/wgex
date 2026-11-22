#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Self-driven guest console (M03-T07 phase B, DEC-034): the lab guest's administrator approval and console login, typed
through the VNC server Tart starts when WGEX_LAB_VNC_FILE is set (Tools/lab/tart/snapshot.sh).

  console.py shot --vnc-file F OUT.png
  console.py login --vnc-file F --login-file L [--user NAME] [--not-before EPOCH] [--deadline EPOCH] [--shots DIR]
  console.py approve --vnc-file F --login-file L [--deadline EPOCH] [--shots DIR]

The password is read from the login file at the moment of use and goes only into the VNC key events; it is never printed,
logged, put on a command line or written anywhere. The caller (the row driver) decides when typing is safe: `login` only
while the guest console is logged out, `approve` only while SecurityAgent shows its window. Framebuffer captures go to
--shots (the caller points it at $TMPDIR, never the tree). One result line goes to stdout: `console=<action> result=<word>`."""
import argparse
import os
import re
import stat
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rfb  # noqa: E402

VNC_LINE = re.compile(r"vnc://:([^@\s]+)@127\.0\.0\.1:(\d{1,5})\b")
LOGIN_WINDOW_SETTLE = 30.0


class ConsoleError(RuntimeError):
    """Named failure; the message never carries a secret."""


def private_file(path):
    """The file must be a regular file owned by this user and unreadable by others (it carries a secret)."""
    try:
        info = os.lstat(path)
    except OSError as error:
        raise ConsoleError(f"{Path(path).name} unreadable") from error
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ConsoleError(f"{Path(path).name} must be a regular 0600 file owned by this user")
    return Path(path).read_text(errors="replace")


def vnc_endpoint(path):
    """(port, one-time password) from Tart's `VNC server is running at vnc://:PASSWORD@127.0.0.1:PORT` line."""
    match = VNC_LINE.search(private_file(path))
    if not match:
        raise ConsoleError("no vnc:// address in the VNC file yet")
    port = int(match[2])
    if not 0 < port < 65536:
        raise ConsoleError("VNC port out of range")
    return port, match[1]


def login_secret(path, user):
    """The guest password from the lab login file (`user: NAME` and `password: VALUE` lines); the file's user must match."""
    fields = {}
    for line in private_file(path).splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip().lower()] = value.strip()
    if fields.get("user") != user:
        raise ConsoleError("login file names another user")
    if not fields.get("password"):
        raise ConsoleError("login file has no password line")
    return fields["password"]


def before_deadline(deadline, step):
    """Raises once the deadline has passed; called right before anything that types the password."""
    if time.time() >= deadline:
        raise ConsoleError(f"deadline passed {step}")


def connect(vnc_file, deadline, factory=rfb.Client):
    """Connect, retrying while Tart has not yet published its address or the server is not yet listening. Each attempt
    (TCP connect, authentication) is bounded by the deadline, and so is the session it returns."""
    last = "no attempt"
    while True:
        if time.time() >= deadline:
            raise ConsoleError(f"VNC connect failed: {last}")
        try:
            port, password = vnc_endpoint(vnc_file)
            return factory("127.0.0.1", port, password, deadline=deadline)
        except (ConsoleError, OSError, rfb.RFBError) as error:
            last = str(error) if isinstance(error, (ConsoleError, rfb.RFBError)) else type(error).__name__
        remaining = deadline - time.time()
        if remaining <= 0:
            raise ConsoleError(f"VNC connect failed: {last}")
        time.sleep(min(2.0, remaining))


class Shots:
    """Numbered framebuffer captures in a caller-chosen directory ($TMPDIR); disabled without one."""

    def __init__(self, directory, action):
        self.directory, self.action, self.count = (Path(directory) if directory else None), action, 0

    def take(self, client, label):
        width, height, pixels = client.refresh()
        if self.directory:
            self.count += 1
            self.directory.mkdir(parents=True, exist_ok=True)
            path = self.directory / f"{self.action}-{self.count:02d}-{label}.png"
            path.write_bytes(rfb.png_bytes(width, height, pixels))
            os.chmod(path, 0o600)
        return width, height, pixels


def wait_until(moment, clock=time.time, sleep=time.sleep):
    while clock() < moment:
        sleep(min(1.0, moment - clock()))


def after_typing(client, shots):
    """The password is out: the deadline guarded typing only, so the closing capture is not cut short by it."""
    client.deadline = None
    time.sleep(3.0)
    shots.take(client, "after")


def do_login(client, secret, shots, deadline):
    """macOS 26 login window of the single-user lab guest (seen live): the user's picture with its "Enter Password"
    field, which has the keyboard focus. Escape clears anything typed into it; then the password and Return. The deadline
    is checked again right before the password goes out (the capture and the pause can use up the window)."""
    shots.take(client, "before")
    before_deadline(deadline, "before typing")
    client.tap("Escape")
    time.sleep(1.0)
    before_deadline(deadline, "before typing")
    client.type_text(secret)
    client.tap("Return")
    after_typing(client, shots)


def do_approve(client, secret, shots, deadline):
    """SecurityAgent's administrator dialog: the user name is filled and the password field has the focus."""
    shots.take(client, "before")
    before_deadline(deadline, "before typing")
    client.type_text(secret)
    client.tap("Return")
    after_typing(client, shots)


def main(argv=None, factory=rfb.Client):
    parser = argparse.ArgumentParser(description="self-driven lab guest console (DEC-034)")
    parser.add_argument("action", choices=("shot", "login", "approve"))
    parser.add_argument("out", nargs="?")
    parser.add_argument("--vnc-file", required=True)
    parser.add_argument("--login-file", default=os.environ.get("WGEX_LAB_LOGIN_FILE") or os.path.join(os.environ.get("WGEX_LAB_VM_ROOT") or os.path.expanduser("~/wgex-lab-vm"), "lab-login"))
    parser.add_argument("--user", default=os.environ.get("WGEX_LAB_USER", "labuser"))
    parser.add_argument("--not-before", type=float, default=0.0)
    parser.add_argument("--deadline", type=float, default=0.0)
    parser.add_argument("--shots")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", args.user):
        parser.error("user must be a short account name")
    deadline = args.deadline or time.time() + 120
    try:
        if args.action == "shot":
            if not args.out:
                parser.error("shot needs OUT.png")
            client = connect(args.vnc_file, deadline, factory)
            try:
                width, height, pixels = client.refresh()
            finally:
                client.close()
            Path(args.out).write_bytes(rfb.png_bytes(width, height, pixels))
            os.chmod(args.out, 0o600)
            print(f"console=shot result=written size={width}x{height}")
            return 0
        wait_until(args.not_before)
        before_deadline(deadline, "before typing")
        client = connect(args.vnc_file, deadline, factory)
        shots = Shots(args.shots, args.action)
        try:
            secret = login_secret(args.login_file, args.user)
            if args.action == "login":
                do_login(client, secret, shots, deadline)
            else:
                do_approve(client, secret, shots, deadline)
            secret = None
        finally:
            client.close()
        print(f"console={args.action} result=typed")
        return 0
    except (ConsoleError, rfb.RFBError, OSError) as error:
        detail = str(error) if isinstance(error, (ConsoleError, rfb.RFBError)) else type(error).__name__
        print(f"console={args.action} result=failed reason={detail[:120]}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
