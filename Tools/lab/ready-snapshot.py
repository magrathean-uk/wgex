#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""M03-T10: makes the macOS 27 `ready` snapshot (`macos27-ready`) from `macos27-base`, the macOS 27 counterpart of the
macOS 26 ready11 recipe (Tools/lab/tart/README.md, "macOS 27 guest").

Run with WGEX_LAB_VM=macos27-wgex WGEX_LAB_USER=admin WGEX_LAB_SNAPSHOT_PREFIX=macos27- and
WGEX_LAB_GUEST_PASSWORD_FILE (the image's public default, for the Login Items sheet only; DEC-034):

  python3 -I -B Tools/lab/ready-snapshot.py --out DIR [--snapshot NAME]

--snapshot NAME (default `ready`, so `macos27-ready`) names the snapshot to take, validated like any lab snapshot name
(letters, digits, `_` and `-`, starting with a letter or digit); `base` and `wgex` are refused because the lab would
refuse them after the whole run. An existing name is refused by `just lab snapshot`, never replaced.

It restores `macos27-base`, builds the Lab app and installs it with the lab wrapping-key escrow
(`guest/wrapping-key.sh`, "provisioned and escrowed"): DEC-007's stable lab signing. No authorizationdb row is written
and no password is typed into a WGEX sheet; the daemon writes its own right at startup. The bundle is made root-owned,
the app opened, the daemon registered and its background item approved by guest GUI automation (macOS 27 asks for an
administrator there; AUTH-REAL's fill of the Login Items sheet). Onboarding then runs to "Open WGEX" with Secure Install
already verified (the escrowed key is readable, so no sheet). The guest is checked (onboarding complete, daemon running,
Secure Install verified, WGEX right written by the daemon) and `just lab snapshot ready` takes `macos27-ready` (or the
named snapshot), never replacing a name. Every run ends with `just lab down` (snapshot.sh restarts the guest after the clone, and a failure after
the restore leaves it running); a failed stop is recorded and fails the run. A short JSON record goes to
DIR/ready-snapshot.json (outside the repository).
"""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "Tools/lab"
NAME = "READY-SNAPSHOT"
BASE = "base"
SNAPSHOT = "ready"
CONTINUE = "wgex.onboarding.continue"
REGISTER = "wgex.onboarding.registerBackgroundService"
# welcome -> backgroundService -> service (Register here) | service -> secureInstall -> firstProfile -> startup -> done -> Open WGEX
BEFORE_REGISTER = 2
MAX_PRESSES = 10
ONBOARDING_SECONDS = 300
STEP_SECONDS = 120
TEARDOWN_SECONDS = 300
PREFERENCES = "Library/Application Support/WGEX/mac-preferences.json"
EXTRA_HELPERS = ("verdict-actions.sh",)
SNAPSHOT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*")
# `base` is the restore source and `wgex` would name the working VM (prefix macos27-): the lab refuses both.
RESERVED = (BASE, "wgex")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def check_environment(environ):
    """The snapshot is macOS 27 only: the prefix decides the snapshot name, so all three parameters must be the
    macos27 ones."""
    wanted = dict(WGEX_LAB_VM="macos27-wgex", WGEX_LAB_USER="admin", WGEX_LAB_SNAPSHOT_PREFIX="macos27-")
    wrong = [key for key, value in wanted.items() if environ.get(key) != value]
    if wrong:
        raise SystemExit("ready-snapshot: set " + " ".join(f"{key}={value}" for key, value in wanted.items()))


def snapshot_name(text):
    """argparse type for --snapshot: the lab's snapshot-name pattern (lib.sh lab_name), minus the reserved names."""
    if not SNAPSHOT_NAME.fullmatch(text):
        raise argparse.ArgumentTypeError(f"invalid snapshot name {text!r}")
    if text in RESERVED:
        raise argparse.ArgumentTypeError(f"snapshot name {text!r} is reserved")
    return text


def secure_install_state(text):
    """`wgex doctor --json` (the last line of verdict-actions.sh secure-install-status): its secureInstall string."""
    lines = text.strip().splitlines()
    try:
        doctor = json.loads(lines[-1]) if lines else {}
    except ValueError:
        return "unreadable"
    state = doctor.get("secureInstall") if isinstance(doctor, dict) else None
    return state if isinstance(state, str) else "unreadable"


def onboarding_complete(text):
    try:
        return json.loads(text).get("onboardingComplete") is True
    except (ValueError, AttributeError):
        return False


class Ready:
    def __init__(self, session, live, auth, snapshot=SNAPSHOT):
        self.session, self.live, self.auth, self.snapshot = session, live, auth, snapshot
        self.probe = auth.AuthReal(session, live)
        self.record = dict(steps=[])
        # First in the cleanups, so it runs after any fixture cleanup and before Session.cleanup writes the step ledger.
        session.cleanups.insert(0, self.stop_guest)

    def step(self, name, **details):
        self.record["steps"].append(dict(step=name, at=datetime.now(timezone.utc).isoformat(timespec="seconds"), **details))

    def action(self, name, check=True, deadline=None):
        command = shlex.join(["bash", self.session.stage + "/verdict-actions.sh", name])
        return self.session.ssh(command, check=check, deadline=deadline).decode(errors="replace")

    def stop_guest(self):
        """Teardown (REV-M03-T10 item 1): `just lab down`, a no-op on a stopped guest. A failure is recorded, never
        raised, so the run's own failure stays the reported one; main() fails the run when the guest was not stopped."""
        try:
            self.session.lab("down", timeout=TEARDOWN_SECONDS)
        except (RuntimeError, OSError) as error:
            self.record.update(guestStopped=False, teardownFailed=str(error))
        else:
            self.record["guestStopped"] = True

    def press_when_ready(self, what):
        self.probe.wait(what, STEP_SECONDS, lambda: self.probe.try_press(CONTINUE), interval=3)
        self.step("continue", screen=what)

    def run(self):
        session, probe = self.session, self.probe
        session.lab("restore", BASE, timeout=900)
        session.await_guest()
        self.step("restored", snapshot="macos27-" + BASE)
        probe.stage()
        for name in EXTRA_HELPERS:
            session.guest_file((LAB / "tart/guest" / name).read_bytes(), name)
        sip = session.ssh("csrutil status").decode(errors="replace").strip()
        self.record["sip"] = "enabled" if sip.endswith("enabled.") else "disabled" if sip.endswith("disabled.") else "unknown"
        if probe.read_right() is not None:
            raise self.auth.Failure("a WGEX right existed in macos27-base; the base is not clean")
        probe.start_clock = session.ssh("date '+%Y-%m-%d %H:%M:%S'").decode().strip()
        session.lab("build", timeout=1800)
        installed = session.lab("install", timeout=900)
        outcome = self.live.wrapping_key_outcome(installed)
        self.record["wrappingKey"] = outcome
        self.step("installed", wrappingKey=outcome)
        # refresh-install without the kickstart: the daemon is not registered yet, so make the bundle root-owned only.
        session.ssh("set -eu; sudo -n chown -R root:wheel /Applications/WGEX.app; codesign --verify --deep --strict /Applications/WGEX.app")
        session.measure_provenance()
        self.record.update({key: session.provenance.get(key) for key in ("guestOS", "sourceCommit", "installed")})
        session.lab("gui", "run", "open", "-a", "WGEX")
        session.lab("gui", "activate", "WGEX")
        for screen in ("welcome", "background service")[:BEFORE_REGISTER]:
            self.press_when_ready(screen)
        probe.press(REGISTER)
        self.step("register")
        probe.approve_background_item()
        self.record["approval"] = {key: probe.approval.get(key) for key in ("item", "sheet", "passwordEntered", "sheetClosed", "btm")
                                   if probe.approval and key in probe.approval}
        if probe.console_step:
            raise self.auth.Failure("background-item approval stopped: " + probe.console_step)
        self.record["daemon"] = probe.wait("daemon running", STEP_SECONDS, probe.daemon_running)
        self.step("daemon running")
        state = probe.wait("secure install verified", STEP_SECONDS,
                           lambda: (lambda value: value if value == "verified" else None)(
                               secure_install_state(self.action("secure-install-status", check=False))), interval=5)
        self.record["secureInstall"] = state
        # A press on a still-disabled Continue does nothing, so press until the app records onboarding complete.
        path = shlex.quote(f"/Users/{self.live.GUEST_USER}/{PREFERENCES}")
        complete = lambda: onboarding_complete(session.ssh("cat " + path, check=False).decode(errors="replace"))
        presses, deadline = 0, time.monotonic() + ONBOARDING_SECONDS
        while not complete():
            if presses >= MAX_PRESSES or time.monotonic() > deadline:
                raise self.auth.Failure(f"onboarding not complete after {presses} Continue presses")
            if probe.try_press(CONTINUE):
                presses += 1
            time.sleep(3)
        self.step("onboarding complete", continuePresses=presses)
        self.record["onboardingComplete"] = True
        right = probe.read_right()
        self.record["rightWrittenBy"] = right.get("identifier") if right else None
        if not right:
            raise self.auth.Failure("the daemon wrote no WGEX right")
        self.record["secureInstallAtSnapshot"] = secure_install_state(self.action("secure-install-status", check=False))
        if self.record["secureInstallAtSnapshot"] != "verified":
            raise self.auth.Failure("Secure Install is not verified before the snapshot")
        session.lab("gui", "run", "osascript", "-e", 'tell application "WGEX" to quit', check=False)
        session.lab("snapshot", self.snapshot, timeout=1200)
        self.step("snapshot", snapshot="macos27-" + self.snapshot)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--snapshot", type=snapshot_name, default=SNAPSHOT, metavar="NAME",
                        help="snapshot name without the macos27- prefix (default: %(default)s)")
    args = parser.parse_args(argv)
    check_environment(os.environ)
    out = args.out.resolve()
    if out == ROOT or ROOT in out.parents:
        parser.error("--out must be outside the repository")
    os.environ["WGEX_LAB_SNAPSHOT"] = BASE
    live = load_module("ready_snapshot_live", LAB / "verdict-live.py")
    auth = load_module("ready_snapshot_auth", LAB / "auth-real.py")
    session = live.Session(NAME, {})
    ready = Ready(session, live, auth, args.snapshot)
    ready.record.update(snapshot="macos27-" + args.snapshot, date=datetime.now(timezone.utc).isoformat(), guest=os.environ["WGEX_LAB_VM"], buildRoot=str(session.output))
    done = False
    try:
        ready.run()
        done = True
    except (auth.Failure, live.RowFailure, RuntimeError, OSError, ValueError, KeyError, TypeError) as error:
        ready.record["stopped"] = str(error) if isinstance(error, auth.Failure) else type(error).__name__ + ": see steps.json"
    finally:
        ready.record["cleanupWarnings"] = session.cleanup()
    ready.record["snapshotTaken"] = done
    stopped = ready.record.get("guestStopped") is True
    out.mkdir(parents=True, exist_ok=True)
    (out / "ready-snapshot.json").write_text(json.dumps(ready.record, indent=2) + "\n")
    taken = "macos27-" + args.snapshot
    message = taken + " taken" if done else taken + " NOT taken: " + ready.record.get("stopped", "?")
    if not stopped:
        message += "; guest NOT stopped: " + ready.record.get("teardownFailed", "teardown did not run") + "; run `just lab down`"
    sys.stdout.write(message + "\n")
    return 0 if done and stopped else 1


if __name__ == "__main__":
    sys.exit(main())
