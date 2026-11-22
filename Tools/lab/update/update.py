# SPDX-License-Identifier: MIT
"""M5.3-07 update bundle: its location, its version and the row's checks. Pure functions; no VM, Xcode or network.

The update is a second Lab build of the same commit, built by Tools/lab/tart/build.sh into its own build root with a
higher CURRENT_PROJECT_VERSION. Lab signing has no stable certificate (DEC-007): "the stable lab identity" is the Lab
signing class itself (ad hoc, recorded as CODE_SIGN_IDENTITY "lab" in the build receipt), which check-verdicts compares
with the base build's receipt.
"""
import importlib.util
import math
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
DIGEST = re.compile(r"[a-f0-9]{12}")
CDHASH = re.compile(r"[a-f0-9]{40}")
# The fixed daemon start line the new daemon logs after the hand-off (DaemonRuntimeMessage, daemon-log-tail.pl vocabulary).
LISTENING = "Daemon listening; recovering"


def _build_root():
    spec = importlib.util.spec_from_file_location("update_build_root", ROOT / "Config/Scripts/build_root.py")
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value.build_root


def build_base(root=ROOT, environment=None):
    """WGEX_BUILD_ROOT for the update build: a sibling of the base derived data, so the base Lab build is never replaced."""
    return _build_root()(root, environment) / "lab-update"


def app_path(root=ROOT, environment=None):
    """Where tart/build.sh leaves the update bundle when WGEX_BUILD_ROOT is build_base()."""
    root = Path(root)
    return build_base(root, environment) / root.name / "derived-data/Build/Products/Lab/WGEX.app"


def base_version(root=ROOT):
    """CURRENT_PROJECT_VERSION of an ordinary Lab build (Config/Base.xcconfig)."""
    text = (Path(root) / "Config/Base.xcconfig").read_text()
    found = re.findall(r"^CURRENT_PROJECT_VERSION\s*=\s*([1-9][0-9]*)\s*$", text, re.M)
    if len(found) != 1:
        raise ValueError("Config/Base.xcconfig: one CURRENT_PROJECT_VERSION required")
    return int(found[0])


def next_version(root=ROOT, requested=None):
    """The update's bundle version: requested when given (it must exceed the base), else the base plus one.

    The guest keeps an anti-downgrade floor (DEC-007), so the update is never at or below the version already run.
    """
    base = base_version(root)
    if requested in (None, ""):
        return base + 1
    if not re.fullmatch(r"[1-9][0-9]*", str(requested)) or int(requested) <= base:
        raise ValueError("update version must be an integer above CURRENT_PROJECT_VERSION " + str(base))
    return int(requested)


def receipt_version(inputs):
    """The one CURRENT_PROJECT_VERSION all targets of a build receipt carry, as an integer; None otherwise."""
    try:
        versions = {settings["CURRENT_PROJECT_VERSION"] for settings in inputs["targets"].values()}
    except (KeyError, TypeError, AttributeError):
        return None
    value = versions.pop() if len(versions) == 1 else None
    return int(value) if isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*", value) else None


def check(name, met):
    return dict(name=name, met=bool(met))


def _snapshot(value):
    return value if isinstance(value, dict) else {}


def _time(value):
    return type(value) in (int, float) and math.isfinite(value)


def handoff_covered(windows, since, until, tolerance):
    """Marker generation ran without a gap from `since` (before the app quits) until `until` (the recovery sample).

    windows are the update generators' own intervals (guest clock); every one must be valid, the earliest must start a
    clock tolerance before `since`, each must start before the ones before it have ended, and together they must reach a
    clock tolerance past `until`. Each window is also evaluated on its own markers, so with this check no outside marker
    sent between the two goes unjudged."""
    if not isinstance(windows, list) or not windows or not all(_time(v) for v in (since, until, tolerance)):
        return False
    if not 0 <= tolerance <= 2 or not since < until:
        return False
    spans = []
    for window in windows:
        start, end = (window.get("start"), window.get("end")) if isinstance(window, dict) else (None, None)
        if not (_time(start) and _time(end) and start < end):
            return False
        spans.append((start, end))
    spans.sort()
    if spans[0][0] > since - tolerance:
        return False
    reach = spans[0][1]
    for start, end in spans[1:]:
        if start > reach:
            return False
        reach = max(reach, end)
    return reach >= until + tolerance


def update_checks(observation):
    """M5.3-07 expectations on one observation (verdict-live update_row, or the recorded fixture)."""
    item = _snapshot(observation.get("update"))
    expected = _snapshot(item.get("expected"))
    before, after = _snapshot(item.get("before")), _snapshot(item.get("after"))
    base_v, update_v = item.get("baseVersion"), item.get("updateVersion")
    versions = type(base_v) is int and type(update_v) is int and 0 < base_v < update_v
    base_daemon, update_daemon = expected.get("baseDaemon"), expected.get("updateDaemon")
    hashes = all(isinstance(value, str) and CDHASH.fullmatch(value) for value in (base_daemon, update_daemon))
    samples = item.get("samples") if isinstance(item.get("samples"), list) else []
    pid_before, pid_after = before.get("daemonPid"), after.get("daemonPid")
    pids = type(pid_before) is int and type(pid_after) is int and pid_before > 0 and pid_after > 0
    digest = before.get("intentDigest")
    log = item.get("daemonLog") if isinstance(item.get("daemonLog"), list) else []
    since, pressed, until = item.get("probedFrom"), item.get("pressedAt"), item.get("recoveredAt")
    return [
        check("distinctUpdateBuild", versions and hashes and base_daemon != update_daemon),
        check("installedWhileConnected", item.get("replaced") is True and before.get("protection") == "protected"
              and item.get("protectionAtReplacement") == "protected" and before.get("runningDaemonCdhash") == base_daemon),
        check("handoffPerformed", item.get("offerShown") is True and item.get("finishPressed") is True and pids
              and pid_after != pid_before and hashes and after.get("runningDaemonCdhash") == update_daemon
              and after.get("bundleVersion") == str(update_v) and LISTENING in log),
        check("intentKept", isinstance(digest, str) and DIGEST.fullmatch(digest) is not None
              and after.get("intentDigest") == digest and after.get("protection") == "protected"),
        # Leaks themselves are judged by the update windows' markers; this check proves those windows left no gap from
        # before the app quit, through the Finish update press, until the new daemon was confirmed protected.
        check("handoffProbedThroughout", _time(pressed) and _time(since) and _time(until) and since < pressed < until
              and handoff_covered(item.get("handoffWindows"), since, until, item.get("clockToleranceSeconds"))),
        # A missing status during the swap is expected (no daemon answers); an unprotected publication is not.
        check("protectionHeldDuringHandoff", bool(samples) and all(isinstance(s, dict) and s.get("protection") in
              ("protected", "blocked", "unknown", "unavailable") for s in samples)
              and before.get("referenceCount") == 1 and after.get("referenceCount") == 1),
    ]


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["path"]:
            sys.stdout.write(str(app_path()) + "\n")
        elif sys.argv[1:2] == ["build-base"] and len(sys.argv) == 2:
            sys.stdout.write(str(build_base()) + "\n")
        elif sys.argv[1:2] == ["version"] and len(sys.argv) <= 3:
            sys.stdout.write(str(next_version(ROOT, sys.argv[2] if len(sys.argv) == 3 else None)) + "\n")
        else:
            raise SystemExit("usage: update.py path|build-base|version [REQUESTED]")
    except (OSError, ValueError) as error:
        raise SystemExit("update: " + str(error)) from None
