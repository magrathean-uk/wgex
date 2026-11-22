#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline re-evaluation of stored boot observations through the current verdict logic (M1-10u).

Reads row-observation.json from one or more capture directories (lab-captures/<ROW>/lab-<nonce>/), read-only, and runs
the post-restart timeline logic (verdict.restart_timeline, boot_report, row_checks) on it; nothing in a capture is
opened for writing and no other file of it is read (steps.json is never touched). With --committed VERDICT.json for a
capture it also says which committed checks still hold and lists any that change. The report goes to stdout; --out
FILE writes the same JSON, and only under $TMPDIR (an absolute path that is not "/"), never under a capture directory
given. Its output is marked "offlineReevaluation": true and "offline re-evaluation, not a verdict" (also on stderr): it
writes nothing under Tests/Reports and replaces no committed verdict. No VM, no SSH, no host app, daemon or network.

There is no opt-out from any rule (M1-10v dropped the flag that waived the unattributed-line rule: no stored capture needed it,
and on a capture with pids it re-opened that rule offline); nothing a stored capture says can waive a check.

Usage (exit 0 all recomputed checks met, 1 not, 2 an error: a missing capture, a reboot-row capture without
row-observation.json, an --out that is a directory, malformed input, an unusable $TMPDIR or --out):
python3 -I -B Tools/lab/verdict-reeval.py CAPTURE_DIR [CAPTURE_DIR ...] [--committed FILE ...] [--out FILE]
"""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys

LAB = Path(__file__).resolve().parent
NOTICE = "offline re-evaluation, not a verdict"
REBOOT_KINDS = ("reboot-intent", "reboot-lockdown", "boot-secrets")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


V = load_module("wgex_verdict", LAB / "verdict.py")
ROWS = json.loads((LAB / "rows.json").read_bytes())["rows"]
SHOWN = ("firstProtectedAt", "appStartedAt", "daemonStartedAt", "protectedOnlyAfterAppSeen", "excludedPreRestartStatusLines", "unknownProtectionCount",
         "failedPhaseCount", "unprotectedCount", "diagnostics", "gap")


class InputError(Exception):
    """An input the re-evaluation cannot use: named on stderr, exit 2 (never the not-PASS exit 1)."""


def row_kind(row):
    """The row's check kind (rows.json checks), or reboot-intent for a reboot row without one, else None."""
    entry = ROWS.get(row) or {}
    return entry.get("checks") or ("reboot-intent" if entry.get("action") == "reboot" else None)


def summarise(check):
    return dict(name=check["name"], met=bool(check["met"]), **{key: check[key] for key in SHOWN if key in check})


def evaluate_capture(capture, committed=None):
    capture = Path(capture)
    if not capture.is_dir():
        raise InputError(f"capture directory not found: {capture}")
    row, capture_id = capture.parent.name, capture.name
    kind = row_kind(row)
    result = dict(row=row, captureId=capture_id, kind=kind)
    path = capture / "row-observation.json"
    if not path.is_file():
        if kind in REBOOT_KINDS:
            raise InputError(f"{row} capture {capture_id} has no row-observation.json: nothing to re-evaluate for a reboot row")
        result["bootTimeline"] = "none recorded (no row-observation.json): this row builds no status timeline across the restart"
        return result
    observation = json.loads(path.read_bytes())
    boot = observation.get("boot")
    if not isinstance(boot, dict):
        if kind in REBOOT_KINDS:
            raise InputError(f"{row} capture {capture_id}: the row observation has no boot object")
        result["bootTimeline"] = "none recorded (row observation has no boot object)"
        return result
    boot = copy.deepcopy(boot)
    window = boot.get("neverOpenWindow")
    if isinstance(window, dict):
        # M1-10u fix pass 1: recomputed from the post-restart lines (the stored window predates the filter), never carried.
        start = window["sshReturnAt"] if "sshReturnAt" in window else window["start"]
        boot["neverOpenWindow"] = dict(window, **V.never_open_window(start, window["driverFirstPollAt"], V.restart_timeline(boot)["lines"],
                                                                     strict=kind == "reboot-lockdown", probed_from=window.get("probedFrom")))
        result["neverOpenWindow"] = boot["neverOpenWindow"]
    observation = dict(observation, boot=boot)
    report = V.boot_report(boot)
    result["postRestart"] = dict(firstProtectedAt=report["firstProtectedAt"], daemonStartedAt=report["daemonStartedAt"], appStartedAt=report["appStartedAt"],
                                 appRunningAfterBoot=report["appRunningAfterBoot"], protectedBeforeAppSeen=report["protectedBeforeAppSeen"],
                                 daemonDrivenReconnect=report["daemonDrivenReconnect"], daemonDrivenReconnectBasis=report["daemonDrivenReconnectBasis"],
                                 timelineAvailable=report["timelineAvailable"], postRestartTimelineConsistent=report["postRestartTimelineConsistent"],
                                 protectedOnlyAfterAppSeen=report.get("protectedOnlyAfterAppSeen"), postRestartTimeline=report["postRestartTimeline"],
                                 legacyFirstProtectedAt=min((item[0] for item in (boot.get("timeline") or []) + (boot.get("statusSamples") or [])
                                                             if item[2] == "protected"), default=None))
    if kind in ("reboot-lockdown", "boot-secrets"):
        checks = V.row_checks(kind, observation)
    else:
        checks = V.reboot_intent_checks(boot)
    result["checks"] = [summarise(check) for check in checks]
    result["rowPassOnRecomputedChecks"] = all(check["met"] for check in checks if check.get("measured") is not False)
    if committed is not None:
        stored = {check["name"]: check for check in committed.get("checks", []) if isinstance(check, dict)}
        recomputed = {check["name"]: check for check in checks}
        changed = [dict(name=name, committedMet=stored[name]["met"], recomputedMet=bool(recomputed[name]["met"]))
                   for name in recomputed if name in stored and bool(stored[name]["met"]) != bool(recomputed[name]["met"])]
        added = [dict(name=name, recomputedMet=bool(check["met"])) for name, check in recomputed.items() if name not in stored]
        result["committed"] = dict(expectationsMet=committed.get("expectationsMet"), changedChecks=changed, addedChecks=added,
                                   stillHolds=committed.get("expectationsMet") is True and not changed and all(item["recomputedMet"] for item in added),
                                   committedFirstProtectedAt=(committed.get("bootObservation") or {}).get("firstProtectedAt"))
    return result


def scratch_directory(parser):
    """$TMPDIR as an absolute directory that is not "/"; anything else is refused (exit 2)."""
    raw = os.environ.get("TMPDIR", "")
    if not raw or not os.path.isabs(raw):
        parser.error("--out needs an absolute $TMPDIR")
    resolved = Path(raw).resolve()
    if resolved == Path(resolved.anchor):
        parser.error("--out needs a $TMPDIR that is not the filesystem root")
    return resolved


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("captures", nargs="+", type=Path)
    parser.add_argument("--committed", type=Path, action="append", default=[], help="committed verdict.json, one per capture in order")
    parser.add_argument("--out", type=Path)
    arguments = parser.parse_args(argv)
    if arguments.committed and len(arguments.committed) != len(arguments.captures):
        parser.error("--committed must be given once per capture")
    if arguments.out is not None:
        scratch = scratch_directory(parser)
        target = arguments.out.resolve()
        if scratch not in target.parents:
            parser.error("--out must be a file under $TMPDIR")
        if target.is_dir():
            parser.error("--out is a directory")
        for capture in arguments.captures:
            directory = capture.resolve()
            if target == directory or directory in target.parents:
                parser.error("--out must not be under a capture directory given")
    try:
        results = []
        for index, capture in enumerate(arguments.captures):
            committed = json.loads(arguments.committed[index].read_bytes()) if arguments.committed else None
            results.append(evaluate_capture(capture, committed))
        document = dict(offlineReevaluation=True, notice=NOTICE, results=results)
        text = json.dumps(document, indent=2, sort_keys=True) + "\n"
        if arguments.out is not None:
            arguments.out.write_text(text)
    except InputError as error:
        sys.stderr.write(f"verdict-reeval: {error}\n")
        return 2
    except OSError as error:
        sys.stderr.write(f"verdict-reeval: unreadable or unwritable input ({type(error).__name__}: {error.filename or error.strerror})\n")
        return 2
    except (ValueError, KeyError, TypeError, IndexError, AttributeError) as error:
        sys.stderr.write(f"verdict-reeval: malformed input ({type(error).__name__}: {error})\n")
        return 2
    sys.stderr.write(NOTICE + "\n")
    sys.stdout.write(text)
    # Exit 1 when any capture's recomputed checks are not all met (a not-PASS), 0 otherwise, like verdict-run.
    return 0 if all(item.get("rowPassOnRecomputedChecks", True) for item in results) else 1


if __name__ == "__main__":
    sys.exit(main())
