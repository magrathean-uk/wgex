# SPDX-License-Identifier: MIT
"""Gate-step entry: build the step's environment from a fixed list, emit timings, preserve command output and exit status.

Every check and check-full step runs through here, so each step gives the same result whatever the caller's shell
exported. The step's environment is the allowlist in Config/Scripts/knobs.py (PATH, HOME, TMPDIR, USER, LOGNAME, SHELL, TERM,
LANG, LC_*, CODEX_THREAD_ID, CLAUDE_CODE_SESSION_ID, WGEX_*, the wrapper's Go variables and the CLEAN_DEV routing names),
the one the tooling self-test applies to itself too; every other inherited variable is dropped, and only a count is printed (the --enter
COMMAND line names them as well; a value is never printed). WGEX_* is on the list: those are the gate's own knobs (check-full's
WGEX_GO_RACE_COUNT=1 and WGEX_LAB_BUILD=1, WGEX_FUZZ_SECONDS, WGEX_DOCS_*) and must reach their steps.

    timed-step.py LABEL COMMAND...    run COMMAND, then print "gate-step: LABEL exit=N seconds=S"
    timed-step.py --enter COMMAND...  refuse a caller's JUST_* execution variable, then strip and run COMMAND with no timing
                                      line (the recipe's own bash entry points)
    timed-step.py --enter             the first line of check and check-full: the same refusal, then start the gate ledger
    timed-step.py --done LABEL        the last line of check and check-full: print "LABEL: passed (N gate steps, ...)"

The outer `just` reads JUST_* (JUST_DRY_RUN echoes every recipe line and runs none) before any step can strip it, so --enter
exits 2 with a named error when it inherits one that changes what just runs (knobs.just_execution_variables). The ledger
(the file named by WGEX_GATE_LEDGER, which the check and check-full recipes export, created here with O_EXCL so a
pre-seeded file is refused) gets one line per finished gate step; --done prints the count. A dry run cannot print that
line: a gate result is the set of gate-step lines plus the final status, never the text "check: passed". The ledger path
is a recipe parameter, so `just check lint` passes `lint` as the ledger instead of running lint: --enter refuses a path
that is relative or outside $TMPDIR (status 2, nothing created).

A step also names, on one line, the verdict-changing WGEX_* variables it passes on (knobs.VERDICT_WGEX_NAMES), so a green
result shows the opt-outs it ran under.
"""
import importlib.util
import os
import subprocess
import sys
import time


def load_knobs():
    """Config/Scripts/knobs.py by path: under python3 -I the script directory is not on sys.path."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "knobs.py")
    spec = importlib.util.spec_from_file_location("wgex_knobs", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


knobs = load_knobs()


def clean_environment():
    """(the caller's environment cut to the allowlist, sorted names dropped)."""
    environment = dict(os.environ)
    return environment, knobs.restrict(environment)


def ledger_path():
    return os.environ.get("WGEX_GATE_LEDGER") or None


def ledger_outside_tmpdir(path):
    """True unless path is absolute and resolves to an entry strictly inside $TMPDIR (or /tmp, the recipes' fallback)."""
    tmp = os.environ.get("TMPDIR") or "/tmp"
    if not (os.path.isabs(path) and os.path.isabs(tmp)):
        return True
    real_tmp, real_path = os.path.realpath(tmp), os.path.realpath(path)
    return real_path == real_tmp or os.path.commonpath([real_tmp, real_path]) != real_tmp


def begin():
    """Create the gate ledger (exclusive); the caller already passed the JUST_* refusal."""
    path = ledger_path()
    if path is None:
        return 0
    if ledger_outside_tmpdir(path):
        sys.stderr.write("gate-entry: refused: WGEX_GATE_LEDGER is not an absolute path inside $TMPDIR (a recipe argument, "
                         "as in `just check lint`, becomes the ledger path); run each recipe on its own\n")
        return 2
    try:
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    except OSError as error:
        sys.stderr.write(f"gate-entry: refused: cannot create the gate ledger ({error.strerror}); it must not exist yet\n")
        return 2
    return 0


def done(arguments):
    """Print the final line from the ledger, which only a process that ran the steps can have."""
    path, label = ledger_path(), arguments[0] if arguments else "gate"
    try:
        with open(path or "") as handle:
            records = [line.split() for line in handle.read().splitlines()]
    except OSError:
        sys.stderr.write(f"gate-entry: {label}: no gate ledger; the gate did not start through --enter\n")
        return 1
    failed = [record[0] for record in records if len(record) != 2 or record[1] != "0"]
    if not records or failed:
        sys.stderr.write(f"gate-entry: {label}: {len(records)} gate steps recorded, failed: {', '.join(failed) or 'none'}\n")
        return 1
    os.unlink(path)
    sys.stdout.write(f"{label}: passed ({len(records)} gate steps, all exit=0)\n")
    return 0


def main():
    arguments = sys.argv[1:]
    if arguments[:1] == ["--done"]:
        return done(arguments[1:])
    entry_only = arguments[:1] == ["--enter"]
    if entry_only:
        label, command = None, arguments[1:]
        status = knobs.refuse_build_variants(os.environ)
        if status:
            return status
        refused = knobs.just_execution_variables(os.environ)
        if refused:
            sys.stderr.write(f"gate-entry: refused: inherited {knobs.printable(refused)} changes what just runs "
                             "(JUST_DRY_RUN echoes the recipe and runs nothing); unset it and run the gate again\n")
            return 2
        if not command:
            return begin()
    else:
        label, *command = arguments
    environment, dropped = clean_environment()
    if dropped:
        names = f": {knobs.printable(dropped)}" if label is None else ""
        sys.stderr.write(f"gate-entry: {label or 'enter'} dropped {len(dropped)} inherited variables{names}\n")
    kept = knobs.verdict_variables(environment)
    if kept:
        sys.stderr.write(f"gate-entry: {label or 'enter'} kept from caller: {knobs.printable(kept)}\n")
    started = time.monotonic()
    result = subprocess.run(command, env=environment)
    status = result.returncode if result.returncode >= 0 else 128 - result.returncode
    if not entry_only:
        sys.stderr.write(f"gate-step: {label} exit={status} seconds={time.monotonic() - started:.3f}\n")
        path = ledger_path()
        if path and os.path.exists(path):
            with open(path, "a") as handle:
                handle.write(f"{label} {status}\n")
    return status


if __name__ == "__main__":
    sys.exit(main())
