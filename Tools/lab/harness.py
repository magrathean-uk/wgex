# SPDX-License-Identifier: MIT
"""Harness deadlines and host-load samples for the verdict pipeline (M1-10i).

Deadlines come from harness-deadlines.sh, the file Tools/lab/tart/lib.sh sources, scaled by WGEX_LAB_HARNESS_SCALE.
Host load is recorded beside a verdict and warned about; it never changes one.
"""
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import subprocess

SOURCE = Path(__file__).resolve().parent / "harness-deadlines.sh"
SCALE_VARIABLE = "WGEX_LAB_HARNESS_SCALE"
SCALE_PATTERN = r"[1-8]"
# Warn when the 1-minute load average exceeds this many times the core count.
LOAD_WARNING_FACTOR = 2
SYSCTL = "/usr/sbin/sysctl"


def read_bases(path=SOURCE):
    """NAME=integer lines; comments and blank lines are the only other content accepted."""
    bases = {}
    for line in Path(path).read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        match = re.fullmatch(r"(HARNESS_[A-Z0-9_]+)=([1-9][0-9]{0,4})", line)
        if not match or match[1] in bases:
            raise ValueError("harness deadline file format")
        bases[match[1]] = int(match[2])
    return bases


BASES = read_bases()


def scale(environ=None):
    raw = (os.environ if environ is None else environ).get(SCALE_VARIABLE, "")
    if raw == "":
        return BASES["HARNESS_SCALE_DEFAULT"]
    if not re.fullmatch(SCALE_PATTERN, raw):
        raise ValueError(SCALE_VARIABLE + " must be an integer 1..8")
    return int(raw)


def seconds(name, environ=None):
    """Effective harness deadline: base x scale, never below the entry's unscaled *_MIN floor."""
    return max(BASES["HARNESS_" + name] * scale(environ), BASES.get("HARNESS_" + name + "_MIN", 0))


def names():
    """The scaled deadlines: neither the default scale, a *_MIN floor nor a *_LOAD threshold."""
    return sorted(key[len("HARNESS_"):] for key in BASES
                  if key != "HARNESS_SCALE_DEFAULT" and not key.endswith("_MIN") and not key.endswith("_LOAD"))


def threshold(name):
    """An unscaled *_LOAD entry as a float (M1-10m): a guest load threshold, never multiplied by the harness scale."""
    if not name.endswith("_LOAD"):
        raise ValueError("only *_LOAD entries are thresholds")
    return float(BASES["HARNESS_" + name])


def host_load(run=None):
    """One read-only sample of vm.loadavg and hw.ncpu; an unreadable host is recorded, never raised."""
    run = run or subprocess.run
    sample = dict(sampledAt=datetime.now(timezone.utc).isoformat())
    try:
        result = run([SYSCTL, "-n", "vm.loadavg", "hw.ncpu"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                     timeout=10, check=False)
        match = re.fullmatch(r"\{ ?([0-9]+(?:\.[0-9]+)?) ([0-9]+(?:\.[0-9]+)?) ([0-9]+(?:\.[0-9]+)?) ?\}\n([1-9][0-9]{0,3})\n?",
                             result.stdout.decode(errors="replace"))
        if result.returncode or not match:
            raise ValueError("unexpected sysctl output")
    except Exception as error:  # noqa: BLE001 - load is evidence only; no failure may reach the verdict
        return dict(sample, available=False, error=type(error).__name__)
    return dict(sample, available=True, load1=float(match[1]), load5=float(match[2]), load15=float(match[3]), cores=int(match[4]))


def overloaded(sample):
    return bool(sample and sample.get("available")) and sample["load1"] > LOAD_WARNING_FACTOR * sample["cores"]


def warning(sample, when):
    """The one-line pipeline warning for an overloaded sample, otherwise None."""
    if not overloaded(sample):
        return None
    try:
        factor = str(scale())
    except ValueError:
        factor = "invalid"
    return (f"verdict: warning: host 1-minute load {sample['load1']:.2f} at {when} exceeds {LOAD_WARNING_FACTOR} x "
            f"{sample['cores']} cores; harness deadlines may expire ({SCALE_VARIABLE}={factor}); the verdict is not adjusted")


def load_record(start, end):
    """verdict.json hostLoad and capture metadata: both samples, the warning rule, the harness scale."""
    try:
        factor = scale()
    except ValueError:
        factor = None
    return dict(start=start, end=end, warningRule=f"load1 > {LOAD_WARNING_FACTOR} x cores",
                overloaded=overloaded(start) or overloaded(end), harnessScale=factor,
                note="recorded only; host load never changes a verdict")
