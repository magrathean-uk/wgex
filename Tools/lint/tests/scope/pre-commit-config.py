#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Checks the .plan/ scope of .pre-commit-config.yaml (M00-T01).

The typos hook must skip every path under .plan/, and gitleaks must still scan
the whole tree: no exclude or files filter, no file arguments, the tree as its
target. No YAML library is installed, so the flat hook list is read line by line.
Usage: pre-commit-config.py <.pre-commit-config.yaml>
"""

import re
import sys
from pathlib import Path

PLAN = (".plan/notes.md", ".plan/work/M00-T01/brief.md", ".plan/STATE.toml")
OUTSIDE = ("Sources/notes.md", "docs/plan/notes.md", "Tools/lint/lint.sh", "x/.plan/notes.md")


def scalar(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def parse(text):
    top, hooks, current = {}, {}, None
    for line in text.splitlines():
        if m := re.match(r"^(\w+):\s*(.*)$", line):
            top[m.group(1)] = scalar(m.group(2))
            current = None
        elif m := re.match(r"^\s*- id:\s*(\S+)\s*$", line):
            current = hooks.setdefault(m.group(1), {})
        elif current is not None and (m := re.match(r"^\s+(\w+):\s*(.*)$", line)):
            current[m.group(1)] = scalar(m.group(2))
    return top, hooks


def main():
    top, hooks = parse(Path(sys.argv[1]).read_text(encoding="utf-8"))
    errors = []
    if "exclude" in top and any(re.search(top["exclude"], p) for p in PLAN):
        errors.append("top-level exclude matches .plan/ paths")
    typos = hooks.get("typos")
    if typos is None:
        errors.append("no typos hook")
    elif "exclude" not in typos:
        errors.append("typos hook has no exclude")
    else:
        pattern = typos["exclude"]
        errors += [f"typos exclude misses {p}" for p in PLAN if not re.search(pattern, p)]
        errors += [f"typos exclude also drops {p}" for p in OUTSIDE if re.search(pattern, p)]
    gitleaks = hooks.get("gitleaks")
    if gitleaks is None:
        errors.append("no gitleaks hook")
    else:
        errors += [f"gitleaks hook filters files ({k})" for k in ("exclude", "files") if k in gitleaks]
        if gitleaks.get("pass_filenames") != "false" or gitleaks.get("always_run") != "true":
            errors.append("gitleaks hook must run on the whole tree (pass_filenames: false, always_run: true)")
        if gitleaks.get("entry", "").split()[-1:] != ["."]:
            errors.append("gitleaks hook entry does not scan the tree root")
    for error in errors:
        print(f"pre-commit-config: {error}", file=sys.stderr)
    if errors:
        print("pre-commit-config: FAIL", file=sys.stderr)
        return 1
    print("pre-commit-config: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
