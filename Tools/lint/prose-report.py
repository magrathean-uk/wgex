# SPDX-License-Identifier: MIT
"""Locate matched prose terms without writing matched lines or values to output."""
from pathlib import Path
import sys

patterns, matches, root = map(Path, sys.argv[1:])
terms = patterns.read_text().splitlines()
for name in matches.read_text().splitlines():
    path = Path(name)
    relative = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
    for number, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        lower = line.lower()
        for index, term in enumerate(terms, 1):
            if term.lower() in lower:
                sys.stderr.write(f"denylisted term #{index}: {relative} line {number}\n")
