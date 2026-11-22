# SPDX-License-Identifier: MIT
"""Restrict daemon console printing to its version/doctor metadata branch."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
TOKENS = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|[{}]|\bprint\s*\(', re.S)


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "Daemon/WGEXDaemon/main.swift"
    text = path.read_text()
    branch = re.search(r'if arguments\.contains\("--version"\)[^{]*\{', text)
    start = branch.end() - 1 if branch else -1
    end = -1
    depth = 0
    prints = []
    for token in TOKENS.finditer(text):
        value = token.group()
        if token.start() >= start >= 0 and end < 0:
            if value == "{":
                depth += 1
            elif value == "}":
                depth -= 1
                if depth == 0:
                    end = token.end()
        if value.startswith("print"):
            prints.append(token.start())
    violations = [offset for offset in prints if not start <= offset < end]
    for offset in violations:
        line = text.count("\n", 0, offset) + 1
        sys.stderr.write(f"wgex_no_print: daemon line {line}: print outside version path\n")
    if violations:
        return 1
    print("daemon-print: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
