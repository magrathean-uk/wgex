#!/usr/bin/env python3
"""Refuse recipe/login-shell references on every non-comment suite line.

The exact-line allowlist is limited to shim setup, a scratch-only docs stub and assertions. A new reference needs an
explicit reason here; whitespace changes also need review. Dynamic recipe names are covered by the runtime shim.
"""

import subprocess
import sys


ALLOWED = {
    'just_log="$work/just.calls"': "the shim log path",
    r'''  printf '#!/bin/sh\nprintf "call: %%s\\n" "$*" >>"%s"\nexit 95\n' "$2" >"$1/just"''': "write the refusing shim",
    '  chmod +x "$1/just"': "make the refusing shim executable",
    '''  sed 's/step docs-check just docs-check/step docs-check echo "docs-check: skipped (scratch tree)"/' "$root/Tools/lint/lint.sh" >"$dir/Tools/lint/lint.sh"''': "replace the absent docs recipe in scratch copies only",
    "expect no-case-runs-a-just-recipe pass '^no-just guard: ok' 'no-just guard: a case' no_just_in_cases": "assert this source guard",
    '''expect nojust-source-shapes-refused fail '^no-just guard: unexpected call at ' - no_just_in_cases "$root/Tools/lint/tests/fail-closed/nojust-cases.bash"''': "assert refusal of the adversarial fixture",
}


def main(path):
    result = subprocess.run(
        ["grep", "-nE", r"\bjust\b|zsh +-l|--login", path], capture_output=True, text=True, timeout=10, check=False
    )
    if result.returncode not in (0, 1):
        print("no-just guard: source grep failed", file=sys.stderr)
        return 1
    bad = False
    for hit in result.stdout.splitlines():
        line, text = hit.split(":", 1)
        if text.lstrip().startswith("#") or text in ALLOWED:
            continue
        print("no-just guard: unexpected call at %s:%s" % (path, line), file=sys.stderr)
        bad = True
    if bad:
        return 1
    print("no-just guard: ok, every non-comment line checked")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
