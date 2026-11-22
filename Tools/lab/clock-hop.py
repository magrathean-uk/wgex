#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bracket the final SSH process only; discovery and guest guards run beforehand."""
import json
import os
import subprocess
import sys
import time


def main():
    started = time.time()
    result = subprocess.run(sys.argv[1:], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=int(os.environ.get("WGEX_LAB_SSH_DEADLINE", "90")), check=False)
    ended = time.time()
    if result.returncode:
        return 1
    stamp = json.loads(result.stdout)["timestamp"]
    sys.stdout.write(json.dumps(dict(start=started, end=ended, timestamp=stamp)) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
