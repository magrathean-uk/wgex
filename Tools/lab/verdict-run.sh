#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# The dry runner uses files only and deliberately bypasses all VM discovery.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
exec python3 -I -B Tools/lab/verdict-run.py "$@"
