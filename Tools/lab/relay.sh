#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Ordinary host UDP relay; state is persistent per tree, not per build session.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
dry=()
if [[ "${1:-}" == --dry-run ]]; then
  dry=(--dry-run)
  shift
fi
exec python3 -I -B "$root/Tools/lab/relay-manager.py" "${1:-start}" ${dry[@]+"${dry[@]}"} "${@:2}"
