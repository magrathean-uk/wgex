#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
# shellcheck source=Tools/lab/tart/guest/guard.sh
source "$(dirname "$0")/guard.sh"
guest_guard
(($# == 0)) || exit 1
# The marker user is checked before any signal, removal or ownership change (and again after the root re-exec).
user="$(guest_lab_user)"
if ((EUID != 0)); then exec sudo -n bash "$0"; fi
state=/var/run/wgex-lab-capture
[[ -d "$state" && ! -L "$state" ]] || exit 0
for record in "$state/"*.pid; do
  [[ -f "$record" && ! -L "$record" ]] || continue
  pid="$(cat "$record")"
  [[ "$pid" =~ ^[0-9]+$ ]] || exit 1
  if kill -0 "$pid" 2>/dev/null; then
    [[ "$(ps -p "$pid" -o comm=)" == /usr/sbin/tcpdump ]] || {
      echo 'PID no longer belongs to capture; refusing signal' >&2
      exit 1
    }
    kill -INT "$pid"
    for ((attempt = 0; attempt < 10; attempt++)); do
      if ! kill -0 "$pid" 2>/dev/null; then break; fi
      sleep 1
    done
    if kill -0 "$pid" 2>/dev/null; then
      echo 'capture has not exited' >&2
      exit 1
    fi
  fi
  rm -f "$record"
done
pcaps="/Users/$user/lab/pcap"
# Only completed capture files become readable to key-only scp.
find "$pcaps" -type f -name '*.pcap' -exec chown "$user":staff {} +
