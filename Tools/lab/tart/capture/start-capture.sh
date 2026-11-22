#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
# shellcheck source=Tools/lab/tart/guest/guard.sh
source "$(dirname "$0")/guard.sh"
guest_guard
iface="${1:?usage: start-capture.sh <en0|utunN> LABEL}"
label="${2:?capture label required}"
[[ "$#" == 2 && "$iface" =~ ^(en0|utun[0-9]+)$ && "$label" =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]*$ ]] || exit 1
# The marker user is checked before the root re-exec and again as root, before any capture state changes.
user="$(guest_lab_user)"
if ((EUID != 0)); then exec sudo -n bash "$0" "$@"; fi
state=/var/run/wgex-lab-capture
pcaps="/Users/$user/lab/pcap"
[[ ! -L "$state" && ! -L "$pcaps" ]] || exit 1
mkdir -p "$state" "$pcaps"
chmod 0700 "$state"
# M1-10o fix pass 2 (F6): a record whose tcpdump has ended (its utun was destroyed by an explicit down) is replaced, so
# the capture restarts on the recreated interface; a running capture is never replaced.
if [[ -e "$state/$iface.pid" || -L "$state/$iface.pid" ]]; then
  previous="$(cat "$state/$iface.pid" 2>/dev/null || true)"
  if [[ -L "$state/$iface.pid" || ! "$previous" =~ ^[0-9]+$ ]] || kill -0 "$previous" 2>/dev/null; then
    echo 'capture already recorded; stop first' >&2
    exit 1
  fi
  rm -f "$state/$iface.pid"
fi
stamp="$(date -u +%Y%m%dT%H%M%SZ)-$$"
umask 077
capture_file="$pcaps/$stamp-$label-$iface.pcap"
nohup /usr/sbin/tcpdump -n -U -s 256 -i "$iface" -w "$capture_file" </dev/null >"$state/$iface.log" 2>&1 &
pid=$!
printf '%s\n' "$pid" >"$state/$iface.pid"
sleep 1
kill -0 "$pid" || {
  rm -f "$state/$iface.pid"
  echo 'tcpdump failed; check guest capture log' >&2
  exit 1
}
printf 'guest capture started: %s (%s)\n' "$iface" "$label"
printf 'captureFile=%s\n' "$capture_file"
