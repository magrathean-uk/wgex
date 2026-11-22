#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Read-mostly capture: one reference, immediately released; guest only.
# shellcheck disable=SC2024 # Output is intentionally owned by the unprivileged capturing user.
set -euo pipefail
# shellcheck source=Tools/lab/tart/guest/guard.sh
source "$(dirname "$0")/guard.sh"
guest_guard
out="${1:?usage: pfctl-capture.sh NEW-OUTPUT-DIRECTORY}"
[[ "$#" == 1 && ! -e "$out" ]] || exit 1
umask 077
mkdir -p "$out"
sw_vers >"$out/sw_vers.txt"
sudo -n pfctl -s info >"$out/info.txt" 2>&1
sudo -n pfctl -s References >"$out/references-before.txt" 2>&1
sudo -n pfctl -sr >"$out/rules.txt" 2>&1
sudo -n pfctl -vsr >"$out/rules-verbose.txt" 2>&1
sudo -n pfctl -a com.apple -s Anchors -v >"$out/anchors.txt" 2>&1
sudo -n pfctl -a com.apple/wgex -sr >"$out/anchor-wgex.txt" 2>&1
token=
release() {
  if [[ -n "$token" ]]; then sudo -n pfctl -X "$token" >"$out/release.txt" 2>&1; fi
}
trap release EXIT
sudo -n pfctl -E >"$out/enable.txt" 2>&1
token="$(awk '$1 == "Token" && $2 == ":" && $3 ~ /^[0-9]+$/ {print $3}' "$out/enable.txt")"
[[ "$token" =~ ^[0-9]+$ ]] || exit 1
sudo -n pfctl -s References >"$out/references-with-token.txt" 2>&1
release
token=
sudo -n pfctl -s References >"$out/references-after.txt" 2>&1
sudo -n pfctl -s info >"$out/info-after.txt" 2>&1
