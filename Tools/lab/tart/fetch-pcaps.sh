#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
# shellcheck source=Tools/lab/tart/lib.sh
source "$(dirname "$0")/lib.sh"
# shellcheck source=Config/Scripts/lib.sh
source "$LAB_ROOT/Config/Scripts/lib.sh"
lab_init "${1:-}"
[[ "${1:-}" != --dry-run ]] || shift
(($# == 0)) || lab_die 'usage: fetch-pcaps.sh [--dry-run]'
builds="$(dirname "$(build_root)")"
[[ "$builds" == /* && -d "$builds" ]] || lab_die 'build output must be an existing absolute directory'
builds="$(cd "$builds" && pwd -P)"
case "$builds/" in "$LAB_ROOT/"* | /) lab_die 'pcaps must be outside the repository' ;; esac
out="$(build_root)/lab-captures/manual"
# Reject symlinks that could redirect pcaps into the source tree.
[[ ! -L "$(build_root)" && ! -L "$(build_root)/lab-captures" && ! -L "$out" ]] || lab_die 'pcap output must not be a symlink'
lab_connect
guest_is_lab
lab_ssh "if test -f /Users/$LAB_USER/lab/capture/stop-capture.sh; then bash /Users/$LAB_USER/lab/capture/stop-capture.sh; else printf 'capture helper absent; fetching completed pcaps only\n' >&2; fi" </dev/null
if [[ "$LAB_DRY" != 1 ]]; then mkdir -p "$out"; fi
lab_scp "$LAB_USER@$LAB_ADDRESS:/Users/$LAB_USER/lab/pcap/*.pcap" "$out/"
