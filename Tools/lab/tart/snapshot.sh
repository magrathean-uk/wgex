#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
# shellcheck source=Tools/lab/tart/lib.sh
source "$(dirname "$0")/lib.sh"
lab_init "${1:-}"
[[ "${1:-}" != --dry-run ]] || shift
command="${1:?usage: snapshot.sh [--dry-run] <NAME|restore NAME|list>}"
shift
started=$SECONDS
# The guest starts headless with Tart's VNC console (lab_start, DEC-112); with WGEX_LAB_VNC_FILE set, its vnc://
# address and one-time password go to that private file for Tools/lab/console/console.py (M03-T07 phase B, DEC-034).
case "$command" in
  list)
    (($# == 0)) || lab_die 'list takes no arguments'
    lab_inventory list | awk -v prefix="$LAB_SNAPSHOT_PREFIX" -v vm="$LAB_VM" 'NR == 1 || (index($0, prefix) && $2 != vm)'
    exit
    ;;
  restore)
    name="${1:?restore needs a snapshot name}"
    shift
    lab_name "$name"
    (($# == 0)) || lab_die 'unexpected restore argument'
    snapshot="$LAB_SNAPSHOT_PREFIX$name"
    # A prefix shorter than the VM name (macos27-) could name the working VM itself.
    [[ "$snapshot" != "$LAB_VM" ]] || lab_die 'snapshot name is the working VM'
    # Validate source BEFORE deleting anything. Restore never pulls an image.
    lab_inventory_is "$snapshot" stopped || lab_die 'snapshot missing or running'
    lab_stop
    lab_tart delete "$LAB_VM"
    lab_tart clone "$snapshot" "$LAB_VM"
    ;;
  *)
    name="$command"
    lab_name "$name"
    (($# == 0)) || lab_die 'unexpected snapshot argument'
    snapshot="$LAB_SNAPSHOT_PREFIX$name"
    [[ "$snapshot" != "$LAB_VM" ]] || lab_die 'snapshot name is the working VM'
    if [[ "$LAB_DRY" != 1 ]] && lab_inventory get "$snapshot" >/dev/null 2>&1; then lab_die 'snapshot exists; choose a new name'; fi
    # A ready snapshot without completed onboarding has no main window, so prepare cannot find
    # wgex.main.sidebarImport (guest run 6, M1-10d L18). The procedure is in README.md.
    case "$name" in ready*) printf 'lab: note: take a ready snapshot only after onboarding has completed (7 x Continue, then Open WGEX) and the main window shows wgex.main.sidebarImport; see Tools/lab/tart/README.md\n' >&2 ;; esac
    lab_connect
    guest_is_lab
    lab_stop
    lab_tart clone "$LAB_VM" "$snapshot"
    ;;
esac
lab_start
lab_wait_ready
elapsed=$((SECONDS - started))
printf '%s %s: %d s (includes shutdown, clone, restart and guarded SSH readiness)\n' "$command" "$name" "$elapsed"
if [[ "$command" == restore && "$name" == approved && "$elapsed" -ge 60 ]]; then printf 'lab: warning: approved restore exceeded the 60-second target; guarded SSH is ready\n' >&2; fi
