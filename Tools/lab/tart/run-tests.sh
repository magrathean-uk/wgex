#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
# shellcheck source=Tools/lab/tart/lib.sh
source "$(dirname "$0")/lib.sh"
lab_init "${1:-}"
[[ "${1:-}" != --dry-run ]] || shift
suite="${1:-smoke}"
(($# == 0)) || shift
keep=0
if [[ "${1:-}" == --keep ]]; then
  keep=1
  shift
fi
(($# == 0)) || lab_die 'usage: run-tests.sh [--dry-run] [smoke] [--keep]'
[[ "$suite" == smoke ]] || lab_die 'unknown suite (available: smoke)'
lab_connect
guest_is_lab
# Require a reset source before testing; never destroy a guest on a guard failure.
if [[ "$keep" == 0 ]]; then lab_inventory_is "$LAB_VM-approved" stopped || lab_die 'approved snapshot missing or running'; fi
reset_after_suite() {
  local status=$?
  trap - EXIT
  if [[ "$keep" == 0 ]]; then
    args=()
    if [[ "$LAB_DRY" == 1 ]]; then args+=(--dry-run); fi
    if ! bash "$LAB_DIR/snapshot.sh" ${args[@]+"${args[@]}"} restore approved; then
      printf 'lab: reset failed; guest state requires owner review\n' >&2
      status=1
    fi
  fi
  exit "$status"
}
trap reset_after_suite EXIT
smoke() {
  guest_is_lab
  lab_ssh_read 'set -eu; sw_vers; sysctl kern.hv_vmm_present; stat -f "marker owner=%u mode=%Lp type=%HT" /var/db/wgex-lab-host; codesign --verify --deep --strict /Applications/WGEX.app; codesign -dv /Applications/WGEX.app 2>&1; defaults read /Applications/WGEX.app/Contents/Info CFBundleShortVersionString; defaults read /Applications/WGEX.app/Contents/Info CFBundleVersion; sudo -n pfctl -s info' </dev/null
}
if [[ "$LAB_DRY" == 1 ]]; then smoke; else
  reports="${WGEX_LAB_REPORTS:-$LAB_ROOT/.build/lab-reports}"
  mkdir -p "$reports"
  log="$reports/$(date -u +%Y%m%dT%H%M%SZ)-$suite.log"
  smoke 2>&1 | tee "$log"
fi
