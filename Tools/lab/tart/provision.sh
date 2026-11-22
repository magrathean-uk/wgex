#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
# shellcheck source=Tools/lab/tart/lib.sh
source "$(dirname "$0")/lib.sh"
lab_init "${1:-}"
[[ "${1:-}" != --dry-run ]] || shift
(($# == 0)) || lab_die 'usage: provision.sh [--dry-run]; tester password on stdin'
lab_connect
lab_ssh_read "set -eu; test \"\$(sysctl -n kern.hv_vmm_present)\" = 1; test \"\$(id -un)\" = $LAB_USER; sudo -n true" </dev/null || lab_die "guest needs administrator $LAB_USER with passwordless sudo (bootstrap over VNC)"
stage="/Users/$LAB_USER/lab/provision-stage"
lab_ssh "umask 077; mkdir -p '$stage'" </dev/null
lab_scp "$LAB_DIR/guest/provision.sh" "$LAB_DIR/guest/guard.sh" "$LAB_DIR/capture/start-capture.sh" "$LAB_DIR/capture/stop-capture.sh" "$LAB_USER@$LAB_ADDRESS:$stage/" </dev/null
if [[ "$LAB_DRY" == 1 ]]; then
  lab_ssh "bash '$stage/provision.sh' '$stage' '$LAB_USER'" </dev/null
elif [[ -t 0 ]]; then
  terminal_state="$(stty -g)"
  trap 'stty "$terminal_state"' EXIT
  printf 'Password for new guest tester (stdin, hidden): ' >&2
  stty -echo
  lab_ssh "bash '$stage/provision.sh' '$stage' '$LAB_USER'"
  stty "$terminal_state"
  trap - EXIT
  printf '\n' >&2
else lab_ssh "bash '$stage/provision.sh' '$stage' '$LAB_USER'"; fi
guest_is_lab
report="${WGEX_LAB_REPORTS:-$LAB_ROOT/.build/lab-reports}"
if [[ "$LAB_DRY" != 1 ]]; then mkdir -p "$report"; fi
lab_scp "$LAB_USER@$LAB_ADDRESS:/Users/$LAB_USER/lab/provisioning-report.txt" "$report/provisioning-report.txt"
printf 'Next: bash Tools/lab/tart/snapshot.sh clean\n'
