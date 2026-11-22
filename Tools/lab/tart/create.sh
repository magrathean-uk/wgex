#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
# shellcheck source=Tools/lab/tart/lib.sh
source "$(dirname "$0")/lib.sh"
lab_init "${1:-}"
[[ "${1:-}" != --dry-run ]] || shift
approved=0
ipsw=latest
while (($#)); do
  case "$1" in
    --yes-download) approved=1 ;;
    --ipsw)
      shift
      ipsw="${1:?--ipsw needs a local path}"
      [[ -f "$ipsw" ]] || lab_die 'IPSW file missing'
      ;;
    *) lab_die 'usage: create.sh [--dry-run] [--yes-download] [--ipsw PATH]' ;;
  esac
  shift
done
printf 'Cloning a macOS 26 guest of your own is the alternative: ./vm-tart clone SOURCE_VM macos26-wgex\nThe IPSW route follows; no clone is executed here.\n'
printf 'Plan: create %s from %s; 4 CPUs, 8192 MiB RAM, 64 GB disk. Latest IPSW may be about 25 GB; owner approval required.\n' "$LAB_VM" "$ipsw"
if [[ "$approved" == 1 ]]; then
  if lab_inventory get "$LAB_VM" >/dev/null 2>&1 && [[ "$LAB_DRY" != 1 ]]; then lab_die 'working guest already exists'; fi
  lab_tart create "--from-ipsw=$ipsw" "$LAB_VM"
  lab_tart set "$LAB_VM" --cpu 4 --memory 8192 --disk-size 64
fi
printf 'Next (owner):\n  cd %s\n  ./vm-tart run --vnc %s\n' "$(dirname "$LAB_WRAPPER")" "$LAB_VM"
printf 'Complete Setup Assistant as %s (administrator), enable Remote Login and authorise the Mac SSH public key.\n' "$LAB_USER"
printf 'Verify the SSH host key interactively; then from the repository:\n  bash Tools/lab/tart/provision.sh\nProvisioning checks guest ProductVersion is 26.x (27.x also accepted with a note) before changing anything.\n'
