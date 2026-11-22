#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
# shellcheck source=Tools/lab/tart/lib.sh
source "$(dirname "$0")/tart/lib.sh"
dry=0
if [[ "${1:-}" == --dry-run ]]; then
  dry=1
  shift
fi
[[ "${1:-}" == up ]] || lab_die 'usage: just lab peer up [--adopt] [--variant NAME] [--dry-run]'
shift
adopt=()
variant=default
while (($#)); do
  case "$1" in
    --dry-run) dry=1 ;;
    --adopt) adopt=(--adopt) ;;
    --variant)
      [[ $# -ge 2 ]] || lab_die '--variant needs a profile name'
      variant="$2"
      shift
      ;;
    *) lab_die 'unexpected peer argument' ;;
  esac
  shift
done
case "$variant" in default | full4 | full4-name | dual | dns | lockdown | wrong-key) ;; *) lab_die 'invalid peer profile variant' ;; esac
mirror="${WGEX_LAB_APT_MIRROR:-https://deb.debian.org/debian}"
[[ "$mirror" =~ ^https?://[a-zA-Z0-9./:_-]+$ ]] || lab_die 'invalid apt mirror'
if [[ "$dry" == 1 ]]; then
  printf 'dry-run: vm-lima wg-peer: stage fixture keys over stdin; provision dedicated wg0; persist wg-quick@wg0 boot configuration (0600, atomic); mirror %s; apt deadlines 180s; adopt=%s; variant=%s\n' "$mirror" "${adopt[*]:-no}" "$variant"
  exit
fi
peer="${WGEX_LAB_VM_ROOT:-$HOME/wgex-lab-vm}/vm-lima"
[[ -x "$peer" ]] || lab_die 'vm-lima wrapper missing (set WGEX_LAB_VM_ROOT)'
peer_run() { perl -e 'alarm shift; exec @ARGV or die "exec failed\n"' 420 "$peer" shell wg-peer -- "$@"; }
# shellcheck disable=SC2016 # expanded in the Linux peer, not the host
peer_run bash -c 'set -eu; test "$(uname -s)" = Linux; case "$(hostname)" in wg-peer | lima-wg-peer) ;; *) exit 1 ;; esac; sudo -n install -d -m 0700 /etc/wireguard/wgex-lab'
peer_run sudo -n tee /etc/wireguard/wgex-lab/provision.sh <"$LAB_ROOT/Tools/lab/lima/peer-provision.sh" >/dev/null
peer_run sudo -n tee /etc/wireguard/wgex-lab/peer-state.sh <"$LAB_ROOT/Tools/lab/lima/peer-state.sh" >/dev/null
for name in server.key client1.key client1.pub client2.key; do
  sed '/^#/d; /^[[:space:]]*$/d' "$LAB_ROOT/Tests/Fixtures/keys/$name" | peer_run sudo -n tee "/etc/wireguard/wgex-lab/$name" >/dev/null
done
peer_run sudo -n chmod -R go-rwx /etc/wireguard/wgex-lab
peer_run sudo -n bash /etc/wireguard/wgex-lab/provision.sh up "$mirror" --variant "$variant" ${adopt[@]+"${adopt[@]}"}
