#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# No host config file, key argument, key diagnostic or console output.
set +x
set -euo pipefail
# shellcheck source=Tools/lab/tart/lib.sh
source "$(dirname "$0")/tart/lib.sh"
dry=0
if [[ "${1:-}" == --dry-run ]]; then
  dry=1
  shift
fi
variant="${1:-default}"
if (($#)); then shift; fi
if [[ "${1:-}" == --dry-run ]]; then
  dry=1
  shift
fi
case "$variant" in default | full4 | full4-name | dual | dns | lockdown | wrong-key) ;; *) lab_die 'profile variant: default, full4, full4-name, dual, dns, lockdown, wrong-key' ;; esac
(($# == 0)) || lab_die 'unexpected profile argument'
if [[ "$dry" == 1 ]]; then
  printf 'dry-run: private stdin pipe wg-peer -> guarded Tart guest; profile %s; no host key file\n' "$variant"
  exit
fi
lab_init
lab_connect
guest_is_lab
lab_ssh "umask 077; mkdir -p /Users/$LAB_USER/lab; test ! -L /Users/$LAB_USER/lab/wgex-lab-$variant.conf" </dev/null
peer="${WGEX_LAB_VM_ROOT:-$HOME/wgex-lab-vm}/vm-lima"
[[ -x "$peer" ]] || lab_die 'vm-lima wrapper missing (set WGEX_LAB_VM_ROOT)'
# Refresh the generator from this checkout, never patch it by hand on the peer.
for name in peer-state.sh peer-provision.sh; do
  target="$name"
  [[ "$name" != peer-provision.sh ]] || target=provision.sh
  perl -e 'alarm shift; exec @ARGV or die "exec failed\n"' "$LAB_PEER_SHELL" "$peer" shell wg-peer -- sudo -n tee "/etc/wireguard/wgex-lab/$target" <"$LAB_ROOT/Tools/lab/lima/$name" >/dev/null
done
perl -e 'alarm shift; exec @ARGV or die "exec failed\n"' "$LAB_PEER_SHELL" "$peer" shell wg-peer -- sudo -n chmod go-rwx /etc/wireguard/wgex-lab/peer-state.sh /etc/wireguard/wgex-lab/provision.sh
perl -e 'alarm shift; exec @ARGV or die "exec failed\n"' "$LAB_PEER_SHELL" "$peer" shell wg-peer -- sudo -n bash /etc/wireguard/wgex-lab/provision.sh profile "$variant" |
  lab_ssh "umask 077; cat > /Users/$LAB_USER/lab/wgex-lab-$variant.conf; chmod 0600 /Users/$LAB_USER/lab/wgex-lab-$variant.conf" >/dev/null 2>&1
printf 'profile copied privately: %s\n' "$variant"
if [[ "$variant" == lockdown ]]; then
  printf 'Lockdown is a daemon global setting, not a WireGuard config key; the verdict runner checks its GUI state.\n'
fi
