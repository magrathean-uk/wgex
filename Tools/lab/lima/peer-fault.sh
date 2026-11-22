#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Scoped impairment on the dedicated peer only, never on the host bridge.
set -euo pipefail
# shellcheck source=Tools/lab/lima/peer-state.sh
source "$(dirname "$0")/peer-state.sh"
peer_guard "$@"
[[ "${1:-}" != --dry-run ]] || shift
if [[ "${1:-}" == cleanup && ! -f "$state/netem-owned" && ! -f "$state/mtu-before" ]]; then
  printf 'peer: no row-owned fault to clear\n'
  exit 0
fi
[[ -f "$state/owned" ]] || peer_die 'wg0 ownership marker missing; run just lab peer up (existing wg0 needs --adopt after verifying dedicated ownership)'
case "${1:-}" in
  check)
    peer_exec ip link show wg0 >/dev/null 2>&1 || peer_die 'wg0 missing; run just lab peer up'
    ;;
  loss | latency)
    iface="$(peer_exec ip -o route get 192.168.64.1 | awk '!found {for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); found = 1; break}}')"
    [[ "$iface" =~ ^[a-zA-Z0-9]+$ ]] || peer_die 'invalid peer uplink'
    [[ ! -f "$state/netem-owned" ]] || exit 1
    # add, never replace: refuse an existing administrator qdisc.
    if [[ "$1" == loss ]]; then peer_exec tc qdisc add dev "$iface" root netem loss 20%; else peer_exec tc qdisc add dev "$iface" root netem delay 300ms; fi
    printf '%s\n' "$iface" >"$state/netem-owned"
    ;;
  cleanup)
    if [[ -f "$state/netem-owned" ]]; then
      read -r iface <"$state/netem-owned"
      [[ "$iface" =~ ^[a-zA-Z0-9]+$ ]] || exit 1
      if peer_exec ip link show "$iface" >/dev/null 2>&1; then
        qdiscs="$(peer_exec tc qdisc show dev "$iface")"
        if grep -Eq '^qdisc netem [^ ]+ root( |$)' <<<"$qdiscs"; then
          peer_exec tc qdisc del dev "$iface" root
        fi
      fi
      rm -f "$state/netem-owned"
    fi
    if [[ -f "$state/mtu-before" ]]; then
      read -r mtu <"$state/mtu-before"
      [[ "$mtu" =~ ^[0-9]+$ ]] || exit 1
      if peer_exec ip link show wg0 >/dev/null 2>&1; then peer_exec ip link set dev wg0 mtu "$mtu"; fi
      rm -f "$state/mtu-before"
    fi
    ;;
  *) exit 2 ;;
esac
