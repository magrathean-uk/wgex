#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# M08-T16 guarded guest-only pf operations for the port-exclusion mechanism spike (design M08-T15 section 4, T1).
# Writes only the sibling anchor com.apple/100.wgex-px (it sorts before the daemon's com.apple/wgex, so its quick rules
# match first and the daemon's anchor and read-back stay untouched) and kills states sourced from the lab tunnel address.
# Everything else is a read. Run by px-spike.py through `just lab ssh`.
set -euo pipefail
refuse() {
  printf 'px-spike: %s\n' "$*" >&2
  exit 1
}
# shellcheck source=Tools/lab/tart/guest/guard.sh
source "$(dirname "$0")/guard.sh"
guest_guard
stage="$(dirname "$0")"
anchor=com.apple/100.wgex-px
action="${1:?action required}"
case "$action" in
  load)
    # load RULES-NAME: the staged rule text (px-rules-*.conf next to this script) into the spike anchor, nat and filter
    # in one transaction (pfctl requires translation before filtering in the text).
    name="${2:?rules required}"
    [[ "$#" == 2 && "$name" =~ ^px-rules-[a-z0-9-]{1,40}\.conf$ && -f "$stage/$name" && ! -L "$stage/$name" ]] || refuse "load: rules name refused or not staged"
    sudo -n pfctl -o none -a "$anchor" -f "$stage/$name" 2>&1
    ;;
  empty)
    # An empty load of the spike anchor (check f: does it flush the nat ruleset too).
    printf '' | sudo -n pfctl -o none -a "$anchor" -f - 2>&1
    ;;
  flush)
    sudo -n pfctl -a "$anchor" -F all 2>&1 || true
    ;;
  show)
    # The spike anchor's translation and filter rules as pfctl prints them back (check e), between markers.
    printf '# nat\n'
    sudo -n pfctl -a "$anchor" -sn 2>/dev/null || true
    printf '# rules\n'
    sudo -n pfctl -a "$anchor" -sr 2>/dev/null || true
    printf '# end\n'
    ;;
  states)
    # The whole state table (check g reads the lines naming the tunnel address).
    sudo -n pfctl -ss 2>/dev/null || true
    ;;
  kill)
    address="${2:?address required}"
    [[ "$#" == 2 && "$address" =~ ^10\.77\.0\.[0-9]{1,3}$ ]] || refuse "kill: only the lab tunnel address"
    sudo -n pfctl -k "$address" 2>&1
    ;;
  main-nat)
    # The main ruleset's translation anchors (the design's precondition: nat-anchor "com.apple/*").
    sudo -n pfctl -s nat 2>/dev/null || true
    ;;
  ipv6)
    # Item i facts: the guest's IPv6 default routes and en0's IPv6 addresses (no change).
    netstat -rn -f inet6 2>/dev/null | awk '$1 == "default" {print "default " $2 " " $NF}'
    ifconfig en0 inet6 2>/dev/null | awk '$1 == "inet6" {print "inet6 " $2 " " $NF}'
    ;;
  stack)
    # Round 3: where a reply dies after pf (read only): the input interface check mode and the IP, TCP and UDP counters.
    printf '# sysctl\n'
    sysctl net.inet.ip.check_interface net.inet.ip.forwarding net.inet6.ip6.check_interface 2>/dev/null || true
    for proto in ip tcp udp; do
      printf '# %s\n' "$proto"
      netstat -s -p "$proto" 2>/dev/null || true
    done
    printf '# end\n'
    ;;
  aux-start)
    # aux-start LABEL: pflog0 (created when missing) and lo0 (packets naming the tunnel address) captures for one window.
    label="${2:?label required}"
    [[ "$#" == 2 && "$label" =~ ^[a-z0-9-]{1,40}$ ]] || refuse "aux-start: label refused"
    aux=/var/tmp/wgex-px-aux
    sudo -n mkdir -p "$aux" && sudo -n chmod 0700 "$aux"
    if ! /sbin/ifconfig pflog0 >/dev/null 2>&1; then
      sudo -n /sbin/ifconfig pflog0 create 2>&1 || printf 'pflog0 create failed\n'
    fi
    sudo -n /sbin/ifconfig pflog0 up 2>/dev/null || true
    for iface in pflog0 lo0; do
      filter=()
      [[ "$iface" == lo0 ]] && filter=(host 10.77.0.2)
      sudo -n bash -c 'nohup /usr/sbin/tcpdump -n -U -s 256 -i "$1" -w "$2" "${@:4}" </dev/null >"$3" 2>&1 & echo $! >"$2.pid"' \
        _ "$iface" "$aux/$label-$iface.pcap" "$aux/$label-$iface.log" ${filter[@]+"${filter[@]}"}
    done
    sleep 1
    for iface in pflog0 lo0; do
      pid="$(sudo -n cat "$aux/$label-$iface.pcap.pid")"
      if sudo -n kill -0 "$pid" 2>/dev/null; then printf 'aux %s %s\n' "$iface" "$aux/$label-$iface.pcap"; else printf 'aux %s failed: %s\n' "$iface" "$(sudo -n sed -n 1,2p "$aux/$label-$iface.log" | tr '\n' ' ')"; fi
    done
    ;;
  aux-stop)
    # aux-stop: stops the tcpdumps aux-start recorded (only those pids).
    aux=/var/tmp/wgex-px-aux
    for file in $(sudo -n find "$aux" -name '*.pcap.pid' 2>/dev/null); do
      pid="$(sudo -n cat "$file")"
      [[ "$pid" =~ ^[0-9]+$ ]] && [[ "$(ps -o comm= -p "$pid" 2>/dev/null)" == *tcpdump ]] && sudo -n kill "$pid" 2>/dev/null || true
      sudo -n rm -f "$file"
    done
    sleep 1
    ;;
  checkif)
    # checkif 0|1|2: DIAGNOSTIC only (never a candidate rule set): the guest's net.inet.ip.check_interface for one
    # window, set back by the driver straight after; prints the previous value.
    value="${2:?value required}"
    [[ "$#" == 2 && "$value" =~ ^[012]$ ]] || refuse "checkif: value refused"
    printf 'previous %s\n' "$(sysctl -n net.inet.ip.check_interface)"
    sudo -n sysctl -w "net.inet.ip.check_interface=$value" 2>&1
    ;;
  *) refuse "unknown action" ;;
esac
