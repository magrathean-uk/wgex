#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# M08-T04 guarded guest-only operations for the exclusions rows. Reads only, except the row's own profile file
# (~/lab/wgex-lab-m08.conf, 0600, never printed) and the probe's files in the stage directory.
set -euo pipefail
# Every refusal names itself on stderr (run 2: a bare exit 1 left the driver only the lab wrapper's guest-version note).
refuse() {
  printf 'm08-actions: %s\n' "$*" >&2
  exit 1
}
# shellcheck source=Tools/lab/tart/guest/guard.sh
source "$(dirname "$0")/guard.sh"
guest_guard
stage="$(dirname "$0")"
action="${1:?action required}"
case "$action" in
  make-conf)
    # make-conf ENTRIES: the full4 fixture profile plus one "# WGEX-Exclude = ENTRIES" line after its Address line.
    entries="${2:?entries required}"
    # Length apart from the character class: macOS regcomp refuses a bound above RE_DUP_MAX (255), so the old bound of 400 never matched.
    [[ "$#" == 2 && "${#entries}" -le 400 && "$entries" =~ ^[A-Za-z0-9.:/,\ -]+$ ]] || refuse "make-conf: entries refused (charset or length)"
    source_conf="$HOME/lab/wgex-lab-full4.conf"
    target="$HOME/lab/wgex-lab-m08.conf"
    [[ -f "$source_conf" && ! -L "$source_conf" ]] || refuse "make-conf: ~/lab/wgex-lab-full4.conf missing or a link"
    [[ ! -L "$target" ]] || refuse "make-conf: target profile is a link"
    umask 077
    # The file carries fixture secrets: copied without printing, one comment line added inside [Interface].
    WGEX_M08_ENTRIES="$entries" perl -ne 'print; if (!$done && /^Address\s*=/) { print "# WGEX-Exclude = $ENV{WGEX_M08_ENTRIES}\n"; $done = 1 } END { $? = $done ? 0 : 1 }' \
      "$source_conf" >"$target.next" || refuse "make-conf: no Address line in the full4 profile"
    chmod 0600 "$target.next"
    mv -f "$target.next" "$target"
    grep -c '^# WGEX-Exclude = ' "$target"
    ;;
  en0)
    # The physical interface's IPv4 address, interface index, router and DHCP resolver (one line, key=value).
    address="$(ipconfig getifaddr en0 2>/dev/null || true)"
    index="$(ifconfig -v en0 2>/dev/null | sed -n 's/.*[[:space:]]index \([0-9][0-9]*\).*/\1/p' | sed -n 1p)"
    router="$(ipconfig getoption en0 router 2>/dev/null || true)"
    resolver="$(ipconfig getoption en0 domain_name_server 2>/dev/null || true)"
    printf 'address=%s index=%s router=%s resolver=%s\n' "${address:-none}" "${index:-none}" "${router:-none}" "${resolver:-none}"
    ;;
  route)
    dst="${2:?destination required}"
    [[ "$dst" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || refuse "route: destination refused"
    route -n get "$dst" 2>/dev/null | awk '$1 == "interface:" {print "interface=" $2}'
    ;;
  lookup)
    # lookup NAME SERVER: one bounded A query to the physical resolver, before the tunnel is up (precondition only).
    name="${2:?name required}"
    server="${3:?server required}"
    [[ "$name" =~ ^[a-z0-9.-]{1,200}$ && "$server" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || refuse "lookup: name or server refused"
    dig +time=3 +tries=1 +short "@$server" "$name" A 2>/dev/null | grep -E '^[0-9.]+$' || true
    ;;
  anchor)
    # The daemon's anchor and its sub-anchors, rules only (evidence).
    sudo -n pfctl -a com.apple/wgex -sr 2>/dev/null || true
    for sub in $(sudo -n pfctl -a com.apple/wgex -sA 2>/dev/null); do
      [[ "$sub" =~ ^[A-Za-z0-9/._-]+$ ]] || continue
      printf '# anchor %s\n' "$sub"
      sudo -n pfctl -a "$sub" -sr 2>/dev/null || true
    done
    ;;
  probe)
    # probe PLAN-NAME: runs the plan staged next to this script, then prints its result.
    plan="${2:?plan required}"
    [[ "$plan" =~ ^plan-[a-z0-9-]{1,40}\.json$ && -f "$stage/$plan" ]] || refuse "probe: plan name refused or not staged"
    result="$stage/${plan/plan-/result-}"
    rm -f "$result"
    /usr/bin/perl "$stage/excl-probe.pl" "$stage/$plan" "$result"
    cat "$result"
    ;;
  *) refuse "unknown action" ;;
esac
