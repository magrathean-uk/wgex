#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# M03-T08: guarded guest-only steps for the cutover rehearsal's RUNBOOK supplements (cutover-live.py). Every mutation is
# scoped to a fixture this script created (the unrelated route and pf reference, the secrets-bundle flag) or to the WGEX
# Lab job and its positively identified effects (the manual drill). No global flush, pf disable or DNS reset.
set -euo pipefail
# shellcheck source=Tools/lab/tart/guest/guard.sh
source "$(dirname "$0")/guard.sh"
guest_guard
stage="$(cd "$(dirname "$0")" && pwd)"
cli=/Applications/WGEX.app/Contents/Helpers/wgex
label=com.magrathean.WGEXApp.dev.daemon
state='/Library/Application Support/WGEX'
# The unrelated fixtures: a host route scoped to en0 via the LAN router (TEST-NET-2, never used by any profile) and one
# pf enable reference of our own. Their identities stay in 0600 stage files; the token is never printed.
unrelated_host=198.51.100.7
action="${1:?action required}"
profile_arg() {
  local id="${1:?profile UUID required}"
  [[ "$id" =~ ^[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}$ ]] || exit 1
  printf '%s\n' "$id"
}
router() { /sbin/route -n get default 2>/dev/null | awk '$1 == "gateway:" { print $2; exit }'; }
unrelated_route_present() {
  local gateway="$1"
  /usr/sbin/netstat -rn -f inet | awk -v h="$unrelated_host" -v g="$gateway" '$1 == h && $2 == g && $NF == "en0" && $3 ~ /I/ { n++ } END { exit n != 1 }'
}
unrelated_reference_present() {
  local token
  read -r token <"$stage/unrelated.token"
  [[ "$token" =~ ^[0-9]+$ ]] || return 1
  sudo -n /sbin/pfctl -s References 2>/dev/null | awk -v t="$token" '$2 == "pfctl" && $3 == t { n++ } END { exit n != 1 }'
}
case "$action" in
  unrelated-up)
    [[ ! -e "$stage/unrelated.token" && ! -e "$stage/unrelated.router" ]] || exit 1
    gateway="$(router)"
    [[ "$gateway" =~ ^[0-9]+(\.[0-9]+){3}$ ]] || exit 1
    umask 077
    printf '%s\n' "$gateway" >"$stage/unrelated.router"
    sudo -n /sbin/route -n add -host "$unrelated_host" "$gateway" -ifscope en0 >/dev/null
    # pfctl -E prints "Token : N" on stderr; only the digits are kept, in the 0600 stage file.
    token="$(sudo -n /sbin/pfctl -E 2>&1 | awk '/^Token : [0-9]+$/ { print $3 }')"
    [[ "$token" =~ ^[0-9]+$ ]] || exit 1
    printf '%s\n' "$token" >"$stage/unrelated.token"
    unrelated_route_present "$gateway"
    unrelated_reference_present
    printf 'unrelated=up route=%s/32 en0 reference=1\n' "$unrelated_host"
    ;;
  unrelated-check)
    read -r gateway <"$stage/unrelated.router"
    route=absent reference=absent
    if unrelated_route_present "$gateway"; then route=present; fi
    if unrelated_reference_present; then reference=present; fi
    printf 'unrelated route=%s reference=%s\n' "$route" "$reference"
    [[ "$route" == present && "$reference" == present ]]
    ;;
  unrelated-down)
    if [[ -f "$stage/unrelated.router" ]]; then
      read -r gateway <"$stage/unrelated.router"
      if unrelated_route_present "$gateway"; then sudo -n /sbin/route -n delete -host "$unrelated_host" -ifscope en0 >/dev/null; fi
      if unrelated_route_present "$gateway"; then exit 1; fi
    fi
    if [[ -f "$stage/unrelated.token" ]]; then
      read -r token <"$stage/unrelated.token"
      [[ "$token" =~ ^[0-9]+$ ]] || exit 1
      if unrelated_reference_present; then sudo -n /sbin/pfctl -X "$token" >/dev/null 2>&1; fi
      if unrelated_reference_present; then exit 1; fi
    fi
    rm -f "$stage/unrelated.router" "$stage/unrelated.token"
    printf 'unrelated=down\n'
    ;;
  secrets-lock | secrets-unlock)
    # The failed-stop fixture: the user-immutable flag makes the daemon's unlink of this profile's bundle fail (EPERM),
    # so the rollback's deleteSecrets step fails twice and the trial stays rollbackPending until the flag is cleared.
    id="$(profile_arg "${2:-}")"
    bundle="$state/secrets/bundles/$id-privateKey-$id.blob"
    if [[ "$action" == secrets-lock ]]; then
      sudo -n test -f "$bundle" || exit 1
      sudo -n /usr/bin/chflags uchg "$bundle"
      printf 'bundle=locked\n'
    else
      if sudo -n test -e "$bundle"; then sudo -n /usr/bin/chflags nouchg "$bundle"; fi
      printf 'bundle=unlocked\n'
    fi
    ;;
  bundle-state)
    id="$(profile_arg "${2:-}")"
    if sudo -n test -e "$state/secrets/bundles/$id-privateKey-$id.blob"; then printf 'bundle=present\n'; else printf 'bundle=absent\n'; fi
    ;;
  journal-cutover)
    # Only the trial's public state leaves the guest: state, reason and rollbackPending from the replayed journal.
    umask 077
    replayed="$(mktemp "$stage/replay.XXXXXX")"
    trap 'rm -f "$replayed"' EXIT
    # shellcheck disable=SC2024 # The guest user owns the 0600 output on purpose; only the read needs root.
    sudo -n /usr/bin/perl "$stage/journal-replay.pl" "$state" >"$replayed" 2>/dev/null || exit 1
    pending="$(plutil -extract cutover.rollbackPending raw -o - "$replayed" 2>/dev/null || printf 'absent')"
    reason="$(plutil -extract cutover.state.rolledBack.reason raw -o - "$replayed" 2>/dev/null || printf 'none')"
    printf 'rollbackPending=%s reason=%s\n' "$pending" "$reason"
    ;;
  restart-daemon)
    before="$(pgrep -o -x WGEXDaemon || true)"
    sudo -n /bin/launchctl kickstart -k "system/$label"
    for ((attempt = 0; attempt < 120; attempt++)); do
      after="$(pgrep -o -x WGEXDaemon || true)"
      if [[ -n "$after" && "$after" != "$before" ]] && "$cli" status --json >/dev/null 2>&1; then
        printf 'restarted=1 changed=1\n'
        exit 0
      fi
      sleep 0.5
    done
    exit 1
    ;;
  boot-session) /usr/sbin/sysctl -n kern.bootsessionuuid | tr '[:lower:]' '[:upper:]' ;;
  app-state) if pgrep -x WGEX >/dev/null; then printf 'app=running\n'; else printf 'app=absent\n'; fi ;;
  manual-drill)
    # RUNBOOK "Manual offline recovery" with the guest Lab label: bootout, then the journal's ownership metadata (the
    # checkpoint with journal.log replayed), the anchor flush, the token release only on an exact References match,
    # owned routes, the canary and the exact DNS key; then each effect is checked absent. The stage files from the
    # rehearsal's remember step (address, routes, canary, token, pid, boot) describe the same trial and must agree.
    id="$(profile_arg "${2:-}")"
    cutover="${3:?cutover stage required}"
    [[ "$cutover" == /Users/*/lab/cutover ]] || exit 1
    umask 077
    replayed="$(mktemp "$stage/drill.XXXXXX")"
    trap 'rm -f "$replayed"' EXIT
    field() { plutil -extract "$1" raw -o - "$replayed" 2>/dev/null; }
    # Unconditional (RUNBOOK): the bootout's own exit status is recorded, never trusted; print exiting 113 (service not
    # found) is the proof that the job is out, as in the RUNBOOK's step 5. bootout can return while launchd still lists
    # the job (guest run M03-T08 2: print exited 0 right after bootout exited 0), so print is polled for up to 20 s.
    if sudo -n /bin/launchctl bootout "system/$label" 2>/dev/null; then booted=0; else booted=$?; fi
    for ((attempt = 0; attempt < 40; attempt++)); do
      if sudo -n /bin/launchctl print "system/$label" >/dev/null 2>&1; then printed=0; else printed=$?; fi
      [[ "$printed" != 113 ]] || break
      sleep 0.5
    done
    printf 'bootout rc=%s print rc=%s after %s polls\n' "$booted" "$printed" "$((attempt + 1))"
    [[ "$printed" == 113 ]] || exit 1
    # shellcheck disable=SC2024 # 0600 output owned by the guest user; only the read needs root.
    sudo -n /usr/bin/perl "$stage/journal-replay.pl" "$state" >"$replayed"
    [[ "$(field cutover.profileID)" == "$id" ]] || exit 1
    generation="$(field generation)"
    resource=
    for ((index = 0; ; index++)); do
      candidate="$(field "resources.$index.generation")" || break
      if [[ "$candidate" == "$generation" ]]; then resource="resources.$index"; fi
    done
    [[ -n "$resource" ]] || exit 1
    printf 'journal profile=match resource=current-generation\n'
    sudo -n /sbin/pfctl -a com.apple/wgex -F all >/dev/null 2>&1
    printf 'anchor flush rc=0\n'
    token="$(field pfToken || true)"
    pid="$(field pfTokenPID || true)"
    boot="$(field pfBootSession | tr '[:lower:]' '[:upper:]' || true)"
    current_boot="$(/usr/sbin/sysctl -n kern.bootsessionuuid | tr '[:lower:]' '[:upper:]')"
    released=no
    if [[ "$token" =~ ^[0-9]+$ && "$pid" =~ ^[0-9]+$ && "$boot" == "$current_boot" ]]; then
      if sudo -n /sbin/pfctl -s References 2>/dev/null | awk -v p="$pid" -v t="$token" '$1 == p && $2 == "pfctl" && $3 == t { n++ } END { exit n != 1 }'; then
        sudo -n /sbin/pfctl -X "$token" >/dev/null 2>&1
        released=exact-match
      fi
    fi
    if [[ "$released" == no && -z "$token" ]]; then
      # No journalled token (an unclean stop): only the sole pfctl References row may be released (RUNBOOK).
      rows="$(sudo -n /sbin/pfctl -s References 2>/dev/null | awk '$1 ~ /^[0-9]+$/ && $2 == "pfctl" && $3 ~ /^[0-9]+$/ { print $3 }')"
      if [[ "$rows" =~ ^[0-9]+$ ]]; then
        token="$rows"
        sudo -n /sbin/pfctl -X "$token" >/dev/null 2>&1
        released=sole-row
      fi
    fi
    printf 'token release=%s\n' "$released"
    [[ "$released" != no ]] || exit 1
    utun="$(field "$resource.identity.name" || true)"
    for ((index = 0; ; index++)); do
      destination="$(field "$resource.routes.$index.destination")" || break
      prefix="$(field "$resource.routes.$index.prefixLength")"
      interface="$(field "$resource.routes.$index.interfaceName")"
      [[ "$interface" == "$utun" && "$interface" =~ ^utun[0-9]+$ ]] || continue
      if /usr/sbin/netstat -rn -f inet | awk -v i="$interface" '$NF == i { n++ } END { exit n == 0 }'; then
        sudo -n /sbin/route -n delete -net "$destination/$prefix" -interface "$interface" >/dev/null 2>&1 || true
      fi
    done
    printf 'utun routes=checked\n'
    canary_interface="$(field "$resource.canaryRoute.identity.name" || true)"
    canary_router="$(field "$resource.canaryRoute.router" || true)"
    if [[ "$canary_interface" =~ ^en[0-9]+$ ]]; then
      row="$(/usr/sbin/netstat -rn -f inet | awk -v i="$canary_interface" -v g="$canary_router" '$1 == "192.0.2.1" && $2 == g && $NF == i && $3 ~ /H/ && $3 ~ /S/ && $3 ~ /2/ && $3 ~ /I/ { n++ } END { print n + 0 }')"
      if [[ "$row" == 1 ]]; then sudo -n /sbin/route -n delete -host 192.0.2.1 -ifscope "$canary_interface" >/dev/null; fi
      printf 'canary owned rows=%s\n' "$row"
    fi
    dns_key="$(field "$resource.dnsKey" || true)"
    if [[ "$dns_key" == "State:/Network/Service/$id/DNS" ]]; then
      printf 'remove %s\nquit\n' "$dns_key" | sudo -n /usr/sbin/scutil
    fi
    # Checks: the WGEX anchor empty, the trial's reference gone, no WGEX address, no canary, no DNS key; the job stays out.
    rules="$(sudo -n /sbin/pfctl -a com.apple/wgex -sr 2>/dev/null)"
    [[ -z "$rules" ]] || exit 1
    ! sudo -n /sbin/pfctl -s References 2>/dev/null | awk -v t="$token" '$2 == "pfctl" && $3 == t { n++ } END { exit n == 0 }' || exit 1
    address="$(cat "$cutover/address")"
    ! {
      /sbin/ifconfig -a
      /usr/sbin/netstat -rn
    } | awk -v a="$address" '{ for (i = 1; i <= NF; i++) { split($i, p, /[%\/]/); if (p[1] == a) n++ } } END { exit n == 0 }' || exit 1
    ! /usr/sbin/netstat -rn -f inet | awk '$1 == "192.0.2.1" { n++ } END { exit n == 0 }' || exit 1
    dns="$(printf 'show State:/Network/Service/%s/DNS\nquit\n' "$id" | scutil)"
    [[ "$dns" != *ServerAddresses* ]] || exit 1
    if sudo -n /bin/launchctl print "system/$label" >/dev/null 2>&1; then exit 1; fi
    printf 'drill: anchor empty, reference released, address, canary and DNS key absent, job booted out\n'
    ;;
  *) exit 2 ;;
esac
