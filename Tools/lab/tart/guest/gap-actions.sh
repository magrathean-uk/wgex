#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# M03 kept-gap injections. This file is copied into the guest, never run on the host.
set -euo pipefail
# shellcheck source=Tools/lab/tart/guest/guard.sh
source "$(dirname "$0")/guard.sh"
guest_guard
stage="$(dirname "$0")"
# The one lab user of the guest image: the console-user check and the logout action both key on it.
lab_user="$(guest_lab_user)"
cli=/Applications/WGEX.app/Contents/Helpers/wgex
now() { perl -MTime::HiRes=time -e 'printf "%.3f", time'; }
dns_service() {
  # Resolve the guest's primary en0 service by UUID, never by a host-supplied name.
  service="$(printf 'show State:/Network/Global/IPv4\n' | scutil | awk '/PrimaryService :/ {print $3}')"
  [[ "$service" =~ ^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$ ]] || exit 1
  device="$(printf 'show Setup:/Network/Service/%s/Interface\n' "$service" | scutil)"
  [[ "$device" == *'DeviceName : en0'* ]] || exit 1
  name="$(printf 'show Setup:/Network/Service/%s\n' "$service" | scutil | sed -n 's/^  UserDefinedName : //p')"
  [[ -n "$name" && "$name" != *$'\n'* ]] || exit 1
}
od_identity() {
  # "pid|start time" of the running Lab daemon; fails when either is unavailable (the daemon is between two lives).
  local pid started
  pid="$(pgrep -o -x WGEXDaemon || true)"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  started="$(LC_ALL=C ps -o lstart= -p "$pid" 2>/dev/null | tr -s ' ' | sed 's/^ //; s/ $//')" || return 1
  [[ -n "$started" ]] || return 1
  printf '%s|%s\n' "$pid" "$started"
}
sample() {
  local status pid refs info rules
  status="$("$cli" status --json 2>/dev/null)" || status='{}'
  pid="$(pgrep -x WGEXDaemon || true)"
  [[ "$pid" =~ ^[0-9]+$ ]] || pid=0
  refs="$(sudo -n pfctl -s References 2>/dev/null)" || refs=
  info="$(sudo -n pfctl -s info 2>/dev/null)" || info=
  rules="$(sudo -n pfctl -a com.apple/wgex -sr 2>/dev/null)" || rules=
  perl "$stage/gap-status.pl" "$(now)" "$pid" "$refs" "$info" "$rules" <<<"$status"
}
case "${1:?action required}" in
  dns-edit)
    dns_service
    [[ ! -e "$stage/dns-before" && ! -L "$stage/dns-before" ]] || exit 1
    umask 077
    networksetup -getdnsservers "$name" >"$stage/dns-before"
    printf '%s\n' "$service" >"$stage/dns-service"
    # Register rollback before changing anything, including a failed read-back.
    trap 'bash "$0" dns-restore' ERR
    sudo -n networksetup -setdnsservers "$name" 192.0.2.53
    [[ "$(networksetup -getdnsservers "$name")" == 192.0.2.53 ]]
    trap - ERR
    printf '{"edited":true}\n'
    ;;
  dns-check)
    dns_service
    [[ "$(cat "$stage/dns-service")" == "$service" ]] || exit 1
    if [[ "$(networksetup -getdnsservers "$name")" == 192.0.2.53 ]]; then
      printf '{"preserved":true}\n'
    else
      printf '{"preserved":false}\n'
    fi
    ;;
  dns-restore)
    [[ -f "$stage/dns-before" && ! -L "$stage/dns-before" ]] || exit 1
    dns_service
    [[ "$(cat "$stage/dns-service")" == "$service" ]] || exit 1
    servers=()
    while IFS= read -r line; do servers+=("$line"); done <"$stage/dns-before"
    [[ "${#servers[@]}" -gt 0 ]] || exit 1
    if [[ "${servers[0]}" == "There aren't any DNS Servers set on "* ]]; then servers=(Empty); fi
    sudo -n networksetup -setdnsservers "$name" "${servers[@]}"
    cmp -s "$stage/dns-before" <(networksetup -getdnsservers "$name")
    printf '{"restored":true}\n'
    ;;
  fault)
    fault="${2:?fault required}"
    [[ "$fault" == token || "$fault" == pf-disable || "$fault" == rt22 ]] || exit 1
    printf 'baseline '
    sample
    # No token is accepted from the caller or guessed from the reference table.
    if [[ "$fault" == token ]]; then
      status="$("$cli" status --json)"
      token="$(plutil -extract ownerPFToken raw -o - - <<<"$status")" || exit 1
      [[ "$token" =~ ^[1-9][0-9]{0,19}$ ]] || exit 1
      # -type accepts every value kind: -extract json refuses the scalar sequence and measuredAt.
      for field in sequence measuredAt journalPolicy; do
        plutil -type "$field" - <<<"$status" >/dev/null || exit 1
      done
      refs="$(sudo -n pfctl -s References 2>/dev/null)"
      awk -v token="$token" '$1 ~ /^[0-9]+$/ && $3 == token {n++} END {exit n != 1}' <<<"$refs"
    fi
    injected="$(now)"
    printf 'injectedAt %s\n' "$injected"
    case "$fault" in
      token) sudo -n pfctl -X "$token" >/dev/null 2>&1 ;;
      pf-disable) sudo -n pfctl -d >/dev/null 2>&1 ;;
      rt22) bash "$stage/verdict-actions.sh" kill-app ;;
    esac
    # Bounded guest-side sampling spans unknown and recovery without one SSH round trip per status. It runs until 14 s after
    # the injection (the 7 s detection bound, 5 s of observation after restoration and a margin), capped by a sample count.
    deadline="$(perl -e 'printf "%.3f", $ARGV[0] + 14' "$injected")"
    for ((i = 0; i < 150; i++)); do
      printf 'sample '
      sample
      awk -v n="$(now)" -v d="$deadline" 'BEGIN { exit !(n >= d) }' && break
      sleep 0.1
    done
    ;;
  rt21-start)
    [[ ! -e "$stage/pf-watch.pid" ]] || exit 1
    sudo -n nohup bash "$0" rt21-watch >/dev/null 2>&1 </dev/null &
    for ((i = 0; i < 40; i++)); do
      [[ ! -f "$stage/pf-watch.failed" ]] || exit 1
      if [[ -f "$stage/pf-watch.ready" ]]; then exit 0; fi
      sleep 0.1
    done
    exit 1
    ;;
  rt21-watch)
    ((EUID == 0)) || exit 1
    pid="$(pgrep -x WGEXDaemon)"
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || exit 1
    umask 077
    mkfifo "$stage/pf-execs.pipe"
    printf '%s\n' "$$" >"$stage/pf-watch.pid"
    ps -p "$$" -o ppid= -o lstart= >"$stage/pf-watch.identity"
    # The filter's own stderr is discarded: process arguments can hold secrets. It records one fixed diagnostic in pf-execs.err itself.
    perl "$stage/pf-execs.pl" "$pid" "$stage/pf-execs.err" <"$stage/pf-execs.pipe" >"$stage/pf-execs.jsonl" 2>/dev/null &
    filter=$!
    /usr/bin/eslogger exec >"$stage/pf-execs.pipe" 2>/dev/null &
    watcher=$!
    watcher_identity="$(ps -p "$watcher" -o ppid= -o lstart=)"
    stop_watch() {
      if [[ "$(ps -p "$watcher" -o ppid= -o lstart=)" == "$watcher_identity" ]]; then kill -TERM "$watcher" 2>/dev/null || true; fi
      wait "$watcher" 2>/dev/null || true
      if ! wait "$filter"; then touch "$stage/pf-watch.failed"; fi
      touch "$stage/pf-watch.done"
    }
    trap stop_watch EXIT
    trap 'exit 0' TERM INT
    sleep 1
    kill -0 "$watcher" "$filter" || {
      touch "$stage/pf-watch.failed"
      exit 1
    }
    touch "$stage/pf-watch.ready"
    if ! wait "$watcher"; then touch "$stage/pf-watch.failed"; fi
    ;;
  rt21-stop)
    # Each refusal names its cause on stderr (fixed words, and the filter's fixed diagnostic only if it matches the known shape),
    # so a failed stop is diagnosable and never echoes parser output.
    pid="$(sudo -n cat "$stage/pf-watch.pid")"
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || {
      echo 'rt21-stop: no watcher pid' >&2
      exit 1
    }
    [[ "$(ps -p "$pid" -o args=)" == *"$stage/gap-actions.sh rt21-watch" ]] || {
      echo 'rt21-stop: watcher is not running' >&2
      exit 1
    }
    [[ "$(ps -p "$pid" -o ppid= -o lstart=)" == "$(sudo -n cat "$stage/pf-watch.identity")" ]] || {
      echo 'rt21-stop: watcher identity changed' >&2
      exit 1
    }
    sudo -n kill -TERM "$pid"
    # eslogger drains its event backlog before it exits, and the filter reads to its end: allow thirty seconds, not four.
    for ((i = 0; i < 300; i++)); do
      if [[ -f "$stage/pf-watch.done" ]]; then break; fi
      sleep 0.1
    done
    if [[ ! -f "$stage/pf-watch.done" || -f "$stage/pf-watch.failed" ]]; then
      echo "rt21-stop: done=$([[ -f "$stage/pf-watch.done" ]] && echo yes || echo no) failed=$([[ -f "$stage/pf-watch.failed" ]] && echo yes || echo no) filter: $(sudo -n head -n 1 "$stage/pf-execs.err" 2>/dev/null | grep -E '^pf-execs: [a-zA-Z ]{1,40}$' || echo 'pf-execs: no diagnostic')" >&2
      exit 1
    fi
    sudo -n cat "$stage/pf-execs.jsonl"
    ;;
  boot-intent-set)
    id="${2:?profile UUID required}"
    setting="${3:?on or off required}"
    [[ "$id" =~ ^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$ && ("$setting" == on || "$setting" == off) ]] || exit 1
    "$cli" boot-intent "$id" "$setting" >/dev/null
    ;;
  console-user)
    if [[ "$(stat -f %Su /dev/console)" == "$lab_user" ]]; then printf 'lab\n'; else printf 'logged-out\n'; fi
    ;;
  agent-state)
    # Self-driven console (M03-T07 phase B, DEC-034): the macOS administrator dialog is SecurityAgent's window in the
    # console session. Fixed words only: agent=absent, or agent=running windows=N (N=unreadable when System Events does
    # not answer). The host types into the dialog only while this reads windows=1.
    pid="$(pgrep -x -u "$lab_user" SecurityAgent || true)"
    if [[ -z "$pid" ]]; then printf 'agent=absent\n'; else
      windows="$(sudo -n launchctl asuser "$(id -u "$lab_user")" osascript -e 'tell application "System Events" to count of windows of process "SecurityAgent"' 2>/dev/null)" || windows=unreadable
      [[ "$windows" =~ ^[0-9]+$ ]] || windows=unreadable
      printf 'agent=running windows=%s\n' "$windows"
    fi
    ;;
  logout)
    [[ "$(id -un)" == "$lab_user" && "$(stat -f %Su /dev/console)" == "$lab_user" ]] || exit 1
    # Only the guest's existing console session is asked to log out. Authentication at relogin stays with G.
    uid="$(id -u)"
    sudo -n launchctl asuser "$uid" osascript -e 'tell application "System Events" to log out'
    ;;
  # LOGIN-SILENT (DEC-021). Window, Dock and menu bar state of the console session; counts and fixed words only.
  login-item-state)
    # The profile's Connect at login choice (profile.macOptions.autoConnectAtLogin) and the app's Hide Dock icon preference.
    id="${2:?profile UUID required}"
    [[ "$id" =~ ^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$ ]] || exit 1
    wanted="$(printf '%s' "$id" | tr '[:lower:]' '[:upper:]')"
    support="$HOME/Library/Application Support/WGEX"
    login="unset"
    for file in "$support/profiles"/*.json; do
      [[ -f "$file" && ! -L "$file" ]] || continue
      [[ "$(basename "$file" .json | tr '[:lower:]' '[:upper:]')" == "$wanted" ]] || continue
      value="$(/usr/bin/plutil -extract profile.macOptions.autoConnectAtLogin raw -o - "$file" 2>/dev/null)" || value="unset"
      [[ "$value" == true || "$value" == false ]] && login="$value"
    done
    dock="unset"
    prefs="$support/mac-preferences.json"
    if [[ -f "$prefs" && ! -L "$prefs" ]]; then
      value="$(/usr/bin/plutil -extract hideDockIcon raw -o - "$prefs" 2>/dev/null)" || value=false
      [[ "$value" == true ]] && dock=true || dock=false
    fi
    printf 'autoConnectAtLogin=%s\nhideDockIcon=%s\n' "$login" "$dock"
    ;;
  presentation)
    # Runs in the console session (System Events and lsappinfo answer for the session that asks). Prints process, the
    # number of standard and other WGEX windows, the menu bar item, a running WGEX Dock item and the app type. A Dock read
    # that fails prints presentation=failed, which the checks treat as an unreadable sample.
    [[ "$(id -un)" == "$lab_user" && "$(stat -f %Su /dev/console)" == "$lab_user" ]] || exit 1
    uid="$(id -u)"
    printf 'sampledAt=%s\n' "$(now)"
    if ! pgrep -x WGEX >/dev/null; then
      printf 'process=absent\n'
      exit 0
    fi
    sudo -n launchctl asuser "$uid" osascript - <<'APPLESCRIPT' || printf 'presentation=failed\n'
tell application "System Events"
  if not (exists process "WGEX") then return "process=absent"
  set standardCount to 0
  set otherCount to 0
  tell process "WGEX"
    repeat with w in windows
      set subroleName to "unknown"
      try
        set subroleName to value of attribute "AXSubrole" of w
      end try
      if subroleName is "AXStandardWindow" then
        set standardCount to standardCount + 1
      else
        set otherCount to otherCount + 1
      end if
    end repeat
    set extra to exists menu bar 2
  end tell
  -- An unreadable Dock list or running-state attribute fails the whole sample; it never reads as "no Dock item".
  set docked to false
  tell process "Dock"
    try
      set dockMatches to (UI elements of list 1 whose name is "WGEX")
    on error
      return "presentation=failed"
    end try
    repeat with i in dockMatches
      try
        set runningState to value of attribute "AXIsApplicationRunning" of i
      on error
        return "presentation=failed"
      end try
      if runningState is true then
        set docked to true
      else if runningState is not false then
        return "presentation=failed"
      end if
    end repeat
  end tell
end tell
return "process=running" & linefeed & "standardWindows=" & standardCount & linefeed & "otherWindows=" & otherCount & linefeed & "menuBarItem=" & extra & linefeed & "dockItem=" & docked
APPLESCRIPT
    kind="$(sudo -n launchctl asuser "$uid" lsappinfo info -only ApplicationType WGEX 2>/dev/null | awk -F'"' '$2 == "ApplicationType" { print $4; exit }')" || kind=""
    [[ "$kind" =~ ^[A-Za-z]+$ ]] || kind="unknown"
    printf 'appType=%s\n' "$kind"
    ;;
  menu-open)
    # Clicks the WGEX menu bar item (menu bar 2), which shows the menu's window with wgex.menu.openWindow.
    [[ "$(id -un)" == "$lab_user" && "$(stat -f %Su /dev/console)" == "$lab_user" ]] || exit 1
    uid="$(id -u)"
    sudo -n launchctl asuser "$uid" osascript -e 'tell application "System Events" to tell process "WGEX" to click menu bar item 1 of menu bar 2' >/dev/null
    printf 'menu=opened\n'
    ;;
  # ONDEMAND-ETH. Public evidence only: no key, document or SSID leaves the guest.
  od-policy)
    # The on-demand policy of one profile in the app's own store (profile.onDemand), as compact JSON.
    id="${2:?profile UUID required}"
    [[ "$id" =~ ^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$ ]] || exit 1
    wanted="$(printf '%s' "$id" | tr '[:lower:]' '[:upper:]')"
    store="$HOME/Library/Application Support/WGEX/profiles"
    found=
    for file in "$store"/*.json; do
      [[ -f "$file" && ! -L "$file" ]] || continue
      base="$(basename "$file" .json | tr '[:lower:]' '[:upper:]')"
      [[ "$base" == "$wanted" ]] || continue
      found="$file"
    done
    [[ -n "$found" ]] || exit 1
    policy="$(/usr/bin/plutil -extract profile.onDemand json -o - "$found" 2>/dev/null)" || policy='"unset"'
    printf 'onDemand=%s\n' "$(printf '%s' "$policy" | tr -d '\n')"
    ;;
  od-probe)
    # One status read as the daemon that answers it: its pid, start time and the on-demand fields (od-status.pl). The read is
    # bracketed by two identity reads (pid and start time); the sample is kept only when both are available and identical, so a
    # status can never be labelled with a replacement daemon's pid. A discarded read prints its reason and carries no pid.
    id="${2:?profile UUID required}"
    [[ "$id" =~ ^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$ ]] || exit 1
    before="$(od_identity || true)"
    status="$("$cli" status --json 2>/dev/null)" || status='{}'
    after="$(od_identity || true)"
    if [[ -z "$before" || -z "$after" ]]; then
      perl "$stage/od-status.pl" "$(now)" 0 "" "$id" identityUnavailable <<<'{}'
    elif [[ "$before" != "$after" ]]; then
      perl "$stage/od-status.pl" "$(now)" 0 "" "$id" daemonChanged <<<'{}'
    else
      perl "$stage/od-status.pl" "$(now)" "${before%%|*}" "${before#*|}" "$id" <<<"$status"
    fi
    ;;
  od-restart)
    # SIGTERM to the running daemon; launchd starts its replacement. Prints the old pid, its start time and the guest-clock instant.
    ident="$(od_identity)" || exit 1
    pid="${ident%%|*}"
    printf 'prevpid=%s\nprevstart=%s\nrestartAt=%s\n' "$pid" "${ident#*|}" "$(now)"
    sudo -n kill -TERM "$pid"
    ;;
  *) exit 2 ;;
esac
