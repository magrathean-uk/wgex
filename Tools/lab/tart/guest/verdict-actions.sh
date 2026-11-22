#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Guarded guest-only row operations. No global pf reset is implemented.
set -euo pipefail
# shellcheck source=Tools/lab/tart/guest/guard.sh
source "$(dirname "$0")/guard.sh"
guest_guard
cli=/Applications/WGEX.app/Contents/Helpers/wgex
action="${1:?action required}"
stage="$(dirname "$0")"
now() { perl -MTime::HiRes=time -e 'printf "%.3f", time'; }
case "$action" in
  profile-id)
    # shellcheck source=Tools/lab/tart/guest/profile-id.sh
    source "$stage/profile-id.sh"
    profile_id "$HOME/Library/Application Support/WGEX/profiles" "${2:?profile name required}"
    ;;
  diagnostics-start)
    if [[ -f "$stage/daemon-log.pid" ]]; then
      read -r pid <"$stage/daemon-log.pid"
      [[ "$pid" =~ ^[0-9]+$ ]] || exit 1
      if kill -0 "$pid" 2>/dev/null; then exit 1; fi
      rm -f "$stage/daemon-log.pid" "$stage/daemon-log.ready" "$stage/daemon-log.pipe"
    fi
    printf 'events=0; rawMessagesOmitted=1\n' >"$stage/daemon-log-count"
    : >"$stage/daemon-log-tail"
    nohup bash "$0" diagnostics-stream >/dev/null 2>&1 </dev/null &
    pid=$!
    printf '%s\n' "$pid" >"$stage/daemon-log.pid"
    for ((attempt = 0; attempt < 50; attempt++)); do
      if ! kill -0 "$pid" 2>/dev/null; then
        printf 'guest: daemon log stream failed to start\n' >&2
        exit 1
      fi
      if [[ -f "$stage/daemon-log.ready" ]]; then exit 0; fi
      sleep 0.1
    done
    printf 'guest: daemon log stream readiness deadline\n' >&2
    exit 1
    ;;
  diagnostics-stream)
    [[ ! -e "$stage/daemon-log.pipe" ]] || exit 1
    mkfifo -m 0600 "$stage/daemon-log.pipe"
    # Only FIFO transport sees raw log data. The on-disk output is a numeric count.
    /usr/bin/log stream --level debug --style compact --predicate 'process == "WGEXDaemon"' >"$stage/daemon-log.pipe" 2>/dev/null &
    log_pid=$!
    perl "$stage/daemon-log-tail.pl" "$stage" <"$stage/daemon-log.pipe" &
    count_pid=$!
    trap 'kill "$log_pid" "$count_pid" 2>/dev/null || true; wait "$log_pid" "$count_pid" 2>/dev/null || true; rm -f "$stage/daemon-log.pipe" "$stage/daemon-log.ready"' EXIT
    trap 'exit 0' TERM INT
    sleep 0.2
    kill -0 "$log_pid" "$count_pid"
    touch "$stage/daemon-log.ready"
    wait "$log_pid"
    ;;
  diagnostics-stop)
    [[ -f "$stage/daemon-log.pid" ]] || exit 0
    read -r pid <"$stage/daemon-log.pid"
    [[ "$pid" =~ ^[0-9]+$ ]] || exit 1
    if kill -0 "$pid" 2>/dev/null; then
      command="$(ps -p "$pid" -o args=)"
      [[ "$command" == *"$stage/verdict-actions.sh diagnostics-stream"* ]] || exit 1
      kill -TERM "$pid"
      for ((attempt = 0; attempt < 50; attempt++)); do
        if ! kill -0 "$pid" 2>/dev/null; then break; fi
        sleep 0.1
      done
      if kill -0 "$pid" 2>/dev/null; then exit 1; fi
    fi
    rm -f "$stage/daemon-log.pid"
    ;;
  diagnostics-tail)
    [[ -f "$stage/daemon-log-tail" && ! -L "$stage/daemon-log-tail" ]] || exit 1
    tail -n 50 "$stage/daemon-log-tail"
    ;;
  refresh-install)
    app=/Applications/WGEX.app
    [[ -d "$app" && ! -L "$app" ]] || exit 1
    plists=("$app"/Contents/Library/LaunchDaemons/*.plist)
    [[ "${#plists[@]}" == 1 && -f "${plists[0]}" ]] || exit 1
    label="$(/usr/libexec/PlistBuddy -c 'Print :Label' "${plists[0]}")"
    [[ "$label" =~ ^com\.magrathean\.WGEXApp(\.dev)?\.daemon$ ]] || exit 1
    sudo -n chown -R root:wheel "$app"
    codesign --verify --deep --strict "$app"
    sudo -n launchctl kickstart -k "system/$label"
    ;;
  secure-install-status)
    # After refresh-install: the relaunched daemon validates its System-keychain wrapping key noninteractively.
    # "verified" means it read the key; needsAttention(wrappingKeyUnavailable) is run 9b F1 (CSSMERR_CSP_OPERATION_AUTH_DENIED).
    doctor=
    for ((attempt = 0; attempt < 30; attempt++)); do
      doctor="$("$cli" doctor --json 2>/dev/null || true)"
      [[ "$doctor" != *'"daemonReachable":true'* ]] || break
      sleep 1
    done
    printf '%s\n' "$doctor"
    ;;
  observe)
    printf '__WGEX_STATUS__\n'
    "$cli" status --json
    printf '__WGEX_PFINFO__\n'
    sudo -n pfctl -s info 2>/dev/null
    printf '__WGEX_REFERENCES__\n'
    sudo -n pfctl -s References 2>/dev/null
    printf '__WGEX_RULES__\n'
    sudo -n pfctl -a com.apple/wgex -vsr 2>/dev/null
    printf '__WGEX_IFCONFIG__\n'
    ifconfig
    printf '__WGEX_ROUTES__\n'
    netstat -rn
    printf '__WGEX_DNS__\n'
    scutil --dns
    printf '__WGEX_LOG__\n'
    # Stream was armed before the action. log show often misses this guest's events.
    [[ -f "$stage/daemon-log.ready" ]] || exit 1
    summary=
    # A counter update may briefly truncate the file; bounded retry avoids a false gap.
    for ((attempt = 0; attempt < 10; attempt++)); do
      if read -r summary <"$stage/daemon-log-count" && [[ "$summary" =~ ^events=[0-9]+\;\ rawMessagesOmitted=1$ ]]; then break; fi
      sleep 0.01
    done
    [[ "$summary" =~ ^events=[0-9]+\;\ rawMessagesOmitted=1$ ]] || exit 1
    printf '%s\n' "$summary"
    ;;
  down) "$cli" down --json ;;
  kill-app | kill-no-app | term)
    pids="$(pgrep -x WGEXDaemon)"
    [[ "$pids" =~ ^[0-9]+$ ]] || exit 1
    if [[ "$action" == term ]]; then sudo -n kill -TERM "$pids"; else sudo -n kill -KILL "$pids"; fi
    ;;
  second-anchor)
    [[ -z "$(sudo -n pfctl -a com.apple/zzz-test -sr 2>/dev/null)" ]] || exit 1
    printf 'pass out all\n' | sudo -n pfctl -o none -a com.apple/zzz-test -f - >/dev/null 2>&1
    ;;
  remove-second-anchor) sudo -n pfctl -a com.apple/zzz-test -F rules >/dev/null 2>&1 ;;
  resolver)
    [[ ! -e /etc/resolver/m1-10.wgex.test ]] || exit 1
    sudo -n mkdir -p /etc/resolver
    printf 'nameserver 192.0.2.53\n' | sudo -n tee /etc/resolver/m1-10.wgex.test >/dev/null
    ;;
  check-resolver)
    [[ "$(cat /etc/resolver/m1-10.wgex.test)" == 'nameserver 192.0.2.53' ]]
    # Capture before matching: under pipefail, grep -q exiting on its first match
    # leaves scutil to take SIGPIPE and the check returns 141 (M1-10g, M5.4-03).
    dns="$(scutil --dns)"
    grep -q 'domain.*m1-10.wgex.test' <<<"$dns"
    ;;
  remove-resolver) sudo -n rm -f /etc/resolver/m1-10.wgex.test ;;
  interface-cycle)
    iface="${2:?lab interface required}"
    [[ "$iface" =~ ^utun[0-9]+$ ]] || exit 1
    addresses="$(ifconfig "$iface")" || exit 1
    grep -q 'inet 10.77.0.2 ' <<<"$addresses" || exit 1
    trap 'if ifconfig "$iface" >/dev/null 2>&1; then sudo -n ifconfig "$iface" up; fi' EXIT
    sudo -n ifconfig "$iface" down
    sleep 1
    if ifconfig "$iface" >/dev/null 2>&1; then sudo -n ifconfig "$iface" up; fi
    trap - EXIT
    ;;
  foreign-up)
    stage="$(dirname "$0")"
    [[ ! -e "$stage/foreign.pid" && ! -e "$stage/foreign.name" ]] || exit 1
    trap 'bash "$0" foreign-down' ERR
    nohup sudo -n "$stage/foreign-utun" >"$stage/foreign.name" 2>"$stage/foreign.err" </dev/null &
    printf '%s\n' "$!" >"$stage/foreign.pid"
    for ((attempt = 0; attempt < 50; attempt++)); do
      if [[ -s "$stage/foreign.name" ]]; then break; fi
      sleep 0.1
    done
    read -r iface <"$stage/foreign.name"
    [[ "$iface" =~ ^utun[0-9]+$ ]] || exit 1
    sudo -n ifconfig "$iface" inet 198.18.0.2 198.18.0.2 up
    # Scoped /1 entries exercise foreign ownership without taking over the guest default.
    sudo -n route -n add -net 0.0.0.0/1 -interface "$iface" -ifscope "$iface" >/dev/null
    sudo -n route -n add -net 128.0.0.0/1 -interface "$iface" -ifscope "$iface" >/dev/null
    trap - ERR
    printf '%s\n' "$iface"
    ;;
  check-foreign)
    stage="$(dirname "$0")"
    read -r iface <"$stage/foreign.name"
    [[ "$iface" =~ ^utun[0-9]+$ ]] || exit 1
    addresses="$(ifconfig "$iface")"
    grep -q '198.18.0.2' <<<"$addresses"
    netstat -rn -f inet | awk -v iface="$iface" '$NF == iface && ($1 == "0/1" || $1 == "128.0/1" || $1 == "128/1") {n++} END {exit n != 2}'
    ;;
  foreign-down)
    iface=
    stage="$(dirname "$0")"
    if [[ -s "$stage/foreign.name" ]]; then
      read -r iface <"$stage/foreign.name"
      [[ "$iface" =~ ^utun[0-9]+$ ]] || exit 1
      sudo -n route -n delete -net 0.0.0.0/1 -ifscope "$iface" >/dev/null 2>&1 || true
      sudo -n route -n delete -net 128.0.0.0/1 -ifscope "$iface" >/dev/null 2>&1 || true
    fi
    if [[ -f "$stage/foreign.pid" ]]; then
      read -r pid <"$stage/foreign.pid"
      [[ "$pid" =~ ^[0-9]+$ ]] || exit 1
      # Signal only the fixture binary, never another interface owner.
      child="$(pgrep -P "$pid" -x foreign-utun || true)"
      if [[ -z "$child" && "$(ps -p "$pid" -o comm=)" == "$stage/foreign-utun" ]]; then child="$pid"; fi
      if [[ "$child" =~ ^[0-9]+$ ]]; then sudo -n kill -TERM "$child"; fi
      for ((attempt = 0; attempt < 50; attempt++)); do
        if ! ifconfig "$iface" >/dev/null 2>&1; then break; fi
        sleep 0.1
      done
      if ifconfig "$iface" >/dev/null 2>&1; then exit 1; fi
      rm -f "$stage/foreign.pid" "$stage/foreign.name"
    fi
    ;;
  reboot) sudo -n shutdown -r now ;;
  lockdown-state)
    # Settings changes are durable journal.log records, not checkpoints, so read the daemon's own replay of
    # journal.json plus journal.log. Only the lockdown flag leaves the guest; the replayed document (it holds the pf
    # token) stays in a 0600 file that is removed on exit.
    umask 077
    replayed="$(mktemp "$stage/replay.XXXXXX")"
    trap 'rm -f "$replayed"' EXIT
    # shellcheck disable=SC2024 # The guest user owns the 0600 output on purpose; only the read needs root.
    sudo -n perl "$stage/journal-replay.pl" '/Library/Application Support/WGEX' >"$replayed" 2>/dev/null || exit 1
    value="$(plutil -extract settings.lockdown raw -o - "$replayed" 2>/dev/null)" || exit 1
    [[ "$value" == true || "$value" == false ]] || exit 1
    printf 'lockdown=%s\n' "$value"
    ;;
  allow-lan-state)
    # M1-10q: the daemon's Allow LAN flag, read exactly like lockdown-state; only the flag leaves the guest.
    umask 077
    replayed="$(mktemp "$stage/replay.XXXXXX")"
    trap 'rm -f "$replayed"' EXIT
    # shellcheck disable=SC2024 # The guest user owns the 0600 output on purpose; only the read needs root.
    sudo -n perl "$stage/journal-replay.pl" '/Library/Application Support/WGEX' >"$replayed" 2>/dev/null || exit 1
    value="$(plutil -extract settings.allowLAN raw -o - "$replayed" 2>/dev/null)" || exit 1
    [[ "$value" == true || "$value" == false ]] || exit 1
    printf 'allowLAN=%s\n' "$value"
    ;;
  boot-intent)
    id="${2:?profile UUID required}"
    [[ "$id" =~ ^[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}$ ]] || exit 1
    value="$(sudo -n plutil -extract startBeforeLoginOverride raw -o - "/Library/Application Support/WGEX/profiles/$id.json" 2>/dev/null)" || exit 1
    [[ "$value" == true || "$value" == false ]] || exit 1
    printf 'bootIntent=%s\n' "$value"
    ;;
  daemon-pid)
    # M1-10u fix pass 1: the daemon's pid before the reboot, so the verdict can tell the previous daemon's lines from a daemon
    # that replaced the post-restart one. Digits only; nothing is printed when no daemon runs.
    pid="$(pgrep -o -x WGEXDaemon || true)"
    if [[ "$pid" =~ ^[0-9]+$ ]]; then printf 'daemonpid=%s\n' "$pid"; fi
    ;;
  prevent-relaunch)
    # M1-10v (the maintainer, 1 Nov 2026; M1-24 section 5.2): BOOT-SECRETS measures the daemon alone, so macOS must not reopen WGEX.app at the
    # next login. Mechanism "loginwindow-reopen-state", guest-only and for the console user only: loginwindow neither saves the
    # running applications at logout (TALLogoutSavesState false) nor reopens saved ones at login (LoginwindowLaunchesRelaunchApps
    # false), in the user's domain and the current host's, and the saved relaunch list (TALAppsToRelaunchAtLogin) is emptied.
    # Nothing of the product and no network or system service is touched. Undo: the snapshot restore (the row restores its
    # snapshot first; the keys persist in the guest until the next restore, so no snapshot may be taken after this row); by hand,
    # `defaults delete com.apple.loginwindow TALLogoutSavesState` and LoginwindowLaunchesRelaunchApps in both domains. The app must
    # already be quit; a running app is refused before anything is written. Fix pass 1 (VERIFY B L6): the SSH user's preferences are
    # only the console session's when the two users are the same, so anything else is refused before anything is written
    # (usermatch=no). Fix pass 1 (L1): the saved relaunch list is counted before it is deleted (relaunchlistbefore, and
    # relaunchlistwgex yes|no for a WGEX bundle id in it), so the first live run shows whether the snapshot's list held the app; no
    # path or bundle id is printed. The read-back is printed as fixed key=value lines and the action fails unless every key reads
    # back as written.
    domain=com.apple.loginwindow
    if [[ -n "$(pgrep -x WGEX || true)" ]]; then
      printf 'mechanism=loginwindow-reopen-state\napp=running\n'
      exit 1
    fi
    console_user="$(stat -f %Su /dev/console 2>/dev/null || true)"
    ssh_user="$(id -un)"
    if [[ -z "$console_user" || "$console_user" == root || "$console_user" != "$ssh_user" ]]; then
      printf 'mechanism=loginwindow-reopen-state\nusermatch=no\napp=none\n'
      exit 1
    fi
    saved="$(defaults -currentHost read "$domain" TALAppsToRelaunchAtLogin 2>/dev/null || true)"
    before="$(grep -c 'BundleID' <<<"$saved" || true)"
    holds=no
    if grep -q 'com\.magrathean\.WGEXApp' <<<"$saved"; then holds=yes; fi
    for scope in "" "-currentHost"; do
      # shellcheck disable=SC2086 # scope is empty or the one fixed flag
      defaults $scope write "$domain" TALLogoutSavesState -bool false
      # shellcheck disable=SC2086
      defaults $scope write "$domain" LoginwindowLaunchesRelaunchApps -bool false
      # shellcheck disable=SC2086
      defaults $scope delete "$domain" TALAppsToRelaunchAtLogin 2>/dev/null || true
    done
    saves=false
    relaunch=false
    for scope in "" "-currentHost"; do
      # shellcheck disable=SC2086
      [[ "$(defaults $scope read "$domain" TALLogoutSavesState 2>/dev/null || true)" == 0 ]] || saves=unconfirmed
      # shellcheck disable=SC2086
      [[ "$(defaults $scope read "$domain" LoginwindowLaunchesRelaunchApps 2>/dev/null || true)" == 0 ]] || relaunch=unconfirmed
    done
    listed="$(defaults -currentHost read "$domain" TALAppsToRelaunchAtLogin 2>/dev/null || true)"
    entries="$(grep -c 'BundleID' <<<"$listed" || true)"
    printf 'mechanism=loginwindow-reopen-state\nusermatch=yes\nrelaunchlistbefore=%s\nrelaunchlistwgex=%s\nsavesstate=%s\nrelaunchapps=%s\nrelaunchlist=%s\napp=none\n' \
      "$before" "$holds" "$saves" "$relaunch" "$entries"
    [[ "$saves" == false && "$relaunch" == false && "$entries" == 0 ]] || exit 1
    ;;
  boot-observe)
    # Fixed key=value lines: sample time, UTC offset, boot time, app and daemon ps etime, launchd runs; then the daemon's
    # status lines since boot in the fixed vocabulary of daemon-log-tail.pl. No other log text leaves this filter.
    sampled="$(now)"
    printf 'now=%s\ntz=%s\n' "$sampled" "$(date +%z)"
    boottime="$(sysctl -n kern.boottime)"
    [[ "$boottime" =~ sec\ =\ ([0-9]+) ]] || exit 1
    boot="${BASH_REMATCH[1]}"
    printf 'boot=%s\n' "$boot"
    daemon_elapsed=none
    for name in WGEX WGEXDaemon; do
      key=app
      if [[ "$name" == WGEXDaemon ]]; then key=daemon; fi
      pid="$(pgrep -o -x "$name" || true)"
      elapsed=none
      if [[ "$pid" =~ ^[0-9]+$ ]]; then
        elapsed="$(ps -p "$pid" -o etime= || true)"
        elapsed="${elapsed// /}"
        # M1-10v (FIX1-VERIFY N-2): a pid whose etime did not parse is an app that exists with no usable start, printed
        # app=unknown (read as running, start unknown, so it fails closed), never app=none; the daemon keeps none plus
        # daemonstart=unknown below.
        if ! [[ "$elapsed" =~ ^([0-9]+-)?([0-9]+:)?[0-9]+:[0-9]+$ ]]; then
          elapsed=none
          if [[ "$name" == WGEX ]]; then elapsed=unknown; fi
        fi
      fi
      printf '%s=%s\n' "$key" "$elapsed"
      if [[ "$name" == WGEXDaemon ]]; then daemon_elapsed="$elapsed"; fi
      # M1-10u: the oldest live WGEXDaemon after the restart is the post-restart daemon; its pid keeps the previous
      # daemon's shutdown lines (log show from before kern.boottime returns them) out of the verdict's boot timeline. Fix pass
      # 1: the pid is printed only when its etime parsed; a daemon whose etime did not parse is daemonstart=unknown, which the
      # verdict names (postRestartDaemonStartUnknown) instead of judging by an unusable start time.
      if [[ "$name" == WGEXDaemon && "$pid" =~ ^[0-9]+$ ]]; then
        if [[ "$elapsed" != none ]]; then printf 'daemonpid=%s\n' "$pid"; else printf 'daemonstart=unknown\n'; fi
      fi
      # Fix pass 1: ps lstart (local time) as an epoch beside the etime estimate, when it parses; the app's only.
      if [[ "$name" == WGEX && "$pid" =~ ^[0-9]+$ ]]; then
        lstart=""
        read -r lstart <<<"$(LC_ALL=C ps -p "$pid" -o lstart= 2>/dev/null || true)" || true
        epoch="$(LC_ALL=C date -j -f '%a %b %e %T %Y' "$lstart" +%s 2>/dev/null || true)"
        if [[ "$epoch" =~ ^[0-9]{9,11}$ ]]; then printf 'applstart=%s\n' "$epoch"; fi
      fi
    done
    # M1-10v fix pass 1 (VERIFY B M1): the two pgrep samples are points, so an app that starts and exits between them is invisible
    # there. The count of unified-log lines from the app's own process since the post-restart daemon's start closes that gap;
    # only the count is printed (appLogLines=N, never a line). The process is "WGEX": project.yml gives target WGEXMac
    # PRODUCT_NAME WGEX (executable Contents/MacOS/WGEX, the same name pgrep -x WGEX matches here), the daemon is WGEXDaemon and the
    # CLI is wgex, and `process ==` is an exact, case-sensitive match, so neither is counted. The window starts at the daemon's
    # earliest possible start (ps etime, minus 5 s) and not at the 300 s margin before kern.boottime used for the daemon's own
    # lines below: the driver quits the app shortly before the reboot, and its shutdown lines inside that margin would make every
    # run a false relaunchNotPrevented. No daemon start (none or an unparsable etime) or an unreadable log is appLogLines=unknown.
    applog=unknown
    if [[ "$daemon_elapsed" =~ ^(([0-9]+)-)?(([0-9]+):)?([0-9]+):([0-9]+)$ ]]; then
      seconds=$((10#${BASH_REMATCH[2]:-0} * 86400 + 10#${BASH_REMATCH[4]:-0} * 3600 + 10#${BASH_REMATCH[5]} * 60 + 10#${BASH_REMATCH[6]}))
      window="$(date -r "$((${sampled%.*} - seconds - 5))" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || true)"
      if [[ -n "$window" ]] && applines="$(/usr/bin/log show --style compact --info --debug --start "$window" --predicate 'process == "WGEX"' 2>/dev/null)"; then
        applog="$(grep -cE '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' <<<"$applines" || true)"
        [[ "$applog" =~ ^[0-9]{1,9}$ ]] || applog=unknown
      fi
    fi
    printf 'appLogLines=%s\n' "$applog"
    plists=(/Applications/WGEX.app/Contents/Library/LaunchDaemons/*.plist)
    [[ "${#plists[@]}" == 1 && -f "${plists[0]}" ]] || exit 1
    label="$(/usr/libexec/PlistBuddy -c 'Print :Label' "${plists[0]}")"
    [[ "$label" =~ ^com\.magrathean\.WGEXApp(\.dev)?\.daemon$ ]] || exit 1
    info="$(sudo -n launchctl print "system/$label" 2>/dev/null || true)"
    runs="$(awk '$1 == "runs" && $2 == "=" {value = $3} END {print value}' <<<"$info")"
    [[ "$runs" =~ ^[0-9]+$ ]] || runs=unknown
    printf 'runs=%s\n__TIMELINE__\n' "$runs"
    # The read starts a fixed margin before kern.boottime, never at it: the guest dates boottime unreliably (run 8g: before
    # the previous daemon's last line), so a post-restart line dated before it must not be dropped here. The host filters by
    # pid and start; status lines past the cap are counted, not dropped unnamed (statuslinesdropped).
    start="$(date -r "$((boot - 300))" '+%Y-%m-%d %H:%M:%S')"
    # The consumer reads to the end, so the producer never takes SIGPIPE; at most 400 status lines.
    # The status line is matched at its position (stamp, type, process[pid:tid], [subsystem:category], then the text), never
    # as text inside another message.
    /usr/bin/log show --style compact --start "$start" --predicate 'process == "WGEXDaemon"' 2>/dev/null |
      perl -ne 'BEGIN { $dropped = 0 } if (/^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?)\s+\S+\s+WGEXDaemon\[(\d{1,10})?[^\]]*\]\s+\[[^\]\s]+\]\s+status: phase=([a-z]{1,32}) protection=(protected|blocked|unprotected|unknown) reason=([A-Za-z]{1,40})\b/) { if ($n++ < 400) { print "$1 status: phase=$3 protection=$4 reason=$5" . (defined $2 ? " pid=$2" : "") . "\n" } else { $dropped++ } } END { print "statuslinesdropped=$dropped\n" }' || true
    ;;
  anchor-rules) sudo -n pfctl -a com.apple/wgex -sr 2>/dev/null ;;
  # Read-only (M1-10m): the guest's load averages, e.g. "{ 1.52 2.10 3.40 }", for the settle before GUI steps.
  guest-load) /usr/sbin/sysctl -n vm.loadavg ;;
  kill-app-process)
    pid="$(pgrep -x WGEX || true)"
    [[ "$pid" =~ ^[0-9]+$ ]] || exit 1
    kill -KILL "$pid"
    # M1-10o: the guest-clock instant of the SIGKILL, so the app-kill timing never counts the SSH round trip.
    killed_at="$(now)"
    for ((attempt = 0; attempt < 50; attempt++)); do
      if ! kill -0 "$pid" 2>/dev/null; then
        printf 'killedAt=%s\n' "$killed_at"
        exit 0
      fi
      sleep 0.1
    done
    exit 1
    ;;
  en0-loss)
    seconds="${2:?loss seconds required}"
    label="${3:?label required}"
    [[ "$seconds" =~ ^[1-9][0-9]?$ && "$label" =~ ^[a-z0-9-]{1,32}$ ]] || exit 1
    out="$stage/en0-$label"
    mkdir -m 0700 "$out"
    # The SSH session dies with en0, so status and the pf reference count are sampled inside the guest (run 6 B1).
    nohup bash "$0" en0-observe "$out" "$((seconds + 45))" >/dev/null 2>&1 </dev/null &
    # Two independent restorers: the cycle's EXIT trap and this watchdog.
    sudo -n nohup bash -c "sleep $((seconds + 70)); /sbin/ifconfig en0 up" >/dev/null 2>&1 </dev/null &
    sudo -n nohup bash "$0" en0-cycle "$out" "$seconds" >/dev/null 2>&1 </dev/null &
    ;;
  en0-cycle)
    ((EUID == 0)) || exit 1
    out="${2:?}"
    seconds="${3:?}"
    [[ -d "$out" && ! -L "$out" && "$seconds" =~ ^[1-9][0-9]?$ ]] || exit 1
    trap '/sbin/ifconfig en0 up' EXIT
    sleep 2
    printf 'down %s\n' "$(now)" >>"$out/times"
    /sbin/ifconfig en0 down
    sleep "$seconds"
    /sbin/ifconfig en0 up
    printf 'up %s\n' "$(now)" >>"$out/times"
    ;;
  en0-observe)
    out="${2:?}"
    seconds="${3:?}"
    [[ -d "$out" && ! -L "$out" && "$seconds" =~ ^[0-9]{1,3}$ ]] || exit 1
    end=$((SECONDS + seconds))
    while ((SECONDS < end)); do
      stamp="$(now)"
      state="$("$cli" status --json 2>/dev/null | tr -d '\n')" || state=unavailable
      references="$(sudo -n pfctl -s References 2>/dev/null || true)"
      # Rows are counted, never printed: the table carries the token.
      count="$(awk '$1 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && $5 == "days" {n++} END {print n + 0}' <<<"$references")"
      printf '%s refs=%s %s\n' "$stamp" "$count" "$state" >>"$out/samples"
      sleep 0.25
    done
    ;;
  en0-collect)
    label="${2:?label required}"
    [[ "$label" =~ ^[a-z0-9-]{1,32}$ ]] || exit 1
    out="$stage/en0-$label"
    [[ -f "$out/times" && ! -L "$out/times" ]] || exit 1
    cat "$out/times"
    printf '__SAMPLES__\n'
    if [[ -f "$out/samples" && ! -L "$out/samples" ]]; then cat "$out/samples"; fi
    ;;
  # M1-47 (POWER-WAKE): an injected power event. The guest does not sleep: a Lab daemon (a Lab build, on a lab host only) treats
  # SIGUSR1 as a sleep and SIGUSR2 as a wake (LabPowerInjector). Only root can signal the root daemon; nothing else is touched.
  power-inject)
    seconds="${2:?sleep seconds required}"
    label="${3:?label required}"
    [[ "$seconds" =~ ^[1-9][0-9]{0,2}$ ]] && ((seconds <= 200)) || exit 1
    [[ "$label" =~ ^[a-z0-9-]{1,32}$ ]] || exit 1
    daemon=/Applications/WGEX.app/Contents/MacOS/WGEXDaemon
    # Exactly one daemon: none or two is refused before anything is created or signalled.
    pid="$(pgrep -o -x WGEXDaemon || true)"
    count="$( (pgrep -x WGEXDaemon || true) | wc -l | tr -d ' ')"
    [[ "$pid" =~ ^[1-9][0-9]{0,9}$ ]] || exit 1
    [[ "$count" == 1 ]] || exit 1
    # SIGUSR1 ends a process that has no handler for it, so only an installed build that carries the injection is signalled.
    [[ -f "$daemon" && ! -L "$daemon" ]] && grep -aqF 'lab power inject sleep' "$daemon" || exit 1
    out="$stage/power-$label"
    mkdir -m 0700 "$out"
    # Status and the pf reference count are sampled inside the guest, as for en0 (the 0.25 s samples are the evidence).
    nohup bash "$0" power-observe "$out" "$((seconds + 45))" >/dev/null 2>&1 </dev/null &
    sudo -n nohup bash "$0" power-cycle "$out" "$seconds" "$pid" >/dev/null 2>&1 </dev/null &
    ;;
  power-cycle)
    ((EUID == 0)) || exit 1
    out="${2:?}"
    seconds="${3:?}"
    pid="${4:?}"
    [[ -d "$out" && ! -L "$out" && "$seconds" =~ ^[1-9][0-9]{0,2}$ && "$pid" =~ ^[1-9][0-9]{0,9}$ ]] || exit 1
    ((seconds <= 200)) || exit 1
    # The daemon is identified again before each signal: only the one process found at the start, still the only WGEXDaemon, gets it.
    signal_daemon() { # signal_daemon <USR1|USR2> <sleep|wake>
      [[ "$(pgrep -x WGEXDaemon | tr '\n' ' ')" == "$pid " ]] || exit 1
      printf '%s %s\n' "$2" "$(now)" >>"$out/times"
      kill -s "$1" "$pid"
    }
    sleep 2
    signal_daemon USR1 sleep
    sleep "$seconds"
    signal_daemon USR2 wake
    ;;
  power-observe)
    # The same 0.25 s sampler as en0 (status, and the pf reference rows counted, never printed), into $out/samples.
    out="${2:?}"
    seconds="${3:?}"
    [[ -d "$out" && ! -L "$out" && "$seconds" =~ ^[0-9]{1,3}$ ]] || exit 1
    exec bash "$0" en0-observe "$out" "$seconds"
    ;;
  power-collect)
    label="${2:?label required}"
    [[ "$label" =~ ^[a-z0-9-]{1,32}$ ]] || exit 1
    out="$stage/power-$label"
    [[ -f "$out/times" && ! -L "$out/times" ]] || exit 1
    printf 'tz=%s\n' "$(date +%z)"
    cat "$out/times"
    printf '__LOG__\n'
    # Only the daemon's two injected-event lines and its status lines leave this filter, in a fixed vocabulary (no other log text).
    slept="$(awk '$1 == "sleep" {print int($2); exit}' "$out/times")"
    lines=""
    if [[ "$slept" =~ ^[0-9]{9,11}$ ]]; then
      start="$(date -r "$((slept - 30))" '+%Y-%m-%d %H:%M:%S')"
      lines="$(/usr/bin/log show --style compact --start "$start" --predicate 'process == "WGEXDaemon"' 2>/dev/null || true)"
    fi
    perl -ne 'if (/^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?)\s+\S+\s+WGEXDaemon\[(\d{1,10})?[^\]]*\]\s+\[[^\]\s]+\]\s+lab power inject (sleep|wake)\s*$/) { print "$1 lab power inject $3" . (defined $2 ? " pid=$2" : "") . "\n" }' <<<"$lines"
    printf '__STATUS__\n'
    perl -ne 'BEGIN { $dropped = 0 } if (/^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?)\s+\S+\s+WGEXDaemon\[(\d{1,10})?[^\]]*\]\s+\[[^\]\s]+\]\s+status: phase=([a-z]{1,32}) protection=(protected|blocked|unprotected|unknown) reason=([A-Za-z]{1,40})\b/) { if ($n++ < 200) { print "$1 status: phase=$3 protection=$4 reason=$5" . (defined $2 ? " pid=$2" : "") . "\n" } else { $dropped++ } } END { print "statuslinesdropped=$dropped\n" }' <<<"$lines"
    printf '__SAMPLES__\n'
    if [[ -f "$out/samples" && ! -L "$out/samples" ]]; then cat "$out/samples"; fi
    ;;
  *)
    printf 'unknown guest verdict action\n' >&2
    exit 2
    ;;
esac
