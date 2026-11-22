#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# M03-T11 AUTH-REAL guest reads. Read-only apart from the sheet cancels (a key press to SecurityAgent, an AXPress on
# the System Settings sheet's Cancel) and, under DEC-034, the Login Items approval sheet's fill (settings-sheet-fill).
# Never types a password into SecurityAgent (the WGEX right's sheet), never stores one beyond that fill and never
# writes the authorisation database.
set -euo pipefail
# shellcheck source=Tools/lab/tart/guest/guard.sh
source "$(dirname "$0")/guard.sh"
guest_guard
action="${1:?action required}"
right_name() {
  [[ "${1:-}" =~ ^com\.magrathean\.WGEXApp\.manage-protection(\.dev)?$ ]] || {
    echo 'guest: WGEX right name required' >&2
    exit 2
  }
}
case "$action" in
  right-read)
    # The right as `security authorizationdb read` returns it, as one JSON object; exit 3 when no such right exists.
    right_name "${2:-}"
    plist="$(security authorizationdb read "$2" 2>/dev/null)" || exit 3
    plutil -convert json -o - - <<<"$plist"
    printf '\n'
    ;;
  net-state)
    # WGEX-relevant network state, compared before and after the sheet is cancelled: each source's raw output under a
    # "==wgex-net NAME EXIT" line (stderr dropped). auth-real.py normalises it into records and compares contents, not
    # counts; a non-zero exit (or sudo refused, for the pf sources) is an unreadable observation and fails the check.
    net_section() {
      local name="$1" out rc=0
      shift
      out="$("$@" 2>/dev/null)" || rc=$?
      printf '==wgex-net %s %s\n' "$name" "$rc"
      if [[ -n "$out" ]]; then printf '%s\n' "$out"; fi
    }
    resolver_files() {
      # /etc/resolver's entries with their contents, each after a "==wgex-file NAME" line; no directory is no files.
      local entry
      [[ -e /etc/resolver ]] || return 0
      find /etc/resolver -mindepth 1 -maxdepth 1 | sort | while IFS= read -r entry; do
        printf '==wgex-file %s\n' "${entry##*/}"
        cat -- "$entry" || exit 1
        printf '\n'
      done
    }
    net_section sudo sudo -n true
    net_section utun ifconfig -l
    net_section routes netstat -rn
    net_section dns scutil --dns
    net_section resolver resolver_files
    net_section pf sudo -n pfctl -s info
    net_section pfReferences sudo -n pfctl -s References
    net_section wgexAnchorRules sudo -n pfctl -a com.apple/wgex -sr
    net_section wgexAnchors sudo -n pfctl -a com.apple -s Anchors
    ;;
  agent-state)
    # The authentication sheet is SecurityAgent's window in the console session; its AX tree is opaque on macOS 27.
    user="$(guest_lab_user --console)"
    pid="$(pgrep -x -u "$user" SecurityAgent || true)"
    if [[ -z "$pid" ]]; then printf 'agent=absent\n'; else
      windows="$(bash "$(dirname "$0")/asu.sh" /usr/bin/osascript -e 'tell application "System Events" to tell process "SecurityAgent" to count of windows' 2>/dev/null || printf unreadable)"
      printf 'agent=running windows=%s\n' "$windows"
    fi
    ;;
  agent-cancel)
    # Escape on the frontmost SecurityAgent sheet is its Cancel (errAuthorizationCanceled, -60006). No text is typed.
    bash "$(dirname "$0")/asu.sh" /usr/bin/osascript -e 'tell application "System Events" to tell process "SecurityAgent" to set frontmost to true' \
      -e 'delay 0.5' -e 'tell application "System Events" to key code 53' >/dev/null
    printf 'cancel=sent\n'
    ;;
  authd-log)
    # authd's own lines for this right since START (guest clock, "YYYY-MM-DD HH:MM:SS"), and the lines of the same
    # evaluation engines, kept only when they match a fixed allowlist; at most 40 lines.
    right_name "${3:-}"
    [[ "${2:-}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}\ [0-9]{2}:[0-9]{2}:[0-9]{2}$ ]] || exit 2
    /usr/bin/log show --start "$2" --style compact --predicate 'process == "authd"' 2>/dev/null | perl "$(dirname "$0")/authd-lines.pl" "$3"
    ;;
  settings-sheet)
    # Live run 5 (macOS 27.2, SIP on): pressing WGEX's background-item switch raised "Login Items is trying to modify
    # your system settings" as an AXSheet on a System Settings window, drawn by LocalAuthenticationRemoteService (which
    # has no window of its own); SecurityAgent never ran. Prints settings-sheet=<sheets> la=<running|absent>.
    sheets="$(bash "$(dirname "$0")/asu.sh" /usr/bin/osascript -e 'tell application "System Events"' \
      -e 'if not (exists process "System Settings") then return 0' \
      -e 'set n to 0' -e 'repeat with w in windows of process "System Settings"' -e 'set n to n + (count of sheets of w)' \
      -e 'end repeat' -e 'return n' -e 'end tell' 2>/dev/null || printf unreadable)"
    if pgrep -x LocalAuthenticationRemoteService >/dev/null; then la=running; else la=absent; fi
    printf 'settings-sheet=%s la=%s\n' "$sheets" "$la"
    ;;
  settings-sheet-cancel)
    # The sheet's two buttons carry no title or description on macOS 27.2; Cancel is the last (below Modify Settings).
    # AXPress on it, never a key press: after an Escape sent to System Settings in live run 5, System Events and
    # screencapture hung in the console session. No text is typed.
    bash "$(dirname "$0")/asu.sh" /usr/bin/osascript -e 'tell application "System Events" to tell process "System Settings"' \
      -e 'perform action "AXPress" of last button of group 1 of sheet 1 of window 1' -e 'end tell' >/dev/null
    printf 'cancel=sent\n'
    ;;
  settings-sheet-fill)
    # DEC-034: the guest administrator's password for the Login Items approval sheet only (the driver has identified it
    # by authd's com.apple.backgroundtaskmanagement.manage-daemons line and LocalAuthenticationRemoteService). It comes
    # on stdin, goes to a 0600 file in this stage directory that is removed straight after fill-sheet.applescript has
    # read it, and never reaches a command line, a log or the output: osascript's stderr is dropped and only a fixed
    # fill= line is printed.
    [[ "${2:-}" =~ ^(set|keys)$ ]] || {
      echo 'guest: fill mode set or keys required' >&2
      exit 2
    }
    umask 077
    secret="$(mktemp "$(dirname "$0")/.sheet.XXXXXX")"
    trap 'rm -f "$secret"' EXIT
    head -c 256 >"$secret"
    if [[ ! -s "$secret" ]]; then
      printf 'fill=empty\n'
      exit 4
    fi
    out="$(bash "$(dirname "$0")/asu.sh" /usr/bin/osascript "$(dirname "$0")/fill-sheet.applescript" "$secret" "$2" 2>/dev/null || printf 'fill=error')"
    rm -f "$secret"
    if [[ "$out" =~ ^fill=(entered|no-sheet|no-field|unreadable|error)(\ mode=(set|keys))?(\ field=(secure|default-focus))?(\ pressed=(modify|no))?$ ]]; then
      printf '%s\n' "$out"
    else
      printf 'fill=unrecognised\n'
    fi
    ;;
  approval-log)
    # authd's lines for the background-item approval right since START (guest clock); at most 10 lines.
    [[ "${2:-}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}\ [0-9]{2}:[0-9]{2}:[0-9]{2}$ ]] || exit 2
    /usr/bin/log show --start "$2" --style compact --predicate 'process == "authd"' 2>/dev/null |
      grep -F 'com.apple.backgroundtaskmanagement.manage-daemons' | tail -n 10 | cut -c 1-300 || true
    ;;
  btm-state)
    # The WGEX rows of sfltool's background-task database: name and disposition only.
    sudo -n sfltool dumpbtm 2>/dev/null | awk '/^ +Name: WGEX/ {name=$2} name && /^ +Disposition:/ {sub(/^ +Disposition: /, ""); print name ": " $0; name=""}' | sort -u
    ;;
  approve-item)
    # Login Items & Extensions: press WGEX's background-item switch (approve-item.applescript) as the console user.
    bash "$(dirname "$0")/asu.sh" /usr/bin/osascript "$(dirname "$0")/approve-item.applescript"
    ;;
  daemon-state)
    label="$(basename /Applications/WGEX.app/Contents/Library/LaunchDaemons/*.plist .plist)"
    [[ "$label" =~ ^com\.magrathean\.WGEXApp(\.dev)?\.daemon$ ]] || exit 1
    state="$(sudo -n launchctl print "system/$label" 2>/dev/null | awk '$1 == "state" {print $3; exit}' || true)"
    printf 'label=%s state=%s pid=%s\n' "$label" "${state:-absent}" "$(pgrep -o -x WGEXDaemon || true)"
    ;;
  *)
    echo "guest: unknown action $action" >&2
    exit 2
    ;;
esac
