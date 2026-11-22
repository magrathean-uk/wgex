#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Drive the guest desktop from SSH: screenshots are taken inside the guest
# (screencapture in the console session), input and accessibility queries run
# inside the guest through System Events in the console session (TCC rows from
# guest/seed-tcc.sh). The guest runs headless with Tart's VNC console (lab_start,
# DEC-112); there is no host window and nothing here touches a host app.
set -euo pipefail
# shellcheck source=Tools/lab/tart/lib.sh
source "$(dirname "$0")/lib.sh"
# shellcheck source=Config/Scripts/lib.sh
source "$LAB_ROOT/Config/Scripts/lib.sh"
lab_init "${1:-}"
[[ "${1:-}" != --dry-run ]] || shift
usage='usage: gui.sh [--dry-run] <shot OUT.png | dump APP [WINDOW [IDENTIFIER]] | click X Y | press APP WINDOW IDENTIFIER press|confirm X Y ROLE [LABEL|FRAME] | press APP WINDOW IDENTIFIER press-only ROLE [LABEL|FRAME] | scroll APP WINDOW IDENTIFIER [LABEL] | keys APP WINDOW IDENTIFIER up|down COUNT [fallback] | activate APP | open-pane URL-OR-APP | run CMD... | seed-tcc [BINARY...]>'
action="${1:?$usage}"
shift
guest_dir="/Users/$LAB_USER/lab/gui"
sync_helpers() {
  lab_connect
  guest_is_lab
  lab_ssh "mkdir -p '$guest_dir'" </dev/null
  lab_scp "$LAB_DIR/guest/asu.sh" "$LAB_DIR/guest/guard.sh" "$LAB_DIR/guest/activate.applescript" "$LAB_DIR/guest/ax-dump.applescript" "$LAB_DIR/guest/clickat.applescript" "$LAB_DIR/guest/ax-action.applescript" "$LAB_DIR/guest/arrow-keys.applescript" "$LAB_DIR/guest/seed-tcc.sh" "$LAB_USER@$LAB_ADDRESS:$guest_dir/" </dev/null
  lab_ssh "chmod +x '$guest_dir/asu.sh' '$guest_dir/seed-tcc.sh'" </dev/null
}
# M1-10j element actions: window, identifier and child label are checked here and passed as argv data.
check_element() {
  [[ "$2" =~ ^[1-9][0-9]?$ ]] || lab_die 'window index must be 1..99'
  [[ "$3" =~ ^wgex\.[A-Za-z0-9.-]+$ ]] || lab_die 'identifier must be a wgex accessibility identifier'
}
# press only (M1-10m): identifier - matches the role alone, so it needs an AX role and a label (a toolbar button by title)
# or (M1-10r) an exact frame (a radio button without its own title or identifier, chosen by position in its group).
check_press_element() {
  if [[ "$3" == - ]]; then
    [[ "$2" =~ ^[1-9][0-9]?$ ]] || lab_die 'window index must be 1..99'
  else check_element "$@"; fi
}
check_label() {
  local pattern='^[A-Za-z0-9][A-Za-z0-9 .,-]{0,79}$'
  [[ "$1" =~ $pattern ]] || lab_die 'label must be 1..80 letters, digits, spaces or .,-'
}
# M1-10k fix pass 1 (F3): frame=X,Y,WxH in the label slot makes the helper match identifier, role and that exact frame.
check_label_or_frame() {
  if [[ "$1" == frame=* ]]; then
    [[ "$1" =~ ^frame=-?[0-9]{1,5},-?[0-9]{1,5},[0-9]{1,5}x[0-9]{1,5}$ ]] || lab_die 'frame must be frame=X,Y,WxH integers'
  else check_label "$1"; fi
}
asu() {
  local quoted
  printf -v quoted '%q ' "$@"
  lab_ssh "'$guest_dir/asu.sh' $quoted" </dev/null
}
case "$action" in
  shot)
    out="${1:?shot needs an output path}"
    (($# == 1)) || lab_die 'shot takes one argument'
    [[ "$out" == *.png ]] || lab_die 'output must be a .png'
    case "$(cd "$(dirname "$out")" 2>/dev/null && pwd || true)" in "$LAB_ROOT"*) lab_die 'never write captures into the repository' ;; esac
    builds="$(build_root)"
    case "$out" in "$builds/"* | "${TMPDIR:?}/"*) ;; *) lab_die 'shots must be under build_root() or TMPDIR' ;; esac
    mkdir -p "$builds/lab-shots"
    shot="$(mktemp "$builds/lab-shots/shot.XXXXXX")"
    trap 'rm -f "$shot"' EXIT
    sync_helpers
    asu screencapture -x "$guest_dir/wgex-shot-$$.png" >/dev/null 2>&1 || lab_die 'guest screencapture failed (no console display?)'
    lab_scp "$LAB_USER@$LAB_ADDRESS:$guest_dir/wgex-shot-$$.png" "$shot" </dev/null || lab_die 'copying the guest capture failed'
    lab_ssh "rm -f $guest_dir/wgex-shot-$$.png" </dev/null
    mv "$shot" "$out"
    printf '%s\n' "$out"
    ;;
  dump)
    app="${1:?dump needs an application process name}"
    window="${2:-1}"
    (($# <= 3)) || lab_die 'dump takes APP [WINDOW [IDENTIFIER]]'
    # M1-10o: IDENTIFIER selects the helper's targeted walk (the AXWindow line, the first element carrying it, and the
    # ax-walk line with target=found|missing); the driver's element searches use it, diagnostics keep the full dump.
    if (($# == 3)); then check_element "$app" "$window" "$3"; fi
    sync_helpers
    # M1-10k fix pass 1 (F1): an osascript or SSH failure ends the output with the fixed line ax-dump=failed exit=N,
    # so an unreadable dump is never mistaken for an empty window. The exit status stays 0 for checked callers.
    # M1-10l: the helper's own last line, ax-walk: elements=N truncated=0|1 errors=M, passes through for the driver.
    status=0
    tree="$(asu osascript "$guest_dir/ax-dump.applescript" "$app" "$window" "${@:3}")" || status=$?
    if [[ -n "$tree" ]]; then printf '%s\n' "$tree" | grep -v -E 'desc=(close|zoom|minimi[sz]e) button|arrow button|page button' || true; fi
    if ((status)); then printf 'ax-dump=failed exit=%d\n' "$status"; fi
    ;;
  click)
    x="${1:?click needs X Y}"
    y="${2:?click needs X Y}"
    (($# == 2)) || lab_die 'click takes X Y'
    [[ "$x$y" =~ ^[0-9]+$ ]] || lab_die 'coordinates are integers'
    sync_helpers
    asu osascript "$guest_dir/clickat.applescript" "$x" "$y" >/dev/null
    ;;
  press)
    # AXPress or AXConfirm on the element matching IDENTIFIER and ROLE (- for identifier only), or on its child
    # labelled LABEL; X Y is the coordinate fallback, which the driver passes only after checking the element frame
    # lies inside the window frame (M1-10j). press-only takes no X Y and never clicks: the off-screen path (F1).
    # frame=X,Y,WxH instead of LABEL picks the element with that frame when a dump shows the identifier twice (F3).
    # IDENTIFIER - (M1-10m) takes the first element of ROLE and its child LABEL: a Settings toolbar tab by title; with
    # frame=X,Y,WxH (M1-10r) the element of ROLE with exactly that frame: a startup radio button by position (M1-10t:
    # AXRadioButton only).
    (($# >= 5)) || lab_die 'press takes APP WINDOW IDENTIFIER press|confirm X Y ROLE [LABEL|FRAME] or APP WINDOW IDENTIFIER press-only ROLE [LABEL|FRAME]'
    check_press_element "$@"
    case "$4" in
      press | confirm)
        (($# == 7 || $# == 8)) || lab_die 'press takes APP WINDOW IDENTIFIER press|confirm X Y ROLE [LABEL|FRAME]'
        [[ "$5" =~ ^[0-9]{1,5}$ && "$6" =~ ^[0-9]{1,5}$ ]] || lab_die 'coordinates are integers'
        role="$7" label_index=8
        ;;
      press-only)
        (($# == 5 || $# == 6)) || lab_die 'press-only takes APP WINDOW IDENTIFIER press-only ROLE [LABEL|FRAME]'
        role="$5" label_index=6
        ;;
      *) lab_die 'action must be press, confirm or press-only' ;;
    esac
    [[ "$role" =~ ^(AX[A-Za-z]{1,40}|-)$ ]] || lab_die 'role must be an AX role name or -'
    (($# < label_index)) || check_label_or_frame "${!label_index}"
    if [[ "$3" == - ]]; then
      [[ "$role" != - ]] || lab_die 'identifier - needs an AX role'
      (($# == label_index)) || lab_die 'identifier - needs a label or a frame'
      # M1-10t (M1-10r VERIFY-B N7): a frame in place of a title is for the startup radio buttons only.
      [[ "${!label_index}" != frame=* || "$role" == AXRadioButton ]] || lab_die 'identifier - with a frame needs the role AXRadioButton'
    fi
    sync_helpers
    # Only the fixed path report leaves the helper: path=element, element-timeout or coordinate; press-only's miss
    # (no element found) or error number=N (AXPress threw, M1-10m). An osascript or SSH failure prints the fixed line
    # ax-action=failed exit=N and keeps its non-zero exit (M1-10k fix pass 1, F1).
    status=0
    # M1-10o fix pass 2 (F1): a press that acted is preceded by pressedAt=<guest epoch>, the helper's delivery instant.
    path_line="$(asu osascript "$guest_dir/ax-action.applescript" "$@")" || status=$?
    while IFS= read -r line; do
      if [[ "$line" =~ ^pressedAt=[0-9]{9,11}\.[0-9]{1,6}$ || "$line" =~ ^path=(element|element-timeout|coordinate|miss|error\ number=-?[0-9]{1,10})$ ]]; then printf '%s\n' "$line"; fi
    done <<<"$path_line"
    if ((status)); then
      printf 'ax-action=failed exit=%d\n' "$status"
      exit "$status"
    fi
    ;;
  scroll)
    # Bring the element (or its child labelled LABEL) into view: AXScrollToVisible, else the enclosing scroll bar.
    # No activate, raise or focus change here or in the helper (M1-10k): window indices stay as the driver dumped them.
    (($# == 3 || $# == 4)) || lab_die 'scroll takes APP WINDOW IDENTIFIER [LABEL]'
    check_element "$@"
    (($# == 3)) || check_label "$4"
    sync_helpers
    scroll_line="$(asu osascript "$guest_dir/ax-action.applescript" "$1" "$2" "$3" scroll "${@:4}")"
    if [[ "$scroll_line" =~ ^scroll=(action|bar|missing|none)$ ]]; then printf '%s\n' "$scroll_line"; fi
    ;;
  keys)
    # SwiftUI sidebar rows ignore clicks; selection moves with arrow keys (L14).
    # fallback: a missing identifier takes the profile list found from the window (L17).
    (($# == 5 || $# == 6)) || lab_die 'keys takes APP WINDOW IDENTIFIER up|down COUNT [fallback]'
    [[ "$2" =~ ^[1-9][0-9]?$ ]] || lab_die 'window index must be 1..99'
    [[ "$3" =~ ^wgex\.[A-Za-z0-9.-]+$ ]] || lab_die 'identifier must be a wgex accessibility identifier'
    [[ "$4" == up || "$4" == down ]] || lab_die 'direction must be up or down'
    [[ "$5" =~ ^(0|[1-9][0-9]?)$ && "$5" -le 64 ]] || lab_die 'count must be 0..64'
    [[ $# == 5 || "$6" == fallback ]] || lab_die 'the sixth argument must be fallback'
    sync_helpers
    # Only the fixed path report leaves the helper: path=identifier or path=window.
    path_line="$(asu osascript "$guest_dir/arrow-keys.applescript" "$@")"
    if [[ "$path_line" =~ ^path=(identifier|window)$ ]]; then printf '%s\n' "$path_line"; fi
    ;;
  activate)
    app="${1:?activate needs an application name}"
    (($# == 1)) || lab_die 'activate takes APP'
    sync_helpers
    asu osascript "$guest_dir/activate.applescript" "$app"
    ;;
  open-pane)
    target="${1:?open-pane needs a URL or application}"
    (($# == 1)) || lab_die 'open-pane takes one argument'
    sync_helpers
    if [[ "$target" == *:* ]]; then asu open "$target"; else asu open -a "$target"; fi
    ;;
  run)
    (($#)) || lab_die 'run needs a command'
    sync_helpers
    asu "$@"
    ;;
  seed-tcc)
    sync_helpers
    quoted=""
    if (($#)); then printf -v quoted "%q " "$@"; fi
    lab_ssh "'$guest_dir/seed-tcc.sh' $quoted" </dev/null
    ;;
  *) lab_die "$usage" ;;
esac
