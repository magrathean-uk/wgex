#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# UNINSTALL (M03-T15, DEC-037 item 4, DEC-040), guest side. Copied into the verdict stage beside guard.sh and
# journal-replay.pl; never run on the host. It starts the product's own `wgex uninstall` in the console session (so the
# administrator dialog appears at the guest console, DEC-034) and reads back what the uninstall left. Output is fixed words,
# counts, process ids and short JSON; never a key, a token or a journal value.
set -euo pipefail
# shellcheck source=Tools/lab/tart/guest/guard.sh
source "$(dirname "$0")/guard.sh"
guest_guard
stage="$(CDPATH='' cd -- "$(dirname "$0")" && pwd)"
work="$stage/uninstall"
lab_user="$(guest_lab_user)"
app=/Applications/WGEX.app
cli="$app/Contents/Helpers/wgex"
root='/Library/Application Support/WGEX'
now() { perl -MTime::HiRes=time -e 'printf "%.3f", time'; }

label() {
  local plists value
  plists=("$app"/Contents/Library/LaunchDaemons/*.plist)
  [[ "${#plists[@]}" == 1 && -f "${plists[0]}" ]] || exit 1
  value="$(/usr/libexec/PlistBuddy -c 'Print :Label' "${plists[0]}")"
  # Lab builds only: the dev daemon's label.
  [[ "$value" == com.magrathean.WGEXApp.dev.daemon ]] || exit 1
  printf '%s' "$value"
}

# One BTM item's disposition word list for a Type and Identifier, "absent" when a successful dump has no such item, or
# "unknown" when sfltool fails or prints nothing (a failed read is never an absence). sfltool prints one block per item; the
# Identifier line follows the Disposition line inside a block.
btm_disposition() {
  local type="$1" identifier="$2" dump
  if ! dump="$(sudo -n sfltool dumpbtm 2>/dev/null)" || [[ -z "$dump" ]]; then
    printf 'unknown\n'
    return 0
  fi
  awk -v type="$type" -v id="$identifier" '
    /^ *UUID: / { kind = ""; disposition = "" }
    /^ *Type: / { kind = $2 }
    /^ *Disposition: / { sub(/^ *Disposition: /, ""); sub(/ \(0x[0-9a-f]+\)$/, ""); disposition = $0 }
    /^ *Identifier: / { if (kind == type && $2 == id) { found = disposition } }
    END { if (found == "") print "absent"; else print found }' <<<"$dump"
}

# A pf read's non-empty line count, or "unknown" when pfctl fails.
pf_count() {
  local out
  out="$(sudo -n pfctl "$@" 2>/dev/null)" || {
    printf 'unknown'
    return 0
  }
  grep -c . <<<"$out" || true
}

case "${1:?action required}" in
  cli-start)
    # The product CLI, run as the console user inside the console session (launchctl asuser, as guest/asu.sh does), so its
    # AuthorizationCopyRights shows SecurityAgent's dialog at the guest console. --yes skips the terminal confirmation only.
    variant="${2:?keep or purge required}"
    [[ "$variant" == keep || "$variant" == purge ]] || exit 2
    [[ "$(id -un)" == "$lab_user" && "$(stat -f %Su /dev/console)" == "$lab_user" ]] || exit 1
    [[ ! -e "$work" ]] || exit 1
    umask 077
    mkdir "$work"
    flags=(uninstall --yes --json)
    [[ "$variant" == purge ]] && flags=(uninstall --purge --yes --json)
    uid="$(id -u "$lab_user")"
    # shellcheck disable=SC2016 # The inner shell expands its own positional parameters.
    nohup bash -c 'sudo -n launchctl asuser "$1" sudo -n -u "$2" "$3" "${@:5}" >"$4/cli.out" 2>/dev/null; printf "%s\n" "$?" >"$4/cli.rc.next"; mv "$4/cli.rc.next" "$4/cli.rc"' \
      _ "$uid" "$lab_user" "$cli" "$work" "${flags[@]}" >/dev/null 2>&1 </dev/null &
    printf 'startedAt=%s\n' "$(now)"
    ;;
  cli-result)
    # rc=running while the CLI waits (for the administrator dialog, say); then rc=N and its JSON reply's fixed fields.
    if [[ ! -f "$work/cli.rc" ]]; then
      printf 'rc=running\n'
      exit 0
    fi
    read -r rc <"$work/cli.rc"
    [[ "$rc" =~ ^[0-9]{1,3}$ ]] || exit 1
    printf 'rc=%s\n' "$rc"
    perl -MJSON::PP -e '
      local $/; my $text = <STDIN>; my $value = eval { JSON::PP->new->decode($text) };
      my %out = (replyReadable => ref $value eq "HASH" ? JSON::PP::true : JSON::PP::false);
      if (ref $value eq "HASH") {
        for my $key (qw(result error step)) {
          $out{$key} = $value->{$key} if defined $value->{$key} && $value->{$key} =~ /\A[A-Za-z]{1,40}\z/;
        }
        $out{purge} = $value->{purge} ? JSON::PP::true : JSON::PP::false if exists $value->{purge};
      }
      print "reply=", JSON::PP->new->canonical->encode(\%out), "\n";' <"$work/cli.out"
    ;;
  services)
    # The background service and the login item as launchd and BTM see them, and the daemon process. Absence is what the tool
    # confirms (launchctl 113: no such service; pgrep 1: no match); any other failure is "unknown", never an absence.
    name="$(label)"
    set +e
    sudo -n launchctl print "system/$name" >/dev/null 2>&1
    rc=$?
    pid="$(pgrep -o -x WGEXDaemon)"
    pid_rc=$?
    set -e
    case "$rc" in 0) job=present ;; 113) job=absent ;; *) job=unknown ;; esac
    case "$pid_rc" in
      0) [[ "$pid" =~ ^[0-9]+$ ]] || pid=unknown ;;
      1) pid=none ;;
      *) pid=unknown ;;
    esac
    printf 'launchdJob=%s\ndaemonPid=%s\n' "$job" "$pid"
    printf 'btmDaemon=%s\n' "$(btm_disposition daemon "16.$name")"
    # The app's own login item (SMAppService.mainApp) is the app item; enabled while registered.
    printf 'btmApp=%s\n' "$(btm_disposition app "2.${name%.daemon}")"
    ;;
  pf)
    # The WGEX anchor as pf lists it, its rules, tables and nested anchors (counts), and the pf references held. A failed read
    # is "unknown"; an anchor the successful listing leaves out holds nothing, so its counts are a confirmed 0.
    if anchors="$(sudo -n pfctl -a com.apple -s Anchors 2>/dev/null)"; then
      if grep -qx '  com.apple/wgex' <<<"$anchors"; then listed=true; else listed=false; fi
    else
      listed=unknown
    fi
    case "$listed" in
      true)
        rules="$(pf_count -a com.apple/wgex -sr)"
        tables="$(pf_count -a com.apple/wgex -sT)"
        nested="$(pf_count -a com.apple/wgex -s Anchors)"
        ;;
      false) rules=0 tables=0 nested=0 ;;
      *) rules=unknown tables=unknown nested=unknown ;;
    esac
    if held="$(sudo -n pfctl -s References 2>/dev/null)"; then
      references="$(grep -cE '^ *[0-9]+ +[^ ]+ +[0-9]+ +[0-9]+ days' <<<"$held" || true)"
    else
      references=unknown
    fi
    printf 'anchorListed=%s\nanchorRules=%s\nanchorTables=%s\nanchorNested=%s\nreferences=%s\n' "$listed" "$rules" "$tables" "$nested" "$references"
    ;;
  refuse)
    # Mutating requests after the uninstall, from the console user in the console session (the profile's owner, so only the
    # uninstall fence can refuse them): start the profile, arm it on demand, and stop the current tunnel (with none running the
    # daemon answers a stop as done without a change). Each prints its exit code and error name only.
    id="${2:?profile UUID required}"
    [[ "$id" =~ ^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$ ]] || exit 1
    [[ "$(id -un)" == "$lab_user" && "$(stat -f %Su /dev/console)" == "$lab_user" ]] || exit 1
    uid="$(id -u "$lab_user")"
    for request in up onDemand down; do
      case "$request" in
        up) argv=(up "$id" --json) ;;
        onDemand) argv=(on-demand "$id" on --json) ;;
        down) argv=(down --json) ;;
      esac
      set +e
      out="$(sudo -n launchctl asuser "$uid" sudo -n -u "$lab_user" "$cli" "${argv[@]}" 2>/dev/null)"
      rc=$?
      set -e
      error="$(perl -MJSON::PP -e 'local $/; my $v = eval { JSON::PP->new->decode(<STDIN>) }; my $e = ref $v eq "HASH" ? $v->{error} // "" : "unreadable"; print $e =~ /\A[A-Za-z]{1,40}\z/ ? $e : "none"' <<<"$out")"
      printf '%s=%s %s\n' "$request" "$rc" "$error"
    done
    ;;
  status)
    # `wgex status --json` reduced to its exit code, phase, protection and every uninstall field it carries, then the text
    # form's uninstall line.
    set +e
    out="$("$cli" status --json 2>/dev/null)"
    rc=$?
    set -e
    printf 'rc=%s\n' "$rc"
    perl -MJSON::PP -e '
      local $/; my $v = eval { JSON::PP->new->decode(<STDIN>) };
      my %out;
      if (ref $v eq "HASH") {
        for my $key (qw(phase protection error)) { $out{$key} = $v->{$key} if defined $v->{$key} && !ref $v->{$key} }
        for my $key (grep { /uninstall/i } keys %$v) { $out{$key} = $v->{$key} }
      } else { $out{unreadable} = JSON::PP::true }
      print "status=", JSON::PP->new->canonical->encode(\%out), "\n";' <<<"$out"
    # The text form's uninstall line (M05-T14), printable characters only; none when the CLI prints no such line.
    # A CLI that fails without printing the line is "unreadable", not none.
    set +e
    text="$("$cli" status 2>/dev/null)"
    text_rc=$?
    set -e
    line="$(grep -m 1 -E '^uninstall: ' <<<"$text" | LC_ALL=C tr -cd '[:print:]' || true)"
    [[ -n "$line" || "$text_rc" == 0 ]] || line=unreadable
    printf 'uninstallLine=%s\n' "${line:-none}"
    ;;
  state-root)
    # The daemon state root: the names of the files left (no content) and the journal as the daemon restores it, reduced in
    # the pipe (the replay carries the pf token; it never reaches a file or a variable). The reduction keeps each top-level
    # field's exact type, the generation number and fixed booleans for what a purge must leave: the default settings, the
    # disconnected pf policy and the completed purge marker; no other journal value leaves. A failed read is "unknown"
    # (root, files) or "unreadable" (journal), never an absence.
    kind="$(sudo -n /bin/sh -c 'if [ -d "$1" ]; then echo present; elif [ -e "$1" ] || [ -L "$1" ]; then echo other; else echo absent; fi' _ "$root" 2>/dev/null || true)"
    case "$kind" in
      present | absent | other) printf 'root=%s\n' "$kind" ;;
      *) printf 'root=unknown\n' ;;
    esac
    [[ "$kind" == present ]] || exit 0
    if listing="$(sudo -n find "$root" -mindepth 1 \( -type f -o -type l \) -print 2>/dev/null)"; then
      [[ -z "$listing" ]] || while IFS= read -r path; do printf 'file=%s\n' "${path#"$root/"}"; done <<<"$listing" | LC_ALL=C sort
    else
      printf 'files=unknown\n'
    fi
    set +e
    sudo -n perl "$stage/journal-replay.pl" "$root" 2>/dev/null | perl -MB -MJSON::PP -e '
      local $/; my $v = eval { JSON::PP->new->decode(<STDIN>) };
      ref $v eq "HASH" or do { print "journal=unreadable\n"; exit 0 };
      my $integer = sub { my ($x) = @_; defined $x && !ref $x && !JSON::PP::is_bool($x) && (B::svref_2object(\$x)->FLAGS & B::SVf_IOK) && $x =~ /\A[0-9]{1,20}\z/ };
      my $kind = sub {
        my ($x) = @_;
        return "null" unless defined $x;
        return "array:" . scalar(@$x) if ref $x eq "ARRAY";
        return "object:" . scalar(keys %$x) if ref $x eq "HASH";
        return $x ? "true" : "false" if JSON::PP::is_bool($x);
        return "integer" if $integer->($x);
        return (B::svref_2object(\$x)->FLAGS & (B::SVf_IOK | B::SVf_NOK)) ? "number" : "string";
      };
      my %out = map { $_ => $kind->($v->{$_}) } keys %$v;
      my $bool = sub { $_[0] ? "true" : "false" };
      $out{"schemaVersion.value"} = 0 + $v->{schemaVersion} if $integer->($v->{schemaVersion});
      $out{"generation.value"} = 0 + $v->{generation} if $integer->($v->{generation});
      my $s = $v->{settings};
      $out{"settings.default"} = $bool->(ref $s eq "HASH" && join(",", sort keys %$s) eq "allowLAN,captiveWindowSeconds,lockdown,notifications"
        && JSON::PP::is_bool($s->{lockdown}) && !$s->{lockdown} && JSON::PP::is_bool($s->{allowLAN}) && $s->{allowLAN}
        && JSON::PP::is_bool($s->{notifications}) && $s->{notifications} && $integer->($s->{captiveWindowSeconds}) && $s->{captiveWindowSeconds} == 300);
      my $p = $v->{pfPolicy};
      $out{"pfPolicy.disconnected"} = $bool->(ref $p eq "HASH" && join(",", keys %$p) eq "disconnected" && ref $p->{disconnected} eq "HASH"
        && !%{ $p->{disconnected} });
      my $u = $v->{uninstall};
      if (ref $u eq "HASH") {
        $out{"uninstall.completed"} = $bool->(JSON::PP::is_bool($u->{completed}) && $u->{completed});
        $out{"uninstall.purgeState"} = $bool->(JSON::PP::is_bool($u->{purgeState}) && $u->{purgeState});
      }
      print "journal=", JSON::PP->new->canonical->encode(\%out), "\n";'
    statuses=("${PIPESTATUS[@]}")
    set -e
    # A replay that failed after printing something is unreadable whatever the reducer made of it (the last line wins).
    [[ "${statuses[0]}" == 0 ]] || printf 'journal=unreadable\n'
    ;;
  profiles)
    # The app's own profile store: the number of profile documents and whether the row's profile is one of them.
    id="${2:?profile UUID required}"
    [[ "$id" =~ ^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$ ]] || exit 1
    wanted="$(printf '%s' "$id" | tr '[:lower:]' '[:upper:]')"
    # A store that is missing holds no profile; one that exists but cannot be listed is "unknown", never empty.
    store="$HOME/Library/Application Support/WGEX/profiles"
    if [[ ! -e "$store" && ! -L "$store" ]]; then
      printf 'appProfiles=0\nprofilePresent=false\n'
      exit 0
    fi
    if [[ -L "$store" || ! -d "$store" ]] || ! names="$(ls -1A -- "$store" 2>/dev/null)"; then
      printf 'appProfiles=unknown\nprofilePresent=unknown\n'
      exit 0
    fi
    count=0 found=false
    while IFS= read -r name; do
      [[ "$name" == *.json && -f "$store/$name" && ! -L "$store/$name" ]] || continue
      count=$((count + 1))
      [[ "$(printf '%s' "${name%.json}" | tr '[:lower:]' '[:upper:]')" == "$wanted" ]] && found=true
    done <<<"$names"
    printf 'appProfiles=%s\nprofilePresent=%s\n' "$count" "$found"
    ;;
  secure-install)
    # The daemon's secure-install state as `wgex doctor --json` reports it (verified, inProgress, needsAttention(reason)).
    value="$("$cli" doctor --json 2>/dev/null | perl -MJSON::PP -e 'local $/; my $v = eval { JSON::PP->new->decode(<STDIN>) }; my $s = ref $v eq "HASH" ? $v->{secureInstall} // "" : ""; print $s =~ /\A[A-Za-z()]{1,60}\z/ ? $s : "unreadable"')" || value=unreadable
    printf 'secureInstall=%s\n' "$value"
    ;;
  app-state)
    # pgrep's 0 is running and its 1 (no match) is exited; any other failure is "unknown", never an exit.
    set +e
    pgrep -x -u "$lab_user" WGEX >/dev/null
    rc=$?
    set -e
    case "$rc" in 0) printf 'app=running\n' ;; 1) printf 'app=exited\n' ;; *) printf 'app=unknown\n' ;; esac
    ;;
  stop-app)
    # Only when the app's own Quit left it running: SIGTERM to the lab user's WGEX, SIGKILL after 10 s.
    # Only pgrep's 1 (no match) is "none"; a failed pgrep is "unknown".
    set +e
    pid="$(pgrep -x -u "$lab_user" WGEX)"
    rc=$?
    set -e
    case "$rc" in
      0) ;;
      1)
        printf 'stopped=none\n'
        exit 0
        ;;
      *)
        printf 'stopped=unknown\n'
        exit 0
        ;;
    esac
    [[ "$pid" =~ ^[0-9]+$ ]] || exit 1
    kill -TERM "$pid"
    for ((attempt = 0; attempt < 50; attempt++)); do
      kill -0 "$pid" 2>/dev/null || {
        printf 'stopped=term\n'
        exit 0
      }
      sleep 0.2
    done
    kill -KILL "$pid"
    printf 'stopped=kill\n'
    ;;
  restart-daemon)
    # The driver's recorded workaround after a tunnel start failed on the freshly installed daemon: launchd restarts it.
    sudo -n launchctl kickstart -k "system/$(label)"
    ;;
  start-failure)
    # The daemon's last start-failure line since the stamp (type, case and step words only).
    since="${2:?log stamp required}"
    [[ "$since" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}\ [0-9]{2}:[0-9]{2}:[0-9]{2}$ ]] || exit 1
    /usr/bin/log show --start "$since" --style compact --predicate 'process == "WGEXDaemon"' 2>/dev/null |
      sed -nE 's/.*(start failed(, type: [A-Za-z]+ case: [A-Za-z]+| at step: [A-Za-z]+)).*/\1/p' | tail -n 2
    ;;
  stamp)
    date '+%Y-%m-%d %H:%M:%S'
    ;;
  cleanup)
    rm -rf "$work"
    ;;
  *) exit 2 ;;
esac
