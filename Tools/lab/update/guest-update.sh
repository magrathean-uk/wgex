#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# M5.3-07 update, guest side. Copied into the verdict stage beside guard.sh, gap-status.pl, journal-replay.pl and
# wrapping-key.sh; never run on the host. It replaces /Applications/WGEX.app with the staged update while the daemon
# keeps the tunnel connected, the way a drag or Sparkle install does, and never restarts the daemon itself: the hand-off
# is the product's own (Finish update). Output is JSON on stdout: versions, pids, code-directory hashes and digests only.
set -euo pipefail
# shellcheck source=Tools/lab/tart/guest/guard.sh
source "$(dirname "$0")/guard.sh"
guest_guard
stage="$(CDPATH='' cd -- "$(dirname "$0")" && pwd)"
work="$stage/update"
app=/Applications/WGEX.app
cli="$app/Contents/Helpers/wgex"
now() { perl -MTime::HiRes=time -e 'printf "%.3f", time'; }
stamp() { perl -MTime::HiRes=time -MPOSIX=strftime -e 'my $t = time; printf "%s.%03d", strftime("%Y-%m-%d %H:%M:%S", localtime $t), ($t - int $t) * 1000'; }
version_of() { /usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$1/Contents/Info.plist"; }

label() {
  local plists value
  plists=("$app"/Contents/Library/LaunchDaemons/*.plist)
  [[ "${#plists[@]}" == 1 && -f "${plists[0]}" ]] || exit 1
  value="$(/usr/libexec/PlistBuddy -c 'Print :Label' "${plists[0]}")"
  # Lab builds only: the dev daemon's label.
  [[ "$value" == com.magrathean.WGEXApp.dev.daemon ]] || exit 1
  printf '%s' "$value"
}

intent_digest() {
  local replayed value=
  # The replayed document holds the pf token: a 0600 file, removed at once; only a digest of the intent leaves.
  replayed="$(mktemp "$work/replay.XXXXXX")"
  # shellcheck disable=SC2024 # The guest user owns the 0600 output on purpose; only the read needs root.
  if sudo -n perl "$stage/journal-replay.pl" '/Library/Application Support/WGEX' >"$replayed" 2>/dev/null; then
    value="$(plutil -extract intent json -o - "$replayed" 2>/dev/null || true)"
  fi
  rm -f "$replayed"
  if [[ -n "$value" ]]; then printf '%s' "$value" | shasum -a 256 | cut -c1-12; else printf none; fi
}

case "${1:?action required}" in
  unpack)
    # The update archive the driver staged: unpacked beside the stage, signature checked, version read.
    [[ -f "$work/WGEX.zip" && ! -L "$work/WGEX.zip" && ! -e "$work/WGEX.app" ]] || exit 1
    umask 077
    ditto -x -k "$work/WGEX.zip" "$work"
    rm -f "$work/WGEX.zip"
    codesign --verify --deep --strict "$work/WGEX.app"
    printf '{"stagedVersion":"%s","installedVersion":"%s"}\n' "$(version_of "$work/WGEX.app")" "$(version_of "$app")"
    ;;
  replace)
    staged="$(version_of "$work/WGEX.app")"
    installed="$(version_of "$app")"
    # Anti-downgrade floor (DEC-007): never install a version at or below the one already run.
    [[ "$staged" =~ ^[1-9][0-9]{0,8}$ && "$installed" =~ ^[1-9][0-9]{0,8}$ ]] && ((staged > installed)) || exit 1
    [[ ! -e "$work/previous" ]] || exit 1
    protection="$("$cli" status --json 2>/dev/null |
      perl -MJSON::PP -e 'local $/; my $d = eval { decode_json(<STDIN>) } || {}; print $d->{protection} // "unknown"' || true)"
    [[ "$protection" =~ ^[a-zA-Z]{1,20}$ ]] || protection=unknown
    mkdir "$work/previous"
    # The running daemon keeps its binary; the bundle on disk becomes the update, as after a drag or Sparkle install.
    sudo -n mv "$app" "$work/previous/WGEX.app"
    sudo -n ditto "$work/WGEX.app" "$app"
    sudo -n chown -R root:wheel "$app"
    codesign --verify --deep --strict "$app"
    printf '{"replaced":true,"fromVersion":"%s","toVersion":"%s","protectionAtReplacement":"%s","replacedAt":%s}\n' \
      "$installed" "$staged" "$protection" "$(now)"
    ;;
  retrust)
    # Lab-only stand-in for the Release designated-requirement ACL (DEC-007): the escrowed wrapping key is re-added
    # trusting the new bundle's daemon before the hand-off starts it.
    WGEX_WRAPPING_KEY_FALLBACK=1 bash "$stage/wrapping-key.sh" "$(label)"
    ;;
  running)
    # The daemon that runs now: pid, its own code-directory hash, the installed version, intent and pf ownership.
    mkdir -p "$work"
    pid="$(pgrep -x WGEXDaemon || true)"
    [[ "$pid" =~ ^[0-9]+$ ]] || pid=0
    cdhash=
    if ((pid > 0)); then
      # Reads every line (no early exit, so the writer never meets a closed pipe) and keeps the first hash.
      cdhash="$(sudo -n codesign -d --verbose=4 "$pid" 2>&1 | perl -ne 'if (!$seen && /^CDHash=([0-9a-f]{40})$/) { print $1; $seen = 1 }')"
    fi
    status="$("$cli" status --json 2>/dev/null)" || status='{}'
    refs="$(sudo -n pfctl -s References 2>/dev/null)" || refs=
    info="$(sudo -n pfctl -s info 2>/dev/null)" || info=
    perl "$stage/gap-status.pl" "$(now)" "$pid" "$refs" "$info" <<<"$status" | perl -MJSON::PP -e '
      local $/; my $s = decode_json(<STDIN>); my ($digest, $cdhash, $version) = @ARGV;
      print JSON::PP->new->canonical->encode({daemonPid => $s->{pid}, protection => $s->{protection},
        referenceCount => $s->{referenceCount}, intentDigest => ($digest =~ /^[a-f0-9]{12}$/ ? $digest : undef),
        runningDaemonCdhash => ($cdhash =~ /^[0-9a-f]{40}$/ ? $cdhash : undef),
        bundleVersion => ($version =~ /^[0-9]{1,9}$/ ? $version : undef)}), "\n";' \
      "$(intent_digest)" "$cdhash" "$(version_of "$app")"
    ;;
  stamp) stamp ;;
  daemon-log)
    # Fixed-vocabulary daemon lines (daemon-log-tail.pl already reduced them) since a stamp, without their stamps.
    since="${2:?stamp required}"
    tail="$stage/daemon-log-tail"
    [[ -f "$tail" && ! -L "$tail" ]] || exit 1
    perl -MJSON::PP -e 'my $since = shift; my @lines;
      while (<STDIN>) {
        chomp;
        next unless /^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?) (.+)$/;
        push @lines, $2 if $1 ge $since && $2 !~ /^</;
      }
      print JSON::PP->new->encode(\@lines), "\n"' "$since" <"$tail"
    ;;
  daemon-log-stamped)
    # The same lines with their stamps, as [stamp, line] pairs: the tail keeps 50 lines, so the driver reads it during the
    # hand-off and merges the reads by stamp (verdict-live.collect_daemon_log).
    since="${2:?stamp required}"
    tail="$stage/daemon-log-tail"
    [[ -f "$tail" && ! -L "$tail" ]] || exit 1
    perl -MJSON::PP -e 'my $since = shift; my @lines;
      while (<STDIN>) {
        chomp;
        next unless /^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?) (.+)$/;
        push @lines, [$1, $2] if $1 ge $since && $2 !~ /^</;
      }
      print JSON::PP->new->encode(\@lines), "\n"' "$since" <"$tail"
    ;;
  cleanup)
    # Only this row's own update directory inside its own stage; the moved previous bundle is root-owned.
    if [[ -d "$work" && ! -L "$work" ]]; then sudo -n rm -rf -- "$work"; fi
    ;;
  *) exit 64 ;;
esac
