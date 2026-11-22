#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# RT-17 identity corpus, guest side. Copied into the verdict stage beside guard.sh, gap-status.pl, journal-replay.pl and
# corpus-attempt.pl; never run on the host. Every corpus identity (the wrong-team certificate, its key and its throwaway
# keychain) is made in this stage's corpus directory and removed by `cleanup`; nothing here touches the host, its keychains
# or the maintainer's identities. Output is JSON on stdout: identifiers, code-directory hashes, outcomes and 12-hex digests only.
set -euo pipefail
# shellcheck source=Tools/lab/tart/guest/guard.sh
source "$(dirname "$0")/guard.sh"
guest_guard
stage="$(CDPATH='' cd -- "$(dirname "$0")" && pwd)"
corpus="$stage/corpus"
app=/Applications/WGEX.app
cli="$app/Contents/Helpers/wgex"
cli_id=com.magrathean.WGEXApp.dev.cli
lab_user="$(guest_lab_user)"
impostor_label=lab.wgex.corpus-impostor
# The wrong team: ten characters shaped like an Apple team identifier, not issued by Apple to anyone.
team=LABWRONG01
signer="WGEX Lab Wrong Team"
clients=(unsigned ad-hoc wrong-team wrong-identifier get-task-allow old-protocol older-build)
# The CLI variants run from a bundle layout like the installed one (no .app name, so LaunchServices never registers it):
# Contents/MacOS/WGEXDaemon is a copy of the running daemon, so each variant's own Lab requirement on the daemon holds and
# only the daemon can refuse it. `genuine` is the genuine CLI run from the same layout: the layout's positive control.
layout="$corpus/layout"
layout_clients=(ad-hoc wrong-team wrong-identifier get-task-allow)
now() { perl -MTime::HiRes=time -e 'printf "%.3f", time'; }
# Local wall time in the log's compact style (milliseconds), so tail lines compare as strings.
stamp() { perl -MTime::HiRes=time -MPOSIX=strftime -e 'my $t = time; printf "%s.%03d", strftime("%Y-%m-%d %H:%M:%S", localtime $t), ($t - int $t) * 1000'; }
bounded() { perl -e 'alarm shift; exec @ARGV or die "exec failed\n"' "$@"; }
as_console() {
  local uid
  uid="$(id -u "$lab_user")"
  sudo -n launchctl asuser "$uid" sudo -n -u "$lab_user" "$@"
}

service() {
  local plists value
  plists=("$app"/Contents/Library/LaunchDaemons/*.plist)
  [[ "${#plists[@]}" == 1 && -f "${plists[0]}" ]] || exit 1
  value="$(plutil -extract MachServices json -o - "${plists[0]}" |
    perl -MJSON::PP -e 'local $/; my $d = decode_json(<STDIN>); my @k = keys %$d; print $k[0] if @k == 1')"
  # Lab builds only: the dev daemon's service.
  [[ "$value" == com.magrathean.WGEXApp.dev.daemon ]] || exit 1
  printf '%s' "$value"
}

intent_digest() {
  local replayed value=
  # The replayed document holds the pf token: a 0600 file, removed at once; only a digest of the intent leaves.
  replayed="$(mktemp "$corpus/replay.XXXXXX")"
  # shellcheck disable=SC2024 # The guest user owns the 0600 output on purpose; only the read needs root.
  if sudo -n perl "$stage/journal-replay.pl" '/Library/Application Support/WGEX' >"$replayed" 2>/dev/null; then
    value="$(plutil -extract intent json -o - "$replayed" 2>/dev/null || true)"
  fi
  rm -f "$replayed"
  if [[ -n "$value" ]]; then printf '%s' "$value" | shasum -a 256 | cut -c1-12; else printf none; fi
}

snapshot() {
  local status pid refs info
  status="$("$cli" status --json 2>/dev/null)" || status='{}'
  pid="$(pgrep -x WGEXDaemon || true)"
  [[ "$pid" =~ ^[0-9]+$ ]] || pid=0
  refs="$(sudo -n pfctl -s References 2>/dev/null)" || refs=
  info="$(sudo -n pfctl -s info 2>/dev/null)" || info=
  perl "$stage/gap-status.pl" "$(now)" "$pid" "$refs" "$info" <<<"$status" | perl -MJSON::PP -e '
    local $/; my $s = decode_json(<STDIN>); my $digest = shift;
    print JSON::PP->new->canonical->encode({daemonPid => $s->{pid}, phase => $s->{phase}, protection => $s->{protection},
      intentDigest => ($digest =~ /^[a-f0-9]{12}$/ ? $digest : undef), ownerTokenHash => $s->{ownerPFTokenHash},
      referenceCount => $s->{referenceCount}});' "$(intent_digest)"
}

# Daemon lifecycle lines (a changed status, pf, recovery, start) in the diagnostics stream's tail since a stamp().
lifecycle_since() {
  local tail="$stage/daemon-log-tail"
  [[ -f "$tail" && ! -L "$tail" ]] || exit 1
  perl -e 'my $since = shift; my $n = 0;
    while (<STDIN>) {
      next unless /^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?) /;
      next if $1 lt $since;
      # A status line is logged whenever any status field changes, so one that repeats the connected state (a handshake or
      # counter update) is not a lifecycle change; every other phase or protection, and every pf or recovery line, is.
      $n++ if /\b(?:status: phase=(?!active protection=protected )|pf: |recovery: )|Daemon listening; recovering/;
    }
    print $n' "$1" <"$tail"
}

# One binary's signing identity as JSON: signature kind, identifier, cdhash, leaf certificate OU, get-task-allow.
describe() {
  local target="$1" display entitlements subject=
  display="$(codesign -d --verbose=4 "$target" 2>&1 || true)"
  entitlements="$(codesign -d --entitlements - --xml "$target" 2>/dev/null || true)"
  if [[ "$display" == *Authority=* ]]; then
    rm -f "$corpus"/leaf*
    codesign -d --extract-certificates="$corpus/leaf" "$target" 2>/dev/null || true
    if [[ -f "$corpus/leaf0" ]]; then
      subject="$(openssl x509 -inform der -in "$corpus/leaf0" -noout -subject -nameopt RFC2253 2>/dev/null || true)"
    fi
    rm -f "$corpus"/leaf*
  fi
  perl -MJSON::PP -e '
    my ($display, $entitlements, $subject) = @ARGV;
    my ($identifier) = $display =~ /^Identifier=([A-Za-z0-9._-]+)$/m;
    my ($cdhash) = $display =~ /^CDHash=([0-9a-f]{40})$/m;
    my $kind = $display =~ /not signed at all/ ? "unsigned" : $display =~ /^Signature=adhoc$/m ? "adhoc"
      : $display =~ /^Authority=/m ? "certificate" : "unknown";
    my ($team) = $subject =~ /(?:^|[,=\s])OU=([A-Z0-9]{10})(?:,|$)/;
    my $task = $entitlements =~ m{<key>com\.apple\.security\.get-task-allow</key>\s*<true/>} ? JSON::PP::true : JSON::PP::false;
    print JSON::PP->new->canonical->encode({signature => $kind, identifier => $identifier, cdhash => $cdhash,
      teamOU => $team, getTaskAllow => $task});' "$display" "$entitlements" "$subject"
}

cdhash_of() {
  describe "$1" | perl -MJSON::PP -e 'local $/; print decode_json(<STDIN>)->{cdhash} // ""'
}

running_daemon_cdhash() {
  local pid
  pid="$(pgrep -x WGEXDaemon || true)"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 0
  # Reads every line (no early exit, so the writer never meets a closed pipe) and keeps the first hash.
  sudo -n codesign -d --verbose=4 "$pid" 2>&1 | perl -ne 'if (!$seen && /^CDHash=([0-9a-f]{40})$/) { print $1; $seen = 1 }'
}

# One attempt's binary at the layout's CLI path. A rename gives it a new vnode, so the kernel never reuses the signature
# it cached for the previous attempt's binary at that path.
install_layout() {
  local next="$layout/Contents/Helpers/.wgex.next"
  cp "$1" "$next"
  mv -f "$next" "$layout/Contents/Helpers/wgex"
  [[ "$(cdhash_of "$layout/Contents/Helpers/wgex")" == "$(cdhash_of "$1")" ]] || exit 1
}

# XPC code-signing refusals during one attempt, from the daemon and from the client itself: libxpc's own lines in the
# refusing process ("Dropping check-in message due to code signing requirement" and its siblings), plus the Lab daemon's own
# admission refusal ("Lab XPC client refused", which declines the connection before libxpc logs anything). The reader keeps
# per-pid counts only; no log line is written anywhere.
watch_start() {
  local process="$1" attempt
  watch_fifo="$corpus/refusals.pipe"
  rm -f "$watch_fifo" "$corpus/refusals" "$corpus/refusals.ready"
  mkfifo -m 0600 "$watch_fifo"
  /usr/bin/log stream --level debug --style compact \
    --predicate "(eventMessage CONTAINS \"code signing requirement\" OR eventMessage CONTAINS \"Lab XPC client refused\") AND (process == \"WGEXDaemon\" OR process == \"$process\")" \
    >"$watch_fifo" 2>/dev/null &
  watch_log=$!
  perl "$stage/corpus-attempt.pl" watch "$corpus/refusals" "$corpus/refusals.ready" <"$watch_fifo" &
  watch_reader=$!
  # An attempt that stops early still stops its own stream.
  trap watch_stop EXIT
  for ((attempt = 0; attempt < 50; attempt++)); do
    if [[ -f "$corpus/refusals.ready" ]]; then
      sleep 0.5
      return 0
    fi
    sleep 0.1
  done
  watch_stop
  exit 1
}

# Stops only the stream and reader watch_start started (their recorded pids); the "pid count" lines stay in
# $corpus/refusals. Runs in the script's own shell, never a subshell, so it waits for its own children.
watch_stop() {
  trap - EXIT
  kill "$watch_log" 2>/dev/null || true
  wait "$watch_log" 2>/dev/null || true
  wait "$watch_reader" 2>/dev/null || true
  rm -f "$watch_fifo" "$corpus/refusals.ready"
}

sign_wrong_team() {
  local target="$1" keychain="$corpus/wrong-team.keychain-db" password transfer line
  local -a saved=()
  password="$(openssl rand -hex 16)"
  transfer="$(openssl rand -hex 16)"
  cat >"$corpus/wrong-team.cnf" <<EOF
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = $signer
OU = $team
O = WGEX Lab Corpus
[ext]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,codeSigning
EOF
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -config "$corpus/wrong-team.cnf" \
    -keyout "$corpus/wrong-team.key" -out "$corpus/wrong-team.pem" 2>/dev/null
  openssl pkcs12 -export -inkey "$corpus/wrong-team.key" -in "$corpus/wrong-team.pem" -name "$signer" \
    -out "$corpus/wrong-team.p12" -passout "pass:$transfer" 2>/dev/null
  rm -f "$corpus/wrong-team.key"
  while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line#\"}"
    line="${line%\"}"
    [[ -z "$line" ]] || saved+=("$line")
  done < <(security list-keychains -d user)
  security create-keychain -p "$password" "$keychain"
  security unlock-keychain -p "$password" "$keychain"
  security import "$corpus/wrong-team.p12" -k "$keychain" -P "$transfer" -T /usr/bin/codesign >/dev/null
  rm -f "$corpus/wrong-team.p12"
  security set-key-partition-list -S apple-tool:,apple: -s -k "$password" "$keychain" >/dev/null
  # codesign finds the identity through the guest user's search list: the throwaway keychain joins it for this one
  # signature, then the guest's own list is put back as it was.
  security list-keychains -d user -s "$keychain" ${saved[@]+"${saved[@]}"}
  codesign -f -s "$signer" --keychain "$keychain" -i "$cli_id" "$target" 2>/dev/null || true
  security list-keychains -d user -s ${saved[@]+"${saved[@]}"}
}

case "${1:?action required}" in
  prepare)
    client="$stage/wgex-corpus-client"
    thin="$stage/wgex-corpus-client-x86_64"
    [[ ! -e "$corpus" && -f "$client" && ! -L "$client" && -f "$thin" && ! -L "$thin" && -x "$cli" ]] || exit 1
    umask 077
    mkdir "$corpus"
    for name in genuine "${layout_clients[@]}"; do cp "$cli" "$corpus/$name"; done
    for name in old-protocol older-build; do cp "$client" "$corpus/$name"; done
    # Apple silicon never executes unsigned arm64 code: the unsigned client is the corpus client's x86_64 slice, which
    # runs unsigned under Rosetta. The host cut the slice (the guest has no developer tools, so no lipo). A slice the linker
    # left unsigned has no signature to remove; describe checks the result.
    cp "$thin" "$corpus/unsigned"
    codesign --remove-signature "$corpus/unsigned" 2>/dev/null || true
    # An explicit designated requirement gives a code directory unlike the build's own ad hoc signature.
    codesign -f -s - -i "$cli_id" -r="designated => identifier \"$cli_id\"" "$corpus/ad-hoc" 2>/dev/null
    codesign -f -s - -i com.magrathean.WGEXApp.dev.impostor "$corpus/wrong-identifier" 2>/dev/null
    printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>' \
      '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' \
      '<plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>' \
      >"$corpus/get-task-allow.plist"
    codesign -f -s - -i "$cli_id" --entitlements "$corpus/get-task-allow.plist" "$corpus/get-task-allow" 2>/dev/null
    codesign -f -s - -i "$cli_id" "$corpus/old-protocol" 2>/dev/null
    codesign -f -s - -i "$cli_id" "$corpus/older-build" 2>/dev/null
    sign_wrong_team "$corpus/wrong-team"
    mkdir -p "$layout/Contents/MacOS" "$layout/Contents/Helpers"
    ditto "$app/Contents/MacOS/WGEXDaemon" "$layout/Contents/MacOS/WGEXDaemon"
    # The installed CLI's loader paths (@executable_path/../Frameworks) resolve the same way from the layout.
    if [[ -d "$app/Contents/Frameworks" ]]; then ditto "$app/Contents/Frameworks" "$layout/Contents/Frameworks"; fi
    rosetta=false
    # Apple silicon runs no unsigned arm64 code, so the unsigned client needs Rosetta, which the driver installed before the
    # connect (verdict-live.py ensure_rosetta: the protected window cuts the guest off from Apple's servers).
    if /usr/bin/arch -x86_64 /usr/bin/true 2>/dev/null; then rosetta=true; fi
    app_hash="$(describe "$app/Contents/MacOS/WGEX")"
    cli_hash="$(describe "$cli")"
    daemon_hash="$(running_daemon_cdhash)"
    layout_hash="$(cdhash_of "$layout/Contents/MacOS/WGEXDaemon")"
    build="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$app/Contents/Info.plist")"
    [[ "$build" =~ ^[0-9]{1,9}$ ]] || exit 1
    {
      printf '%s\n' "$app_hash" "$cli_hash" "$build" "$daemon_hash" "$layout_hash" "$rosetta"
      for name in "${clients[@]}"; do printf '%s %s\n' "$name" "$(describe "$corpus/$name")"; done
    } | perl -MJSON::PP -e '
      my $json = JSON::PP->new->canonical;
      my ($app, $cli, $build, $daemon, $layout, $rosetta) = map { my $line = <STDIN>; chomp $line; $line } 1 .. 6;
      $app = decode_json($app); $cli = decode_json($cli);
      my @clients;
      while (my $line = <STDIN>) {
        my ($name, $value) = split / /, $line, 2;
        my $item = decode_json($value);
        $item->{name} = $name;
        $item->{protocolVersion} = 6 if $name eq "old-protocol";
        $item->{clientBuild} = 0 if $name eq "older-build";
        push @clients, $item;
      }
      print $json->encode({genuine => {app => $app->{cdhash}, cli => $cli->{cdhash}, teamOU => $cli->{teamOU},
        daemonBuild => 0 + $build, daemon => ($daemon =~ /^[0-9a-f]{40}$/ ? $daemon : undef),
        layoutDaemon => ($layout =~ /^[0-9a-f]{40}$/ ? $layout : undef),
        rosetta => ($rosetta eq "true" ? JSON::PP::true : JSON::PP::false)}, clients => \@clients}), "\n";'
    ;;
  attempt)
    name="${2:?client required}"
    [[ " genuine ${clients[*]} " == *" $name "* && -f "$corpus/$name" && ! -L "$corpus/$name" && -d "$layout" ]] || exit 1
    # Never run the genuine CLI under a corpus name: a variant whose signing left the build's own hash is refused here.
    genuine="$(cdhash_of "$cli")"
    variant="$(cdhash_of "$corpus/$name")"
    if [[ "$name" == genuine ]]; then
      [[ -n "$genuine" && "$variant" == "$genuine" ]] || exit 1
    else
      [[ -n "$genuine" && "$variant" != "$genuine" ]] || exit 1
    fi
    svc="$(service)"
    case "$name" in
      unsigned) exe="$corpus/unsigned" args=(current "$svc") ;;
      old-protocol | older-build) exe="$corpus/$name" args=("$name" "$svc") ;;
      # The layout control: a read-only request the daemon must serve.
      genuine) install_layout "$corpus/genuine" && exe="$layout/Contents/Helpers/wgex" args=(status --json) ;;
      # The genuine CLI's own privileged request: stop the connected tunnel.
      *) install_layout "$corpus/$name" && exe="$layout/Contents/Helpers/wgex" args=(down --json) ;;
    esac
    before="$(snapshot)"
    since="$(stamp)"
    watch_start "$(basename "$exe")"
    code=0
    : >"$corpus/report"
    bounded 30 "$exe" "${args[@]}" >"$corpus/report" 2>/dev/null &
    client_pid=$!
    wait "$client_pid" || code=$?
    # The log stream delivers lines with a short delay.
    sleep 2
    watch_stop
    refusals="$(cat "$corpus/refusals")"
    after="$(snapshot)"
    lines="$(lifecycle_since "$since")"
    # Only fixed fields of the client's own report leave the guest: the CLI's error name or status, or the corpus client's
    # mode, outcome and XPC error code. A client that wrote no report (launch, loader, guard or usage failure) has none.
    perl "$stage/corpus-attempt.pl" report "$name" "$code" "$(head -c 4096 "$corpus/report")" "$before" "$after" "$lines" \
      "$refusals" "$client_pid"
    ;;
  impostor)
    svc="$(service)"
    uid="$(id -u "$lab_user")"
    umask 077
    target="$corpus/impostor"
    cp "$stage/wgex-corpus-client" "$target"
    codesign -f -s - -i "$impostor_label" "$target" 2>/dev/null
    log="$corpus/impostor.log"
    : >"$log"
    plist="$corpus/$impostor_label.plist"
    printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>' \
      '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' \
      '<plist version="1.0"><dict>' "<key>Label</key><string>$impostor_label</string>" \
      "<key>ProgramArguments</key><array><string>$target</string><string>serve</string><string>$svc</string><string>$log</string></array>" \
      "<key>MachServices</key><dict><key>$svc</key><true/></dict>" '</dict></plist>' >"$plist"
    plutil -lint "$plist" >/dev/null
    before="$(snapshot)"
    since="$(stamp)"
    registered=false
    if sudo -n launchctl bootstrap "gui/$uid" "$plist" 2>/dev/null; then registered=true; fi
    # Unprivileged lookup from the console session: the user's domain resolves the impostor (the control).
    control="$(as_console perl -e 'alarm shift; exec @ARGV or die' 30 "$target" probe-user "$svc" 2>/dev/null || true)"
    first="$(grep -c '^connection$' "$log" || true)"
    # Privileged lookup from the same session: the genuine CLI must reach the root daemon, never the impostor.
    status="$(as_console perl -e 'alarm shift; exec @ARGV or die' 30 "$cli" status --json 2>/dev/null || true)"
    sleep 2
    second="$(grep -c '^connection$' "$log" || true)"
    after="$(snapshot)"
    lines="$(lifecycle_since "$since")"
    sudo -n launchctl bootout "gui/$uid/$impostor_label" 2>/dev/null || true
    perl -MJSON::PP -e '
      my ($registered, $control, $first, $second, $status, $before, $after, $lines) = @ARGV;
      my $probe = eval { decode_json($control) } || {};
      my $state = eval { decode_json($status) } || {};
      my $served = defined $state->{phase} && !ref $state->{phase}
        && $state->{phase} =~ /^(?:idle|preparing|configuring|active|reasserting|captiveWindow|stopping|failed)$/;
      print JSON::PP->new->canonical->encode({registered => $registered eq "true" ? JSON::PP::true : JSON::PP::false,
        controlReached => ($probe->{impostor} ? JSON::PP::true : JSON::PP::false),
        connectionsBeforePrivileged => 0 + $first, connectionsAfterPrivileged => 0 + $second,
        privilegedServedByDaemon => ($served ? JSON::PP::true : JSON::PP::false),
        before => decode_json($before), after => decode_json($after), lifecycleLines => 0 + $lines}), "\n";' \
      "$registered" "$control" "$first" "$second" "$status" "$before" "$after" "$lines"
    ;;
  control)
    # The log observer's positive control: the genuine CLI's down is privileged work the tail must show.
    since="$(stamp)"
    "$cli" down --json >/dev/null
    lines=0
    protection=unknown
    for ((attempt = 0; attempt < 30; attempt++)); do
      lines="$(lifecycle_since "$since")"
      protection="$("$cli" status --json 2>/dev/null |
        perl -MJSON::PP -e 'local $/; my $d = eval { decode_json(<STDIN>) } || {}; print $d->{protection} // "unknown"' || true)"
      if ((lines >= 1)) && [[ "$protection" == unprotected ]]; then break; fi
      sleep 0.5
    done
    [[ "$protection" =~ ^[a-zA-Z]{1,20}$ ]] || protection=unknown
    printf '{"genuineDownLifecycleLines":%d,"protectionAfter":"%s"}\n' "$lines" "$protection"
    ;;
  cleanup)
    uid="$(id -u "$lab_user")"
    sudo -n launchctl bootout "gui/$uid/$impostor_label" 2>/dev/null || true
    if [[ -f "$corpus/wrong-team.keychain-db" ]]; then security delete-keychain "$corpus/wrong-team.keychain-db" 2>/dev/null || true; fi
    # Only this row's own corpus directory inside its own stage.
    if [[ -d "$corpus" && ! -L "$corpus" ]]; then rm -rf -- "$corpus"; fi
    ;;
  *) exit 64 ;;
esac
