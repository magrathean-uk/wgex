#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# M1-12 guest cutover rehearsal (M03-T08). Usage:
#   cutover-rehearsal.sh --report-root DIR GUEST   the whole live rehearsal in the named Tart guest (cutover-live.py):
#                                                  four scenarios and ten RUNBOOK supplements, written to
#                                                  DIR/cutover-rehearsal/verdict.json with a row's provenance
#   cutover-rehearsal.sh --scenario STEP PROFILE   one scenario step against the running guest; the live driver's building block
#   cutover-rehearsal.sh --dry-run                 every step in order with fixture providers and the corrupt-fixture checks
set -euo pipefail
base="$(cd "$(dirname "$0")" && pwd)"
if [[ "${1:-}" == --report-root ]]; then
  [[ $# == 3 && -n "$2" ]] || {
    printf 'usage: cutover-rehearsal.sh --report-root DIR GUEST\n' >&2
    exit 2
  }
  [[ "$3" =~ ^macos(26|27)-wgex(-[a-zA-Z0-9_-]+)?$ ]] || {
    printf 'lab: GUEST must be macos26-wgex, macos27-wgex or a named variant\n' >&2
    exit 2
  }
  [[ -z "${WGEX_LAB_TEST_BIN:-}" ]] || {
    printf 'lab: mock injection requires --dry-run\n' >&2
    exit 2
  }
  cd "$base/../.."
  WGEX_LAB_VM="$3" exec python3 -I -B "$base/cutover-live.py" --report-root "$2"
fi
# shellcheck source=Tools/lab/tart/lib.sh
source "$base/tart/lib.sh"
# The same assertions run in the guest and in the dry-run SSH fixture. Providers supply observations only.
assert_reverted_body="$(
  cat <<'ASSERT'
test "$(journal_field cutover.state.rolledBack.reason)" = "$expected_reason" || exit 1
test "$(journal_field cutover.rollbackPending)" = false || exit 1
if journal_field intent >/dev/null 2>&1; then exit 1; fi
if journal_field pfToken >/dev/null 2>&1; then exit 1; fi
test "$(journal_field settings.lockdown)" = false || exit 1
boot_intent_absent || exit 1
bundle_absent || exit 1
anchor_empty || exit 1
owned_reference_absent || exit 1
wgex_address_absent || exit 1
canary_route_absent || exit 1
dns_absent || exit 1
ASSERT
)"
# shellcheck disable=SC2016 # Expanded only by the guest or fixture observation shell.
assert_confirmed_body='test "$(journal_field cutover.state.confirmed)" = "{}" || exit 1'
# M1-12b. While a trial is armed, journal.json is usually the checkpoint written when the trial was armed and its
# generation allocated; the trial's resources and pf token are appended to journal.log. DaemonJournal.commit checkpoints
# on cutover, generation and clean-shutdown changes, and also once journal.log passes 64 KiB or before an append that
# would pass 8 MiB, so a long armed trial can have some resources in journal.json and the rest in journal.log.
# journal_document therefore prints the daemon's own replay of both
# (tart/guest/journal-replay.pl), and the keys below are read from that flat document. The resource is the one whose
# generation is the document's current generation. Without a journalled token the sole pfctl References row is used, as
# the RUNBOOK's manual drill does; anything else is ambiguous and fails. The same body runs in the guest and in the
# dry-run fixture; providers supply journal_document, pf_references and boot_session, and set stage, profile and
# remember_wait. A replay failure is retried like a missing address until the deadline: a checkpoint that lands between
# the helper's reads of journal.json and journal.log looks like a sequence gap for that one read. read, not
# $(cat <<...): bash 3.2 misparses the case patterns inside a command substitution.
IFS= read -r -d '' remember_body <<'REMEMBER' || true
umask 077
document="$stage/journal.replayed.json"
trap 'rm -f "$document"' EXIT
replayed_field() { plutil -extract "$1" raw -o - "$document" 2>/dev/null; }
deadline=$((SECONDS + remember_wait))
resource=
while :; do
  if replay_error="$(journal_document 2>&1 >"$document")"; then
    replay_error=
    generation="$(replayed_field generation)" || exit 1
    index=0
    while candidate="$(replayed_field "resources.$index.generation")"; do
      if test "$candidate" = "$generation"; then
        if replayed_field "resources.$index.addresses.0" >/dev/null; then resource="resources.$index"; fi
        break
      fi
      index=$((index + 1))
    done
    test -z "$resource" || break
  else
    replay_error="journal replay failed: ${replay_error:-no diagnostics}"
  fi
  if test "$SECONDS" -ge "$deadline"; then
    echo "cutover remember: ${replay_error:-no tunnel address journalled for the current generation}" >&2
    exit 1
  fi
  sleep 1
done
test "$(replayed_field cutover.profileID)" = "$profile" || exit 1
address="$(replayed_field "$resource.addresses.0")" || exit 1
address="${address%%/*}"
test -n "$address" || exit 1
routes=
index=0
while destination="$(replayed_field "$resource.routes.$index.destination")"; do
  prefix="$(replayed_field "$resource.routes.$index.prefixLength")" || exit 1
  interface="$(replayed_field "$resource.routes.$index.interfaceName")" || exit 1
  routes="$routes$destination/$prefix $interface
"
  index=$((index + 1))
done
# OwnedCanaryRoute.route is fixed: 192.0.2.1/32 scoped to the journalled physical interface via the journalled router.
canary=
if canary_interface="$(replayed_field "$resource.canaryRoute.identity.name")"; then
  router="$(replayed_field "$resource.canaryRoute.router")" || exit 1
  canary="192.0.2.1/32 $canary_interface $router"
fi
dns_key="$(replayed_field "$resource.dnsKey")" || dns_key=
if token="$(replayed_field pfToken)"; then
  token_source=journal
  pid="$(replayed_field pfTokenPID)" || exit 1
  boot="$(replayed_field pfBootSession)" || exit 1
else
  token_source=references
  references="$(pf_references)" || exit 1
  rows="$(printf '%s\n' "$references" | awk '$1 ~ /^[0-9]+$/ && $2 == "pfctl" && $3 ~ /^[0-9]+$/ { print $1, $3 }')"
  case "$rows" in
    '' | *'
'*)
      echo 'cutover remember: no journalled pf token and no single pfctl References row' >&2
      exit 1
      ;;
  esac
  pid="${rows%% *}"
  token="${rows#* }"
  boot="$(boot_session)" || exit 1
fi
case "$token" in '' | *[!0-9]*) exit 1 ;; esac
case "$pid" in '' | *[!0-9]*) exit 1 ;; esac
test -n "$boot" || exit 1
printf '%s\n' "$address" >"$stage/address"
printf '%s' "$routes" >"$stage/routes"
printf '%s\n' "$canary" >"$stage/canary"
printf '%s\n' "$dns_key" >"$stage/dns-key"
printf '%s\n' "$token" >"$stage/token"
printf '%s\n' "$token_source" >"$stage/token-source"
printf '%s\n' "$pid" >"$stage/pid"
printf '%s\n' "$boot" | tr '[:lower:]' '[:upper:]' >"$stage/boot"
REMEMBER
dry=0
step=
if [[ "${1:-}" == --dry-run ]]; then
  dry=1
  shift
  [[ $# == 0 ]] || lab_die 'usage: cutover-rehearsal.sh --dry-run'
elif [[ "${1:-}" == --scenario ]]; then
  [[ $# == 3 ]] || lab_die 'usage: cutover-rehearsal.sh --scenario STEP PROFILE-UUID'
  step="$2"
  case "$step" in
    expiry | start | confirm | reboot-confirmed | abort | abort-attempt | armed-reboot | settle-aborted | settle-daemonRestart | assert-aborted | assert-daemonRestart) ;;
    *) lab_die "unknown scenario step: $step" ;;
  esac
  shift 2
else
  lab_die 'usage: cutover-rehearsal.sh --report-root DIR GUEST | --scenario STEP PROFILE-UUID | --dry-run'
fi
profile="${1:-}"
scratch=
if [[ "$dry" == 1 ]]; then
  scratch="$(mktemp -d "${TMPDIR:?}/wgex-cutover-mock.XXXXXX")"
  trap 'rm -rf "$scratch"' EXIT
  mkdir "$scratch/bin"
  touch "$scratch/bin/fixture-only"
  export WGEX_LAB_TEST_BIN="$scratch/bin"
  export WGEX_CUTOVER_MOCK_STATE="$scratch/state"
  export WGEX_CUTOVER_MOCK_LOG="$scratch/log"
  export WGEX_CUTOVER_ASSERT_REVERTED="$scratch/assert-reverted.sh"
  export WGEX_CUTOVER_ASSERT_CONFIRMED="$scratch/assert-confirmed.sh"
  export WGEX_CUTOVER_REMEMBER="$scratch/remember.sh"
  export WGEX_CUTOVER_REPLAY="$base/tart/guest/journal-replay.pl"
  export WGEX_CUTOVER_JOURNAL="$scratch/journal"
  export WGEX_CUTOVER_MOCK_STAGE="$scratch/stage"
  printf '%s\n' "$assert_reverted_body" >"$WGEX_CUTOVER_ASSERT_REVERTED"
  printf '%s\n' "$assert_confirmed_body" >"$WGEX_CUTOVER_ASSERT_CONFIRMED"
  printf '%s\n' "$remember_body" >"$WGEX_CUTOVER_REMEMBER"
  # The armed-trial state directory captured in guest run 7 (fixture SOURCE.txt): the checkpoint as written at arming plus
  # the journal.log frames the daemon appended afterwards, reframed from their bodies exactly as JournalRecord.encode
  # writes them (little-endian length, high bit for a non-durable record, JSON body, SHA-256 of the body; this reproduces
  # the captured journal.log byte for byte). checkpoint-only holds the checkpoint alone, the shape the pre-M1-12b reader
  # expected to be enough; gap lacks the first record after the checkpoint, so every replay fails until the deadline.
  fixture="$base/tests/fixtures/cutover-armed-run7"
  mkdir -p "$WGEX_CUTOVER_JOURNAL/armed" "$WGEX_CUTOVER_JOURNAL/checkpoint-only" "$WGEX_CUTOVER_JOURNAL/gap" "$WGEX_CUTOVER_MOCK_STAGE"
  for journal in armed checkpoint-only gap; do cp "$fixture/journal.json" "$WGEX_CUTOVER_JOURNAL/$journal/journal.json"; done
  frame_records() {
    # shellcheck disable=SC2016 # Perl source.
    perl -MJSON::PP -MDigest::SHA=sha256 -ne 'next if $. < $ENV{WGEX_CUTOVER_FIRST_RECORD}; chomp; my $durable = JSON::PP->new->decode($_)->{durable}; print pack("V", length($_) | ($durable ? 0 : 0x80000000)), $_, sha256($_)' \
      "$fixture/journal.log.jsonl"
  }
  WGEX_CUTOVER_FIRST_RECORD=1 frame_records >"$WGEX_CUTOVER_JOURNAL/armed/journal.log"
  WGEX_CUTOVER_FIRST_RECORD=2 frame_records >"$WGEX_CUTOVER_JOURNAL/gap/journal.log"
  printf 'none\n' >"$WGEX_CUTOVER_MOCK_STATE"
  cat >"$scratch/bin/fake" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
name="${0##*/}"
printf '%s\n' "$name" >>"$WGEX_CUTOVER_MOCK_LOG"
fault="${WGEX_CUTOVER_MOCK_FAULT:-}"
journal_field() {
  case "$1" in
    cutover.state.rolledBack.reason) if [[ "$fault" == reason ]]; then printf 'wrong\n'; else cat "$WGEX_CUTOVER_MOCK_STATE"; fi ;;
    cutover.rollbackPending) if [[ "$fault" == pending ]]; then printf 'true\n'; else printf 'false\n'; fi ;;
    intent) [[ "$fault" == intent ]] || return 1; printf 'present\n' ;;
    pfToken) [[ "$fault" == token ]] || return 1; printf '9001\n' ;;
    settings.lockdown) if [[ "$fault" == lockdown ]]; then printf 'true\n'; else printf 'false\n'; fi ;;
    cutover.state.confirmed)
      [[ "$fault" != confirmed ]] && grep -qx confirmed "$WGEX_CUTOVER_MOCK_STATE" || return 1
      printf '{}\n'
      ;;
    *) return 93 ;;
  esac
}
journal_document() {
  case "$fault" in
    checkpointOnly) perl "$WGEX_CUTOVER_REPLAY" "$WGEX_CUTOVER_JOURNAL/checkpoint-only" ;;
    replayGap) perl "$WGEX_CUTOVER_REPLAY" "$WGEX_CUTOVER_JOURNAL/gap" ;;
    noToken | ambiguousReference)
      # shellcheck disable=SC2016 # Perl source.
      perl "$WGEX_CUTOVER_REPLAY" "$WGEX_CUTOVER_JOURNAL/armed" |
        perl -MJSON::PP -e 'my $json = JSON::PP->new->canonical; my $document = $json->decode(do { local $/; <STDIN> }); delete @$document{qw(pfToken pfTokenPID pfBootSession)}; print $json->encode($document)'
      ;;
    *) perl "$WGEX_CUTOVER_REPLAY" "$WGEX_CUTOVER_JOURNAL/armed" ;;
  esac
}
pf_references() {
  printf 'No ALTQ support in kernel\nALTQ related functions disabled\nTOKENS:\nPID Process Name TOKEN TIMESTAMP\n'
  printf '4243 pfctl 9002 0 days 00:00:05\n'
  [[ "$fault" != ambiguousReference ]] || printf '4244 pfctl 9003 0 days 00:00:01\n'
}
boot_session() { printf '66666666-6666-4666-8666-666666666666\n'; }
boot_intent_absent() { [[ "$fault" != bootIntent ]]; }
bundle_absent() { [[ "$fault" != secret ]]; }
anchor_empty() { [[ "$fault" != anchor ]]; }
owned_reference_absent() { [[ "$fault" != reference ]]; }
wgex_address_absent() { [[ "$fault" != address ]]; }
canary_route_absent() { [[ "$fault" != canary ]]; }
dns_absent() { [[ "$fault" != dns ]]; }
case "$name" in
  sw_vers) printf '27.0.1\n' ;;
  vm-tart) [[ "$1" != ip ]] || printf '192.0.2.1\n' ;;
  scp) ;;
  ssh)
    command="${!#}"
    case "$command" in
      true) ;;
      'sw_vers -productVersion') printf '26.6.2\n' ;;
      *kern.hv_vmm_present*wgex-lab-host*) ;;
      'mkdir -p '* | 'chmod +x '*) ;;
      *'# cutover:remember'*)
        grep -Eq '^(armed|confirmed)$' "$WGEX_CUTOVER_MOCK_STATE"
        stage="$WGEX_CUTOVER_MOCK_STAGE"
        profile=00000000-0000-4000-8000-000000000101 # the run 7 capture's trial profile
        if [[ "$fault" == wrongProfile ]]; then profile=22222222-2222-2222-2222-222222222222; fi
        remember_wait=0
        # shellcheck disable=SC1090 # same remember body sent to the guest
        source "$WGEX_CUTOVER_REMEMBER"
        ;;
      *'# cutover:status'*) ;;
      *'# cutover:start'*) printf 'armed\n' >"$WGEX_CUTOVER_MOCK_STATE" ;;
      *'# cutover:confirm'*) grep -qx armed "$WGEX_CUTOVER_MOCK_STATE"; printf 'confirmed\n' >"$WGEX_CUTOVER_MOCK_STATE" ;;
      *'# cutover:wait-timeout'*) grep -qx armed "$WGEX_CUTOVER_MOCK_STATE"; printf 'timeout\n' >"$WGEX_CUTOVER_MOCK_STATE" ;;
      *'# cutover:wait-daemonRestart'*) grep -qx daemonRestart "$WGEX_CUTOVER_MOCK_STATE" ;;
      *'# cutover:reboot'*)
        state="$(cat "$WGEX_CUTOVER_MOCK_STATE")"
        if [[ "$state" == armed ]]; then printf 'daemonRestart\n' >"$WGEX_CUTOVER_MOCK_STATE"; fi
        ;;
      *'# cutover:assert-confirmed'*)
        # shellcheck disable=SC1090 # fixture path created by this script
        source "$WGEX_CUTOVER_ASSERT_CONFIRMED"
        ;;
      *'# cutover:assert-'*)
        expected_reason="${command##*# cutover:assert-}"
        # shellcheck disable=SC1090 # same assertion body sent to the guest
        source "$WGEX_CUTOVER_ASSERT_REVERTED"
        ;;
      *'# cutover:abort'*) printf 'aborted\n' >"$WGEX_CUTOVER_MOCK_STATE" ;;
      *) exit 92 ;;
    esac
    ;;
  *) exit 91 ;;
esac
MOCK
  chmod +x "$scratch/bin/fake"
  for tool in sw_vers vm-tart ssh scp; do ln -s fake "$scratch/bin/$tool"; done
  profile="${profile:-00000000-0000-4000-8000-000000000101}"
  lab_init --dry-run
else
  [[ -z "${WGEX_LAB_TEST_BIN:-}" ]] || lab_die 'mock injection requires --dry-run'
  lab_init
fi
[[ "$profile" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$ ]] || lab_die 'a dedicated installed lab profile UUID is required'
profile="$(printf '%s' "$profile" | tr '[:lower:]' '[:upper:]')"
lab_connect
guest_is_lab
cli=/Applications/WGEX.app/Contents/Helpers/wgex
stage="/Users/$LAB_USER/lab/cutover"
lab_ssh "mkdir -p '$stage'" </dev/null
lab_scp "$base/tart/guest/asu.sh" "$LAB_USER@$LAB_ADDRESS:$stage/asu.sh" </dev/null
lab_scp "$base/tart/guest/guard.sh" "$LAB_USER@$LAB_ADDRESS:$stage/guard.sh" </dev/null
lab_scp "$base/tart/guest/journal-replay.pl" "$LAB_USER@$LAB_ADDRESS:$stage/journal-replay.pl" </dev/null
lab_ssh "chmod +x '$stage/asu.sh'" </dev/null
owner_cli() {
  local marker="$1" quoted
  shift
  printf -v quoted '%q ' "$@"
  lab_ssh "'$stage/asu.sh' '$cli' $quoted # cutover:$marker" </dev/null
}
cleanup() {
  local result=$?
  # The dry run aborts after a failure; a live scenario step leaves recovery to its driver (cutover-live.py), which
  # must see a failed rollback as it is (failed-stop retry).
  if [[ "$result" != 0 && "$dry" == 1 ]]; then owner_cli abort cutover abort >/dev/null 2>&1 || true; fi
  if [[ -n "$scratch" ]]; then rm -rf "$scratch"; fi
  return "$result"
}
trap cleanup EXIT
reboot_guest() {
  lab_ssh 'sudo -n /sbin/shutdown -r +1 # cutover:reboot' </dev/null
  if [[ "$dry" != 1 ]]; then sleep 75; fi
  lab_wait_ready
}
wait_for_rollback() {
  local reason="$1"
  lab_ssh "set -eu
j='/Library/Application Support/WGEX/journal.json'
deadline=\$((SECONDS + 180))
while test \"\$SECONDS\" -lt \"\$deadline\"; do
  if test \"\$(sudo -n plutil -extract cutover.state.rolledBack.reason raw -o - \"\$j\" 2>/dev/null)\" = '$reason' &&
     test \"\$(sudo -n plutil -extract cutover.rollbackPending raw -o - \"\$j\" 2>/dev/null)\" = false; then exit 0; fi
  sleep 1
done
exit 1
# cutover:wait-$reason" </dev/null
}
# canary_route_absent: once the canary is gone, `route -n get [-ifscope en0] 192.0.2.1` on the 26.6.2 guest exits 0 with
# `destination: default` for both the global and the scoped lookup (guest run 7); the `not in table` failure was never
# seen there and stays accepted for other releases. A `destination: 192.0.2.1` line, or no destination line, fails.
assert_reverted() {
  local reason="$1"
  # Only these observation providers touch the guest. The assertion body above contains no host commands.
  lab_ssh "set -euo pipefail
j='/Library/Application Support/WGEX/journal.json'
expected_reason='$reason'
journal_field() { sudo -n plutil -extract \"\$1\" raw -o - \"\$j\"; }
boot_intent_absent() { test \"\$(sudo -n plutil -extract startBeforeLoginOverride raw -o - '/Library/Application Support/WGEX/profiles/$profile.json')\" = false; }
bundle_absent() { sudo -n test ! -e '/Library/Application Support/WGEX/secrets/bundles/$profile-privateKey-$profile.blob'; }
anchor_empty() {
  rules=\"\$(sudo -n pfctl -a com.apple/wgex -sr 2>/dev/null)\" || return
  test -z \"\$rules\"
}
owned_reference_absent() {
  current_boot=\"\$(sysctl -n kern.bootsessionuuid | tr '[:lower:]' '[:upper:]')\" || return
  recorded_boot=\"\$(cat '$stage/boot')\" || return
  if test \"\$current_boot\" != \"\$recorded_boot\"; then return 0; fi
  recorded_pid=\"\$(cat '$stage/pid')\" || return
  recorded_token=\"\$(cat '$stage/token')\" || return
  references=\"\$(sudo -n pfctl -s References 2>/dev/null)\" || return
  printf '%s\\n' \"\$references\" | awk -v p=\"\$recorded_pid\" -v t=\"\$recorded_token\" '\$1 == p && \$2 == \"pfctl\" && \$3 == t { found=1 } END { exit found }'
}
wgex_address_absent() {
  address=\"\$(cat '$stage/address')\" || return
  test -n \"\$address\" || return 1
  observations=\"\$({ /sbin/ifconfig -a || exit; netstat -rn; })\" || return
  printf '%s\\n' \"\$observations\" | awk -v address=\"\$address\" '{ for (i=1; i<=NF; i++) { split(\$i, part, /[%\\/]/); if (part[1] == address) found=1 } } END { exit found }'
}
canary_route_absent() {
  canary=\"\$(cat '$stage/canary')\" || return
  test -n \"\$canary\" || return 0
  interface=\"\${canary#* }\"
  interface=\"\${interface%% *}\"
  if observation=\"\$(/sbin/route -n get -ifscope \"\$interface\" 192.0.2.1 2>&1)\"; then
    printf '%s\\n' \"\$observation\" | awk '\$1 == \"destination:\" { seen=1; if (\$2 == \"192.0.2.1\") found=1 } END { exit (found || !seen) }'
  else
    case \"\$observation\" in *'not in table'*) ;; *) return 1 ;; esac
  fi
}
dns_absent() {
  dns=\"\$(printf 'show State:/Network/Service/$profile/DNS\\nquit\\n' | scutil)\" || return
  case \"\$dns\" in *ServerAddresses*) return 1 ;; esac
}
$assert_reverted_body
# cutover:assert-$reason" </dev/null || return
  owner_cli status status --json
}
assert_confirmed() {
  lab_ssh "set -eu
journal_field() { sudo -n plutil -extract \"\$1\" json -o - '/Library/Application Support/WGEX/journal.json'; }
$assert_confirmed_body
# cutover:assert-confirmed" </dev/null
}
remember_resources() {
  # Only these providers touch the guest; the remember body above contains no host commands.
  lab_ssh "set -eu
stage='$stage'
profile='$profile'
remember_wait=60
journal_document() { sudo -n /usr/bin/perl '$stage/journal-replay.pl' '/Library/Application Support/WGEX'; }
pf_references() { sudo -n /sbin/pfctl -s References 2>/dev/null; }
boot_session() { /usr/sbin/sysctl -n kern.bootsessionuuid; }
$remember_body
# cutover:remember" </dev/null
}
remembered() { [[ "$(cat "$WGEX_CUTOVER_MOCK_STAGE/$1")" == "$2" ]] || lab_die "remembered $1 does not match the armed-trial fixture"; }
# The captured token stays in the fixture files: compared, never printed.
fixture_token() { plutil -extract pfToken raw -o - "$fixture/expected-replayed.json"; }
scenario_expiry() {
  owner_cli start cutover start "$profile" --confirm-within 60s
  remember_resources
  if [[ "$dry" == 1 ]]; then
    remembered address 10.77.0.2
    remembered routes $'192.0.2.1/32 en0\n10.77.0.0/24 utun4'
    remembered canary '192.0.2.1/32 en0 192.168.64.1'
    remembered dns-key State:/Network/Service/00000000-0000-4000-8000-000000000101/DNS
    remembered token-source journal
    remembered token "$(fixture_token)"
    remembered pid 1088
    remembered boot 00000000-0000-4000-8000-000000000102
    WGEX_CUTOVER_MOCK_FAULT=noToken remember_resources
    remembered token-source references
    remembered token 9002
    remembered pid 4243
    remembered boot 66666666-6666-4666-8666-666666666666
    for fault in checkpointOnly replayGap ambiguousReference wrongProfile; do
      if WGEX_CUTOVER_MOCK_FAULT="$fault" remember_resources >/dev/null 2>&1; then lab_die "remember accepted corrupt fixture: $fault"; fi
    done
    remember_resources
  fi
  wait_for_rollback timeout
  assert_reverted timeout
}
# The running console app supplies the dedicated lab bundle after every rollback.
scenario_start() {
  owner_cli start cutover start "$profile" --confirm-within 10m
  remember_resources
}
scenario_confirm() { owner_cli confirm cutover confirm; }
scenario_reboot_confirmed() {
  reboot_guest
  assert_confirmed
  if [[ "$dry" == 1 ]]; then
    if WGEX_CUTOVER_MOCK_FAULT=confirmed assert_confirmed >/dev/null 2>&1; then lab_die 'confirmed assertion accepted corrupt fixture'; fi
  fi
}
# Abort reverts an armed trial and a confirmed one alike; after a reboot the trial's token, pid and boot are new.
scenario_abort() {
  remember_resources
  owner_cli abort cutover abort
  assert_reverted aborted
}
scenario_armed_reboot() {
  reboot_guest
  wait_for_rollback daemonRestart
  assert_reverted daemonRestart
}
case "$step" in
  expiry) scenario_expiry ;;
  start) scenario_start ;;
  confirm) scenario_confirm ;;
  reboot-confirmed) scenario_reboot_confirmed ;;
  abort) scenario_abort ;;
  # One abort with its exit status passed through and no assertion: a failed rollback must stay visible.
  abort-attempt) owner_cli abort cutover abort ;;
  armed-reboot) scenario_armed_reboot ;;
  settle-aborted | settle-daemonRestart)
    wait_for_rollback "${step#settle-}"
    assert_reverted "${step#settle-}"
    ;;
  assert-aborted | assert-daemonRestart) assert_reverted "${step#assert-}" ;;
  '')
    scenario_expiry
    scenario_start
    scenario_confirm
    scenario_reboot_confirmed
    scenario_abort
    scenario_start
    scenario_armed_reboot
    ;;
esac
[[ -z "$step" ]] || exit 0
if [[ "$dry" == 1 ]]; then
  for fault in reason pending intent token lockdown bootIntent secret anchor reference address canary dns; do
    if WGEX_CUTOVER_MOCK_FAULT="$fault" assert_reverted daemonRestart >/dev/null 2>&1; then
      lab_die "teardown assertion accepted corrupt fixture: $fault"
    fi
  done
  grep -qx ssh "$WGEX_CUTOVER_MOCK_LOG"
  grep -qx vm-tart "$WGEX_CUTOVER_MOCK_LOG"
  printf 'cutover rehearsal: shared assertions passed (expiry, confirmed restart, abort, armed reboot; armed-trial journal replayed, References fallback; 17 corrupt fixtures rejected)\n'
fi
