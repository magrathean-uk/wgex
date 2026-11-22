#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Offline regression harness. Fake tools never execute their recorded payloads.
set -euo pipefail
# Hermetic: no inherited WGEX_*, STUB_* or FAKE_* variable changes a result (WGEX_LAB_VM, WGEX_LAB_TEST_BIN, the deadline
# knobs, the fake tools' FAKE_* channels, ...); a test that needs one sets it itself. Names only, never values.
# WGEX_BUILD_ROOT is kept: it routes build output (Config/Scripts/build_root.py) and selects no behaviour, so an operator's
# choice of where lab-scripts-test builds must keep working.
removed=()
for name in $(compgen -e); do
  case "$name" in
    WGEX_BUILD_ROOT) ;;
    WGEX_* | STUB_* | FAKE_*)
      removed+=("$name")
      unset "$name"
      ;;
  esac
done
if ((${#removed[@]})); then
  list="$(printf '%s, ' "${removed[@]}")"
  printf 'lab tests: removed inherited variables: %s\n' "${list%, }" >&2
fi
base="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-${CLEAN_DEV_BUILDS:?CLEAN_DEV_BUILDS is required}}/wgex-lab-tests.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/missing" "$work/WGEX.app/Contents/MacOS" "$work/builds"
touch "$work/bin/fixture-only" "$work/missing/fixture-only" "$work/local.ipsw" "$work/WGEX.app.lab-build.sha256"
cat >"$work/bin/fake" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
name="${0##*/}"
printf '%s' "$name" >>"$FAKE_LOG"
printf ' %q' "$@" >>"$FAKE_LOG"
printf '\n' >>"$FAKE_LOG"
case "$name" in
  sw_vers) printf '%s\n' "${FAKE_HOST_VERSION:-27.0.1}" ;;
  vm-tart)
    case "$1" in
      ip)
        if [[ -n "${FAKE_IP_DELAY_FILE:-}" ]]; then
          count=0
          if [[ -f "$FAKE_IP_DELAY_FILE" ]]; then read -r count <"$FAKE_IP_DELAY_FILE"; fi
          printf '%s\n' "$((count + 1))" >"$FAKE_IP_DELAY_FILE"
          ((count >= 3)) || exit 1
        fi
        if [[ "${3:-}" == arp && "${FAKE_ARP:-1}" == 0 ]]; then exit 1; fi
        printf '192.0.2.1\n'
        ;;
      get)
        [[ "${FAKE_SNAPSHOT:-1}" == 1 || "$2" != *-approved ]] || exit 1
        if [[ "$2" == *-approved && "${FAKE_RUNNING_SNAPSHOT:-0}" == 1 ]]; then printf 'running\n'; exit; fi
        if [[ "$2" == macos2[67]-wgex && -f "$FAKE_STATE" ]]; then cat "$FAKE_STATE"; else printf 'stopped\n'; fi
        ;;
      list) printf 'Source Name State\nlocal macos26-wgex-approved stopped\nlocal macos27-wgex stopped\nlocal macos27-base stopped\n' ;;
      run) printf 'running\n' >"$FAKE_STATE" ;;
      delete) [[ "$2" == macos2[67]-wgex ]] || exit 1; printf 'stopped\n' >"$FAKE_STATE" ;;
    esac
    ;;
  ssh)
    command="${!#}"
    case "$command" in
      true)
        if [[ -n "${FAKE_SSH_DELAY_FILE:-}" ]]; then
          count=0
          if [[ -f "$FAKE_SSH_DELAY_FILE" ]]; then read -r count <"$FAKE_SSH_DELAY_FILE"; fi
          printf '%s\n' "$((count + 1))" >"$FAKE_SSH_DELAY_FILE"
          ((count >= 2)) || exit 1
        fi
        [[ "${FAKE_SSH:-1}" == 1 ]]
        ;;
      'sw_vers -productVersion') printf '%s\n' "${FAKE_GUEST_VERSION:-26.6.2}" ;;
      *kern.hv_vmm_present*)
        if [[ "$command" == *pfctl* && "${FAKE_SMOKE:-1}" == 0 ]]; then echo 'simulated smoke failure' >&2; exit 88; fi
        [[ "${FAKE_HV:-1}" == 1 ]] || exit 1
        if [[ "$command" == *wgex-lab-host* ]]; then [[ "${FAKE_MARKER:-1}" == 1 ]] || exit 1; fi
        ;;
      *shutdown*) printf 'stopped\n' >"$FAKE_STATE" ;;
      *ax-dump.applescript* | *ax-action.applescript*)
        [[ "${FAKE_AX_FAIL:-0}" == 0 ]] || exit 1
        if [[ -n "${FAKE_AX_PATH:-}" ]]; then printf '%s\n' "$FAKE_AX_PATH"; fi
        ;;
    esac
    ;;
  sysctl) printf '0\n' ;;
  ssh-keyscan) [[ "${FAKE_KEYSCAN:-1}" == 1 ]] && printf '%s ssh-ed25519 %s\n' "${!#}" "${FAKE_HOSTKEY:-AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTheLabTrustTestOnly0000000000000}" ;;
  codesign) [[ "${FAKE_SIGNED:-1}" == 1 ]] ;;
  shasum) [[ "${FAKE_RECEIPT:-1}" == 1 ]] ;;
  scp | ditto) : ;;
  *) printf 'unexpected fake %s\n' "$name" >&2; exit 1 ;;
esac
FAKE
chmod +x "$work/bin/fake"
for tool in vm-tart ssh ssh-keyscan scp sw_vers codesign shasum ditto sysctl; do ln -s fake "$work/bin/$tool"; done
export WGEX_LAB_TEST_BIN="$work/bin" FAKE_LOG="$work/argv.log" FAKE_STATE="$work/state"
export PATH="$work/bin:$PATH"
pass=0
fail=0
ok() {
  printf 'ok %02d - %s\n' "$((pass + fail + 1))" "$1"
  pass=$((pass + 1))
}
bad() {
  printf 'FAIL - %s\n' "$1"
  fail=$((fail + 1))
}
run_ok() {
  local title="$1"
  shift
  : >"$FAKE_LOG"
  if "$@" >"$work/output" 2>&1; then ok "$title"; else
    bad "$title"
    cat "$work/output"
  fi
}
run_refuse() {
  local title="$1" reason="$2"
  shift 2
  : >"$FAKE_LOG"
  if "$@" >"$work/output" 2>&1; then bad "$title"; elif rg -q -- "$reason" "$work/output"; then ok "$title"; else
    bad "$title (wrong reason)"
    cat "$work/output"
  fi
}
contains() { if rg -Fq -- "$2" "$FAKE_LOG"; then ok "$1"; else
  bad "$1"
  cat "$FAKE_LOG"
fi; }
absent() { if rg -q -- "$2" "$FAKE_LOG"; then bad "$1"; else ok "$1"; fi; }
output_has() { if rg -q -- "$2" "$work/output"; then ok "$1"; else
  bad "$1"
  cat "$work/output"
fi; }
output_lacks() { if rg -q -- "$2" "$work/output"; then bad "$1"; else ok "$1"; fi; }
lifecycle_sequence() {
  local actual
  actual="$(rg '^vm-tart (create|set|delete|clone|run) ' "$FAKE_LOG" || true)"
  if [[ "$actual" == "$2" ]]; then ok "$1"; else
    bad "$1"
    printf '%s\n' "$actual"
  fi
}
# Invalid build arguments must fail locally, before any VM or build command.
run_refuse 'live build dispatch handles empty dry array without VM access' 'usage: build.sh' env -u WGEX_LAB_TEST_BIN bash "$base/lab.sh" build unexpected
run_refuse 'missing lab wrapper' 'lab wrapper missing' env WGEX_LAB_TEST_BIN="$work/missing" bash "$base/create.sh" --dry-run
run_refuse 'test seam refuses live mode' 'test tools require' bash "$base/create.sh"
run_refuse 'host 25 rejected' 'host must run macOS 26.x or 27.x' env FAKE_HOST_VERSION=25.6 bash "$base/create.sh" --dry-run --yes-download
absent 'host refusal precedes create' 'vm-tart create'
run_ok 'host 26 accepted' env FAKE_HOST_VERSION=26.6.2 bash "$base/create.sh" --dry-run
run_ok 'create without approval only plans' bash "$base/create.sh" --dry-run
absent 'no implicit download or VM mutation' 'vm-tart (create|set|run)'
run_ok 'approved creation argv' bash "$base/create.sh" --dry-run --yes-download
lifecycle_sequence 'create then resource settings in order' $'vm-tart create --from-ipsw=latest macos26-wgex\nvm-tart set macos26-wgex --cpu 4 --memory 8192 --disk-size 64'
contains 'latest IPSW creation' 'vm-tart create --from-ipsw=latest macos26-wgex'
contains 'CPU RAM disk argv' 'vm-tart set macos26-wgex --cpu 4 --memory 8192 --disk-size 64'
run_ok 'local IPSW argv' bash "$base/create.sh" --dry-run --yes-download --ipsw "$work/local.ipsw"
contains 'local IPSW selected' "--from-ipsw=$work/local.ipsw"
run_refuse 'invalid VM cannot target other lab guests' 'VM must be' env WGEX_LAB_VM=macos26-agent bash "$base/provision.sh" --dry-run
run_refuse 'guest 25 rejected before provisioning' 'guest must run macOS 26.x or 27.x' env FAKE_GUEST_VERSION=25.6 bash "$base/provision.sh" --dry-run
absent 'guest version refusal precedes mutation' 'scp|mkdir|sudo.*shutdown'
run_ok 'Tahoe guest accepted before provisioning' env FAKE_GUEST_VERSION=26.6.2 bash "$base/provision.sh" --dry-run
run_ok '27 guest accepted with note' env FAKE_GUEST_VERSION=27.0.1 bash "$base/provision.sh" --dry-run
if rg -q 'macOS 27 guest accepted' "$work/output"; then ok '27 note emitted'; else bad '27 note missing'; fi
run_refuse 'no answering SSH probe' 'no guest address' env FAKE_SSH=0 bash "$base/provision.sh" --dry-run
run_ok 'delayed Tart address and SSH publication recover offline' env FAKE_IP_DELAY_FILE="$work/ip-attempts" FAKE_SSH_DELAY_FILE="$work/ssh-attempts" bash "$base/provision.sh" --dry-run
if [[ "$(cat "$work/ip-attempts")" -ge 4 && "$(cat "$work/ssh-attempts")" -ge 3 ]]; then ok 'both discovery and SSH are retried'; else bad 'discovery retry missing'; fi
run_ok 'DHCP fallback after ARP failure' env FAKE_ARP=0 bash "$base/provision.sh" --dry-run
contains 'ARP resolver first' 'vm-tart ip --resolver arp macos26-wgex'
contains 'DHCP resolver fallback' 'vm-tart ip --resolver dhcp macos26-wgex'
contains 'SSH bypasses config and agent' 'ssh -F /dev/null -o IdentityAgent=none -i'
contains 'SSH pins the lab host key file' '-o UserKnownHostsFile='
contains 'SSH key authentication only' '-o IdentitiesOnly=yes -o BatchMode=yes'
contains 'provisioning report fetched' 'provisioning-report.txt'
run_refuse 'missing marker blocks tests' 'marker check failed' env FAKE_MARKER=0 bash "$base/run-tests.sh" --dry-run smoke
absent 'no reset after guard refusal' 'vm-tart (delete|clone|run)'
run_refuse 'hypervisor absent blocks tests' 'marker check failed' env FAKE_HV=0 bash "$base/run-tests.sh" --dry-run smoke
run_refuse 'unsigned bundle refused' 'bundle must be signed' env FAKE_SIGNED=0 bash "$base/install-app.sh" --dry-run "$work/WGEX.app"
absent 'unsigned app never copied' 'scp'
run_refuse 'mismatched Lab receipt refused' 'receipt does not match' env FAKE_RECEIPT=0 bash "$base/install-app.sh" --dry-run "$work/WGEX.app"
absent 'receipt refusal precedes SSH' 'ssh|scp'
run_ok 'signed Lab bundle install' bash "$base/install-app.sh" --dry-run "$work/WGEX.app"
contains 'bundle archive copied over scp' 'scp -F /dev/null'
contains 'guest ditto preserves signed bundle' 'ditto'
run_ok 'clean snapshot' bash "$base/snapshot.sh" --dry-run clean
lifecycle_sequence 'snapshot clones then restarts in order' $'vm-tart clone macos26-wgex macos26-wgex-clean\nvm-tart run --vnc-experimental --no-graphics macos26-wgex'
contains 'snapshot uses local clone' 'vm-tart clone macos26-wgex macos26-wgex-clean'
contains 'snapshot restarts working guest headless with the VNC console' 'vm-tart run --vnc-experimental --no-graphics macos26-wgex'
run_ok 'ready snapshot dry run' bash "$base/snapshot.sh" --dry-run ready9
if rg -q 'ready snapshot only after onboarding has completed \(7 x Continue, then Open WGEX\)' "$work/output"; then ok 'ready snapshot names the onboarding prerequisite'; else bad 'ready snapshot names the onboarding prerequisite'; fi
run_ok 'restore approved' bash "$base/snapshot.sh" --dry-run restore approved
lifecycle_sequence 'restore delete clone restart in order' $'vm-tart delete macos26-wgex\nvm-tart clone macos26-wgex-approved macos26-wgex\nvm-tart run --vnc-experimental --no-graphics macos26-wgex'
contains 'restore deletes working guest only' 'vm-tart delete macos26-wgex'
contains 'restore clones approved locally' 'vm-tart clone macos26-wgex-approved macos26-wgex'
# Headless with Tart's VNC console by default (DEC-112): never a host window, never the host's Screen Sharing app.
output_has 'restore without a VNC file starts headless, VNC output discarded' 'dry-run: env CI=1 \S*vm-tart run --vnc-experimental --no-graphics macos26-wgex .>/dev/null$'
absent 'restore never opens a Tart window' '(^| )--graphics( |$)|^vm-tart run macos26-wgex$'
# Self-driven console (M03-T07 phase B, DEC-034): the VNC address and one-time password to a private file on request.
run_ok 'restore with a VNC file starts the VNC server' env WGEX_LAB_VNC_FILE="$work/vnc.txt" bash "$base/snapshot.sh" --dry-run restore approved
output_has 'VNC start is headless and prints instead of opening Screen Sharing' "dry-run: env CI=1 \\S*vm-tart run --vnc-experimental --no-graphics macos26-wgex .>$work/vnc.txt"
absent 'VNC start never opens a Tart window' '(^| )--graphics( |$)|^vm-tart run macos26-wgex$'
run_refuse 'relative VNC file refused' 'must be an absolute path' env WGEX_LAB_VNC_FILE=vnc.txt bash "$base/snapshot.sh" --dry-run restore approved
absent 'relative VNC file starts nothing' 'vm-tart run'
run_refuse 'missing reset source preserves working VM' 'snapshot missing or running' env FAKE_SNAPSHOT=0 bash "$base/snapshot.sh" --dry-run restore approved
absent 'no delete without reset source' 'vm-tart delete'
run_refuse 'running snapshot refused before delete' 'snapshot missing or running' env FAKE_RUNNING_SNAPSHOT=1 bash "$base/snapshot.sh" --dry-run restore approved
absent 'running snapshot preserves working VM' 'vm-tart delete'
run_refuse 'snapshot traversal refused' 'invalid snapshot name' bash "$base/snapshot.sh" --dry-run ../foreign
run_ok 'snapshot list' bash "$base/snapshot.sh" --dry-run list
run_ok 'smoke with automatic approved reset' bash "$base/run-tests.sh" --dry-run smoke
contains 'smoke reads pf only' 'pfctl\ -s\ info'
contains 'smoke resets approved snapshot' 'vm-tart clone macos26-wgex-approved macos26-wgex'
run_refuse 'suite error propagates after reset' 'simulated smoke failure' env FAKE_SMOKE=0 bash "$base/run-tests.sh" --dry-run smoke
contains 'failed suite still restores approved' 'vm-tart clone macos26-wgex-approved macos26-wgex'
run_ok 'keep suppresses reset' bash "$base/run-tests.sh" --dry-run smoke --keep
absent 'keep has no lifecycle mutations' 'vm-tart (delete|clone|run)'
run_refuse 'unknown suites refused' 'unknown suite' bash "$base/run-tests.sh" --dry-run invented
run_refuse 'reset needs explicit consent' 'explicit reset-btm' bash "$base/lab.sh" --dry-run reset-btm
run_ok 'explicit remote reset wrapper' bash "$base/lab.sh" --dry-run reset-btm --yes-reset
contains 'reset is invoked over SSH' 'reset-btm.sh'
run_refuse 'pcaps cannot land in repository' 'outside.*repository' env CLEAN_DEV_BUILDS="$base" bash "$base/fetch-pcaps.sh" --dry-run
# Safe output for this test is a simulated external path; no directory is made.
run_ok 'pcap fetch is guest scp only' env CLEAN_DEV_BUILDS=/tmp bash "$base/fetch-pcaps.sh" --dry-run
contains 'pcap fetch uses scp' 'scp -F /dev/null'
contains 'capture stops inside guest before fetch' 'capture/stop-capture.sh'
run_ok 'pcap override uses checkout-scoped manual captures' env WGEX_BUILD_ROOT="$work/builds" bash "$base/fetch-pcaps.sh" --dry-run
tree="$(basename "$(cd "$base/../../.." && pwd)")"
contains 'manual captures use the canonical build root' "$work/builds/$tree/lab-captures/manual"
# M03-T11: the macOS 27 guest is the same scripts with parameters; the macOS 26 defaults above are unchanged.
g27=(env WGEX_LAB_VM=macos27-wgex WGEX_LAB_USER=admin FAKE_GUEST_VERSION=27.2)
run_ok 'macOS 27 guest provisioning dry run' "${g27[@]}" bash "$base/provision.sh" --dry-run
contains 'macOS 27 VM resolves its own address' 'vm-tart ip --resolver arp macos27-wgex'
contains 'macOS 27 SSH uses the guest user' 'admin@192.0.2.1'
contains 'provisioning checks the parameter user' '=\ admin\;\ sudo\ -n\ true'
contains 'guest provisioning is told the user' "\\'/Users/admin/lab/provision-stage\\'\\ \\'admin\\'"
output_lacks 'a macos27 VM running 27 needs no macOS 26 note' 'macOS 26 acceptance remains required'
run_ok 'default provisioning keeps the labuser user' bash "$base/provision.sh" --dry-run
contains 'default SSH user unchanged' 'labuser@192.0.2.1'
contains 'default provisioning user check unchanged' '=\ labuser\;\ sudo\ -n\ true'
run_refuse 'macos27 VM refuses a macOS 26 guest' 'macos27-wgex must run macOS 27.x' env WGEX_LAB_VM=macos27-wgex WGEX_LAB_USER=admin FAKE_GUEST_VERSION=26.6.2 bash "$base/provision.sh" --dry-run
absent 'OS family refusal precedes mutation' 'scp|mkdir|sudo.*shutdown'
run_refuse 'guest user with shell syntax refused' 'guest user must be a short account name' env WGEX_LAB_USER="admin';x" bash "$base/provision.sh" --dry-run
absent 'refused guest user never reaches the guest' 'vm-tart|ssh|scp'
run_refuse 'empty-looking guest user refused' 'guest user must be a short account name' env WGEX_LAB_USER=Admin bash "$base/provision.sh" --dry-run
run_refuse 'other VM families still refused' 'VM must be' env WGEX_LAB_VM=macos27-agent bash "$base/provision.sh" --dry-run
run_ok 'macOS 27 restore from macos27-base' "${g27[@]}" WGEX_LAB_SNAPSHOT_PREFIX=macos27- bash "$base/snapshot.sh" --dry-run restore base
lifecycle_sequence 'macOS 27 restore deletes, clones macos27-base, restarts' $'vm-tart delete macos27-wgex\nvm-tart clone macos27-base macos27-wgex\nvm-tart run --vnc-experimental --no-graphics macos27-wgex'
run_ok 'macOS 27 snapshot names macos27-base' "${g27[@]}" WGEX_LAB_SNAPSHOT_PREFIX=macos27- bash "$base/snapshot.sh" --dry-run base
lifecycle_sequence 'macOS 27 snapshot clones then restarts' $'vm-tart clone macos27-wgex macos27-base\nvm-tart run --vnc-experimental --no-graphics macos27-wgex'
run_ok 'default snapshot prefix is the VM name' "${g27[@]}" bash "$base/snapshot.sh" --dry-run clean
contains 'macos27-wgex default prefix' 'vm-tart clone macos27-wgex macos27-wgex-clean'
run_refuse 'restore never names the working VM' 'snapshot name is the working VM' "${g27[@]}" WGEX_LAB_SNAPSHOT_PREFIX=macos27- bash "$base/snapshot.sh" --dry-run restore wgex
absent 'working-VM restore deletes nothing' 'vm-tart (delete|clone|run)'
run_refuse 'snapshot never names the working VM' 'snapshot name is the working VM' "${g27[@]}" WGEX_LAB_SNAPSHOT_PREFIX=macos27- bash "$base/snapshot.sh" --dry-run wgex
absent 'working-VM snapshot clones nothing' 'vm-tart (delete|clone|run)'
run_refuse 'snapshot prefix of another family refused' 'snapshot prefix must start macos27-' "${g27[@]}" WGEX_LAB_SNAPSHOT_PREFIX=macos26-wgex- bash "$base/snapshot.sh" --dry-run restore approved
absent 'foreign prefix deletes nothing' 'vm-tart (delete|clone|run)'
run_refuse 'snapshot prefix must end with a dash' 'snapshot prefix must start macos27-' "${g27[@]}" WGEX_LAB_SNAPSHOT_PREFIX=macos27-base bash "$base/snapshot.sh" --dry-run restore x
run_ok 'macOS 27 snapshot list' "${g27[@]}" WGEX_LAB_SNAPSHOT_PREFIX=macos27- bash "$base/snapshot.sh" --dry-run list
output_has 'macOS 27 list shows macos27-base' 'macos27-base'
output_lacks 'macOS 27 list hides the working VM' 'macos27-wgex stopped'
run_ok 'default snapshot list' bash "$base/snapshot.sh" --dry-run list
output_lacks 'default list shows no macOS 27 clones' 'macos27'
# lab trust replaces only the trusted guest family's line and keeps the other guest's (M03-T11 phase B).
k26=AAAAC3NzaC1lZDI1NTE5AAAAIMacOS26LabGuestHostKeyForTrustTest000000000
k27=AAAAC3NzaC1lZDI1NTE5AAAAIMacOS27LabGuestHostKeyForTrustTest000000000
k27b=AAAAC3NzaC1lZDI1NTE5AAAAIMacOS27LabGuestRekeyedHostKeyForTrustTest00
kh="$work/known_hosts"
trust_lines() { if [[ "$(<"$kh")" == "$2" ]]; then ok "$1"; else
  bad "$1"
  cat "$kh"
fi; }
printf '192.0.2.* ssh-ed25519 %s\n192.0.2.* ssh-ed25519 %s\n' "$k26" "$k27" >"$kh"
run_ok 'trust macOS 27 over the untagged pair' "${g27[@]}" WGEX_LAB_KNOWN_HOSTS="$kh" FAKE_HOSTKEY="$k27" bash "$base/lab.sh" --dry-run trust
trust_lines 'trust keeps the macOS 26 line and tags the macOS 27 line' "192.0.2.* ssh-ed25519 $k26"$'\n'"192.0.2.* ssh-ed25519 $k27 wgex-lab-guest=macos27"
output_has 'trust reports the kept line' 'for macos27 .* \(kept 1 other line'
run_ok 'trust macOS 26 tags its own line' env WGEX_LAB_KNOWN_HOSTS="$kh" FAKE_HOSTKEY="$k26" bash "$base/lab.sh" --dry-run trust
trust_lines 'trust macOS 26 keeps the macOS 27 line' "192.0.2.* ssh-ed25519 $k27 wgex-lab-guest=macos27"$'\n'"192.0.2.* ssh-ed25519 $k26 wgex-lab-guest=macos26"
run_ok 'trust a re-keyed macOS 27 guest' "${g27[@]}" WGEX_LAB_KNOWN_HOSTS="$kh" FAKE_HOSTKEY="$k27b" bash "$base/lab.sh" --dry-run trust
trust_lines 'a re-key replaces only the tagged macOS 27 line' "192.0.2.* ssh-ed25519 $k26 wgex-lab-guest=macos26"$'\n'"192.0.2.* ssh-ed25519 $k27b wgex-lab-guest=macos27"
run_ok 'trust is idempotent' "${g27[@]}" WGEX_LAB_KNOWN_HOSTS="$kh" FAKE_HOSTKEY="$k27b" bash "$base/lab.sh" --dry-run trust
trust_lines 'repeat trust leaves one line per guest' "192.0.2.* ssh-ed25519 $k26 wgex-lab-guest=macos26"$'\n'"192.0.2.* ssh-ed25519 $k27b wgex-lab-guest=macos27"
if [[ "$(stat -f %Lp "$kh")" == 644 ]]; then ok 'trusted file stays 0644'; else bad 'trusted file mode changed'; fi
cp "$kh" "$work/known_hosts.before"
run_refuse 'no host key leaves the file untouched' 'no ed25519 host key' "${g27[@]}" WGEX_LAB_KNOWN_HOSTS="$kh" FAKE_KEYSCAN=0 bash "$base/lab.sh" --dry-run trust
if cmp -s "$kh" "$work/known_hosts.before"; then ok 'refused trust keeps both lines'; else bad 'refused trust changed the file'; fi
rm -f "$kh"
run_ok 'trust creates a missing file' "${g27[@]}" WGEX_LAB_KNOWN_HOSTS="$kh" FAKE_HOSTKEY="$k27" bash "$base/lab.sh" --dry-run trust
trust_lines 'a new file holds the one tagged line' "192.0.2.* ssh-ed25519 $k27 wgex-lab-guest=macos27"
# Guest scripts read the lab user from the marker (guard.sh guest_lab_user); {} keeps labuser.
mkdir -p "$work/marker-bin"
# The marker's bytes: none with FAKE_MARKER_EMPTY=1, else FAKE_MARKER_CONTENT, else {"user":FAKE_MARKER_USER}, else {}
# (the macOS 26 marker).
cat >"$work/marker-content" <<'CONTENT'
if [[ "${FAKE_MARKER_EMPTY:-0}" == 1 ]]; then :
elif [[ -n "${FAKE_MARKER_CONTENT:-}" ]]; then printf '%s\n' "$FAKE_MARKER_CONTENT"
elif [[ -n "${FAKE_MARKER_USER:-}" ]]; then printf '{"user":"%s"}\n' "$FAKE_MARKER_USER"
else printf '{}\n'; fi
CONTENT
# cat reads the marker as the caller: refused when the mode (FAKE_MARKER_STAT) gives others no read or
# FAKE_MARKER_UNREADABLE=1; every other path is the real cat.
cat >"$work/marker-bin/cat" <<CAT
#!/usr/bin/env bash
[[ "\$*" == '-- /var/db/wgex-lab-host' ]] || exec /bin/cat "\$@"
mode="\${FAKE_MARKER_STAT:-Regular File:0:644}"
mode="\${mode##*:}"
if [[ "\${FAKE_MARKER_UNREADABLE:-0}" == 1 ]] || ! ((8#\$mode & 8#004)); then echo 'cat: Permission denied' >&2; exit 1; fi
bash '$work/marker-content'
CAT
# The real plutil parses the marker; FAKE_PLUTIL_FAIL=type|extract injects a failure into that step.
cat >"$work/marker-bin/plutil" <<'PLUTIL'
#!/usr/bin/env bash
if [[ "${FAKE_PLUTIL_FAIL:-}" == type && "$1" == -type ]]; then echo '<stdin>: simulated type failure' >&2; exit 1; fi
if [[ "${FAKE_PLUTIL_FAIL:-}" == extract && "$1" == -extract ]]; then echo '<stdin>: simulated extract failure' >&2; exit 1; fi
exec /usr/bin/plutil "$@"
PLUTIL
cat >"$work/marker-bin/id" <<'ID'
#!/usr/bin/env bash
[[ "$1" == -u && "$2" != "${FAKE_NO_ACCOUNT:-}" ]] && printf '501\n'
ID
# lstat of the marker: type, owner and mode (FAKE_MARKER_STAT overrides the valid root-owned 0644 regular file). The
# console owner is FAKE_CONSOLE_OWNER (default admin).
cat >"$work/marker-bin/stat" <<'STAT'
#!/usr/bin/env bash
if [[ "$*" == '-f %Su /dev/console' ]]; then printf '%s\n' "${FAKE_CONSOLE_OWNER:-admin}"; exit; fi
[[ "$*" == '-f %HT:%u:%Lp /var/db/wgex-lab-host' && "${FAKE_MARKER_STAT-x}" != '' ]] || exit 1
printf '%s\n' "${FAKE_MARKER_STAT:-Regular File:0:644}"
STAT
# The guest VM check: FAKE_HV is the hypervisor sysctl (default 1), FAKE_GUEST_VERSION the guest OS (default 27.0.1).
cat >"$work/marker-bin/sysctl" <<'SYSCTL'
#!/usr/bin/env bash
printf '%s\n' "${FAKE_HV:-1}"
SYSCTL
cat >"$work/marker-bin/sw_vers" <<'SWVERS'
#!/usr/bin/env bash
printf '%s\n' "${FAKE_GUEST_VERSION:-27.0.1}"
SWVERS
cat >"$work/marker-bin/csrutil" <<'CSRUTIL'
#!/usr/bin/env bash
printf 'System Integrity Protection status: disabled.\n'
CSRUTIL
# sudo logs and never runs its payload; the one exception is the privileged marker read, logged as marker-read so
# '^sudo' still means a mutation, which serves the marker unless FAKE_SUDO_READ_FAIL=1.
cat >"$work/marker-bin/sudo" <<SUDO
#!/usr/bin/env bash
if [[ "\$*" == '-n cat -- /var/db/wgex-lab-host' ]]; then
  printf 'marker-read sudo %s\\n' "\$*" >>"\$FAKE_LOG"
  [[ "\${FAKE_SUDO_READ_FAIL:-0}" == 0 ]] || exit 1
  bash '$work/marker-content'
  exit
fi
printf 'sudo' >>"\$FAKE_LOG"
printf ' %s' "\$@" >>"\$FAKE_LOG"
printf '\\n' >>"\$FAKE_LOG"
SUDO
chmod +x "$work/marker-bin/plutil" "$work/marker-bin/cat" "$work/marker-bin/id" "$work/marker-bin/sudo" "$work/marker-bin/stat" "$work/marker-bin/sysctl" "$work/marker-bin/sw_vers" "$work/marker-bin/csrutil"
# shellcheck disable=SC2016 # script argument expanded by child bash
run_ok 'marker user names the lab user' env PATH="$work/marker-bin:$PATH" FAKE_MARKER_USER=admin bash "$base/tests/guard-call.sh" 'test "$(guest_lab_user)" = admin'
# shellcheck disable=SC2016 # script argument expanded by child bash
run_ok 'a marker without a user keeps labuser' env PATH="$work/marker-bin:$PATH" bash "$base/tests/guard-call.sh" 'test "$(guest_lab_user)" = labuser'
# shellcheck disable=SC2016 # script argument expanded by child bash
run_refuse 'a marker user that is no account name is refused' 'marker user is not an account name' env PATH="$work/marker-bin:$PATH" FAKE_MARKER_USER='a b' bash "$base/tests/guard-call.sh" 'guest_lab_user'
run_ok 'console helper follows the marker user' env PATH="$work/marker-bin:$PATH" FAKE_MARKER_USER=admin bash "$base/guest/asu.sh" true
contains 'console helper runs as the marker user' 'sudo -n launchctl asuser 501 sudo -n -u admin true'
run_ok 'console helper default stays labuser' env PATH="$work/marker-bin:$PATH" bash "$base/guest/asu.sh" true
contains 'console helper default user' 'sudo -n launchctl asuser 501 sudo -n -u labuser true'
run_ok 'explicit console user wins over the marker' env PATH="$work/marker-bin:$PATH" FAKE_MARKER_USER=admin WGEX_LAB_CONSOLE_USER=other bash "$base/guest/asu.sh" true
contains 'explicit console user' 'sudo -n -u other true'
# The marker is trusted only as a root-owned regular file, mode 0644 or stricter, naming an existing account (review A2).
mb=(env PATH="$work/marker-bin:$PATH")
run_ok 'a 0600 root marker is accepted' "${mb[@]}" FAKE_MARKER_USER=admin FAKE_MARKER_STAT='Regular File:0:600' bash "$base/guest/asu.sh" true
contains 'a 0600 marker is read with sudo' 'marker-read sudo -n cat -- /var/db/wgex-lab-host'
contains 'stricter marker keeps the marker user' 'sudo -n launchctl asuser 501 sudo -n -u admin true'
run_ok 'a readable marker needs no sudo read' "${mb[@]}" FAKE_MARKER_USER=admin bash "$base/guest/asu.sh" true
absent 'a readable marker is read as the caller' '^marker-read'
run_ok 'a dictionary without a user keeps labuser' "${mb[@]}" FAKE_MARKER_CONTENT='{"other":"x"}' bash "$base/guest/asu.sh" true
contains 'a marker without a user key runs as labuser' 'sudo -n -u labuser true'
# Review A3: a marker read, parse or extraction error refuses; it never falls back to labuser. Settings are ;-separated.
for case in 'marker unreadable even with sudo|FAKE_MARKER_STAT=Regular File:0:600;FAKE_SUDO_READ_FAIL=1|lab marker unreadable' \
  'readable-mode marker that cannot be read|FAKE_MARKER_UNREADABLE=1;FAKE_SUDO_READ_FAIL=1|lab marker unreadable' \
  'marker that does not parse|FAKE_MARKER_CONTENT={"user":|lab marker does not parse' \
  'marker that is no plist|FAKE_MARKER_CONTENT=garbage|lab marker does not parse' \
  'zero-byte marker|FAKE_MARKER_EMPTY=1|lab marker is empty' \
  'whitespace-only marker|FAKE_MARKER_CONTENT=   |lab marker is empty' \
  'tab-only marker|FAKE_MARKER_CONTENT='$'\t \t''|lab marker is empty' \
  'marker that is no dictionary|FAKE_MARKER_CONTENT=["admin"]|lab marker is not a dictionary' \
  'marker user that is no string|FAKE_MARKER_CONTENT={"user":["admin"]}|lab marker user is not a string' \
  'marker user type failure|FAKE_PLUTIL_FAIL=type|lab marker user cannot be read' \
  'marker user extraction failure|FAKE_PLUTIL_FAIL=extract|lab marker user cannot be extracted'; do
  IFS='|' read -r label settings reason <<<"$case"
  IFS=';' read -r -a vars <<<"$settings"
  run_refuse "console helper refuses a $label" "$reason" "${mb[@]}" FAKE_MARKER_USER=admin "${vars[@]}" bash "$base/guest/asu.sh" true
  absent "console helper runs nothing on a $label" '^sudo'
  run_refuse "TCC seeding refuses a $label" "$reason" "${mb[@]}" FAKE_MARKER_USER=admin "${vars[@]}" bash "$base/guest/seed-tcc.sh" /bin/sh
  absent "TCC seeding mutates nothing on a $label" '^sudo'
  # shellcheck disable=SC2016 # script argument expanded by child bash
  run_refuse "guest_lab_user refuses a $label" "$reason" "${mb[@]}" FAKE_MARKER_USER=admin "${vars[@]}" bash "$base/tests/guard-call.sh" 'guest_lab_user'
done
for case in 'symlink|Symbolic Link:0:644|not a regular file' 'wrong owner|Regular File:501:644|not owned by root' \
  'group-writable mode|Regular File:0:664|0644 or stricter' 'other-writable mode|Regular File:0:646|0644 or stricter' \
  'executable mode|Regular File:0:755|0644 or stricter' 'missing marker||lab marker missing'; do
  IFS='|' read -r label marker_stat reason <<<"$case"
  run_refuse "console helper refuses a $label" "$reason" "${mb[@]}" FAKE_MARKER_USER=admin FAKE_MARKER_STAT="$marker_stat" bash "$base/guest/asu.sh" true
  absent "console helper runs nothing on a $label" '^sudo'
  run_refuse "TCC seeding refuses a $label" "$reason" "${mb[@]}" FAKE_MARKER_USER=admin FAKE_MARKER_STAT="$marker_stat" bash "$base/guest/seed-tcc.sh" /bin/sh
  absent "TCC seeding mutates nothing on a $label" '^sudo'
done
for case in 'bad name|a b|not an account name' 'upper-case name|Admin|not an account name' \
  'path name|../root|not an account name' 'unknown account|ghost|has no account'; do
  IFS='|' read -r label marker_user reason <<<"$case"
  run_refuse "console helper refuses a $label" "$reason" "${mb[@]}" FAKE_MARKER_USER="$marker_user" FAKE_NO_ACCOUNT=ghost bash "$base/guest/asu.sh" true
  absent "console helper runs nothing for a $label" '^sudo'
  run_refuse "TCC seeding refuses a $label" "$reason" "${mb[@]}" FAKE_MARKER_USER="$marker_user" FAKE_NO_ACCOUNT=ghost bash "$base/guest/seed-tcc.sh" /bin/sh
  absent "TCC seeding mutates nothing for a $label" '^sudo'
done
run_refuse 'an explicit console user is validated too' 'not an account name' "${mb[@]}" WGEX_LAB_CONSOLE_USER='x;y' bash "$base/guest/asu.sh" true
run_ok 'TCC seeding with the default marker' "${mb[@]}" bash "$base/guest/seed-tcc.sh" /bin/sh
contains 'TCC seeding restarts the labuser tccd' 'sudo -n launchctl kickstart -k gui/501/com.apple.tccd'
run_ok 'TCC seeding with the configured marker user' "${mb[@]}" FAKE_MARKER_USER=admin FAKE_NO_ACCOUNT=labuser bash "$base/guest/seed-tcc.sh" /bin/sh
contains 'TCC seeding restarts the admin tccd' 'sudo -n launchctl kickstart -k gui/501/com.apple.tccd'
# Review A4: the console helper runs the guest VM check before launchctl or any other command.
for case in 'host without the hypervisor|FAKE_HV=0' 'macOS 25 guest|FAKE_GUEST_VERSION=25.6'; do
  IFS='|' read -r label setting <<<"$case"
  run_refuse "console helper refuses a $label" 'macOS 26 or 27 VM required' "${mb[@]}" FAKE_MARKER_USER=admin "$setting" bash "$base/guest/asu.sh" true
  absent "console helper runs nothing on a $label" '^sudo|launchctl'
done
# Review A4 audit: every guest and capture script that can change state runs the guest VM check first, and the marker
# check before it uses the lab user. The capture scripts run beside guard.sh, as provisioning copies them.
stage="$work/guest-stage"
mkdir -p "$stage"
cp "$base"/guest/*.sh "$base"/guest/*.pl "$base"/capture/*.sh "$stage/"
for case in 'asu.sh|true' 'seed-tcc.sh|/bin/sh' 'gap-actions.sh|none' 'verdict-actions.sh|none' 'wrapping-key.sh|' \
  "pfctl-capture.sh|$work/pfctl-out" 'provision.sh|' 'start-capture.sh|en0 audit' 'stop-capture.sh|'; do
  IFS='|' read -r script args <<<"$case"
  read -r -a argv <<<"$args"
  for setting in FAKE_HV=0 FAKE_GUEST_VERSION=25.6; do
    run_refuse "$script refuses a failed guest VM check ($setting)" 'macOS 26 or 27 VM required' "${mb[@]}" "$setting" bash "$stage/$script" "${argv[@]}"
    absent "$script changes nothing on a failed guest VM check ($setting)" '^sudo'
  done
done
# guest_lab_user repeats the VM check, so the order is also pinned: guest_guard runs before the first sudo, launchctl,
# signal or lab-user read in each guarded script.
for script in asu.sh seed-tcc.sh gap-actions.sh verdict-actions.sh wrapping-key.sh pfctl-capture.sh start-capture.sh stop-capture.sh; do
  order="$(awk '/^guest_guard$/ && !g { g = NR } /sudo -n|launchctl|guest_lab_user( --console)?\)|kill |rm -/ && !/^ *#/ && !a { a = NR } END { print (g && g < a) ? "ok" : "bad" }' "$stage/$script")"
  if [[ "$order" == ok ]]; then ok "$script runs guest_guard before acting"; else bad "$script runs guest_guard before acting"; fi
done
if [[ -e "$work/pfctl-out" ]]; then bad 'pfctl capture made no output directory before its guard'; else ok 'pfctl capture made no output directory before its guard'; fi
for script in gap-actions.sh start-capture.sh stop-capture.sh; do
  case "$script" in gap-actions.sh) argv=(none) ;; start-capture.sh) argv=(en0 audit) ;; *) argv=() ;; esac
  run_refuse "$script refuses a whitespace-only marker before acting" 'lab marker is empty' "${mb[@]}" FAKE_MARKER_CONTENT='  ' bash "$stage/$script" "${argv[@]}"
  absent "$script changes nothing on a whitespace-only marker" '^sudo'
done
for script in "$base/guest/gap-actions.sh" "$base/../corpus/guest-corpus.sh" "$base/capture/start-capture.sh" "$base/capture/stop-capture.sh"; do
  if rg -q 'guest_lab_user' "$script" && ! rg -q 'user=labuser' "$script"; then ok "${script##*/} takes the marker user"; else bad "${script##*/} takes the marker user"; fi
done
# Review A5: WGEX_LAB_CONSOLE_USER applies only where a caller opts in with --console (asu.sh, seed-tcc.sh). Every other
# caller keeps the marker's user with the override set: an override naming no account would refuse there.
# shellcheck disable=SC2016 # script argument expanded by child bash
run_ok 'guest_lab_user ignores the console override by default' "${mb[@]}" FAKE_MARKER_USER=admin WGEX_LAB_CONSOLE_USER=other bash "$base/tests/guard-call.sh" 'test "$(guest_lab_user)" = admin'
# shellcheck disable=SC2016 # script argument expanded by child bash
run_ok 'guest_lab_user --console takes the console override' "${mb[@]}" FAKE_MARKER_USER=admin WGEX_LAB_CONSOLE_USER=other bash "$base/tests/guard-call.sh" 'test "$(guest_lab_user --console)" = other'
# shellcheck disable=SC2016 # script argument expanded by child bash
run_ok 'guest_lab_user --console keeps the marker user without an override' "${mb[@]}" FAKE_MARKER_USER=admin bash "$base/tests/guard-call.sh" 'test "$(guest_lab_user --console)" = admin'
# shellcheck disable=SC2016 # script argument expanded by child bash
run_refuse 'guest_lab_user refuses an unknown option' 'usage: guest_lab_user' "${mb[@]}" FAKE_MARKER_USER=admin bash "$base/tests/guard-call.sh" 'guest_lab_user --other'
cp "$base/../corpus/guest-corpus.sh" "$stage/"
ov=(FAKE_MARKER_USER=admin WGEX_LAB_CONSOLE_USER=ghost FAKE_NO_ACCOUNT=ghost)
run_ok 'gap fixtures ignore the console override' "${mb[@]}" "${ov[@]}" bash "$stage/gap-actions.sh" console-user
output_has 'gap fixtures match the console against the marker user' '^lab$'
run_ok 'gap fixtures ignore a valid console override' "${mb[@]}" FAKE_MARKER_USER=admin WGEX_LAB_CONSOLE_USER=other bash "$stage/gap-actions.sh" console-user
output_has 'gap fixtures keep the marker user over a valid override' '^lab$'
run_ok 'identity corpus ignores the console override' "${mb[@]}" "${ov[@]}" bash "$stage/guest-corpus.sh" cleanup
contains 'identity corpus acts for the marker user' 'sudo -n launchctl bootout gui/501/lab.wgex.corpus-impostor'
for case in 'start-capture.sh|en0 audit' 'stop-capture.sh|'; do
  IFS='|' read -r script args <<<"$case"
  read -r -a argv <<<"$args"
  run_ok "$script ignores the console override" "${mb[@]}" "${ov[@]}" bash "$stage/$script" "${argv[@]}"
  contains "$script re-executes as root with the marker user" "sudo -n bash $stage/$script"
done
for script in gap-actions.sh guest-corpus.sh start-capture.sh stop-capture.sh; do
  if rg -q 'guest_lab_user --console' "$stage/$script"; then bad "$script never opts in to the console override"; else ok "$script never opts in to the console override"; fi
done
for script in asu.sh seed-tcc.sh; do
  if rg -q 'guest_lab_user --console\)' "$stage/$script"; then ok "$script opts in to the console override"; else bad "$script opts in to the console override"; fi
done
run_ok 'dispatcher restores approved on up' bash "$base/lab.sh" --dry-run up
contains 'up restores approved' 'vm-tart clone macos26-wgex-approved macos26-wgex'
run_ok 'dispatcher snapshot forwards name' bash "$base/lab.sh" --dry-run snapshot clean
contains 'dispatcher clone name' 'vm-tart clone macos26-wgex macos26-wgex-clean'
# shellcheck disable=SC2016 # script argument expanded by child bash
run_refuse 'guest guard refuses absent hypervisor' 'macOS 26 or 27 VM required' bash -c 'source "$1"; guest_guard' _ "$base/guest/guard.sh"
run_refuse 'BTM guest script refuses absent hypervisor' 'reset requires macOS 26 or 27 guest' bash "$base/reset-btm.sh" --yes-reset
run_ok 'help works with no Tart wrapper or VM lookup' env WGEX_LAB_TEST_BIN="$work/missing" bash "$base/lab.sh" help
absent 'help never inspects VM' 'vm-tart|ssh|scp'
run_ok 'peer up dry recipe never contacts Lima' bash "$base/lab.sh" peer up --dry-run
absent 'peer dry has no VM commands' 'vm-tart|ssh|scp'
run_ok 'peer adoption dry recipe never contacts Lima' bash "$base/lab.sh" peer up --adopt --dry-run
absent 'peer adoption dry has no VM commands' 'vm-tart|ssh|scp'
run_ok 'dual peer topology dry recipe never contacts Lima' bash "$base/lab.sh" peer up --variant dual --dry-run
if rg -q 'variant=dual' "$work/output"; then ok 'peer variant is explicit'; else bad 'peer variant is explicit'; fi
run_refuse 'peer variant traversal refused before Lima' 'profile variant' bash "$base/lab.sh" peer up --variant ../private --dry-run
run_ok 'relay start dry recipe has no socket or PID mutation' bash "$base/lab.sh" relay start --dry-run
run_ok 'relay stop dry recipe has no signals' bash "$base/lab.sh" --dry-run relay stop
run_ok 'relay status dry recipe is offline' bash "$base/lab.sh" relay status --dry-run
run_ok 'default profile dry recipe never reads keys' bash "$base/lab.sh" profile default --dry-run
run_ok 'full4 profile dry recipe is offline' bash "$base/lab.sh" profile full4 --dry-run
run_ok 'dual profile dry recipe is offline' bash "$base/lab.sh" profile dual --dry-run
run_ok 'DNS profile dry recipe is offline' bash "$base/lab.sh" profile dns --dry-run
run_ok 'lockdown profile dry recipe is offline' bash "$base/lab.sh" profile lockdown --dry-run
run_refuse 'profile traversal rejected before SSH' 'profile variant' bash "$base/lab.sh" profile ../private --dry-run
run_ok 'verdict row replay bypasses all VM discovery' bash "$base/lab.sh" verdict M5.1-01 --dry-run --report-root "$work/reports"
absent 'verdict replay has no VM commands' 'vm-tart|ssh|scp'
run_ok 'verdict prefix dry syntax works' bash "$base/lab.sh" --dry-run verdict M5.1-01 --report-root "$work/reports"
run_ok 'snapshot build assertion is accepted offline' bash "$base/lab.sh" verdict M5.1-01 --no-install --dry-run --report-root "$work/reports"
run_ok 'GUI activate treats quote-bearing app names as argv' bash "$base/gui.sh" --dry-run activate 'WGEX"; do shell script "false'
contains 'activation uses a static AppleScript file' 'activate.applescript'
absent 'no interpolated tell application' 'tell.*application'
contains 'SSH connect and keepalive use the scaled harness bounds (M1-10i)' '-o ConnectTimeout=20 -o ServerAliveInterval=5 -o ServerAliveCountMax=12'
run_ok 'GUI activate with harness scale 2' env WGEX_LAB_HARNESS_SCALE=2 bash "$base/gui.sh" --dry-run activate WGEX
contains 'harness scale 2 halves the default bounds' '-o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=6'
run_refuse 'invalid harness scale refused before SSH' 'WGEX_LAB_HARNESS_SCALE must be an integer 1..8' env WGEX_LAB_HARNESS_SCALE=9 bash "$base/gui.sh" --dry-run activate WGEX
absent 'refused harness scale never reaches the guest' 'ssh|scp'
run_ok 'GUI keys pass identifier and count as argv to a static AppleScript' bash "$base/gui.sh" --dry-run keys WGEX 1 wgex.main.profiles up 4
contains 'arrow keys use a static AppleScript file' 'arrow-keys.applescript'
contains 'arrow keys carry identifier and count as data' 'wgex.main.profiles\ up\ 4'
absent 'arrow keys never interpolate AppleScript' 'tell.*application|key code'
run_refuse 'GUI keys refuse an unknown direction' 'direction must be up or down' bash "$base/gui.sh" --dry-run keys WGEX 1 wgex.main.profiles left 1
run_refuse 'GUI keys refuse an unbounded count' 'count must be 0..64' bash "$base/gui.sh" --dry-run keys WGEX 1 wgex.main.profiles down 65
run_refuse 'GUI keys refuse a non-wgex identifier' 'wgex accessibility identifier' bash "$base/gui.sh" --dry-run keys WGEX 1 'x"; do shell script "false' up 1
run_refuse 'GUI keys refuse an unknown sixth argument' 'sixth argument must be fallback' bash "$base/gui.sh" --dry-run keys WGEX 1 wgex.main.profiles up 1 'x"; do shell script "false'
absent 'refused keys never reach the guest' 'ssh|scp'
run_ok 'GUI keys accept the window fallback as data' bash "$base/gui.sh" --dry-run keys WGEX 1 wgex.main.profiles down 2 fallback
contains 'window fallback is passed to the static AppleScript' 'wgex.main.profiles\ down\ 2\ fallback'
absent 'window fallback never interpolates AppleScript' 'tell.*application|key code'
# M1-10j: element actions pass identifier, mode, fallback point, role and child label as argv to a static AppleScript.
run_ok 'GUI press passes identifier, fallback point and role as argv' bash "$base/gui.sh" --dry-run press WGEX 1 wgex.protection.lockdown press 327 542 AXCheckBox
contains 'element press uses a static AppleScript file' 'ax-action.applescript'
contains 'element press carries identifier, mode, point and role as data' 'wgex.protection.lockdown\ press\ 327\ 542\ AXCheckBox'
absent 'element press never interpolates AppleScript' 'tell.*application|perform action'
run_ok 'GUI press passes a child label as data' bash "$base/gui.sh" --dry-run press WGEX 2 wgex.main.startupOption press 420 250 - 'Connect at boot before login'
contains 'child label reaches the static AppleScript as one argument' 'press\ 420\ 250\ -\ Connect\\\ at'
run_ok 'GUI press-only passes no point (verify F1)' bash "$base/gui.sh" --dry-run press WGEX 1 wgex.protection.lockdown press-only AXCheckBox
contains 'press-only carries identifier, mode and role only' 'wgex.protection.lockdown\ press-only\ AXCheckBox'
run_ok 'GUI press-only passes a child label' bash "$base/gui.sh" --dry-run press WGEX 2 wgex.main.startupOption press-only AXRadioGroup 'Connect at boot before login'
contains 'press-only child label is one argument' 'press-only\ AXRadioGroup\ Connect\\\ at'
run_ok 'GUI scroll passes the identifier as data' bash "$base/gui.sh" --dry-run scroll WGEX 1 wgex.protection.lockdown
contains 'scroll uses the element helper in scroll mode' 'wgex.protection.lockdown\ scroll'
run_refuse 'GUI press refuses an unknown action' 'action must be press, confirm or press-only' bash "$base/gui.sh" --dry-run press WGEX 1 wgex.protection.lockdown click 1 2 AXButton
run_refuse 'GUI press refuses a non-wgex identifier' 'wgex accessibility identifier' bash "$base/gui.sh" --dry-run press WGEX 1 'x"; do shell script "false' press 1 2 -
run_refuse 'GUI press refuses non-integer coordinates' 'coordinates are integers' bash "$base/gui.sh" --dry-run press WGEX 1 wgex.protection.lockdown press 1 -2 -
run_refuse 'GUI press refuses a quote-bearing label' 'label must be' bash "$base/gui.sh" --dry-run press WGEX 1 wgex.protection.lockdown press 1 2 - 'x"; do shell script "false'
run_refuse 'GUI press refuses a quote-bearing role' 'role must be an AX role name' bash "$base/gui.sh" --dry-run press WGEX 1 wgex.protection.lockdown press 1 2 'AX"; do shell script "false'
run_refuse 'GUI press refuses the old form without a role' 'confirm X Y ROLE' bash "$base/gui.sh" --dry-run press WGEX 1 wgex.protection.lockdown press 1 2
run_refuse 'GUI press-only refuses a point' 'press-only takes' bash "$base/gui.sh" --dry-run press WGEX 1 wgex.protection.lockdown press-only AXCheckBox 1 2
run_refuse 'GUI press-only refuses a bad role' 'role must be an AX role name' bash "$base/gui.sh" --dry-run press WGEX 1 wgex.protection.lockdown press-only 327
run_refuse 'GUI scroll refuses a bad window index' 'window index must be 1..99' bash "$base/gui.sh" --dry-run scroll WGEX 0 wgex.protection.lockdown
absent 'refused element actions never reach the guest' 'ssh|scp'
# M1-10k fix pass 1 (F1): an osascript or SSH failure is a fixed marker line, never an empty dump or a silent press.
run_ok 'GUI dump of a readable window prints no failure marker' bash "$base/gui.sh" --dry-run dump WGEX 1
output_lacks 'readable dump carries no marker' 'ax-dump=failed'
run_ok 'GUI dump keeps exit 0 when osascript fails' env FAKE_AX_FAIL=1 bash "$base/gui.sh" --dry-run dump WGEX 2
output_has 'failed dump ends with the fixed marker line' '^ax-dump=failed exit=1$'
run_refuse 'GUI press reports an osascript failure and keeps its exit' '^ax-action=failed exit=1$' env FAKE_AX_FAIL=1 bash "$base/gui.sh" --dry-run press WGEX 1 wgex.protection.lockdown press-only AXCheckBox
# F3: frame=X,Y,WxH in the label slot reaches the helper as one argument; anything else in that form is refused.
run_ok 'GUI press-only passes a remembered frame' bash "$base/gui.sh" --dry-run press WGEX 1 wgex.protection.lockdown press-only AXCheckBox frame=286,834,82x16
contains 'press-only frame is one argument after the role' 'press-only\ AXCheckBox\ frame=286\\\,834\\\,82x16'
run_ok 'GUI press passes a negative-origin frame' bash "$base/gui.sh" --dry-run press WGEX 1 wgex.protection.lockdown press 327 842 AXCheckBox frame=286,-40,82x16
contains 'press frame follows the role' 'AXCheckBox\ frame=286\\\,-40\\\,82x16'
run_refuse 'GUI press refuses a malformed frame' 'frame must be frame=X,Y,WxH integers' bash "$base/gui.sh" --dry-run press WGEX 1 wgex.protection.lockdown press-only AXCheckBox 'frame=1,2,3'
run_refuse 'GUI press refuses a quote-bearing frame' 'frame must be frame=X,Y,WxH integers' bash "$base/gui.sh" --dry-run press WGEX 1 wgex.protection.lockdown press-only AXCheckBox 'frame=1,2,3x4"; do shell script "false'
absent 'refused frames never reach the guest' 'ssh|scp'
# M1-10m: identifier - presses a container's child by its title (a Settings toolbar tab); it needs a role and a label.
run_ok 'GUI press by title passes identifier -, the container role and the title' bash "$base/gui.sh" --dry-run press WGEX 2 - press 476 56 AXToolbar Service
contains 'title press reaches the static AppleScript as data' 'WGEX\ 2\ -\ press\ 476\ 56\ AXToolbar\ Service'
run_refuse 'GUI press refuses identifier - with role -' 'identifier - needs an AX role' bash "$base/gui.sh" --dry-run press WGEX 2 - press 1 2 - Service
run_refuse 'GUI press refuses identifier - without a label' 'identifier - needs a label or a frame' bash "$base/gui.sh" --dry-run press WGEX 2 - press-only AXToolbar
# M1-10r: identifier - with an exact frame presses the element of that role and frame (a startup radio button by position).
run_ok 'GUI press by role and frame passes identifier -, the role and the frame' bash "$base/gui.sh" --dry-run press WGEX 2 - press 686 752 AXRadioButton frame=659,744,195x16
run_ok 'GUI press-only by role and frame passes identifier -, the role and the frame' bash "$base/gui.sh" --dry-run press WGEX 2 - press-only AXRadioButton frame=659,744,195x16
contains 'role-and-frame press-only reaches the static AppleScript as data' 'WGEX\ 2\ -\ press-only\ AXRadioButton\ frame=659\\\,744\\\,195x16'
run_refuse 'GUI press refuses identifier - with a malformed frame' 'frame must be' bash "$base/gui.sh" --dry-run press WGEX 2 - press-only AXRadioButton frame=1,2,3
# M1-10t (M1-10r VERIFY-B N7): identifier - with a frame is for AXRadioButton only; a label form keeps any role.
run_refuse 'GUI press refuses identifier - with a frame on AXButton' 'identifier - with a frame needs the role AXRadioButton' bash "$base/gui.sh" --dry-run press WGEX 2 - press 686 752 AXButton frame=659,744,195x16
run_refuse 'GUI press-only refuses identifier - with a frame on AXCheckBox' 'identifier - with a frame needs the role AXRadioButton' bash "$base/gui.sh" --dry-run press WGEX 2 - press-only AXCheckBox frame=659,744,195x16
absent 'a refused role never reaches the guest' 'ssh|scp'
run_ok 'GUI press-only by title still takes any role with identifier -' bash "$base/gui.sh" --dry-run press WGEX 2 - press-only AXToolbar Service
run_refuse 'GUI scroll still refuses identifier -' 'wgex accessibility identifier' bash "$base/gui.sh" --dry-run scroll WGEX 2 -
# M1-10m: press-only's lookup miss and AXPress error reports pass the fixed filter; anything else is dropped.
run_ok 'GUI press-only passes a lookup miss' env FAKE_AX_PATH=path=miss bash "$base/gui.sh" --dry-run press WGEX 1 wgex.protection.lockdown press-only AXCheckBox
output_has 'lookup miss is the fixed report' '^path=miss$'
run_ok 'GUI press-only passes an AXPress error with its number' env 'FAKE_AX_PATH=path=error number=-25200' bash "$base/gui.sh" --dry-run press WGEX 1 wgex.protection.lockdown press-only AXCheckBox
output_has 'AXPress error is the fixed report' '^path=error number=-25200$'
run_ok 'GUI press-only drops an unknown report' env 'FAKE_AX_PATH=path=error number=-1; x' bash "$base/gui.sh" --dry-run press WGEX 1 wgex.protection.lockdown press-only AXCheckBox
output_lacks 'an unknown report never leaves gui.sh' 'path='
# M1-10o fix pass 2 (F1): the helper's delivery stamp passes before the path; a malformed stamp is dropped.
run_ok 'GUI press passes the delivery stamp and the path' env $'FAKE_AX_PATH=pressedAt=1793373879.512\npath=element' bash "$base/gui.sh" --dry-run press WGEX 1 wgex.protection.endCaptiveWindow press 330 310 AXButton
output_has 'delivery stamp is the fixed line' '^pressedAt=1793373879\.512$'
output_has 'path follows as the fixed line' '^path=element$'
run_ok 'GUI press drops a malformed stamp' env $'FAKE_AX_PATH=pressedAt=1793373879.512; x\npath=element' bash "$base/gui.sh" --dry-run press WGEX 1 wgex.protection.endCaptiveWindow press 330 310 AXButton
output_lacks 'a malformed stamp never leaves gui.sh' 'pressedAt'
output_has 'the path still leaves gui.sh' '^path=element$'
# M1-10o fix pass 2 (F7): the targeted dump passes the identifier as data; anything else never reaches the guest.
run_ok 'GUI targeted dump passes the identifier as argv' bash "$base/gui.sh" --dry-run dump WGEX 1 wgex.protection.lockdown
contains 'targeted dump uses the static dump AppleScript' 'ax-dump.applescript'
contains 'targeted dump carries app, window and identifier as data' 'ax-dump.applescript\ WGEX\ 1\ wgex.protection.lockdown'
run_refuse 'GUI targeted dump refuses a non-wgex identifier' 'wgex accessibility identifier' bash "$base/gui.sh" --dry-run dump WGEX 1 'x"; do shell script "false'
absent 'a refused identifier never reaches the guest' 'ssh|scp'
run_refuse 'GUI targeted dump refuses a bad window index' 'window index must be 1..99' bash "$base/gui.sh" --dry-run dump WGEX 0 wgex.protection.lockdown
absent 'a refused window never reaches the guest' 'ssh|scp'
run_refuse 'GUI targeted dump refuses a fourth argument' 'dump takes APP' bash "$base/gui.sh" --dry-run dump WGEX 1 wgex.protection.lockdown extra
absent 'a refused extra argument never reaches the guest' 'ssh|scp'
run_ok 'iperf3 fetch dry recipe is offline' bash "$base/lab.sh" iperf3 fetch --dry-run
absent 'iperf3 dry fetch has no VM commands' 'vm-tart|ssh|scp'
if rg -q 'releases/download/3\.22/iperf3-arm64-osx-15 sha256 [0-9a-f]{64}' "$work/output"; then ok 'iperf3 dry run names the pinned release and digest'; else bad 'iperf3 dry run names the pinned release and digest'; fi
run_ok 'iperf3 prefix dry syntax works' bash "$base/lab.sh" --dry-run iperf3 fetch
# The wrapping key flows through the interactive security stdin parser, never -X argv.
if rg -q 'security add-generic-password.*-X' "$base/guest/wrapping-key.sh"; then bad 'wrapping key on argv'; else ok 'wrapping key absent from security argv'; fi
run_ok 'row MTU filter dry command is offline' bash "$base/lab.sh" --dry-run relay mtu on
run_ok 'row MTU teardown dry command is offline' bash "$base/lab.sh" --dry-run relay mtu off
run_ok 'final-hop clock dry command uses guarded SSH discovery' bash "$base/lab.sh" --dry-run ssh --clock "/Users/labuser/lab/verdict-lab-fixture/leakprobe"
run_ok 'interactive SSH dry command has no overall deadline' bash "$base/lab.sh" --dry-run ssh
contains 'interactive shell requests a TTY' 'ssh -t'
# M1-10g: grep -q (or an awk/head that stops early) exits on its first match; a producer
# still writing then takes SIGPIPE and pipefail reports 141 although the match succeeded.
# The producer writes far more than a pipe buffer after the matching first line. The old
# forms must fail (141, or 2 from awk's EPIPE if a parent ignores SIGPIPE); the new pass.
sigpipe_producer() { awk 'BEGIN { print "  domain   : m1-10.wgex.test"; for (i = 0; i < 200000; i++) print "  filler   : resolver line", i }'; }
pipefail_status() {
  local status=0
  (
    set -euo pipefail
    "$@"
  ) >/dev/null 2>&1 || status=$?
  printf '%s' "$status"
}
old_grep() { sigpipe_producer | grep -q 'domain.*m1-10.wgex.test'; }
new_grep() {
  local dns
  dns="$(sigpipe_producer)" || return
  grep -q 'domain.*m1-10.wgex.test' <<<"$dns"
}
new_grep_absent() {
  local dns
  dns="$(sigpipe_producer)" || return
  grep -q 'domain.*m1-11.wgex.test' <<<"$dns"
}
old_awk() { sigpipe_producer | awk '$1 == "domain" {print $3; exit}'; }
new_awk() {
  local domain
  domain="$(sigpipe_producer | awk '!found && $1 == "domain" {print $3; found = 1}')" || return
  [[ "$domain" == m1-10.wgex.test ]]
}
new_case() {
  local dns
  dns="$(sigpipe_producer)" || return
  case "$dns" in *m1-10.wgex.test*) return 0 ;; esac
  return 1
}
status="$(pipefail_status old_grep)"
if [[ "$status" != 0 ]]; then ok "old grep -q pipeline fails under pipefail (status $status)"; else bad 'old grep -q pipeline passed under pipefail; the producer did not outlive the match'; fi
status="$(pipefail_status old_awk)"
if [[ "$status" != 0 ]]; then ok "old early-exit awk pipeline fails under pipefail (status $status)"; else bad 'old early-exit awk pipeline passed under pipefail; the producer did not outlive the match'; fi
status="$(pipefail_status new_grep)"
if [[ "$status" == 0 ]]; then ok 'captured grep -q passes under pipefail'; else bad "captured grep -q returned $status"; fi
status="$(pipefail_status new_grep_absent)"
if [[ "$status" == 1 ]]; then ok 'captured grep -q still fails on a missing match'; else bad "captured grep -q on a missing match returned $status, expected 1"; fi
status="$(pipefail_status new_awk)"
if [[ "$status" == 0 ]]; then ok 'first-match awk without exit passes under pipefail'; else bad "first-match awk returned $status"; fi
status="$(pipefail_status new_case)"
if [[ "$status" == 0 ]]; then ok 'captured case match passes under pipefail'; else bad "captured case match returned $status"; fi
# No lab shell script may pipe into grep -q or head again (this harness holds the old form above).
# rg exits 1 for no match; 0 (a match) or 2 (a scan error) both fail the check.
scan_status=0
early_exit="$(rg -n --glob '*.sh' --glob '!**/tart/tests/run.sh' -e '\|[[:space:]]*grep[[:space:]]+(-[[:alpha:]]*q|--quiet|--silent)' -e '\|[[:space:]]*head([[:space:]]|$)' "$base/.." 2>&1)" || scan_status=$?
if ((scan_status == 1)); then ok 'no lab script pipes into grep -q or head'; else
  bad "lab script pipes into grep -q or head (rg status $scan_status)"
  printf '%s\n' "$early_exit"
fi
printf 'tests: %d passed, %d failed\n' "$pass" "$fail"
((fail == 0))
