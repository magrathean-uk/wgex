#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Host helpers. Dry runs never contact guests or change VMs.
set -euo pipefail
LAB_DIR="$(CDPATH='' cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC2034 # consumed by scripts sourcing this library
LAB_ROOT="$(CDPATH='' cd -- "$LAB_DIR/../../.." && pwd)"
# Guest parameters (M03-T11): macOS 26 defaults; the macOS 27 guest is WGEX_LAB_VM=macos27-wgex WGEX_LAB_USER=admin
# WGEX_LAB_SNAPSHOT_PREFIX=macos27- (snapshot macos27-base). The VM family fixes the guest OS major lab_connect expects.
LAB_USER="${WGEX_LAB_USER:-labuser}"
LAB_VM="${WGEX_LAB_VM:-macos26-wgex}"
LAB_SNAPSHOT_PREFIX="${WGEX_LAB_SNAPSHOT_PREFIX:-$LAB_VM-}"
LAB_GUEST_MAJOR=26
LAB_KEY="${WGEX_LAB_KEY:-$HOME/.ssh/id_ed25519}"
LAB_WRAPPER="${WGEX_LAB_VM_ROOT:-$HOME/wgex-lab-vm}/vm-tart"
LAB_DRY=0
LAB_ADDRESS=
LAB_DEADLINE="${WGEX_LAB_SSH_DEADLINE:-600}"
lab_die() {
  printf 'lab: %s\n' "$*" >&2
  exit 1
}
# Harness deadline bases (M1-10i), shared with Tools/lab/harness.py; lab_harness applies WGEX_LAB_HARNESS_SCALE.
# Resolved from this file's own location, never from $PWD or the caller; a copied tree must carry it.
# M1-10t (M1-10s LOW-1): the guard tests the very string the next line sources ("$LAB_DIR/../...", resolved by the kernel, so a
# symlinked tart directory cannot make them disagree); the message adds the lexical parent so the expected place is readable.
[[ -f "$LAB_DIR/../harness-deadlines.sh" ]] ||
  lab_die "harness deadlines missing: $(CDPATH='' cd -- "$LAB_DIR/.." && pwd)/harness-deadlines.sh (tested as $LAB_DIR/../harness-deadlines.sh)"
# shellcheck source=Tools/lab/harness-deadlines.sh
source "$LAB_DIR/../harness-deadlines.sh"
lab_init() {
  if [[ "${1:-}" == --dry-run ]]; then LAB_DRY=1; fi
  [[ "$LAB_VM" =~ ^macos(26|27)-wgex(-[a-zA-Z0-9_-]+)?$ ]] || lab_die 'VM must be macos26-wgex, macos27-wgex or a named variant'
  LAB_GUEST_MAJOR="${BASH_REMATCH[1]}"
  [[ "$LAB_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || lab_die 'guest user must be a short account name'
  [[ "$LAB_SNAPSHOT_PREFIX" =~ ^macos${LAB_GUEST_MAJOR}-([a-zA-Z0-9_-]*-)?$ ]] || lab_die "snapshot prefix must start macos$LAB_GUEST_MAJOR- and end with -"
  # Injection only works with --dry-run and a fixture marker.
  if [[ -n "${WGEX_LAB_TEST_BIN:-}" ]]; then
    [[ "$LAB_DRY" == 1 && -f "$WGEX_LAB_TEST_BIN/fixture-only" ]] || lab_die 'test tools require --dry-run and fixture-only marker'
    LAB_WRAPPER="$WGEX_LAB_TEST_BIN/vm-tart"
  fi
  [[ -x "$LAB_WRAPPER" ]] || lab_die 'lab wrapper missing (set WGEX_LAB_VM_ROOT); no fallback'
  # Clones get a new MAC and therefore a new address on every restore, so the
  # guest host key is pinned for the whole host-only subnet in a lab-specific
  # file (written once by `lab trust`), never in ~/.ssh/known_hosts.
  LAB_KNOWN_HOSTS="${WGEX_LAB_KNOWN_HOSTS:-$(dirname "$LAB_WRAPPER")/wgex-known_hosts}"
  case "$(lab_local sw_vers -productVersion)" in
    26.* | 27.*) ;;
    *) lab_die 'host must run macOS 26.x or 27.x' ;;
  esac
  [[ "$LAB_DEADLINE" =~ ^[1-9][0-9]*$ && "$LAB_DEADLINE" -le 900 ]] || lab_die 'SSH deadline must be 1..900 seconds'
  lab_harness
}
# Scaled harness bounds for host-side and SSH steps (M1-10i): base x WGEX_LAB_HARNESS_SCALE (1..8, default 4).
# Keepalive keeps its 5 s interval; the count scales, so an unanswered session is dropped after 5 x count seconds.
lab_harness() {
  LAB_HARNESS_SCALE="${WGEX_LAB_HARNESS_SCALE:-$HARNESS_SCALE_DEFAULT}"
  [[ "$LAB_HARNESS_SCALE" =~ ^[1-8]$ ]] || lab_die 'WGEX_LAB_HARNESS_SCALE must be an integer 1..8'
  LAB_CONNECT_PROBE=$((HARNESS_CONNECT_PROBE * LAB_HARNESS_SCALE))
  LAB_WAIT_STOPPED=$((HARNESS_WAIT_STOPPED * LAB_HARNESS_SCALE))
  LAB_WAIT_READY=$((HARNESS_WAIT_READY * LAB_HARNESS_SCALE))
  # shellcheck disable=SC2034 # consumed by Tools/lab/profile.sh
  LAB_PEER_SHELL=$((HARNESS_PEER_SHELL * LAB_HARNESS_SCALE))
  LAB_SSH=(-F /dev/null -o IdentityAgent=none -i "$LAB_KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=$((HARNESS_SSH_CONNECT_TIMEOUT * LAB_HARNESS_SCALE)) -o ServerAliveInterval=5 -o ServerAliveCountMax=$((HARNESS_SSH_ALIVE_COUNT * LAB_HARNESS_SCALE)) -o NumberOfPasswordPrompts=0 -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o UserKnownHostsFile="$LAB_KNOWN_HOSTS" -o StrictHostKeyChecking=yes)
}
lab_print() {
  printf 'dry-run:' >&2
  printf ' %q' "$@" >&2
  printf '\n' >&2
}
lab_local() {
  if [[ -n "${WGEX_LAB_TEST_BIN:-}" && "$LAB_DRY" == 1 ]]; then
    [[ -x "$WGEX_LAB_TEST_BIN/${1##*/}" ]] || lab_die "missing fake tool: $1"
    "$WGEX_LAB_TEST_BIN/${1##*/}" "${@:2}"
  else "$@"; fi
}
lab_mutate() {
  if [[ "$LAB_DRY" == 1 ]]; then
    lab_print "$@"
    if [[ -n "${WGEX_LAB_TEST_BIN:-}" ]]; then lab_local "$@"; fi
  else lab_local "$@"; fi
}
lab_tart() { (CDPATH='' cd -- "$(dirname "$LAB_WRAPPER")" && lab_mutate "$LAB_WRAPPER" "$@"); }
lab_inventory() {
  if [[ "$LAB_DRY" == 1 && -z "${WGEX_LAB_TEST_BIN:-}" ]]; then
    lab_print "$LAB_WRAPPER" "$@"
    case "$1" in get) printf 'stopped\n' ;; ip) printf '192.0.2.1\n' ;; esac
  else (CDPATH='' cd -- "$(dirname "$LAB_WRAPPER")" && lab_local "$LAB_WRAPPER" "$@"); fi
}
# Inventory state test, SIGPIPE-safe under pipefail: capture, then grep -qw (M1-10g).
lab_inventory_is() {
  local inventory
  inventory="$(lab_inventory get "$1")" || return
  grep -qw -- "$2" <<<"$inventory"
}
lab_ssh_read() {
  if [[ "$LAB_DRY" == 1 && -z "${WGEX_LAB_TEST_BIN:-}" ]]; then
    lab_print ssh "${LAB_SSH[@]}" "$LAB_USER@$LAB_ADDRESS" "$@"
    if [[ "${1:-}" == 'sw_vers -productVersion' ]]; then lab_dry_version; fi
  else lab_deadline ssh "${LAB_SSH[@]}" "$LAB_USER@$LAB_ADDRESS" "$@"; fi
}
lab_dry_version() { if [[ "$LAB_GUEST_MAJOR" == 27 ]]; then printf '27.2\n'; else printf '26.6.2\n'; fi; }
lab_deadline() {
  if [[ -n "${WGEX_LAB_TEST_BIN:-}" && "$LAB_DRY" == 1 ]]; then lab_local "$@"; else
    perl -e 'alarm shift; exec @ARGV or die "exec failed\n"' "$LAB_DEADLINE" "$@"
  fi
}
lab_ssh() {
  if [[ "$LAB_DRY" == 1 ]]; then lab_mutate ssh "${LAB_SSH[@]}" "$LAB_USER@$LAB_ADDRESS" "$@"; else
    lab_deadline ssh "${LAB_SSH[@]}" "$LAB_USER@$LAB_ADDRESS" "$@"
  fi
}
lab_scp() {
  if [[ "$LAB_DRY" == 1 ]]; then lab_mutate scp "${LAB_SSH[@]}" "$@"; else lab_deadline scp "${LAB_SSH[@]}" "$@"; fi
}
lab_connect_probe() {
  local remaining=$((connect_deadline - SECONDS))
  ((remaining > 0)) || return 1
  if ((remaining > LAB_CONNECT_PROBE)); then remaining="$LAB_CONNECT_PROBE"; fi
  if [[ "$LAB_DRY" == 1 ]]; then lab_local "$@"; else
    perl -e 'alarm shift; exec @ARGV or die "exec failed\n"' "$remaining" "$@"
  fi
}
lab_connect() {
  [[ -f "$LAB_KEY" || "$LAB_DRY" == 1 ]] || lab_die 'SSH key missing'
  local resolver candidate version addresses attempt delay=1 budget="${WGEX_LAB_CONNECT_TIMEOUT:-120}"
  [[ "$budget" =~ ^[1-9][0-9]*$ && "$budget" -le 900 ]] || lab_die 'connect timeout must be 1..900 seconds'
  local connect_deadline=$((SECONDS + budget))
  for ((attempt = 0; attempt < 16 && SECONDS < connect_deadline; attempt++)); do
    for resolver in arp dhcp; do
      if [[ "$LAB_DRY" == 1 && -z "${WGEX_LAB_TEST_BIN:-}" ]]; then
        addresses="$(lab_inventory ip --resolver "$resolver" "$LAB_VM" || true)"
      else
        addresses="$(CDPATH='' cd -- "$(dirname "$LAB_WRAPPER")" && lab_connect_probe "$LAB_WRAPPER" ip --resolver "$resolver" "$LAB_VM" || true)"
      fi
      for candidate in $addresses; do
        [[ "$candidate" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
        LAB_ADDRESS="$candidate"
        if [[ "$LAB_DRY" == 1 && -z "${WGEX_LAB_TEST_BIN:-}" ]]; then
          version="$(lab_dry_version)"
        elif lab_connect_probe ssh "${LAB_SSH[@]}" "$LAB_USER@$LAB_ADDRESS" true </dev/null >/dev/null 2>&1; then
          version="$(lab_connect_probe ssh "${LAB_SSH[@]}" "$LAB_USER@$LAB_ADDRESS" 'sw_vers -productVersion' </dev/null || true)"
        else continue; fi
        if [[ -n "$version" ]]; then
          # A macos26 VM may run 27 (with the note); a macos27 VM must run 27.
          case "$version" in
            26.*) [[ "$LAB_GUEST_MAJOR" == 26 ]] || lab_die "VM $LAB_VM must run macOS 27.x" ;;
            27.*) [[ "$LAB_GUEST_MAJOR" == 27 ]] || printf 'lab: macOS 27 guest accepted; macOS 26 acceptance remains required\n' >&2 ;;
            *) lab_die 'guest must run macOS 26.x or 27.x' ;;
          esac
          return
        fi
      done
    done
    if [[ "$LAB_DRY" != 1 ]]; then
      local remaining=$((connect_deadline - SECONDS))
      ((remaining > 0)) || break
      if ((delay > remaining)); then delay="$remaining"; fi
      sleep "$delay"
      delay=$((delay * 2))
      if ((delay > 16)); then delay=16; fi
    fi
  done
  lab_die "no guest address answers key-only SSH after ${budget}s readiness budget; if the guest is up, pin its host key once with: just lab trust (writes $LAB_KNOWN_HOSTS)"
}
guest_is_lab() {
  # shellcheck disable=SC2016 # expanded by the guest shell
  lab_ssh_read 'set -eu; test "$(sysctl -n kern.hv_vmm_present)" = 1; m=/var/db/wgex-lab-host; test -f "$m"; test ! -L "$m"; test "$(stat -f "%u:%Lp" "$m")" = 0:644' </dev/null || lab_die 'guest hypervisor or root-owned 0644 marker check failed'
}
lab_name() { [[ "${1:-}" =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]*$ ]] || lab_die 'invalid snapshot name'; }
lab_wait_stopped() {
  local n
  for ((n = 0; n < LAB_WAIT_STOPPED; n++)); do
    if lab_inventory_is "$LAB_VM" stopped; then return; fi
    [[ "$LAB_DRY" == 1 ]] || sleep 1
  done
  lab_die 'guest did not stop; clone/delete refused'
}
lab_stop() {
  if lab_inventory_is "$LAB_VM" running; then
    lab_connect
    guest_is_lab
    lab_ssh 'sudo -n shutdown -h now' || true
  fi
  lab_wait_stopped
}
lab_start() {
  # Headless with a console (DEC-112): no Tart window on any host display. Virtualization.framework's VNC server
  # (--vnc-experimental, 127.0.0.1 only) keeps the guest's display attached, so guest screencapture and System Events
  # work, and Tools/lab/console/console.py types the console login and administrator approval through it (DEC-034).
  # CI=1 makes Tart print its vnc:// address and one-time password instead of opening the host's Screen Sharing app:
  # into WGEX_LAB_VNC_FILE when set (lab_private_output: regular, one link, this user's, 0600, emptied before Tart
  # writes), otherwise to /dev/null.
  local file="${WGEX_LAB_VNC_FILE:-}" args=(run --vnc-experimental --no-graphics "$LAB_VM")
  if [[ -n "$file" ]]; then [[ "$file" == /* && "$file" != *$'\n'* ]] || lab_die 'WGEX_LAB_VNC_FILE must be an absolute path'; fi
  if [[ "$LAB_DRY" == 1 ]]; then
    lab_print env CI=1 "$LAB_WRAPPER" "${args[@]}" ">${file:-/dev/null}"
    if [[ -n "${WGEX_LAB_TEST_BIN:-}" ]]; then (CDPATH='' cd -- "$(dirname "$LAB_WRAPPER")" && CI=1 lab_local "$LAB_WRAPPER" "${args[@]}") >/dev/null; fi
    return
  fi
  if [[ -n "$file" ]]; then lab_private_output "$file"; else exec 9>/dev/null; fi
  (CDPATH='' cd -- "$(dirname "$LAB_WRAPPER")" && CI=1 exec "$LAB_WRAPPER" "${args[@]}") </dev/null >&9 2>&1 9>&- &
  exec 9>&-
}
# Opens descriptor 9 on FILE for output that will carry a secret (Tart's VNC address and one-time password, M03-T07).
# umask does not change an existing file's mode, so the descriptor itself is validated after the open: a regular file
# with one link, owned by this user, still the file the path names; it is then set to 0600 and emptied through that
# descriptor, and only then may the caller write to it (>&9). A link or an existing non-regular target is refused before
# the open; one swapped in between is refused by the descriptor check, and nothing is written to it. O_RDWR (<>) never
# blocks on a FIFO and creates a missing file at 0600 under umask 077.
lab_private_output() {
  local file="$1" previous
  [[ "$file" == /* && "$file" != *$'\n'* ]] || lab_die 'private output must be an absolute path'
  [[ -d "$(dirname "$file")" ]] || lab_die 'private output directory missing'
  [[ ! -L "$file" ]] || lab_die 'private output is a link'
  [[ ! -e "$file" || -f "$file" ]] || lab_die 'private output is not a regular file'
  previous="$(umask)"
  umask 077
  if ! exec 9<>"$file"; then
    umask "$previous"
    lab_die 'private output cannot be opened'
  fi
  umask "$previous"
  # shellcheck disable=SC2016 # Python source
  if ! python3 -I -c '
import os, stat, sys
info = os.fstat(0)
named = os.lstat(sys.argv[1])
if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
    sys.exit(1)
if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
    sys.exit(1)
os.fchmod(0, 0o600)
os.ftruncate(0, 0)
if stat.S_IMODE(os.fstat(0).st_mode) != 0o600:
    sys.exit(1)
' "$file" <&9 >/dev/null 2>&1; then
    exec 9>&-
    lab_die 'private output is not a private regular file of this user'
  fi
}
lab_wait_ready() {
  # A Tahoe guest needs 80 to 120 s from power-on to SSH (161 s restores on a load-60 host, run 8); poll every 5 s
  # for up to the scaled harness bound (300 s x WGEX_LAB_HARNESS_SCALE).
  local n deadline=$((SECONDS + LAB_WAIT_READY))
  for ((n = 0; n < LAB_WAIT_READY / 5 && SECONDS < deadline; n++)); do
    if (lab_connect && guest_is_lab) >/dev/null 2>&1; then
      lab_connect
      guest_is_lab
      return
    fi
    [[ "$LAB_DRY" == 1 ]] || sleep 5
  done
  lab_die 'guest not ready after restart'
}
lab_trust() {
  # Trust-on-first-use for the lab image's host key, pinned for the host-only
  # subnet so restored clones (new MAC, new address) keep working. Prints the
  # fingerprint; compare it with the one accepted interactively when the guest
  # was first provisioned. Each guest family keeps its own line, tagged
  # `wgex-lab-guest=macosNN` (M03-T11): trusting one guest replaces only lines
  # with its tag or its exact key (an untagged line from before the tag) and
  # keeps every other line, so the macOS 26 and macOS 27 guests both verify.
  local addresses address subnet key fingerprint tag line current="" kept="" written fields
  addresses="$(lab_inventory ip "$LAB_VM")"
  address="${addresses%%$'\n'*}"
  [[ "$address" =~ ^([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+$ ]] || lab_die 'guest address unknown; is it running?'
  subnet="${BASH_REMATCH[1]}"
  key="$(lab_local ssh-keyscan -t ed25519 -T 5 "$address" 2>/dev/null | awk '!found && $2 == "ssh-ed25519" {print $2, $3; found = 1}' || true)"
  [[ "$key" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+$ ]] || lab_die 'ssh-keyscan returned no ed25519 host key'
  tag="wgex-lab-guest=macos$LAB_GUEST_MAJOR"
  if [[ -f "$LAB_KNOWN_HOSTS" ]]; then current="$(<"$LAB_KNOWN_HOSTS")"; fi
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    read -r -a fields <<<"$line"
    if [[ "${fields[3]:-}" == "$tag" || "${fields[1]:-} ${fields[2]:-}" == "$key" ]]; then continue; fi
    kept+="$line"$'\n'
  done <<<"$current"
  written="$(printf '%s.* %s %s' "$subnet" "$key" "$tag")"
  printf '%s%s\n' "$kept" "$written" >"$LAB_KNOWN_HOSTS.tmp.$$"
  chmod 0644 "$LAB_KNOWN_HOSTS.tmp.$$"
  mv -f -- "$LAB_KNOWN_HOSTS.tmp.$$" "$LAB_KNOWN_HOSTS"
  fingerprint="$(ssh-keygen -lf /dev/stdin <<<"$written" | awk '{print $2}')"
  printf 'pinned %s.* for macos%s in %s (kept %s other line(s))\nfingerprint %s\n' "$subnet" "$LAB_GUEST_MAJOR" "$LAB_KNOWN_HOSTS" "$(printf '%s' "$kept" | grep -c . || true)" "$fingerprint"
}
