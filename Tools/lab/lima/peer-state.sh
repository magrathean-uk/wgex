# SPDX-License-Identifier: MIT
# shellcheck shell=bash
# Shared dedicated-peer guard. The host-only seam requires scratch state and fake tools.
peer_die() {
  printf 'peer: %s\n' "$*" >&2
  exit 1
}
peer_variant() {
  case "$1" in default | full4 | full4-name | dual | dns | lockdown | wrong-key) ;; *) peer_die 'profile variant: default, full4, full4-name, dual, dns, lockdown, wrong-key' ;; esac
}
# shellcheck disable=SC2034 # boot_conf is read by peer-provision.sh, which sources this file
peer_guard() {
  state=/etc/wireguard/wgex-lab
  # wg-quick@wg0 reads this file at every peer boot.
  boot_conf=/etc/wireguard/wg0.conf
  peer_test_bin=
  if [[ -n "${WGEX_LAB_PEER_TEST_ROOT:-}" ]]; then
    local root="$WGEX_LAB_PEER_TEST_ROOT"
    [[ "${1:-}" == --dry-run && -f "$root/fixture-only" && ! -L "$root" ]] || peer_die 'test tools require --dry-run and fixture-only marker'
    case "$root" in "${TMPDIR:?}/"* | "${CLEAN_DEV_BUILDS:?}/"*) ;; *) peer_die 'test state must be in routed scratch/build output' ;; esac
    state="$root/state"
    boot_conf="$root/wireguard/wg0.conf"
    peer_test_bin="$root/bin"
    [[ -d "$state" && ! -L "$state" ]] || peer_die 'invalid test state'
    local tool
    for tool in ip wg tc iperf3 python3; do [[ -x "$peer_test_bin/$tool" ]] || peer_die 'missing mandatory fake peer tool'; done
    export PATH="$peer_test_bin:$PATH"
  else
    [[ "$(uname -s)" == Linux && "$EUID" == 0 && "$(hostname)" =~ ^(lima-)?wg-peer$ ]] || peer_die 'requires root on dedicated Linux wg-peer'
    [[ "${1:-}" != --dry-run ]] || peer_die 'direct dry run requires the fixture seam'
  fi
}
peer_exec() {
  if [[ -n "$peer_test_bin" ]]; then
    [[ -x "$peer_test_bin/$1" ]] || peer_die 'missing mandatory fake peer tool'
    "$peer_test_bin/$1" "${@:2}"
  else "$@"; fi
}
