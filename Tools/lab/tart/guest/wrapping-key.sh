#!/bin/bash
# SPDX-License-Identifier: MIT
# Lab guest only: keeps the daemon's System-keychain wrapping key readable across Lab reinstalls, with no prompt.
# Lab builds are ad hoc signed, so the key's decrypt ACL pins the installed daemon's cdhash and every rebuild changes
# it (run 9b F1: CSSMERR_CSP_OPERATION_AUTH_DENIED until an administrator approves Secure Install). The key this
# script creates is escrowed root-only inside the guest (never on the host, never printed); after an install the same
# bytes are re-added trusting only the new daemon, so stored secrets stay readable and the ACL keeps the single-daemon
# cdhash shape the daemon itself writes. A key the lab did not create (no escrow, or another creation date) is left
# alone; --replace-unescrowed swaps it for an escrowed key only while no ciphertext exists (the ready11 baseline).
# Set WGEX_WRAPPING_KEY_FALLBACK=0 only for the daemon-provisioning proof. Never rotates a key.
set +x
set -euo pipefail
# shellcheck source=Tools/lab/tart/guest/guard.sh
source "$(dirname "$0")/guard.sh"
guest_guard
replace=0
if [[ "${1:-}" == --replace-unescrowed ]]; then
  replace=1
  shift
fi
service="${1:?usage: wrapping-key.sh [--replace-unescrowed] DAEMON-SERVICE-LABEL}"
(($# == 1)) || exit 1
[[ "$service" =~ ^com\.magrathean\.[a-zA-Z0-9.-]+$ ]] || exit 1
keychain=/Library/Keychains/System.keychain
daemon=/Applications/WGEX.app/Contents/MacOS/WGEXDaemon
state='/Library/Application Support/WGEX/secrets'
escrow_dir=/var/db/wgex-lab-keys
escrow="$escrow_dir/$service.key"
binding="$escrow_dir/$service.created"

# Attribute and ACL lines of this service's wrapping-key item; dump-keychain without -d never reads item data.
item_lines() {
  sudo -n security dump-keychain -a "$keychain" 2>/dev/null | awk -v service="$service" '
    function flush() {
      if (block ~ /"acct"<blob>="wrapping-key-v1"/ && index(block, "\"svce\"<blob>=\"" service "\"")) { found++; print block }
      block = ""
    }
    /^keychain: / { flush() }
    { block = block $0 "\n" }
    END { flush(); exit (found > 1) }'
}
items() { item_lines | grep -c '^keychain: ' || true; }
present() { sudo -n security find-generic-password -s "$service" -a wrapping-key-v1 "$keychain" >/dev/null 2>&1; }
created() { item_lines | sed -n 's/^.*"cdat"<timedate>=[^"]*"\([0-9]\{14\}Z\).*$/\1/p'; }
trusted() { item_lines | sed -n 's/^ *requirement: cdhash H"\([0-9a-f]\{40\}\)"$/\1/p'; }
installed() { codesign -d --verbose=4 "$daemon" 2>&1 | sed -n 's/^CDHash=\([0-9a-f]\{40\}\)$/\1/p'; }
ciphertext() { sudo -n test -d "$state" && [[ -n "$(sudo -n find "$state" -type f -name '*.blob' -print -quit)" ]]; }
escrowed() {
  sudo -n test -f "$escrow" && sudo -n test ! -L "$escrow" && sudo -n test -f "$binding" && sudo -n test ! -L "$binding"
}

# security's interactive parser takes the command on stdin, so the key never appears in argv; prompts and
# diagnostics are discarded as well. The ACL trusts exactly the installed daemon's designated requirement.
add_key() {
  printf 'add-generic-password -s "%s" -a wrapping-key-v1 -X "%s" -T "%s" "%s"\n' "$service" "$1" "$daemon" "$keychain" |
    sudo -n security -i >/dev/null 2>&1
}
record_binding() {
  local stamp
  stamp="$(created)"
  [[ "$stamp" =~ ^[0-9]{14}Z$ ]] || exit 1
  printf '%s\n' "$stamp" | sudo -n tee "$binding" >/dev/null
}
read_escrow() {
  local key
  key="$(sudo -n cat "$escrow")"
  [[ "$key" =~ ^[0-9a-f]{64}$ ]] || exit 1
  printf '%s' "$key"
}
verify_trust() {
  local want
  want="$(installed)"
  [[ "$want" =~ ^[0-9a-f]{40}$ && "$(trusted)" == "$want" ]] || {
    echo "wrapping key ACL does not trust the installed daemon" >&2
    exit 1
  }
  echo "$1 for $service; decrypt ACL trusts installed daemon cdhash $want"
}

[[ -f "$daemon" && ! -L "$daemon" ]] || exit 1
if [[ "$(items)" -gt 1 ]]; then
  echo "more than one wrapping key item for $service" >&2
  exit 1
fi
if [[ "${WGEX_WRAPPING_KEY_FALLBACK:-1}" != 1 ]]; then
  if present; then echo "wrapping key present for $service"; else echo "wrapping key absent; the daemon provisions it during Secure Install"; fi
  exit 0
fi
if present && [[ "$replace" == 1 ]]; then
  if escrowed && [[ "$(sudo -n cat "$binding")" == "$(created)" ]]; then
    echo "wrapping key already escrowed for $service"
  elif ciphertext; then
    echo "retained ciphertext requires recovery of the original wrapping key" >&2
    exit 1
  else
    # No ciphertext exists, so the unescrowed key protects nothing; the replacement below is escrowed.
    sudo -n security delete-generic-password -s "$service" -a wrapping-key-v1 "$keychain" >/dev/null 2>&1
    sudo -n rm -f "$escrow" "$binding"
    echo "unescrowed wrapping key removed for $service (no ciphertext)"
  fi
fi
if present; then
  if ! escrowed || [[ "$(sudo -n cat "$binding")" != "$(created)" ]]; then
    echo "wrapping key present for $service; not escrowed by the lab, left unchanged (a reinstalled ad hoc daemon is refused)"
    exit 0
  fi
  if [[ "$(trusted)" == "$(installed)" ]]; then
    verify_trust "wrapping key unchanged"
    exit 0
  fi
  # Same bytes, new trusted daemon: delete then re-add from the escrow. An interruption between the two leaves the
  # escrow, and the next run re-adds it through the absent-item path below.
  key="$(read_escrow)"
  sudo -n security delete-generic-password -s "$service" -a wrapping-key-v1 "$keychain" >/dev/null 2>&1
  add_key "$key"
  unset key
  present || exit 1
  record_binding
  verify_trust "wrapping key re-trusted"
  exit 0
fi
if escrowed; then
  key="$(read_escrow)"
  add_key "$key"
  unset key
  present || exit 1
  record_binding
  verify_trust "wrapping key restored from the lab escrow"
  exit 0
fi
if ciphertext; then
  echo "retained ciphertext requires recovery of the original wrapping key" >&2
  exit 1
fi
key="$(head -c 32 /dev/urandom | xxd -p | tr -d '\n')"
[[ "$key" =~ ^[0-9a-f]{64}$ ]] || exit 1
# Escrow first: a failure after the keychain add can still be recovered from the escrow.
sudo -n install -d -m 0700 -o root -g wheel "$escrow_dir"
sudo -n install -m 0600 -o root -g wheel /dev/null "$escrow"
printf '%s' "$key" | sudo -n tee "$escrow" >/dev/null
add_key "$key"
unset key
present || exit 1
sudo -n install -m 0600 -o root -g wheel /dev/null "$binding"
record_binding
verify_trust "wrapping key provisioned and escrowed"
