#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
# Every guest script that can change state runs guest_guard first: the guest VM check (macOS 26 or 27 and the
# hypervisor sysctl), then the marker check. guest_lab_user repeats both before it trusts the marker's user.
guest_vm_check() {
  local version
  version="$(sw_vers -productVersion)"
  [[ ("$version" == 26.* || "$version" == 27.*) && "$(sysctl -n kern.hv_vmm_present)" == 1 ]] || {
    echo 'guest: macOS 26 or 27 VM required' >&2
    exit 1
  }
}
# The marker must be a regular file (lstat, never a symlink), owned by root, mode 0644 or stricter (no group or other
# write, no execute).
guest_marker_check() {
  local marker=/var/db/wgex-lab-host info owner mode
  info="$(stat -f '%HT:%u:%Lp' "$marker" 2>/dev/null)" || {
    echo 'guest: lab marker missing' >&2
    exit 1
  }
  mode="${info##*:}"
  owner="${info%:*}"
  owner="${owner##*:}"
  [[ "${info%%:*}" == 'Regular File' ]] || {
    echo 'guest: lab marker is not a regular file' >&2
    exit 1
  }
  [[ "$owner" == 0 ]] || {
    echo 'guest: lab marker is not owned by root' >&2
    exit 1
  }
  if [[ ! "$mode" =~ ^[0-7]{1,3}$ ]] || ((8#$mode & ~8#644)); then
    echo 'guest: lab marker mode must be 0644 or stricter' >&2
    exit 1
  fi
}
guest_guard() {
  guest_vm_check
  if [[ "$(sw_vers -productVersion)" == 27.* ]]; then
    echo 'guest: macOS 27 accepted; macOS 26 acceptance remains required' >&2
  fi
  guest_marker_check
}
# The guest's one lab user (M03-T11): the marker's "user" on the macOS 27 guest ({"user":"admin"}), labuser where the
# marker is {} (the macOS 26 guests). Only a caller that passes --console (asu.sh, seed-tcc.sh) lets
# WGEX_LAB_CONSOLE_USER, when set, name the user instead; every other caller gets the marker's user. The name must match
# the account pattern and name an existing account.
# shellcheck disable=SC2120 # the argument is optional; callers without --console are the default
guest_lab_user() {
  local marker=/var/db/wgex-lab-host user console=0
  case "$#:${1:-}" in
    0:) ;;
    1:--console) console=1 ;;
    *)
      echo 'guest: usage: guest_lab_user [--console]' >&2
      exit 1
      ;;
  esac
  guest_vm_check
  guest_marker_check
  # Fail closed: a marker the caller cannot read is read with the guest's passwordless sudo, and an empty or
  # whitespace-only marker or any read, parse or extraction error refuses. Only a parsed dictionary with no "user" key
  # (the macOS 26 marker {}) keeps labuser.
  local content json kind
  content="$(cat -- "$marker" 2>/dev/null)" || content="$(sudo -n cat -- "$marker" 2>/dev/null)" || {
    echo 'guest: lab marker unreadable' >&2
    exit 1
  }
  # plutil converts an empty or whitespace-only input to {}; such a marker refuses before conversion.
  [[ "$content" == *[![:space:]]* ]] || {
    echo 'guest: lab marker is empty' >&2
    exit 1
  }
  json="$(printf '%s' "$content" | plutil -convert json -o - - 2>/dev/null)" || {
    echo 'guest: lab marker does not parse' >&2
    exit 1
  }
  [[ "$json" == '{'* ]] || {
    echo 'guest: lab marker is not a dictionary' >&2
    exit 1
  }
  if kind="$(printf '%s' "$json" | plutil -type user - 2>&1)"; then
    [[ "$kind" == string ]] || {
      echo 'guest: lab marker user is not a string' >&2
      exit 1
    }
    user="$(printf '%s' "$json" | plutil -extract user raw -o - - 2>/dev/null)" || {
      echo 'guest: lab marker user cannot be extracted' >&2
      exit 1
    }
  elif [[ "$kind" == *'No value at that key path'* ]]; then
    user=labuser
  else
    echo 'guest: lab marker user cannot be read' >&2
    exit 1
  fi
  if ((console)); then user="${WGEX_LAB_CONSOLE_USER:-$user}"; fi
  [[ "$user" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || {
    echo 'guest: marker user is not an account name' >&2
    exit 1
  }
  id -u "$user" >/dev/null 2>&1 || {
    echo 'guest: marker user has no account' >&2
    exit 1
  }
  printf '%s\n' "$user"
}
