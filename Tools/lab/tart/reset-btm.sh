#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Guest only. Use lab.sh reset-btm --yes-reset to copy and invoke it remotely.
set -euo pipefail
version="$(sw_vers -productVersion)"
[[ ("$version" == 26.* || "$version" == 27.*) && "$(sysctl -n kern.hv_vmm_present)" == 1 ]] || {
  echo 'reset requires macOS 26 or 27 guest' >&2
  exit 1
}
if [[ "$version" == 27.* ]]; then
  echo 'guest: macOS 27 accepted; macOS 26 acceptance remains required' >&2
fi
m=/var/db/wgex-lab-host
[[ -f "$m" && ! -L "$m" && "$(stat -f '%u:%Lp' "$m")" == 0:644 ]] || {
  echo 'reset requires root-owned 0644 lab marker' >&2
  exit 1
}
[[ "${1:-}" == --yes-reset && "$#" == 1 ]] || {
  echo 'explicit --yes-reset required' >&2
  exit 1
}
sudo -n sfltool resetbtm
