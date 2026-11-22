#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# The app acknowledgement resource must match the reviewed repository notices.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if ! cmp -s "${1:-$root/THIRD_PARTY_NOTICES.md}" "${2:-$root/Apps/WGEXMac/Resources/THIRD_PARTY_NOTICES.md}"; then
  echo 'notices-sync: FAIL (repository and app notices differ)' >&2
  exit 1
fi
echo 'notices-sync: ok'
