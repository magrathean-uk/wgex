#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# `just packages-matrix` (plan 03 §7): builds every Swift package in Packages/
# with xcodebuild for macOS, the iOS Simulator and the tvOS Simulator. The
# generic simulator destinations need the simulator SDKs but no installed
# runtime. Output goes to $(build_root)/derived-data. Every package
# and platform is attempted; failures are listed together at the end.
# Usage: packages-matrix.sh [package ...]   (default: every package)
set -euo pipefail
# shellcheck source=Config/Scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$WGEX_ROOT"
require_current_engine
configure_caches

DESTINATIONS=(
  'generic/platform=macOS'
  'generic/platform=iOS Simulator'
  'generic/platform=tvOS Simulator'
)

# scheme_for <package dir>: the scheme that builds every target of the
# package (<Name>-Package when the package has several products, else <Name>).
scheme_for() {
  local dir="$1" name
  name="$(basename "$dir")"
  (cd "$dir" && xcodebuild -list -json 2>/dev/null) | python3 -I -c '
import json, sys
name = sys.argv[1]
data = json.load(sys.stdin)
schemes = (data.get("workspace") or data.get("project") or {}).get("schemes", [])
for candidate in (name + "-Package", name):
    if candidate in schemes:
        print(candidate)
        sys.exit(0)
sys.exit(1)' "$name"
}

case "${1:-}" in
  --macos)
    DESTINATIONS=('generic/platform=macOS')
    shift
    ;;
  --simulators)
    DESTINATIONS=('generic/platform=iOS Simulator' 'generic/platform=tvOS Simulator')
    shift
    ;;
esac
packages=()
if (($#)); then
  for p in "$@"; do
    [[ -f "Packages/$p/Package.swift" ]] || {
      echo "packages-matrix: no package Packages/$p" >&2
      exit 2
    }
    packages+=("$p")
  done
else
  for manifest in Packages/*/Package.swift; do
    packages+=("$(basename "$(dirname "$manifest")")")
  done
fi

failed=()
passed=0
for name in "${packages[@]}"; do
  dir="$WGEX_ROOT/Packages/$name"
  if ! scheme="$(scheme_for "$dir")"; then
    echo "packages-matrix: $name: no buildable scheme found" >&2
    failed+=("$name (scheme)")
    continue
  fi
  for destination in "${DESTINATIONS[@]}"; do
    echo "packages-matrix: $name [$scheme] -> $destination"
    label="package-$name-${destination#generic/platform=}"
    set +e
    (cd "$dir" && xcodebuild build -scheme "$scheme" -configuration Debug \
      -destination "$destination" -derivedDataPath "$(derived_data)" -quiet) 2>&1 | xcodebuild_filter "$label"
    codes=("${PIPESTATUS[@]}")
    set -e
    if xcodebuild_finish "$label" "${codes[0]}" "${codes[1]}"; then
      passed=$((passed + 1))
    else
      failed+=("$name ($destination)")
    fi
  done
done

if ((${#failed[@]})); then
  printf 'packages-matrix: FAILED:\n' >&2
  printf '  %s\n' "${failed[@]}" >&2
  exit 1
fi
echo "packages-matrix: $passed builds passed (${#packages[@]} packages x ${#DESTINATIONS[@]} platforms)"
