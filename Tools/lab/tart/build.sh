#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Build only; never launch WGEX. Mirrors Config/Scripts/build.sh conventions.
set -euo pipefail
# shellcheck source=Tools/lab/tart/lib.sh
source "$(dirname "$0")/lib.sh"
# shellcheck source=Config/Scripts/lib.sh
source "$LAB_ROOT/Config/Scripts/lib.sh"
[[ "${1:-}" != --dry-run ]] || LAB_DRY=1
[[ "${1:-}" != --dry-run ]] || shift
(($# == 0)) || lab_die 'usage: build.sh [--dry-run]'
cd "$LAB_ROOT"
if [[ "$LAB_DRY" != 1 ]]; then require_current_engine; fi
output="$(build_root)/derived-data"
rg -q '^  Lab: debug$' project.yml || lab_die 'Lab configuration missing from project.yml'
# Build-time generation uses Debug identifiers, inherited by Lab. The scheme
# pre-action regenerates these from Lab settings during the actual build.
lab_mutate bash Config/Scripts/generate-build-identifiers.sh --configuration Debug
lab_mutate xcodegen generate --spec project.yml --quiet
build_version_args=()
if [[ -n "${WGEX_LAB_BUNDLE_VERSION:-}" ]]; then
  [[ "$WGEX_LAB_BUNDLE_VERSION" =~ ^[1-9][0-9]*$ ]] || lab_die 'WGEX_LAB_BUNDLE_VERSION must be a positive integer'
  build_version_args=("CURRENT_PROJECT_VERSION=$WGEX_LAB_BUNDLE_VERSION")
fi
label=lab-WGEX-Mac-build
app="$output/Build/Products/Lab/WGEX.app"
if [[ "$LAB_DRY" != 1 ]]; then
  python3 -I -B Tools/lab/check-verdicts.py --prepare-build "$app"
fi
# The status is xcodebuild's own, never the filter's (M1-23); stderr (including the dry-run echo) joins the filter.
set +e
# Command-line conditions also reach local Swift package targets.
# shellcheck disable=SC2016 # literal Xcode inherited setting
lab_mutate xcodebuild build -project WGEX.xcodeproj -scheme WGEX-Mac \
  -configuration Lab -destination 'generic/platform=macOS' \
  -derivedDataPath "$output" -disableAutomaticPackageResolution \
  -onlyUsePackageVersionsFromResolvedFile -skipPackageUpdates \
  'SWIFT_ACTIVE_COMPILATION_CONDITIONS=$(inherited) DEBUG WGEX_LAB_BUILD' WGEX_LAB_BUILD=1 ${build_version_args[@]+"${build_version_args[@]}"} 2>&1 | xcodebuild_filter "$label"
codes=("${PIPESTATUS[@]}")
set -e
# A dry run is a single echo that xcbeautify --quiet would drop: show the env-free log.
if [[ "$LAB_DRY" == 1 ]]; then cat -- "$(xcodebuild_log_path "$label")" >&2 || true; fi
xcodebuild_finish "$label" "${codes[0]}" "${codes[1]}"
if [[ "$LAB_DRY" != 1 ]]; then
  # xcodebuild inherits the host umask (077 here), which would ship a 0700
  # bundle; secure install then chowns it to root and locks the login user
  # out. Normalise to the modes a drag-installed bundle has (0755/0644).
  chmod -R u+rwX,go+rX,go-w "$app"
  codesign --verify --deep --strict "$app"
  (cd "$app" && shasum -a 256 Contents/MacOS/WGEX Contents/MacOS/WGEXDaemon Contents/Helpers/wgex Contents/Info.plist) >"$app.lab-build.sha256"
  python3 -I -B Tools/lab/check-verdicts.py --finish-build "$app"
fi
