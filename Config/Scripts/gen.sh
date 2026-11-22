#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# `just gen`: writes the Debug build identifiers, generates WGEX.xcodeproj with
# XcodeGen, then runs the post-checks (plan 03 §4, §7):
#   - no target resolves SWIFT_VERSION other than 6 (none is 5.0);
#   - bundle identifiers and product names per target, Debug and Release;
#   - the preprocessed daemon plist has no EnvironmentVariables key.
set -euo pipefail
# shellcheck source=Config/Scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$WGEX_ROOT"
derived="$(derived_data)"

bash Config/Scripts/generate-build-identifiers.sh --configuration Debug
xcodegen generate --spec project.yml --quiet
echo "gen: generated WGEX.xcodeproj"

failed=0
check() { # check <description> <condition-command...>
  local what="$1"
  shift
  if "$@"; then
    echo "gen: ok   $what"
  else
    echo "gen: FAIL $what" >&2
    failed=1
  fi
}

no_swift5() { ! grep -qE 'SWIFT_VERSION = "?5' WGEX.xcodeproj/project.pbxproj; }
check "no SWIFT_VERSION = 5.x in project.pbxproj" no_swift5

work="$(mktemp -d "${TMPDIR:-/tmp}/wgex-gen.XXXXXX")"
trap 'rm -rf "$work"' EXIT

for configuration in Debug Release Lab; do
  base="$(xcconfig_value WGEX_BUNDLE_ID_BASE "$configuration")"
  settings="$work/settings-$configuration.txt"
  : >"$settings"
  for scheme in "WGEX-Mac|macOS" "WGEX-iOS|iOS Simulator" "WGEX-TV|tvOS Simulator"; do
    xcodebuild build-for-testing -project WGEX.xcodeproj -scheme "${scheme%%|*}" -configuration "$configuration" \
      -destination "generic/platform=${scheme#*|}" -derivedDataPath "$derived" \
      -showBuildSettings >>"$settings" 2>>"$work/settings-$configuration.err"
  done
  # target|bundle id|product name; product name "-" means not checked.
  expectations=(
    "WGEXMac|$base|WGEX"
    "WGEXDaemon|$base.daemon|WGEXDaemon"
    "WGEXCLI|$base.cli|wgex"
    "WGEXiOS|$base|WGEX"
    "WGEXTV|$base|WGEX"
    "WGEXTunnel-iOS|$base.tunnel|WGEXTunnel"
    "WGEXTunnel-tvOS|$base.tunnel|WGEXTunnel"
    "WGEXLiveActivity|$base.liveactivity|WGEXLiveActivity"
  )
  # shellcheck disable=SC2016 # awk program, not a shell expansion
  check "$configuration: every target resolves SWIFT_VERSION = 6" \
    awk '/^Build settings for action [a-z-]+ and target/ {n++} /^[[:space:]]+SWIFT_VERSION = / {if ($3 != "6") bad=1; s++} END {exit !(n > 0 && s == n && !bad)}' "$settings"
  for expectation in "${expectations[@]}"; do
    IFS='|' read -r target bundle product <<<"$expectation"
    actual="$(awk -v t="$target" '
      /^Build settings for action [a-z-]+ and target/ {cur=$NF; gsub(/[":]/, "", cur)}
      cur == t && $1 == "PRODUCT_BUNDLE_IDENTIFIER" {id=$3}
      cur == t && $1 == "PRODUCT_NAME" {name=$3}
      END {print id "|" name}' "$settings")"
    check "$configuration: $target is $bundle ($product)" test "$actual" = "$bundle|$product"
  done
  plist="$work/daemon-$configuration.plist"
  bash Config/Scripts/preprocess-daemon-plist.sh Daemon/WGEXDaemon/com.magrathean.WGEXApp.daemon.plist.in "$plist" "$base"
  no_environment() { ! plutil -extract EnvironmentVariables xml1 -o /dev/null "$1" 2>/dev/null; }
  check "$configuration: preprocessed daemon plist has no EnvironmentVariables" no_environment "$plist"
done

if ((failed)); then
  echo "gen: post-checks FAILED" >&2
  exit 1
fi
echo "gen: post-checks passed"
