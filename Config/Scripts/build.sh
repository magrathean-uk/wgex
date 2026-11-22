#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# `just build <mac|ios|ios-device|tv|all> [debug|release]` (plan 03 §7). Writes
# the build identifiers for the configuration first, regenerates the project when
# project.yml is newer, and builds into $(build_root)/derived-data.
# iOS and tvOS build for the generic simulator destinations, which need the
# simulator SDK but no installed runtime.
# ios-device (M06-T09) builds WGEX-iOS Debug for generic/platform=iOS with
# Automatic development signing on the WGEX team, the restricted entitlements
# and the Debug bundle base, into $CLEAN_DEV_BUILDS. It only ever runs
# `xcodebuild build`: no archive, no export, no Developer ID or distribution
# identity or profile. `just install-ios-device <udid>` installs the result.
set -euo pipefail
for name in "${!WGEX_OWN_MAC_@}"; do
  echo "build: inherited $name is forbidden in ordinary builds" >&2
  exit 1
done
# shellcheck source=Config/Scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$WGEX_ROOT"

platform="${1:?usage: build.sh <mac|ios|ios-device|tv|all> [debug|release]}"
configuration="$(configuration_name "${2:-debug}")"

if [[ "$platform" == ios-device ]]; then
  # Refused before anything is generated or built.
  if [[ "$configuration" != Debug ]]; then
    echo "build: ios-device builds Debug only (Development signing); Release and distribution signing are out of scope" >&2
    exit 2
  fi
  if [[ "${CLEAN_DEV_BUILDS:-}" != /* ]]; then
    echo "build: ios-device needs an absolute CLEAN_DEV_BUILDS; signed products go only to routed build output" >&2
    exit 2
  fi
  device_root="$(build_root)"
  if [[ "$device_root" != "${CLEAN_DEV_BUILDS%/}"/* ]]; then
    echo "build: ios-device output $device_root is not under CLEAN_DEV_BUILDS ($CLEAN_DEV_BUILDS); unset WGEX_BUILD_ROOT or route it there" >&2
    exit 2
  fi
  device_team="$(xcconfig_value WGEX_TEAM "$configuration")"
fi

require_current_engine
configure_caches

if [[ ! -d WGEX.xcodeproj ]] || [[ project.yml -nt WGEX.xcodeproj/project.pbxproj ]]; then
  bash Config/Scripts/gen.sh
fi
bash Config/Scripts/generate-build-identifiers.sh --configuration "$configuration"

build_one() { # build_one <scheme> <destination> <products-subdir> [xcodebuild arguments...]
  local scheme="$1" destination="$2" products="$3" codes label
  shift 3
  label="$scheme-build-$configuration"
  echo "build: $scheme ($configuration, $destination)"
  # The status is xcodebuild's own, never the filter's (M1-23).
  set +e
  xcodebuild build \
    -project WGEX.xcodeproj \
    -scheme "$scheme" \
    -configuration "$configuration" \
    -destination "$destination" \
    -derivedDataPath "$(derived_data)" ${@+"$@"} 2>&1 |
    xcodebuild_filter "$label"
  codes=("${PIPESTATUS[@]}")
  set -e
  xcodebuild_finish "$label" "${codes[0]}" "${codes[1]}" || return
  echo "build: $scheme -> $(derived_data)/Build/Products/$products"
}

case "$platform" in
  mac) build_one WGEX-Mac 'generic/platform=macOS' "$configuration" ;;
  ios) build_one WGEX-iOS 'generic/platform=iOS Simulator' "$configuration-iphonesimulator" ;;
  ios-device)
    # Command-line settings outrank Config/Signing-AdHoc.xcconfig, which Debug includes.
    build_one WGEX-iOS 'generic/platform=iOS' "$configuration-iphoneos" \
      -allowProvisioningUpdates \
      CODE_SIGN_STYLE=Automatic \
      "DEVELOPMENT_TEAM=$device_team" \
      "CODE_SIGN_IDENTITY=Apple Development" \
      PROVISIONING_PROFILE_SPECIFIER= \
      WGEX_RESTRICTED_ENTITLEMENTS=YES
    ;;
  tv)
    if ! xcrun simctl list runtimes | grep -q 'tvOS'; then
      echo "build: no tvOS simulator runtime installed (P0-11); building for the generic tvOS Simulator destination"
    fi
    build_one WGEX-TV 'generic/platform=tvOS Simulator' "$configuration-appletvsimulator"
    ;;
  all)
    "$0" mac "$configuration"
    "$0" ios "$configuration"
    "$0" tv "$configuration"
    ;;
  *)
    echo "build: unknown platform $platform (expected mac, ios, ios-device, tv or all)" >&2
    exit 2
    ;;
esac
