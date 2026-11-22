#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# ios-design-shots.sh <output-directory>: renders the iOS screens to PNG through IOSDesignShotsTests, light and dark: the
# iPhone set on the iPhone 18 Pro simulator, the iPad split view on the iPad Pro 13-inch (M5) simulator (WGEX_SHOTS_IPHONE
# and WGEX_SHOTS_IPAD name others). Builds once, then tests on each simulator in turn without clones; never launches the
# app. A named simulator whose data is no longer on disk is stood in for by a temporary "WGEX shots" device of the same
# type, deleted on exit. A heavy job: run it under hostload. The output directory must be outside the repository.
set -euo pipefail
out="${1:?usage: ios-design-shots.sh <output-directory outside the repository>}"
# shellcheck source=Config/Scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/../../../Config/Scripts/lib.sh"
mkdir -p "$out"
out="$(cd "$out" && pwd -P)"
case "$out/" in
  "$(cd "$WGEX_ROOT" && pwd -P)"/*)
    echo "ios-design-shots: refusing an output directory inside the repository: $out" >&2
    exit 2
    ;;
esac
configure_caches
derived="$(build_root)/derived-data-ios-shots"
created=()

remove_created() {
  local udid
  for udid in ${created[@]+"${created[@]}"}; do
    with_deadline 120 xcrun simctl shutdown "$udid" >/dev/null 2>&1 || true
    if with_deadline 180 xcrun simctl delete "$udid"; then
      echo "ios-design-shots: deleted temporary simulator $udid"
    else
      echo "ios-design-shots: could not delete temporary simulator $udid; delete it with xcrun simctl delete" >&2
    fi
  done
}
trap remove_created EXIT

# shots_destination <name> <device type identifier>: sets destination to the available simulator named <name> when its
# data is on disk, otherwise to a new temporary "WGEX shots <name>" device of that type on the newest iOS runtime.
shots_destination() {
  local name="$1" type="$2" udid runtime
  udid="$(with_deadline 60 xcrun simctl list devices available -j | python3 -I -c '
import json, sys
name = sys.argv[1]
for runtime, devices in json.load(sys.stdin)["devices"].items():
    for device in devices:
        if device["name"] == name and "iOS" in runtime:
            print(device["udid"])
            raise SystemExit
' "$name")"
  if [[ -n "$udid" && -d "$HOME/Library/Developer/CoreSimulator/Devices/$udid/data" ]]; then
    destination="id=$udid"
    return
  fi
  runtime="$(with_deadline 60 xcrun simctl list runtimes available -j | python3 -I -c '
import json, re, sys
plain = re.compile(r"com\.apple\.CoreSimulator\.SimRuntime\.iOS(-[0-9]+)+")
ios = [r for r in json.load(sys.stdin)["runtimes"] if r.get("platform") == "iOS" and plain.fullmatch(r["identifier"])]
print(max(ios, key=lambda r: [int(p) for p in r["version"].split(".")])["identifier"] if ios else "")
')"
  [[ -n "$runtime" ]] || {
    echo "ios-design-shots: no available iOS runtime for a temporary $name" >&2
    return 1
  }
  udid="$(with_deadline 180 xcrun simctl create "WGEX shots $name" "$type" "$runtime")"
  created+=("$udid")
  echo "ios-design-shots: $name is not on disk; created temporary simulator $udid ($type, $runtime)"
  destination="id=$udid"
}

shots_xcodebuild() { # shots_xcodebuild <label> <xcodebuild arguments...>
  local label="$1" codes
  shift
  set +e
  (cd "$WGEX_ROOT/Packages/WGEXUITesting" && TEST_RUNNER_WGEX_DESIGN_SHOTS="$out" xcodebuild "$@" -scheme WGEXUITesting \
    -derivedDataPath "$derived") 2>&1 | xcodebuild_filter "$label"
  codes=("${PIPESTATUS[@]}")
  set -e
  xcodebuild_finish "$label" "${codes[0]}" "${codes[1]}"
}

shots_xcodebuild ios-design-shots-build build-for-testing -destination 'generic/platform=iOS Simulator'
destination=""
for slot in "${WGEX_SHOTS_IPHONE:-iPhone 18 Pro}|com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro" \
  "${WGEX_SHOTS_IPAD:-iPad Pro 13-inch (M5)}|com.apple.CoreSimulator.SimDeviceType.iPad-Pro-13-inch-M5-12GB"; do
  shots_destination "${slot%%|*}" "${slot#*|}"
  shots_xcodebuild ios-design-shots-test test-without-building -destination "platform=iOS Simulator,$destination" \
    -parallel-testing-enabled NO -only-testing:WGEXUITestingTests/IOSDesignShotsTests
done
echo "ios-design-shots: $(find "$out" -maxdepth 1 -name '*.png' | wc -l | tr -d ' ') pictures in $out"
