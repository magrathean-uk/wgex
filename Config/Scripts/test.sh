#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# `just test <package|mac|ios|tv|all>` (plan 03 §7, ticket P0-21).
#   <package>  `swift test` in Packages/<package>
#   all        every package; hosted app tests remain explicit targets
#   mac        builds the Mac test bundles only: they are hosted by WGEX.app,
#              which is never launched on the host; they run in the VM lab (P0-12)
#   ios        hosted unit tests in an iOS simulator
#   tv         tvOS UI tests need a tvOS simulator runtime (P0-11); without one
#              the bundles are built only
set -euo pipefail
# shellcheck source=Config/Scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$WGEX_ROOT"
what="${1:?usage: test.sh <package|mac|ios|tv|all>}"
case "$what" in
  mac | ios | tv) require_current_engine ;;
  tsan) require_current_engine --test-support ;;
esac
configure_caches
# Caller leak-test knobs must not weaken package tests; tsan sets its own cycle count below.
unset WGEX_ENGINE_CYCLES WGEX_ENGINE_PROCESS_LIMITS WGEX_ENGINE_LEAK_READY

package_test() { # package_test <name>
  case "$1" in
    WGEXEngine) require_current_engine --test-support || return ;;
    WGEXBackendMac) require_current_engine || return ;;
  esac
  echo "test: swift test $1"
  local scratch
  scratch="$(build_root)/spm/shared"
  local flags=()
  local test_support=0
  if [[ "$1" == WGEXEngine ]]; then
    test_support=1
    scratch="$(build_root)/spm/engine-integration"
    flags+=(-Xswiftc -enable-actor-data-race-checks)
  fi
  if [[ "${WGEX_LAB_BUILD:-0}" == 1 ]]; then
    scratch="$(build_root)/spm/lab"
    flags+=(-Xswiftc -DWGEX_LAB_BUILD)
  fi
  WGEX_ENGINE_TEST_SUPPORT="$test_support" swift test --package-path "Packages/$1" --scratch-path "$scratch" \
    --cache-path "$(dependency_cache)/swiftpm" ${flags[@]+"${flags[@]}"}
}

ensure_project() {
  if [[ ! -d WGEX.xcodeproj ]] || [[ project.yml -nt WGEX.xcodeproj/project.pbxproj ]]; then
    bash Config/Scripts/gen.sh
  fi
  bash Config/Scripts/generate-build-identifiers.sh --configuration Debug
}

xcode() { # xcode <action> <scheme> <destination> [extra...]
  local action="$1" scheme="$2" destination="$3" codes label
  shift 3
  label="$scheme-$action"
  # Output is filtered (no environment dumps, M1-23); the status is xcodebuild's own, never the filter's.
  set +e
  xcodebuild "$action" -project WGEX.xcodeproj -scheme "$scheme" -configuration Debug \
    -destination "$destination" -derivedDataPath "$(derived_data)" "$@" 2>&1 | xcodebuild_filter "$label"
  codes=("${PIPESTATUS[@]}")
  set -e
  xcodebuild_finish "$label" "${codes[0]}" "${codes[1]}"
}

# hosted_simulator <iOS|tvOS> <ensure|ensure-if-installed>: sets udid to this build key's WGEX-owned simulator device
# (M1-26), creating it from an installed runtime when needed, and prints its name and UDID. The shared simulators
# are never selected, booted, shut down or erased. Status of simulator_device otherwise (4: no runtime, quietly for
# ensure-if-installed).
hosted_simulator() {
  local device runtime device_type state
  device="$(simulator_device "$1" "$2")" || return
  IFS=$'\t' read -r udid runtime device_type state <<<"$device"
  echo "test: simulator $(simulator_name "$1") $udid ($runtime, $device_type, $state)"
}

case "$what" in
  all)
    failed=()
    for manifest in Packages/*/Package.swift; do
      name="$(basename "$(dirname "$manifest")")"
      package_test "$name" || failed+=("$name")
    done
    if ((${#failed[@]})); then
      echo "test: FAILED packages: ${failed[*]}" >&2
      exit 1
    fi
    echo "test: every package passed"
    ;;
  tsan)
    WGEX_ENGINE_TEST_SUPPORT=1 WGEX_ENGINE_CYCLES=100 swift test --package-path Packages/WGEXEngine \
      --scratch-path "$(build_root)/spm/engine-tsan" --cache-path "$(dependency_cache)/swiftpm" \
      --sanitize thread -Xswiftc -enable-actor-data-race-checks
    ;;
  engine)
    (cd Engine/go && GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off go run -tags wgextest ./cmd/wgex-engine-test)
    ;;
  go-race)
    race_flags=(-race)
    [[ "${WGEX_GO_RACE_COUNT:-}" != 1 ]] || race_flags+=(-count=1)
    (cd Engine/go && GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off go test "${race_flags[@]}" ./...)
    peer_proxy="${GOPROXY:-https://proxy.golang.org,direct}"
    [[ "${WGEX_OFFLINE:-0}" != 1 ]] || peer_proxy=off
    (cd Tools/testpeer && GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY="$peer_proxy" go test "${race_flags[@]}" ./...)
    ;;
  fuzz)
    bash Tools/fuzz/run.sh
    ;;
  tools)
    bash Tools/lab/tests/run.sh
    ;;
  mac)
    ensure_project
    xcode build-for-testing WGEX-Mac 'generic/platform=macOS'
    echo "test: Mac test bundles built; hosted and UI tests launch WGEX.app and run only in the VM lab (P0-12)"
    ;;
  ios)
    udid=""
    hosted_simulator iOS ensure || {
      echo "test: no WGEX iOS simulator device could be prepared" >&2
      exit 1
    }
    ensure_project
    xcode test WGEX-iOS "id=$udid" -only-testing:WGEXiOSUnitTests
    ;;
  tv)
    ensure_project
    udid=""
    hosted_simulator tvOS ensure-if-installed && status=0 || status=$?
    if [[ "$status" == 0 ]]; then
      xcode test WGEX-TV "id=$udid"
    elif [[ "$status" == 4 ]]; then
      xcode build-for-testing WGEX-TV 'generic/platform=tvOS Simulator'
      echo "test: tvOS bundles built; no tvOS simulator runtime is installed (P0-11), so nothing ran"
    else
      echo "test: no WGEX tvOS simulator device could be prepared" >&2
      exit 1
    fi
    ;;
  *)
    if [[ -f "Packages/$what/Package.swift" ]]; then
      package_test "$what"
    else
      echo "test: unknown target $what (a package name, mac, ios, tv or all)" >&2
      exit 2
    fi
    ;;
esac
