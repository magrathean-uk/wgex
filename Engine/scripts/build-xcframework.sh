#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Builds the production engine XCFramework (plan 03 §6, ADR-006).
#
# Usage: build-xcframework.sh [--force] [--clean] [macos|ios|tvos|ios-simulator|tvos-simulator]
#   With no slice, builds all five slices: three device slices and the iOS and
#   tvOS simulator slices (ADR-006 amendment). A single slice produces an
#   XCFramework containing only that slice. --clean uses and empties only this
#   tree's Go cache. --force rebuilds even when the source digest and toolchain match.
#   Single slices and their provenance stay under $(build_root)/engine/slices/.
#
# Output: Packages/WGEXEngine/Binary/WGEXEngine.xcframework and provenance.json
# beside it. Intermediate archives go to $(build_root)/engine/out
# (override with WGEX_ENGINE_OUT). Run under 'zsh -lc' so build routing applies.
# Every output is built under a temporary name in the same directory and renamed
# into place (M1-28), so a symlink left at the final name is replaced, never
# written through into another tree's build. A linked Binary directory or parent
# is refused, one build per tree runs at a time (lock beside Binary), and the
# temporaries of a dead writer are removed at the start of the next build.
set -euo pipefail
# shellcheck source=Engine/scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

new_xcf=""
new_provenance=""
cleanup_new() {
  [[ -z "$new_xcf" ]] || rm -rf -- "$new_xcf"
  [[ -z "$new_provenance" ]] || rm -f -- "$new_provenance"
  restore_publish_aside
  release_binary_lock
}
trap cleanup_new EXIT

clean=0
force=0
single=0
slices="macos ios tvos ios-simulator tvos-simulator"
while (($# > 0)); do
  case "$1" in
    --clean)
      clean=1
      force=1
      ;;
    --force) force=1 ;;
    macos | ios | tvos | ios-simulator | tvos-simulator)
      slices="$1"
      single=1
      ;;
    -h | --help)
      sed -n '2,12p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *) die "unknown argument '$1' (usage: build-xcframework.sh [--force] [--clean] [macos|ios|tvos|ios-simulator|tvos-simulator])" ;;
  esac
  shift
done

require_own_binary
assert_toolchain macosx iphoneos appletvos iphonesimulator appletvsimulator
detect_toolchain
log "go $go_version, Xcode $xcode_version ($xcode_build), GOTOOLCHAIN=$GOTOOLCHAIN GOFLAGS=$GOFLAGS GOPROXY=$GOPROXY"
app_version_values
SCRIPT_SHA="$(source_digest)"
# The cache key is the source digest plus the toolchain that compiles (detect_toolchain in lib.sh), never the
# Toolchain.lock floors.
configure_caches
BUILD="$(build_root)"
OUT="${WGEX_ENGINE_OUT:-$BUILD/engine/out}"
if ((single)); then
  BIN_DIR="$BUILD/engine/slices/$slices"
  OUT="$BIN_DIR/out"
fi
XCF="$BIN_DIR/WGEXEngine.xcframework"
# One build per tree at a time: take the lock before the up-to-date check, so a waiting writer sees the winner's build.
acquire_binary_lock "$BIN_DIR"
remove_build_leftovers "$BIN_DIR"
if ((force == 0 && single == 0)) && python3 -I "$ENGINE_SCRIPTS/source-digest.py" --verify "$BIN_DIR" --toolchain "${toolchain[@]}" 2>/dev/null; then
  # The archive was built by the tools in its provenance, which the verify above proved equal to the found ones.
  log "engine: source digest and toolchain match; using existing five-slice XCFramework (built with $(python3 -I "$ENGINE_SCRIPTS/source-digest.py" --provenance-tools "$BIN_DIR"))"
  exit 0
fi

log "app_version=$APP_VERSION build=$APP_BUILD script_sha=$SCRIPT_SHA"

rm -rf "$OUT"
for s in $slices; do
  cache="$(dependency_cache)/go-$s"
  if ((clean)); then
    cache="$BUILD/engine/gocache/$s"
    rm -rf "$cache"
  fi
  build_slice "$s" "$OUT/$s" "$cache" ""
  mkdir -p "$OUT/$s/include"
  cp "$GO_DIR/bridge/wgex.h" "$GO_DIR/bridge/module.modulemap" "$OUT/$s/include/"
done

log "verify slices"
"$ENGINE_SCRIPTS/verify-slices.sh" "$OUT"

log "assemble $(basename "$XCF")"
set --
for s in $slices; do
  set -- "$@" -library "$OUT/$s/libwgex.a" -headers "$OUT/$s/include"
done
new_xcf="$BIN_DIR/.new-$$-$(basename "$XCF")"
create_xcframework "$new_xcf" "$@"

log "verify packaged slices"
"$ENGINE_SCRIPTS/verify-slices.sh" "$new_xcf"
publish "$new_xcf" "$XCF"
new_xcf=""

# provenance.json: written by hand to avoid a jq dependency; every value is a
# version string, a hex digest or an ISO timestamp, so no escaping is needed
if ! git_rev="$(git -C "$ROOT" rev-parse --verify HEAD 2>/dev/null)"; then
  git_rev=unknown
fi
git_dirty=false
if [[ -n "$(git -C "$ROOT" status --porcelain -- Engine 2>/dev/null)" ]]; then
  git_dirty=true
fi
new_provenance="$(mktemp "$BIN_DIR/.provenance.json.XXXXXX")"
wg_version="$(sed -n 's/^# golang\.zx2c4\.com\/wireguard //p' "$GO_DIR/vendor/modules.txt")"
engine_commit="$(sed -nE 's/^const WireGuardCommit = "([0-9a-f]+)"$/\1/p' "$GO_DIR/engine/engine.go")"
{
  printf '{\n'
  printf '  "app_version": "%s",\n' "$APP_VERSION"
  printf '  "build": "%s",\n' "$APP_BUILD"
  printf '  "go": "%s",\n' "$go_version"
  printf '  "xcode": "%s (%s)",\n' "$xcode_version" "$xcode_build"
  printf '  "engine_module": "golang.zx2c4.com/wireguard",\n'
  printf '  "engine_version": "%s",\n' "$wg_version"
  printf '  "engine_commit": "%s",\n' "$engine_commit"
  printf '  "script_sha256": "%s",\n' "$(script_sha)"
  printf '  "source_sha256": "%s",\n' "$SCRIPT_SHA"
  printf '  "toolchain_sha256": "%s",\n' "$TOOLCHAIN_SHA"
  printf '  "source_revision": "%s",\n' "$git_rev"
  printf '  "source_engine_dirty": %s,\n' "$git_dirty"
  printf '  "go_flags": "GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off -trimpath -buildvcs=false",\n'
  printf '  "slices": {\n'
  sep=""
  for s in $slices; do
    slice_params "$s"
    printf '%s    "%s": { "target": "%s", "goos": "%s", "sdk": "%s", "libwgex_sha256": "%s" }' \
      "$sep" "$s" "$TRIPLE_FOR" "$GOOS_FOR" "$(xcrun --sdk "$SDK_FOR" --show-sdk-version)" "$(sha256 "$OUT/$s/libwgex.a")"
    sep=$',\n'
  done
  printf '\n  },\n'
  printf '  "built_at": "%s"\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '}\n'
} >"$new_provenance"
publish "$new_provenance" "$BIN_DIR/provenance.json"
new_provenance=""

log "done: ${XCF#"$ROOT"/} ($slices)"
