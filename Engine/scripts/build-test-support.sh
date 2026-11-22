#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Builds the test-support engine XCFramework (plan 03 §6 step 5, ADR-006).
#
# Usage: build-test-support.sh [--clean]
#   macOS slice only, built with -tags wgextest so the testsupport package
#   (wgex_test_* exports; netstack pairs from P1-18) is linked in. Output:
#   Packages/WGEXEngine/Binary/WGEXEngineTest.xcframework, Clang module
#   CWGEXEngineTest. It replaces WGEXEngine.xcframework in test targets and is
#   never linked into a product; two Go c-archives cannot share one binary.
#   Reuse needs the source digest and the compiling toolchain to match, as for the production archive.
#   Outputs are built under a temporary name in the same directory and renamed
#   into place (M1-28), so a symlink at the final name is replaced, never followed.
#   A linked Binary directory or parent is refused, one build per tree runs at a time (lock beside
#   Binary), and a dead writer's temporaries are removed at the start of the next build.
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
case "${1:-}" in
  "") ;;
  --clean) clean=1 ;;
  *) die "unknown argument '$1' (usage: build-test-support.sh [--clean])" ;;
esac

require_own_binary
assert_toolchain macosx
detect_toolchain
app_version_values
SCRIPT_SHA="$(source_digest)"
configure_caches
BUILD="$(build_root)"
OUT="${WGEX_ENGINE_TEST_OUT:-$BUILD/engine/out-test}"
XCF="$BIN_DIR/WGEXEngineTest.xcframework"
cache="$(dependency_cache)/go-macos-wgextest"
# One build per tree at a time: take the lock before the up-to-date check, so a waiting writer sees the winner's build.
acquire_binary_lock "$BIN_DIR"
remove_build_leftovers "$BIN_DIR"
if ((clean == 0)) && python3 -I "$ENGINE_SCRIPTS/source-digest.py" --verify "$BIN_DIR" --test-support --toolchain "${toolchain[@]}" 2>/dev/null; then
  log "engine-test: source digest and toolchain match; using existing test-support XCFramework"
  exit 0
fi

rm -rf "$OUT"
if ((clean)); then
  cache="$BUILD/engine/gocache/macos-wgextest"
  rm -rf "$cache"
fi
build_slice macos "$OUT/macos" "$cache" wgextest
mkdir -p "$OUT/macos/include"
cp "$GO_DIR/bridge/wgex.h" "$GO_DIR/testsupport/wgex_test.h" "$GO_DIR/testsupport/module.modulemap" \
  "$OUT/macos/include/"

log "verify test-support slice"
"$ENGINE_SCRIPTS/verify-slices.sh" --test-support "$OUT"

log "assemble $(basename "$XCF")"
new_xcf="$BIN_DIR/.new-$$-$(basename "$XCF")"
create_xcframework "$new_xcf" -library "$OUT/macos/libwgex.a" -headers "$OUT/macos/include"
publish "$new_xcf" "$XCF"
new_xcf=""
new_provenance="$(mktemp "$BIN_DIR/.provenance-test.json.XXXXXX")"
printf '{"source_sha256":"%s","toolchain_sha256":"%s","go":"%s","xcode":"%s (%s)","slices":{"macos":{"libwgex_sha256":"%s"}}}\n' \
  "$SCRIPT_SHA" "$TOOLCHAIN_SHA" "$go_version" "$xcode_version" "$xcode_build" "$(sha256 "$OUT/macos/libwgex.a")" >"$new_provenance"
publish "$new_provenance" "$BIN_DIR/provenance-test.json"
new_provenance=""
log "done: ${XCF#"$ROOT"/}"
