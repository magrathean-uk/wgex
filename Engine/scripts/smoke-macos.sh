#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Links a minimal Swift program against the macOS slice of the packaged
# XCFramework (no Xcode project) and runs it: it prints wgex_build_info() and
# fails unless the JSON has the five documented keys and the pinned commit.
#
# Usage: smoke-macos.sh [xcframework]   (default: Packages/WGEXEngine/Binary/WGEXEngine.xcframework)
set -euo pipefail
# shellcheck source=Engine/scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

xcf="${1:-$BIN_DIR/WGEXEngine.xcframework}"
slice="$xcf/macos-arm64"
[[ -f "$slice/libwgex.a" ]] || die "no macOS slice at $slice; run Engine/scripts/build-xcframework.sh first"

work="$(mktemp -d "${TMPDIR:-/tmp}/wgex-smoke.XXXXXX")"
trap 'rm -rf "$work"' EXIT

cat >"$work/main.swift" <<'SWIFT'
import CWGEXEngine
import Foundation

let info = String(cString: wgex_build_info())
print(info)
let object = try JSONSerialization.jsonObject(with: Data(info.utf8)) as? [String: String] ?? [:]
let keys = ["app_version", "build", "engine_commit", "go", "script_sha"]
guard object.keys.sorted() == keys, object["engine_commit"] == CommandLine.arguments[1] else { exit(1) }
SWIFT

# The macOS slice currently links with no extra libraries; CoreFoundation is
# what the iOS and tvOS slices need (Go runtime bundle lookup), passed here so
# the smoke line matches the package's linker settings
xcrun --sdk macosx swiftc -target "arm64-apple-macos$MIN_OS" \
  -I "$slice/Headers" -L "$slice" -lwgex -framework CoreFoundation \
  -o "$work/smoke" "$work/main.swift"

commit="$(sed -nE 's/^const WireGuardCommit = "([0-9a-f]+)"$/\1/p' "$GO_DIR/engine/engine.go")"
"$work/smoke" "$commit"
echo "smoke-macos: ok"
