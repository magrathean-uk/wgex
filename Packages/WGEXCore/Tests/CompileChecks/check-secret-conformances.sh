#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Positive control plus compiler-enforced negative assertions; no secret bytes.
# Usage: check-secret-conformances.sh [module-directory] [module-cache-path]
# Defaults are in the canonical WGEXCore scratch build, never the checkout .build.
set -euo pipefail
work="$(mktemp -d "${TMPDIR:?}/wgex-conformances.XXXXXX")"
trap 'rm -rf "$work"' EXIT
# shellcheck source=Config/Scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/../../../../Config/Scripts/lib.sh"
module_dir="${1:-$(build_root)/spm/shared/arm64-apple-macosx/debug/Modules}"
module_cache="${2:-$(build_root)/secret-conformance-module-cache}"
if [[ ! -d "$module_dir/WGEXCore.swiftmodule" ]]; then
  echo "WGEXCore module missing from supplied build directory: $module_dir" >&2
  exit 1
fi
cat >"$work/control.swift" <<'SWIFT'
import WGEXCore
func check<T: ~Copyable & Sendable>(_: T.Type) {}
check(SecretBytes.self)
check(PrivateKey.self)
check(PresharedKey.self)
check(ParsedSecrets.self)
check(SecretText.self)
check(ParsedConfiguration.self)
check(UAPIDocument.self)
SWIFT
xcrun swiftc -typecheck -module-cache-path "$module_cache" -swift-version 6 -I "$module_dir" "$work/control.swift"
for secret_type in SecretBytes PrivateKey PresharedKey ParsedSecrets SecretText ParsedConfiguration UAPIDocument; do
  for conformance in Encodable Decodable CustomStringConvertible CustomDebugStringConvertible Copyable; do
    cat >"$work/rejected.swift" <<SWIFT
import WGEXCore
func require<T: $conformance>(_: T.Type) {}
require($secret_type.self)
SWIFT
    if xcrun swiftc -typecheck -module-cache-path "$module_cache" -swift-version 6 -I "$module_dir" "$work/rejected.swift" >"$work/compiler.log" 2>&1; then
      echo "Unexpected conformance: $secret_type $conformance" >&2
      exit 1
    fi
    if ! grep -q "'$secret_type'.*'$conformance'" "$work/compiler.log"; then
      cat "$work/compiler.log" >&2
      exit 1
    fi
  done
done
echo 'Secret conformance checks: 7 Sendable controls and 35 expected compilation failures passed'
