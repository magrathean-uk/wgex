#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Inspect built Mach-O files only. Never launches any product.
set -euo pipefail
# shellcheck source=Engine/scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

products="$(build_root)/derived-data/Build/Products"
# Release checks inspect the Mac gate or every platform when requested.
if [[ "${1:-}" == --release ]]; then
  release_platform="${2:-all}"
  release_mode="${3:-ordinary}"
  [[ "$release_platform" == mac || "$release_platform" == all ]] || die "release platform must be mac or all"
  [[ "$release_mode" == ordinary || "$release_mode" == own-mac ]] || die "release mode must be ordinary or own-mac"
  [[ "$release_mode" != own-mac || "$release_platform" == mac ]] || die "own-Mac release mode requires mac"
  (($# <= 3)) || die "unexpected release-link arguments"
  # The marker is the own-Mac leaf common name: WGEX_OWN_MAC_LEAF, else the value in the git-ignored
  # Config/Local.xcconfig. Without either (an ordinary check on a clean checkout), any Apple Development
  # leaf-shaped string counts as the marker; own-Mac mode needs the exact value.
  own_mac_leaf="${WGEX_OWN_MAC_LEAF:-}"
  if [[ -z "$own_mac_leaf" && -f "$ROOT/Config/Local.xcconfig" ]]; then
    own_mac_leaf="$(sed -nE 's/^[[:space:]]*WGEX_OWN_MAC_LEAF[[:space:]]*=[[:space:]]*(.*[^[:space:]])[[:space:]]*$/\1/p' "$ROOT/Config/Local.xcconfig" | tail -n 1)"
  fi
  [[ "$release_mode" != own-mac || -n "$own_mac_leaf" ]] || die "own-Mac release mode needs WGEX_OWN_MAC_LEAF in Config/Local.xcconfig"
  work="$(mktemp -d "${TMPDIR:?}/wgex-release-link.XXXXXX")"
  trap 'rm -rf "$work"' EXIT
  forbidden='labEscapeHatch|LabDiagnostics|LabFileSecretStore|FakeTunnelBackend|FakeServiceController|WGEXTesting|WGEXDaemonCoreTesting|InMemoryXPCTransport|InMemoryDaemonKeyProvider|TemporarySecureInstallSystem|PFFileTokenJournal|LabHooks|LabPowerInjector|FakeDNSSession|FakeRouteKernel|FakeEngineResolver|FakeKillSwitchMonitor|FakePowerMonitor|FakeLoginSessionMonitor|FakeRouteMonitor|FakeUnderlayMonitor|wgex_test_|CWGEXEngineTest|com\.magrathean\.WGEXApp\.lab'
  for binary in \
    "$products/Release/WGEX.app/Contents/MacOS/WGEXDaemon" \
    "$products/Release/WGEX.app/Contents/MacOS/WGEX" \
    "$products/Release-iphonesimulator/WGEX.app/WGEX" \
    "$products/Release-appletvsimulator/WGEX.app/WGEX"; do
    [[ "$release_platform" != mac || "$binary" != *simulator* ]] || continue
    [[ -f "$binary" ]] || die "missing Release product: $binary; run just build all release"
    nm "$binary" >"$work/nm" 2>/dev/null
    xcrun swift-demangle <"$work/nm" >"$work/demangled"
    strings -a "$binary" >"$work/strings"
    if grep -E "$forbidden" "$work/nm" "$work/demangled" "$work/strings" >"$work/matches"; then
      die "Release contains lab/testing symbols or strings: ${binary#"$products"/}"
    fi
    case "$binary" in
      "$products/Release/WGEX.app/Contents/MacOS/WGEXDaemon" | "$products/Release/WGEX.app/Contents/MacOS/WGEX")
        marker_status=0
        if [[ -n "$own_mac_leaf" ]]; then
          grep -F -- "$own_mac_leaf" "$work/strings" >"$work/own-mac-marker" || marker_status=$?
        else
          grep -E 'Apple Development: [^"]+ \([A-Z0-9]{10}\)' "$work/strings" >"$work/own-mac-marker" || marker_status=$?
        fi
        ((marker_status < 2)) || die "cannot check own-Mac marker: ${binary#"$products"/}"
        if [[ "$release_mode" == ordinary && "$marker_status" == 0 ]]; then
          die "ordinary Release contains own-Mac marker: ${binary#"$products"/}"
        elif [[ "$release_mode" == own-mac && "$marker_status" != 0 ]]; then
          die "own-Mac Release is missing own-Mac marker: ${binary#"$products"/}"
        fi
        ;;
    esac
    log "Release nm + strings: clean ${binary#"$products"/}"
  done
  # CodeSignOnCopy can silently strip this slot from an otherwise valid target signature.
  python3 -I - "$products/Release/WGEX.app/Contents/MacOS/WGEXDaemon" <<'PYSIGNATURE'
import pathlib
import struct
import sys

# Mach-O arm64 (the project's fixed architecture), LC_CODE_SIGNATURE and
# CSSLOT_LAUNCH_CONSTRAINT_PARENT from Apple's cs_blobs.h. Read bytes only.
data = pathlib.Path(sys.argv[1]).read_bytes()
if data[:4] != bytes.fromhex("cffaedfe"):
    sys.exit("release-link-check: expected thin arm64 daemon")
offset = 32
for _ in range(struct.unpack_from("<I", data, 16)[0]):
    command, size = struct.unpack_from("<II", data, offset)
    if command == 0x1D:
        signature = struct.unpack_from("<I", data, offset + 8)[0]
        count = struct.unpack_from(">I", data, signature + 8)[0]
        for index in range(count):
            slot, position = struct.unpack_from(">II", data, signature + 12 + index * 8)
            if slot == 9:
                magic, length = struct.unpack_from(">II", data, signature + position)
                if magic == 0xFADE8181 and length > 8:
                    sys.stdout.write("Release daemon parent launch constraint: present\n")
                    sys.exit(0)
        break
    offset += size
sys.exit("release-link-check: embedded daemon parent launch constraint missing")
PYSIGNATURE
  if [[ "$release_platform" == mac ]]; then
    log 'release-link-check: ok (daemon + Mac app)'
  else
    log 'release-link-check: ok (daemon + all three apps)'
  fi
  exit 0
fi
configuration="${1:-Debug}"
failures=0
check() {
  local expectation="$1" binary="$2" symbols
  [[ -f "$binary" ]] || die "missing product: $binary; run just build all debug"
  symbols="$(nm "$binary" 2>/dev/null)"
  if [[ "$expectation" == present ]]; then
    if [[ "$symbols" != *_wgex_build_info* || "$symbols" != *_wgex_create* || "$symbols" != *_wgex_destroy* ]]; then
      log "FAIL: no engine ABI in ${binary#"$products"/}"
      failures=$((failures + 1))
    fi
  elif [[ "$symbols" == *_wgex_* || "$symbols" == *_cgo_* ]]; then
    log "FAIL: engine/runtime in client ${binary#"$products"/}"
    failures=$((failures + 1))
  fi
  if [[ "$symbols" == *FakeEngineResolver* ]]; then
    log "FAIL: test double in ${binary#"$products"/}"
    failures=$((failures + 1))
  fi
  if [[ "$symbols" == *_wgex_test_* ]]; then
    log "FAIL: test exports in ${binary#"$products"/}"
    failures=$((failures + 1))
  fi
  log "$expectation: ${binary#"$products"/}"
}

check present "$products/$configuration/WGEXDaemon"
check absent "$products/$configuration/WGEX.app/Contents/MacOS/WGEX"
check absent "$products/$configuration/wgex"
for platform in iphonesimulator appletvsimulator; do
  check present "$products/$configuration-$platform/WGEXTunnel.appex/WGEXTunnel"
  check absent "$products/$configuration-$platform/WGEX.app/WGEX"
done
((failures == 0)) || die "engine placement failed ($failures problems)"
log "engine-link-check: ok (3 engine hosts, 4 clients; no test exports)"
