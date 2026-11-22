#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Verifies engine archives before they are packaged (plan 03 §6 step 3).
#
# Usage: verify-slices.sh [--test-support] <dir>...
#   Each <dir> holds one subdirectory per slice whose name starts with the
#   platform (macos, ios, tvos; for example out/macos or macos-arm64 inside an
#   XCFramework) and contains "simulator" for a simulator slice
#   (out/ios-simulator, ios-arm64-simulator), holding libwgex.a. With no <dir>, the production
#   XCFramework in Packages/WGEXEngine/Binary is verified.
#
# Every archive member, including go.o, must carry LC_BUILD_VERSION with the
# slice's platform (macOS 1, iOS 2, tvOS 3, iOS Simulator 7, tvOS Simulator 8)
# and minos 26.0 for macOS, 27.0 for all other slices. Production archives
# must export wgex_build_info and wgex_free, must contain no _wgex_test_ symbol
# and no gvisor.dev code or module. --test-support instead requires
# _wgex_test_ping and skips the production-only checks.
set -euo pipefail
# shellcheck source=Engine/scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

mode=production
if [[ "${1:-}" == "--test-support" ]]; then
  mode=test-support
  shift
fi
if (($# == 0)); then
  set -- "$BIN_DIR/WGEXEngine.xcframework"
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/wgex-verify.XXXXXX")"
trap 'rm -rf "$work"' EXIT

failures=0
fail() {
  printf 'FAIL %s\n' "$*" >&2
  failures=$((failures + 1))
}

# verify_archive <slice> <archive>
verify_archive() {
  local slice="$1" archive="$2" dir member members dups lc platform minos n=0 syms gvm
  slice_params "$slice"
  printf -- '--- %s (%s): %s\n' "$slice" "$TRIPLE_FOR" "${archive#"$ROOT"/}"

  members="$(ar -t "$archive" | grep -v '^__\.SYMDEF')" || true
  [[ -n "$members" ]] || {
    fail "$slice: no members in archive"
    return
  }
  grep -qx 'go.o' <<<"$members" || fail "$slice: go.o missing from archive"
  dups="$(printf '%s\n' "$members" | sort | uniq -d)"
  [[ -z "$dups" ]] || fail "$slice: duplicate member names, cannot verify each: $dups"

  dir="$work/$slice-$(sha256 "$archive" | cut -c1-12)"
  mkdir -p "$dir"
  (cd "$dir" && ar -x "$archive")

  while IFS= read -r member; do
    n=$((n + 1))
    lc="$(otool -l "$dir/$member" | awk '
      $1 == "cmd" { inbv = ($2 == "LC_BUILD_VERSION"); if ($2 ~ /^LC_VERSION_MIN_/) legacy = 1 }
      inbv && $1 == "platform" { p = p $2 " " }
      inbv && $1 == "minos" { m = m $2 " " }
      END { printf "%s|%s|%s", p, m, legacy }')"
    platform="${lc%%|*}"
    minos="${lc#*|}"
    minos="${minos%%|*}"
    if [[ "$lc" == *"|1" ]]; then
      fail "$slice/$member: legacy LC_VERSION_MIN_* load command"
    fi
    if [[ "$platform" != "$PLATFORM_FOR " || "$minos" != "$MIN_OS " ]]; then
      fail "$slice/$member: LC_BUILD_VERSION platform='${platform% }' minos='${minos% }', want platform=$PLATFORM_FOR minos=$MIN_OS"
    fi
  done <<<"$members"
  printf '    %d members checked (want LC_BUILD_VERSION platform %s minos %s)\n' "$n" "$PLATFORM_FOR" "$MIN_OS"

  syms="$(nm -gU "$archive" 2>/dev/null | awk 'NF >= 3 { print $3 }')"
  if [[ "$mode" == test-support ]]; then
    grep -qx '_wgex_test_ping' <<<"$syms" || fail "$slice: _wgex_test_ping not exported"
  else
    grep -qx '_wgex_build_info' <<<"$syms" || fail "$slice: _wgex_build_info not exported"
    grep -qx '_wgex_free' <<<"$syms" || fail "$slice: _wgex_free not exported"
    # Captured first: under pipefail, producer | grep -q can report SIGPIPE
    if [[ "$(nm "$archive" 2>/dev/null)" == *_wgex_test_* ]]; then
      fail "$slice: _wgex_test_ symbols in a production archive"
    fi

    # go version -m cannot read c-archives (exit 1, no output, Go 1.27.3), so
    # use it when it can and always scan the archive bytes: linked gvisor code
    # leaves gvisor.dev in symbol names, file paths and the embedded module info.
    gvm="$(go version -m "$archive" 2>/dev/null || true)"
    if [[ "$gvm" == *gvisor.dev* ]]; then
      fail "$slice: go version -m lists gvisor.dev"
    fi
    LC_ALL=C grep -aq 'golang\.zx2c4\.com/wireguard' "$dir/go.o" ||
      fail "$slice: module info for golang.zx2c4.com/wireguard not found in go.o; gvisor scan would be vacuous"
    if LC_ALL=C grep -aq 'gvisor\.dev' "$archive"; then
      fail "$slice: gvisor.dev found in a production archive"
    fi
  fi
}

archives=0
for root in "$@"; do
  [[ -d "$root" ]] || die "not a directory: $root"
  # Absolute, because members are extracted from inside a scratch directory
  root="$(cd "$root" && pwd)"
  for sub in "$root"/*/; do
    sub="${sub%/}"
    [[ -f "$sub/libwgex.a" ]] || continue
    name="$(basename "$sub")"
    case "$name" in
      macos*simulator*) die "no macOS simulator slice exists: $sub" ;;
      macos*) slice=macos ;;
      tvos*simulator*) slice=tvos-simulator ;;
      tvos*) slice=tvos ;;
      ios*simulator*) slice=ios-simulator ;;
      ios*) slice=ios ;;
      *) die "cannot tell the slice of $sub" ;;
    esac
    verify_archive "$slice" "$sub/libwgex.a"
    archives=$((archives + 1))
  done
done

((archives > 0)) || die "no libwgex.a found under: $*"
if ((failures > 0)); then
  printf 'verify-slices: FAILED (%d problem(s) in %d archive(s))\n' "$failures" "$archives" >&2
  exit 1
fi
printf 'verify-slices: ok (%d archive(s), mode %s)\n' "$archives" "$mode"
