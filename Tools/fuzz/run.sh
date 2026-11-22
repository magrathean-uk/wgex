#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Offline, time-bounded Swift fuzz campaigns for the M1-14 import and codec targets.
# Usage: Tools/fuzz/run.sh [seconds-per-target (60)] [seed (20261025)]
# Exit status: 0 clean, 1 findings (reproducers written), 2 crash (reproducer saved
# from the pending vector), 3 hang (reproducer saved by the watchdog), other: build error.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
seconds="${1:-${WGEX_FUZZ_SECONDS:-60}}"
seed="${2:-20261025}"
# shellcheck source=Config/Scripts/lib.sh
source "$root/Config/Scripts/lib.sh"
configure_caches
scratch="$(build_root)/spm/fuzz"
pending="$(mktemp -d "${TMPDIR:-/tmp}/wgex-fuzz.XXXXXX")"
trap 'rm -rf "$pending"' EXIT
# Mutations can contain ephemeral keys. Read/replay fixture copies and write
# every pending vector or finding only inside this test's temporary directory.
campaign_root="$pending/fixtures"
mkdir -p "$campaign_root/Tests/Fixtures"
cp -R "$root/Tests/Fixtures/conf" "$root/Tests/Fixtures/fuzz" "$root/Tests/Fixtures/keys" "$campaign_root/Tests/Fixtures/"

# Release build: the 50 ms deadline is meaningful only for optimised code.
swift build -c release --package-path "$root/Tools/fuzz" --scratch-path "$scratch" --cache-path "$(dependency_cache)/swiftpm" >&2
binary="$(swift build -c release --package-path "$root/Tools/fuzz" --scratch-path "$scratch" --cache-path "$(dependency_cache)/swiftpm" --show-bin-path)/swift-fuzz"

[[ "$seconds" =~ ^[0-9]+$ ]] || {
  echo 'seconds must be a non-negative integer' >&2
  exit 2
}
status=0
"$binary" "$campaign_root" "$seconds" "$seed" "$pending" || status=$?

if [ "$status" -gt 128 ] && [ -f "$pending/pending.name" ]; then
  name="$(tr -cd 'A-Za-z0-9_.-' <"$pending/pending.name")"
  findings="$(build_root)/fuzz-findings"
  mkdir -p "$findings"
  retained="$(mktemp -d "$findings/seed-$seed.XXXXXX")"
  reproducer="$retained/${name:-crash}.bin"
  cp "$pending/pending.bin" "$reproducer"
  printf 'fuzz: crash reproducer=%s seed=%s\n' "$reproducer" "$seed"
  exit 2
fi
# Preserve non-crash findings/hangs too, without copying original fixture vectors.
if ((status != 0)); then
  for vector in "$campaign_root/Tests/Fixtures/fuzz/reproducers/"*.bin; do
    [[ -f "$vector" && ! -f "$root/Tests/Fixtures/fuzz/reproducers/${vector##*/}" ]] || continue
    if [[ -z "${retained:-}" ]]; then
      findings="$(build_root)/fuzz-findings"
      mkdir -p "$findings"
      retained="$(mktemp -d "$findings/seed-$seed.XXXXXX")"
    fi
    cp "$vector" "$retained/"
    printf 'fuzz: finding=%s seed=%s\n' "$retained/${vector##*/}" "$seed"
  done
fi
exit "$status"
