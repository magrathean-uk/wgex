#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# RT-17: compile the identity-corpus client for the guest. Compile only: it is never run here, and the guest signs each
# variant itself (the client refuses to run outside a lab VM). Universal: the x86_64 slice is the unsigned client, which runs
# under Rosetta. The guest has no developer tools (its lipo is the xcode-select shim), so the host cuts that slice into
# OUTPUT-x86_64 and the guest only copies it.
set -euo pipefail
root="$(CDPATH='' cd -- "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=Config/Scripts/lib.sh
source "$root/Config/Scripts/lib.sh"
if (($# > 1)); then
  echo 'usage: corpus/build.sh [OUTPUT]' >&2
  exit 1
fi
output="${1:-$(build_root)/lab-tools/wgex-corpus-client}"
mkdir -p "$(dirname "$output")"
xcrun --sdk macosx clang -arch arm64 -arch x86_64 -mmacosx-version-min=26.0 -std=gnu11 -fobjc-arc -Wall -Wextra -Werror \
  -framework Foundation "$root/Tools/lab/corpus/client.m" -o "$output"
lipo "$output" -thin x86_64 -output "$output-x86_64"
printf 'corpus-client=%s\n' "$output"
