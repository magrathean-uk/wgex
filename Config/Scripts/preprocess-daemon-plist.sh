#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Expands ${WGEX_BUNDLE_ID_BASE} in the daemon launchd plist template and
# validates the result: well-formed, no EnvironmentVariables key (plan 03 §4).
# Usage: preprocess-daemon-plist.sh <template> <output> [bundle-id-base]
# Xcode calls it as a run-script phase with SCRIPT_INPUT_FILE_0 and
# SCRIPT_OUTPUT_FILE_0; the base then comes from WGEX_BUNDLE_ID_BASE.
set -euo pipefail

template="${1:-${SCRIPT_INPUT_FILE_0:?template path missing}}"
output="${2:-${SCRIPT_OUTPUT_FILE_0:?output path missing}}"
base="${3:-${WGEX_BUNDLE_ID_BASE:?WGEX_BUNDLE_ID_BASE is not set}}"

if [[ ! "$base" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]]; then
  echo "preprocess-daemon-plist: invalid bundle identifier base" >&2
  exit 1
fi

mkdir -p "$(dirname "$output")"
sed "s/\${WGEX_BUNDLE_ID_BASE}/$base/g" "$template" >"$output"

# shellcheck disable=SC2016 # a literal ${ means an unexpanded template variable
if grep -q '\${' "$output"; then
  echo "preprocess-daemon-plist: unexpanded variable in $output" >&2
  exit 1
fi
if grep -qE '<key>[[:space:]]*EnvironmentVariables[[:space:]]*</key>' "$output"; then
  echo "preprocess-daemon-plist: EnvironmentVariables key is forbidden" >&2
  exit 1
fi
plutil -lint -s "$output"
label="$(plutil -extract Label raw -o - "$output")"
if [[ "$label" != "$base.daemon" ]]; then
  echo "preprocess-daemon-plist: Label is $label, expected $base.daemon" >&2
  exit 1
fi
