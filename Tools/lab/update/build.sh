#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# M5.3-07 update bundle: a second Lab build of this commit with a higher CURRENT_PROJECT_VERSION, made by the ordinary
# Lab build script (same inputs, same ad hoc Lab signing class, DEC-007) into its own build root, so the base build is
# never replaced. Build only; never boots a VM or launches WGEX. A real build is a heavy job (one per project).
set -euo pipefail
root="$(CDPATH='' cd -- "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
dry=()
if [[ "${1:-}" == --dry-run ]]; then
  dry=(--dry-run)
  shift
fi
if (($# != 0)); then
  echo 'usage: update/build.sh [--dry-run]' >&2
  exit 1
fi
helper=(python3 -I -B "$root/Tools/lab/update/update.py")
# WGEX_LAB_UPDATE_VERSION may raise the version further; it must stay above the base build's (anti-downgrade floor).
version="$("${helper[@]}" version "${WGEX_LAB_UPDATE_VERSION:-}")"
base="$("${helper[@]}" build-base)"
app="$("${helper[@]}" path)"
WGEX_BUILD_ROOT="$base" WGEX_LAB_BUNDLE_VERSION="$version" bash "$root/Tools/lab/tart/build.sh" ${dry[@]+"${dry[@]}"}
if ((${#dry[@]} == 0)); then
  built="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$app/Contents/Info.plist")"
  if [[ "$built" != "$version" ]]; then
    echo 'update: the built bundle version differs from the requested update version' >&2
    exit 1
  fi
fi
printf 'update=%s version=%s\n' "$app" "$version"
