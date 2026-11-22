#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
# shellcheck source=Tools/lab/tart/lib.sh
source "$(dirname "$0")/lib.sh"
# shellcheck source=Config/Scripts/lib.sh
source "$LAB_ROOT/Config/Scripts/lib.sh"
lab_init "${1:-}"
[[ "${1:-}" != --dry-run ]] || shift
app="${1:?usage: install-app.sh [--dry-run] PATH/TO/WGEX.app}"
(($# == 1)) || lab_die 'unexpected install argument'
[[ -d "$app" && "${app##*/}" == WGEX.app ]] || lab_die 'WGEX.app bundle required'
app="$(cd "$(dirname "$app")" && pwd)/${app##*/}"
lab_local codesign --verify --deep --strict "$app" || lab_die 'bundle must be signed and signature valid'
lab_local codesign -dv "$app" 2>&1 || lab_die 'bundle must be signed'
[[ -f "$app.lab-build.sha256" ]] || lab_die 'Lab build receipt missing; use lab build'
(cd "$app" && lab_local shasum -a 256 -c "$app.lab-build.sha256") || lab_die 'Lab build receipt does not match bundle'
if [[ "$LAB_DRY" != 1 ]]; then
  python3 -I -B "$LAB_ROOT/Tools/lab/check-verdicts.py" --inspect-build "$app" >/dev/null || lab_die 'Lab provenance receipt does not match checkout or bundle'
fi
fallback="${WGEX_WRAPPING_KEY_FALLBACK:-1}"
[[ "$fallback" == 0 || "$fallback" == 1 ]] || lab_die 'WGEX_WRAPPING_KEY_FALLBACK must be 0 or 1'
lab_connect
guest_is_lab
stage="/Users/$LAB_USER/lab/install-stage"
lab_ssh "mkdir -p '$stage'" </dev/null
# Archive with ditto to preserve symlinks, resource forks and signatures across scp.
archive_dir="$(build_root)/lab-install-dry-run"
if [[ "$LAB_DRY" != 1 ]]; then
  mkdir -p "$(build_root)"
  archive_dir="$(mktemp -d "$(build_root)/lab-install.XXXXXX")"
  trap 'rm -rf "$archive_dir"' EXIT
fi
lab_mutate ditto -c -k --sequesterRsrc --keepParent "$app" "$archive_dir/WGEX.zip"
lab_scp "$archive_dir/WGEX.zip" "$LAB_USER@$LAB_ADDRESS:$stage/" </dev/null
lab_ssh "set -eu; rm -rf '$stage/WGEX.app'; ditto -x -k '$stage/WGEX.zip' '$stage'; codesign --verify --deep --strict '$stage/WGEX.app'; sudo -n rm -rf /Applications/WGEX.app; sudo -n ditto '$stage/WGEX.app' /Applications/WGEX.app; codesign --verify --deep --strict /Applications/WGEX.app; rm -rf '$stage/WGEX.app' '$stage/WGEX.zip'" </dev/null
# The daemon's wrapping key lives in the guest's System keychain; provision it once per guest.
lab_scp "$LAB_DIR/guest/wrapping-key.sh" "$LAB_DIR/guest/guard.sh" "$LAB_USER@$LAB_ADDRESS:$stage/" </dev/null
# shellcheck disable=SC2016 # the label is read on the guest from the installed plist name
lab_ssh "set -eu; label=\$(basename /Applications/WGEX.app/Contents/Library/LaunchDaemons/*.plist .plist); WGEX_WRAPPING_KEY_FALLBACK='$fallback' bash '$stage/wrapping-key.sh' \"\$label\"; rm -f '$stage/wrapping-key.sh' '$stage/guard.sh'" </dev/null
