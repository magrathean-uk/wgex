#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Fails on any EnvironmentVariables key in a launchd plist or plist template
# under Daemon/ (plan 03 §4: environment never reaches the privileged daemon).
# Usage: check-launchd-plists.sh [file|dir ...]   (default: Daemon/**/*.plist*)
set -euo pipefail
# shellcheck source=Tools/lint/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

plists=()
if (($#)); then
  while IFS= read -r -d '' f; do plists+=("$f"); done < <(expand_args "$@")
else
  # Repository mode fails closed: git must list the files and the repository always has the daemon's plist (M1-32).
  load_repo_files 'Daemon/**/*.plist*' || exit 1
  if ((${#REPO_FILES[@]} == 0)); then
    echo 'check-launchd-plists: no Daemon plists in the repository listing (a broken index or listing)' >&2
    exit 1
  fi
  plists=("${REPO_FILES[@]}")
fi

found=0
checked=0
for f in ${plists[@]+"${plists[@]}"}; do
  case "$f" in *.plist | *.plist.*) ;; *) continue ;; esac
  checked=$((checked + 1))
  # Binary plists are converted; XML and .plist.in templates are read as text.
  if head -c 6 "$f" | grep -q '^bplist'; then
    text="$(plutil -convert xml1 -o - "$f")"
  else
    text="$(cat "$f")"
  fi
  if grep -qE '<key>[[:space:]]*EnvironmentVariables[[:space:]]*</key>' <<<"$text"; then
    echo "EnvironmentVariables key in launchd plist: $(rel "$f")" >&2
    found=1
  fi
done

if ((found)); then
  echo "check-launchd-plists: FAIL" >&2
  exit 1
fi
echo "check-launchd-plists: ok ($checked plist(s))"
