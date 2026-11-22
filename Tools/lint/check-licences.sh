#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Licence policy gate (ADR-001). Scans Vendor/, Packages/, Engine/go (not its
# vendor/ module tree, which go-licenses covers via Tools/lint/notices.py) and
# Tools/ for SPDX identifiers, licence headers and licence files.
#   - Allowed: MIT, BSD-2-Clause, BSD-3-Clause, ISC, Apache-2.0, Zlib.
#   - GPL, LGPL, AGPL, Elastic and SSPL fail anywhere, as does any other
#     SPDX identifier and any LICENSE/COPYING file that is not a recognised
#     allowed text.
# Matched text is never printed; only file, line and rule are reported.
# The gate and its self-test harness are excluded: they must name the forbidden licences.
# Usage: check-licences.sh [dir|file ...]   (default: the repo tree)
set -euo pipefail
# shellcheck source=Tools/lint/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

ALLOWED='MIT BSD-2-Clause BSD-3-Clause ISC Apache-2.0 Zlib'
COPYLEFT='GNU (Affero |Lesser |Library )?General Public License|GNU GPL|\b(A|L)?GPL\b|\b(A|L)?GPL-?[0-9]|Elastic License|Server Side Public License|\bSSPL\b'
MPL_TEXT='Mozilla Public License'
# An SPDX header is a comment line; prose that merely mentions the tag is not one.
SPDX_LINE='^[[:space:]]*(//|#|/\*|\*|--|;|<!--)[[:space:]]*SPDX-License-Identifier:'
LICENCE_TEXTS='Permission is hereby granted, free of charge|Apache License|Redistribution and use in source and binary forms|Permission to use, copy, modify, and/or distribute this software|This software is provided .as-is.|Mozilla Public License'

found=0
scanned=0
fail() { # fail <relative path> <message>
  echo "licence: $1: $2" >&2
  found=1
}

# check_file <absolute path> <path relative to its root>
check_file() {
  local f="$1" r="$2" lines id ids base
  grep -qI . "$f" 2>/dev/null || return 0 # binary or empty
  scanned=$((scanned + 1))

  lines="$(grep -nIiE -e "$COPYLEFT" "$f" | cut -d: -f1 | paste -sd, - || true)"
  [[ -n "$lines" ]] && fail "$r" "copyleft or restricted licence text, line(s) $lines"

  lines="$(grep -nIE -e "$MPL_TEXT" "$f" | cut -d: -f1 | paste -sd, - || true)"
  if [[ -n "$lines" ]]; then
    fail "$r" "MPL-2.0 text is not allowed, line(s) $lines"
  fi

  # SPDX identifiers: every token of every expression must be allowed.
  ids="$(grep -hIE "$SPDX_LINE" "$f" | sed -E 's/.*SPDX-License-Identifier:[[:space:]]*//' |
    tr -c 'A-Za-z0-9.+\n-' ' ' | tr ' ' '\n' | grep -E '^[A-Za-z0-9]' | grep -v -E '^(AND|OR|WITH)$' | sort -u || true)"
  for id in $ids; do
    if [[ " $ALLOWED " == *" $id "* ]]; then
      continue
    else
      fail "$r" "SPDX identifier '$id' is not on the allowlist"
    fi
  done

  base="$(basename "$f")"
  case "$base" in
    LICENSE | LICENSE.* | LICENCE | LICENCE.* | COPYING | COPYING.*)
      if ! grep -qIE -e "$LICENCE_TEXTS" "$f"; then
        fail "$r" "licence file is not a recognised allowed licence text"
      fi
      ;;
  esac
}

if (($#)); then
  for arg in "$@"; do
    if [[ -d "$arg" ]]; then
      root="${arg%/}"
      while IFS= read -r -d '' f; do
        check_file "$f" "${f#"$root"/}"
      done < <(find "$root" -type f -print0)
    else
      check_file "$arg" "$(basename "$arg")"
    fi
  done
else
  # Repository mode fails closed: git must list the files and the repository always has some to scan (M1-32).
  load_repo_files Vendor Packages Engine/go Tools Apps Daemon Extensions Config \
    ':!:Engine/go/vendor/**' ':!:Tools/*/vendor/**' ':!:Tools/lint/check-licences.sh' ':!:Tools/lint/run-selftests.sh' \
    ':!:Config/Scripts/tests/run.py' || exit 1 # This harness also names restricted-licence fixtures.
  if ((${#REPO_FILES[@]} == 0)); then
    echo 'check-licences: no files to scan; the repository listing is empty (a broken index or listing)' >&2
    exit 1
  fi
  for f in "${REPO_FILES[@]}"; do
    check_file "$f" "$(rel "$f")"
  done
fi

if (($# == 0)); then
  # Whole-tree run: check the vendor ledger and the explicit wgextest-only
  # module notices (gvisor, google/btree and x/time), including licence texts.
  for module in gvisor.dev/gvisor github.com/google/btree golang.org/x/time; do
    licence="Engine/go/vendor/$module/LICENSE"
    if [[ -f "$LINT_ROOT/$licence" ]]; then
      check_file "$LINT_ROOT/$licence" "$licence"
    else
      fail "$licence" "missing test-support licence"
    fi
  done
  python3 -I "$LINT_ROOT/Tools/lint/notices.py" --check >&2 || found=1
fi

if ((found)); then
  echo "check-licences: FAIL (allowed: $ALLOWED)" >&2
  exit 1
fi
echo "check-licences: ok ($scanned text files scanned)"
