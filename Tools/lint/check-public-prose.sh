#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# One fixed-string grep pass over each file set; never emit matched text.
# POSIX mode (POSIXLY_CORRECT, SHELLOPTS=posix, bash --posix) has no process substitution in bash 3.2, and a syntax error
# there let this check end with status 0 and no verdict. Leave it before anything else is parsed: re-exec this same
# interpreter ("$BASH", not whatever `bash` PATH finds) without the variables and startup files that switch it on. A
# startup file could switch POSIX mode back on in the new process, so the re-exec happens at most once
# (WGEX_PROSE_REEXEC) and a second sighting of POSIX mode fails closed with status 2 instead of looping.
# Run as `sh`, "$BASH" is /bin/sh, which is POSIX by its own name, so that case re-execs /bin/bash instead.
case ":${SHELLOPTS-}:" in
  *:posix:*)
    if [[ -n "${WGEX_PROSE_REEXEC-}" ]]; then
      echo 'check-public-prose: POSIX mode is still on after one re-exec (a startup file switches it on); refusing to run' >&2
      exit 2
    fi
    interpreter="$BASH"
    case "${BASH##*/}" in sh) interpreter=/bin/bash ;; esac
    exec env -u POSIXLY_CORRECT -u SHELLOPTS -u BASH_ENV -u ENV WGEX_PROSE_REEXEC=1 "$interpreter" "${BASH_SOURCE[0]}" "$@"
    ;;
esac
set -euo pipefail
# shellcheck source=Tools/lint/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
work="$(mktemp -d "${TMPDIR:-/tmp}/wgex-prose.XXXXXX")"
# The trap fails closed: bash 3.2 hands an EXIT trap status 0 after a shell error under set -e (unbound variable, ${x:?},
# readonly, bad substitution, failed source), so the script sets finished=1 just before each intended successful end.
# finished=0 first: an exported finished=1 in the caller must not mark an erroring script as finished.
finished=0
trap 'rc=$?; ((rc != 0)) || ((${finished:-0})) || rc=1; rm -rf "$work"; exit "$rc"' EXIT
grep -v -e '^[[:space:]]*$' -e '^#' "$LINT_ROOT/Tools/lint/public-prose-denylist.txt" >"$work/patterns"
[[ -s "$work/patterns" ]] || {
  echo 'check-public-prose: empty denylist' >&2
  exit 1
}
files=()
if (($#)); then
  while IFS= read -r -d '' f; do
    relative="$(rel "$f")"
    relative="${relative#./}"
    case "$relative" in .plan/*) continue ;; esac
    files+=("$f")
  done < <(expand_args "$@")
else
  # Repository mode fails closed: git must list the files, and a repository always has some to scan (M1-32).
  load_repo_files ':!:.plan/**' ':!:Tools/lint/public-prose-denylist.txt' || exit 1
  if ((${#REPO_FILES[@]} == 0)); then
    echo 'check-public-prose: no files to scan; the repository listing is empty (a broken index or listing)' >&2
    exit 1
  fi
  files=("${REPO_FILES[@]}")
fi
status=0
if ((${#files[@]})); then
  # -l gives filenames only; no private matched text reaches a log or temp file.
  grep -IlFi -f "$work/patterns" -- "${files[@]}" >"$work/matches" || status=$?
  if ((status > 1)); then
    echo 'check-public-prose: grep failed' >&2
    exit "$status"
  fi
  if [[ -s "$work/matches" ]]; then
    python3 -I "$LINT_ROOT/Tools/lint/prose-report.py" "$work/patterns" "$work/matches" "$LINT_ROOT"
    echo 'check-public-prose: FAIL' >&2
    exit 1
  fi
fi
finished=1
echo 'check-public-prose: ok'
