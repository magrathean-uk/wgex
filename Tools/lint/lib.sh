# SPDX-License-Identifier: MIT
# shellcheck shell=bash
# Shared helpers for Tools/lint scripts. Source, do not execute.

LINT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export WGEX_LINT_ROOT="$LINT_ROOT"

# Pathspecs for trees that are not first-party source, used by the code
# linters (shellcheck, shfmt) but not by the public-prose check, which reads
# everything: the vendored Go module tree (third-party code) and the design
# tool's scratch directories (another workflow's working files).
# Keep in step with typos.toml, .swiftlint.yml and .swiftformat.
# shellcheck disable=SC2034 # used by the scripts that source this file
NOT_FIRST_PARTY=(
  ':!:Engine/go/vendor/**'
  ':!:Design/.work/**'
  ':!:Design/.taste-skill/**'
)

# Pathspecs for the typos step in lint.sh, shared with run-selftests.sh so the
# self-test proves the same selection. Machine-written lab verdicts are out:
# their 12-hex digests read as words (M1-10f); the per-row README.md stays in.
# shellcheck disable=SC2034 # used by the scripts that source this file
TYPOS_PATHSPEC=(
  ':!:.plan/**'
  ':!:Vendor/**'
  ':!:Tests/Reports/**/*.xcodeproj/**'
  ':!:Tests/Reports/**/*.log'
  ':!:Tests/Reports/**/verdict*.json'
  ':!:Design/mac-v2/*.dc.html'
  "${NOT_FIRST_PARTY[@]}"
)

# load_repo_files [pathspec...]: fills the array REPO_FILES with the index and tracked working-tree files (absolute
# paths), excluding the linter self-test fixtures. It fails closed (M1-32): when git cannot list files (dubious
# ownership, a broken index, no repository, no git) it prints "lint: git could not list repository files: <git's
# first stderr line>" and returns 1. Call it directly, never inside `< <(...)` or `$(...)`, which hide the status
# and the array, and stop on a non-zero return:  load_repo_files '*.sh' || exit 1
# An empty REPO_FILES is a success here (the pathspec may match nothing); a caller that knows the repository always
# holds such files must treat an empty result as a failure.
REPO_FILES=()
load_repo_files() {
  REPO_FILES=()
  local scratch rc=0 first="" f
  scratch="$(mktemp -d "${TMPDIR:-/tmp}/wgex-repo-files.XXXXXX")" || {
    echo 'lint: cannot create a scratch directory to list repository files' >&2
    return 1
  }
  git -C "$LINT_ROOT" ls-files -z --cached --deduplicate -- "$@" ':!:Tools/lint/tests/**' >"$scratch/list" 2>"$scratch/err" || rc=$?
  if ((rc != 0)); then
    IFS= read -r first <"$scratch/err" || true
    rm -rf "$scratch"
    printf 'lint: git could not list repository files: %s\n' "${first:-git exited with status $rc}" >&2
    return 1
  fi
  while IFS= read -r -d '' f; do
    if [[ -f "$LINT_ROOT/$f" ]]; then REPO_FILES+=("$LINT_ROOT/$f"); fi
  done <"$scratch/list"
  rm -rf "$scratch"
}

# repo_files [pathspec...]: the same list on stdout, NUL-separated, for stream consumers (the tooling self-test reads
# it so). It fails closed too, but inside `< <(...)` the status is lost, so the lint scripts use load_repo_files.
repo_files() {
  load_repo_files "$@" || return 1
  if ((${#REPO_FILES[@]} > 0)); then printf '%s\0' "${REPO_FILES[@]}"; fi
}

# expand_args <path...>: files given directly, or every file under a directory, NUL-separated
expand_args() {
  local p
  for p in "$@"; do
    if [[ -d "$p" ]]; then
      find "$p" -type f -print0
    else
      printf '%s\0' "$p"
    fi
  done
}

# rel <path>: path relative to the repo root, for messages
rel() { printf '%s' "${1#"$LINT_ROOT"/}"; }

# Build-independent linters use only persistent dependency caches.
# shellcheck source=Config/Scripts/lib.sh
source "$LINT_ROOT/Config/Scripts/lib.sh"
GOCACHE="$(dependency_cache)/go"
export GOCACHE
STATICCHECK_CACHE="$(dependency_cache)/staticcheck"
export STATICCHECK_CACHE
