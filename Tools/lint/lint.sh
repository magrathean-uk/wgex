#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Tree-wide lint gate behind `just lint`. Runs every linter, then reports all
# failures together. Fixtures under Tools/lint/tests are excluded.
set -uo pipefail
# shellcheck source=Tools/lint/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$LINT_ROOT" || exit 1
export STATICCHECK_CACHE="${STATICCHECK_CACHE:-${XDG_CACHE_HOME:-$HOME/Library/Caches}/staticcheck}"

failed=()
step() { # step <name> <cmd...>
  local name="$1"
  shift
  printf '==> %s\n' "$name"
  if ! "$@"; then
    failed+=("$name")
  fi
}
skip() { printf '==> %s: skipped (%s)\n' "$1" "$2"; }
# A selection that could not be made is a failure, never a skip (M1-32): the repository always holds Swift, shell and
# prose files, so an empty selection can only mean a broken listing. load_repo_files has already named a git failure.
fail_selection() { # fail_selection <message or ""> <step name...>
  local message="$1" name
  shift
  [[ -z "$message" ]] || printf 'lint: %s\n' "$message" >&2
  for name in "$@"; do
    printf '==> %s: FAILED (no file selection)\n' "$name"
    failed+=("$name")
  done
}

count() { tr -cd '\0' | wc -c | tr -d ' '; }

if ! load_repo_files '*.swift' ':!:Vendor/**' ':!:Tests/Reports/**/*.xcodeproj/**' "${NOT_FIRST_PARTY[@]}"; then
  fail_selection "" swiftlint swiftformat
elif ((${#REPO_FILES[@]} == 0)); then
  fail_selection "no tracked Swift files in the repository listing (a broken index or listing)" swiftlint swiftformat
else
  step swiftlint swiftlint lint --strict --no-cache --quiet "${REPO_FILES[@]}"
  step swiftformat swiftformat --lint --cache ignore "${REPO_FILES[@]}"
fi

if ! load_repo_files '*.sh' '.githooks/*' "${NOT_FIRST_PARTY[@]}"; then
  fail_selection "" shellcheck shfmt
elif ((${#REPO_FILES[@]} == 0)); then
  fail_selection "no tracked shell files in the repository listing (a broken index or listing)" shellcheck shfmt
else
  step shellcheck shellcheck "${REPO_FILES[@]}"
  step shfmt shfmt -i 2 -ci -d "${REPO_FILES[@]}"
fi

if ! load_repo_files "${TYPOS_PATHSPEC[@]}"; then
  fail_selection "" typos
elif ((${#REPO_FILES[@]} == 0)); then
  fail_selection "no tracked prose files in the repository listing (a broken index or listing)" typos
else
  step typos typos --force-exclude --exclude 'Design/mac-v2/*.dc.html' "${REPO_FILES[@]}"
fi

if [[ -f Engine/go/go.mod ]]; then
  step "go vet" bash -c 'cd Engine/go && go vet ./...'
  step staticcheck bash -c 'cd Engine/go && staticcheck ./...'
  step govulncheck bash Tools/lint/check-go-vulnerabilities.sh
else
  skip "go vet/staticcheck/govulncheck" "no Engine/go/go.mod yet (P0-05)"
fi

step check-no-secrets-in-strings Tools/lint/check-no-secrets-in-strings.sh
step gitleaks bash Tools/lint/check-gitleaks.sh
step check-public-prose Tools/lint/check-public-prose.sh
step check-launchd-plists Tools/lint/check-launchd-plists.sh
step check-package-deps Tools/lint/check-package-deps.sh
step check-licences Tools/lint/check-licences.sh
step daemon-print python3 -I Tools/lint/check-daemon-print.py
step notices-sync bash Tools/lint/check-notices-sync.sh
step docs-check just docs-check

if ((${#failed[@]} > 0)); then
  printf 'lint: FAILED: %s\n' "${failed[*]}" >&2
  exit 1
fi
echo "lint: all checks passed"
