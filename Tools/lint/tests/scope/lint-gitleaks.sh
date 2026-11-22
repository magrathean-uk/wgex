#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# M00-T01: the `just lint` entry point (Tools/lint/lint.sh) rejects a token planted under .plan/ through its gitleaks
# step, and redacts it. lint.sh and its helpers are copied into a scratch repository, so the real tree is never
# scanned or touched. Other steps fail there (no Swift, no manifests); only the gitleaks step is asserted. A control
# run with the token removed proves the gitleaks step, not something else, caused the failure.
# Usage: lint-gitleaks.sh <repository root> <output directory>
set -euo pipefail
root="$1"
out="$2/lint-gitleaks"
repo="$out/repo"
mkdir -p "$repo/Tools/lint" "$repo/Config/Scripts" "$repo/.plan/work"
find "$root/Tools/lint" -maxdepth 1 -type f -exec cp {} "$repo/Tools/lint/" \;
cp "$root/Config/Scripts/lib.sh" "$root/Config/Scripts/build_root.py" "$repo/Config/Scripts/"
cp "$root/.gitleaks.toml" "$root/.gitleaksignore" "$repo/"
# A fake GitHub token built at run time from a fixed seed, so no secret-shaped literal is committed.
token="ghp_$(printf 'wgex-lint-selftest-M00-T01' | shasum -a 256 | cut -c1-36)"
printf 'github_token = "%s"\n' "$token" >"$repo/.plan/work/notes.md"
git -C "$repo" -c init.defaultBranch=main init -q
git -C "$repo" add -f .

run_lint() { # run_lint <log>: lint.sh under a deadline; its status is ignored (other steps fail in a scratch tree)
  perl -e 'alarm shift; exec @ARGV or die "exec failed\n"' 300 bash "$repo/Tools/lint/lint.sh" >"$1" 2>&1 || true
}
gitleaks_failed() { grep -qE '^lint: FAILED: (.* )?gitleaks( |$)' "$1"; }

run_lint "$out/planted.log"
if grep -qF "$token" "$out/planted.log"; then
  echo 'lint-gitleaks: the planted token appears unredacted in the lint output' >&2
  exit 1
fi
grep -q '^==> gitleaks$' "$out/planted.log" || {
  echo 'lint-gitleaks: lint.sh has no gitleaks step' >&2
  exit 1
}
grep -qE 'leaks found: [1-9]' "$out/planted.log" || {
  echo 'lint-gitleaks: gitleaks reported no leak for the token under .plan/' >&2
  exit 1
}
grep -qF '.plan/work/notes.md' "$out/planted.log" || {
  echo 'lint-gitleaks: the finding does not name .plan/work/notes.md' >&2
  exit 1
}
gitleaks_failed "$out/planted.log" || {
  echo 'lint-gitleaks: lint.sh did not fail its gitleaks step on the token under .plan/' >&2
  exit 1
}

printf 'Clean text.\n' >"$repo/.plan/work/notes.md"
git -C "$repo" add -f .
run_lint "$out/clean.log"
grep -q 'no leaks found' "$out/clean.log" || {
  echo 'lint-gitleaks: the clean scratch tree did not scan clean' >&2
  exit 1
}
if gitleaks_failed "$out/clean.log"; then
  echo 'lint-gitleaks: lint.sh failed its gitleaks step on a clean tree' >&2
  exit 1
fi
echo 'lint-gitleaks: lint.sh rejects a redacted token under .plan/ and passes the clean tree'
