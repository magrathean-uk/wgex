#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Proves every linter rejects its negative fixture under Tools/lint/tests/.
# A case passes only when the linter exits non-zero AND its output names the
# expected rule, so a crashed or missing tool cannot pass. Linter output is
# kept in a temporary file and never echoed (fixtures hold denylisted terms).
set -uo pipefail
# shellcheck source=Tools/lint/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

T="$LINT_ROOT/Tools/lint/tests"
L="$LINT_ROOT/Tools/lint"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/wgex-lint-selftest.XXXXXX")"
# The trap fails closed: bash 3.2 hands an EXIT trap status 0 after a shell error under set -e (unbound variable, ${x:?},
# readonly, bad substitution, failed source), so the script sets finished=1 just before each intended successful end.
# finished=0 first: an exported finished=1 in the caller must not mark an erroring script as finished.
finished=0
trap 'rc=$?; ((rc != 0)) || ((${finished:-0})) || rc=1; rm -rf "$OUT"; exit "$rc"' EXIT
export STATICCHECK_CACHE="${STATICCHECK_CACHE:-${XDG_CACHE_HOME:-$HOME/Library/Caches}/staticcheck}"

pass=0
fail=0

# expect_caught <name> <fixture> <marker regex> <cmd...>
expect_caught() {
  local name="$1" fixture="$2" marker="$3" log
  shift 3
  log="$OUT/$name.log"
  if [[ ! -e "$fixture" ]]; then
    printf 'FAIL  %-22s fixture missing: %s\n' "$name" "$(rel "$fixture")"
    fail=$((fail + 1))
    return
  fi
  "$@" >"$log" 2>&1
  local rc=$?
  if ((rc != 0)) && grep -qE "$marker" "$log"; then
    printf 'ok    %-22s caught %-45s exit %d, matched /%s/\n' "$name" "$(rel "$fixture")" "$rc" "$marker"
    pass=$((pass + 1))
  else
    printf 'FAIL  %-22s NOT caught %-41s exit %d\n' "$name" "$(rel "$fixture")" "$rc"
    fail=$((fail + 1))
  fi
}

in_dir() { # in_dir <dir> <cmd...>
  local d="$1"
  shift
  (cd "$d" && "$@")
}

expect_caught swiftlint "$T/swiftlint/ForceUnwrap.swift" 'force_unwrapping' \
  swiftlint lint --strict --no-cache --config "$LINT_ROOT/.swiftlint.yml" "$T/swiftlint/ForceUnwrap.swift"
expect_caught swiftlint-acl "$T/swiftlint/ForceUnwrap.swift" 'explicit_acl' \
  swiftlint lint --strict --no-cache --config "$LINT_ROOT/.swiftlint.yml" "$T/swiftlint/ForceUnwrap.swift"
# The house config excludes Tools/lint/tests even for explicit paths, so lint a copy.
mkdir -p "$OUT/swiftformat" && cp "$T/swiftformat/Unformatted.swift" "$OUT/swiftformat/"
expect_caught swiftformat "$T/swiftformat/Unformatted.swift" 'redundantSelf' \
  swiftformat --lint --cache ignore --config "$LINT_ROOT/.swiftformat" "$OUT/swiftformat/Unformatted.swift"
expect_caught shellcheck "$T/shellcheck/unquoted.sh" 'SC2086' \
  shellcheck "$T/shellcheck/unquoted.sh"
expect_caught shfmt "$T/shfmt/misformatted.sh" '^\+\+\+ ' \
  shfmt -i 2 -ci -d "$T/shfmt/misformatted.sh"
expect_caught typos "$T/typos/misspelled.md" 'should be' \
  typos --config "$LINT_ROOT/typos.toml" "$T/typos/misspelled.md"
expect_caught go-vet "$T/go-vet/main.go" 'Printf format %d' \
  in_dir "$T/go-vet" env GOPROXY=off GOTOOLCHAIN=local GOFLAGS=-mod=mod go vet ./...
expect_caught staticcheck "$T/staticcheck/main.go" 'SA4017' \
  in_dir "$T/staticcheck" env GOPROXY=off GOTOOLCHAIN=local GOFLAGS=-mod=mod staticcheck ./...
expect_caught secrets-base64 "$T/secrets/base64.swift" 'secret-shaped string' \
  "$L/check-no-secrets-in-strings.sh" "$T/secrets/base64.swift"
expect_caught secrets-hex64 "$T/secrets/hex64.go" 'secret-shaped string' \
  "$L/check-no-secrets-in-strings.sh" "$T/secrets/hex64.go"
expect_caught public-prose "$T/prose/denylisted.md" 'denylisted term #' \
  "$L/check-public-prose.sh" "$T/prose/denylisted.md"
expect_caught launchd-plist "$T/launchd/Daemon/WGEXDaemon/fixture.daemon.plist.in" 'EnvironmentVariables key' \
  "$L/check-launchd-plists.sh" "$T/launchd"
expect_caught package-deps "$T/package-deps/Packages/WGEXFixture/Package.swift" 'P0-04' \
  "$L/check-package-deps.sh" "$T/package-deps/Packages"

expect_caught release-imports "$T/release-imports/Unsafe.swift" 'Release imports WGEXTesting' \
  "$L/check-package-deps.sh" --release-imports "$T/release-imports"
expect_caught release-imports-daemon-testing "$T/release-imports/UnsafeDaemonTesting.swift" 'Release imports WGEXDaemonCoreTesting' \
  "$L/check-package-deps.sh" --release-imports "$T/release-imports/UnsafeDaemonTesting.swift"

# expect_clean <name> <fixture> <cmd...>: the linter must accept the fixture (exit 0)
expect_clean() {
  local name="$1" fixture="$2" log
  shift 2
  log="$OUT/$name.log"
  if [[ ! -e "$fixture" ]]; then
    printf 'FAIL  %-22s fixture missing: %s\n' "$name" "$(rel "$fixture")"
    fail=$((fail + 1))
    return
  fi
  if "$@" >"$log" 2>&1; then
    printf 'ok    %-22s accepted %-43s exit 0\n' "$name" "$(rel "$fixture")"
    pass=$((pass + 1))
  else
    printf 'FAIL  %-22s wrongly rejected %-36s\n' "$name" "$(rel "$fixture")"
    fail=$((fail + 1))
  fi
}

expect_clean release-imports-guarded "$T/release-imports/Guarded.swift" \
  "$L/check-package-deps.sh" --release-imports "$T/release-imports/Guarded.swift"

# Licence gate (P0-06): every planted violation is rejected, the clean tree is accepted.
LG="$L/check-licences.sh"
expect_caught licence-gpl-spdx "$T/licences/gpl-spdx" 'Planted.swift: SPDX identifier .GPL-3.0-or-later. is not on the allowlist' "$LG" "$T/licences/gpl-spdx"
expect_caught licence-gpl-text "$T/licences/gpl-text" 'header.go: copyleft or restricted licence text' "$LG" "$T/licences/gpl-text"
expect_caught licence-lgpl "$T/licences/restricted/lgpl.swift" 'lgpl.swift: copyleft' "$LG" "$T/licences/restricted/lgpl.swift"
expect_caught licence-agpl "$T/licences/restricted/agpl.swift" 'agpl.swift: copyleft' "$LG" "$T/licences/restricted/agpl.swift"
expect_caught licence-elastic "$T/licences/restricted/elastic.yml" 'elastic.yml: copyleft or restricted' "$LG" "$T/licences/restricted/elastic.yml"
expect_caught licence-sspl "$T/licences/restricted/sspl.go" 'sspl.go: copyleft or restricted' "$LG" "$T/licences/restricted/sspl.go"
expect_caught licence-mpl-outside "$T/licences/mpl-outside" 'Packages/Fixture/Mpl.swift: SPDX identifier .MPL-2.0. is not on the allowlist' "$LG" "$T/licences/mpl-outside"
expect_caught licence-mpl-former-text "$T/licences/mpl-former-path" 'MPL-2.0 text is not allowed' "$LG" "$T/licences/mpl-former-path"
expect_caught licence-mpl-former-spdx "$T/licences/mpl-former-path" 'SPDX identifier .MPL-2.0. is not on the allowlist' "$LG" "$T/licences/mpl-former-path"
expect_caught licence-unknown-spdx "$T/licences/unknown-spdx" 'LicenseRef-Proprietary. is not on the allowlist' "$LG" "$T/licences/unknown-spdx"
expect_caught licence-file "$T/licences/bad-licence-file" 'LICENSE: licence file is not a recognised' "$LG" "$T/licences/bad-licence-file"
expect_clean licence-pass "$T/licences/pass" "$LG" "$T/licences/pass"

# Secret scanner exclusions (P0-19): the same key-shaped string is allowed under
# Tests/Fixtures, Tools/testpeer/testdata, Vendor, Engine/go/vendor and
# Design/.work and reported everywhere else, including first-party Engine/go.
secrets_tree() {
  local log="$OUT/secrets-tree.log"
  "$L/check-no-secrets-in-strings.sh" "$T/secrets/tree" >"$log" 2>&1
  local rc=$?
  if ((rc != 0)) && [[ "$(grep -c '^secret-shaped string:' "$log")" == 2 ]] &&
    grep -q '^secret-shaped string: Sources/Leak.swift ' "$log" &&
    grep -q '^secret-shaped string: Engine/go/bridge/leak.go ' "$log"; then
    printf 'ok    %-22s reports only %-40s exit %d\n' secrets-exclusions "Sources/Leak.swift, Engine/go/bridge/leak.go" "$rc"
    pass=$((pass + 1))
  else
    printf 'FAIL  %-22s exclusions wrong (exit %d)\n' secrets-exclusions "$rc"
    fail=$((fail + 1))
  fi
}
secrets_tree

# The real fixture keys themselves: caught outside the allowed paths, accepted inside.
real_keys() {
  local keys="$LINT_ROOT/Tests/Fixtures/keys" f n=0 out="$OUT/realkeys"
  mkdir -p "$out/outside/Sources" "$out/inside/Tests/Fixtures/keys"
  for f in "$keys"/*.key "$keys"/*.pub; do
    [[ -f "$f" ]] || continue
    n=$((n + 1))
    printf 'let fixtureKey%d = "%s"\n' "$n" "$(grep -v '^#' "$f" | head -n 1)" >>"$out/outside/Sources/Keys.swift"
  done
  cp "$out/outside/Sources/Keys.swift" "$out/inside/Tests/Fixtures/keys/Keys.swift"
  local want
  want="$(seq 1 "$n" | paste -sd, -)"
  if ((n == 0)); then
    printf 'FAIL  %-22s no keys in %s\n' secrets-real-keys "$(rel "$keys")"
    fail=$((fail + 1))
  elif ! "$L/check-no-secrets-in-strings.sh" "$out/outside" >"$OUT/real-out.log" 2>&1 && grep -q "Sources/Keys.swift line(s) $want\$" "$OUT/real-out.log"; then
    if "$L/check-no-secrets-in-strings.sh" "$out/inside" >"$OUT/real-in.log" 2>&1; then
      printf 'ok    %-22s %d fixture keys flagged outside, accepted inside Tests/Fixtures\n' secrets-real-keys "$n"
      pass=$((pass + 1))
    else
      printf 'FAIL  %-22s fixture keys wrongly flagged inside Tests/Fixtures\n' secrets-real-keys
      fail=$((fail + 1))
    fi
  else
    printf 'FAIL  %-22s fixture keys not all flagged outside the allowed paths\n' secrets-real-keys
    fail=$((fail + 1))
  fi
}
real_keys

if bash "$T/govulncheck/run.sh" >"$OUT/govulncheck.log" 2>&1; then
  printf 'ok    %-22s seven offline fallback and failure-propagation cases\n' govulncheck
  pass=$((pass + 1))
else
  printf 'FAIL  %-22s fallback regression\n' govulncheck
  fail=$((fail + 1))
fi
# M1-13: custom Swift rules run on copies outside the fixture exclusion.
swift_custom() {
  local root="$1"
  shift
  env WGEX_LINT_ROOT="$root" swiftlint lint --strict --no-cache --config "$LINT_ROOT/.swiftlint.yml" "$@"
}
mkdir -p "$OUT/custom/Sources" "$OUT/custom/Tests" "$OUT/custom/Daemon/WGEXDaemon"
for fixture_rule in 'Print:wgex_no_print' 'Todo:wgex_ticket_comment' 'Fixme:wgex_ticket_comment' 'Risk:wgex_bare_risk'; do
  fixture="${fixture_rule%%:*}"
  rule="${fixture_rule#*:}"
  fixture_dir="$OUT/custom/Sources"
  if [[ "$fixture" == Print ]]; then fixture_dir="$OUT/custom/Packages/P/Sources/P"; fi
  mkdir -p "$fixture_dir"
  cp "$T/swiftlint/$fixture.txt" "$fixture_dir/$fixture.swift"
  expect_caught "custom-$fixture" "$fixture_dir/$fixture.swift" "$rule" \
    swift_custom "$OUT/custom" "$fixture_dir/$fixture.swift"
done
cp "$T/swiftlint/Allowed.txt" "$OUT/custom/Sources/Allowed.swift"
expect_clean custom-ticket "$OUT/custom/Sources/Allowed.swift" \
  swift_custom "$OUT/custom" "$OUT/custom/Sources/Allowed.swift"
cp "$T/swiftlint/Print.txt" "$OUT/custom/Tests/Print.swift"
expect_clean custom-test-print "$OUT/custom/Tests/Print.swift" \
  swift_custom "$OUT/custom" "$OUT/custom/Tests/Print.swift"
# M1-13: the print convention covers products, not command-line tools.
for directory in Apps Daemon Extensions; do
  mkdir -p "$OUT/custom/$directory/Fixture"
  cp "$T/swiftlint/Print.txt" "$OUT/custom/$directory/Fixture/Print.swift"
  expect_caught "print-$directory" "$OUT/custom/$directory/Fixture/Print.swift" 'wgex_no_print' \
    swift_custom "$OUT/custom" "$OUT/custom/$directory/Fixture/Print.swift"
done
mkdir -p "$OUT/custom/Tools/Fixture" "$OUT/custom/Packages/Fixture/Tests"
for directory in Tools/Fixture Packages/Fixture/Tests; do
  cp "$T/swiftlint/Print.txt" "$OUT/custom/$directory/Print.swift"
  expect_clean "print-allowed-${directory%%/*}" "$OUT/custom/$directory/Print.swift" \
    swift_custom "$OUT/custom" "$OUT/custom/$directory/Print.swift"
done
# A Tools/Tests ancestor outside the repository must not exempt product code.
for ancestor in Tools Tests; do
  scope="$OUT/$ancestor/repository"
  mkdir -p "$scope/Apps/Fixture"
  cp "$T/swiftlint/Print.txt" "$scope/Apps/Fixture/Print.swift"
  expect_caught "print-parent-$ancestor" "$scope/Apps/Fixture/Print.swift" 'wgex_no_print' \
    swift_custom "$scope" "$scope/Apps/Fixture/Print.swift"
done
for extension in json plist py sh md yml; do
  cp "$T/secrets/base64.swift" "$OUT/secret.$extension"
  expect_caught "secrets-$extension" "$OUT/secret.$extension" 'secret-shaped string' \
    "$L/check-no-secrets-in-strings.sh" "$OUT/secret.$extension"
done
# M1-13: notices sync and every newly included licence tree.
printf 'same\n' >"$OUT/notices-a.md"
printf 'different\n' >"$OUT/notices-b.md"
expect_caught notices-sync "$OUT/notices-b.md" 'notices-sync: FAIL' \
  bash "$L/check-notices-sync.sh" "$OUT/notices-a.md" "$OUT/notices-b.md"
expect_clean notices-sync-pass "$OUT/notices-a.md" \
  bash "$L/check-notices-sync.sh" "$OUT/notices-a.md" "$OUT/notices-a.md"
# Generator keeps the Wintun section: regeneration must match the committed notices.
# GOROOT is unset in the caller's environment, as under the gate wrapper: notices.py derives it from the local go.
env -u GOROOT python3 -I "$LINT_ROOT/Tools/lint/notices.py" --output "$OUT/notices-regen.md" >/dev/null 2>&1 || true
expect_clean notices-wintun "$LINT_ROOT/THIRD_PARTY_NOTICES.md" \
  grep -q '^### golang.zx2c4.com/wintun$' "$OUT/notices-regen.md"
expect_clean notices-regen-match "$LINT_ROOT/THIRD_PARTY_NOTICES.md" \
  cmp -s "$OUT/notices-regen.md" "$LINT_ROOT/THIRD_PARTY_NOTICES.md"
# Negative case: with no go on PATH the Go sections degrade to placeholders, so the regeneration must not pass as final.
go_licences_dir="$(dirname "$(command -v go-licenses 2>/dev/null || echo /nonexistent/go-licenses)")"
PY3="$(command -v python3)"
env -u GOROOT PATH="$go_licences_dir:/usr/bin:/bin" "$PY3" -I "$LINT_ROOT/Tools/lint/notices.py" \
  --output "$OUT/notices-nogo.md" >/dev/null 2>&1 || true
expect_clean notices-regen-no-go-placeholder "$OUT/notices-nogo.md" \
  grep -q 'PLACEHOLDER: Go licence report unavailable' "$OUT/notices-nogo.md"
expect_caught notices-regen-no-go "$OUT/notices-nogo.md" 'differ' \
  cmp "$OUT/notices-nogo.md" "$LINT_ROOT/THIRD_PARTY_NOTICES.md"
for directory in Apps Daemon Extensions Config; do
  mkdir -p "$OUT/licences/$directory"
  cp "$T/licences/gpl-spdx/Planted.swift" "$OUT/licences/$directory/Planted.swift"
  expect_caught "licence-$directory" "$OUT/licences/$directory" 'not on the allowlist' \
    "$LG" "$OUT/licences/$directory"
done
cat >"$OUT/custom/Daemon/WGEXDaemon/main.swift" <<'SWIFT'
if arguments.contains("--version") || arguments.contains("--doctor") {
    print("version")
}
SWIFT
expect_clean daemon-version-print "$OUT/custom/Daemon/WGEXDaemon/main.swift" \
  python3 -I "$L/check-daemon-print.py" "$OUT/custom/Daemon/WGEXDaemon/main.swift"
printf '\nprint("outside")\n' >>"$OUT/custom/Daemon/WGEXDaemon/main.swift"
expect_caught daemon-other-print "$OUT/custom/Daemon/WGEXDaemon/main.swift" 'wgex_no_print' \
  python3 -I "$L/check-daemon-print.py" "$OUT/custom/Daemon/WGEXDaemon/main.swift"
# M1-10f: lint.sh's typos selection skips machine-written verdicts under
# Tests/Reports but still checks prose there. Each scratch tree is indexed in a
# disposable git repository so the real TYPOS_PATHSPEC does the selecting.
typos_tree() { # typos_tree <dir> [config]: the lint.sh typos step over a scratch tree
  local saved="$LINT_ROOT" listed=0 config="${2:-$LINT_ROOT/typos.toml}"
  LINT_ROOT="$1"
  load_repo_files "${TYPOS_PATHSPEC[@]}" || listed=1
  LINT_ROOT="$saved"
  if ((listed)); then return 1; fi
  if ((${#REPO_FILES[@]} == 0)); then
    echo 'typos_tree: empty selection' >&2
    return 1
  fi
  (cd "$1" && typos --config "$config" --force-exclude "${REPO_FILES[@]}")
}
row="Tests/Reports/M1/M1-10/FIXTURE-ROW"
for tree in verdict md; do
  mkdir -p "$OUT/typos-$tree/$row"
  cp "$T/typos/report-row/verdict.json" "$T/typos/report-row/README.md" "$OUT/typos-$tree/$row/"
done
cp "$T/typos/digest.md" "$OUT/typos-md/$row/digest.md"
for tree in verdict md; do
  git -C "$OUT/typos-$tree" -c init.defaultBranch=main init -q &&
    git -C "$OUT/typos-$tree" add -A
done
expect_caught typos-digest-raw "$T/typos/report-row/verdict.json" 'should be' \
  typos --config "$LINT_ROOT/typos.toml" "$T/typos/report-row/verdict.json"
expect_clean typos-verdict-skipped "$OUT/typos-verdict/$row/verdict.json" \
  typos_tree "$OUT/typos-verdict"
expect_caught typos-report-md "$OUT/typos-md/$row/digest.md" 'should be' \
  typos_tree "$OUT/typos-md"
expect_clean lint-scope-hook "$T/scope/run.sh" bash "$T/scope/run.sh" "$LINT_ROOT" "$OUT"
# M00-T01: .plan/ is out of typos scope twice over, TYPOS_PATHSPEC (lint.sh) and typos.toml. unscoped.toml is the house
# config without its .plan/ line, so the pathspec alone must hide the misspelling; outside .plan/ it is still caught.
grep -vxF '  ".plan/**",' "$LINT_ROOT/typos.toml" >"$OUT/typos-unscoped.toml"
for tree in plan outside; do
  mkdir -p "$OUT/typos-$tree/.plan/nested" "$OUT/typos-$tree/Sources"
  cp "$T/typos/misspelled.md" "$OUT/typos-$tree/.plan/nested/typo.md"
  printf 'Clean text.\n' >"$OUT/typos-$tree/Sources/clean.md"
done
cp "$T/typos/misspelled.md" "$OUT/typos-outside/Sources/typo.md"
for tree in plan outside; do
  git -C "$OUT/typos-$tree" -c init.defaultBranch=main init -q &&
    git -C "$OUT/typos-$tree" add -A
done
expect_caught typos-plan-unscoped "$OUT/typos-plan/.plan/nested/typo.md" 'should be' \
  in_dir "$OUT/typos-plan" typos --config "$OUT/typos-unscoped.toml" .plan/nested/typo.md
expect_clean typos-plan-pathspec "$OUT/typos-plan/.plan/nested/typo.md" \
  typos_tree "$OUT/typos-plan" "$OUT/typos-unscoped.toml"
expect_clean typos-plan-toml "$OUT/typos-plan/.plan/nested/typo.md" \
  in_dir "$OUT/typos-plan" typos --config "$LINT_ROOT/typos.toml" --force-exclude .plan/nested/typo.md
expect_caught typos-plan-outside "$OUT/typos-outside/Sources/typo.md" 'should be' \
  typos_tree "$OUT/typos-outside"
# The pre-commit typos hook excludes ^\.plan/ and the gitleaks hook still scans the whole tree; mutated copies are refused.
PC="$T/scope/pre-commit-config.py"
expect_clean pre-commit-plan-scope "$LINT_ROOT/.pre-commit-config.yaml" python3 -I "$PC" "$LINT_ROOT/.pre-commit-config.yaml"
grep -vF 'exclude: ^\.plan/' "$LINT_ROOT/.pre-commit-config.yaml" >"$OUT/pre-commit-no-typos-exclude.yaml"
expect_caught pre-commit-typos-scope "$OUT/pre-commit-no-typos-exclude.yaml" 'typos hook has no exclude' \
  python3 -I "$PC" "$OUT/pre-commit-no-typos-exclude.yaml"
sed 's|^\(        always_run: true\)$|\1\
        exclude: ^\\.plan/|' "$LINT_ROOT/.pre-commit-config.yaml" >"$OUT/pre-commit-gitleaks-exclude.yaml"
expect_caught pre-commit-gitleaks-scope "$OUT/pre-commit-gitleaks-exclude.yaml" 'gitleaks hook filters files .exclude.' \
  python3 -I "$PC" "$OUT/pre-commit-gitleaks-exclude.yaml"
# gitleaks still scans .plan/: a fake GitHub token planted under a scratch .plan/ is reported by the pre-commit hook's
# `gitleaks dir` and the global hook's staged scan, both under the house .gitleaks.toml. The token is built at run time
# from a fixed seed so no secret-shaped literal is committed.
mkdir -p "$OUT/gitleaks-plan/.plan/work"
cp "$LINT_ROOT/.gitleaks.toml" "$OUT/gitleaks-plan/"
printf 'github_token = "ghp_%s"\n' "$(printf 'wgex-lint-selftest-M00-T01' | shasum -a 256 | cut -c1-36)" \
  >"$OUT/gitleaks-plan/.plan/work/notes.md"
git -C "$OUT/gitleaks-plan" -c init.defaultBranch=main init -q && git -C "$OUT/gitleaks-plan" add -A
expect_caught gitleaks-plan-dir "$OUT/gitleaks-plan/.plan/work/notes.md" 'leaks found: [1-9]' \
  in_dir "$OUT/gitleaks-plan" gitleaks dir --redact --no-banner .
expect_caught gitleaks-plan-staged "$OUT/gitleaks-plan/.plan/work/notes.md" 'leaks found: [1-9]' \
  in_dir "$OUT/gitleaks-plan" gitleaks git --pre-commit --staged --redact --no-banner
# The same token under .plan/ fails the gitleaks step of lint.sh itself (`just lint`), redacted, in a scratch copy.
expect_clean lint-gitleaks-plan "$T/scope/lint-gitleaks.sh" bash "$T/scope/lint-gitleaks.sh" "$LINT_ROOT" "$OUT"
# A lint.sh without its gitleaks step is refused by the same fixture.
mkdir -p "$OUT/no-gitleaks-root/Tools/lint" "$OUT/no-gitleaks-root/Config/Scripts" "$OUT/no-gitleaks-out"
find "$L" -maxdepth 1 -type f -exec cp {} "$OUT/no-gitleaks-root/Tools/lint/" \;
cp "$LINT_ROOT/Config/Scripts/lib.sh" "$LINT_ROOT/Config/Scripts/build_root.py" "$OUT/no-gitleaks-root/Config/Scripts/"
cp "$LINT_ROOT/.gitleaks.toml" "$LINT_ROOT/.gitleaksignore" "$OUT/no-gitleaks-root/"
grep -vF 'step gitleaks ' "$L/lint.sh" >"$OUT/no-gitleaks-root/Tools/lint/lint.sh"
expect_caught lint-gitleaks-missing "$OUT/no-gitleaks-root/Tools/lint/lint.sh" 'lint.sh has no gitleaks step' \
  bash "$T/scope/lint-gitleaks.sh" "$OUT/no-gitleaks-root" "$OUT/no-gitleaks-out"
# M1-47: the Release link check rejects a product carrying LabPowerInjector and accepts clean ones (stub nm, strings, xcrun).
expect_clean check-link "$T/check-link/run.sh" bash "$T/check-link/run.sh"
# M1-32: lint fails closed when git cannot list files; EXIT traps keep the status; zero manifests are refused.
# The suite runs under its own deadline (macOS has no GNU timeout): it holds some forty subprocesses of up to 120 s each.
if perl -e 'alarm shift; exec @ARGV or die "exec failed\n"' 900 bash "$T/fail-closed/run.sh" >"$OUT/fail-closed.log" 2>&1; then
  printf 'ok    %-22s %s\n' fail-closed "$(tail -n 1 "$OUT/fail-closed.log")"
  pass=$((pass + 1))
else
  grep '^FAIL' "$OUT/fail-closed.log" || tail -n 5 "$OUT/fail-closed.log"
  printf 'FAIL  %-22s fail-closed regression\n' fail-closed
  fail=$((fail + 1))
fi
finished=1
printf 'selftests: %d caught, %d not caught\n' "$pass" "$fail"
((fail == 0))
