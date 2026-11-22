#!/usr/bin/env bash
# Only mock the advisory tool; never contact a database in these regression checks. The mock goes first on PATH and
# answers every call (an unknown case exits 99), so the real govulncheck is never reachable from here.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/wgex-govulncheck-test.XXXXXX")"
# The trap fails closed: bash 3.2 hands an EXIT trap status 0 after a shell error under set -e (unbound variable, ${x:?},
# readonly, bad substitution, failed source), so the script sets finished=1 just before each intended successful end.
# finished=0 first: an exported finished=1 in the caller must not mark an erroring script as finished.
finished=0
# shellcheck disable=SC2154 # rc is assigned inside the trap string
trap 'rc=$?; ((rc != 0)) || ((${finished:-0})) || rc=1; rm -rf "$work"; exit "$rc"' EXIT
deadline() { perl -e 'alarm shift; exec @ARGV or die "exec failed\n"' 120 "$@"; }
# Own the complete Go environment, independent of the caller. Snapshot names AND values so additions, changes and
# removals (including dropping a caller-selected database) all fail the mock. No actual Go tool runs here.
while IFS= read -r name; do
  case "$name" in GO* | CGO_*) unset "$name" ;; esac
done < <(compgen -e)
# Deliberately distinctive sentinels: hard-coding production defaults must not look like preservation.
export GOPROXY=https://wgex-selftest.invalid GOTOOLCHAIN=wgex-selftest-toolchain GOSUMDB=wgex-selftest.invalid GOFLAGS=-tags=wgexselftest GOVULNDB=file:///wgex-selftest-no-database
export WGEX_VULN_TEST_ENV="$work/go-environment"
env | grep -E '^(GO[^=]*|CGO_[^=]*)=' | LC_ALL=C sort >"$WGEX_VULN_TEST_ENV"
cat >"$work/govulncheck" <<'MOCK'
#!/usr/bin/env bash
# The script must preserve the test-owned Go environment and call exactly `govulncheck ./...` from Engine/go.
[[ "$*" == "./..." ]] || {
  echo "govulncheck mock: unexpected arguments: $*" >&2
  exit 98
}
[[ -n "${WGEX_VULN_TEST_ROOT:-}" && -d "$WGEX_VULN_TEST_ROOT/Engine/go" && "$(pwd -P)" == "$(cd "$WGEX_VULN_TEST_ROOT/Engine/go" && pwd -P)" ]] || {
  echo "govulncheck mock: wrong directory: $PWD (want the tree's Engine/go)" >&2
  exit 96
}
env | grep -E '^(GO[^=]*|CGO_[^=]*)=' | LC_ALL=C sort >"$WGEX_VULN_TEST_ENV.actual"
if ! cmp -s "$WGEX_VULN_TEST_ENV" "$WGEX_VULN_TEST_ENV.actual"; then
  echo 'govulncheck mock: Go environment changed' >&2
  exit 96
fi
# Five lines across both streams; the final sentinels expose truncation after the case's third line.
echo 'Scanning your code and 1 package across 1 dependent module for known vulnerabilities...'
echo 'govulncheck mock: diagnostic on stderr' >&2
status=0
case "$WGEX_VULN_TEST_CASE" in
  unreachable) echo 'govulncheck: fetching vulnerabilities: Get "https://vuln.go.dev/index/db.json.gz": unexpected EOF'; status=1 ;;
  vulnerable) echo 'Vulnerability: fixture advisory'; status=3 ;;
  compile-error) echo 'loading packages: fixture compiler error'; status=1 ;;
  clean) echo 'No vulnerabilities found.' ;;
  *) exit 99 ;;
esac
echo 'govulncheck mock: fourth line WGEX_STDOUT_END'
echo 'govulncheck mock: fifth line WGEX_STDERR_END' >&2
exit "$status"
MOCK
chmod +x "$work/govulncheck"
export PATH="$work:$PATH"
# The mock locates the tree by this variable (the script under test cannot move it), and checks the working directory.
export WGEX_VULN_TEST_ROOT="$root"
[[ -d "$root/Engine/go" ]] || {
  echo "govulncheck regression: $root/Engine/go is missing" >&2
  exit 1
}
# Only the exact value 1 skips the mock: unset, yes and 10 must all reach it.
for test_case in offline unreachable vulnerable compile-error clean unset-offline yes-offline ten-offline; do
  status=0
  case "$test_case" in
    offline) deadline env WGEX_OFFLINE=1 WGEX_VULN_TEST_CASE=offline bash "$root/Tools/lint/check-go-vulnerabilities.sh" >"$work/result" 2>&1 || status=$? ;;
    unset-offline) deadline env -u WGEX_OFFLINE WGEX_VULN_TEST_CASE=vulnerable bash "$root/Tools/lint/check-go-vulnerabilities.sh" >"$work/result" 2>&1 || status=$? ;;
    yes-offline) deadline env WGEX_OFFLINE=yes WGEX_VULN_TEST_CASE=vulnerable bash "$root/Tools/lint/check-go-vulnerabilities.sh" >"$work/result" 2>&1 || status=$? ;;
    ten-offline) deadline env WGEX_OFFLINE=10 WGEX_VULN_TEST_CASE=vulnerable bash "$root/Tools/lint/check-go-vulnerabilities.sh" >"$work/result" 2>&1 || status=$? ;;
    *) deadline env WGEX_OFFLINE=0 WGEX_VULN_TEST_CASE="$test_case" bash "$root/Tools/lint/check-go-vulnerabilities.sh" >"$work/result" 2>&1 || status=$? ;;
  esac
  # Each case is an explicit check: ok becomes 1 only when every condition holds. A bare `[[ ]] && ! grep ...` list never
  # fails the script under set -e (a failing non-final command of an && list, or a failing `!` command, does not exit).
  # Online cases require the whole five-line output, including both final sentinels.
  ok=0
  case "$test_case" in
    offline) [[ "$status" == 0 ]] && [[ "$(wc -l <"$work/result" | tr -d ' ')" == 1 ]] && grep -qx 'govulncheck: skipped (WGEX_OFFLINE=1; vulnerability database was not checked)' "$work/result" && ok=1 ;;
    *)
      grep -qx 'Scanning your code and 1 package across 1 dependent module for known vulnerabilities...' "$work/result" &&
        grep -qx 'govulncheck mock: diagnostic on stderr' "$work/result" &&
        grep -qx 'govulncheck mock: fourth line WGEX_STDOUT_END' "$work/result" &&
        grep -qx 'govulncheck mock: fifth line WGEX_STDERR_END' "$work/result" && ! grep -q 'skipped' "$work/result" &&
        case "$test_case" in
          unreachable) [[ "$status" == 1 ]] && grep -q 'fetching vulnerabilities' "$work/result" && ok=1 ;;
          vulnerable | unset-offline | yes-offline | ten-offline) [[ "$status" == 3 ]] && grep -qx 'Vulnerability: fixture advisory' "$work/result" && ok=1 ;;
          compile-error) [[ "$status" == 1 ]] && grep -q 'fixture compiler error' "$work/result" && ok=1 ;;
          clean) [[ "$status" == 0 ]] && grep -qx 'No vulnerabilities found.' "$work/result" && ok=1 ;;
        esac
      ;;
  esac
  ((ok)) || {
    echo "govulncheck regression: $test_case FAILED (status $status)" >&2
    exit 1
  }
  echo "govulncheck regression: $test_case passed"
done
finished=1
