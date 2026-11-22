#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Serial builds with independent lint in parallel; preserve either failure [M1-13].
set -uo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root" || exit 1
step() {
  local label="$1"
  shift
  python3 -I Config/Scripts/timed-step.py "check/$label" "$@"
}
# The self-test has no build dependency (about two minutes against the build gate's ten or more), so it runs first: a broken
# self-test stops the gate before lint and the build steps start, and its result is never hidden behind a build failure [M1-10t].
step tooling-selftest just tooling-selftest || exit $?
step lint just lint &
lint_pid=$!
trap 'kill "$lint_pid" 2>/dev/null || true; wait "$lint_pid" 2>/dev/null || true' EXIT
build_status=0
build_gate() {
  step engine just engine && step engine-test just engine-test && step gen just gen &&
    step packages-macos just packages-matrix --macos && step build-debug just build all debug &&
    step engine-link just engine-link-check &&
    step entitlements-debug bash Tools/lint/check-entitlements.sh --configuration Debug --require mac,ios,tv
}
build_gate || build_status=$?
lint_status=0
wait "$lint_pid" || lint_status=$?
trap - EXIT
if ((build_status || lint_status)); then
  printf 'check: failed (build/test=%d, lint=%d)\n' "$build_status" "$lint_status" >&2
  exit 1
fi
step package-tests just test all && step go-race just test go-race
