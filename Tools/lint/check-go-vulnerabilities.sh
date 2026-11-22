#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# M1-13: advisory failures are fatal unless explicitly offline.
set -euo pipefail
if [[ "${WGEX_OFFLINE:-0}" == 1 ]]; then
  echo 'govulncheck: skipped (WGEX_OFFLINE=1; vulnerability database was not checked)'
  exit 0
fi
work="$(mktemp -d "${TMPDIR:-/tmp}/wgex-govulncheck.XXXXXX")"
# The trap fails closed: bash 3.2 hands an EXIT trap status 0 after a shell error under set -e (unbound variable, ${x:?},
# readonly, bad substitution, failed source), so the script sets finished=1 just before each intended successful end.
# finished=0 first: an exported finished=1 in the caller must not mark an erroring script as finished.
finished=0
# shellcheck disable=SC2154 # rc is assigned inside the trap string
trap 'rc=$?; ((rc != 0)) || ((${finished:-0})) || rc=1; rm -rf "$work"; exit "$rc"' EXIT
cd "$(dirname "${BASH_SOURCE[0]}")/../../Engine/go"
status=0
govulncheck ./... >"$work/output" 2>&1 || status=$?
cat "$work/output"
finished=1
exit "$status"
