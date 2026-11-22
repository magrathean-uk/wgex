#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Host-only tools gate. Test seams use ordinary files and recorded payloads.
set -euo pipefail
# Hermetic: no inherited WGEX_*, STUB_* or FAKE_* variable changes a result (WGEX_LAB_VM, WGEX_LAB_TEST_BIN, the deadline
# knobs, the fake tools' FAKE_* channels, ...); a test that needs one sets it itself. Names only, never values.
# WGEX_BUILD_ROOT is kept: it routes build output (Config/Scripts/build_root.py) and selects no behaviour, so an operator's
# choice of where lab-scripts-test builds must keep working.
removed=()
for name in $(compgen -e); do
  case "$name" in
    WGEX_BUILD_ROOT) ;;
    WGEX_* | STUB_* | FAKE_*)
      removed+=("$name")
      unset "$name"
      ;;
  esac
done
if ((${#removed[@]})); then
  list="$(printf '%s, ' "${removed[@]}")"
  printf 'lab tests: removed inherited variables: %s\n' "${list%, }" >&2
fi
root="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$root"
# shellcheck source=Config/Scripts/lib.sh
source "$root/Config/Scripts/lib.sh"
configure_caches
build="$(build_root)"
swift test --package-path Tools/leakprobe --scratch-path "$build/spm/leakprobe" --cache-path "$(dependency_cache)/swiftpm"
mkdir -p "$build/lab-tools"
xcrun --sdk macosx clang -mmacosx-version-min=26.0 -std=c11 -D WGEX_LAB_BUILD -Wall -Wextra -Werror Tools/lab/tart/guest/foreign-utun.c -o "$build/lab-tools/foreign-utun"
# The fixture refuses on this host (no root, no hypervisor) before it opens any control socket, and its guard checks
# the guest OS version and the hypervisor sysctl before socket().
if foreign_out="$("$build/lab-tools/foreign-utun" 2>&1)"; then foreign_status=0; else foreign_status=$?; fi
[[ "$foreign_status" == 1 && "$foreign_out" == 'foreign-utun: guarded root guest required' ]] || {
  printf 'foreign-utun did not refuse outside a guarded guest (status %s)\n' "$foreign_status" >&2
  exit 1
}
foreign_src="$(<Tools/lab/tart/guest/foreign-utun.c)"
foreign_pre="${foreign_src%%socket(PF_SYSTEM*}"
[[ "$foreign_pre" == *kern.osproductversion* && "$foreign_pre" == *kern.hv_vmm_present* && "$foreign_pre" == *wgex-lab-host* ]] || {
  echo 'foreign-utun must run the guest VM and marker checks before socket()' >&2
  exit 1
}
python3 -I -B Tools/lab/state.py publish-helpers
python3 -I -B -m unittest discover -s Tools/lab/tests -p 'test_*.py'
bash Tools/lab/tart/tests/run.sh
shellcheck Tools/lab/*.sh Tools/lab/tart/*.sh Tools/lab/tart/guest/*.sh Tools/lab/tart/tests/*.sh Tools/lab/lima/*.sh Tools/lab/update/*.sh Tools/lab/corpus/*.sh
