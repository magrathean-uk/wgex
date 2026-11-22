#!/usr/bin/env bash
# M1-47: the Release link check (Engine/scripts/check-link.sh --release mac) must reject a Release product that carries
# LabPowerInjector, the Lab-only power-event injection, and accept products without it. Nothing is built or launched: stub nm,
# strings and xcrun go first on PATH (the real strings reads only the sections of a Mach-O, and the stubs are not valid ones),
# and WGEX_BUILD_ROOT routes the script to a products tree made here. The daemon stub is a minimal thin arm64 Mach-O with the
# parent launch-constraint slot, so a clean case runs the script to its real end.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/wgex-check-link-test.XXXXXX")"
# No exit handler: the fail-closed suite wants an injection case for every one, and the work directory is under TMPDIR (removed with
# the session). A setup error stops the script under `set -e` with a non-zero status; the work directory is removed at the end.

mkdir -p "$work/bin" "$work/base"
cat >"$work/bin/nm" <<'STUB'
#!/usr/bin/env bash
# Only a product under the test's products tree may be inspected.
[[ "$1" == "$LINK_TEST_PRODUCTS"/* ]] || exit 99
printf '0000000100000000 T __mh_execute_header\n0000000100001000 T _main\n'
printf '0000000100002000 T _$s12WGEXDaemonCore18SystemPowerMonitorCMa\n'
case "${LINK_TEST_NM:-clean}" in
  clean) ;;
  plain) printf '0000000100003000 T _$s12WGEXDaemonCore16LabPowerInjectorCMa\n' ;;
  # Raw mangling can split a type name; only the demangled stream shows it (xcrun stub below).
  mangled) printf '0000000100003000 T _$s_split_lab_power_marker\n' ;;
  *) exit 98 ;;
esac
STUB
cat >"$work/bin/strings" <<'STUB'
#!/usr/bin/env bash
# `strings -a` as the script calls it: every printable run of the file, one per line.
[[ "$1" == -a && "$2" == "$LINK_TEST_PRODUCTS"/* ]] || exit 99
LC_ALL=C tr -c '[:print:]\n' '\n' <"$2"
STUB
cat >"$work/bin/xcrun" <<'STUB'
#!/usr/bin/env bash
[[ "$1" == swift-demangle ]] || exit 99
sed 's/_\$s_split_lab_power_marker/WGEXDaemonCore.LabPowerInjector/'
STUB
chmod 0700 "$work/bin/nm" "$work/bin/strings" "$work/bin/xcrun"

name="$(basename "$root")"
export WGEX_BUILD_ROOT="$work/base"
build="$work/base/$name"
products="$build/derived-data/Build/Products"
export LINK_TEST_PRODUCTS="$products"
daemon="$products/Release/WGEX.app/Contents/MacOS/WGEXDaemon"
app="$products/Release/WGEX.app/Contents/MacOS/WGEX"

# make_products <text for the daemon> <text for the app>: fresh stub products; the text is appended after the Mach-O bytes.
make_products() {
  rm -rf "$products"
  mkdir -p "$(dirname "$daemon")"
  python3 -I - "$daemon" "$app" "$1" "$2" <<'PYSTUB'
import struct
import sys

daemon, app, daemon_text, app_text = sys.argv[1:]
# Header (magic, cputype, subtype, filetype, ncmds=1, sizeofcmds=16, flags, reserved), then LC_CODE_SIGNATURE (0x1D, size 16,
# dataoff 48), then a super blob (count 1) whose one index entry is slot 9 at offset 20, a 0xFADE8181 blob of length 16.
header = bytes.fromhex("cffaedfe") + struct.pack("<7I", 0x0100000C, 0, 2, 1, 16, 0, 0)
command = struct.pack("<IIII", 0x1D, 16, 48, 32)
superblob = struct.pack(">III", 0xFADE0CC0, 32, 1) + struct.pack(">II", 9, 20) + struct.pack(">II", 0xFADE8181, 16) + bytes(8)
with open(daemon, "wb") as handle:
    handle.write(header + command + superblob + daemon_text.encode() + b"\n")
with open(app, "wb") as handle:
    handle.write(b"not a product, a stub\n" + app_text.encode() + b"\n")
PYSTUB
}

pass=0
fail=0
# expect <case> <exit: ok|rejected> <regex the output must match> ; the nm mode and product text come from the variables set by the caller.
expect() {
  local label="$1" want="$2" marker="$3" log="$work/$1.log" rc=0
  PATH="$work/bin:$PATH" bash "$root/Engine/scripts/check-link.sh" --release mac >"$log" 2>&1 || rc=$?
  if { [[ "$want" == ok ]] && ((rc == 0)) && grep -qE "$marker" "$log"; } ||
    { [[ "$want" == rejected ]] && ((rc != 0)) && grep -qE "$marker" "$log"; }; then
    printf 'ok    %-26s %s (exit %d)\n' "$label" "$want" "$rc"
    pass=$((pass + 1))
  else
    printf 'FAIL  %-26s wanted %s, got exit %d; output:\n' "$label" "$want" "$rc"
    sed 's/^/      /' "$log"
    fail=$((fail + 1))
  fi
}

# Each case below names a lab symbol on its own line as the only difference from the clean one.
export LINK_TEST_NM=clean
make_products 'WGEX daemon' 'WGEX app'
expect clean-products ok 'release-link-check: ok \(daemon \+ Mac app\)'
make_products 'SystemPowerMonitor LabPower LabInjector power inject' 'WGEX app'
expect near-miss-names-pass ok 'release-link-check: ok \(daemon \+ Mac app\)'

# Control: a pattern that was already in the list is rejected by the same machinery, so the cases below are not vacuous.
make_products 'FakePowerMonitor' 'WGEX app'
expect existing-pattern-control rejected 'Release contains lab/testing symbols or strings: Release/WGEX.app/Contents/MacOS/WGEXDaemon'

make_products 'WGEXDaemonCore.LabPowerInjector' 'WGEX app'
expect injector-string-in-daemon rejected 'Release contains lab/testing symbols or strings: Release/WGEX.app/Contents/MacOS/WGEXDaemon$'
make_products 'WGEX daemon' 'LabPowerInjectorSignals'
expect injector-string-in-app rejected 'Release contains lab/testing symbols or strings: Release/WGEX.app/Contents/MacOS/WGEX$'
make_products 'WGEX daemon' 'WGEX app'
LINK_TEST_NM=plain expect injector-symbol-in-nm rejected 'Release contains lab/testing symbols or strings: Release/WGEX.app/Contents/MacOS/WGEXDaemon$'
LINK_TEST_NM=mangled expect injector-split-mangled-name rejected 'Release contains lab/testing symbols or strings: Release/WGEX.app/Contents/MacOS/WGEXDaemon$'

rm -rf "$work"
printf 'check-link: %d passed, %d failed\n' "$pass" "$fail"
((fail == 0))
