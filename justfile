# WGEX task runner. Ordinary recipes refuse inherited own-Mac flags before login zsh;
# its host cache and build routing applies (plan 03 §7). env(1) drops the zsh startup knobs first (Config/Scripts/knobs.py
# ZSH_KNOB_NAMES: ZDOTDIR makes zsh read a caller's .zshenv instead of ~/.zshenv, which can re-export every variable the gate
# entry strips or end a line with exit 0), so even the outer `just check` line, which runs before timed-step, is covered.
set shell := ["/usr/bin/env", "-u", "ZDOTDIR", "-u", "TMPPREFIX", "-u", "NULLCMD", "-u", "READNULLCMD", "-u", "ARGV0", "-u", "CDPATH", "-u", "TMOUT", "python3", "-I", "-B", "Config/Scripts/knobs.py", "zsh", "-lc"]

# List recipes
default:
    @just --list --unsorted

# Check Toolchain.lock minimum versions; newer is fine, older/missing fails [P0-02]
doctor *args:
    bash Tools/doctor/doctor.sh {{args}}

# Run every linter on the tree [P0-09]
lint:
    bash Tools/lint/lint.sh

# Package dependency table and Release testing-import check [M1-15]
check-package-deps:
    bash Tools/lint/check-package-deps.sh

# Prove each linter rejects its negative fixture [P0-09]
lint-selftest:
    bash Tools/lint/run-selftests.sh

# Tooling regression tests [M1-13]
tooling-selftest:
    python3 -I -B Config/Scripts/tests/run.py

# Index every new file only in a disposable TMPDIR copy; prove the complete lint gate [M1-13]
staged-tree-proof:
    python3 -I Config/Scripts/tests/staged-tree.py

# Prove stale-engine refusal and rebuilding; temporarily edits then restores one Go comment [M1-13]
digest-proof:
    python3 -I Config/Scripts/tests/prove-digest.py

# Fast per-ticket gate; host builds and package tests only [M1-13]. The result is the set of gate-step lines and the final
# status; the last line, printed by timed-step from the gate ledger, cannot appear in a dry run (CONTRIBUTING.md, gate evidence).
check $WGEX_GATE_LEDGER=join(env('TMPDIR', '/tmp'), 'wgex-gate-' + uuid()):
    python3 -I Config/Scripts/timed-step.py --enter
    python3 -I Config/Scripts/timed-step.py check/doctor just doctor --quiet
    python3 -I Config/Scripts/timed-step.py --enter bash Config/Scripts/check.sh
    python3 -I Config/Scripts/timed-step.py --done check

# Full milestone gate: iOS hosted units may launch WGEX.app inside iOS Simulator
# only, without NE or host networking; host app/daemon/CLI launches remain forbidden [M1-13]
check-full $WGEX_GATE_LEDGER=join(env('TMPDIR', '/tmp'), 'wgex-gate-' + uuid()):
    python3 -I Config/Scripts/timed-step.py --enter
    python3 -I Config/Scripts/timed-step.py full/check env WGEX_GO_RACE_COUNT=1 just check
    python3 -I Config/Scripts/timed-step.py full/packages-simulators just packages-matrix --simulators
    python3 -I Config/Scripts/timed-step.py full/ios-hosted just test ios
    python3 -I Config/Scripts/timed-step.py full/build-release just build mac release
    python3 -I Config/Scripts/timed-step.py full/entitlements-release bash Tools/lint/check-entitlements.sh --configuration Release --require mac
    python3 -I Config/Scripts/timed-step.py full/release-link just check-release-link mac
    python3 -I Config/Scripts/timed-step.py full/tsan just test-tsan
    python3 -I Config/Scripts/timed-step.py full/lint-selftest just lint-selftest
    python3 -I Config/Scripts/timed-step.py full/fuzz env WGEX_FUZZ_SECONDS=60 just test fuzz
    python3 -I Config/Scripts/timed-step.py full/lab-scripts just lab-scripts-test
    python3 -I Config/Scripts/timed-step.py full/docs-tests just docs-test
    python3 -I Config/Scripts/timed-step.py full/lab-compile just lab-compile
    python3 -I Config/Scripts/timed-step.py full/backend-mac-lab env WGEX_LAB_BUILD=1 just test WGEXBackendMac
    python3 -I Config/Scripts/timed-step.py full/profile-store-lab env WGEX_LAB_BUILD=1 just test WGEXProfileStore
    python3 -I Config/Scripts/timed-step.py full/ui-lab env WGEX_LAB_BUILD=1 just test WGEXUI
    python3 -I Config/Scripts/timed-step.py --done check-full

# Prepare a new checkout in dependency order [M1-13]
bootstrap:
    just doctor
    just engine
    just engine-test
    just gen

# Build Lab only; never boots a VM or launches a product [M1-13]. Also compiles the RT-17 corpus client and
# dry-runs the M5.3-07 update build (its real build is the row's own heavy step) [M03-T03]
lab-compile:
    just lab build
    bash Tools/lab/corpus/build.sh
    bash Tools/lab/update/build.sh --dry-run

# Remove generated project and build output [P0-01]
clean:
    rm -rf -- WGEX.xcodeproj Engine/build Packages/WGEXEngine/Binary
    bash -c 'source Config/Scripts/lib.sh; rm -rf -- "$(build_root)"'

# Generate WGEX.xcodeproj with XcodeGen, then run the post-checks [P0-03]
gen:
    bash Config/Scripts/gen.sh

# Build the engine XCFramework [P0-05]
engine *args:
    bash Engine/scripts/build-xcframework.sh {{args}}

# Build the test-support XCFramework [P0-05, P1-18]
engine-test:
    bash Engine/scripts/build-test-support.sh

# Build a platform: mac (ad hoc), ios or tv (simulators), or all [P0-03]
build platform configuration="debug":
    bash Config/Scripts/build.sh {{platform}} {{configuration}}

# Install the Development-signed `just build ios-device` result on a connected iPhone or iPad [M06-T09]
[positional-arguments]
install-ios-device udid:
    bash Config/Scripts/install-ios-device.sh "$@"

# Opt-in own-Mac Release build; compare two attempts with `compare A B`.
[script]
[positional-arguments]
build-own-mac attempt="A" *rest:
    exec /usr/bin/env -u ZDOTDIR -u TMPPREFIX -u NULLCMD -u READNULLCMD -u ARGV0 -u CDPATH -u TMOUT -u BASH_ENV -u ENV bash Config/Scripts/build-own-mac.sh "$@"

# Build every package for macOS, iOS Simulator and tvOS Simulator; optional package names [P0-04]
packages-matrix *packages:
    bash Config/Scripts/packages-matrix.sh {{packages}}

# Run tests: a package name, all (every package), mac, ios or tv [P0-04, P0-21]
test target="all":
    bash Config/Scripts/test.sh {{target}}
    @if [ "{{target}}" = mac ]; then bash -c 'source Config/Scripts/lib.sh && cd "$WGEX_ROOT" && configure_caches && echo "test: compiling the Mac previews (WGEXUITesting)" && swift build --package-path Packages/WGEXUITesting --scratch-path "$(build_root)/spm/shared" --cache-path "$(dependency_cache)/swiftpm"'; fi

# Delete stale WGEX simulator devices: dry run unless --apply; manual, never part of check or check-full [M1-26]
sim-prune *args:
    bash -c 'source Config/Scripts/lib.sh && simulator_prune "$@"' sim-prune {{args}}

# Verify entitlements and Info.plist keys of the built products [P0-20]
check-entitlements configuration="debug":
    bash Tools/lint/check-entitlements.sh --configuration {{configuration}}

# Device integration tests [P1-05]
test-device *args:
    @echo "not implemented yet: see plan ticket P1-05" >&2; exit 2

# Lab guest control (Tart). Every subcommand runs through Tools/lab/tart/lab.sh:
# lab up                     restore approved, boot, verify guarded SSH
# lab down                   clean guest shutdown
# lab ssh [-- cmd ...]       interactive or explicit guest command
# lab test [smoke] [--keep]  read-only suite, then restore approved
# lab snapshot NAME          stopped clone, then restart
# lab restore NAME           replace working guest from stopped clone
# lab build                  xcodebuild -configuration Lab via lab/build.sh
# lab install [WGEX.app]     signed Lab build to guest /Applications
# lab pcaps                  guest pcaps to build_root()/lab-captures/manual
# lab trust                  pin the lab SSH host key explicitly
# lab gui shot OUT.png        guest screenshot (guest work only)
# lab gui dump APP [WINDOW]   guest accessibility tree
# lab gui activate APP        focus the guest app
# lab gui open-pane TARGET    guest URL or application
# lab gui run CMD...          guest command in the console session
# lab gui seed-tcc [BINARY...] guest TCC fixture setup
# lab gui click X Y          click guest screen coordinates
# lab gui keys APP WINDOW ID up|down COUNT  focus ID, press arrow keys (sidebar selection)
# lab reset-btm --yes-reset  explicit guest reset; never approves daemon
# lab verdict ROW [--dry-run]  receiver verdict and bounded row report
# lab peer up [--dry-run]      provision dedicated Lima wg0
# lab relay [start|stop|status] [--dry-run]  managed ordinary UDP relay
# lab profile [default|full4|dual|dns|lockdown|wrong-key] [--dry-run]  private config pipe; every variant carries DNS
# lab iperf3 fetch|path [--dry-run]  pinned static guest iperf3, fetched and verified host-side
# lab help                   complete subcommand list
[positional-arguments]
lab *args:
    bash Tools/lab/tart/lab.sh "$@"

# Userspace WireGuard test peer; `just testpeer -- --help` lists its flags [P0-08]
[positional-arguments]
testpeer *args:
    cd Tools/testpeer && if [[ "${1-}" == "--" ]]; then shift; fi && go run . "$@"

# Release archives [P1-06]
archive *args:
    @echo "not implemented yet: see plan ticket P1-06" >&2; exit 2

# Notarise a disk image [P7-03]
notarize *args:
    @echo "not implemented yet: see plan ticket P7-03" >&2; exit 2

# Generate the Sparkle appcast [P7-04]
appcast *args:
    @echo "not implemented yet: see plan ticket P7-04" >&2; exit 2

# Software bill of materials [P7-11]
sbom *args:
    @echo "not implemented yet: see plan ticket P7-11" >&2; exit 2

# Bump the version [P7-01]
bump *args:
    @echo "not implemented yet: see plan ticket P7-01" >&2; exit 2

# Assert engine placement in the built daemon/providers and its absence from apps/CLI [P1-02]
engine-link-check:
    bash Engine/scripts/check-link.sh

# P1-03a: the real c-archive passed 100 cycles with TSan; keep it in the gate.
test-tsan:
    bash Config/Scripts/test.sh tsan

# Assert no lab hooks or testing backends in Release products without launching them [M1-01]
check-release-link platform="all" mode="ordinary":
    bash Engine/scripts/check-link.sh --release {{platform}} {{mode}}

# Fail-closed check of the tracked docs source: present, non-empty, citations and links resolve [M1-13]
docs-check:
    python3 -I Tools/docs/check.py

# docs-check regressions: missing source, dangling citation, broken link [M1-13]
docs-test:
    bash Tools/docs/tests/run.sh

# Offline verdict and mocked Tart regression suites; no VM access [M1-13]
lab-scripts-test:
    bash Tools/lab/tests/run.sh
