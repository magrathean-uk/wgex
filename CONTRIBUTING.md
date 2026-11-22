# Contributing

## Toolchain

Toolchain minimum versions live in [`Toolchain.lock`](Toolchain.lock); newer is fine. Install the Homebrew tools
(`brew install just xcodegen swiftlint swiftformat xcbeautify typos-cli shellcheck shfmt
pre-commit gitleaks python@3.15 ripgrep`) and the Go tools at the pinned module versions with
`go install <module>@<version>`, then run:

```sh
just doctor        # minimum versions; newer is fine, older/missing fails
just lint          # every linter on the tree
just lint-selftest # proves each linter rejects its fixture in Tools/lint/tests/
just bootstrap     # doctor, engine, engine-test, gen; first checkout
just check         # fast gate: doctor, lint, macOS matrix, debug build, unit/race tests
just check-full    # milestone gate: simulator matrix, release checks, TSan, fuzz, scripts and Lab compile
just docs-check    # docs/ source present and non-empty, cited paths and relative links resolve
just packages-matrix   # every package for macOS, iOS Simulator and tvOS Simulator
just testpeer -- --help   # the userspace WireGuard test peer (Tools/testpeer)
```

`just doctor --redact` masks device identifiers, certificate holder names and
the home directory, for pasting into evidence files.

## Hooks

If your Git setup has a global `core.hooksPath` with a gitleaks `pre-commit`
hook, that hook runs first on every commit and is the baseline secrets gate.

Run the repository's checks on demand with:

```sh
pre-commit run --all-files
```

The repository also ships opt-in hooks in [`.githooks/`](.githooks):
`pre-commit` (calls the global `pre-commit` hook first, then the
pre-commit framework on staged files) and `pre-push` (runs `just check`).
They are not enabled automatically. To enable them for this clone only:

```sh
git config core.hooksPath .githooks
```

This repository-level setting replaces the global hooks path for this clone,
which is why `.githooks/pre-commit` calls the global hook itself. Undo with
`git config --unset core.hooksPath`. Never change the global setting for this
repository.

## Commits

One commit per reviewed change, imperative subject of at most 72 characters,
and a body naming the commands that prove it and where the evidence lives (a test log, or
a path in the pull request).

## Linter fixtures

`Tools/lint/tests/` holds deliberately bad files, one per linter. They are
excluded from `just lint` and pre-commit. The code linters also skip the
vendored Go module tree (`Engine/go/vendor/`) and the design tool's scratch
directories (`Design/.work/`, `Design/.taste-skill/`); the public-prose check
still checks every indexed file. Add a fixture and a case in
`Tools/lint/run-selftests.sh` whenever a linter or rule is added.

## Build output and caches

All builds use `<base>/<checkout-name>`; base is `WGEX_BUILD_ROOT`, then
`CLEAN_DEV_BUILDS`, then `${TMPDIR:-/tmp}/wgex-build`. Worktrees therefore have
separate DerivedData and SwiftPM scratch. Swift package tests share one scratch
path; engine integration, TSan and Lab flags use separate paths. Go and SwiftPM
dependency caches live under `${CLEAN_DEVELOPMENT_CACHE_ROOT:-<build-root>}/wgex-deps`.

`just engine` hashes tracked and non-ignored unstaged engine sources and scripts,
vendor module metadata and the resolved APP_VERSION/APP_BUILD values passed to
the Go linker. Toolchain.lock minimum versions are eligibility policy, so floor
edits do not invalidate engine sources; preflight enforces the floors before reuse.
Provenance and build logs record the found tool versions. Unrelated Base.xcconfig
settings also leave the digest unchanged. It reuses a complete archive only when provenance and
archive checksums match. The source digest is embedded in the existing
`wgex_build_info().script_sha` field and recorded as `source_sha256` in provenance.
`just engine --force` rebuilds; `just engine macos` writes a separate archive
under the build root and leaves the production five-slice archive untouched.

One engine build runs per tree at a time. `just engine` and `just engine-test`
take an exclusive kernel lock (`flock`) on `Packages/WGEXEngine/.Binary.build.lock`
(git-ignored); a second writer in the same tree waits, then finds the first one's
build up to date (unless it was forced). `WGEX_ENGINE_LOCK_WAIT` is the wait in whole seconds (default
1800); `1.5`, `30m` or an empty value stop the writer with an error before it builds.
When the wait ends the writer fails naming the lock file, every process that has it
open (found with `lsof`, with its command line) and, as "last writer pid", the pid
the last build recorded in the file, which may have exited and is not necessarily a
holder. The kernel frees the lock when the last process holding the file exits, so a
crashed or killed build leaves nothing stale to clear; the next build removes its
temporaries. A held lock means a live process, possibly an orphaned assembler child,
still has the file open: find it with `lsof Packages/WGEXEngine/.Binary.build.lock`,
wait for it, or stop it only if it is not an engine build. Build steps inherit the
lock's file descriptor on purpose, so an orphan of a build keeps the tree locked; the
risk is that a toolchain helper that daemonises keeps the lock after a good build until
it exits, and every later engine step in that tree then waits and fails. Do not delete
the lock file to get past a wait: that does not free the lock, and a new file would let
a second build in beside the first. The engine
scripts are part of the engine source digest, so changing them needs `just engine`
and `just engine-test` in every tree.

`WGEX_OWN_MAC_BUILD` is reserved for the opt-in `just build-own-mac` recipe.
Every ordinary recipe refuses it when inherited, including empty or zero values;
gate entry also refuses an inherited `WGEX_LAB_BUILD`. Lab gate steps opt in
explicitly. An ordinary Release keeps its existing requirement strings.

Signing identity stays out of the repository. Copy `Config/Local.xcconfig.example` to
the git-ignored `Config/Local.xcconfig` and set `WGEX_TEAM` (your Apple Developer
team), `WGEX_OWN_MAC_LEAF` (the exact common name of your Apple Development
certificate) and `WGEX_OWN_MAC_PROFILE` (the UUID of your installed provisioning
profile). `Config/Base.xcconfig` includes the file when it exists, and
`just build-own-mac` reads all three from it, keeps the exact team and leaf
checks, and writes the pinned values into a generated, git-ignored Swift file
for the daemon requirement. Tests use synthetic identifiers only.

The own-Mac recipe requires external storage mode and an explicit
`WGEX_OWN_MAC_OUTPUT_ROOT`: an absolute internal-disk directory of your choice,
outside the repository. There is no default; an unset or empty variable is
refused. Supply a separate private job `TMPDIR` below the output directory's
parent, without nesting either directory inside the other. Direct Bash preserves
the supplied job temporary directory and session routing. The output directory,
its parent and the temporary directory must belong to the current user, have no
group or other permissions, and contain no symlinked ancestors. Each attempt
name is single use, including failed attempts;
its new DerivedData directory is never reused. The recipe passes
`SWIFT_ACTIVE_COMPILATION_CONDITIONS=$(inherited) WGEX_OWN_MAC_BUILD` directly to
Xcode. `just check-release-link mac` refuses own-Mac policy strings in ordinary
Release products; `just check-release-link mac own-mac` requires the own-Mac
marker in both the app and daemon. These checks inspect binaries without
launching them.

`just lint` scans the Git index and tracked working files, including new staged
files. Stage new files for the normal gate; use explicit paths and self-tests
while preparing a change. `WGEX_OFFLINE=1` explicitly skips the advisory database
check with one line; otherwise an unavailable database fails lint. `docs/` is the tracked
source of the public docs; edit it directly. `just docs-check` fails closed on a
missing or empty source, a cited repository path that does not exist and a
relative link that does not resolve.

## Gate evidence and test keys

Gates emit `gate-step:` records with an exit status and elapsed seconds. Keep raw
output under the routed build root and record the first green milestone run,
step list and timings in the pull request description.

A gate result is the set of `gate-step:` lines (every step of `just check` or
`just check-full`, each `exit=0`), the final line `check: passed (N gate steps,
all exit=0)` or `check-full: passed (N gate steps, all exit=0)` with N equal to
the number of that recipe's own `gate-step:` lines (check-full's `full/check` step
runs `just check`, which prints its own 12-step `check: passed` line and its own
steps; check-full's N counts its 15 `full/` steps), and the command's exit status. Never accept the text
`check: passed` alone, and never a run with zero `gate-step:` lines: `JUST_DRY_RUN`
and similar `just` variables make the outer `just` echo the recipe and run
nothing. The recipes' first line (`timed-step.py --enter`) refuses to start with
such a `JUST_*` variable in the environment (exit 2, error names the variable),
and the final line is printed by `timed-step.py --done` from a ledger that only
the executed steps write, so a dry run cannot print it. Gate entry also names,
on one `kept from caller:` line, any verdict-changing `WGEX_*` opt-out it passed
on (`WGEX_OFFLINE`); record those with a green result.

`JUST_QUIET` (or `just --quiet`) also silences that refusal text: the run still
exits 2 with zero `gate-step:` lines, so the rule above rejects it, but the
error naming the variable is not shown. `check` and `check-full` take their
ledger path as a recipe parameter, so never pass them an argument: `just check
lint` would make `lint` the ledger, and `--enter` refuses any ledger path that
is relative or outside `$TMPDIR` (exit 2, nothing created). Run each recipe on
its own.

Every gate step's environment is built from a fixed list, not from a strip list
(`Config/Scripts/knobs.py`, applied by `timed-step.py` at gate entry and by the
tooling self-test to its own process). The list is `PATH`, `HOME`, `TMPDIR`,
`USER`, `LOGNAME`, `SHELL`, `TERM`, `LANG`, `LC_*`, `CODEX_THREAD_ID`, `CLAUDE_CODE_SESSION_ID`, `WGEX_*`,
`GOPROXY`, `GOTOOLCHAIN`, `GOSUMDB`, `GOVULNDB`, `DEVCACHE` and every
`CLEAN_DEV_*` and `CLEAN_DEVELOPMENT_*` name (the routing names
`~/.config/wgex/env.zsh` pins; a self-test reads that file and fails if it names
one the list does not pass). Everything else the caller exported is dropped, so
a variable nobody listed (a build setting such as `OTHER_SWIFT_FLAGS`,
`TEST_RUNNER_<VAR>`, `DYLD_*`, `GIT_*`, a toolchain selector, a knob a newer tool
adds) cannot change a step. Each step that drops anything prints one line with a count, `gate-entry:
LABEL dropped N inherited variables`; the `--enter COMMAND` line (check's bash entry point) also names them;
a value is never printed. Every recipe line runs under `zsh -lc`, so
`env.zsh` re-exports the caches and routing the list leaves out (`GOPATH`,
`GOCACHE`, `XCODE_DERIVED_DATA_PATH`, `SWIFTPM_SHARED_CACHE`, `XDG_*`); a bare
bash or python3 step sees the list only. `GOFLAGS` is not on it (the gate cannot
tell a wrapper's from a caller's). Engine builds and `Config/Scripts/test.sh`
set their own; `Tools/lint/lint.sh`'s `go vet` and `staticcheck` rely on vendor
auto-detection, with the same result.
`GOPROXY`, `GOTOOLCHAIN`, `GOSUMDB` and `GOVULNDB` pass with whatever value any caller exported.
This is acceptable for the wrapped offline gate: its wrapper fixes these values and `WGEX_OFFLINE=1` skips the advisory
database; an unwrapped caller with `WGEX_OFFLINE` unset still chooses these values.

To add a name, edit `GATE_ALLOWED_NAMES` or `GATE_ALLOWED_PREFIXES` in
`knobs.py` (one place; the gate and the self-test both read it), say why in its
docstring, add it to `test_the_allowlist_passes_exactly_its_names_and_prefixes`
and to this paragraph. A test channel that has to cross a gate step (a stub's
log path, say) must be a `WGEX_*` name.

What breaks, on purpose: `DEVELOPER_DIR`, `TOOLCHAINS` and `SDKROOT` overrides
are dropped, so a step gets xcode-select's default; doctor enforces the minimum
versions in `Toolchain.lock` and fails if that default is below the floor; `SSH_AUTH_SOCK`, `HTTPS_PROXY` and the
password-manager session variables are dropped (nothing offline needs them; an online
testpeer run behind a proxy would, and so would anything else that fetches); go
flags (`GOFLAGS`) are set by repository scripts where needed; `GOPATH` comes from
`env.zsh`; `GOCACHE` and `STATICCHECK_CACHE` are set by the repository's scripts. `GOENV` uses go's default file under the trusted
HOME; neither `env.zsh` nor the repository sets it. The outer `just check` line runs before
`timed-step.py`, so the justfile's recipe shell still removes the zsh startup
variables (`ZDOTDIR` and the rest of `knobs.ZSH_KNOB_NAMES`) itself.

HOME and PATH are trusted inputs of the gate. The trust boundary is the user's
own account: a caller who can set HOME can already set PATH and edit every
dotfile, so pinning HOME buys nothing real and would break the routing
`~/.config/wgex/env.zsh` derives from it; both are on the list and pass
unchanged. The rule, the reason for the list and the record of the earlier strip
list's names are in `Config/Scripts/knobs.py`, and the tooling self-test pins
them; change all three together.

The print convention applies to Apps, Daemon, Extensions and package Sources.
Command-line tools under Tools and tests may print their public output. The
daemon exception covers only the version/doctor branch. Never print secrets.
Tests may generate ephemeral keys in memory and store them only in their own
temporary directory; never use a real key active on another device or commit
key material. Fuzz campaigns run against temporary fixture copies so findings
cannot write generated keys into the repository. Crash/findings are retained in
per-test directories under `<build-root>/fuzz-findings/`, with path and seed in
the diagnostic; these private test artifacts must not be committed.

Engine race tests use vendored modules with network downloads disabled. Testpeer
uses the versions pinned in its go.mod/go.sum with `-mod=readonly`; missing
modules populate the dependency cache. `WGEX_OFFLINE=1` disables those downloads
as well as the explicit advisory-database skip.

The build-root override must be an absolute path outside this repository,
including after symlink resolution. BuildIdentifiers generation renames a
same-directory temporary file to keep replacement atomic across volumes.
Full gates run hosted iOS simulator unit tests explicitly and use fresh Go
race runs (-count=1). Lab flags apply to WGEXBackendMac, WGEXProfileStore and WGEXUI.
Contributors run the iOS WGEX.app test host inside iOS Simulator for these unit
tests: no Network Extension runs and host networking cannot be changed. Do not
launch the Mac app, daemon or CLI on your own machine; use the lab guests.

The supported SwiftLint entry point is `just lint` (Tools/lint/lint.sh), which
sets WGEX_LINT_ROOT. Direct calls without this variable are unsupported; custom
fixture invocations must set it to their absolute repository root. Print filters anchor to this absolute
root, so Tools/Tests folders above the checkout cannot hide a violation.

## Lab command reference

Guest operations are guarded contributor workflows that run inside a lab VM;
host verification uses only `just lab build` and the mocked harness. `just lab trust` explicitly pins the lab SSH host
key. The guest GUI forms are `just lab gui shot OUT.png`, `dump APP [WINDOW]`,
`click X Y`, `activate APP`, `open-pane TARGET`, `run CMD...` and
`seed-tcc [BINARY...]`, each prefixed with `just lab gui`.
