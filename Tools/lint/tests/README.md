# Linter negative fixtures

Every file here is deliberately wrong. `Tools/lint/run-selftests.sh` runs each
linter on its fixture and fails unless the linter rejects it. The tree-wide
`just lint` excludes this directory. Values here are fixtures, not secrets.

## Licence fixtures

`licences/` feeds `Tools/lint/check-licences.sh`. Each directory except `pass/`
plants a violation (copyleft SPDX tag, copyleft header text without a tag,
LGPL, AGPL, Elastic and SSPL markers, MPL-2.0, an identifier outside the
allowlist, an unrecognised licence file) and must be rejected. MPL-2.0 is
rejected everywhere. `licences/pass/` must be accepted. These are fixtures;
none of this code ships.

## Secret-scanner fixtures

`secrets/tree/` is a miniature repository for
`Tools/lint/check-no-secrets-in-strings.sh`: key-shaped strings under
`Tests/Fixtures/`, `Vendor/` and `Engine/go/vendor/` are allowed; the same kind
of string under `Sources/` must be reported. The self-test also builds the real
`Tests/Fixtures/keys/` values into a temporary Swift file to prove the scanner
flags those exact keys anywhere outside the allowed paths.

## Typos selection fixtures

`typos/report-row/` and `typos/digest.md` feed the M1-10f cases in
`Tools/lint/run-selftests.sh`. The 12-hex digest `6c676daa00de` is flagged by
typos when checked directly. Copied into a `Tests/Reports/` tree, the
`verdict.json` holding it is left out of the lint typos step, while the same
digest in a Markdown file there is still caught.

## Plan scope fixtures

`.plan/` is orchestration state, out of scope for typos, public prose and the
secret-string scan, but not for gitleaks (M00-T01). `scope/run.sh` proves the
prose and secret-string skips and the pre-commit hook refusing a commit when
the framework is absent. The `typos-plan-*` cases plant `typos/misspelled.md`
under a scratch `.plan/`: hidden by `TYPOS_PATHSPEC` alone (a config without
its `.plan/` line) and by `typos.toml` alone, caught outside `.plan/`.
`scope/pre-commit-config.py` checks the typos hook's `.plan/` exclude and that
gitleaks has no filter; mutated copies of the config are refused. The
`gitleaks-plan-*` cases plant a fake token, built at run time, under a scratch
`.plan/` and expect both the hook's `gitleaks dir` and the staged scan to
report it. `scope/lint-gitleaks.sh` copies `lint.sh` and its helpers into a
scratch repository, plants the same token under `.plan/` and requires the
`just lint` entry point to fail its whole-tree gitleaks step
(`Tools/lint/check-gitleaks.sh`) with the token redacted, then to pass that
step once the token is gone; a copy of `lint.sh` without the step is refused.

## Fail-closed cases

`fail-closed/run.sh` (called from `Tools/lint/run-selftests.sh` under a deadline, runnable alone) proves M1-32 in scratch
trees under `$TMPDIR`; the real checkout is never run in. `load_repo_files` in `Tools/lint/lib.sh` fills `REPO_FILES`; it
and the stream form `repo_files` return 1 with `lint: git could not list repository files: <git's first stderr line>` when
git cannot list files, and every repository-mode check (and each selection in `lint.sh`) stops with a failure instead of
seeing zero files. The cases cover `GIT_TEST_ASSUME_DIFFERENT_OWNER=1`, a non-repository root, a corrupt index, an empty
repository listing for every repository-mode check (a failure in repository mode; explicit paths keep their old
behaviour), zero package manifests, `EXIT` traps, and a clean tree still passing. The planted file is the existing
`prose/denylisted.md` fixture; output stays in files and is never echoed. `git`, `bash`, `python3` and every
script under test run under a perl-alarm deadline (`WGEX_FC_DEADLINE`, default 120 s); the local file utilities used on
scratch trees (`cp`, `mkdir`, `rm`, `chmod`, `mktemp`, `dirname`, `sed`, `awk`, `grep`, `cmp`, `cut`, `sort`, `wc`, `tr`,
`cat`, `printf`) do not. A case with a git and a python3 that hang proves a nested run still finishes.

### No self-test reaches the network

Nothing in `Tools/lint/tests` may run the real `govulncheck`: it fetches the vulnerability database. Four layers, each
enough on its own for the cases it covers:

1. The whole fail-closed suite is offline whatever the caller exported: `WGEX_OFFLINE=1` (`lint.sh` and
   `check-go-vulnerabilities.sh` skip the database) and `GOVULNDB=file:///nonexistent` (a real call could not fetch), with
   `GOPROXY=off` and `GOTOOLCHAIN=local`. The cases that need the online path (`lint_reports`, the
   `exit-traps-*-check-go-vulnerabilities` cases) set `WGEX_OFFLINE=0` themselves and run under `bash`.
2. A mock `govulncheck` first on `PATH` (it prints `No vulnerabilities found.` and counts its calls) and a tripwire
   behind it in place of the real binary (it records any call and exits 97).
3. The five `lint.sh` cases run `bash Tools/lint/lint.sh`, never `just lint`: a `just` recipe runs under `zsh -lc`, whose
   login profile rebuilds `PATH` and puts the real `govulncheck` (`~/.toolchains/go/bin`) ahead of the
   mock and the tripwire, so neither sees that call. Any case that goes through `just` or another login shell bypasses
   layer 2; only layer 1 (and the sandbox below) holds there. A refusing `just` shim on the suite's mock PATH records
   arguments and exits 95; the final guard requires its log empty, including when a case expected that failure.
   `no-case-runs-a-just-recipe` also greps every non-comment suite line for `\bjust\b|zsh +-l|--login` with a reasoned
   exact-line allowlist in `fail-closed/nojust_scan.py`. This catches literal login-shell bypasses; runtime-built paths
   or shell names remain outside that text check. `nojust-cases.bash` probes multi-line helpers, spacing, options,
   indentation and a variable-held recipe name through an isolated shim. It is scanned for the login-shell shape,
   which is never executed. The unrelated `just docs-check` step in scratch copies of `lint.sh` is replaced by a stub
   because those trees contain no `Tools/docs`; the checkout's `lint.sh` is unchanged.
4. Every scratch tree holds an `Engine/go/go.mod`, so each `lint.sh` run reaches its govulncheck step. The last case,
   `govulncheck-never-real`, requires an empty tripwire log, at least one mock call (the online cases reached it) and
   that each of the five `lint.sh` cases printed `==> govulncheck` and `govulncheck: skipped (WGEX_OFFLINE=1; ...)`.

`govulncheck/run.sh` has its own mock first on `PATH` that answers every call. It removes inherited `GO*` and `CGO_*`
variables, sets its own offline Go environment and snapshots the complete names and values. The mock exits 98 unless
called as `govulncheck ./...`, and exits 96 unless the working directory is the tree's `Engine/go`
(`$WGEX_VULN_TEST_ROOT/Engine/go`) and the Go environment exactly matches that snapshot, including `GOVULNDB`. Added,
changed and removed variables are refused. It prints five lines across stdout and stderr; each online case requires
the case's result and both fourth/fifth-line sentinels. Each script invocation has a 120 s perl-alarm deadline.
The go-vet and staticcheck fixtures in `run-selftests.sh` explicitly set `GOPROXY=off` as well as `GOTOOLCHAIN=local`.

To prove the suite never reaches the real tool, run it under `sandbox-exec` with a profile that allows everything except
`process-exec` of the real `govulncheck` path and `network-outbound`, with `WGEX_OFFLINE=0` exported to it: the kernel log
(`log show --predicate 'sender == "Sandbox"'`) must hold no denial of the real binary and none of the network. A tripwire
on `PATH` set outside the suite proves nothing: a login `zsh` shadows it.

### EXIT traps

On bash 3.2 (`/bin/bash`, the shell the gate runs) an `EXIT` trap of the form `rc=$?; ...; exit "$rc"` receives status 0
after a shell-level error under `set -e` (an unbound variable, `${x:?}`, a readonly assignment, a bad substitution, a
failed `source`), so the script exits 0 and `lint.sh` reports the check as passed. Every `EXIT` trap in `Tools/lint`
therefore fails closed: `trap 'rc=$?; ((rc != 0)) || ((${finished:-0})) || rc=1; ...; exit "$rc"' EXIT`, and the script
sets `finished=0` before the trap (an exported `finished=1` in the caller must not count) and `finished=1` just before
each intended successful end. The suite checks behaviour, not text:

- `trap-preserves-status-<kind>` runs each real trap line, verbatim, in a `set -euo pipefail` probe after an unbound
  variable, `${x:?}`, a readonly assignment, a bad substitution and a failed `source` (all must exit non-zero), and after
  `false`, `exit 3` and a clean finish (status kept exactly);
- `exit-traps-keep-status-<script>` copies each real script that sets a trap into a scratch tree, injects an unbound
  variable right after the trap and requires a non-zero exit with the error on stderr; for the three scripts `lint.sh`
  runs (`check-public-prose`, `check-package-deps`, `check-go-vulnerabilities`) it also requires `lint.sh` to name the
  step in its `FAILED` line; `exit-traps-keep-status-covers-every-trap` fails when a script gains a trap without a case;
- `exit-traps-ignore-inherited-finished-<script>` runs the same injected copies under an exported `finished=1` and
  requires the same non-zero exit (and, for the three `lint.sh` steps, the same `FAILED` line);
- `fail-closed/trap_scan.py` discovers traps: any `trap` command with `EXIT` (any case) or a numeric zero (`0`, `00`)
  among its signals, or the one-argument `trap EXIT` (a reset), indented or not, inside a function or an `if`, after a
  `NAME=value` prefix, one line or several, with or without a comment. `<<` inside `$((` or `((` is a shift, not a
  here-document. Every such trap in `Tools/lint` must be
  exactly `trap '<action>' EXIT` (or `trap -- '<action>' EXIT`) on one line at column 0 with nothing after it; any other
  form fails `trap-discovery-real-scripts` until it is rewritten or the probes learn it. `trap-discovery-refuses-<form>`
  proves it on scratch scripts (indented, in a function, in an `if`, trailing comment, `EXIT INT TERM`, signal `0`,
  trailing whitespace, multi-line, line continuation, double-quoted, a bare handler name, a lower-case `exit`, `00`, an
  assignment prefix, `trap EXIT`, a trap after a spaced arithmetic shift, a trap after a quote inside `$( )` inside a
  double-quoted string, a trap after a partly quoted here-document delimiter); the probes run every trap in a file, not
  only the first (`trap-probe-covers-second-trap`). Here-document bodies are data to the scanner. The delimiter is the
  whole word with its quotes removed (`E"O"F` and `'E'OF` close on `EOF`), and a `$( )` inside a double-quoted string is
  lexed with its own quotes.
- The scanner is backed by a plain search (`trap_inventory`): every non-comment line that holds the word `trap` must be
  covered by a trap statement, a here-document body, a one-line word or a comment in the scanner's output, otherwise
  the suite fails (`trap-discovery-backstop-names-unaccounted-lines`: a scanner that reports nothing).
  Unquoted or double-quoted backticks raise a scan error (status 2), including inside substitutions; the suite covers
  VERIFY e1/e2/e5 and all nine later-word and quote-split ADV shapes. Single-quoted or escaped backticks, comments and
  here-document bodies do not trigger this backtick error. A word holding `trap` after `;`, `&&`, `||`, `|`, a backtick or `$(` is not accounted as a string. An unterminated quote, `$( )` or here-document is a scan failure. A line with the word inside
  a quoted string that spans several lines therefore fails too; write such text in a here-document. `trap-probe-refuses-non-trap-line`: the
  probes and the injection run a line only after checking it is the canonical trap form, so an inventory that names the
  wrong line cannot probe something harmless.
- `govulncheck-test-kills-<mutant>` runs `govulncheck/run.sh` against twenty-one mutants of `check-go-vulnerabilities.sh`
  (failures ignored `V`, `finished=1` removed `F2`, the offline skip disabled `O`, `${WGEX_OFFLINE:-0}` changed to `:-1`
  `D`, `./...` changed to `.` `SC`, the findings no longer printed `C`; and, for the mock's directory, environment and
  streams: `cd` to `tests/go-vet` `CD3`, `cd` removed `CD`, `cd` to `Tools/lint` `CD2`, `GOVULNDB` set `DB`, `head -n 1`
  on the output `H1`, `grep -v` on it `TR`, stderr sent to `/dev/null` `E2`, `!= 0` in place of `== 1` `NZ`; and
  `GOOS=linux` `X-GOOS`, `head -n 3` `X-HEAD3`, `== 1*` `X-GLOB`, `env -u GOVULNDB` `X-UNSETDB`; and hard-coded `GOSUMDB=off` `Y-SUMDBOFF`,
  `GOPROXY=off GOTOOLCHAIN=local` `Y-PROXYOFF`, `GOFLAGS=-mod=readonly` `Y-SAMEFLAGS`); the
  self-test must exit non-zero and name the case. Its assertions set `ok=1` only when every condition holds; a bare
  `[[ ]] && ! grep` list never fails under `set -e`. The sixth case, `unset-offline`, runs under `env -u WGEX_OFFLINE` and
  must reach the mock (the vulnerable mock gives status 3 and its finding text): the default is online. The seventh,
  `yes-offline`, sets `WGEX_OFFLINE=yes`; the eighth, `ten-offline`, sets `WGEX_OFFLINE=10`. Both must reach the mock:
  only the value `1` means explicitly offline.

### Known limits of the trap scanner

`fail-closed/trap_scan.py` is a lexer, not a shell, and these shapes are outside what it (and the plain search behind it)
can see; none occurs in `Tools/lint` and the list is also the docstring of the scanner:

- `eval "trap '...' EXIT"` and `eval "$cmd"`: the trap is text inside one word, which the plain search accepts silently.
- A trap built at run time (`T=trap; $T '...' EXIT`, `${T:-trap} '...' EXIT`) and a trap in a here-document or file that
  is executed later as a script.
- `SIGEXIT` is matched as `EXIT` although bash 3.2 does not accept it (the scanner is generous on purpose).
- Inside a double-quoted `$( )` only parentheses and quotes are counted: a `case` pattern `a)` or a here-document with an
  unbalanced quote there ends the substitution in the wrong place. Backtick substitutions fail the scan with status 2;
  they cannot desynchronise the inventory across later words or quote-split trap spellings.
- `$[ ... ]` legacy arithmetic with `<<` reads as a here-document (a scan failure when it is never closed).
- Plain ANSI-C quoted here-document delimiters (`$'EOF'`) close on `EOF`, even with a later `$EOF` line. Escaped
  ANSI-C delimiters are unsupported and fail the scan with status 2.

### Known limit: a partial listing

A listing that is wrong but not empty is not detected. With `GIT_INDEX_FILE` pointing at an index that holds only a few
files, the checks scan those files and pass. The gate (`gate-entry`) strips `GIT_INDEX_FILE`, so this affects bare runs
only; it is recorded here, not fixed (N3 of the M1-32 verification).
