#!/usr/bin/env bash
# M1-32: the lint scripts fail closed when git cannot list the repository's files, and their EXIT traps keep the
# exit status. Every case builds a scratch tree under $TMPDIR (the real checkout is only read, never run in) and
# runs the real scripts in it, each under a deadline. A case passes only when the exit status matches AND the
# output names the expected message, so a crash, a timeout or an unrelated failure cannot pass. Output is kept
# in files and never echoed: the planted file holds a denylisted term (the existing prose fixture).
# shellcheck disable=SC2016 # single quotes are deliberate: the probe scripts and patterns carry literal $
set -uo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/wgex-fail-closed.XXXXXX")"
# The trap fails closed: bash 3.2 hands an EXIT trap status 0 after a shell error under set -e (unbound variable, ${x:?},
# readonly, bad substitution, failed source), so the script sets finished=1 just before each intended successful end.
# finished=0 first: an exported finished=1 in the caller must not mark an erroring script as finished.
finished=0
trap 'rc=$?; ((rc != 0)) || ((${finished:-0})) || rc=1; rm -rf "$work"; exit "$rc"' EXIT

pass=0
fail=0
# No case may run the real govulncheck (it fetches the vulnerability database, and downloads are not allowed on this
# host). Four layers, none of which depends on the others:
#   1. the whole suite is offline: WGEX_OFFLINE=1 (lint.sh and check-go-vulnerabilities.sh skip the database) and
#      GOVULNDB=file:///nonexistent (a real call could not fetch), whatever the caller exported. The cases that need the
#      online path set WGEX_OFFLINE=0 themselves and run under bash, where the next layer holds;
#   2. a mock govulncheck goes first on PATH and a tripwire behind it stands in for the real binary: it records any call
#      that gets past the mock and fails it;
#   3. the lint.sh cases run it with bash, never through `just`: every `just` recipe runs under `zsh -lc`, whose login
#      profile rebuilds PATH and puts the real govulncheck ahead of the mock and the tripwire (M1-39 VERIFY, F1);
#   4. every scratch tree holds an Engine/go/go.mod, so each lint.sh run reaches the govulncheck step, and the last case
#      of the suite requires those runs to have skipped it (M1-39 N4, M1-42 F1).
export WGEX_OFFLINE=1 GOVULNDB=file:///nonexistent GOPROXY=off GOTOOLCHAIN=local
mockbin="$work/mock-bin"
tripbin="$work/tripwire-bin"
mock_log="$work/mock-govulncheck.calls"
trip_log="$work/tripwire-govulncheck.calls"
just_log="$work/just.calls"
make_just_shim() {
  printf '#!/bin/sh\nprintf "call: %%s\\n" "$*" >>"%s"\nexit 95\n' "$2" >"$1/just"
  chmod +x "$1/just"
}
mkdir -p "$mockbin" "$tripbin"
make_just_shim "$mockbin" "$just_log"
: >"$mock_log"
: >"$trip_log"
: >"$just_log"
printf '#!/bin/sh\nprintf "call: %%s\\n" "$*" >>"%s"\necho "No vulnerabilities found."\nexit 0\n' "$mock_log" >"$mockbin/govulncheck"
printf '#!/bin/sh\nprintf "call: %%s\\n" "$*" >>"%s"\necho "govulncheck tripwire: the real tool must never run in a self-test" >&2\nexit 97\n' "$trip_log" >"$tripbin/govulncheck"
chmod +x "$mockbin/govulncheck" "$tripbin/govulncheck"
export PATH="$mockbin:$tripbin:$PATH"
# git, bash, python3 and every script under test run under a deadline (macOS has no GNU timeout); local file
# utilities on scratch (cp, mkdir, rm, chmod, mktemp, dirname, sed, awk, grep, cmp, cut, sort, wc, tr, cat, printf) do not.
# WGEX_FC_DEADLINE shortens it for the hanging-tools case below.
deadline() { perl -e 'alarm shift; exec @ARGV or die "exec failed\n"' "${WGEX_FC_DEADLINE:-120}" "$@"; }

# expect <name> <fail|pass> <required regex> <forbidden regex or -> <cmd...>
expect() {
  local name="$1" want="$2" marker="$3" forbidden="$4" log="$work/$1.log" rc=0 ok=1
  shift 4
  "$@" >"$log" 2>&1 || rc=$?
  if [[ "$want" == fail ]]; then ((rc != 0)) || ok=0; else ((rc == 0)) || ok=0; fi
  grep -qE -e "$marker" "$log" || ok=0
  if [[ "$forbidden" != - ]] && grep -qE -e "$forbidden" "$log"; then ok=0; fi
  if ((ok)); then
    printf 'ok    %-48s exit %d, matched /%s/\n' "$name" "$rc" "$marker"
    pass=$((pass + 1))
  else
    printf 'FAIL  %-48s exit %d (wanted %s, /%s/)\n' "$name" "$rc" "$want" "$marker"
    fail=$((fail + 1))
  fi
}

# make_tree <dir> <repo|plain> <planted|clean>: the lint scripts, their one dependency and a tiny tree.
make_tree() {
  local dir="$1" kind="$2" content="$3"
  mkdir -p "$dir/Tools/lint" "$dir/Config/Scripts" "$dir/Daemon/Fixture" "$dir/Sources" "$dir/Packages" "$dir/Engine/go"
  printf 'module fixture\n\ngo 1.21\n' >"$dir/Engine/go/go.mod" # lint.sh reaches its govulncheck step (skipped: WGEX_OFFLINE=1)
  cp "$root"/Tools/lint/*.sh "$root"/Tools/lint/*.py "$root"/Tools/lint/*.txt "$root"/Tools/lint/*.tsv "$dir/Tools/lint/"
  cp "$root/Config/Scripts/lib.sh" "$root/Config/Scripts/build_root.py" "$dir/Config/Scripts/"
  cp "$root/justfile" "$dir/justfile"
  # Tools/docs is absent from these scratch trees. Stub its unrelated recipe so every suite PATH call hits the shim;
  # lint.sh in the checkout stays untouched, and the Go/lint steps being tested are unchanged.
  sed 's/step docs-check just docs-check/step docs-check echo "docs-check: skipped (scratch tree)"/' "$root/Tools/lint/lint.sh" >"$dir/Tools/lint/lint.sh"
  printf 'plain notes\n' >"$dir/README.md"
  printf 'let value = 1\n' >"$dir/Sources/Value.swift"
  printf '<?xml version="1.0"?>\n<plist version="1.0"><dict><key>Label</key><string>x</string></dict></plist>\n' >"$dir/Daemon/Fixture/x.plist"
  [[ "$content" == planted ]] && cp "$root/Tools/lint/tests/prose/denylisted.md" "$dir/NOTES.md"
  if [[ "$kind" == repo ]]; then
    deadline git -C "$dir" -c init.defaultBranch=main init -q && deadline git -C "$dir" add -A
  fi
}

# in_tree <dir> <env assignments...> -- <cmd...>: run with a scratch ceiling so git never finds a parent repository
in_tree() {
  local dir="$1"
  shift
  (cd "$dir" && deadline env GIT_CEILING_DIRECTORIES="$work" "$@")
}

NAMED='^lint: git could not list repository files: '

planted="$work/planted"
make_tree "$planted" repo planted
nonrepo="$work/nonrepo"
make_tree "$nonrepo" plain planted
broken="$work/broken-index"
make_tree "$broken" repo planted
printf 'not an index\n' >"$broken/.git/index"
clean="$work/clean"
make_tree "$clean" repo clean

# 1. Ownership: the FIX3-VERIFY repro, directly on the scripts (no gate entry strips the variable here).
own() { in_tree "$planted" GIT_TEST_ASSUME_DIFFERENT_OWNER=1 "$@"; }
expect owner-prose fail "$NAMED" '^check-public-prose: ok' own bash Tools/lint/check-public-prose.sh
expect owner-secrets fail "$NAMED" 'no secret-shaped strings|^check-no-secrets.*ok' own bash Tools/lint/check-no-secrets-in-strings.sh
expect owner-launchd fail "$NAMED" '^check-launchd-plists: ok' own bash Tools/lint/check-launchd-plists.sh
expect owner-licences fail "$NAMED" '^check-licences: ok' own bash Tools/lint/check-licences.sh
expect owner-package-deps fail "$NAMED" '^check-package-deps: ok' own bash Tools/lint/check-package-deps.sh
expect owner-lint fail "$NAMED" '^lint: all checks passed|skipped \(no (Swift|shell)' own bash Tools/lint/lint.sh
expect owner-lint-failed fail '^lint: FAILED: .*swiftlint.*shellcheck.*typos.*check-public-prose' '^lint: all checks passed' own bash Tools/lint/lint.sh

# 2. Non-repository LINT_ROOT (the scripts take LINT_ROOT from their own location).
np() { in_tree "$nonrepo" "$@"; }
expect nonrepo-prose fail "$NAMED" '^check-public-prose: ok' np bash Tools/lint/check-public-prose.sh
expect nonrepo-lint fail "$NAMED" '^lint: all checks passed|skipped \(no (Swift|shell)' np bash Tools/lint/lint.sh
expect nonrepo-explicit-path pass '^check-public-prose: ok' - np bash Tools/lint/check-public-prose.sh README.md

# 3. A broken index also fails closed.
expect broken-index-prose fail "$NAMED" '^check-public-prose: ok' in_tree "$broken" bash Tools/lint/check-public-prose.sh

# 4. load_repo_files and repo_files themselves, as the self-test harness uses it (LINT_ROOT overridden after sourcing).
cat >"$work/lib-case.sh" <<'LIBCASE'
source "$1/Tools/lint/lib.sh"
LINT_ROOT="$2"
if [[ "$3" == stream ]]; then
  repo_files '*.md' >"$4" || exit 7
  printf 'listed %d\n' "$(tr -cd '\0' <"$4" | wc -c | tr -d ' ')"
else
  load_repo_files '*.md' || exit 7
  printf 'listed %d\n' "${#REPO_FILES[@]}"
fi
LIBCASE
lib_case() { deadline env GIT_CEILING_DIRECTORIES="$work" bash "$work/lib-case.sh" "$root" "$1" "$2" "$work/stream.out"; }
expect lib-nonrepo fail "$NAMED" '^listed' lib_case "$nonrepo" array
expect lib-clean pass '^listed 1$' - lib_case "$clean" array
expect lib-stream-nonrepo fail "$NAMED" '^listed' lib_case "$nonrepo" stream
expect lib-stream-clean pass '^listed 1$' - lib_case "$clean" stream

# 5. Empty first-party selection in repository mode is a failure; explicit paths keep today's behaviour.
empty="$work/empty"
make_tree "$empty" repo clean
deadline git -C "$empty" rm -q -r --cached .
expect empty-prose fail '^check-public-prose: .*no files' '^check-public-prose: ok' in_tree "$empty" bash Tools/lint/check-public-prose.sh
expect empty-lint fail '^lint: FAILED: .*swiftlint.*swiftformat' 'skipped \(no (Swift|shell)' in_tree "$empty" bash Tools/lint/lint.sh
expect empty-lint-message fail '^lint: no tracked (Swift|shell|prose) files' 'skipped \(no (Swift|shell)' in_tree "$empty" bash Tools/lint/lint.sh
# The other three repository-mode checks refuse an empty listing by name. Without these cases, dropping the check is
# hidden on bash 3.2 (an empty "${array[@]}" is an error there) and would let zero files pass on bash 4.4 and later.
expect empty-secrets fail '^check-no-secrets-in-strings: no files to scan' 'no secret-shaped|: ok' in_tree "$empty" bash Tools/lint/check-no-secrets-in-strings.sh
expect empty-launchd fail '^check-launchd-plists: no Daemon plists' '^check-launchd-plists: ok' in_tree "$empty" bash Tools/lint/check-launchd-plists.sh
expect empty-licences fail '^check-licences: no files to scan' '^check-licences: ok' in_tree "$empty" bash Tools/lint/check-licences.sh

# 6. Zero manifests: repository mode refuses them by name; fixture mode reports an empty directory without an unbound variable.
expect zero-manifests-repo fail '^check-package-deps: no Packages/\*/Package.swift' '^check-package-deps: ok' in_tree "$planted" bash Tools/lint/check-package-deps.sh
mkdir -p "$work/empty-fixture"
expect zero-manifests-fixture pass '^check-package-deps: ok \(0 package\(s\)\)' 'unbound variable' deadline bash "$planted/Tools/lint/check-package-deps.sh" "$work/empty-fixture"

# 7. EXIT traps fail closed. On bash 3.2 a shell-level error under `set -e` (unbound variable, ${x:?}, a readonly
# assignment, a bad substitution, a failed `source`) reaches an EXIT trap with $? still 0, so `rc=$?; ...; exit "$rc"`
# turned it into a pass (VERIFY of M1-32, M1). Each trap therefore also needs a completion flag that the script sets
# just before every intended successful exit, and initialises to 0 first (an exported finished=1 must not count).
# Three kinds of check, all on behaviour:
#   (a) every real trap line, run verbatim in a `set -euo pipefail` probe after each error kind;
#   (b) one scratch copy of every real script with an unbound variable injected right after its trap, also run under
#       an exported finished=1;
#   (c) discovery: trap_scan.py finds every EXIT trap in any form; one that is not the canonical injectable form fails
#       the suite, so a trap the probes cannot run cannot slip past them (VERIFY of M1-32 FIX1, P3).
trap_scan() { deadline python3 -I "$root/Tools/lint/tests/fail-closed/trap_scan.py" "$@"; }
# trap_unaccounted <accounts file> <script>...: prints "<file>:<line>" for every non-comment line with the word `trap` that no
# scanner record covers (a trap statement, a here-document body, a one-line word, a comment). This plain search does not
# use the scanner's idea of the syntax, so a trap the scanner lost (a quote that spans lines, a swallowed region) shows up.
trap_unaccounted() {
  local acc="$1" f word='(^|[^A-Za-z0-9_])trap([^A-Za-z0-9_]|$)'
  shift
  for f in "$@"; do
    # the pattern comes in as one line (-v) so that this function's own lines stay accounted for as one-line words
    awk -F'\t' -v f="$f" -v acc="$acc" -v word="$word" '
      FILENAME == acc { if ($1 == f) for (l = $2; l <= $3; l++) covered[l] = 1; next }
      $0 ~ word && $0 !~ /^[ \t]*#/ && !(FNR in covered) { print f ":" FNR }
    ' "$acc" "$f" || return 1
  done
}
# trap_inventory <out file> <script>...: writes "<file><TAB><line>" per canonical EXIT trap to <out file>; fails when any
# EXIT trap in the scripts is not the canonical form, when the scan itself fails, or when a plain search for the word
# `trap` finds a line the scanner did not account for (fail closed on disagreement)
trap_inventory() {
  local out="$1" scan="$work/trap-scan.out" acc="$work/trap-accounted.tsv" rc=0 kind f a b hit hits="$work/trap-unaccounted.out" n=0 bad=0
  shift
  trap_scan "$@" >"$scan" || rc=$?
  if ((rc != 0)); then
    echo "trap discovery failed (status $rc)" >&2
    return 1
  fi
  : >"$out"
  : >"$acc"
  while IFS=$'\t' read -r kind f a b _; do
    case "$kind" in
      canonical)
        printf '%s\t%s\n' "$f" "$a" >>"$out"
        n=$((n + 1))
        ;;
      noncanonical)
        printf 'non-canonical EXIT trap at %s:%s (%s)\n' "${f#"$root"/}" "$a" "$b" >&2
        bad=1
        ;;
      account) printf '%s\t%s\t%s\n' "$f" "$a" "$b" >>"$acc" ;;
      *)
        echo "trap discovery: unknown scanner record: $kind" >&2
        bad=1
        ;;
    esac
  done <"$scan"
  trap_unaccounted "$acc" "$@" >"$hits" || {
    echo "trap discovery: the plain search failed" >&2
    return 1
  }
  while IFS= read -r hit; do
    printf 'unaccounted trap word at %s: the scanner and a plain search disagree\n' "${hit#"$root"/}" >&2
    bad=1
  done <"$hits"
  ((bad == 0)) && printf '%d canonical EXIT trap(s) in %d script(s)\n' "$n" "$(cut -f1 "$out" | sort -u | wc -l | tr -d ' ')"
}
# The one form the probes and the injection run: the line the inventory names must match it before it is used, so an
# inventory that names the wrong line (an off-by-one scanner) fails instead of probing something harmless (N3 of M1-37).
TRAP_FORM="^trap (-- )?'[^']*' EXIT\$"
# trap_kind <kind> <minimum number of traps> <inventory file>: run every listed trap line in a `set -euo pipefail`
# probe after <kind> and compare the status (every trap in a file, not only the first)
trap_kind() {
  local kind="$1" min="$2" inv="$3" f line text n=0 bad=0 inj want probe="$work/trap-probe.sh" rc ok
  case "$kind" in
    unbound) inj=': "${wgex_unbound_probe}"' want=nonzero ;;
    colon) inj=': "${wgex_unset_probe:?probe}"' want=nonzero ;;
    readonly) inj='readonly wgex_ro_probe=1; wgex_ro_probe=2' want=nonzero ;;
    badsub) inj='wgex_x=abc; : "${wgex_x@Q}"' want=nonzero ;;
    source) inj='source /nonexistent/wgex-probe' want=nonzero ;;
    false) inj='false' want=1 ;;
    exit3) inj='exit 3' want=3 ;;
    clean) inj=':' want=0 ;;
  esac
  while IFS=$'\t' read -r f line; do
    text="$(sed -n "${line}p" "$f")"
    n=$((n + 1))
    if ! [[ "$text" =~ $TRAP_FORM ]]; then
      printf 'trap at %s:%s: the named line is not the canonical trap form\n' "${f#"$root"/}" "$line" >&2
      bad=1
      continue
    fi
    # the probe defines every variable the real traps remove ($work, $OUT), initialises the flag and ends like the real scripts
    printf 'set -euo pipefail\nwork="$1" OUT="$1"\nfinished=0\n%s\n%s\nfinished=1\nexit 0\n' "$text" "$inj" >"$probe"
    mkdir -p "$work/trap-probe-dir"
    rc=0
    deadline /bin/bash "$probe" "$work/trap-probe-dir" >/dev/null 2>&1 || rc=$?
    ok=0
    if [[ "$want" == nonzero ]]; then ((rc != 0)) && ok=1; else ((rc == want)) && ok=1; fi
    if ((! ok)); then
      printf 'trap at %s:%s: wrong status %d after %s (wanted %s)\n' "${f#"$root"/}" "$line" "$rc" "$kind" "$want" >&2
      bad=1
    fi
  done <"$inv"
  ((n >= min && bad == 0)) && echo "all $n EXIT traps: $kind ok"
}

# (c) Discovery. Scratch scripts carry each trap form the old `^trap .* EXIT$` pattern missed; each must be found and
# refused. Quoted here-documents: the scanner treats their bodies as data, so this file itself holds one trap.
forms="$work/forms"
mkdir -p "$forms"
cat >"$forms/indented.sh" <<'FORM'
#!/usr/bin/env bash
work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
FORM
cat >"$forms/function.sh" <<'FORM'
cleanup() {
  trap 'rm -rf "$work"' EXIT
}
FORM
cat >"$forms/inif.sh" <<'FORM'
if true; then trap 'rm -rf "$work"' EXIT; fi
FORM
cat >"$forms/comment.sh" <<'FORM'
trap 'rm -rf "$work"' EXIT # tidy up
FORM
cat >"$forms/multisig.sh" <<'FORM'
trap 'rm -rf "$work"' EXIT INT TERM
FORM
cat >"$forms/zero.sh" <<'FORM'
trap 'rm -rf "$work"' 0
FORM
cat >"$forms/dquote.sh" <<'FORM'
trap "rm -rf $work" EXIT
FORM
cat >"$forms/handler.sh" <<'FORM'
trap cleanup EXIT
FORM
cat >"$forms/multiline.sh" <<'FORM'
trap '
  rm -rf "$work"
' EXIT
FORM
cat >"$forms/continued.sh" <<'FORM'
trap 'rm -rf "$work"' \
  EXIT
FORM
printf 'trap '"'"'rm -rf "$work"'"'"' EXIT  \n' >"$forms/trailing.sh" # a trailing blank is fragile inside a here-document body
cat >"$forms/two-good.sh" <<'FORM'
trap 'rc=$?; ((rc != 0)) || ((${finished:-0})) || rc=1; rm -rf "$work"; exit "$rc"' EXIT
trap -- 'rc=$?; ((rc != 0)) || ((${finished:-0})) || rc=1; rm -rf "$work"; exit "$rc"' EXIT
FORM
cat >"$forms/two-second-bad.sh" <<'FORM'
trap 'rc=$?; ((rc != 0)) || ((${finished:-0})) || rc=1; rm -rf "$work"; exit "$rc"' EXIT
trap 'rc=$?; rm -rf "$work"; exit "$rc"' EXIT
FORM
cat >"$forms/not-traps.sh" <<'FORM'
trap 'rm -rf "$work"' INT
# trap 'rm -rf "$work"' EXIT
echo "trap 'rm -rf $work' EXIT"
x=$((1 << 2))
trap -p EXIT
cat <<EOF
trap 'rm -rf "$work"' EXIT
EOF
FORM
# Forms the first scanner missed (M1-37 VERIFY, N2): a spaced arithmetic shift read as a here-document that swallowed the
# rest of the file, other spellings of the exit condition, an assignment prefix, a one-argument reset.
cat >"$forms/arith-hidden.sh" <<'FORM'
x=$((1 << 2))
y=$(( 1<<3 ))
((z = 1 << 3))
trap 'rm -rf "$work"' EXIT # hidden
FORM
cat >"$forms/arith-canonical.sh" <<'FORM'
x=$((1 << 2))
y=$(( (1 + 2) << 3 ))
((z = 1 << 3))
trap 'rm -rf "$work"' EXIT
FORM
cat >"$forms/lowercase.sh" <<'FORM'
trap 'rm -rf "$work"' exit
FORM
cat >"$forms/numeric.sh" <<'FORM'
trap 'rm -rf "$work"' 00
FORM
cat >"$forms/prefixed.sh" <<'FORM'
x=1 trap 'rm -rf "$work"' EXIT
FORM
cat >"$forms/oneword.sh" <<'FORM'
trap EXIT
FORM
# A quote inside $( ) inside a double-quoted string must not end that string (M1-37 VERIFY N2e; M1-39 VERIFY F3b: the
# one-line form hid a live trap inside one word, which the backstop accepted as a string).
cat >"$forms/lost.sh" <<'FORM'
echo "it's $(echo "a'b")"
trap 'rm -rf "$work"' EXIT # hidden
echo it\'s
FORM
cat >"$forms/desync-subst.sh" <<'FORM'
echo "$(echo "'")" ; trap 'echo T' EXIT INT ; echo "'" # "
FORM
# A backtick substitution can desynchronise later words; the lexer must reject it with status 2.
cat >"$forms/desync-backtick.sh" <<'FORM'
echo "`echo "'"`" ; trap 'echo T' EXIT INT ; echo "'" # "
FORM
# M1-42 VERIFY e1, e2 and e5: these traps execute despite the lexer's backtick desync.
cat >"$forms/desync-e1.sh" <<'FORM'
echo "`echo "'"`" & trap 'echo T' EXIT INT ; echo "'" # "
FORM
cat >"$forms/desync-e2.sh" <<'FORM'
echo "`echo "'"`" ; { trap 'echo T' EXIT INT ; } ; echo "'" # "
FORM
cat >"$forms/desync-e5.sh" <<'FORM'
echo "`echo "'"`" ; \trap 'echo T' EXIT INT ; echo "'" # "
FORM
cat >"$forms/split_ansic.sh" <<'FORM'
echo "`echo "'"`" ; $'tr'ap 'echo T' EXIT INT ; echo "'" # "
FORM
cat >"$forms/split_sq.sh" <<'FORM'
echo "`echo "'"`" ; t''rap 'echo T' EXIT INT ; echo "'" # "
FORM
cat >"$forms/split_trbsap.sh" <<'FORM'
echo "`echo "'"`" ; tr\ap 'echo T' EXIT INT ; echo "'" # "
FORM
cat >"$forms/split_trdq.sh" <<'FORM'
echo "`echo "'"`" ; "tr"ap 'echo T' EXIT INT ; echo "'" # "
FORM
cat >"$forms/split_trdqdq.sh" <<'FORM'
echo "`echo "'"`" ; tr""ap 'echo T' EXIT INT ; echo "'" # "
FORM
cat >"$forms/xword_amp.sh" <<'FORM'
echo "`echo "'"`" ; echo "'" ; echo " x" & trap 'echo T' EXIT INT ; echo "" # "
FORM
cat >"$forms/xword_assign.sh" <<'FORM'
echo "`echo "'"`" ; echo "'" ; echo " x" ; X=1 trap 'echo T' EXIT INT ; echo "" # "
FORM
cat >"$forms/xword_bang.sh" <<'FORM'
echo "`echo "'"`" ; echo "'" ; echo " x" ; ! trap 'echo T' EXIT INT ; echo "" # "
FORM
cat >"$forms/xword_brace.sh" <<'FORM'
echo "`echo "'"`" ; echo "'" ; echo " x" ; { trap 'echo T' EXIT INT ; } ; echo "" # "
FORM
cat >"$forms/ansi-delimiter.sh" <<'FORM'
cat <<$'EOF'
data
EOF
trap 'echo T' EXIT INT
FORM
cat >"$forms/ansi-later.sh" <<'FORM'
cat <<$'EOF'
data
EOF
trap 'echo T' EXIT INT
EOF=
$EOF
FORM
# A partly quoted here-document delimiter is the whole word with its quotes removed (M1-39 VERIFY F3a): E"O"F is EOF, so
# the trap after it is live; a second here-document closes on the lines that do not end the first.
cat >"$forms/delim-double.sh" <<'FORM'
cat <<E"O"F
data
EOF
trap 'echo T' EXIT INT
: <<'X'
E"O"F
X
FORM
cat >"$forms/delim-single.sh" <<'FORM'
cat <<'E'OF
data
EOF
trap 'echo T' EXIT INT
: <<'X'
'E'OF
X
FORM
cat >"$forms/delim-data.sh" <<'FORM'
cat <<E"O"F
trap 'rm -rf "$work"' EXIT
EOF
FORM
cat >"$forms/nospace-heredoc.sh" <<'FORM'
cat<<X
trap 'rm -rf "$work"' EXIT
X
FORM
cat >"$forms/open-heredoc.sh" <<'FORM'
cat <<EOF
trap 'rm -rf "$work"' EXIT
FORM
cat >"$forms/open-quote.sh" <<'FORM'
echo 'unfinished
trap 'rm -rf "$work"' EXIT
FORM
for form in indented function inif comment multisig zero dquote handler multiline continued trailing arith-hidden lowercase numeric prefixed oneword; do
  expect "trap-discovery-refuses-$form" fail '^non-canonical EXIT trap at ' '^[0-9]+ canonical' trap_inventory "$work/forms.tsv" "$forms/$form.sh"
done
expect trap-discovery-ignores-non-traps pass '^0 canonical EXIT trap\(s\) in 0 script' 'non-canonical' trap_inventory "$work/forms.tsv" "$forms/not-traps.sh"
expect trap-discovery-arithmetic-shift-not-heredoc pass '^1 canonical EXIT trap\(s\) in 1 script' 'non-canonical|unaccounted' trap_inventory "$work/forms.tsv" "$forms/arith-canonical.sh"
expect trap-discovery-nospace-heredoc-is-data pass '^0 canonical EXIT trap\(s\) in 0 script' 'non-canonical|unaccounted' trap_inventory "$work/forms.tsv" "$forms/nospace-heredoc.sh"
expect trap-discovery-refuses-quote-in-substitution fail '^non-canonical EXIT trap at .*trailing comment' '^[0-9]+ canonical' trap_inventory "$work/forms.tsv" "$forms/lost.sh"
expect trap-discovery-refuses-desync-in-substitution fail '^non-canonical EXIT trap at ' '^[0-9]+ canonical|unaccounted' trap_inventory "$work/forms.tsv" "$forms/desync-subst.sh"
expect trap-discovery-fails-on-backtick-desync fail '^trap discovery failed \(status 2\)' '^[0-9]+ canonical' trap_inventory "$work/forms.tsv" "$forms/desync-backtick.sh"
for form in e1 e2 e5; do
  expect "trap-desync-$form-is-live" pass '^T$' - deadline bash "$forms/desync-$form.sh"
  expect "trap-discovery-refuses-desync-$form" fail '^trap discovery failed \(status 2\)' '^[0-9]+ canonical' trap_inventory "$work/forms.tsv" "$forms/desync-$form.sh"
done
for form in xword_brace xword_amp xword_bang xword_assign split_trbsap split_trdq split_trdqdq split_ansic split_sq; do
  expect "trap-$form-is-live" pass '^T$' - deadline bash "$forms/$form.sh"
  expect "trap-discovery-refuses-$form" fail '^trap discovery failed \(status 2\)' '^[0-9]+ canonical' trap_inventory "$work/forms.tsv" "$forms/$form.sh"
done
for form in ansi-delimiter ansi-later; do
  expect "trap-$form-is-live" pass '^T$' - deadline bash "$forms/$form.sh"
  expect "trap-discovery-refuses-$form" fail '^non-canonical EXIT trap at .*signals are EXIT INT' '^[0-9]+ canonical|never closed' trap_inventory "$work/forms.tsv" "$forms/$form.sh"
done
expect trap-discovery-refuses-partly-quoted-delimiter fail '^non-canonical EXIT trap at .*signals are EXIT INT' '^[0-9]+ canonical|never closed' trap_inventory "$work/forms.tsv" "$forms/delim-double.sh"
expect trap-discovery-refuses-single-quoted-delimiter-part fail '^non-canonical EXIT trap at .*signals are EXIT INT' '^[0-9]+ canonical|never closed' trap_inventory "$work/forms.tsv" "$forms/delim-single.sh"
expect trap-discovery-partly-quoted-delimiter-is-data pass '^0 canonical EXIT trap\(s\) in 0 script' 'non-canonical|unaccounted' trap_inventory "$work/forms.tsv" "$forms/delim-data.sh"
# The backstop itself: with a scanner that reports nothing (a lexer that lost every trap), the plain search must name the
# lines it cannot account for. A subshell, so the stub does not outlive the case.
blind_scanner() (
  trap_scan() { :; }
  trap_inventory "$work/forms.tsv" "$forms/lost.sh"
)
expect trap-discovery-backstop-names-unaccounted-lines fail '^unaccounted trap word at .*lost\.sh:2' '^[0-9]+ canonical' blind_scanner
expect trap-discovery-fails-on-open-heredoc fail '^trap discovery failed \(status 2\)' - trap_inventory "$work/forms.tsv" "$forms/open-heredoc.sh"
expect trap-discovery-fails-on-open-quote fail '^trap discovery failed \(status 2\)' - trap_inventory "$work/forms.tsv" "$forms/open-quote.sh"
expect trap-discovery-lists-every-trap pass '^2 canonical EXIT trap\(s\) in 1 script' - trap_inventory "$work/forms.tsv" "$forms/two-good.sh"
probe_second() { trap_inventory "$work/forms.tsv" "$forms/two-second-bad.sh" >/dev/null && trap_kind unbound 2 "$work/forms.tsv"; }
expect trap-probe-covers-second-trap fail 'wrong status' - probe_second
probe_both() { trap_inventory "$work/forms.tsv" "$forms/two-good.sh" >/dev/null && trap_kind unbound 2 "$work/forms.tsv"; }
expect trap-probe-two-good-traps pass '^all 2 EXIT traps: unbound ok' 'wrong status' probe_both

# An inventory that names a line that is not the canonical trap (here an INT trap) must fail the probe, not run it.
probe_wrong_line() {
  printf '%s\t%s\n' "$forms/not-traps.sh" 1 >"$work/wrong-line.tsv"
  trap_kind unbound 1 "$work/wrong-line.tsv"
}
expect trap-probe-refuses-non-trap-line fail 'not the canonical trap form' '^all [0-9]+ EXIT traps' probe_wrong_line

# The real scripts: every EXIT trap in Tools/lint must be canonical, and each is probed.
real_traps="$work/real-traps.tsv"
real_inventory() { trap_inventory "$real_traps" "$root"/Tools/lint/*.sh "$root"/Tools/lint/tests/*/*.sh; }
expect trap-discovery-real-scripts pass '^[0-9]+ canonical EXIT trap\(s\) in [0-9]+ script' 'non-canonical' real_inventory
for kind in unbound colon readonly badsub source false exit3 clean; do
  expect "trap-preserves-status-$kind" pass "^all [0-9]+ EXIT traps: $kind ok" 'wrong status' trap_kind "$kind" 5 "$real_traps"
done

# (b) The real scripts. inj tree: a manifest in the index (so check-package-deps gets past its zero-manifest refusal and
# reaches its trap) and the test scripts that set traps (make_tree gave it the go.mod that makes lint.sh run its
# govulncheck step).
inj="$work/inj"
make_tree "$inj" repo clean
mkdir -p "$inj/Packages/Fixture" "$inj/Tools/lint/tests/govulncheck" "$inj/Tools/lint/tests/fail-closed"
printf '// swift-tools-version: 6.0\nimport PackageDescription\nlet package = Package(name: "Fixture")\n' >"$inj/Packages/Fixture/Package.swift"
cp "$root/Tools/lint/tests/govulncheck/run.sh" "$inj/Tools/lint/tests/govulncheck/run.sh"
cp "$root/Tools/lint/tests/fail-closed/run.sh" "$inj/Tools/lint/tests/fail-closed/run.sh"
deadline git -C "$inj" add -A

# inject_tree <name> <script path relative to the root>: a copy of $inj whose script reads an unbound variable right
# after its first EXIT trap (the line comes from the discovery above)
inject_tree() {
  local dir="$work/inj-$1" rel="$2" ln
  ln="$(awk -F'\t' -v f="$root/$rel" '$1 == f { print $2; exit }' "$real_traps")"
  [[ "$ln" =~ ^[0-9]+$ ]] || return 1
  [[ "$(sed -n "${ln}p" "$inj/$rel")" =~ $TRAP_FORM ]] || return 1 # the named line is the canonical trap, not a neighbour
  cp -R "$inj" "$dir" || return 1
  awk -v n="$ln" 'NR == n { print; print ": \"${wgex_unbound_probe}\""; next } { print }' "$inj/$rel" >"$dir/$rel.new" || return 1
  cat "$dir/$rel.new" >"$dir/$rel" && rm -f "${dir:?}/${rel:?}.new" # cat keeps the file mode: lint.sh runs the checks directly
  grep -q 'wgex_unbound_probe' "$dir/$rel"                          # the injection landed
}
# lint_reports <name> <step name in lint.sh> [env assignment]: lint.sh over inj-<name> must name the step in its FAILED line
lint_reports() {
  local out="$work/lint-$1.out$$" rc=0 extra=()
  [[ -n "${3:-}" ]] && extra=("$3")
  (cd "$work/inj-$1" && deadline env GIT_CEILING_DIRECTORIES="$work" WGEX_OFFLINE=0 GOPROXY=off GOTOOLCHAIN=local ${extra[@]+"${extra[@]}"} bash Tools/lint/lint.sh) >"$out" 2>&1 || rc=$?
  if grep -q 'wgex_unbound_probe: unbound variable' "$out" && grep -Eq "^lint: FAILED: (.* )?$2( |\$)" "$out"; then
    echo "lint.sh reports FAILED: $2"
  fi
  return "$rc"
}
UNBOUND='wgex_unbound_probe: unbound variable'
injected=0
for entry in \
  check-public-prose:Tools/lint/check-public-prose.sh \
  check-package-deps:Tools/lint/check-package-deps.sh \
  check-go-vulnerabilities:Tools/lint/check-go-vulnerabilities.sh \
  check-entitlements:Tools/lint/check-entitlements.sh \
  run-selftests:Tools/lint/run-selftests.sh \
  govulncheck-test:Tools/lint/tests/govulncheck/run.sh \
  fail-closed:Tools/lint/tests/fail-closed/run.sh; do
  if inject_tree "${entry%%:*}" "${entry#*:}"; then
    injected=$((injected + 1))
  else
    printf 'FAIL  %-48s could not inject into %s\n' "exit-traps-keep-status-${entry%%:*}" "${entry#*:}"
    fail=$((fail + 1))
  fi
done
# Each injected copy must exit non-zero and show the unbound-variable error (the old trap form exits 0 on bash 3.2).
expect exit-traps-keep-status-check-public-prose fail "$UNBOUND" - in_tree "$work/inj-check-public-prose" bash Tools/lint/check-public-prose.sh
expect exit-traps-keep-status-check-package-deps fail "$UNBOUND" - in_tree "$work/inj-check-package-deps" bash Tools/lint/check-package-deps.sh
expect exit-traps-keep-status-check-go-vulnerabilities fail "$UNBOUND" - in_tree "$work/inj-check-go-vulnerabilities" env WGEX_OFFLINE=0 bash Tools/lint/check-go-vulnerabilities.sh
expect exit-traps-keep-status-check-entitlements fail "$UNBOUND" - in_tree "$work/inj-check-entitlements" bash Tools/lint/check-entitlements.sh --products "$work/no-products"
expect exit-traps-keep-status-run-selftests fail "$UNBOUND" - in_tree "$work/inj-run-selftests" bash Tools/lint/run-selftests.sh
expect exit-traps-keep-status-govulncheck-test fail "$UNBOUND" - in_tree "$work/inj-govulncheck-test" bash Tools/lint/tests/govulncheck/run.sh
expect exit-traps-keep-status-fail-closed fail "$UNBOUND" - in_tree "$work/inj-fail-closed" bash Tools/lint/tests/fail-closed/run.sh
# ... under an exported finished=1 in the caller (the flag is never inherited: every script initialises it to 0 first)
expect exit-traps-ignore-inherited-finished-check-public-prose fail "$UNBOUND" - in_tree "$work/inj-check-public-prose" finished=1 bash Tools/lint/check-public-prose.sh
expect exit-traps-ignore-inherited-finished-check-package-deps fail "$UNBOUND" - in_tree "$work/inj-check-package-deps" finished=1 bash Tools/lint/check-package-deps.sh
expect exit-traps-ignore-inherited-finished-check-go-vulnerabilities fail "$UNBOUND" - in_tree "$work/inj-check-go-vulnerabilities" finished=1 WGEX_OFFLINE=0 bash Tools/lint/check-go-vulnerabilities.sh
expect exit-traps-ignore-inherited-finished-check-entitlements fail "$UNBOUND" - in_tree "$work/inj-check-entitlements" finished=1 bash Tools/lint/check-entitlements.sh --products "$work/no-products"
expect exit-traps-ignore-inherited-finished-run-selftests fail "$UNBOUND" - in_tree "$work/inj-run-selftests" finished=1 bash Tools/lint/run-selftests.sh
expect exit-traps-ignore-inherited-finished-govulncheck-test fail "$UNBOUND" - in_tree "$work/inj-govulncheck-test" finished=1 bash Tools/lint/tests/govulncheck/run.sh
expect exit-traps-ignore-inherited-finished-fail-closed fail "$UNBOUND" - in_tree "$work/inj-fail-closed" finished=1 bash Tools/lint/tests/fail-closed/run.sh
# ... and lint.sh must report FAILED for the three it runs (check-entitlements and the self-tests are gate steps of their own).
expect exit-traps-keep-status-lint-check-public-prose fail '^lint.sh reports FAILED: check-public-prose' - lint_reports check-public-prose check-public-prose
expect exit-traps-keep-status-lint-check-package-deps fail '^lint.sh reports FAILED: check-package-deps' - lint_reports check-package-deps check-package-deps
expect exit-traps-keep-status-lint-govulncheck fail '^lint.sh reports FAILED: govulncheck' - lint_reports check-go-vulnerabilities govulncheck
expect exit-traps-ignore-inherited-finished-lint-check-public-prose fail '^lint.sh reports FAILED: check-public-prose' - lint_reports check-public-prose check-public-prose finished=1
expect exit-traps-ignore-inherited-finished-lint-check-package-deps fail '^lint.sh reports FAILED: check-package-deps' - lint_reports check-package-deps check-package-deps finished=1
expect exit-traps-ignore-inherited-finished-lint-govulncheck fail '^lint.sh reports FAILED: govulncheck' - lint_reports check-go-vulnerabilities govulncheck finished=1
# A new script with an EXIT trap must get a case above.
trap_coverage() {
  local n
  n="$(cut -f1 "$real_traps" | sort -u | wc -l | tr -d ' ')"
  ((n == injected)) && echo "all $n trap scripts have an injection case"
}
expect exit-traps-keep-status-covers-every-trap pass '^all [0-9]+ trap scripts have an injection case' - trap_coverage

# 7b. The govulncheck self-test must itself be able to fail (VERIFY of M1-32 FIX1, P1: its assertions were `&&` lists that
# never exit under set -e). Each mutant of check-go-vulnerabilities.sh goes into a copy of the inj tree, which also holds
# the self-test; the self-test must exit non-zero and name the case it caught.
mutant_tree() { # <name> <script path relative to the root> <sed expression>
  local dir="$work/mut-$1"
  cp -R "$inj" "$dir" || return 1
  mkdir -p "$dir/Tools/lint/tests/go-vet" || return 1 # a mutant that cd's there must find a directory (and the wrong module), not an error
  sed "$3" "$inj/$2" >"$dir/$2.new" || return 1
  cat "$dir/$2.new" >"$dir/$2" && rm -f "${dir:?}/${2:?}.new"
  ! cmp -s "$inj/$2" "$dir/$2" # the mutation landed
}
GV=Tools/lint/check-go-vulnerabilities.sh
mutant_ok=0
mutant_tree gv-V "$GV" 's/|| status=\$?/|| true/' && mutant_ok=$((mutant_ok + 1))                         # failures and an unreachable database ignored
mutant_tree gv-F2 "$GV" '/^finished=1$/d' && mutant_ok=$((mutant_ok + 1))                                 # an online clean run exits 1
mutant_tree gv-O "$GV" 's/WGEX_OFFLINE:-0}" == 1/WGEX_OFFLINE:-0}" == 2/' && mutant_ok=$((mutant_ok + 1)) # the offline skip never happens
mutant_tree gv-D "$GV" 's/WGEX_OFFLINE:-0}/WGEX_OFFLINE:-1}/' && mutant_ok=$((mutant_ok + 1))             # an unset knob skips the database
mutant_tree gv-SC "$GV" 's|govulncheck \./\.\.\. |govulncheck . |' && mutant_ok=$((mutant_ok + 1))        # only the root package is checked
mutant_tree gv-C "$GV" '/^cat "\$work\/output"$/d' && mutant_ok=$((mutant_ok + 1))                        # findings are never shown
# M1-42 (M1-39 VERIFY F2): the mock checks the directory, the environment and both streams
mutant_tree gv-CD3 "$GV" 's|)/\.\./\.\./Engine/go"|)/../../Tools/lint/tests/go-vet"|' && mutant_ok=$((mutant_ok + 1))                # another module is checked (fail-open)
mutant_tree gv-CD "$GV" '/^cd "\$(dirname/d' && mutant_ok=$((mutant_ok + 1))                                                         # no cd: the caller's directory is checked
mutant_tree gv-CD2 "$GV" 's|)/\.\./\.\./Engine/go"|)"|' && mutant_ok=$((mutant_ok + 1))                                              # cd to Tools/lint
mutant_tree gv-DB "$GV" 's|^govulncheck \./\.\.\. |GOVULNDB=file:///nonexistent govulncheck ./... |' && mutant_ok=$((mutant_ok + 1)) # another database
mutant_tree gv-H1 "$GV" 's|^cat "\$work/output"$|head -n 1 "$work/output"|' && mutant_ok=$((mutant_ok + 1))                          # only the first output line shown
mutant_tree gv-TR "$GV" 's|^cat "\$work/output"$|grep -v "^Scanning" "$work/output"|' && mutant_ok=$((mutant_ok + 1))                # a line of the output filtered out
mutant_tree gv-E2 "$GV" 's|>"\$work/output" 2>&1|>"$work/output" 2>/dev/null|' && mutant_ok=$((mutant_ok + 1))                       # stderr lost
mutant_tree gv-NZ "$GV" 's/WGEX_OFFLINE:-0}" == 1/WGEX_OFFLINE:-0}" != 0/' && mutant_ok=$((mutant_ok + 1))                           # any value but 0 means offline
mutant_tree gv-X-GOOS "$GV" 's|^govulncheck ./\.\.\. |GOOS=linux govulncheck ./... |' && mutant_ok=$((mutant_ok + 1))
mutant_tree gv-X-HEAD3 "$GV" 's|^cat "\$work/output"$|head -n 3 "$work/output"|' && mutant_ok=$((mutant_ok + 1))
mutant_tree gv-X-GLOB "$GV" 's/WGEX_OFFLINE:-0}" == 1/WGEX_OFFLINE:-0}" == 1*/' && mutant_ok=$((mutant_ok + 1))
mutant_tree gv-X-UNSETDB "$GV" 's|^govulncheck ./\.\.\. |env -u GOVULNDB govulncheck ./... |' && mutant_ok=$((mutant_ok + 1))
mutant_tree gv-Y-SUMDBOFF "$GV" 's|^govulncheck ./\.\.\. |GOSUMDB=off govulncheck ./... |' && mutant_ok=$((mutant_ok + 1))
mutant_tree gv-Y-PROXYOFF "$GV" 's|^govulncheck ./\.\.\. |GOPROXY=off GOTOOLCHAIN=local govulncheck ./... |' && mutant_ok=$((mutant_ok + 1))
mutant_tree gv-Y-SAMEFLAGS "$GV" 's|^govulncheck ./\.\.\. |GOFLAGS=-mod=readonly govulncheck ./... |' && mutant_ok=$((mutant_ok + 1))
if ((mutant_ok != 21)); then
  printf 'FAIL  %-48s could not build the govulncheck mutants (%d of 21)\n' govulncheck-mutants "$mutant_ok"
  fail=$((fail + 1))
fi
GVT=Tools/lint/tests/govulncheck/run.sh
expect govulncheck-test-passes pass '^govulncheck regression: clean passed' 'FAILED' in_tree "$inj" bash "$GVT"
expect govulncheck-test-kills-V fail '^govulncheck regression: unreachable FAILED \(status 0\)' - in_tree "$work/mut-gv-V" bash "$GVT"
expect govulncheck-test-kills-F2 fail '^govulncheck regression: clean FAILED \(status 1\)' - in_tree "$work/mut-gv-F2" bash "$GVT"
expect govulncheck-test-kills-O fail '^govulncheck regression: offline FAILED \(status 99\)' - in_tree "$work/mut-gv-O" bash "$GVT"
expect govulncheck-test-kills-D fail '^govulncheck regression: unset-offline FAILED \(status 0\)' - in_tree "$work/mut-gv-D" bash "$GVT"
expect govulncheck-test-kills-SC fail '^govulncheck regression: unreachable FAILED \(status 98\)' - in_tree "$work/mut-gv-SC" bash "$GVT"
expect govulncheck-test-kills-C fail '^govulncheck regression: unreachable FAILED \(status 1\)' - in_tree "$work/mut-gv-C" bash "$GVT"
expect govulncheck-test-kills-CD3 fail '^govulncheck regression: unreachable FAILED \(status 96\)' - in_tree "$work/mut-gv-CD3" bash "$GVT"
expect govulncheck-test-kills-CD fail '^govulncheck regression: unreachable FAILED \(status 96\)' - in_tree "$work/mut-gv-CD" bash "$GVT"
expect govulncheck-test-kills-CD2 fail '^govulncheck regression: unreachable FAILED \(status 96\)' - in_tree "$work/mut-gv-CD2" bash "$GVT"
expect govulncheck-test-kills-DB fail '^govulncheck regression: unreachable FAILED \(status 96\)' - in_tree "$work/mut-gv-DB" bash "$GVT"
expect govulncheck-test-kills-H1 fail '^govulncheck regression: unreachable FAILED \(status 1\)' - in_tree "$work/mut-gv-H1" bash "$GVT"
expect govulncheck-test-kills-TR fail '^govulncheck regression: unreachable FAILED \(status 1\)' - in_tree "$work/mut-gv-TR" bash "$GVT"
expect govulncheck-test-kills-E2 fail '^govulncheck regression: unreachable FAILED \(status 1\)' - in_tree "$work/mut-gv-E2" bash "$GVT"
expect govulncheck-test-kills-NZ fail '^govulncheck regression: yes-offline FAILED \(status 0\)' - in_tree "$work/mut-gv-NZ" bash "$GVT"
expect govulncheck-test-kills-X-GOOS fail '^govulncheck regression: unreachable FAILED \(status 96\)' - in_tree "$work/mut-gv-X-GOOS" bash "$GVT"
expect govulncheck-test-kills-X-HEAD3 fail '^govulncheck regression: unreachable FAILED \(status 1\)' - in_tree "$work/mut-gv-X-HEAD3" bash "$GVT"
expect govulncheck-test-kills-X-GLOB fail '^govulncheck regression: ten-offline FAILED \(status 0\)' - in_tree "$work/mut-gv-X-GLOB" bash "$GVT"
expect govulncheck-test-kills-X-UNSETDB fail '^govulncheck regression: unreachable FAILED \(status 96\)' - in_tree "$work/mut-gv-X-UNSETDB" bash "$GVT"
expect govulncheck-test-kills-Y-SUMDBOFF fail '^govulncheck regression: unreachable FAILED \(status 96\)' - in_tree "$work/mut-gv-Y-SUMDBOFF" bash "$GVT"
expect govulncheck-test-kills-Y-PROXYOFF fail '^govulncheck regression: unreachable FAILED \(status 96\)' - in_tree "$work/mut-gv-Y-PROXYOFF" bash "$GVT"
expect govulncheck-test-kills-Y-SAMEFLAGS fail '^govulncheck regression: unreachable FAILED \(status 96\)' - in_tree "$work/mut-gv-Y-SAMEFLAGS" bash "$GVT"

# 8. A clean tree still passes the checks that can run without the toolchain.
expect clean-prose pass '^check-public-prose: ok' - in_tree "$clean" bash Tools/lint/check-public-prose.sh
expect clean-launchd pass '^check-launchd-plists: ok \(1 plist' - in_tree "$clean" bash Tools/lint/check-launchd-plists.sh
expect clean-secrets pass '^check-no-secrets-in-strings: ok' 'secret-shaped string' in_tree "$clean" bash Tools/lint/check-no-secrets-in-strings.sh
expect planted-prose-still-caught fail 'denylisted term #' - in_tree "$planted" bash Tools/lint/check-public-prose.sh

# N6: execute the two real fixture command lines with a non-offline caller and refusing tool shims. Neither Go tool
# may inherit that proxy, even when no dependency currently needs downloading.
selftest_go_offline() {
  local probe="$work/go-offline"
  mkdir -p "$probe"
  printf '#!/bin/sh\n[ "$GOPROXY" = off ] || exit 96\necho "go fixture: proxy off"\n' >"$probe/go"
  cp "$probe/go" "$probe/staticcheck"
  chmod +x "$probe/go" "$probe/staticcheck"
  cat >"$probe/run.sh" <<'PROBE'
set -euo pipefail
T="$1/Tools/lint/tests"
in_dir() { local d="$1"; shift; (cd "$d" && "$@"); }
PROBE
  awk '/^  in_dir.* env .* (go vet|staticcheck) / { print; n++ } END { if (n != 2) exit 1 }' "$root/Tools/lint/run-selftests.sh" >>"$probe/run.sh" || return 1
  deadline env PATH="$probe:$PATH" GOPROXY=https://invalid.invalid bash "$probe/run.sh" "$root" >"$probe/result" || return 1
  [[ "$(grep -cx 'go fixture: proxy off' "$probe/result")" == 2 ]] && echo 'go fixtures: both force GOPROXY=off'
}
expect selftests-go-fixtures-offline pass '^go fixtures: both force GOPROXY=off' - selftest_go_offline

# 9. Every subprocess runs under a deadline. With git hanging on init, add and rm and python3 hanging always (shims that
# sleep) and a 1 s deadline, a nested run must still finish and print its summary; a bare git, bash or script call here
# would sit until the outer deadline kills the whole run (status 142, no summary). run-selftests.sh must wrap its call
# of this suite the same way.
if [[ -z "${WGEX_FC_NESTED:-}" ]]; then
  hang="$work/hang-bin"
  mkdir -p "$hang"
  real_git="$(command -v git)"
  # The shims must outlive the enclosing bound, so a missing per-command deadline cannot finish on its own.
  printf '#!/bin/sh\ncase " $* " in *" init "* | *" add "* | *" rm "*) exec sleep 600 ;; esac\nexec "%s" "$@"\n' "$real_git" >"$hang/git"
  printf '#!/bin/sh\nexec sleep 600\n' >"$hang/python3"
  chmod +x "$hang/git" "$hang/python3"
  # Leave room for the expanded mock/scanner cases and shared-host load; the self-test caller is bounded at 900 s.
  hung_run() { perl -e 'alarm shift; exec @ARGV or die "exec failed\n"' 300 env PATH="$hang:$PATH" WGEX_FC_NESTED=1 WGEX_FC_DEADLINE=1 bash "$root/Tools/lint/tests/fail-closed/run.sh"; }
  expect hung-tools-run-finishes fail '^fail-closed: [0-9]+ passed, [0-9]+ failed' - hung_run
  # structural: the one call of this suite in run-selftests.sh carries a perl alarm
  selftest_call_has_deadline() {
    grep -Eq 'alarm shift;.* [0-9]+ bash "\$T/fail-closed/run\.sh"' "$root/Tools/lint/run-selftests.sh" && echo 'run-selftests.sh calls the suite under a deadline'
  }
  expect selftests-call-has-deadline pass '^run-selftests.sh calls the suite under a deadline' - selftest_call_has_deadline
fi

# 9b. No case runs a `just` recipe: every recipe starts a login zsh, which rebuilds PATH ahead of the mock and the tripwire
# (M1-39 VERIFY F1). Lint runs as `bash Tools/lint/lint.sh`; a case that needs `just` has to say why and move this check.
no_just_in_cases() {
  deadline python3 -I "$root/Tools/lint/tests/fail-closed/nojust_scan.py" "${1:-$root/Tools/lint/tests/fail-closed/run.sh}"
}
expect no-case-runs-a-just-recipe pass '^no-just guard: ok' 'no-just guard: a case' no_just_in_cases

# The runtime guard must reject calls even when a case expects the shim's failure.
nojust_shapes() (
  local probe="$work/nojust-probe" shape rc probe_log
  mkdir -p "$probe"
  probe_log="$probe/calls"
  make_just_shim "$probe" "$probe_log"
  for shape in J1 J2 J5 J6 J8; do
    : >"$probe_log"
    rc=0
    deadline env PATH="$probe:$PATH" bash "$root/Tools/lint/tests/fail-closed/nojust-cases.bash" "$shape" || rc=$?
    [[ "$rc" == 95 ]] && grep -q '^call: ' "$probe_log" && ! just_calls_empty "$probe_log" || return 1
    echo "nojust probe: $shape refused"
  done
)
expect nojust-source-shapes-refused fail '^no-just guard: unexpected call at ' - no_just_in_cases "$root/Tools/lint/tests/fail-closed/nojust-cases.bash"

# 10. The guard: nothing above got past the mock to the real govulncheck (the tripwire behind it never fired), the mock was
# reached (the online cases did run the govulncheck step against it), and every lint.sh case ran the govulncheck step and
# skipped it: the scratch trees hold an Engine/go/go.mod, so a lint.sh run that did not skip it would have run whatever
# govulncheck its PATH found first (the tripwire only sees calls that PATH resolves to it), which is the M1-39 VERIFY F1 route.
just_calls_empty() {
  local log="${1:-$just_log}"
  [[ ! -s "$log" ]] || {
    echo 'nojust guard: the recipe shim was called' >&2
    return 1
  }
}
govulncheck_guard() {
  local trips mocks name
  just_calls_empty || return 1
  trips="$(wc -l <"$trip_log" | tr -d ' ')"
  mocks="$(wc -l <"$mock_log" | tr -d ' ')"
  if ((trips != 0)); then
    echo "govulncheck guard: the real govulncheck was called $trips time(s)" >&2
    cat "$trip_log" >&2
    return 1
  fi
  ((mocks > 0)) || {
    echo 'govulncheck guard: the mock was never called, so no case reached the govulncheck step' >&2
    return 1
  }
  for name in owner-lint owner-lint-failed nonrepo-lint empty-lint empty-lint-message; do
    if ! grep -qx '==> govulncheck' "$work/$name.log" || ! grep -qx 'govulncheck: skipped (WGEX_OFFLINE=1; vulnerability database was not checked)' "$work/$name.log"; then
      echo "govulncheck guard: the lint.sh case $name did not skip the govulncheck step" >&2
      return 1
    fi
  done
  echo "govulncheck guard: mock called $mocks time(s), the real tool never, every lint.sh case skipped the database"
}
expect nojust-shapes-refused pass '^nojust probe: J8 refused' - nojust_shapes
expect govulncheck-never-real pass '^govulncheck guard: mock called [0-9]+ time\(s\), the real tool never' 'real govulncheck was called|did not skip' govulncheck_guard

finished=1
printf 'fail-closed: %d passed, %d failed\n' "$pass" "$fail"
((fail == 0))
