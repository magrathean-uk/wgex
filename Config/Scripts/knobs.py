# SPDX-License-Identifier: MIT
"""The environment a gate step is allowed to inherit from its caller (M1-44), and the corpus of hostile names behind it.

Gate entry is an allowlist. Config/Scripts/timed-step.py builds every step's environment from the fixed list below and drops
everything else: no name has to be recognised as dangerous, so a variable no list ever heard of (a tool knob a newer
tool adds, an xcodebuild build setting, TEST_RUNNER_<VAR>, DYLD_*, a toolchain selector) cannot reach a step. The tooling
self-test (Config/Scripts/tests/run.py) applies the same list to its own process at import, less the WGEX_ prefix, which it
is hermetic against. One definition, so the two cannot drift; both load this file by path, so neither depends on sys.path.

The list (GATE_ALLOWED_NAMES, GATE_ALLOWED_PREFIXES, allowed()):
  PATH HOME TMPDIR USER LOGNAME SHELL TERM LANG    the account and the shell's own state
  LC_*                                             locale
  CODEX_THREAD_ID CLAUDE_CODE_SESSION_ID           session ids env.zsh derives scratch and builds from (Claude wins);
                                                   identifiers, not credentials; messaging tokens and sockets stay dropped
  WGEX_*                                           the gate's own knobs (check-full's WGEX_GO_RACE_COUNT=1 and
                                                   WGEX_LAB_BUILD=1, WGEX_FUZZ_SECONDS, WGEX_OFFLINE)
  GOPROXY GOTOOLCHAIN GOSUMDB GOVULNDB             what the offline gate wrapper exports
  CLEAN_DEV_* CLEAN_DEVELOPMENT_* DEVCACHE         every routing name env.zsh pins (prefixes, so a name it adds is covered)
GOFLAGS is not on the list: the gate cannot tell a wrapper's GOFLAGS from a caller's. Engine builds and Config/Scripts/test.sh
set their own; Tools/lint/lint.sh's go vet and staticcheck rely on vendor auto-detection, with the same result.
Add it, and say so in CONTRIBUTING.md, the day a wrapper has to pass one.
The CLEAN_DEV names are taken from ~/.config/wgex/env.zsh by reading it (never edited from here); the self-test reads the
file again and fails if a CLEAN_DEV*, CLEAN_DEVELOPMENT_*, DEVCACHE or derived session-key input does not pass. The derivation
scans the session section and follows assignments to the id, key and prefix; zsh ${(P)...} indirection is a known limit.

What the list leaves to env.zsh: every recipe line runs under `zsh -lc`, which loads ~/.config/wgex/env.zsh again, keyed on
HOME and the CLEAN_DEV pins, and re-exports the caches and routing (GOPATH, GOCACHE, GOMODCACHE, XCODE_DERIVED_DATA_PATH,
SWIFTPM_SHARED_CACHE, XDG_*, the other caches, PYTHON_HISTORY, FPATH). A step started by a `just` recipe therefore sees the
list plus what env.zsh derives from it; a bare bash or python3 step sees the list only.

What it breaks, on purpose: a caller who selects Xcode or a toolchain through DEVELOPER_DIR, TOOLCHAINS or SDKROOT gets
xcode-select's default (doctor enforces Toolchain.lock minimum versions and fails if the default is below the floor);
SSH_AUTH_SOCK, HTTPS_PROXY and the password-manager session variables are dropped (nothing offline needs them; an online
testpeer run behind a proxy would); GOFLAGS is set by the repository's scripts where needed; GOPATH comes from env.zsh; GOCACHE and
STATICCHECK_CACHE are set by the repository's scripts. GOENV uses go's default file under the trusted HOME; neither env.zsh nor the repository sets it.

Trusted inputs (TRUSTED_NAMES; design decision of 1 Nov 2026): HOME and PATH are
trusted inputs of the gate. The trust boundary is the user's own account: a caller who can set HOME can already set PATH
and edit every dotfile, so stripping or pinning HOME buys nothing real, and it would break the routing that
~/.config/wgex/env.zsh derives from it. Both are on the list and pass unchanged. The same rule is in
CONTRIBUTING.md's gate section, and the self-test test_home_and_path_are_trusted_inputs_passed_through_unchanged pins it,
so a change to it is deliberate: change the rule, both documents and that test together.

What gate entry prints: one line per step that dropped anything, "gate-entry: LABEL dropped N inherited variables" (the
--enter COMMAND line, check's bash entry point, also names them, through printable(); a value is never printed). WGEX_* is kept, so the verdict-changing
opt-outs (VERDICT_WGEX_NAMES) still get their own names-only "kept from caller:" line. `timed-step.py --enter` still
REFUSES a caller's JUST_* execution variable (see JUST_* below): the outer `just` has read it before any step can drop it.

The corpus below is the record of the earlier strip list (M1-10x): the names that were shown to change what a gate step
does, each with its reason. Nothing strips by it any more. Two things still use it: ZSH_KNOB_NAMES is the `env -u` list of
the justfile's recipe shell, the only protection of the outer `just check` line, which runs before timed-step starts; and
the self-test builds its polluted caller environments from every list, so a name added here is exercised without an edit
to a test. WGEX_* and the STUB_* channels below are what the self-test's own tests read; a test that needs one sets it
explicitly in the child environment.

Corpus: every environment variable that changes a non-interactive run of bash or python3, derived from man bash
(INVOCATION, Shell Variables, FUNCTIONS, ENVIRONMENT; host /bin/bash 3.2.57, probed one variable at a time), the bash
5.x manual (not installed here, so those entries are from the manual only) and python3 -h, --help-env and man python3.
Not read by a non-interactive child, so not in it: IFS, OPTIND, OPTERR and RANDOM (bash ignores them in the
environment, probed), PS1-PS3, PROMPT_COMMAND, HIST*, MAIL*, INPUTRC, EMACS, FIGNORE, HOSTFILE, IGNOREEOF, COMP*,
histchars and COLUMNS/LINES (interactive, readline or select only), NO_COLOR (only switches colour off).
Also not in it, although bash 3.2.57 imports an inherited value in place of its own (probed): OSTYPE, HOSTTYPE,
MACHTYPE and HOSTNAME, and TEXTDOMAIN and TEXTDOMAINDIR (only $"..." strings); no tracked script, justfile or test reads
any of them (git grep). The allowlist drops all of them anyway.
Each entry below with the reason it is dangerous:
  BASH_ENV            file every non-interactive bash sources before the script
  ENV                 file an interactive POSIX-mode bash (or sh -i) sources
  SHELLOPTS           set -o options (xtrace, posix, noglob, ...) enabled before any startup file
  BASHOPTS            shopt options (nullglob, failglob, extglob, ...) enabled at startup (bash 4.1+)
  POSIXLY_CORRECT     starts bash in POSIX mode (3.2 then has no process substitution)
  BASH_COMPAT         selects an older compatibility level (bash 4.3+)
  BASH_XTRACEFD       file descriptor that receives xtrace output (bash 4.1+)
  BASH_LOADABLES_PATH search path for enable -f loadable builtins (bash 5)
  BASH_ARGV0          assigning it renames $0 (bash 5.0+)
  BASH_FUNC_<name>%%  exported function definitions, imported into every bash child (prefix, set through env(1))
  PS4                 prefix printed before each xtrace line
  TMOUT               default timeout of the read builtin
  GLOBIGNORE          patterns removed from pathname expansion results (bash 3.2.57 ignores it in the environment,
                      probed; newer bash may not)
  GLOBSORT            sort order of pathname expansion results (bash 5.3)
  CDPATH              extra search path (and printed target) of cd
  CHILD_MAX           how many exited child statuses bash remembers, so wait results (bash 4.x)
  EXECIGNORE          patterns of executables that command search skips (bash 4.0+)
  FUNCNEST            maximum function nesting depth (bash 4.2+; inert on 3.2.57, probed: nested calls still run)
  TIMEFORMAT          layout of the output of the time keyword
  SECONDS             seeds the $SECONDS elapsed-time counter (imported by 3.2.57, probed)
  PYTHON*             every variable python3 -h, --help-env and man python3 document (PYTHONPATH, PYTHONHOME,
                      PYTHONSTARTUP, PYTHONSAFEPATH, PYTHONWARNINGS, PYTHON_COLORS, PYTHON_HISTORY, ...); a prefix
  FORCE_COLOR         makes the stdlib colourise unittest and traceback output, also under -I (probed, ANSI escapes)
PYTHON_HISTORY (the REPL history file that ~/.config/wgex/env.zsh exports) is not on the allowlist either: env.zsh sets it
again in every `zsh -lc` step, and no child is interactive.

zsh knobs (ZSH_KNOB_NAMES, in KNOB_NAMES), derived from man zsh (STARTUP/SHUTDOWN FILES, PARAMETERS USED BY THE SHELL; host
zsh 5.9, probed one variable at a time with `env NAME=x zsh -fc 'print ${(P)1}' _ NAME`): zsh imports every inherited
variable as a parameter, so these are the ones that change a non-interactive `zsh -lc` run. The justfile's recipe shell,
["/usr/bin/env", "-u", ..., "zsh", "-lc"], removes them, and it is the only thing that protects the outer `just check` /
`just check-full` line, because that zsh starts before timed-step does (gate entry drops them too, as it drops everything
off the list).
  ZDOTDIR      directory zsh reads .zshenv, .zprofile and .zlogin from instead of ~ (a caller's file can re-export every
               variable stripped here, or `exit 0` so a recipe line ends green without running)
  TMPPREFIX    prefix of the temp files for here-documents and =(...) (probed: an unusable value fails them)
  NULLCMD      command a bare `> file` runs (probed: imported)
  READNULLCMD  command a bare `< file` runs (probed: imported)
  ARGV0        exported value becomes argv[0] of external commands (zshparam; probe inconclusive, so removed on the manual)
  CDPATH, TMOUT   already in the bash list; zsh imports them too
Not in it: FPATH/fpath (no gate recipe or script autoloads a function, and the host login zsh exports FPATH itself, via
brew shellenv; revisit if a recipe ever autoloads), MODULE_PATH and IFS (probed: zsh does not import them), SHELL (selects
nothing; it is on the allowlist), and the interactive-only parameters (PROMPT*, PS1-PS3, HIST*, WORDCHARS, FIGNORE,
KEYTIMEOUT, LISTMAX, REPORTTIME, TIMEFMT, MAIL*, ZLE_*, PSVAR, WATCH).

Git knobs (the GIT_ prefix in TOOL_KNOB_PREFIXES, M1-10x fix 3): every GIT_* variable is hostile, not a list of names.
git 2.56.0 names 171 GIT_* variables (strings of the binary), and a list of the ones found so far missed twice (the
repository selectors, then GIT_TEST_FSMONITOR, FIX2-VERIFY G1). The families, each with why it changes a step:
  GIT_DIR, GIT_WORK_TREE, GIT_INDEX_FILE, GIT_COMMON_DIR, GIT_OBJECT_DIRECTORY, GIT_ALTERNATE_OBJECT_DIRECTORIES,
  GIT_NAMESPACE, GIT_EXEC_PATH     repository, index, objects, refs namespace and the git-* helper directory: an empty
               index or repository blinds every repo_files-based lint check
  GIT_CONFIG* (GIT_CONFIG, _GLOBAL, _SYSTEM, _NOSYSTEM, _COUNT, _KEY_n, _VALUE_n, _PARAMETERS)   configuration
  GIT_CEILING_DIRECTORIES, GIT_DISCOVERY_ACROSS_FILESYSTEM    where repository discovery stops
  GIT_LITERAL_PATHSPECS, GIT_GLOB_PATHSPECS, GIT_NOGLOB_PATHSPECS, GIT_ICASE_PATHSPECS    pathspec matching (the lint
               checks' ':!:...' exclusions and file selection)
  GIT_REPLACE_REF_BASE, GIT_GRAFT_FILE, GIT_SHALLOW_FILE    which objects and history git sees
  GIT_ATTR_SOURCE, GIT_ATTR_GLOBAL  where .gitattributes is read from
  GIT_TEST_* (46 names)            test hooks the production binary honours: GIT_TEST_FSMONITOR=<program> runs that
               program like core.fsmonitor inside every git call; it rewrote the planted file and turned the lint step
               from exit=1 to exit=0 (FIX2-VERIFY G1)
  GIT_EXTERNAL_DIFF, GIT_EDITOR, GIT_SEQUENCE_EDITOR, GIT_PAGER, GIT_ASKPASS, GIT_SSH, GIT_SSH_COMMAND    programs git
               runs on the caller's behalf
  GIT_TEMPLATE_DIR                 files copied into every new repository (the self-test and lint self-tests create
               scratch repositories)
  GIT_TRACE* (and their _REDACT switches), GIT_PROGRESS_DELAY and the rest    output and diagnostics; the prefix
               covers a name a newer git adds without an edit here
Also hostile for git, by name (TOOL_KNOB_NAMES):
  XDG_CONFIG_HOME                  git reads $XDG_CONFIG_HOME/git/config as global configuration (and git/ignore and
               git/attributes), the same channel as GIT_CONFIG_GLOBAL: a core.fsmonitor hook there runs inside a step
               (FIX1-VERIFY F1). Dropping it changes nothing for the account: git's default is then $HOME/.config/git,
               and a nested `zsh -lc` step gets $HOME/.config back from env.zsh. shellcheck also reads $XDG_CONFIG_HOME/shellcheckrc, but only when no
               .shellcheckrc is found above the script, and the repository has one (probed).
No gate step needs a GIT_* value from its caller (git grep: the only GIT_* name a tracked script sets or
reads is GIT_OPTIONAL_LOCKS). The candidates, each checked:
  GIT_OPTIONAL_LOCKS  dropped: Config/Scripts/lib.sh exports GIT_OPTIONAL_LOCKS=0 after entry, and every gate step that
               runs git on the real checkout does so under it (the lint scripts through Tools/lint/lib.sh, the engine
               scripts through Engine/scripts/lib.sh, source-digest.py from scripts that source either);
               Tools/docs/check.py only runs `git archive`, which takes no optional lock, and the self-test's own git
               calls run in scratch repositories.
  GIT_EDITOR          dropped. This host's login shell does not export it; the Claude Code harness exports GIT_EDITOR=true
               to every command it starts. No tracked script runs a git command that opens an editor (no commit, merge,
               tag, rebase, revert or notes; git grep).

Configuration-file redirects of xcodebuild, go and SwiftPM (TOOL_KNOB_NAMES, M1-10x fix 3): each points one tool at a
configuration file outside the repository without changing the account, the same rule as ZDOTDIR and XDG_CONFIG_HOME.
  XCODE_XCCONFIG_FILE    xcodebuild loads that file's build settings for every target, above every other level, the
               command line and -xcconfig included (man xcodebuild, Environment Variables); a define there turned a
               throwaway package's build from rc 65 to rc 0 through timed-step (FIX2-VERIFY G2), and the variable
               survives `zsh -lc` into gen, packages-macos, build-debug and the xcodebuild tests
  GOENV                  the go environment file (`go env GOENV`): its CC, CGO_*, GOFLAGS, GOEXPERIMENT and other values
               apply to every go command the gate starts wherever the wrapper or test.sh sets no variable of its own
               (probed: CC=<hook> in that file ran the hook inside check/go-race); go then reads its default file under
               the trusted HOME
  SWIFTPM_MIRROR_CONFIG  SwiftPM's dependency mirror table (mirrors.json) is read from that path (strings of swift-package
               and Xcode's SwiftPM.framework; probed: a throwaway package's dependency resolved from the mirrored
               repository). Every WGEX package has path dependencies only, so it changes nothing today
Review (offline: man xcodebuild, xcodebuild -help, swift --help (names no variable), strings of swift-package, SWBCore,
Xcode's SwiftPM and DVTFoundation): no other environment variable points xcodebuild, SwiftBuild or SwiftPM at a configuration file. The rest
are toolchain selectors (XCODE_DEVELOPER_DIR_PATH, SWIFT_EXEC_MANIFEST, SWIFTPM_CUSTOM_BIN_DIR, SWIFTPM_CUSTOM_LIBS_DIR),
caches and outputs (SWIFTPM_MODULECACHE_OVERRIDE, SWIFTPM_TESTS_MODULECACHE, SWIFTPM_BUILD_SBOM_*), credentials no gate
step uses (SWIFTPM_NETRC_DATA, SWIFTPM_REGISTRY_*: nothing is fetched) or feature switches; ~/.swiftpm, ~/.netrc and
Xcode's defaults are under the trusted HOME.
XDG_* review (M1-10x fix 2; strings of each binary, then a git config with a core.fsmonitor hook placed under each base
directory, probed one at a time): of the tools the gate starts only git (XDG_CONFIG_HOME, XDG_CACHE_HOME) and shellcheck
(every XDG_* name, through its runtime library) name any XDG_* variable, and just names XDG_RUNTIME_DIR; zsh, bash, BSD
grep, python3 (stdlib: webbrowser.py only, never imported by the gate), xcodebuild, SwiftPM, XCBuild and SwiftBuild name
none. Not hostile, so not in the corpus (env.zsh sets them again in every `zsh -lc` step; the allowlist drops them at entry):
  XDG_CACHE_HOME, XDG_DATA_HOME, XDG_STATE_HOME    routing env.zsh sets (like TMPDIR); git uses XDG_CACHE_HOME only for
               the credential-cache socket, which no gate step uses; no git or shellcheck configuration is read from them
               (probed: the hook did not run)
  XDG_CONFIG_DIRS, XDG_DATA_DIRS    git does not read them (probed); shellcheck ignores a shellcheckrc under
               XDG_CONFIG_DIRS (probed)
  XDG_RUNTIME_DIR                   just 1.59.0 on macOS still writes shebang-recipe scripts under TMPDIR with it set
               (probed), and no gate recipe has a shebang; a temp location, not configuration

JUST_* (execution): the outer `just` reads these before gate entry runs. Gate entry drops every JUST_* from a step's
environment (they are not on the allowlist), and `timed-step.py --enter` (the first line of check and check-full) REFUSES with a named error and status 2
when it inherits one that changes what just runs: every JUST_* name that is not in JUST_PRESENTATION_NAMES, so a name
added by a newer just is refused until someone classifies it. The classification is checked against `just --help` by the
self-test. JUST_DRY_RUN (echo the recipe, run nothing), JUST_JUSTFILE, JUST_WORKING_DIRECTORY, JUST_QUIET, JUST_NO_DEPS,
JUST_DOTENV_COMMAND, JUST_TEMPDIR and the rest of JUST_EXECUTION_NAMES are in that group.

Verdict opt-outs (VERDICT_WGEX_NAMES): WGEX_* names that pass gate entry but change what a green result means.
timed-step prints one names-only "kept from caller:" line when it passes any of them on.
Build variants: ordinary recipes refuse an inherited WGEX_OWN_MAC_BUILD by presence, including empty or zero values.
The dedicated own-Mac recipe bypasses the ordinary recipe shell and sets its own compile define explicitly.
Gate entry also refuses inherited WGEX_LAB_BUILD; gate steps can opt into Lab explicitly.

Tool knobs (TOOL_KNOB_*): variables the BSD userland and just read, probed on this host. GREP_OPTIONS (BSD grep
2.6.0-FreeBSD: GREP_OPTIONS=--count turns every grep into a counter), GREP_COLOR and GREP_COLORS, CLICOLOR_FORCE (BSD
ls and friends colour piped output) and JUST_* (JUST_QUIET silences the recipes, JUST_JUSTFILE redirects a recipe to
another justfile).
"""
import re

# The allowlist gate entry and the self-test apply (see "The list" above); everything else in this file is the corpus.
GATE_ALLOWED_NAMES = frozenset({"PATH", "HOME", "TMPDIR", "USER", "LOGNAME", "SHELL", "TERM", "LANG", "CODEX_THREAD_ID",
                                "CLAUDE_CODE_SESSION_ID",
                                "GOPROXY", "GOTOOLCHAIN", "GOSUMDB", "GOVULNDB", "DEVCACHE"})
GATE_ALLOWED_PREFIXES = ("LC_", "WGEX_", "CLEAN_DEV_", "CLEAN_DEVELOPMENT_")
# The macOS python3 adds this to its own environment at startup, whatever the caller exported (so timed-step and the
# self-test would always find it): dropped like the rest, but not counted, so a clean caller prints no entry line.
INTERPRETER_NAMES = frozenset({"__CF_USER_TEXT_ENCODING"})

# The corpus (see "Corpus" above): names the earlier strip list held. Nothing strips by these; ZSH_KNOB_NAMES feeds the
# justfile's `env -u`, and the self-test builds its polluted callers from all of them.
KNOB_PREFIXES = ("WGEX_", "STUB_", "PYTHON", "BASH_FUNC_")
ZSH_KNOB_NAMES = frozenset({"ZDOTDIR", "TMPPREFIX", "NULLCMD", "READNULLCMD", "ARGV0", "CDPATH", "TMOUT"})
KNOB_NAMES = ZSH_KNOB_NAMES | frozenset({"BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "POSIXLY_CORRECT", "BASH_COMPAT", "BASH_XTRACEFD",
                        "BASH_LOADABLES_PATH", "BASH_ARGV0", "PS4", "TMOUT", "GLOBIGNORE", "GLOBSORT", "CDPATH",
                        "CHILD_MAX", "EXECIGNORE", "FUNCNEST", "TIMEFORMAT", "SECONDS", "FORCE_COLOR"})
# HOME and PATH are trusted inputs of the gate: on the allowlist, never pinned (see "Trusted inputs" above for the rule and why).
TRUSTED_NAMES = frozenset({"HOME", "PATH"})
# Every GIT_* name, with no exception (see "Git knobs" above for the families and the empty keep list).
TOOL_KNOB_PREFIXES = ("JUST_", "GIT_")
# The configuration-file redirects of xcodebuild, go and SwiftPM are listed by name: each tool reads many other variables
# that are toolchain selectors, outside the class.
CONFIG_REDIRECT_NAMES = frozenset({"XCODE_XCCONFIG_FILE", "GOENV", "SWIFTPM_MIRROR_CONFIG"})
TOOL_KNOB_NAMES = CONFIG_REDIRECT_NAMES | frozenset({"XDG_CONFIG_HOME", "GREP_OPTIONS", "GREP_COLOR", "GREP_COLORS",
                                                     "CLICOLOR_FORCE"})
VERDICT_WGEX_NAMES = frozenset({"WGEX_OFFLINE"})
GATE_REFUSED_BUILD_VARIANTS = frozenset({"WGEX_OWN_MAC_BUILD", "WGEX_LAB_BUILD"})
# Every JUST_* name `just --help` (1.59.0) and the binary list, split by whether it changes what a recipe run does. A JUST_*
# name outside JUST_PRESENTATION_NAMES (these, or any unknown one) makes `timed-step.py --enter` refuse.
JUST_EXECUTION_NAMES = frozenset({"JUST_ALLOW_MISSING", "JUST_CEILING", "JUST_DOTENV_COMMAND", "JUST_DRY_RUN", "JUST_JOBS",
                                  "JUST_JUSTFILE", "JUST_JUSTFILE_NAME", "JUST_NO_CACHE", "JUST_NO_DEPS", "JUST_NO_DOTENV",
                                  "JUST_ONE", "JUST_QUIET", "JUST_TEMPDIR", "JUST_UNSTABLE", "JUST_WORKING_DIRECTORY",
                                  "JUST_YES"})
# Output layout, listing, --choose and Windows path conversion only (`just --help` descriptions); JUST_LOG is the stderr log level.
JUST_PRESENTATION_NAMES = frozenset({"JUST_ALIAS_STYLE", "JUST_CHOOSER", "JUST_COLOR", "JUST_COMMAND_COLOR",
                                     "JUST_COMPLETE_ALIASES", "JUST_CYGPATH", "JUST_DEFAULT_LIST", "JUST_DUMP_FORMAT",
                                     "JUST_EVALUATE_FORMAT", "JUST_EXPLAIN", "JUST_GROUP", "JUST_HIGHLIGHT",
                                     "JUST_INDENTATION", "JUST_LIST_HEADING", "JUST_LIST_PREFIX", "JUST_LIST_SUBMODULES",
                                     "JUST_LOG", "JUST_NO_ALIASES", "JUST_NO_HIGHLIGHT", "JUST_TIME", "JUST_TIMESTAMP",
                                     "JUST_TIMESTAMP_FORMAT", "JUST_UNSORTED", "JUST_VERBOSE"})


def allowed(name, withhold_prefixes=()):
    """True when a variable called name may reach a gate step: it is on the allowlist and not under a withheld prefix."""
    return ((name in GATE_ALLOWED_NAMES or name.startswith(GATE_ALLOWED_PREFIXES))
            and not name.startswith(tuple(withhold_prefixes)))


def dropped(environment, withhold_prefixes=()):
    """Sorted names in environment that the allowlist does not pass, to be counted (withhold_prefixes: allowed names to drop
    anyway; INTERPRETER_NAMES are not counted)."""
    return sorted(name for name in environment if not allowed(name, withhold_prefixes) and name not in INTERPRETER_NAMES)


def restrict(environment, withhold_prefixes=()):
    """Delete every name the allowlist does not pass from environment (a dict or os.environ) in place; returns the sorted
    names deleted and counted. The self-test passes withhold_prefixes=("WGEX_",), gate entry passes none."""
    names = dropped(environment, withhold_prefixes)
    for name in names + [name for name in INTERPRETER_NAMES if name in environment]:
        del environment[name]
    return names


def just_execution_variables(environment):
    """Sorted JUST_* names in environment that change what just runs: every one outside JUST_PRESENTATION_NAMES."""
    return sorted(name for name in environment if name.startswith("JUST_") and name not in JUST_PRESENTATION_NAMES)


def verdict_variables(environment):
    """Sorted names in environment that are kept at gate entry but change what a green result means."""
    return sorted(name for name in environment if name in VERDICT_WGEX_NAMES)


def printable(names):
    """Names only, never values, each character outside [A-Za-z0-9_] replaced, so a crafted name cannot forge a line."""
    return ", ".join(re.sub(r"[^A-Za-z0-9_]", "_", name) for name in names)


def refuse_build_variants(environment, names=GATE_REFUSED_BUILD_VARIANTS):
    """Refuse variant names by presence; never print their values or silently strip them."""
    import sys
    refused = sorted(names.intersection(environment))
    if refused:
        sys.stderr.write(f"gate-entry: refused: inherited build variant {printable(refused)}; "
                         "unset it and run the recipe again\n")
        return 2
    return 0


if __name__ == "__main__":
    import os
    import sys
    status = refuse_build_variants(os.environ, frozenset({"WGEX_OWN_MAC_BUILD"}))
    if status:
        sys.exit(status)
    # The justfile supplies the fixed shell and command after this guard.
    os.execvp(sys.argv[1], sys.argv[1:])
