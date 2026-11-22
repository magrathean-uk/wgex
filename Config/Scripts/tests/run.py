# SPDX-License-Identifier: MIT
"""M1-13 tooling regressions; all fixtures live in session scratch."""
import datetime
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import plistlib
import re
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
# The caller's environment is cut here, at import, to the allowlist the gate entry applies (Config/Scripts/knobs.py, which
# holds the list and the reason for it), less the WGEX_ prefix: this self-test is hermetic against the gate's own knobs as
# well, and a test that needs one (or any dropped name) sets it explicitly in the child environment. The polluted callers
# the tests build come from the knobs.py corpus (KNOB_PREFIXES, KNOB_NAMES and the tool knobs), so a name added there is
# exercised without editing a test.
_KNOBS_SPEC = importlib.util.spec_from_file_location("wgex_knobs", Path(__file__).resolve().parents[1] / "knobs.py")
knobs = importlib.util.module_from_spec(_KNOBS_SPEC)
_KNOBS_SPEC.loader.exec_module(knobs)
KNOB_PREFIXES, KNOB_NAMES = knobs.KNOB_PREFIXES, knobs.KNOB_NAMES
TOOL_KNOB_PREFIXES, TOOL_KNOB_NAMES = knobs.TOOL_KNOB_PREFIXES, knobs.TOOL_KNOB_NAMES
SELFTEST_WITHHELD_PREFIXES = ("WGEX_",)


def restrict_to_allowlist(environment):
    """Delete every name outside the gate allowlist, and every WGEX_* name, from environment in place; returns the sorted
    names deleted (knobs.restrict)."""
    return knobs.restrict(environment, SELFTEST_WITHHELD_PREFIXES)


# At import, so every runner (just tooling-selftest, python3 run.py, unittest discovery) is hermetic, and every child
# environment built from os.environ below starts without the caller's extras. A count only on stderr: on a real host the
# list is long and every name is routine.
_DROPPED_VARIABLES = restrict_to_allowlist(os.environ)
if _DROPPED_VARIABLES:
    print(f"tooling-selftest: dropped {len(_DROPPED_VARIABLES)} inherited variables", file=sys.stderr)

SHELL_SHEBANG = re.compile(r"#!\s*(?:\S*/env\s+(?:-\S+\s+)*)?(?:\S*/)?(?:bash|zsh|dash|ksh|sh)(?:\s|$)")
SHELL_SUFFIXES = (".sh", ".bash", ".zsh")
# Words after which a command starts again (`then source x`), and prefixes that run the next word as the command.
SHELL_KEYWORDS = frozenset({"if", "then", "else", "elif", "do", "while", "until", "!", "time", "{", "builtin", "command"})
SHELL_NAMES = frozenset({"bash", "zsh", "dash", "ksh", "sh"})
ASSIGNMENT_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=", re.S)
PLAIN_EXPANSION = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])")
# The dynamic head of a sourced path: a variable, ${VAR}, ${VAR[0]%/*} or ${VAR##*/}, or one of exactly two substitution shapes
# (in $(...) or backticks): `dirname WORD`, and `cd [--] DIR && pwd [-L|-P]` where DIR is `$(dirname WORD)` (a CDPATH= prefix
# and redirections to /dev/null are allowed). A substitution that merely mentions dirname or pwd ($(echo dirname),
# $(cd /tmp && pwd), $(cd "$(dirname "$0")/.." && pwd)) is not a directory this parser knows, so it is refused, as is
# anything else (${VAR:-default}, $(mktemp -d)).
_ANCHOR_WORD = r"""(?:"(?:[^"`$\\]|\\.|\$(?!\())*"|[A-Za-z0-9_./${}\[\]@%#*~:+-]+)"""
_ANCHOR_DIRNAME = r"dirname\s+(?:--\s+)?" + _ANCHOR_WORD
_ANCHOR_DIR = r"\$\(\s*" + _ANCHOR_DIRNAME + r"\s*\)"
_ANCHOR_CD_PREFIX = r"""(?:CDPATH=(?:''|"")?\s+)?cd\s+(?:--\s+)?"""
_ANCHOR_PWD_TAIL = r"""(?:\s*(?:[0-9]?>\s*/dev/null|2>&1))*\s*&&\s*pwd(?:\s+-[LP])?"""
_ANCHOR_CD_PWD = _ANCHOR_CD_PREFIX + r"""(?:"%s"|%s)""" % (_ANCHOR_DIR, _ANCHOR_DIR) + _ANCHOR_PWD_TAIL
_ANCHOR_SUBSTITUTION = (r"(?:\$\(\s*%s\s*\)|`\s*%s\s*`|\$\(\s*%s\s*\)|`\s*%s\s*`)"
                        % (_ANCHOR_DIRNAME, _ANCHOR_DIRNAME, _ANCHOR_CD_PWD, _ANCHOR_CD_PWD))
_ANCHOR_VARIABLE = r"""\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?(?:%%?[^}]*|\#\#?[^}]*)?\})"""
SUBSTITUTION_ANCHOR = re.compile(_ANCHOR_SUBSTITUTION + r"\Z", re.S)
# `$(cd "$(dirname WORD)/literal" && pwd)`: the script directory plus a literal path (group "suffix"), as in `ROOT=$(cd
# "$(dirname "$0")/../.." && pwd)`. A variable assigned it is that directory, not the script directory.
SUBSTITUTION_WITH_SUFFIX = re.compile(r"\$\(\s*" + _ANCHOR_CD_PREFIX + r"""\"?""" + _ANCHOR_DIR + r"""(?P<suffix>/[^\s"$`\\&;|()]*)"?"""
                                      + _ANCHOR_PWD_TAIL + r"\s*\)\Z", re.S)
# The same with an expansion in the path after the dirname (`$(cd "$(dirname "$0")/$SUB" && pwd)`): not a directory the scanner
# can read, so a variable assigned it is refused (head_variable_anchor).
SUBSTITUTION_DYNAMIC_SUFFIX = re.compile(r"\$\(\s*" + _ANCHOR_CD_PREFIX + r"""\"?""" + _ANCHOR_DIR + r"""/[^\s"]*[$`][^"]*"?"""
                                         + _ANCHOR_PWD_TAIL + r"\s*\)\Z", re.S)
SOURCE_ANCHOR = re.compile("(?:" + _ANCHOR_VARIABLE + "|" + _ANCHOR_SUBSTITUTION + r")\Z", re.S)
# `source` and `.` as a command, with these prefixes dropped; `command -v source` only looks the word up.
REDIRECTION = re.compile(r"(?:[0-9]+|&)?(?:<<<|<<-?|<>|>>|>\||>&|<&|>|<)(.*)\Z", re.S)
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
SHELL_C_OPTION = re.compile(r"-[A-Za-z]*c[A-Za-z]*\Z")
SHELL_ARGUMENT_OPTION = re.compile(r"[-+][A-Za-z]*[oO]\Z")
# A token of a line and the places a command can start, for the backstop that does not trust shell_commands.
# A token is cut at 200 characters (a `source` or `.` word is short; the argument only has to exist), so a line of one
# enormous word costs a bounded step per command mark, not a pass over the whole line.
CASE_ARM_MARK = re.compile(r"(?:^|[;&|]|(?<![\w-])in(?![\w-]))\s*\(?\s*[^\s;&|()]+\)\s*")
COMMAND_MARK = re.compile(r"(?:^|[;&|(`]|(?<!\$)\{|(?<![\w-])(?:then|do|else|elif|if|while|until)(?![\w-])|(?<!\S)!)\s*")
LINE_TOKEN = re.compile(r"""(?:[^\s;|()'"\\`]|\\.|'[^']{0,200}'?|"(?:[^"\\]|\\.){0,200}"?){1,200}""", re.S)


def is_shell_script(path):
    """True for a file with a shell suffix (.sh, .bash, .zsh) or a shell shebang (sh, bash, zsh, dash, ksh, also via env)."""
    path = Path(path)
    if path.suffix in SHELL_SUFFIXES:
        return True
    try:
        with open(path, "rb") as handle:
            head = handle.read(200)
    except OSError:
        return False
    first = head.split(b"\n", 1)[0].decode("utf-8", errors="replace")
    return bool(SHELL_SHEBANG.match(first))


def _span_single(text, i):
    end = text.find("'", i + 1)
    return len(text) if end < 0 else end + 1


def _span_backtick(text, i):
    end = text.find("`", i + 1)
    return len(text) if end < 0 else end + 1


def _span_double(text, i):
    """Index after the double-quoted string that starts at text[i], expansions inside it (which nest quotes) included."""
    i += 1
    while i < len(text) and text[i] != '"':
        if text[i] == "\\":
            i += 2
        elif text.startswith("$(", i):
            i = _span_paren(text, i)
        elif text.startswith("${", i):
            i = _span_brace(text, i)
        elif text[i] == "`":
            i = _span_backtick(text, i)
        else:
            i += 1
    return min(i + 1, len(text))


def _span_paren(text, i):
    """Index after the $( ... ) that starts at text[i]."""
    depth, i = 1, i + 2
    while i < len(text) and depth:
        char = text[i]
        if char == "\\":
            i += 2
            continue
        if char == "'":
            i = _span_single(text, i)
            continue
        if char == '"':
            i = _span_double(text, i)
            continue
        if char == "`":
            i = _span_backtick(text, i)
            continue
        depth += (char == "(") - (char == ")")
        i += 1
    return min(i, len(text))


def _span_brace(text, i):
    """Index after the ${ ... } that starts at text[i]."""
    depth, i = 1, i + 2
    while i < len(text) and depth:
        char = text[i]
        if char == "\\":
            i += 2
            continue
        if char == "'":
            i = _span_single(text, i)
            continue
        if char == '"':
            i = _span_double(text, i)
            continue
        depth += (char == "{") - (char == "}")
        i += 1
    return min(i, len(text))


def shell_commands(text):
    """Commands of text as lists of raw words (quotes, escapes and expansions kept, comments dropped).

    A command ends at an unquoted ; & | ( ) or newline, except the & of a redirection (2>&1, <&3, &>file), which stays in
    its word. Quoted strings, ${...}, $(...) and backticks stay inside their word, so a `;` or a space in a quoted path
    does not split it. This is a scanner for source lines, not a shell parser.
    """
    commands, words, start = [], [], None
    i, n = 0, len(text)

    def close_word(end):
        nonlocal start
        if start is not None:
            words.append(text[start:end])
            start = None

    def close_command(end):
        close_word(end)
        if words:
            commands.append(list(words))
            words.clear()

    while i < n:
        char = text[i]
        if char in " \t\r":
            close_word(i)
            i += 1
        elif char == "&" and ((start is not None and text[i - 1] in "<>") or text.startswith("&>", i)):
            if start is None:
                start = i
            i += 1
        elif char == "\n" or char in ";&|()":
            close_command(i)
            i += 1
        elif char == "#" and start is None:
            end = text.find("\n", i)
            i = n if end < 0 else end
        else:
            if start is None:
                start = i
            if char == "\\":
                i += 2
            elif char == "'":
                i = _span_single(text, i)
            elif char == '"':
                i = _span_double(text, i)
            elif char == "`":
                i = _span_backtick(text, i)
            elif text.startswith("$(", i):
                i = _span_paren(text, i)
            elif text.startswith("${", i):
                i = _span_brace(text, i)
            else:
                i += 1
    close_command(n)
    return commands


def _substitutions(text, in_double=False):
    """The text inside every $(...) and backtick substitution of text (single-quoted text is not expanded)."""
    found, i, n = [], 0, len(text)
    while i < n:
        char = text[i]
        if char == "\\":
            i += 2
        elif char == "'" and not in_double:
            i = _span_single(text, i)
        elif char == '"' and not in_double:
            end = _span_double(text, i)
            found += _substitutions(text[i + 1:max(end - 1, i + 1)], True)
            i = end
        elif text.startswith("$(", i):
            end = _span_paren(text, i)
            found.append(text[i + 2:end - 1])
            i = end
        elif char == "`":
            end = _span_backtick(text, i)
            found.append(text[i + 1:end - 1])
            i = end
        else:
            i += 1
    return found


def _unquote(word):
    """word without one layer of outer quotes (and the $ of $'...'), for the code `eval`, `sh -c`, trap and alias run; the
    escapes a double quote keeps (\\" \\\\ \\$ \\`) are removed, as the shell removes them before the code runs."""
    if word.startswith("$'") and word.endswith("'") and len(word) >= 3:
        return word[2:-1]
    if len(word) >= 2 and word[0] == word[-1] == '"':
        return re.sub(r'\\(["\\$`])', r"\1", word[1:-1])
    if len(word) >= 2 and word[0] == word[-1] == "'":
        return word[1:-1]
    return word


def _literal(word):
    """word with its quotes and backslashes removed when nothing in it expands (\\., 'sour''ce' and "source" read as the
    words they are), else None."""
    pieces = _word_pieces(word)
    return "".join(value for _, value in pieces) if all(kind == "lit" for kind, _ in pieces) else None


def _command_words(words):
    """words of one command from its command word on: leading keywords (then, do, !, {, time, ...), VAR=x assignments,
    redirections (`2>/dev/null`, `>&2`, `2> file`), `function`, `coproc [NAME]`, and the options of command, builtin and time
    are dropped. `command -v`, which only looks a word up, gives []."""
    words = list(words)
    while words:
        if ASSIGNMENT_WORD.match(words[0]):
            words.pop(0)
            continue
        redirect = REDIRECTION.match(words[0])
        if redirect:
            words.pop(0)
            if not redirect.group(1) and words:  # `2> /dev/null`: the next word is its target
                words.pop(0)
            continue
        word = _literal(words[0])
        if word is None:
            break
        if word in SHELL_KEYWORDS:
            words.pop(0)
            if word in ("command", "builtin", "time"):
                if words and _literal(words[0]) in ("-v", "-V"):
                    return []
                while words and (_literal(words[0]) or "").startswith("-"):
                    words.pop(0)
        elif word == "function":
            del words[:2]
        elif word == "coproc":
            words.pop(0)
            if len(words) > 1 and IDENTIFIER.match(_literal(words[0]) or "") and _literal(words[1]) == "{":
                words.pop(0)
        else:
            break
    return words


def _shell_code(words):
    """The code word of every `<shell> [options] -c [--] CODE` in words, wherever it sits (`sudo bash -c CODE`,
    `run_x label sh -ec CODE`): options are skipped (-o and -O take an argument, as do --rcfile and --init-file), a script
    name ends the options."""
    codes = []
    for index, word in enumerate(words):
        if (_literal(word) or "").rsplit("/", 1)[-1] not in SHELL_NAMES:
            continue
        position = index + 1
        while position < len(words):
            option = _literal(words[position])
            if option is None:
                break
            if SHELL_C_OPTION.match(option):
                position += 1
                while position < len(words) and re.match(r"(?:--|[-+][A-Za-z]+)\Z", _literal(words[position]) or ""):
                    position += 1
                if position < len(words):
                    codes.append(words[position])
                break
            if option in ("--rcfile", "--init-file") or SHELL_ARGUMENT_OPTION.match(option):
                position += 2
            elif option.startswith(("-", "+")) and option not in ("-", "+", "--"):
                position += 1
            else:
                break
    return codes


def _here_string_code(words):
    """The code word of every here-string of a shell in words (`bash <<<'CODE'`, `sh <<< "CODE"`, `bash -s <<< CODE`,
    `sudo bash -s <<< CODE`, `zsh<<<'CODE'`): a here-string given to any other command is data, not code."""
    codes, shell = [], False
    for index, word in enumerate(words):
        glued = re.match(r"([^<>'\"\s]*)<<<(.*)\Z", word, re.S)
        if not glued:
            shell = shell or (_literal(word) or "").rsplit("/", 1)[-1] in SHELL_NAMES
            continue
        shell = shell or (_literal(glued.group(1)) or "").rsplit("/", 1)[-1] in SHELL_NAMES
        code = glued.group(2) or (words[index + 1] if index + 1 < len(words) else "")
        if code:
            codes.append(code)
    return codes if shell else []


def _variable_code(words, code_variables):
    """The source arguments held by the variables that words name as a whole (`"$c"`, `$c`, `"${c}"`): the code of a variable
    that eval or `bash -c` runs."""
    found = []
    for word in words:
        named = re.fullmatch(r'"?\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))"?', word)
        if named:
            found += code_variables.get(named.group(1) or named.group(2), [])
    return found


def source_commands(text, depth=0, code_variables=None):
    """The argument (the raw word) of every `source` / `.` command in text. A `source` or `.` with no argument is
    ignored: bash rejects it ("filename argument required"), and prose or other languages in a heredoc produce it.
    The command word is read unquoted (`\\.`, `"source"`, `sour''ce`), after any leading keyword, assignment, redirection,
    `function`, `coproc` or `command -p` (_command_words). The command is found at a command position (after ; && || | (
    then do else ! or those prefixes), inside $(...) and backticks, inside the quoted code of eval, inside the code of
    a `<shell> [options] -c [--] CODE` wherever it sits in a command (`sudo bash -c`, `env bash -c`, a wrapper function),
    in the here-string word of a shell (`bash <<<'CODE'`), in the action of trap, in the value of an alias, and in a
    variable that eval or `bash -c` runs as a whole (`c='. "$D/x.sh"'; eval "$c"`; code_variables maps such a name to the
    source arguments of its value); an echo or printf command is a message, not a wrapper."""
    found, code_variables = [], code_variables or {}
    for command in shell_commands(text):
        for word in command:
            if depth < 4:
                for inner in _substitutions(word):
                    found += source_commands(inner, depth + 1, code_variables)
        words = _command_words(command)
        if not words:
            continue
        head = _literal(words[0])
        if head in ("source", "."):
            if len(words) > 1:
                found.append(words[1])
        elif depth < 4 and head == "eval":
            found += source_commands(" ".join(_unquote(word) for word in words[1:]), depth + 1, code_variables)
            found += _variable_code(words[1:], code_variables)
        elif depth < 4 and head == "trap":
            actions = list(words[1:])
            while actions and (_literal(actions[0]) or "").startswith("-"):  # -p, -l and `--`
                actions.pop(0)
            if actions:
                found += source_commands(_unquote(actions[0]), depth + 1, code_variables)
        elif depth < 4 and head == "alias":
            for word in words[1:]:
                assigned = ASSIGNMENT_WORD.match(word)
                if assigned:
                    found += source_commands(_unquote(word[assigned.end():]), depth + 1, code_variables)
        elif depth < 4 and head not in ("echo", "printf"):
            codes = _shell_code(words)
            for code in codes:
                found += source_commands(_unquote(code), depth + 1, code_variables)
            found += _variable_code(codes, code_variables)
            for code in _here_string_code(command):
                found += source_commands(_unquote(code), depth + 1, code_variables)
    return found


def hidden_source(line):
    """True when a word of line unquotes to `source` or `.` at a command start and has an argument: judged from the text of
    the line (a command start is a line start, ; & | ( { ` then do else elif if while until or a `!` word, and the `)` of a case
    arm, `a) source x;;`: a `)` after a pattern word that follows a line start, ; & | or `in`, when the word after it is source
    or `.` and has an argument; so `echo "a) . b"` and perl's `(defined $x) . "\\n"` are not), not from
    shell_commands, so a line whose quoting that scanner misreads (the tail of a multi-line string, then `; a) source x`) is
    still caught. source_lines refuses such a line when source_commands extracted nothing from it."""
    line = re.split(r"(?<!\S)#", line, maxsplit=1)[0]
    for marks, after_paren in ((COMMAND_MARK, False), (CASE_ARM_MARK, True)):
        for mark in marks.finditer(line):
            tokens, position = [], mark.end()
            while len(tokens) < 16:
                while position < len(line) and line[position] in " \t":
                    position += 1
                token = LINE_TOKEN.match(line, position)
                if not token:
                    break
                tokens.append(token.group())
                position = token.end()
                if after_paren and _literal(tokens[0]) not in ("source", "."):
                    break  # a `)` that does not open a source command: one token is all it costs
            words = _command_words(tokens)
            if len(words) > 1 and _literal(words[0]) in ("source", "."):
                return True
    return False


def _word_pieces(text, in_double=False):
    """text as [("lit", literal) | ("dyn", expansion)], quotes removed, adjacent pieces of one kind merged."""
    pieces, i, n = [], 0, len(text)

    def add(kind, value):
        if pieces and pieces[-1][0] == kind:
            pieces[-1] = (kind, pieces[-1][1] + value)
        else:
            pieces.append((kind, value))

    while i < n:
        char = text[i]
        if char == "\\":
            add("lit", text[i + 1:i + 2])
            i += 2
        elif char == "'" and not in_double:
            end = _span_single(text, i)
            add("lit", text[i + 1:end - 1])
            i = end
        elif char == '"' and not in_double:
            end = _span_double(text, i)
            for kind, value in _word_pieces(text[i + 1:max(end - 1, i + 1)], True):
                add(kind, value)
            i = end
        elif text.startswith("$(", i):
            end = _span_paren(text, i)
            add("dyn", text[i:end])
            i = end
        elif text.startswith("${", i):
            end = _span_brace(text, i)
            add("dyn", text[i:end])
            i = end
        elif char == "`":
            end = _span_backtick(text, i)
            add("dyn", text[i:end])
            i = end
        elif PLAIN_EXPANSION.match(text, i):
            end = PLAIN_EXPANSION.match(text, i).end()
            add("dyn", text[i:end])
            i = end
        else:
            add("lit", char)
            i += 1
    return pieces


def source_target(argument):
    """(tail, None) for a sourced path this parser can resolve, else (None, reason).

    Resolvable: one dynamic anchor (SOURCE_ANCHOR) followed by one literal `/tail` (quoted or not, `$D/x`, "$D"/x,
    "$D//x"), or a literal relative path with no expansion (`./x.sh`, `lib/x.sh`). Everything else is refused with its
    reason: an empty word, a lone variable (`"$f"`), an expansion in the tail, an absolute or `~` path, `$` inside single
    quotes (never expanded), a head that is not a plain variable or exactly `$(dirname WORD)` / `$(cd DIR && pwd)` (or
    their backtick forms; see SOURCE_ANCHOR).
    """
    pieces = _word_pieces(argument)
    if not pieces:
        return None, "empty argument"
    if any(kind == "lit" and re.search(r"[$`]", value) for kind, value in pieces):
        return None, "a literal $ or backtick (single quotes do not expand)"
    kind, head = pieces[0]
    if kind == "dyn":
        if not SOURCE_ANCHOR.match(head):
            return None, f"head {head} is not a variable, ${{VAR...}}, $(dirname WORD) or $(cd DIR && pwd)"
        if len(pieces) != 2 or pieces[1][0] != "lit" or not pieces[1][1].startswith("/"):
            return None, "the head is not followed by exactly one literal /path"
        tail = pieces[1][1].lstrip("/")
        return (tail, None) if tail else (None, "empty tail")
    if len(pieces) == 1:
        if head.startswith(("/", "~")):
            return None, "absolute or ~ path"
        return head, None
    return None, "a literal followed by an expansion"


def read_script(path):
    """Text of path, decoded with errors="replace": a non-UTF-8 byte never raises, it is read as U+FFFD."""
    return Path(path).read_bytes().decode("utf-8", errors="replace")


APPEND_WORD = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\+=", re.S)


def variable_facts(text):
    """(assignments, code_variables) for every variable that text assigns.

    assignments is {name: [(kind, value)]}: kind "=" with the raw value word for NAME=value (also behind local, export,
    readonly, declare and a command prefix), kind "changed" with no value for NAME+=, `printf -v NAME` and `read NAME`.
    code_variables is {name: [source arguments]} for every NAME=value whose value, read as shell code, holds a source command
    (see source_commands). Both are read from the whole file, in any order: a variable that is assigned again anywhere is
    not the value of its first assignment."""
    assignments, code_variables = {}, {}
    for command in shell_commands(text):
        for word in command:
            assigned = ASSIGNMENT_WORD.match(word)
            appended = APPEND_WORD.match(word)
            if assigned:
                name, value = word[:assigned.end() - 1], word[assigned.end():]
                assignments.setdefault(name, []).append(("=", value))
                arguments = source_commands(_unquote(value), 1)
                if arguments:
                    code_variables.setdefault(name, []).extend(arguments)
            elif appended:
                assignments.setdefault(appended.group(1), []).append(("changed", None))
        words = _command_words(command)
        head = _literal(words[0]) if words else None
        names = []
        if head == "printf":
            names = [_literal(word) for previous, word in zip(words[1:], words[2:]) if _literal(previous) == "-v"]
        elif head == "read":
            index = 1
            while index < len(words):
                redirect = REDIRECTION.match(words[index])
                if redirect:  # `< file`, `<<<"$x"`: the next word is the target when the operator stands alone
                    index += 1 if redirect.group(1) else 2
                    continue
                names.append(_literal(words[index]))
                index += 1
        for name in names:
            if name and IDENTIFIER.match(name):
                assignments.setdefault(name, []).append(("changed", None))
    return assignments, code_variables


def _is_ancestor_path(suffix):
    """True when the literal path suffix only climbs (`/..`, `/../..`, `/.`): the directory is the script directory or one
    of its ancestors, not a directory below or beside it."""
    normal = os.path.normpath(suffix.lstrip("/") or ".")
    return normal == "." or all(part == ".." for part in normal.split("/"))


def head_variable_anchor(name, assignments):
    """("script", None), ("unknown", None) or (None, reason) for the variable name at the head of a sourced path.

    "script": the variable's one value is exactly `$(dirname WORD)` or `$(cd "$(dirname WORD)" && pwd)`, so its directory is
    the script directory and the tail is tried there only. "unknown": no assignment in the file, or one that is not read (a
    path of `$(cd "$(dirname "$0")/../.." && pwd)` climbs to an ancestor; a literal, `$HOME`, `${X:-y}`): the tail is tried
    against the script directory and ROOT. A reason refuses the line: the variable is assigned again (NAME= with another
    value, NAME+=, printf -v NAME, read NAME), so its value at the source line is not its first value, or it is assigned a
    directory below or beside the script directory (`D="$(dirname "$0")/sub"`, `D=$(cd "$(dirname "$0")/sub" && pwd)`),
    or its value mentions dirname or ${0%/*} without matching a read shape, where the tail could be tried against the wrong
    directory."""
    events = assignments.get(name, [])
    if not events:
        return "unknown", None
    if any(kind != "=" for kind, _ in events) or len({value for _, value in events}) > 1:
        return None, (f"{name} is reassigned (NAME=, NAME+=, printf -v NAME or read NAME), so its value at the source line "
                      "is unknown and the tail cannot be tried against the script directory or ROOT")
    value = events[0][1]
    pieces = _word_pieces(value)
    if len(pieces) == 1 and pieces[0][0] == "dyn" and SUBSTITUTION_ANCHOR.match(pieces[0][1]):
        return "script", None
    suffix = None
    if pieces and pieces[0][0] == "dyn" and SUBSTITUTION_ANCHOR.match(pieces[0][1]):
        if any(kind == "dyn" for kind, _ in pieces[1:]):  # `/$SUB`, `/${SUB}`, `/$(echo sub)`, `/sub$N`: a path no one can read
            return None, (f"{name} is assigned {value}, the script directory followed by an expansion (a directory the scanner "
                          "cannot read), so the tail cannot be tried against the script directory or ROOT")
        suffix = "".join(text for _, text in pieces[1:])
    elif len(pieces) == 1 and pieces[0][0] == "dyn" and SUBSTITUTION_DYNAMIC_SUFFIX.match(pieces[0][1]):
        return None, (f"{name} is assigned {value}, the script directory followed by an expansion (a directory the scanner "
                      "cannot read), so the tail cannot be tried against the script directory or ROOT")
    elif len(pieces) == 1 and pieces[0][0] == "dyn" and SUBSTITUTION_WITH_SUFFIX.match(pieces[0][1]):
        suffix = SUBSTITUTION_WITH_SUFFIX.match(pieces[0][1]).group("suffix")
    if suffix is None and ("dirname" in value or "${0%/*}" in value):
        return None, (f"{name} is assigned {value}, not a supported script-directory shape, so the tail cannot be tried "
                      "against the script directory or ROOT")
    if suffix is not None and suffix.strip("/") and not _is_ancestor_path(suffix):
        where = "beside" if os.path.normpath(suffix.lstrip("/")).startswith("..") else "below"
        return None, (f"{name} is assigned {value}, a directory {where} the script directory (a subdirectory or sibling, not "
                      "the script directory), so the tail cannot be tried against the script directory or ROOT")
    return "unknown", None


def resolved_name(name):
    """The repository-relative name of the file that ROOT/name resolves to, symlinks followed, or None when it resolves
    outside ROOT (or no file exists)."""
    real, root = (ROOT / name).resolve(), ROOT.resolve()
    return str(real.relative_to(root)) if root in real.parents else None


def source_lines(script):
    """(line, files, reason) for every source / . command in the file ROOT/script, read from the ROOT copy.

    line is the stripped logical line (a backslash continuation is removed, as bash does: it joins with nothing). files are
    the repository-relative existing files (is_file(), tracked or not; a symlink counts under its own name, and only when it
    resolves inside ROOT) the path resolves to, and reason is None; or files is empty and reason says why the path is refused:
    source_target refuses its shape, it is no file, it resolves through a symlink to a file outside ROOT, it is a file under
    both the script directory and ROOT (two different files: ambiguous), its head variable is assigned again or assigned a
    directory below or beside the script directory, its assigned directory has an unsupported shape
    (head_variable_anchor), or the line holds a source command the scanner
    could not extract (hidden_source, the backstop). A head that is exactly `$(dirname WORD)` or `$(cd "$(dirname WORD)" &&
    pwd)`, or a variable that is only ever assigned that, is the script directory: the tail is tried there and nowhere else.
    A line with a source command is never left out. Known limits: `%/*` heads beyond $0, ${D:=...} assignments, zsh ${0:h}
    and ${0:A:h}, and directory indirection can still fall back to unknown anchors. Correct ancestor shapes outside the
    read forms (cd -P, cd with a semicolon, a quote before /.., and ${0%/*}/..) can be refused loudly.
    """
    entries = []
    text = read_script(ROOT / script)
    script_directory = (ROOT / script).parent
    assignments, code_variables = variable_facts(text)
    for line in re.sub(r"\\\r?\n", "", text).splitlines():
        arguments = source_commands(line, 0, code_variables)
        if not arguments and hidden_source(line):
            entries.append((line.strip(), [], "a source or . command the scanner could not extract (an unbalanced quote or a "
                                             "prefix it does not know)"))
        for argument in arguments:
            tail, reason = source_target(argument)
            anchors = (script_directory, ROOT)
            if tail is not None:
                kind, head = _word_pieces(argument)[0]
                if kind == "dyn" and SUBSTITUTION_ANCHOR.match(head):
                    anchors = (script_directory,)
                else:
                    variable = re.match(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)", head)
                    if variable:
                        anchor, why = head_variable_anchor(variable.group(1), assignments)
                        if anchor is None:
                            tail, reason = None, why
                        elif anchor == "script":
                            anchors = (script_directory,)
            files, outside = [], []
            if tail is not None:
                for anchor in anchors:
                    candidate = Path(os.path.normpath(anchor / tail))
                    name = str(candidate.relative_to(ROOT)) if ROOT in candidate.parents else None
                    if name and candidate.is_file() and name not in files + outside:
                        (files if resolved_name(name) else outside).append(name)
                if not files and outside:
                    reason = f"{outside[0]} is a symlink to a file outside the repository"
                elif not files:
                    reason = f"{tail} is no file under the script's directory or the repository root"
                elif len(files) > 1:
                    reason = (f"{tail} is a file under the script's directory ({files[0]}) and under the repository root "
                              f"as {files[1]}: ambiguous")
                    files = []
            entries.append((line.strip(), files, reason))
    return entries


def sourced_files(script):
    """Repository-relative files that the file ROOT/script sources, whatever their suffix.

    Read from the ROOT copy with errors="replace". A file counts when is_file() holds under ROOT, tracked or not; the
    path is tried against the script's directory, then ROOT (so a `$D/..` anchor is script-relative or root-relative).
    A source line with no such file (a runtime path, a shape source_target refuses, an ambiguous tail, a head variable
    assigned a subdirectory) contributes nothing here: source_lines reports it, and the completeness test refuses it
    unless it is allowlisted with a reason. A file git does not track is returned here (it is on disk); the completeness
    test refuses a line that resolves to one.
    """
    found = []
    for _, files, _ in source_lines(script):
        found += [name for name in files if name not in found]
    return found


def missing_sources(tree, scripts):
    """(script, sourced file) pairs where script, which exists in tree, sources a file that tree lacks.

    The sources are read from the ROOT copy of script (sourced_files), not from tree/script: a script edited or
    stubbed inside tree is checked against the sources of the original.
    """
    return [(script, name) for script in scripts if (tree / script).is_file()
            for name in sourced_files(script) if not (tree / name).is_file()]


# Source lines of tracked shell scripts that source_lines cannot resolve to a file, each with the reason it is safe. The
# completeness test (test_every_tracked_shell_script_source_line_resolves_or_is_allowlisted) refuses any other such line
# and any entry here that no longer matches a line. Key: (repository-relative script, stripped logical line).
SOURCE_ALLOWLIST = {
    ("Tools/lab/cutover-rehearsal.sh", 'source "$WGEX_CUTOVER_REMEMBER"'):
        "runtime fixture: the path is a file the script itself writes into its scratch directory (cutover-rehearsal.sh:134-142)",
    ("Tools/lab/cutover-rehearsal.sh", 'source "$WGEX_CUTOVER_ASSERT_CONFIRMED"'):
        "runtime fixture: the path is a file the script itself writes into its scratch directory (cutover-rehearsal.sh:134-142)",
    ("Tools/lab/cutover-rehearsal.sh", 'source "$WGEX_CUTOVER_ASSERT_REVERTED"'):
        "runtime fixture: the path is a file the script itself writes into its scratch directory (cutover-rehearsal.sh:134-142)",
    ("Tools/lab/tart/capture/start-capture.sh", 'source "$(dirname "$0")/guard.sh"'):
        "guest-staged: guard.sh sits next to the capture scripts only after guest/provision.sh:55 copies it from guest/guard.sh",
    ("Tools/lab/tart/capture/stop-capture.sh", 'source "$(dirname "$0")/guard.sh"'):
        "guest-staged: guard.sh sits next to the capture scripts only after guest/provision.sh:55 copies it from guest/guard.sh",
    ("Tools/lab/m08/guest/m08-actions.sh", 'source "$(dirname "$0")/guard.sh"'):
        "guest-staged: guard.sh sits next to the M08 guest scripts only after m08/m08-rows.py:61 GUEST_HELPERS stages it from tart/guest/guard.sh",
    ("Tools/lab/m08/guest/px-spike.sh", 'source "$(dirname "$0")/guard.sh"'):
        "guest-staged: px-spike.py stage() calls the M08 stage, which copies tart/guest/guard.sh beside px-spike.sh (m08/m08-rows.py:61)",
    ("Tools/lab/corpus/guest-corpus.sh", 'source "$(dirname "$0")/guard.sh"'):
        "guest-staged: guard.sh sits next to guest-corpus.sh only after verdict-live.py:2488 stages it from tart/guest/guard.sh and :1219 copies this script beside it",
    ("Tools/lab/update/guest-update.sh", 'source "$(dirname "$0")/guard.sh"'):
        "guest-staged: guard.sh sits next to guest-update.sh only after verdict-live.py:2488 stages it from tart/guest/guard.sh and :1145 copies this script beside it",
    ("Tools/lab/tart/tests/run.sh",
     "run_refuse 'guest guard refuses absent hypervisor' 'macOS 26 or 27 VM required' bash -c 'source \"$1\"; guest_guard' _ "
     "\"$base/guest/guard.sh\""):
        "wrapped: the child shell's $1 is \"$base/guest/guard.sh\", the tracked guest/guard.sh, passed as an argument on this line",
    ("Tools/lint/tests/fail-closed/run.sh", 'source "$1/Tools/lint/lib.sh"'):
        "heredoc child lib-case.sh: its $1 is the suite's $root, the real checkout root (fail-closed/run.sh:9, :107), so it sources the tracked Tools/lint/lib.sh",
    ("Tools/lint/check-entitlements.sh", 'if source != "-":'):
        "not shell: a line of the Python program that python3 -c runs (expected_entitlements); `source` is a Python variable",
}


def tracked_files():
    """Repository-relative names of every file `git ls-files` lists under ROOT (an intent-to-add file included)."""
    listing = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True, timeout=60)
    if listing.returncode != 0:
        raise RuntimeError("git ls-files failed: " + listing.stderr.decode("utf-8", errors="replace"))
    return {name for name in listing.stdout.decode("utf-8", errors="replace").split("\0") if name}


def source_completeness(tracked, allowlist):
    """(problems, walk, resolved) for the completeness walk under ROOT.

    The walk is every tracked shell script (a shell suffix or a shell shebang) plus, transitively, every tracked file those
    scripts source, whatever its suffix. problems (strings) lists: a source / . line that resolves to no file, or to a file
    that is not in tracked (untracked or git-ignored: present on this disk, absent from a clean checkout), or to a tracked
    symlink whose target (resolved, symlinks followed) is not tracked or lies outside ROOT, and is not in
    allowlist; an allowlist entry that matches no line; an allowlist reason under six words. walk is the set of names
    walked and resolved the number of lines that resolved to tracked files.
    """
    walk = {name for name in tracked
            if (ROOT / name).is_file() and not (ROOT / name).is_symlink() and is_shell_script(ROOT / name)}
    queue = sorted(walk)
    while queue:
        for name in sourced_files(queue.pop()):
            if name in tracked and name not in walk:
                walk.add(name)
                queue.append(name)
    problems, used, resolved = [], set(), 0
    for name in sorted(walk):
        for line, files, reason in source_lines(name):
            untracked = [file for file in files if file not in tracked]
            links = [f"{file}, a symlink to {resolved_name(file)}" for file in files
                     if file in tracked and resolved_name(file) not in tracked]
            if files and not untracked and not links:
                resolved += 1
            elif (name, line) in allowlist:
                used.add((name, line))
            elif untracked:
                problems.append(f"{name}: {line}: sources an untracked file {', '.join(untracked)}")
            elif links:
                problems.append(f"{name}: {line}: sources {', '.join(links)}, which is untracked")
            else:
                problems.append(f"{name}: {line}: {reason}")
    problems += [f"allowlist entry matches no source line: {key}" for key in sorted(set(allowlist) - used)]
    problems += [f"allowlist reason under six words: {key}" for key, reason in sorted(allowlist.items())
                 if len(reason.split()) < 6]
    return problems, walk, resolved


# The quoted argument of `eval`, of `bash|sh|zsh|dash|ksh [-opts] -c [--]` (the shell bare or by absolute path; options with
# an argument such as `-o pipefail` or `-euo pipefail`; the argument quoted "...", '...' or $'...') and the here-string of a
# shell (`bash <<<'...'`) is code that runs.
SHELL_INVOCATION = (r"""(?:/[^\s"'$;&|()]*/)?(?:bash|zsh|dash|ksh|sh)"""
                    r"""(?:\s+(?:[-+][A-Za-z]+(?:\s+[A-Za-z_][A-Za-z0-9_]*)?|--[A-Za-z][A-Za-z-]*))*?""")
QUOTED_CODE = r"""("(?:[^"\\]|\\.)*"|\$'(?:[^'\\]|\\.)*'|'[^']*')"""
EMBEDDED_PREFIX = (r"(?:eval\s+|" + SHELL_INVOCATION + r"\s+-[A-Za-z]*c(?:\s+(?:--|[-+][A-Za-z]+))*\s+|"
                   + SHELL_INVOCATION + r"\s*<<<\s*)")
EMBEDDED_CODE = re.compile(r"(?:^|(?<=[\s;&|(`{]))" + EMBEDDED_PREFIX + QUOTED_CODE)
# A call is `xcodebuild` by bare name or behind a path: absolute (/usr/bin/xcodebuild), led by a variable
# (${DEV}/usr/bin/xcodebuild) or by a command substitution ($(xcode-select -p)/usr/bin/xcodebuild); `\s` before it covers
# env/xcrun/command prefixes and the repo wrappers that exec their arguments (lab_mutate, with_deadline, check, ...). The path
# cannot contain `=`, so `XCB=/usr/bin/xcodebuild` is a holder, not a call. A path led by a variable or a substitution counts at
# every position (an unknown position fails loudly, it does not pass silently), except as an operand of a named path consumer
# (PATH_CONSUMER: `mkdir -p "$LOGS/xcodebuild"`, `rm -rf "${BUILD}/xcodebuild"`, `[[ -x "$DEV/usr/bin/xcodebuild" ]]`), as the
# target of a redirection and in an assignment; those positions do not invoke the path (substitutions within it still run).
# A variable name takes all of its characters (the lookahead), so a run of long names such as `$ABC$DEF...` has one way to match and cannot
# backtrack exponentially; the alternatives of a path start with different characters and `!` is not a boundary, so no
# position of a long word starts a pass over the rest of it.
_XCODEBUILD_PATH_HEAD = r"""\$\{[^}\s]*\}|\$[A-Za-z_][A-Za-z0-9_]*(?![A-Za-z0-9_])|\$\([^()]*\)"""
_XCODEBUILD_PATH_CHAR = r"""[^\s"'`;&|()=<>${}]"""
XCODEBUILD_PATH = r"(?:(?:" + _XCODEBUILD_PATH_HEAD + "|" + _XCODEBUILD_PATH_CHAR + r")*/)?"
# The same path with a backtick substitution as its head, only for taking the quotes off a quoted path: the backtick is a
# boundary of the call patterns, so a backtick alternative there would start a pass at every backtick of a run of them. After
# the quotes are off, the part after the closing backtick is an absolute path the plain pattern counts.
XCODEBUILD_QUOTED_PATH = r"(?:(?:" + _XCODEBUILD_PATH_HEAD + r"|`[^`]*`|" + _XCODEBUILD_PATH_CHAR + r")*/)?"
XCODEBUILD_PLAIN_PATH = r"(?:" + _XCODEBUILD_PATH_CHAR + r"*/)?"
XCODEBUILD_END = r"""xcodebuild(?=\s|$|[;&|)"'])"""
XCODEBUILD_BOUNDARY = r"(?:^|[\s(;&|`{])"
# Where a command starts inside a segment (a segment is already split at ; && || |): the segment start, after ( ` or {, after
# a `!` that is a word of its own, after then/do/else/elif/if/while/until, and after the prefixes env, exec, command, time,
# builtin, nohup and sudo (with their options), VAR=x assignments and the quoted-code openers of eval and `bash -c`.
COMMAND_START = (r"(?:^|[(`{]|(?<!\S)!(?=\s))\s*(?:(?:then|do|else|elif|if|while|until)\s+)*"
                 r"(?:(?:env|exec|command|time|builtin|nohup|sudo)\s+(?:-[A-Za-z]+\s+)*|[A-Za-z_][A-Za-z0-9_]*=\S*\s+|"
                 + EMBEDDED_PREFIX + r")*")
# The commands whose operands are paths they read, create, remove or test and never run: the operand of one is not a call.
PATH_CONSUMER = re.compile(COMMAND_START + r"(?:mkdir|rm|ls|cp|mv|tee|touch|chmod|stat|cat|readlink|test|\[\[|\[)(?=\s|$)")
# A redirection operator just before a word: the word is a file, not a command.
REDIRECT_TARGET = re.compile(r"(?:[0-9]*|&)(?:>>?|<|>\||>&|&>>?)\s*\Z")
XCODEBUILD_PLAIN_CALL = re.compile(XCODEBUILD_BOUNDARY + XCODEBUILD_PLAIN_PATH + XCODEBUILD_END)
XCODEBUILD_PATH_CALL = re.compile(XCODEBUILD_BOUNDARY + XCODEBUILD_PATH + XCODEBUILD_END)
XCODEBUILD_HOLDER = re.compile(r"""(?:^|[\s(;&|`{])([A-Za-z_][A-Za-z0-9_]*)=["']?""" + XCODEBUILD_PATH + XCODEBUILD_END)
XCODEBUILD_PLAIN_HOLDER = re.compile(
    r"""(?:^|[\s(;&|`{])([A-Za-z_][A-Za-z0-9_]*)=["']?""" + XCODEBUILD_PLAIN_PATH + XCODEBUILD_END)
# ${XCB:-xcodebuild}, ${XCB=/usr/bin/xcodebuild}: a default that is xcodebuild is read as xcodebuild itself.
XCODEBUILD_DEFAULT = re.compile(r"""\$\{[A-Za-z_][A-Za-z0-9_]*:?[-=](?:[^\s"'`;&|()=<>}]*/)?xcodebuild\}""")
MESSAGE_COMMAND = re.compile(r"\s*(?:echo|printf|lab_die)(?:\s|$)")
XCODEBUILD_READ_ONLY = re.compile(r"(?:^|\s)(?:-version|-list|-showBuildSettings)(?=[\s)\"';&|]|$)")
SEGMENT_SEPARATOR = re.compile(r"(\|\||&&|;|\|)")
# File descriptors other than stdout (2>&1, 2>file, 3>&-) are not what a pipe carries.
OTHER_FD_REDIRECT = re.compile(r"(?:^|(?<=[\s;&|(]))(?:[02-9]|[1-9][0-9]+)>>?(?:&[0-9-]*|\s*[^\s;&|()<>]*)")
STDOUT_REDIRECT = re.compile(r"(?:&>>?|>>?&?|>\|)\s*([^\s;&|()<>]*)")


def strip_quoted(text):
    """text with the content of quoted strings removed (so a `;` or `|` inside a message cannot split a command),
    keeping $(...) and backtick substitutions inside double quotes, whose commands do run."""
    out, i, n = [], 0, len(text)
    while i < n:
        char = text[i]
        if char == "\\":
            out.append(text[i:i + 2])
            i += 2
        elif char == "'":
            end = text.find("'", i + 1)
            out.append("''")
            i = n if end < 0 else end + 1
        elif char == '"':
            out.append('"')
            i += 1
            while i < n and text[i] != '"':
                if text[i] == "\\":
                    i += 2
                elif text.startswith("$(", i):
                    depth, j = 1, i + 2
                    while j < n and depth:
                        depth += (text[j] == "(") - (text[j] == ")")
                        j += 1
                    out.append(text[i:j])
                    i = j
                elif text[i] == "`":
                    j = text.find("`", i + 1)
                    j = n if j < 0 else j + 1
                    out.append(text[i:j])
                    i = j
                else:
                    i += 1
            out.append('"')
            i += 1
        else:
            out.append(char)
            i += 1
    return "".join(out)


def expand_embedded_code(line):
    """line with the quoted argument of eval / bash|sh|zsh -c, or the here-string of a shell, replaced by its content, so
    the code it runs is scanned as code (segments, pipes and redirections included) instead of being dropped as a quoted
    string. $'...' is read with \\n as `;` and \\' \\\\ \\" unescaped; other escapes (\\x78) are not decoded."""
    def inline(match):
        quoted = match.group(1)
        if quoted[0] == '"':
            code = re.sub(r'\\(["\\$`])', r"\1", quoted[1:-1])
        elif quoted[0] == "$":
            code = re.sub(r"\\(['\\\"])", r"\1", quoted[2:-1].replace("\\n", ";"))
        else:
            code = quoted[1:-1]
        prefix = match.group(0)[:match.start(1) - match.start()]
        return prefix + (" " if prefix.endswith("<<<") else "") + code
    for _ in range(4):  # nested quoted code
        expanded = EMBEDDED_CODE.sub(inline, line)
        if expanded == line:
            break
        line = expanded
    return line


def redirects_stdout(segment):
    """True when the segment sends stdout anywhere but /dev/null (a file, fd 2, a process), which starves a pipe."""
    segment = OTHER_FD_REDIRECT.sub(" ", segment)
    return any(match.group(1) != "/dev/null" for match in STDOUT_REDIRECT.finditer(segment))


def path_operand_test(segment):
    """A function that says whether the word of segment starting at an index is a path and not a command: the operand of a
    named path consumer (PATH_CONSUMER) in the innermost command ($(...), (...) or backticks around the word start a command of
    their own) or the target of a redirection. Words are asked for in increasing order, so the segment is scanned once."""
    stack, scanned, consumers = [], 0, {}

    def operand(start):
        nonlocal scanned
        for index in range(scanned, start):
            char = segment[index]
            if char == "(":
                stack.append(("(", index + 1))
            elif char == ")":
                if stack and stack[-1][0] == "(":
                    stack.pop()
            elif char == "`":
                if stack and stack[-1][0] == "`":
                    stack.pop()
                else:
                    stack.append(("`", index + 1))
        scanned = max(scanned, start)
        if REDIRECT_TARGET.search(segment, max(0, start - 16), start):
            return True
        opener = stack[-1][1] if stack else 0
        if opener not in consumers:  # the first 300 characters hold any prefix; a longer one counts as a call
            consumers[opener] = PATH_CONSUMER.match(segment[opener:opener + 300])
        found = consumers[opener]
        return bool(found) and opener + found.end() <= start
    return operand


def xcodebuild_calls_without_filter(text):
    """(line number, command) for each xcodebuild call not piped straight into xcodebuild_filter and not allowlisted.

    A call is xcodebuild by bare name, a path (absolute, led by a variable: "${DEV}/usr/bin/xcodebuild", or led by a
    command substitution: "$(xcode-select -p)/usr/bin/xcodebuild"), quoted name, a default (${XCB:-xcodebuild}), or through a
    variable assigned from any of those (`XCB=xcodebuild`, `XCB=${XCB:-xcodebuild}`, `XCB="${DEV}/usr/bin/xcodebuild"`, then
    $XCB, ${XCB} or "$XCB"). A path led by a variable or a substitution, and a variable assigned one, count at every position
    (after env, exec, command, a repo wrapper such as lab_mutate or with_deadline, xcrun, xargs, in a case arm, behind a
    redirection), so an unknown position fails loudly; they do not count as the operand of mkdir, rm, ls, cp, mv, tee, touch,
    chmod, stat, cat, readlink, test, [ or [[ (`mkdir -p "$LOGS/xcodebuild"`, `[[ -x "$DEV/usr/bin/xcodebuild" ]]`), as the
    target of a redirection, or in an assignment (path_operand_test); commands inside substitutions there still count.
    Each logical line (backslash continuations and a trailing pipe join the next line; comments and quoted strings are ignored)
    is scanned in separate substitution scopes, then split into segments on ; && || and | within each scope. Per segment:
    echo/printf/lab_die messages are skipped; the allowlist (-version, -list and -showBuildSettings print no build
    log and the settings are never echoed; -create-xcframework only with its output sent to /dev/null) counts only
    when it is in the call's own segment; and the filter must be the very next segment after a single `|` with the
    call's stdout not redirected anywhere but /dev/null. The quoted argument of eval and of a shell -c (bare or absolute
    path, options with arguments, `--`, "...", '...' or $'...'), and the here-string of a shell, is scanned as
    code, and a message that contains $(...) or backticks is not skipped because the substitution runs.
    """
    logical_lines, logical, first = [], "", 0
    for number, raw in enumerate(text.splitlines(), 1):
        if not logical:
            first = number
            if raw.lstrip().startswith("#"):
                continue
        stripped = raw.rstrip()
        if stripped.endswith("\\") or (stripped.endswith("|") and not stripped.endswith("||")):
            logical += stripped.rstrip("\\") + " "
            continue
        logical_lines.append((first, logical + stripped))
        logical = ""
    prepared, originals = [], dict(logical_lines)
    for number, raw in logical_lines:
        scopes = [raw]
        for scope_index, line in enumerate(scopes):
            line = expand_embedded_code(line)
            line = XCODEBUILD_DEFAULT.sub("xcodebuild", line)  # ${XCB:-xcodebuild} build
            line = re.sub(r"""["'](""" + XCODEBUILD_QUOTED_PATH + r"""xcodebuild)["']""", r"\1", line)
            line = re.sub(r'"(\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)"', r"\1", line)  # "$XCB" build
            line = re.sub(r"(?:^|(?<=\s))#.*$", "", strip_quoted(line))
            if scope_index == 0:
                originals[number] = line
            # A substitution's separators and case closers belong to its own command scope. Scan that body separately,
            # leaving a harmless substitution in the surrounding path so assignment/operand checks still see the word.
            pieces, start = [], 0
            while True:
                opener = line.find("$(", start)
                if opener < 0:
                    pieces.append(line[start:])
                    break
                end = _span_paren(line, opener)
                scopes.append(line[opener + 2:end - 1])
                pieces.extend((line[start:opener], "$( : )"))
                start = end
            line = "".join(pieces)
            # Only a case-pattern closer opens a command after `)`; no substitution body remains in this scope.
            line = CASE_ARM_MARK.sub(lambda mark: mark.group() + " ", line)
            prepared.append((number, line))
    plain_holders = {name for _, line in prepared for name in XCODEBUILD_PLAIN_HOLDER.findall(line)}
    path_holders = {name for _, line in prepared for name in XCODEBUILD_HOLDER.findall(line)} - plain_holders

    def holder_calls(base, holders):  # $XCB, ${XCB}: a variable assigned a path to xcodebuild is the call itself
        if not holders:
            return base
        names = "|".join(sorted(holders))
        return re.compile(base.pattern + "|" + XCODEBUILD_BOUNDARY + r"\$(?:" + names + r"|\{(?:" + names + r")\})(?=\s|$|[;&|)])")

    plain_call = holder_calls(XCODEBUILD_PLAIN_CALL, plain_holders)
    path_call = holder_calls(XCODEBUILD_PATH_CALL, path_holders)
    problems = []
    for number, line in prepared:
        parts = SEGMENT_SEPARATOR.split(line)
        segments, separators = parts[0::2], parts[1::2]
        for index, segment in enumerate(segments):
            if MESSAGE_COMMAND.match(segment) and "$(" not in segment and "`" not in segment:
                continue
            matches = [(found, False) for found in plain_call.finditer(segment)]
            matches += [(found, True) for found in path_call.finditer(segment) if "$" in found.group()]
            matches.sort(key=lambda pair: pair[0].start())
            operand = path_operand_test(segment)
            for position, (found, led_by_variable) in enumerate(matches):
                # The match includes its boundary character: a ( or ` boundary opens a command of its own that the path is in
                # (`cat <("$DEV/usr/bin/xcodebuild" build)`), so the operand test is asked from the path, after the opener.
                if led_by_variable and operand(found.start() + (1 if found.group()[:1] in ("(", "`") else 0)):
                    continue
                rest = segment[found.end():matches[position + 1][0].start() if position + 1 < len(matches) else len(segment)]
                following = segments[index + 1] if index + 1 < len(segments) and separators[index] == "|" else ""
                if re.match(r"\s*xcodebuild_filter(?:\s|$|\))", following) and not redirects_stdout(segment):
                    continue
                if XCODEBUILD_READ_ONLY.search(rest):
                    continue
                if "-create-xcframework" in rest and ">/dev/null" in rest:
                    continue
                problems.append((number, line.strip()))
                break
            else:
                continue
            break
    return [(number, originals[number].strip()) for number in dict.fromkeys(number for number, _ in problems)]


def cleanup_canary_derived_data(path):
    """Bound cleanup when a host .DS_Store writer races xcodebuild's deep output tree."""
    for attempt in range(5):
        try:
            shutil.rmtree(path)
            return
        except FileNotFoundError:
            return
        except OSError:
            if attempt < 4:
                time.sleep(0.05)
    shutil.rmtree(path, ignore_errors=True)


class ToolingTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="wgex-tooling-", dir=os.environ["TMPDIR"],
                                                ignore_cleanup_errors=True)
        self.addCleanup(self.work.cleanup)
        self.work = Path(self.work.name)

    def test_canary_cleanup_retries_a_late_ds_store_write(self):
        temporary = tempfile.TemporaryDirectory(prefix="cleanup-race-", dir=self.work)
        self.addCleanup(shutil.rmtree, temporary.name, ignore_errors=True)
        logs = Path(temporary.name) / "Logs/Test"
        logs.mkdir(parents=True)
        original_rmdir = os.rmdir
        injected = False

        def late_write(path, *args, **kwargs):
            nonlocal injected
            if Path(path).name == "Test" and not injected:
                injected = True
                (logs / ".DS_Store").touch()
            return original_rmdir(path, *args, **kwargs)

        # Reproduce TemporaryDirectory's former teardown failure without timing a host writer.
        with patch.object(os, "rmdir", side_effect=late_write):
            with self.assertRaises(OSError) as raised:
                temporary.cleanup()
        self.assertEqual(raised.exception.errno, errno.ENOTEMPTY)
        self.assertTrue(injected)
        (logs / ".DS_Store").unlink()
        injected = False
        with patch.object(os, "rmdir", side_effect=late_write):
            cleanup_canary_derived_data(temporary.name)
        self.assertTrue(injected)
        self.assertFalse(Path(temporary.name).exists())

    def test_canary_cleanup_has_a_bounded_retry_budget(self):
        def busy(path, *, ignore_errors=False):
            if not ignore_errors:
                raise OSError(errno.ENOTEMPTY, "fixture late writer")

        with patch.object(shutil, "rmtree", side_effect=busy) as remove, patch.object(time, "sleep") as sleep:
            cleanup_canary_derived_data(self.work / "busy-canary-dd")
        self.assertEqual(remove.call_count, 6)
        self.assertEqual(remove.call_args.kwargs, {"ignore_errors": True})
        self.assertEqual(sleep.call_count, 4)
        self.assertTrue(all(call.args == (0.05,) for call in sleep.call_args_list))

    def test_swift_tests_drop_inherited_engine_leak_knobs(self):
        root = self.work / "engine-knobs"
        for name in ("lib.sh", "test.sh"):
            target = root / "Config/Scripts" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            self.copy_source(ROOT / "Config/Scripts" / name, target)
        library = root / "Config/Scripts/lib.sh"
        library.write_text(library.read_text() + '\nrequire_current_engine() { return 0; }\n')
        for package in ("WGEXCore", "WGEXEngine"):
            manifest = root / "Packages" / package / "Package.swift"
            manifest.parent.mkdir(parents=True)
            manifest.touch()
        tools = self.work / "bin"
        tools.mkdir()
        calls = self.work / "swift-calls"
        tool = tools / "swift"
        tool.write_text('#!/bin/bash\n'
                        'printf "%s\\n" "${WGEX_ENGINE_CYCLES-unset}|${WGEX_ENGINE_PROCESS_LIMITS-unset}|'
                        '${WGEX_ENGINE_LEAK_READY-unset}" >>"$WGEX_SWIFT_TEST_CALLS"\n'
                        '[[ "$1" == test ]]\n')
        tool.chmod(0o755)
        env = os.environ | {"PATH": f"{tools}:{os.environ['PATH']}", "WGEX_SWIFT_TEST_CALLS": str(calls),
                            "WGEX_BUILD_ROOT": str(self.work / "builds"),
                            "CLEAN_DEVELOPMENT_CACHE_ROOT": str(self.work / "cache"),
                            "WGEX_ENGINE_CYCLES": "0", "WGEX_ENGINE_PROCESS_LIMITS": "1",
                            "WGEX_ENGINE_LEAK_READY": "/fixture-ready"}
        for target, expected in (("WGEXEngine", ["unset|unset|unset"]),
                                 ("all", ["unset|unset|unset"] * 2), ("tsan", ["100|unset|unset"])):
            with self.subTest(target=target):
                calls.unlink(missing_ok=True)
                result = subprocess.run(["bash", str(root / "Config/Scripts/test.sh"), target], env=env,
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(calls.read_text().splitlines(), expected)

    def copy_source(self, source, target, _sourced=False):
        shutil.copy(source, target)
        if Path(source) == ROOT / "Config/Scripts/lib.sh":
            helper = ROOT / "Config/Scripts/build_root.py"
            shutil.copy(helper, Path(target).with_name(helper.name))
        # A copied shell script (a shell suffix or shebang) brings every file it sources (transitively, whatever the
        # suffix and encoding of that file) at the same tree-relative path; existing copies are never replaced. A source
        # line the parser cannot resolve brings nothing: test_every_tracked_shell_script_source_line_resolves_or_is_allowlisted
        # refuses such a line in the tracked scripts unless it is allowlisted with a reason.
        relative = Path(source).relative_to(ROOT) if ROOT in Path(source).parents else None
        if relative is None or not (_sourced or is_shell_script(source)) or not str(target).endswith(str(relative)):
            return
        tree = Path(str(target)[:-len(str(relative))])
        for name in sourced_files(relative):
            if not (tree / name).exists():
                (tree / name).parent.mkdir(parents=True, exist_ok=True)
                self.copy_source(ROOT / name, tree / name, True)

    def shell(self, script, env=None):
        return subprocess.run(["bash", "-eu", "-c", script], env=env, text=True, capture_output=True)

    def module(self, path):
        spec = importlib.util.spec_from_file_location("merge_fixture", ROOT / path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_python_and_shell_build_roots_agree(self):
        helper = self.module("Config/Scripts/build_root.py")
        root = self.work / "renamed-tree"
        library = root / "Config/Scripts/lib.sh"
        library.parent.mkdir(parents=True)
        self.copy_source(ROOT / "Config/Scripts/lib.sh", library)
        base_env = {key: value for key, value in os.environ.items()
                    if key not in ("WGEX_BUILD_ROOT", "CLEAN_DEV_BUILDS")}
        base_env["TMPDIR"] = str(self.work)
        for overrides in ({}, {"CLEAN_DEV_BUILDS": str(self.work / "session")},
                          {"WGEX_BUILD_ROOT": str(self.work / "override")}):
            env = base_env | overrides
            shell = self.shell(f'source "{library}"; build_root', env)
            self.assertEqual(shell.returncode, 0, shell.stderr)
            self.assertEqual(str(helper.build_root(root, env)), shell.stdout)
        for base in ("relative", str(root), str(root.parent)):
            with self.assertRaises(ValueError):
                helper.build_root(root, base_env | {"WGEX_BUILD_ROOT": base})

    def test_lab_python_paths_and_helper_publication_use_tree_root(self):
        state = self.module("Tools/lab/state.py")
        verdict = self.module("Tools/lab/verdict-run.py")
        live = self.module("Tools/lab/verdict-live.py")
        base = self.work / "override"
        expected = base / ROOT.name
        with patch.dict(os.environ, {"WGEX_BUILD_ROOT": str(base)}):
            self.assertEqual(verdict.report_root(True, None), expected / "lab-verdict-replay")
            self.assertEqual(verdict.report_root(False, None), expected / "lab-verdict-failures")
            session = live.Session("fixture", {})
            self.assertEqual(session.output.parent.parent, expected / "lab-captures")
        binaries = {name: self.work / "state/helpers" / name for name in ("leakprobe", "foreign-utun")}
        for path in (expected / "spm/leakprobe/debug/leakprobe", expected / "lab-tools/foreign-utun"):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"guest helper fixture")
        with patch.object(state, "state_directory", return_value=self.work / "state"), \
                patch.object(state, "guest_binaries", return_value=binaries):
            state.publish_helpers(expected)
        self.assertTrue(all(path.read_bytes() == b"guest helper fixture" for path in binaries.values()))

    def test_tools_dispatch_uses_guest_binary_runner(self):
        root = self.work / "tools-dispatch"
        library = root / "Config/Scripts/lib.sh"
        library.parent.mkdir(parents=True)
        for name in ("lib.sh", "test.sh"):
            self.copy_source(ROOT / "Config/Scripts" / name, library.with_name(name))
        runner = root / "Tools/lab/tests/run.sh"
        runner.parent.mkdir(parents=True)
        runner.write_text('#!/bin/bash\nexit 73\n')
        result = subprocess.run(["bash", str(library.with_name("test.sh")), "tools"],
                                env=os.environ | {"WGEX_BUILD_ROOT": str(self.work / "builds"),
                                                  "CLEAN_DEVELOPMENT_CACHE_ROOT": str(self.work / "cache")},
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 73, result.stderr)
        commands = subprocess.run(["just", "--dry-run", "lab-scripts-test"], cwd=ROOT,
                                  capture_output=True, text=True)
        self.assertEqual(commands.returncode, 0, commands.stderr)
        self.assertIn("bash Tools/lab/tests/run.sh", commands.stdout + commands.stderr)
        self.assertNotIn("unittest discover", commands.stdout + commands.stderr)

    def test_configuration_digest_exceptions_are_exact(self):
        fixtures = ROOT / "Tools/lab/tests/fixtures"
        names = ("blocked", "captiveWindow", "dns-protected", "protected", "unprotected")
        records = "".join(f"{fixtures / (name + '.json')}\0Tools/lab/tests/fixtures/{name}.json\0" for name in names)
        command = ["python3", "-I", str(ROOT / "Tools/lint/secret-shapes.py")]
        result = subprocess.run(command, input=records, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        source = fixtures / "blocked.json"
        changed = self.work / "changed.json"
        content = source.read_text()
        original = re.search(r'"configurationSHA256": "([0-9a-f]+)"', content)[1]
        changed.write_text(content.replace(original, hashlib.sha256(b"unreviewed digest").hexdigest()))
        for path, relative in ((changed, "Tools/lab/tests/fixtures/blocked.json"),
                               (source, "Tools/lab/tests/fixtures/other.json")):
            result = subprocess.run(command, input=f"{path}\0{relative}\0", capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)

    def test_digest_outside_checkout_reports_discovery_failure(self):
        root = self.work / "not-a-repository"
        root.mkdir()
        result = self.digest(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source discovery failed", result.stderr)
        self.assertNotIn("run 'just engine'", result.stderr)

    def test_gate_timing_preserves_command_result(self):
        for code in (0, 7):
            result = subprocess.run(["python3", "-I", str(ROOT / "Config/Scripts/timed-step.py"),
                                     "fixture", "python3", "-c", f'print("fixture output"); raise SystemExit({code})'],
                                     capture_output=True, text=True)
            self.assertEqual(result.returncode, code, result.stderr)
            self.assertEqual(result.stdout, "fixture output\n")
            self.assertRegex(result.stderr, rf"gate-step: fixture exit={code} seconds=\d+\.\d{{3}}")

    GATE_STEP = ["python3", "-I", str(ROOT / "Config/Scripts/timed-step.py")]
    PRINT_ENVIRONMENT = 'import json, os; print(json.dumps(sorted(os.environ)))'
    PRINT_ENVIRONMENT_VALUES = 'import json, os; print(json.dumps(dict(os.environ)))'

    # What a caller can export that is not on the allowlist, beyond the corpus: build settings and test-runner
    # pass-throughs xcodebuild reads (M1-10x FIX3 RISKS 1 and 2), toolchain selectors, proxies, a name nothing has heard of.
    # Values are canaries, never printed. Not DYLD_*: dyld would stop this suite's own Homebrew python3 on a bad
    # DYLD_INSERT_LIBRARIES (FIX3: /usr/bin/env, a platform binary, drops them first), so the allowlist test checks those names
    # on the function only.
    UNLISTED = {"OTHER_SWIFT_FLAGS": "-wgex-canary-unknown-flag", "TEST_RUNNER_WGEXCANARY": "1", "FOO_BAR": "canary-value-not-printed",
                "DEVELOPER_DIR": "/canary-dev-dir", "TOOLCHAINS": "canary", "SDKROOT": "/canary-sdk", "GOFLAGS": "-mod=mod",
                "GOENV": "/canary-goenv", "GOPATH": "/canary-gopath", "GOCACHE": "/canary-gocache",
                "SSH_AUTH_SOCK": "/canary-sock",
                "HTTPS_PROXY": "http://canary-proxy.invalid", "SWIFTPM_MIRROR_CONFIG": "/canary-mirrors.json",
                "XCODE_XCCONFIG_FILE": "/canary.xcconfig", "GIT_EXTERNAL_DIFF": "/canary-diff", "XDG_CONFIG_HOME": "/canary-xdg",
                "PWD": "/canary-pwd", "SHLVL": "9", "CLAUDE_CODE_MESSAGING_TOKEN": "canary-value-not-printed",
                "CLAUDE_CODE_MESSAGING_SOCKET": "canary-value-not-printed", "LANGUAGE": "canary",
                "CLEAN_DEVX": "canary-near-miss", "CLEAN_DEVELOPMEN": "canary-near-miss", "DEVCACHE2": "canary-near-miss",
                "LCX_ALL": "canary-near-miss", "WGEXX": "canary-near-miss-is-not-wgex-underscore"}

    def allowlist_given(self):
        """One variable per allowlist name and prefix, with distinct values (HOME, PATH and TMPDIR the real ones)."""
        given = {name: f"allowed-{name.lower()}" for name in sorted(knobs.GATE_ALLOWED_NAMES - {"HOME", "PATH", "TMPDIR"})}
        for prefix in knobs.GATE_ALLOWED_PREFIXES:
            given[prefix + "FIXTURE"] = f"allowed-{prefix.lower()}fixture"
        given["LC_ALL"] = "allowed-lc-all"
        given["CLEAN_DEV_BUILDS"] = "allowed-clean-dev-builds"
        given["CLEAN_DEVELOPMENT_ROOT"] = "allowed-clean-development-root"
        return given | {name: os.environ[name] for name in ("HOME", "PATH", "TMPDIR")}

    def gate_polluted_names(self):
        """Every corpus name the old strip list held, plus one sample per prefix (derived, so a name added later is exercised),
        plus the gate's own WGEX_ knobs, which the gate keeps and the self-test drops."""
        names = {name: "canary-value-not-printed" for name in sorted(KNOB_NAMES | TOOL_KNOB_NAMES)}
        for prefix in KNOB_PREFIXES + TOOL_KNOB_PREFIXES:
            names[prefix + "SAMPLE"] = "canary-value-not-printed"
        return names | self.UNLISTED | {"WGEX_GO_RACE_COUNT": "1", "WGEX_LAB_BUILD": "1", "WGEX_FUZZ_SECONDS": "60",
                                        "PYTHON_HISTORY": "dropped-value"}

    def test_gate_entry_builds_each_steps_environment_from_the_allowlist(self):
        """M1-44 item 1 (M1-10x FIX3 RISKS 1 and 2, allowlist proposal): a step's environment is the fixed list in knobs.py and
        nothing else, whatever the caller exported: every allowlist name and prefix reaches the step with its value; every
        corpus name, xcodebuild build settings and TEST_RUNNER_<VAR>, DYLD_*, toolchain selectors, proxies and an unknown name
        are dropped. One entry line gives a count (--enter COMMAND also gives the names);
        a value is never printed."""
        polluted = self.gate_polluted_names()
        dropped_names = sorted(name for name in polluted if not name.startswith("WGEX_") and name != "BASH_FUNC_SAMPLE"
                               and not knobs.allowed(name))
        self.assertGreater(len(dropped_names), 50)
        given = self.allowlist_given()
        self.assertEqual(set(given) - {name for name in given if name.startswith(knobs.GATE_ALLOWED_PREFIXES)},
                         set(knobs.GATE_ALLOWED_NAMES))
        # Plain identifiers go through the environment mapping; BASH_FUNC_<name>%% (as `export -f` makes it) through env(1).
        function = {"BASH_FUNC_cd%%": "() {  echo bash-func-canary-not-printed >&2; builtin cd \"$@\"; }"}
        plain = {name: value for name, value in polluted.items() if name != "BASH_FUNC_SAMPLE"}
        command = ["env"] + [f"{name}={value}" for name, value in function.items()] + self.GATE_STEP
        for arguments in (["fixture"], ["--enter"]):
            # --enter refuses execution variables and inherited variants; labelled steps still receive WGEX_*.
            wanted = [name for name in dropped_names if arguments == ["fixture"] or not name.startswith("JUST_")]
            carried = {name: value for name, value in plain.items() if arguments == ["fixture"] or
                       (not name.startswith("JUST_") and name not in knobs.GATE_REFUSED_BUILD_VARIANTS)}
            gates_own = {name: value for name, value in carried.items() if name.startswith("WGEX_")}
            result = subprocess.run(command + arguments + ["python3", "-I", "-c", self.PRINT_ENVIRONMENT_VALUES],
                                    env=os.environ | carried | given, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            seen = json.loads(result.stdout)
            seen.pop("__CF_USER_TEXT_ENCODING", None)  # macOS python3 adds it to its own environment at startup
            self.assertEqual(seen, dict(os.environ) | given | gates_own)  # exactly the list: nothing more, values unchanged
            for name in wanted + ["BASH_FUNC_cd%%"]:
                self.assertNotIn(name, seen)
            label = "fixture" if arguments == ["fixture"] else "enter"
            shown = "" if label == "fixture" else ": " + ", ".join(re.sub(r"[^A-Za-z0-9_]", "_", name)
                                                                    for name in sorted(wanted + ["BASH_FUNC_cd%%"]))
            # names only on the --enter COMMAND line; every step's line carries the count, so a polluted caller shows
            self.assertEqual([line for line in result.stderr.splitlines() if "dropped" in line],
                             [f"gate-entry: {label} dropped {len(wanted) + 1} inherited variables{shown}"])
            self.assertEqual([line for line in result.stderr.splitlines() if "kept from caller" in line], [])
            self.assertEqual(len([line for line in result.stderr.splitlines() if line.startswith("gate-step:")]),
                             1 if arguments == ["fixture"] else 0)
            self.assertNotIn("canary", result.stderr)  # no value on a gate line (the step's own dump holds WGEX_SAMPLE's)
            self.assertEqual(result.stdout.count("canary"), 1)  # the one WGEX_ name carrying a canary value, kept by design
            self.assertNotIn("allowed-", result.stderr)  # nor an allowed one on a gate line
        # A step that is already clean prints no entry line, and the command status survives either way.
        clean = dict(os.environ)
        restrict_to_allowlist(clean)
        for arguments in (["fixture"], ["--enter"]):
            result = subprocess.run(self.GATE_STEP + arguments + ["python3", "-I", "-c", "raise SystemExit(7)"],
                                    env=clean, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 7, result.stderr)
            self.assertNotIn("gate-entry:", result.stderr)
        # check re-enters its own bash script through the gate entry; the full gate is unchanged apart from the docs switch.
        dry = subprocess.run(["just", "--dry-run", "check"], cwd=ROOT, capture_output=True, text=True, timeout=60)
        self.assertIn("Config/Scripts/timed-step.py --enter bash Config/Scripts/check.sh", dry.stdout + dry.stderr)

    def test_the_allowlist_passes_exactly_its_names_and_prefixes(self):
        """M1-44 item 1: the list is PATH, HOME, TMPDIR, USER, LOGNAME, SHELL, TERM, LANG, LC_*, CODEX_THREAD_ID,
        CLAUDE_CODE_SESSION_ID, WGEX_*, GOPROXY, GOTOOLCHAIN, GOSUMDB, GOVULNDB, DEVCACHE and the CLEAN_DEV_ and CLEAN_DEVELOPMENT_ prefixes, no more (GOFLAGS is not
        on it, knobs.py says why); a near miss of any prefix is dropped; the self-test also withholds WGEX_."""
        self.assertEqual(knobs.GATE_ALLOWED_NAMES, frozenset({"PATH", "HOME", "TMPDIR", "USER", "LOGNAME", "SHELL", "TERM", "LANG",
                                                              "CODEX_THREAD_ID", "CLAUDE_CODE_SESSION_ID", "GOPROXY", "GOTOOLCHAIN",
                                                              "GOSUMDB", "GOVULNDB", "DEVCACHE"}))
        self.assertEqual(knobs.GATE_ALLOWED_PREFIXES, ("LC_", "WGEX_", "CLEAN_DEV_", "CLEAN_DEVELOPMENT_"))
        for name in sorted(knobs.GATE_ALLOWED_NAMES) + ["LC_ALL", "LC_CTYPE", "WGEX_OFFLINE", "CLEAN_DEV_MODE", "CLEAN_DEVELOPMENT_ROOT"]:
            self.assertTrue(knobs.allowed(name), name)
        for name in ("GOFLAGS", "GOENV", "GOPATH", "LANGUAGE", "LC", "WGEX", "CLEAN_DEV", "CLEAN_DEVELOPMENT", "CLEAN_DEVX",
                     "DEVCACHE2", "XDG_CACHE_HOME", "PWD", "SHLVL", "OTHER_SWIFT_FLAGS", "TEST_RUNNER_X", "PYTHON_HISTORY",
                     "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "SSH_AUTH_SOCK", "HTTPS_PROXY", "DEVELOPER_DIR", "SDKROOT"):
            self.assertFalse(knobs.allowed(name), name)
        self.assertTrue(knobs.allowed("WGEX_OFFLINE"))
        self.assertFalse(knobs.allowed("WGEX_OFFLINE", ("WGEX_",)))
        environment = {"PATH": "p", "WGEX_X": "1", "FOO": "2", "LC_ALL": "C", "__CF_USER_TEXT_ENCODING": "0x0"}
        self.assertEqual(knobs.dropped(environment), ["FOO"])  # the interpreter's own variable is not counted
        self.assertEqual((knobs.restrict(environment, ("WGEX_",)), environment), (["FOO", "WGEX_X"], {"PATH": "p", "LC_ALL": "C"}))

    def test_the_allowlist_passes_every_routing_name_env_zsh_exports(self):
        """M1-44 item 1 (FIX3-VERIFY allowlist note: take the CLEAN_DEV list from env.zsh by test, not by hand): every
        CLEAN_DEV*, CLEAN_DEVELOPMENT_* and DEVCACHE name ~/.config/wgex/env.zsh mentions passes the allowlist, so a name it
        adds cannot re-route scratch or builds under a step. Every session-key input it reads must also pass.
        The file is only read. A name unset at column 0 at top level before its first assignment and any read, then assigned,
        is local: it is not itself required, but its visible assigned values are followed. Other unset shapes fail closed with
        a line number (M1-56 fix 2 review R1 and R2 now fail red). Canaries and harmless edits use the checked-in fixture.
        The section scan catches conditions and helpers; the walk follows assignments, read, printf -v and eval.
        The walk stops at preamble constants derived only from HOME or earlier constants. Known limits moved to M1-56b:
        redirections before read/printf values, reassigned HOME, and file paths from unapproved inputs outside the section.
        Review R3 remains, moved to M1-56b: quoted literal text or assignment-shaped command arguments can cause a false red.
        Condition-only printenv and zsh ${(P)...} indirection are also not read."""
        env_zsh = Path(os.environ["HOME"]) / ".config/wgex/env.zsh"

        def routing_names(source):
            # Shell removes a backslash-newline before it splits words, including in multiline unset lists.
            original_source = source
            continuations, removed = [], 0
            for match in re.finditer(r"\\\r?\n", source):
                continuations.append((match.start() - removed, len(match.group())))
                removed += len(match.group())
            source = re.sub(r"\\\r?\n", "", source)

            def physical_location(offset):
                offset += sum(length for position, length in continuations if position <= offset)
                line = original_source.count("\n", 0, offset) + 1
                return line, offset == 0 or original_source[offset - 1] == "\n"

            names = set(re.findall(r"\b(CLEAN_DEV[A-Z_]*|DEVCACHE[A-Z_]*)\b", source))
            assignments, _ = variable_facts(source)
            section = re.search(r"(?ms)^# ---- session key[^\n]*\n(.*?)^# ---- mode\b", source)
            # variable_facts records changed targets without values. Follow their command arguments here without changing
            # the source scanner's reassignment policy; eval's quoted assignment is inspected, never executed.
            for command in shell_commands(source):
                words = _command_words(command)
                head = _literal(words[0]) if words else None
                if head in ("read", "printf"):
                    # File redirections locate data; their paths are not the value assigned by read/printf.
                    # A here-string does supply the value, so retain that operand for the dependency walk.
                    arguments = []
                    for index, word in enumerate(words[1:], 1):
                        redirect = REDIRECTION.match(word)
                        if redirect:
                            if word.startswith("<<<"):
                                arguments.append(redirect.group(1) or (words[index + 1] if index + 1 < len(words) else ""))
                            break
                        arguments.append(word)
                    changed, _ = variable_facts(" ".join(command))
                    for target, events in changed.items():
                        if any(kind == "changed" for kind, _ in events):
                            assignments.setdefault(target, []).append(("=", " ".join(arguments)))
                elif head == "eval":
                    evaluated, _ = variable_facts(" ".join(_unquote(word) for word in words[1:]))
                    for target, events in evaluated.items():
                        assignments.setdefault(target, []).extend(events)

            # Retain subshell depth, which shell_commands intentionally discards, so an unset inside (...) is not local
            # to the sourced file. Quotes, comments, substitutions and redirections follow the same word boundaries.
            commands, words, start, depth, i = [], [], None, 0, 0
            offsets, word_offsets, tripwire_events = [], [], []

            def close_word(end):
                nonlocal start
                if start is not None:
                    words.append(source[start:end])
                    word_offsets.append(start)
                    start = None

            def close_command(end):
                close_word(end)
                if words:
                    commands.append((list(words), depth))
                    offsets.append(word_offsets[0])
                    tripwire_events.append((list(words), list(word_offsets)))
                    words.clear()
                    word_offsets.clear()

            while i < len(source):
                char = source[i]
                if char in " \t\r":
                    close_word(i)
                    i += 1
                elif char == "&" and ((start is not None and source[i - 1] in "<>") or source.startswith("&>", i)):
                    if start is None:
                        start = i
                    i += 1
                elif char == "\n" or char in ";&|()":
                    close_command(i)
                    if char in "()":
                        tripwire_events.append((char, i))
                    if char == "(":
                        depth += 1
                    elif char == ")":
                        depth = max(0, depth - 1)
                    i += 1
                elif char == "#" and start is None:
                    end = source.find("\n", i)
                    i = len(source) if end < 0 else end
                else:
                    if start is None:
                        start = i
                    if char == "\\":
                        i += 2
                    elif char == "'":
                        i = _span_single(source, i)
                    elif char == '"':
                        i = _span_double(source, i)
                    elif char == "`":
                        i = _span_backtick(source, i)
                    elif source.startswith("$(", i):
                        i = _span_paren(source, i)
                    elif source.startswith("${", i):
                        i = _span_brace(source, i)
                    else:
                        i += 1
            close_command(len(source))

            def unset_arguments(words):
                words = _command_words(words)
                if not words or _literal(words[0]) != "unset":
                    return set(), False
                arguments, dynamic = set(), False
                for word in words[1:]:
                    literal = _literal(word)
                    if literal is None:
                        dynamic = True
                    elif literal == "-f":
                        return set(), False  # functions are not variable locals
                    elif IDENTIFIER.fullmatch(literal):
                        arguments.add(literal)
                return arguments, dynamic

            def candidate_locals(words, earlier):
                arguments, _ = unset_arguments(words)
                if not arguments:
                    return set()
                prefix = "\n".join(" ".join(command) for command in earlier)
                prior_assignments, _ = variable_facts(prefix)
                for command in earlier:
                    earlier_words = _command_words(command)
                    if earlier_words and _literal(earlier_words[0]) == "eval":
                        evaluated, _ = variable_facts(" ".join(_unquote(word) for word in earlier_words[1:]))
                        prior_assignments.update(evaluated)
                candidates = set()
                for name in arguments:
                    reference = r"\$(?:\{)?" + re.escape(name) + r"(?![A-Za-z0-9_])"
                    command_read = r"\b(?:printenv|declare|typeset)\s+(?:-[A-Za-z]+\s+)*" + re.escape(name) + r"\b"
                    if name in assignments and name not in prior_assignments and not re.search(reference + "|" + command_read, prefix):
                        candidates.add(name)
                return candidates

            # Once a name is a local candidate, an unsupported later unset of that same name must also trip the guard.
            candidates, earlier = set(), []
            for command, _ in tripwire_events:
                if isinstance(command, str):
                    continue
                candidates.update(candidate_locals(command, earlier))
                for word in command:
                    for code in _substitutions(word):
                        for inner in shell_commands(code):
                            candidates.update(candidate_locals(inner, earlier))
                earlier.append(command)

            def variable_unset(words):
                arguments, dynamic = unset_arguments(words)
                return bool(arguments & candidates) or (dynamic and bool(candidates))

            def unsupported(offset):
                line, _ = physical_location(offset)
                raise AssertionError(f"unsupported shape, see M1-56b (line {line})")

            # This guard is deliberately separate from the dependency walk. A case arm's ')' must not close an outer
            # subshell, and '! if' must still open a conditional. Any candidate unset inside either is unsupported.
            case_depth = paren_depth = control_depth = brace_depth = 0
            for command, positions in tripwire_events:
                if isinstance(command, str):
                    if not case_depth:
                        paren_depth = max(0, paren_depth + (1 if command == "(" else -1))
                    continue
                if variable_unset(command):
                    _, column_zero = physical_location(positions[0])
                    if not column_zero or command[0] != "unset" or case_depth or paren_depth or control_depth or brace_depth:
                        unsupported(positions[0])
                # Substitutions also run in a subshell, including substitutions in double-quoted words.
                for word, position in zip(command, positions):
                    for code in _substitutions(word):
                        for inner in shell_commands(code):
                            if variable_unset(inner):
                                inner_offset = code.find(inner[0])
                                unsupported(position + word.find(code) + max(inner_offset, 0))
                opening = list(command)
                while opening and _literal(opening[0]) in ("then", "do", "else", "!", "{"):
                    opening.pop(0)
                first = _literal(opening[0]) if opening else None
                if first == "esac" and case_depth:
                    case_depth -= 1
                elif first == "case":
                    case_depth += 1
                elif not case_depth:
                    if first in ("fi", "done"):
                        control_depth = max(0, control_depth - 1)
                    elif first in ("if", "for", "while", "until", "select"):
                        control_depth += 1
                    brace_depth = max(0, brace_depth + sum(_literal(word) == "{" for word in command)
                                      - sum(_literal(word) == "}" for word in command))

            locals_, previous, blocks = set(), [], 0
            for (command, subshell_depth), offset in zip(commands, offsets):
                first = _literal(command[0])
                if first in ("fi", "done", "esac"):
                    blocks = max(0, blocks - 1)
                blocks = max(0, blocks - sum(word == "}" for word in command))
                if first == "unset" and physical_location(offset)[1] and not blocks and not subshell_depth:
                    arguments = [_literal(word) for word in command[1:]]
                    while arguments and arguments[0] in ("-v", "--"):
                        arguments.pop(0)
                    if all(name and IDENTIFIER.fullmatch(name) for name in arguments):
                        prefix = "\n".join(" ".join(c) for c in previous)
                        prior_assignments, _ = variable_facts(prefix)
                        for earlier in previous:
                            earlier_words = _command_words(earlier)
                            if earlier_words and _literal(earlier_words[0]) == "eval":
                                evaluated, _ = variable_facts(" ".join(_unquote(word) for word in earlier_words[1:]))
                                prior_assignments.update(evaluated)
                        for name in arguments:
                            reference = r"\$(?:\{)?" + re.escape(name) + r"(?![A-Za-z0-9_])"
                            command_read = r"\b(?:printenv|declare|typeset)\s+(?:-[A-Za-z]+\s+)*" + re.escape(name) + r"\b"
                            if name in assignments and name not in prior_assignments and not re.search(reference + "|" + command_read, prefix):
                                locals_.add(name)
                opening = list(command)
                while opening and _literal(opening[0]) in ("then", "do", "else"):
                    opening.pop(0)
                if opening and _literal(opening[0]) in ("if", "for", "while", "until", "case", "select"):
                    blocks += 1
                blocks += sum(word == "{" for word in command)
                previous.append(command)

            section_names = set(re.findall(r"\$\{?([A-Z][A-Z0-9_]*)", section.group(1))) if section else set()
            names.update(section_names - locals_)
            names.difference_update(locals_)
            # Only the straight-line preamble is eligible, and only literal values or simple expansions of HOME and
            # earlier constants. Do not stop at a value that reads an external input or runs a substitution.
            constants = {"HOME"}
            for line in source.splitlines():
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                commands = shell_commands(line)
                if len(commands) != 1:
                    break
                words = commands[0]
                if words and words[0] == "export":
                    words = words[1:]
                if not words or not all(ASSIGNMENT_WORD.match(word) for word in words):
                    break
                for word in words:
                    assigned = ASSIGNMENT_WORD.match(word)
                    name, value = word[:assigned.end() - 1], word[assigned.end():]
                    pieces = _word_pieces(value)
                    if all(kind == "lit" or (re.fullmatch(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})", part)
                                             and part.lstrip("$").strip("{}") in constants) for kind, part in pieces):
                        if assignments.get(name) == [("=", value)]:  # a later reassignment may read a real external input
                            constants.add(name)
            pending, seen = ["__cd_id", "__cd_key", "__cd_h", *(section_names & locals_)], set()
            while pending:
                name = pending.pop()
                if name in seen or name in constants:
                    continue
                seen.add(name)
                if re.fullmatch(r"[A-Z][A-Z0-9_]*", name) and name not in locals_:
                    names.add(name)
                for _, value in assignments.get(name, []):
                    if value is not None:
                        pending.extend(re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)", value))
                        pending.extend(re.findall(r"\bprintenv\s+([A-Z][A-Z0-9_]*)\b", value))
            return names

        fixture = (ROOT / "Config/Scripts/tests/fixtures/env-zsh-storage-shape.zsh").read_text()
        names = routing_names(fixture)
        with self.subTest(control="fixture"):
            for name in sorted(names):
                self.assertTrue(knobs.allowed(name), name)
        self.assertLessEqual({"CLAUDE_CODE_SESSION_ID", "CODEX_THREAD_ID"}, names)
        self.assertLessEqual({"CLEAN_DEV_MODE", "CLEAN_DEV_STAMP", "CLEAN_DEV_SESSION", "CLEAN_DEV_SCRATCH", "CLEAN_DEV_BUILDS",
                              "CLEAN_DEVELOPMENT_ROOT", "CLEAN_DEVELOPMENT_CACHE_ROOT", "DEVCACHE"}, names)
        if env_zsh.is_file():
            source = env_zsh.read_text()
            live_names = routing_names(source)
            with self.subTest(control="live header renamed"):
                self.assertLessEqual(routing_names(source.replace("# ---- session key", "# ---- renamed session")), live_names)
            with self.subTest(control="live allowlist"):
                for name in sorted(live_names):
                    self.assertTrue(knobs.allowed(name), name)
        # Outside the session section too: the same derivation must contribute new inputs to the checked names.
        canary = fixture + '\nif [ -n "$__cd_id" ]; then :\nelif [ -n "${WGEX_CANARY_ID:-}" ]; then __cd_id="$WGEX_CANARY_ID"\nfi\n'
        self.assertIn("WGEX_CANARY_ID", routing_names(canary))
        # Variants change only the synthetic fixture; none is executed as shell code.
        session_end = fixture.find("# ---- mode")
        variants = {}
        for label, name, code in (
            ("V8 condition", "GROK_DISABLE", '[ -z "${GROK_DISABLE:-}" ] || :'),
            ("V10 helper", "GROK_SESSION_ID", '__cd_pick(){ printf %s "$GROK_SESSION_ID"; }; __cd_id="$(__cd_pick)"'),
            ("V12 printf", "GROK_SESSION_ID", 'printf -v __cd_id %s "$GROK_SESSION_ID"'),
            ("V13 eval", "GROK_SESSION_ID", r'eval "__cd_id=\$GROK_SESSION_ID"'),
            ("V14 key", "AGENT_SESSION_KEY", '__cd_key="$AGENT_SESSION_KEY"'),
            ("V15 prefix", "GROK_PREFIX", '__cd_h="${GROK_PREFIX:-x}"'),
            ("V16 read", "GROK_SESSION_ID", 'read -r __cd_id <<<"$GROK_SESSION_ID"'),
        ):
            variants[label] = (name, fixture[:session_end] + code + "\n" + fixture[session_end:])
        # Outside the section so its scan cannot mask a broken printenv or transitive walk.
        variants["V3 printenv"] = ("GROK_SESSION_ID", fixture + '\n__cd_id="$(printenv GROK_SESSION_ID)"\n')
        variants["V7 two-hop"] = ("GROK_SESSION_ID", fixture +
                                  '\n__cd_alt="$(printenv GROK_SESSION_ID)"; __cd_id="$__cd_alt"\n')
        variants["reassigned preamble constant"] = ("GROK_SESSION_ID", fixture +
                                                    '\nDEVMACHINE="$GROK_SESSION_ID"; __cd_id="$DEVMACHINE"\n')
        variants["eval-reassigned preamble constant"] = ("GROK_SESSION_ID", fixture +
                                                         '\n' + r'eval "DEVMACHINE=\$GROK_SESSION_ID"; __cd_id="$DEVMACHINE"' + '\n')
        for label, name, code in (
            ("outside printf", "GROK_SESSION_ID", 'printf -v __cd_id %s "$GROK_SESSION_ID"'),
            ("outside eval", "GROK_SESSION_ID", r'eval "__cd_id=\$GROK_SESSION_ID"'),
            ("outside read", "GROK_SESSION_ID", 'read -r __cd_id <<<"$GROK_SESSION_ID"'),
            ("outside key", "AGENT_SESSION_KEY", '__cd_key="$AGENT_SESSION_KEY"'),
            ("outside prefix", "GROK_PREFIX", '__cd_h="${GROK_PREFIX:-x}"'),
        ):
            variants[label] = (name, fixture + "\n" + code + "\n")
        for label, (name, changed) in variants.items():
            with self.subTest(canary=label):
                self.assertTrue(changed != fixture, "routing canary did not change its fixture")
                self.assertIn(name, routing_names(changed))
        with self.subTest(local="section reference"):
            self.assertNotIn("STORAGE_ROOT", names)
        with self.subTest(local="follow assigned value"):
            changed = fixture.replace('STORAGE_ROOT="${STORAGE_ROOT:-$HOME/work}"', 'STORAGE_ROOT="$GROK_X"')
            self.assertNotEqual(changed, fixture)
            self.assertNotIn("STORAGE_ROOT", routing_names(changed))
            self.assertIn("GROK_X", routing_names(changed))
        for prefix in ('GROK_LOCAL=old\nunset GROK_LOCAL\n', 'echo "$GROK_LOCAL"\nunset GROK_LOCAL\n'):
            with self.subTest(local="unset does not qualify", prefix=prefix):
                changed = prefix + 'GROK_LOCAL=value\n' + fixture.replace(
                    '# ---- mode', '[ -n "$GROK_LOCAL" ] || :\n# ---- mode', 1)
                self.assertIn("GROK_LOCAL", routing_names(changed))
        with self.subTest(local="column-0 unset"):
            changed = 'unset GROK_LOCAL\nGROK_LOCAL=value\n' + fixture.replace(
                '# ---- mode', '[ -n "$GROK_LOCAL" ] || :\n# ---- mode', 1)
            self.assertNotIn("GROK_LOCAL", routing_names(changed))
        with self.subTest(local="R3 quoted literal residual"):
            changed = "printf '%s\\n' '$GROK_LOCAL'\nunset GROK_LOCAL\nGROK_LOCAL=value\n" + fixture.replace(
                '# ---- mode', '[ -n "$GROK_LOCAL" ] || :\n# ---- mode', 1)
            self.assertIn("GROK_LOCAL", routing_names(changed))
        for label, prefix, line in (
            ("indented", '  unset GROK_LOCAL\n', 1),
            ("case arm", 'case x in\n x) unset GROK_LOCAL ;;\nesac\n', 2),
            ("column-0 in case arm", 'case x in\n x)\nunset GROK_LOCAL\n;;\nesac\n', 3),
            ("subshell", '(unset GROK_LOCAL)\n', 1),
            ("function", 'f() {\nunset GROK_LOCAL\n}\n', 2),
            ("negation", '! unset GROK_LOCAL\n', 1),
            ("and", 'false && unset GROK_LOCAL\n', 1),
            ("or", 'true || unset GROK_LOCAL\n', 1),
            ("semicolon", ':; unset GROK_LOCAL\n', 1),
            ("substitution", 'x="$(unset GROK_LOCAL)"\n', 1),
            ("multiline substitution", 'x="$(\nprintf x\nunset GROK_LOCAL\n)"\n', 3),
            ("later conditional unset", 'unset GROK_LOCAL\nGROK_LOCAL=value\nfalse && unset GROK_LOCAL\n', 3),
            ("continued earlier command", "printf '%s' \\\n value\n  unset GROK_LOCAL\n", 3),
            ("R1 case in subshell", '(\ncase x in\n x) : ;;\nesac\nunset GROK_LOCAL\n)\n', 5),
            ("R2 negated if", '! if false; then\nunset GROK_LOCAL\nfi\n', 2),
        ):
            with self.subTest(unsupported_unset=label):
                changed = prefix + 'GROK_LOCAL="${GROK_LOCAL:-value}"\n' + fixture.replace(
                    '# ---- mode', '[ -n "$GROK_LOCAL" ] || :\n# ---- mode', 1)
                with self.assertRaisesRegex(AssertionError, rf"^unsupported shape, see M1-56b \(line {line}\)$"):
                    routing_names(changed)
        for code in ('__cd_hd="$HOME"', '[ -n "${TMPDIR:-}" ] || __cd_id=""',
                     'read -r __cd_id < "$__cd_state/id"', '__cd_id="$(cat "$__cd_state/id")"'):
            with self.subTest(harmless_routing_edit=code):
                changed = fixture[:session_end] + code + "\n" + fixture[session_end:]
                derived = routing_names(changed)
                self.assertTrue(all(knobs.allowed(name) for name in derived), "harmless edit required a disallowed name")
                for header in ("# ---- session key", "# ---- mode"):
                    with self.subTest(renamed_header=header):
                        renamed = routing_names(changed.replace(header, "# ---- renamed", 1))
                        self.assertLessEqual(renamed, derived)
                        self.assertTrue(all(knobs.allowed(name) for name in renamed), "renamed header required a disallowed name")

    def test_claude_session_routing_survives_a_real_timed_step(self):
        """F1: a Claude-only caller and a caller with both ids keep the routing and Claude-first precedence.
        Inject the ids into the actual timed-step child, independently of the self-test's import environment.
        Hermetic: the routing source is the tracked fixture env-zsh-routing.zsh under a scratch HOME; the host's home,
        env.zsh, storage.conf and caches are never read, and the routing test below proves it against a hostile host."""
        self.check_claude_session_routing()

    def test_claude_session_routing_ignores_a_hostile_host(self):
        """M02-T13: the real-timed-step routing check passes whatever the host's storage configuration is. The host's HOME
        is a decoy whose env.zsh, .zshenv and storage.conf would redirect every cache and leave a marker if anything read
        them, and the host's routing variables are poisoned; the check still passes and the marker never appears."""
        decoy = self.work / "hostile-host"
        (decoy / ".config/wgex").mkdir(parents=True)
        marker = decoy / "was-read"
        (decoy / ".config/wgex/env.zsh").write_text(f'touch "{marker}"\nexport TMPDIR=/hostile CLEAN_DEV_BUILDS=/hostile\n')
        (decoy / ".config/wgex/storage.conf").write_text('INTERNAL_ROOT=/hostile\nEXTERNAL_ROOT=/Volumes/hostile\n')
        (decoy / ".zshenv").write_text(f'touch "{marker}"\n. "$HOME/.config/wgex/env.zsh"\n')
        hostile = {"HOME": str(decoy), "DEVMACHINE": str(decoy / ".config/wgex"), "DEVCACHE": "/hostile",
                   "CLEAN_DEV_MODE": "external", "CLEAN_DEV_STAMP": "external|/hostile|c-aaaaaaaaaaaa",
                   "CLEAN_DEV_SESSION": "c-aaaaaaaaaaaa", "CLEAN_DEV_BUILDS": "/hostile", "CLEAN_DEV_SCRATCH": "/hostile",
                   "CLAUDE_CODE_SESSION_ID": "hostile-session-aaaaaaaaaaaa", "CODEX_THREAD_ID": "hostile-codex-bbbbbbbbbbbb",
                   "DEV_STORAGE_VOLUME_TEST": "present", "ZDOTDIR": str(decoy)}
        with patch.dict(os.environ, hostile):
            self.check_claude_session_routing()
        self.assertFalse(marker.exists(), "the routing check read the host's home")

    def check_claude_session_routing(self):
        home = self.work / "home"
        machine = home / ".config/wgex"
        machine.mkdir(parents=True)
        shutil.copyfile(ROOT / "Config/Scripts/tests/fixtures/env-zsh-routing.zsh", machine / "env.zsh")
        cache = self.work / "routing-cache"
        (machine / "storage.conf").write_text(f'INTERNAL_ROOT="{cache}"\n')
        (home / ".zshenv").write_text('. "$HOME/.config/wgex/env.zsh"\n')
        routing = ("TMPDIR", "CLEAN_DEV_SESSION", "CLEAN_DEV_BUILDS", "CLEAN_DEV_STAMP", "CLEAN_DEV_SCRATCH")
        probe = self.work / "claude-routing.py"
        probe.write_text(f'import json, os, sys\nsys.path.insert(0, {str(ROOT / "Config/Scripts")!r})\n'
                         'import build_root\n'
                         f'print(json.dumps({{"routing": {{name: os.environ.get(name) for name in {routing!r}}}, '
                         f'"build_root": str(build_root.build_root({str(ROOT)!r})), '
                         '"messaging_present": [name for name in ("CLAUDE_CODE_MESSAGING_TOKEN", '
                         '"CLAUDE_CODE_MESSAGING_SOCKET") if name in os.environ]}))\n')
        command = ["zsh", "-lc", f'python3 -I "{probe}"']
        base = {"HOME": str(home), "PATH": os.environ["PATH"], "TMPDIR": str(self.work),
                "CLAUDE_CODE_SESSION_ID": "fixture-session-123456789abc"}
        expected_stamp = "c-123456789abc"
        for other_id in ({}, {"CODEX_THREAD_ID": "fixture-codex-abcdef123456"}):
            with self.subTest(both_ids=bool(other_id)):
                caller = base | other_id
                before = subprocess.run(command, env=caller, capture_output=True, text=True, timeout=60)
                self.assertEqual(before.returncode, 0, before.stderr)
                original = json.loads(before.stdout)
                self.assertEqual(original["routing"]["CLEAN_DEV_SESSION"], expected_stamp)
                self.assertEqual(original["routing"]["TMPDIR"], str(cache / "scratch" / expected_stamp / "tmp"))
                self.assertEqual(original["routing"]["CLEAN_DEV_BUILDS"], str(cache / "builds" / expected_stamp))
                self.assertEqual(original["build_root"], str(cache / "builds" / expected_stamp / ROOT.name))
                # Simulate the already-routed caller entering a real timed step; the login shell must keep these paths.
                caller |= original["routing"] | {"CLAUDE_CODE_MESSAGING_TOKEN": "fixture", "CLAUDE_CODE_MESSAGING_SOCKET": "fixture"}
                result = subprocess.run(self.GATE_STEP + ["probe/claude-routing"] + command, env=caller,
                                        capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("gate-step: probe/claude-routing exit=0", result.stderr)
                self.assertEqual(json.loads(result.stdout), original)

    def test_gate_allowlist_docs_cover_go_callers_and_drop_counts(self):
        """F2/F4: the public rule states the caller Go policy and describes the conditional entry line accurately."""
        text = " ".join((ROOT / "CONTRIBUTING.md").read_text().split())
        with self.subTest(finding="F2"):
            self.assertIn("`GOPROXY`, `GOTOOLCHAIN`, `GOSUMDB` and `GOVULNDB` pass with whatever value any caller exported", text)
            self.assertIn("This is acceptable for the wrapped offline gate: its wrapper fixes these values and `WGEX_OFFLINE=1` skips the advisory database", text)
            self.assertIn("an unwrapped caller with `WGEX_OFFLINE` unset still chooses these values", text)
        with self.subTest(finding="F4"):
            self.assertIn("Each step that drops anything prints one line with a count", text)
        with self.subTest(finding="F1"):
            self.assertIn("`CLAUDE_CODE_SESSION_ID`", text)

    def test_gate_entry_and_selftest_share_one_allowlist(self):
        """M1-44 item 2: the gate entry and the self-test use one definition (Config/Scripts/knobs.py), so they cannot drift:
        the gate drops exactly what the self-test drops, less the WGEX_* names the self-test also withholds."""
        timed = self.module("Config/Scripts/timed-step.py")
        for name in ("GATE_ALLOWED_NAMES", "GATE_ALLOWED_PREFIXES", "KNOB_PREFIXES", "KNOB_NAMES", "TOOL_KNOB_PREFIXES", "TOOL_KNOB_NAMES"):
            self.assertEqual(getattr(timed.knobs, name), getattr(knobs, name), name)
        self.assertEqual(SELFTEST_WITHHELD_PREFIXES, ("WGEX_",))
        polluted = self.gate_polluted_names() | {"CODEX_THREAD_ID": "x", "LC_ALL": "x", "CLEAN_DEV_BUILDS": "x", "DEVCACHE": "x"}
        selftest = set(restrict_to_allowlist(dict(polluted)))
        with patch.dict(os.environ, polluted, clear=True):
            gate = set(timed.clean_environment()[1])
        self.assertEqual(selftest - gate, {name for name in polluted if name.startswith("WGEX_")})
        self.assertEqual(gate - selftest, set())
        self.assertGreater(len(gate), 50)
        for name in ("PYTHON_HISTORY", "FOO_BAR", "OTHER_SWIFT_FLAGS", "TEST_RUNNER_WGEXCANARY"):
            self.assertIn(name, selftest)
        for name in ("CODEX_THREAD_ID", "LC_ALL", "CLEAN_DEV_BUILDS", "DEVCACHE"):
            self.assertNotIn(name, selftest)
        # the gate entry holds no list of its own
        self.assertNotIn("BASH_ENV", (ROOT / "Config/Scripts/timed-step.py").read_text())
        self.assertNotIn("GATE_ALLOWED_NAMES = ", (ROOT / "Config/Scripts/timed-step.py").read_text())

    def test_the_selftest_cuts_its_own_environment_to_the_allowlist_at_import(self):
        """M1-44 item 2: importing the self-test (every runner does) drops everything off the allowlist from its own process
        and every WGEX_* name, and prints a count, never a name or value."""
        script = ('import importlib.util, json, os, sys\n'
                  'spec = importlib.util.spec_from_file_location("selftest", sys.argv[1])\n'
                  'module = importlib.util.module_from_spec(spec)\n'
                  'spec.loader.exec_module(module)\n'
                  'print(json.dumps(sorted(os.environ)))\n')
        given = self.allowlist_given()
        result = subprocess.run(["python3", "-I", "-B", "-c", script, str(Path(__file__).resolve())],
                                env=os.environ | self.UNLISTED | {"STUB_SCENARIO": "x", "WGEX_OFFLINE": "1"} | given,
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        seen = set(json.loads(result.stdout)) - {"__CF_USER_TEXT_ENCODING"}  # macOS python3 adds it at startup
        self.assertEqual(seen, {name for name in {*os.environ, *given} if not name.startswith("WGEX_")})
        self.assertRegex(result.stderr, r"^tooling-selftest: dropped \d+ inherited variables\n$")
        self.assertNotIn("canary", result.stderr)

    def test_routing_survives_a_polluted_caller_through_a_login_shell_step(self):
        """M1-44 item 3c (cheap form; `just check` from a polluted caller is the acceptance run): a step that starts a login
        zsh, as every recipe line does, sees the same routing whether the caller is clean or polluted with every corpus name,
        build settings, DYLD_*, a toolchain selector and cache variables of its own (GOCACHE, GOPATH, XDG_CONFIG_HOME): the
        CLEAN_DEV pins, TMPDIR, the caches env.zsh derives and the build root under the key are identical, and no polluted
        name or value survives. The dropped cache variables come back from env.zsh, not from the caller."""
        if not (Path(os.environ["HOME"]) / ".config/wgex/env.zsh").is_file():
            self.skipTest("~/.config/wgex/env.zsh is absent on this host")
        probe = self.work / "routing-probe.py"
        probe.write_text(f'import json, os, sys\nsys.path.insert(0, {str(ROOT / "Config/Scripts")!r})\nimport build_root\n'
                         f'print(json.dumps({{"env": dict(os.environ), "build_root": str(build_root.build_root({str(ROOT)!r}))}}))\n')
        polluted = {name: value for name, value in self.gate_polluted_names().items() if not name.startswith("WGEX_")}
        polluted["JUST_LOG"] = "canary-value-not-printed"  # a presentation name: harmless to just, still dropped
        outputs = []
        for extra in ({}, polluted):
            result = subprocess.run(self.GATE_STEP + ["probe/routing", "zsh", "-lc", f'python3 -I "{probe}"'],
                                    env=os.environ | extra, capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("canary", result.stdout.replace("canary-value-not-printed", "") + result.stderr)
            outputs.append((json.loads(result.stdout), result.stderr))
        (clean, _), (hostile, stderr) = outputs
        self.assertRegex(stderr, rf"gate-entry: probe/routing dropped {len(polluted)} inherited variables\n")
        routing = ("TMPDIR", "CLEAN_DEV_MODE", "CLEAN_DEV_STAMP", "CLEAN_DEV_SESSION", "CLEAN_DEV_SCRATCH", "CLEAN_DEV_BUILDS",
                   "CLEAN_DEVELOPMENT_ROOT", "CLEAN_DEVELOPMENT_CACHE_ROOT", "CLEAN_DEVELOPMENT_BUILD_ROOT", "DEVCACHE",
                   "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "GOCACHE", "GOMODCACHE", "GOPATH", "XCODE_DERIVED_DATA_PATH",
                   "SWIFTPM_SHARED_CACHE", "CLANG_MODULE_CACHE_PATH")
        self.assertEqual({name: hostile["env"].get(name) for name in routing}, {name: clean["env"].get(name) for name in routing})
        self.assertEqual(hostile["build_root"], clean["build_root"])
        self.assertIn("DEVCACHE", clean["env"])
        for name, value in polluted.items():
            self.assertEqual(hostile["env"].get(name), clean["env"].get(name), name)  # gone, or the value env.zsh gives it
            self.assertNotEqual(hostile["env"].get(name), value, name)
        for name in ("OTHER_SWIFT_FLAGS", "TEST_RUNNER_WGEXCANARY", "DEVELOPER_DIR", "SDKROOT", "GOFLAGS", "DYLD_INSERT_LIBRARIES",
                     "PYTHONPATH", "GIT_EXTERNAL_DIFF", "FOO_BAR"):
            self.assertNotIn(name, hostile["env"])
        key = clean["env"].get("CLEAN_DEV_SESSION")
        if key:  # a keyed session: scratch and builds sit under the key
            self.assertTrue(hostile["env"]["TMPDIR"].startswith(hostile["env"]["CLEAN_DEV_SCRATCH"]), key)
            self.assertTrue(hostile["build_root"].startswith(hostile["env"]["CLEAN_DEV_BUILDS"]), key)
            self.assertIn(key, hostile["build_root"])

    @unittest.skipUnless(shutil.which("xcodebuild"), "xcodebuild is not installed")
    def test_xcodebuild_build_settings_and_test_runner_variables_do_not_reach_a_gate_step(self):
        """M1-44 item 3a and 3b (M1-10x FIX3 RISKS 1 and 2): xcodebuild takes a plain environment variable as a build setting
        (OTHER_SWIFT_FLAGS=-wgex-canary-unknown-flag turned a throwaway package build from rc 0 to rc 65) and passes
        TEST_RUNNER_<VAR> into the test runner. Through the gate entry a throwaway package (no dependencies, nothing fetched)
        builds and tests exactly as with a clean caller; without it, each canary is live on its own (rc 65, with the
        reason in the output)."""
        package = self.work / "canary-package"
        (package / "Sources/Canary").mkdir(parents=True)
        (package / "Tests/CanaryTests").mkdir(parents=True)
        (package / "Package.swift").write_text('// swift-tools-version:5.9\nimport PackageDescription\n'
                                               'let package = Package(name: "Canary", targets: [.target(name: "Canary"), '
                                               '.testTarget(name: "CanaryTests", dependencies: ["Canary"])])\n')
        (package / "Sources/Canary/Canary.swift").write_text("public let canary = 1\n")
        (package / "Tests/CanaryTests/CanaryTests.swift").write_text(
            'import XCTest\n@testable import Canary\nfinal class CanaryTests: XCTestCase {\n'
            '    func testRunnerEnvironmentIsClean() {\n'
            '        XCTAssertNil(ProcessInfo.processInfo.environment["WGEXCANARY"])\n        XCTAssertEqual(canary, 1)\n    }\n}\n')
        # Keep xcodebuild's deep output out of the shared TemporaryDirectory teardown.
        derived_data = Path(tempfile.mkdtemp(prefix="wgex-canary-dd-", dir=os.environ["TMPDIR"]))
        self.addCleanup(cleanup_canary_derived_data, derived_data)
        script = (f'cd "{package}" && xcodebuild -scheme Canary-Package -destination "platform=macOS" '
                  f'-derivedDataPath "{derived_data}" test')
        build_setting = {"OTHER_SWIFT_FLAGS": "-wgex-canary-unknown-flag"}
        test_runner = {"TEST_RUNNER_WGEXCANARY": "1"}
        passed = re.compile(r"Test Case '-\[CanaryTests\.CanaryTests testRunnerEnvironmentIsClean\]' passed")

        def run(extra, gated):
            command = (self.GATE_STEP + ["probe/xcodebuild"] if gated else []) + ["zsh", "-lc", script]
            return subprocess.run(command, env=os.environ | extra, capture_output=True, text=True, timeout=420)
        clean = run({}, gated=True)
        self.assertEqual(clean.returncode, 0, clean.stdout[-2000:] + clean.stderr)
        self.assertRegex(clean.stdout, passed)
        # the inputs are live: without the gate entry each one fails the same package on its own
        control = run(build_setting, gated=False)
        self.assertEqual(control.returncode, 65, control.stdout[-2000:])
        self.assertIn("unknown argument: '-wgex-canary-unknown-flag'", control.stdout)
        control = run(test_runner, gated=False)
        self.assertEqual(control.returncode, 65, control.stdout[-2000:])
        self.assertIn("XCTAssertNil failed", control.stdout)
        # through the gate entry both are gone: the same result as the clean caller, the count on the entry line
        for name, extra in (("both", build_setting | test_runner), ("build setting", build_setting), ("test runner", test_runner)):
            result = run(extra, gated=True)
            self.assertEqual(result.returncode, 0, (name, result.stdout[-2000:], result.stderr))
            self.assertRegex(result.stdout, passed)
            self.assertIn("TEST SUCCEEDED", result.stdout)
            self.assertNotIn("canary-unknown-flag", result.stdout + result.stderr)
            self.assertIn(f"gate-entry: probe/xcodebuild dropped {len(extra)} inherited variables\n", result.stderr)
            self.assertIn("gate-step: probe/xcodebuild exit=0 ", result.stderr)
            self.assertEqual(sorted(re.findall(r"^Test Case .* (?:passed|failed)", result.stdout, re.M)),
                             sorted(re.findall(r"^Test Case .* (?:passed|failed)", clean.stdout, re.M)))

    def test_lab_test_runners_unset_the_callers_wgex_stub_and_fake_variables(self):
        """M1-10x item 2 (M1-10w VERIFY-B M2): neither lab suite's result depends on an inherited WGEX_LAB_VM, WGEX_LAB_TEST_BIN,
        WGEX_LAB_APT_MIRROR, a deadline knob or any other WGEX_*, STUB_* or FAKE_* name; each runner names (never prints)
        what it removed. A PATH stub (the first command each runner reaches) records the environment it was handed."""
        stubs = self.work / "lab-stubs"
        stubs.mkdir()
        hostile = {"WGEX_LAB_VM": "canary-lab-vm-not-printed", "WGEX_LAB_TEST_BIN": "/canary-lab-bin-not-printed",
                   "WGEX_LAB_APT_MIRROR": "canary-lab-mirror-not-printed", "WGEX_LAB_SSH_DEADLINE": "1",
                   "WGEX_LAB_CONNECT_TIMEOUT": "1", "WGEX_LAB_HARNESS_SCALE": "9",
                   "STUB_SCENARIO": "canary-stub-not-printed", "FAKE_HOST_VERSION": "canary-fake-not-printed",
                   "FAKE_LOG": "/canary-fake-log-not-printed"}
        # WGEX_BUILD_ROOT is routing, not a behaviour knob (M1-10x fix 1, VERIFY-B L5): both runners keep it, unnamed.
        routed = str(self.work / "routed-build-root")
        for script, first in (("Tools/lab/tests/run.sh", "swift"), ("Tools/lab/tart/tests/run.sh", "mktemp")):
            dump = self.work / f"lab-env-{first}"
            (stubs / first).write_text(f'#!/bin/bash\n/usr/bin/env >"{dump}"\nexit 1\n')
            (stubs / first).chmod(0o755)
            result = subprocess.run(["bash", str(ROOT / script)], capture_output=True, text=True,
                                    env=os.environ | {"PATH": f"{stubs}:{os.environ['PATH']}", "WGEX_BUILD_ROOT": routed} | hostile,
                                    timeout=120)
            self.assertTrue(dump.exists(), result.stderr)  # the runner got as far as its first real command
            lines = [line for line in dump.read_text().splitlines() if "=" in line]
            names = {line.split("=", 1)[0] for line in lines}
            self.assertEqual({name for name in names if name.startswith(("WGEX_", "STUB_", "FAKE_"))}, {"WGEX_BUILD_ROOT"}, script)
            self.assertIn(f"WGEX_BUILD_ROOT={routed}", lines)
            self.assertIn("PATH", names)
            notice = [line for line in result.stderr.splitlines() if "removed inherited variables" in line]
            self.assertEqual(len(notice), 1, result.stderr)
            self.assertEqual(sorted(notice[0].split("removed inherited variables: ", 1)[1].split(", ")), sorted(hostile), script)
            self.assertNotIn("canary", result.stdout + result.stderr)
            (stubs / first).unlink()
        # a clean parent prints no notice
        (stubs / "swift").write_text('#!/bin/bash\nexit 1\n')
        (stubs / "swift").chmod(0o755)
        result = subprocess.run(["bash", str(ROOT / "Tools/lab/tests/run.sh")], capture_output=True, text=True,
                                env=os.environ | {"PATH": f"{stubs}:{os.environ['PATH']}"}, timeout=120)
        self.assertNotIn("removed inherited variables", result.stderr)
        # and a caller who sets only WGEX_BUILD_ROOT gets no removal notice either
        result = subprocess.run(["bash", str(ROOT / "Tools/lab/tests/run.sh")], capture_output=True, text=True,
                                env=os.environ | {"PATH": f"{stubs}:{os.environ['PATH']}", "WGEX_BUILD_ROOT": routed}, timeout=120)
        self.assertNotIn("removed inherited variables", result.stderr)

    def test_check_full_docs_step_is_plain_and_fail_closed(self):
        """M00-T02: the check-full docs step is `just docs-test` with no environment switch, and docs-check and docs-test
        fail closed on their own (a missing source is covered by Tools/docs/tests/run.sh)."""
        full = subprocess.run(["just", "--dry-run", "check-full"], cwd=ROOT, capture_output=True, text=True)
        steps = (full.stdout + full.stderr).splitlines()
        docs = [line for line in steps if "full/docs-tests" in line]
        self.assertEqual(len(docs), 1, docs)
        self.assertRegex(docs[0], r"timed-step\.py full/docs-tests just docs-test$")
        self.assertNotIn("WGEX_DOCS", full.stdout + full.stderr)
        for recipe in ("docs-test", "docs-check", "lint"):
            plain = subprocess.run(["just", "--dry-run", recipe], cwd=ROOT, capture_output=True, text=True)
            self.assertNotIn("WGEX_DOCS", plain.stdout + plain.stderr)
        self.assertNotIn("WGEX_DOCS", (ROOT / "Tools/lint/lint.sh").read_text())

    PYTHON3_PROBE = re.compile(r"(?:command\s+-v|type(?:\s+-\w+)?|which(?:\s+-\w+)?)\s+python3\b")
    PYTHON3_CALL = re.compile(r"(?:^|[\s|&;(`\"'/])python3(?=\s|$)(?P<rest>.{0,3})")

    @classmethod
    def python3_calls(cls, line):
        """(calls, calls without -I) on one script line: bare, absolute-path (/usr/bin/python3) and `command python3` calls
        count; only `command -v`, `type` and `which` presence probes and comments do not (M1-10x fix 1, VERIFY-B L3)."""
        text = re.sub(r"^\s*brew_tool \S+ \S+ ", "", line)  # doctor: key and command names, then the call
        if text.lstrip().startswith("#"):
            return 0, 0
        calls = bad = 0
        for found in cls.PYTHON3_CALL.finditer(text):
            if cls.PYTHON3_PROBE.search(text[:found.end()]):
                continue
            calls += 1
            bad += not found.group("rest").startswith(" -I")
        return calls, bad

    def test_the_python3_scanner_sees_absolute_path_and_command_calls_but_not_probes(self):
        """M1-10x fix 1 (VERIFY-B L3, mutants M4b and M4c): `/usr/bin/python3 -c` and `command python3 -c` are calls that
        need -I; `command -v python3`, `type python3` and `which python3` are presence probes."""
        for line in ('/usr/bin/python3 -c "print(1)"', 'command python3 -c "print(1)"', 'x="$(python3 -c 1)"',
                     'out=$(/opt/homebrew/bin/python3 - <<EOF', 'env python3 script.py'):
            self.assertGreaterEqual(self.python3_calls(line)[1], 1, line)
        self.assertEqual(self.python3_calls('a && python3 -I -c 1 && python3 b.py'), (2, 1))
        for line in ('/usr/bin/python3 -I -c "print(1)"', 'command python3 -I -c 1', 'python3 -I -B x.py'):
            self.assertEqual(self.python3_calls(line), (1, 0), line)
        for line in ('command -v python3 >/dev/null', 'type python3', 'type -P python3', 'which python3', '# python3 -c 1', ''):
            self.assertEqual(self.python3_calls(line), (0, 0), line)

    def test_every_python3_call_in_the_gate_scripts_isolates_the_interpreter(self):
        """M1-10x item 4 (M1-10w VERIFY-B L2): no PYTHONPATH, PYTHONHOME or user site can inject code into a gate script's
        python3. Every call in Config/Scripts, Tools/lint, Tools/doctor, Engine/scripts and the justfile takes -I."""
        listed = subprocess.run(["git", "ls-files", "-z", "--", "Config/Scripts", "Tools/lint", "Tools/doctor", "Engine/scripts",
                                 "justfile"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split("\0")
        problems = []
        calls = 0
        for name in filter(None, listed):
            if not (name.endswith(".sh") or name == "justfile"):
                continue
            for number, line in enumerate((ROOT / name).read_text().splitlines(), 1):
                found, bad = self.python3_calls(line)
                calls += found
                problems += [f"{name}:{number}: {line.strip()}"] * bad
        self.assertGreater(calls, 20)
        self.assertEqual(problems, [])
        # and a planted module on PYTHONPATH does not run in the heredoc-driven import check
        planted = self.work / "planted-python"
        planted.mkdir()
        (planted / "ast.py").write_text("import sys\nsys.stderr.write('planted-ast-canary-not-printed\\n')\nraise ImportError('planted')\n")
        empty = self.work / "no-swift-here"
        empty.mkdir()
        result = subprocess.run(["bash", str(ROOT / "Tools/lint/check-package-deps.sh"), "--release-imports", str(empty)],
                                env=os.environ | {"PYTHONPATH": str(planted)}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("canary", result.stdout + result.stderr)

    def test_public_prose_check_fails_closed_under_posix_mode(self):
        """M1-10x item 5 (M1-10w FIX1-VERIFY NEW-2): called directly with POSIXLY_CORRECT=1 (bash 3.2 then has no process
        substitution) a denylisted term still fails the check; it is never rc 0 behind a syntax error."""
        terms = [line for line in (ROOT / "Tools/lint/public-prose-denylist.txt").read_text().splitlines()
                 if line and not line.startswith("#")]
        bad, good = self.work / "posix-bad.md", self.work / "posix-good.md"
        bad.write_text("clean\n" + terms[0] + "\n")
        good.write_text("clean\n")
        script = str(ROOT / "Tools/lint/check-public-prose.sh")
        for environment in ({}, {"POSIXLY_CORRECT": "1"}, {"SHELLOPTS": "posix", "POSIXLY_CORRECT": "y"}):
            env = os.environ | environment
            result = subprocess.run(["bash", script, str(bad)], env=env, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 1, (environment, result.stdout, result.stderr))
            self.assertRegex(result.stderr, r"denylisted term #1: .*posix-bad\.md line(?:\(s\))? 2")
            self.assertNotIn("syntax error", result.stderr)
            self.assertNotIn(terms[0], result.stderr)
            result = subprocess.run(["bash", script, str(good)], env=env, capture_output=True, text=True, timeout=60)
            self.assertEqual((result.returncode, result.stdout.strip()), (0, "check-public-prose: ok"), result.stderr)

    def test_public_prose_check_reexecs_at_most_once_and_never_loops_or_runs_another_bash(self):
        """M1-10x fix 1 (VERIFY-B M3, L6): a startup file that switches POSIX mode back on (BASH_ENV with `set -o posix`, or
        `export POSIXLY_CORRECT=1`) made the single re-exec loop forever (31,550 re-execs in two minutes). The re-exec now
        drops BASH_ENV and ENV as well, runs "$BASH" (not the first `bash` on PATH), and a second sighting of POSIX mode
        fails closed with status 2. Every run has a timeout, so a regression fails instead of hanging the self-test."""
        terms = [line for line in (ROOT / "Tools/lint/public-prose-denylist.txt").read_text().splitlines()
                 if line and not line.startswith("#")]
        bad = self.work / "reexec-bad.md"
        bad.write_text("clean\n" + terms[0] + "\n")
        script = str(ROOT / "Tools/lint/check-public-prose.sh")
        startup = {"set -o posix": self.work / "posix-startup.sh", "export POSIXLY_CORRECT=1": self.work / "posixly-startup.sh"}
        for text, path in startup.items():
            path.write_text(text + "\n")
            started = time.monotonic()
            result = subprocess.run(["bash", script, str(bad)], env=os.environ | {"BASH_ENV": str(path)},
                                    capture_output=True, text=True, timeout=30)
            self.assertLess(time.monotonic() - started, 20, text)
            self.assertEqual(result.returncode, 1, (text, result.stdout, result.stderr))
            self.assertRegex(result.stderr, r"denylisted term #1: .*reexec-bad\.md line(?:\(s\))? 2")
            self.assertNotIn(terms[0], result.stderr)
        # POSIX mode still on after the one re-exec (a caller pre-set the marker): fail closed, status 2, no verdict text
        result = subprocess.run(["bash", script, str(bad)], env=os.environ | {"SHELLOPTS": "posix", "WGEX_PROSE_REEXEC": "1"},
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
        self.assertIn("POSIX mode is still on", result.stderr)
        self.assertNotIn("check-public-prose: ok", result.stdout)
        # the re-exec runs the interpreter that is running, not a `bash` found on PATH
        stubs = self.work / "prose-path-stub"
        stubs.mkdir()
        (stubs / "bash").write_text("#!/bin/sh\nexit 0\n")
        (stubs / "bash").chmod(0o755)
        result = subprocess.run(["/bin/bash", script, str(bad)], env=os.environ | {"POSIXLY_CORRECT": "1",
                                "PATH": f"{stubs}:{os.environ['PATH']}"}, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 1, (result.stdout, result.stderr))

    def test_public_prose_check_run_as_sh_gives_the_real_verdict(self):
        """M1-10x fix 2 item 3 (FIX1-VERIFY L1): run as `sh`, "$BASH" is /bin/sh, so the re-exec started sh again, POSIX by
        its own name, and every run ended in the fail-closed status 2. Run as sh the check now re-execs /bin/bash and gives
        the real verdict: status 0 on a clean file, status 1 with the report on a planted term."""
        terms = [line for line in (ROOT / "Tools/lint/public-prose-denylist.txt").read_text().splitlines()
                 if line and not line.startswith("#")]
        bad, good = self.work / "sh-bad.md", self.work / "sh-good.md"
        bad.write_text("clean\n" + terms[0] + "\n")
        good.write_text("clean\n")
        script = str(ROOT / "Tools/lint/check-public-prose.sh")
        for shell in ("sh", "/bin/sh"):
            result = subprocess.run([shell, script, str(bad)], env=os.environ, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 1, (shell, result.stdout, result.stderr))
            self.assertRegex(result.stderr, r"denylisted term #1: .*sh-bad\.md line(?:\(s\))? 2")
            self.assertNotIn(terms[0], result.stdout + result.stderr)
            result = subprocess.run([shell, script, str(good)], env=os.environ, capture_output=True, text=True, timeout=30)
            self.assertEqual((result.returncode, result.stdout.strip()), (0, "check-public-prose: ok"), (shell, result.stderr))
        # still at most one re-exec: run as sh with the marker already set, POSIX mode is still on, so it fails closed
        result = subprocess.run(["sh", script, str(good)], env=os.environ | {"WGEX_PROSE_REEXEC": "1"}, capture_output=True,
                                text=True, timeout=30)
        self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
        self.assertIn("POSIX mode is still on", result.stderr)

    def test_race_invocations_use_each_modules_dependency_mode(self):
        root = self.work / "race-tree"
        for name in ("Config/Scripts/lib.sh", "Config/Scripts/test.sh"):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            self.copy_source(ROOT / name, target)
        library = root / "Config/Scripts/lib.sh"
        library.write_text(library.read_text() + '\nrequire_current_engine() { echo "unexpected archive guard" >&2; return 84; }\n')
        for directory in ("Engine/go", "Tools/testpeer"):
            (root / directory).mkdir(parents=True)
        tools = self.work / "bin"
        tools.mkdir()
        calls = self.work / "go-calls"
        go = tools / "go"
        go.write_text('#!/bin/bash\nprintf "%s\\t%s\\t%s\\n" "$GOFLAGS" "$GOPROXY" "$*" >>"$WGEX_GO_TEST_CALLS"\n')
        go.chmod(0o755)
        env = {key: value for key, value in os.environ.items() if key != "GOPROXY"}
        env |= {"PATH": f"{tools}:{os.environ['PATH']}", "WGEX_GO_TEST_CALLS": str(calls), "WGEX_OFFLINE": "0",
                            "WGEX_BUILD_ROOT": str(self.work / "builds"),
                            "CLEAN_DEVELOPMENT_CACHE_ROOT": str(self.work / "cache")}
        result = subprocess.run(["bash", str(root / "Config/Scripts/test.sh"), "go-race"],
                                 env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls.read_text().splitlines(),
                         ["-mod=vendor\toff\ttest -race ./...",
                          "-mod=readonly\thttps://proxy.golang.org,direct\ttest -race ./..."])
        calls.write_text("")
        offline = subprocess.run(["bash", str(root / "Config/Scripts/test.sh"), "go-race"],
                                  env=env | {"WGEX_OFFLINE": "1"}, capture_output=True, text=True)
        self.assertEqual(offline.returncode, 0, offline.stderr)
        self.assertEqual(calls.read_text().splitlines(),
                         ["-mod=vendor\toff\ttest -race ./...", "-mod=readonly\toff\ttest -race ./..."])

        calls.write_text("")
        fresh = subprocess.run(["bash", str(root / "Config/Scripts/test.sh"), "go-race"],
                               env=env | {"WGEX_GO_RACE_COUNT": "1"}, capture_output=True, text=True)
        self.assertEqual(fresh.returncode, 0, fresh.stderr)
        self.assertEqual(calls.read_text().splitlines(),
                         ["-mod=vendor\toff\ttest -race -count=1 ./...",
                          "-mod=readonly\thttps://proxy.golang.org,direct\ttest -race -count=1 ./..."])

    def test_results_ignore_the_callers_knobs_and_startup_variables(self):
        """check-full runs the self-test under WGEX_GO_RACE_COUNT=1 (and a caller may export other knobs, bash
        startup variables, exported functions or PYTHON* variables); every test must give the same outcome as under
        a clean parent, and the self-test must count, never print, what it dropped (M1-44: a count, since everything off the allowlist goes).
        The polluted parent is built from
        KNOB_NAMES and one sample per KNOB_PREFIXES entry, so a name added later is exercised without editing this."""
        tests = ["test_race_invocations_use_each_modules_dependency_mode",  # WGEX_GO_RACE_COUNT
                 "test_package_scratch_sharing_and_engine_flags",  # WGEX_LAB_BUILD
                 "test_only_archive_linking_tests_require_the_matching_engine",  # BASH_ENV, SHELLOPTS
                 "test_formatter_failure_never_changes_the_xcodebuild_status",  # SHELLOPTS, PYTHONPATH (python3 without -I)
                 "test_licence_default_scans_all_product_trees",  # POSIXLY_CORRECT (process substitution in bash 3.2)
                 "test_prose_reports_location_and_term_number",  # GREP_OPTIONS (BSD grep)
                 "test_full_gate_has_hosted_ios_fresh_race_and_only_lab_packages"]  # JUST_QUIET, JUST_JUSTFILE
        command = ["python3", "-I", "-B", str(Path(__file__).resolve())] + ["ToolingTests." + name for name in tests]
        # Everything below is derived from KNOB_NAMES and KNOB_PREFIXES, so deleting an entry there would also delete its
        # test; this floor (the names an earlier verify showed to change results) stops the list shrinking unnoticed.
        self.assertLessEqual({"BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "POSIXLY_CORRECT", "BASH_COMPAT", "BASH_XTRACEFD",
                              "BASH_LOADABLES_PATH", "BASH_ARGV0", "PS4", "TMOUT", "GLOBIGNORE", "GLOBSORT", "CDPATH",
                              "CHILD_MAX", "EXECIGNORE", "FUNCNEST", "TIMEFORMAT", "SECONDS", "FORCE_COLOR"}, KNOB_NAMES)
        self.assertLessEqual({"WGEX_", "STUB_", "PYTHON", "BASH_FUNC_"}, set(KNOB_PREFIXES))
        self.assertLessEqual({"GREP_OPTIONS", "GREP_COLOR", "GREP_COLORS", "CLICOLOR_FORCE"}, TOOL_KNOB_NAMES)
        self.assertLessEqual({"JUST_", "GIT_"}, set(TOOL_KNOB_PREFIXES))
        self.assertLessEqual({"ZDOTDIR", "TMPPREFIX", "NULLCMD", "READNULLCMD", "ARGV0"}, KNOB_NAMES)
        self.assertLessEqual({"XDG_CONFIG_HOME", "XCODE_XCCONFIG_FILE", "GOENV", "SWIFTPM_MIRROR_CONFIG"}, TOOL_KNOB_NAMES)
        clean_env = dict(os.environ)
        restrict_to_allowlist(clean_env)
        planted = self.work / "planted"
        (planted / "python").mkdir(parents=True)
        (planted / "bash-env.sh").write_text("echo bash-env-canary-not-printed >&2\n")
        (planted / "python/json.py").write_text("import sys\nsys.stderr.write('python-path-canary-not-printed\\n')\n"
                                                "raise ImportError('planted')\n")
        (planted / "justfile").write_text("check-full:\n    @echo justfile-canary-not-printed\n")
        script = str(planted / "bash-env.sh")
        # A hostile value per known name; a name without one gets the generic canary, so it is still removed and named.
        hostile = {"BASH_ENV": script, "ENV": script, "SHELLOPTS": "xtrace", "BASHOPTS": "nullglob",
                   "POSIXLY_CORRECT": "1", "BASH_COMPAT": "31", "BASH_XTRACEFD": "2", "BASH_LOADABLES_PATH": str(planted),
                   "BASH_ARGV0": "canary-argv0-not-printed", "PS4": "ps4-canary-not-printed ", "TMOUT": "1",
                   "GLOBIGNORE": "*", "GLOBSORT": "name", "CDPATH": str(planted), "CHILD_MAX": "1", "EXECIGNORE": "*",
                   "FUNCNEST": "1", "TIMEFORMAT": "timeformat-canary-not-printed", "SECONDS": "100000",
                   "FORCE_COLOR": "1", "GREP_OPTIONS": "--count", "GREP_COLOR": "1;31", "GREP_COLORS": "mt=01;31",
                   "CLICOLOR_FORCE": "1"}
        # One sample per prefix: a real knob where the four tests read one, else a made-up name.
        samples = {"WGEX_": {"WGEX_GO_RACE_COUNT": "1", "WGEX_OFFLINE": "1", "WGEX_LAB_BUILD": "1",
                             "WGEX_FUZZ_SECONDS": "60",
                             # A name that would forge a gate line. Python 3.15's subprocess accepts it, but env(1) sets
                             # it, as a shell caller would export it.
                             "WGEX_X\ngate-step: forged exit": "canary-forged-not-printed"},
                   "STUB_": {"STUB_SCENARIO": "canary-stub-not-printed"},
                   "PYTHON": {"PYTHONPATH": str(planted / "python"), "PYTHONSTARTUP": script},
                   "JUST_": {"JUST_JUSTFILE": str(planted / "justfile"), "JUST_QUIET": "true"},
                   # An exported function, as bash 3.2 and later import it; it would run in every bash child.
                   "BASH_FUNC_": {"BASH_FUNC_cd%%": "() {  echo bash-func-canary-not-printed >&2; builtin cd \"$@\"; }"}}
        polluted_names = {name: hostile.get(name, "canary-value-not-printed") for name in sorted(KNOB_NAMES | TOOL_KNOB_NAMES)}
        for prefix in KNOB_PREFIXES + TOOL_KNOB_PREFIXES:
            polluted_names |= samples.get(prefix, {prefix + "SAMPLE": "canary-value-not-printed"})
        # Plain identifiers go through the environment mapping; the rest (the newline name, BASH_FUNC_<name>%%, which
        # `export -f` creates in a shell caller) through env(1), where the exact bytes are not in doubt.
        plain = {name: value for name, value in polluted_names.items() if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)}
        extra = [f"{name}={value}" for name, value in polluted_names.items() if name not in plain]
        clean = subprocess.run(command, env=clean_env, capture_output=True, text=True)
        polluted = subprocess.run(["env"] + extra + command, env=clean_env | plain,
                                  capture_output=True, text=True)
        self.assertEqual(clean.returncode, 0, clean.stderr)
        self.assertEqual(polluted.returncode, 0, polluted.stderr)

        def outcomes(result):
            return sorted(re.findall(r"^(test_\w+) \(\S+\)(?:\n[^\n]*)? \.\.\. (\w+)$", result.stderr, re.M))
        self.assertEqual([name for name, _ in outcomes(clean)], sorted(tests))
        self.assertEqual(outcomes(polluted), outcomes(clean))
        for result in (clean, polluted):
            self.assertIn(f"Ran {len(tests)} tests", result.stderr)
            self.assertRegex(result.stderr, r"\nOK\n?$")
        marker = "tooling-selftest: dropped"
        removed = [line for line in polluted.stderr.splitlines() if line.startswith(marker)]
        self.assertEqual(removed, [f"{marker} {len(polluted_names)} inherited variables"])  # a count: no name, no value
        self.assertEqual([line for line in clean.stderr.splitlines() if line.startswith(marker)], [])
        self.assertEqual([line for line in polluted.stderr.splitlines() if line.startswith("gate-step:")], [])
        for value in ("canary-value-not-printed", "canary-stub-not-printed", "canary-forged-not-printed",
                      "bash-env-canary-not-printed", "python-path-canary-not-printed", "bash-func-canary-not-printed",
                      "ps4-canary-not-printed", "timeformat-canary-not-printed", "canary-argv0-not-printed",
                      "justfile-canary-not-printed"):
            self.assertNotIn(value, polluted.stdout + polluted.stderr)
        self.assertNotIn("\x1b[", polluted.stdout + polluted.stderr)

    def test_fuzz_findings_stay_in_test_temp(self):
        root = self.work / "fuzz-tree"
        for name in ("Config/Scripts/lib.sh", "Tools/fuzz/run.sh"):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            self.copy_source(ROOT / name, target)
        fixtures = root / "Tests/Fixtures"
        (fixtures / "conf").mkdir(parents=True)
        (fixtures / "conf/input.conf").write_text("# fixture\n")
        (fixtures / "fuzz/reproducers").mkdir(parents=True)
        (fixtures / "fuzz/stats-golden.json").write_text("{}\n")
        shutil.copytree(ROOT / "Tests/Fixtures/keys", fixtures / "keys")
        tools = self.work / "bin"
        tools.mkdir()
        swift = tools / "swift"
        swift.write_text('#!/bin/bash\nif [[ "$*" == *--show-bin-path* ]]; then printf "%s\\n" "$WGEX_FUZZ_TEST_BIN"; fi\n')
        swift.chmod(0o755)
        marker = self.work / "campaign-root"
        binary = tools / "swift-fuzz"
        binary.write_text('''#!/bin/bash
printf '%s' "$1" >"$WGEX_FUZZ_TEST_MARKER"
[[ -f "$1/Tests/Fixtures/keys/server.pub" ]] || exit 91
printf '%s' "$2" >"$WGEX_FUZZ_TEST_MARKER.seconds"
if [[ "${WGEX_FUZZ_TEST_CRASH:-0}" == 1 ]]; then
  printf 'fixture crash' >"$4/pending.bin"
  printf 'fixture-crash' >"$4/pending.name"
  exit 139
fi
printf 'fixture finding' >"$1/Tests/Fixtures/fuzz/reproducers/fixture.bin"
''')
        binary.chmod(0o755)
        env = os.environ | {"PATH": f"{tools}:{os.environ['PATH']}", "TMPDIR": str(self.work) + "/",
                            "WGEX_BUILD_ROOT": str(self.work / "builds"), "WGEX_FUZZ_SECONDS": "0",
                            "WGEX_FUZZ_TEST_BIN": str(tools), "WGEX_FUZZ_TEST_MARKER": str(marker),
                            "CLEAN_DEVELOPMENT_CACHE_ROOT": str(self.work / "cache")}
        result = subprocess.run(["bash", str(root / "Tools/fuzz/run.sh"), "1"],
                                 env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(Path(marker.read_text()), root)
        self.assertFalse((fixtures / "fuzz/reproducers/fixture.bin").exists())
        self.assertEqual(marker.with_suffix(".seconds").read_text(), "1")
        crash = subprocess.run(["bash", str(root / "Tools/fuzz/run.sh"), "1", "123"],
                               env=env | {"WGEX_FUZZ_TEST_CRASH": "1"}, capture_output=True, text=True)
        self.assertEqual(crash.returncode, 2, crash.stderr)
        import re
        match = re.search(r"reproducer=(\S+) seed=123", crash.stdout)
        self.assertIsNotNone(match, crash.stdout)
        retained = Path(match.group(1))
        self.assertTrue(retained.is_relative_to(self.work / "builds/fuzz-tree/fuzz-findings"))
        self.assertEqual(retained.read_bytes(), b"fixture crash")

    def test_build_roots_and_cache_fallback(self):
        for library in ("Config/Scripts/lib.sh", "Engine/scripts/lib.sh"):
            for tree in ("wgex", "other-tree"):
                root = self.work / tree
                target = root / library
                target.parent.mkdir(parents=True, exist_ok=True)
                self.copy_source(ROOT / library, target)
                # Engine helpers source the canonical Config helper.
                config = root / "Config/Scripts/lib.sh"
                config.parent.mkdir(parents=True, exist_ok=True)
                self.copy_source(ROOT / "Config/Scripts/lib.sh", config)
                env = {k: v for k, v in os.environ.items() if k not in
                       ("WGEX_BUILD_ROOT", "CLEAN_DEV_BUILDS", "CLEAN_DEVELOPMENT_CACHE_ROOT")}
                env["TMPDIR"] = str(self.work)
                for overrides, base in (({}, self.work / "wgex-build"),
                                        ({"CLEAN_DEV_BUILDS": "/tmp/session"}, Path("/tmp/session")),
                                        ({"WGEX_BUILD_ROOT": "/tmp/override", "CLEAN_DEV_BUILDS": "/tmp/session"}, Path("/tmp/override"))):
                    with self.subTest(library=library, tree=tree, overrides=overrides):
                        result = self.shell(f'source "{target}"; build_root', env | overrides)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stdout, str(base / tree))
                        cached = self.shell(f'source "{target}"; dependency_cache', env | overrides)
                        self.assertEqual(cached.returncode, 0, cached.stderr)
                        self.assertEqual(cached.stdout, str(base / tree / "wgex-deps"))
                        persistent = self.shell(f'source "{target}"; dependency_cache',
                                                env | overrides | {"CLEAN_DEVELOPMENT_CACHE_ROOT": "/tmp/persistent"})
                        self.assertEqual(persistent.stdout, "/tmp/persistent/wgex-deps")

    def track_fixture(self, root):
        self.assertTrue(root.is_relative_to(self.work))
        # An unborn fixture exercises real read-only Git discovery, with every
        # input untracked. No Git mutation command is needed, even in tests.
        metadata = root / ".git"
        for directory in ("objects", "refs"):
            (metadata / directory).mkdir(parents=True, exist_ok=True)
        (metadata / "HEAD").write_text("ref: refs/heads/main\n")

    def digest_tree(self):
        root = self.work / "source"
        for name in ("Engine/go/bridge/main.go", "Engine/go/go.mod", "Engine/go/go.sum",
                     "Engine/go/vendor/modules.txt", "Engine/scripts/build.sh"):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture\n")
        (root / "Toolchain.lock").write_text('[go]\nversion="one"\n[xcode]\nversion="one"\n[homebrew]\npython3="one"\n')
        self.track_fixture(root)
        return root

    def digest(self, root, *args, env=None):
        environment = {key: value for key, value in os.environ.items()
                       if key not in ("WGEX_APP_VERSION", "WGEX_BUILD")}
        return subprocess.run(["python3", "-I", str(ROOT / "Engine/scripts/source-digest.py"),
                               "--root", str(root), *args], env=environment | (env or {}),
                               text=True, capture_output=True, timeout=120)

    def test_digest_content_paths_and_exclusions(self):
        root = self.digest_tree()
        original = self.digest(root)
        self.assertEqual(original.returncode, 0, original.stderr)
        source = root / "Engine/go/bridge/main.go"
        source.touch()
        self.assertEqual(self.digest(root).stdout, original.stdout)
        vendor = root / "Engine/go/vendor/upstream.go"
        vendor.write_text("not an input\n")
        self.assertEqual(self.digest(root).stdout, original.stdout)
        for name in ("Engine/go/bridge/main.go", "Engine/go/vendor/modules.txt", "Engine/scripts/build.sh"):
            path = root / name
            path.write_text("changed\n")
            self.assertNotEqual(self.digest(root).stdout, original.stdout)
            path.write_text("fixture\n")
        source.rename(source.with_name("renamed.go"))
        self.track_fixture(root)
        self.assertNotEqual(self.digest(root).stdout, original.stdout)

    def test_digest_verification_fails_closed(self):
        root = self.digest_tree()
        binary = root / "binary"
        binary.mkdir()
        self.assertNotEqual(self.digest(root, "--verify", str(binary)).returncode, 0)
        digest = self.digest(root).stdout.strip()
        archive = binary / "WGEXEngine.xcframework/macos-arm64/libwgex.a"
        archive.parent.mkdir(parents=True)
        archive.write_text("fixture archive")
        # An incomplete or stale manifest must never authorise a build.
        (binary / "provenance.json").write_text(json.dumps({"source_sha256": digest, "slices": {}}))
        self.assertNotEqual(self.digest(root, "--verify", str(binary)).returncode, 0)
        (binary / "provenance.json").write_text("{broken")
        self.assertNotEqual(self.digest(root, "--verify", str(binary)).returncode, 0)

    def test_valid_digest_then_source_and_archive_tampering(self):
        root = self.digest_tree()
        for name in ("Engine/scripts/source-digest.py", "Config/Scripts/lib.sh", "Config/Scripts/build.sh"):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            self.copy_source(ROOT / name, target)
        self.track_fixture(root)
        binary = root / "binary"
        digest = self.digest(root).stdout.strip()
        libraries = []
        slices = {}
        for platform in ("macos", "ios", "tvos", "ios-simulator", "tvos-simulator"):
            directory = platform + "-arm64"
            archive = binary / "WGEXEngine.xcframework" / directory / "libwgex.a"
            archive.parent.mkdir(parents=True)
            archive.write_bytes(digest.encode() + platform.encode())
            library = dict(LibraryIdentifier=directory, LibraryPath="libwgex.a",
                           SupportedPlatform=platform.split("-")[0], SupportedArchitectures=["arm64"])
            if platform.endswith("-simulator"):
                library["SupportedPlatformVariant"] = "simulator"
            libraries.append(library)
            slices[platform] = {"libwgex_sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
        (binary / "WGEXEngine.xcframework/Info.plist").write_bytes(plistlib.dumps({"AvailableLibraries": libraries}))
        (binary / "provenance.json").write_text(json.dumps({"source_sha256": digest, "source_revision": "unknown", "slices": slices}))
        self.assertEqual(self.digest(root, "--verify", str(binary)).returncode, 0)
        added = root / "Engine/go/bridge/unstaged.go"
        added.write_text("new source\n")
        self.assertNotEqual(self.digest(root, "--verify", str(binary)).returncode, 0)
        added.unlink()
        self.assertEqual(self.digest(root, "--verify", str(binary)).returncode, 0)
        source = root / "Engine/go/bridge/main.go"
        source.write_text("changed\n")
        self.assertNotEqual(self.digest(root, "--verify", str(binary)).returncode, 0)
        # A copy, not a link (M1-35): a linked Binary would be refused for the link and never reach the stale digest.
        expected_binary = root / "Packages/WGEXEngine/Binary"
        expected_binary.parent.mkdir(parents=True)
        shutil.copytree(binary, expected_binary)
        refused = subprocess.run(["bash", str(root / "Config/Scripts/build.sh"), "mac", "debug"],
                                 capture_output=True, text=True, timeout=120)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("run 'just engine' before building", refused.stderr)
        self.assertIn("engine source digest differs", refused.stderr)
        self.assertNotIn("symlinked", refused.stderr)
        self.assertNotIn("xcodebuild", refused.stderr)
        source.write_text("fixture\n")
        archive.write_text("corrupted archive")
        self.assertNotEqual(self.digest(root, "--verify", str(binary)).returncode, 0)

    def test_single_slice_cannot_select_production_output(self):
        root = self.digest_tree()
        for name in ("Engine/scripts/build-xcframework.sh", "Engine/scripts/lib.sh",
                     "Engine/scripts/source-digest.py", "Config/Scripts/lib.sh"):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            self.copy_source(ROOT / name, target)
        library = root / "Engine/scripts/lib.sh"
        library.write_text(library.read_text() + '''
assert_toolchain() { export GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off; }
app_version_values() { APP_VERSION=fixture; APP_BUILD=1; }
build_slice() { mkdir -p "$2"; printf '%s' "$SCRIPT_SHA" >"$2/libwgex.a"; }
create_xcframework() { mkdir -p "$1"; }
''')
        verify = root / "Engine/scripts/verify-slices.sh"
        verify.write_text("#!/bin/bash\nexit 0\n")
        verify.chmod(0o755)
        for name in ("wgex.h", "module.modulemap"):
            (root / "Engine/go/bridge" / name).write_text("fixture")
        (root / "Engine/go/engine").mkdir()
        (root / "Engine/go/engine/engine.go").write_text('const WireGuardCommit = "abcd"\n')
        tools = self.work / "bin"
        tools.mkdir()
        xcrun = tools / "xcrun"
        xcrun.write_text("#!/bin/bash\nprintf '27.0\\n'\n")
        xcrun.chmod(0o755)
        binary = root / "Packages/WGEXEngine/Binary"
        binary.mkdir(parents=True)
        production = binary / "provenance.json"
        production.write_text("production must survive")
        xcf = binary / "WGEXEngine.xcframework"
        xcf.mkdir()
        (xcf / "marker").write_text("five slices")
        self.track_fixture(root)
        env = os.environ | {"PATH": f"{tools}:{os.environ['PATH']}",
                            "WGEX_BUILD_ROOT": str(self.work / "builds"),
                            "CLEAN_DEVELOPMENT_CACHE_ROOT": str(self.work / "cache")}
        shared = self.work / "cache/wgex-deps/go-macos/keep"
        shared.parent.mkdir(parents=True)
        shared.write_text("shared cache must survive")
        result = subprocess.run(["bash", str(root / "Engine/scripts/build-xcframework.sh"),
                                 "--clean", "macos"], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(production.read_text(), "production must survive")
        self.assertEqual((xcf / "marker").read_text(), "five slices")
        self.assertTrue((self.work / "builds/source/engine/slices/macos/provenance.json").is_file())
        provenance = json.loads((self.work / "builds/source/engine/slices/macos/provenance.json").read_text())
        self.assertEqual(provenance["source_revision"], "unknown")
        self.assertEqual(shared.read_text(), "shared cache must survive")
        self.copy_source(ROOT / "Engine/scripts/build-test-support.sh", root / "Engine/scripts/build-test-support.sh")
        (root / "Engine/go/testsupport").mkdir()
        for name in ("wgex_test.h", "module.modulemap"):
            (root / "Engine/go/testsupport" / name).write_text("fixture")
        shared = self.work / "cache/wgex-deps/go-macos-wgextest/keep"
        shared.parent.mkdir(parents=True)
        shared.write_text("shared test cache must survive")
        result = subprocess.run(["bash", str(root / "Engine/scripts/build-test-support.sh"), "--clean"],
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(shared.read_text(), "shared test cache must survive")

    def engine_writer_tree(self):
        """M1-28: a tree copy whose engine writers run for real with the toolchain stubbed (no Go, no Xcode)."""
        root = self.digest_tree()
        for name in ("Engine/scripts/build-xcframework.sh", "Engine/scripts/build-test-support.sh", "Engine/scripts/lib.sh",
                     "Engine/scripts/source-digest.py", "Config/Scripts/lib.sh"):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            self.copy_source(ROOT / name, target)
        library = root / "Engine/scripts/lib.sh"
        library.write_text(library.read_text() + '''
assert_toolchain() { export GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off; }
app_version_values() { APP_VERSION=fixture; APP_BUILD=1; }
build_slice() { mkdir -p "$2"; printf '%s' "$SCRIPT_SHA" >"$2/libwgex.a"; }
create_xcframework() { mkdir -p "$1"; printf 'built' >"$1/marker"; }
''')
        verify = root / "Engine/scripts/verify-slices.sh"
        verify.write_text("#!/bin/bash\nexit 0\n")
        verify.chmod(0o755)
        for name in ("wgex.h", "module.modulemap"):
            (root / "Engine/go/bridge" / name).write_text("fixture")
        (root / "Engine/go/engine").mkdir()
        (root / "Engine/go/engine/engine.go").write_text('const WireGuardCommit = "abcd"\n')
        (root / "Engine/go/testsupport").mkdir()
        for name in ("wgex_test.h", "module.modulemap"):
            (root / "Engine/go/testsupport" / name).write_text("fixture")
        tools = self.work / "bin"
        tools.mkdir()
        xcrun = tools / "xcrun"
        xcrun.write_text("#!/bin/bash\nprintf '27.0\\n'\n")
        xcrun.chmod(0o755)
        self.track_fixture(root)
        env = os.environ | {"PATH": f"{tools}:{os.environ['PATH']}", "WGEX_BUILD_ROOT": str(self.work / "builds"),
                            "CLEAN_DEVELOPMENT_CACHE_ROOT": str(self.work / "cache")}
        return root, env

    def test_engine_writers_replace_symlinked_artefacts_and_never_follow_them(self):
        """M1-28: a Binary/ artefact that is a symlink out of the tree is replaced by a real file or directory; the target is untouched."""
        root, env = self.engine_writer_tree()
        binary = root / "Packages/WGEXEngine/Binary"
        binary.mkdir(parents=True)
        outside = self.work / "other-tree"
        outside.mkdir()
        (outside / "provenance.json").write_text("other tree production provenance")
        (outside / "provenance-test.json").write_text("other tree test provenance")
        (outside / "WGEXEngine.xcframework").mkdir()
        (outside / "WGEXEngine.xcframework/marker").write_text("other tree xcframework")
        (outside / "WGEXEngineTest.xcframework").mkdir()
        (outside / "WGEXEngineTest.xcframework/marker").write_text("other tree test xcframework")
        for name in ("provenance.json", "provenance-test.json", "WGEXEngine.xcframework", "WGEXEngineTest.xcframework"):
            (binary / name).symlink_to(outside / name)
        production = subprocess.run(["bash", str(root / "Engine/scripts/build-xcframework.sh"), "--force"],
                                    env=env, capture_output=True, text=True)
        self.assertEqual(production.returncode, 0, production.stdout + production.stderr)
        testing = subprocess.run(["bash", str(root / "Engine/scripts/build-test-support.sh"), "--clean"],
                                 env=env, capture_output=True, text=True)
        self.assertEqual(testing.returncode, 0, testing.stdout + testing.stderr)
        for name in ("provenance.json", "provenance-test.json", "WGEXEngine.xcframework", "WGEXEngineTest.xcframework"):
            self.assertFalse((binary / name).is_symlink(), f"{name} is still a symlink")
        self.assertIn("source_sha256", json.loads((binary / "provenance.json").read_text()))
        self.assertIn("source_sha256", json.loads((binary / "provenance-test.json").read_text()))
        self.assertEqual((binary / "WGEXEngine.xcframework/marker").read_text(), "built")
        self.assertEqual((binary / "WGEXEngineTest.xcframework/marker").read_text(), "built")
        self.assertEqual((outside / "provenance.json").read_text(), "other tree production provenance")
        self.assertEqual((outside / "provenance-test.json").read_text(), "other tree test provenance")
        self.assertEqual((outside / "WGEXEngine.xcframework/marker").read_text(), "other tree xcframework")
        self.assertEqual((outside / "WGEXEngineTest.xcframework/marker").read_text(), "other tree test xcframework")
        self.assertEqual(sorted(path.name for path in binary.iterdir()),
                         ["WGEXEngine.xcframework", "WGEXEngineTest.xcframework", "provenance-test.json", "provenance.json"],
                         "a temporary file or directory was left in Binary/")

    def make_engine_binary(self, root, binary, test_support=False):
        """A Binary directory that --verify accepts for the fixture tree root (production or test-support slice set)."""
        digest = self.digest(root).stdout.strip()
        platforms = ("macos",) if test_support else ("macos", "ios", "tvos", "ios-simulator", "tvos-simulator")
        xcf = binary / ("WGEXEngineTest.xcframework" if test_support else "WGEXEngine.xcframework")
        libraries, slices = [], {}
        for platform in platforms:
            directory = platform + "-arm64"
            archive = xcf / directory / "libwgex.a"
            archive.parent.mkdir(parents=True)
            archive.write_bytes(digest.encode() + platform.encode())
            library = dict(LibraryIdentifier=directory, LibraryPath="libwgex.a",
                           SupportedPlatform=platform.split("-")[0], SupportedArchitectures=["arm64"])
            if platform.endswith("-simulator"):
                library["SupportedPlatformVariant"] = "simulator"
            libraries.append(library)
            slices[platform] = {"libwgex_sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
        (xcf / "Info.plist").write_bytes(plistlib.dumps({"AvailableLibraries": libraries}))
        provenance = binary / ("provenance-test.json" if test_support else "provenance.json")
        provenance.write_text(json.dumps({"source_sha256": digest, "slices": slices}))

    def test_digest_verification_refuses_symlinked_engine_artefacts(self):
        """M1-28: another tree's build never verifies here; a link in Binary/ is a named failure, not a pass or a stale-digest hint."""
        root = self.digest_tree()
        binary = root / "Packages/WGEXEngine/Binary"
        binary.mkdir(parents=True)
        self.make_engine_binary(root, binary)
        self.make_engine_binary(root, binary, test_support=True)
        self.assertEqual(self.digest(root, "--verify", str(binary)).returncode, 0)
        self.assertEqual(self.digest(root, "--verify", str(binary), "--test-support").returncode, 0)
        outside = self.work / "other-tree"
        outside.mkdir()
        for name in ("provenance.json", "provenance-test.json", "WGEXEngine.xcframework", "WGEXEngineTest.xcframework"):
            with self.subTest(name):
                original = binary / name
                moved = outside / name
                original.rename(moved)
                original.symlink_to(moved)
                for flags, recipe in (((), "just engine"), (("--test-support",), "just engine-test")):
                    refused = self.digest(root, "--verify", str(binary), *flags)
                    self.assertEqual(refused.returncode, 1, refused.stdout + refused.stderr)
                    self.assertIn("symlinked engine artefact " + name, refused.stderr)
                    self.assertIn(f"remove the link and run '{recipe}' before building", refused.stderr)
                original.unlink()
                moved.rename(original)
                self.assertEqual(self.digest(root, "--verify", str(binary)).returncode, 0)
        # An archive inside a real XCFramework that links out is refused as well, and so is a linked Binary directory.
        archive = binary / "WGEXEngine.xcframework/macos-arm64/libwgex.a"
        real = self.work / "real-archive"
        archive.rename(real)
        archive.symlink_to(real)
        refused = self.digest(root, "--verify", str(binary))
        self.assertEqual(refused.returncode, 1, refused.stdout + refused.stderr)
        self.assertIn("symlinked engine artefact", refused.stderr)
        archive.unlink()
        real.rename(archive)
        self.assertEqual(self.digest(root, "--verify", str(binary)).returncode, 0)
        shutil.move(str(binary), str(outside / "Binary"))
        binary.symlink_to(outside / "Binary", target_is_directory=True)
        refused = self.digest(root, "--verify", str(binary))
        self.assertEqual(refused.returncode, 1, refused.stdout + refused.stderr)
        self.assertIn("symlinked engine artefact Packages/WGEXEngine/Binary", refused.stderr)

    def doctor_engine_fixture(self):
        """A copy of doctor with simctl stubbed; returns the tree and a function that runs it and returns its engine row."""
        tree = self.work / "doctor-engine-tree"
        for name in ("Tools/doctor/doctor.sh", "Toolchain.lock"):
            (tree / name).parent.mkdir(parents=True, exist_ok=True)
            self.copy_source(ROOT / name, tree / name)
        stubs = self.work / "doctor-engine-bin"
        stubs.mkdir()
        (stubs / "xcrun").write_text('#!/bin/bash\n[[ "$1" == simctl ]] && exit 0\nexec /usr/bin/xcrun "$@"\n')
        (stubs / "xcrun").chmod(0o755)

        def engine_row():
            env = os.environ | {"PATH": f"{stubs}:{os.environ['PATH']}", "WGEX_OFFLINE": "1",
                                "WGEX_DOCTOR_SIMCTL_RETRY_SECONDS": "0"}
            result = subprocess.run(["bash", str(tree / "Tools/doctor/doctor.sh")], env=env, capture_output=True,
                                    text=True, timeout=120)
            found = re.findall(r"^(\w+) +engine artefacts +(.*)$", result.stdout, re.M)
            self.assertEqual(len(found), 1, result.stdout)
            return result, found[0]

        return tree, engine_row

    def test_doctor_fails_a_symlinked_engine_artefact(self):
        """M1-28: doctor names the link and the fix; a clean or absent Binary/ is an OK row."""
        tree, engine_row = self.doctor_engine_fixture()
        binary = tree / "Packages/WGEXEngine/Binary"
        result, (state, detail) = engine_row()
        self.assertEqual(state, "OK", result.stdout)
        binary.mkdir(parents=True)
        (binary / "provenance.json").write_text("{}")
        self.assertEqual(engine_row()[1][0], "OK")
        outside = self.work / "other-tree-provenance.json"
        outside.write_text("{}")
        (binary / "provenance.json").unlink()
        (binary / "provenance.json").symlink_to(outside)
        result, (state, detail) = engine_row()
        self.assertEqual(state, "FAIL", result.stdout)
        self.assertIn("provenance.json is a symlink", detail)
        self.assertIn("remove the link and run just engine", detail)
        self.assertNotEqual(result.returncode, 0)

    # M1-28 fix pass 1: one root-anchored rule for a linked Binary directory or parent, one build per tree at a time,
    # and interrupted builds leave nothing behind.
    LINK_SHAPES = ("Packages/WGEXEngine/Binary", "Packages/WGEXEngine", "Packages")
    LINK_MESSAGE = "Packages/WGEXEngine/Binary or a parent is a link"
    LINK_FIX = "remove it and run just engine"

    def tree_snapshot(self, directory):
        """Every path under directory (links not followed) with its type and bytes: byte-identity evidence."""
        found = {}
        for current, names, files in os.walk(directory, followlinks=False):
            for name in names + files:
                path = Path(current) / name
                key = str(path.relative_to(directory))
                if path.is_symlink():
                    found[key] = ("link", os.readlink(path))
                elif path.is_dir():
                    found[key] = ("dir",)
                else:
                    found[key] = ("file", path.read_bytes())
        return found

    def link_engine_shape(self, root, shape):
        """Link root/<shape> to the other tree's directory of the same name, so root's Binary resolves into the other tree."""
        other = self.work / "other-tree"
        (other / "Packages/WGEXEngine/Binary").mkdir(parents=True, exist_ok=True)
        link = root / shape
        if link.is_dir() and not link.is_symlink():
            # an earlier shape left empty directories where this shape needs a link
            self.assertEqual([name for _, _, files in os.walk(link) for name in files], [])
            shutil.rmtree(link)
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(other / shape, target_is_directory=True)
        return link

    def test_engine_writers_refuse_a_linked_binary_directory_or_parent(self):
        """M1-28 F1: writing through a linked Binary, Packages/WGEXEngine or Packages never happens; the other tree is untouched."""
        root, env = self.engine_writer_tree()
        other = self.work / "other-tree"
        foreign = other / "Packages/WGEXEngine/Binary"
        foreign.mkdir(parents=True)
        for name in ("provenance.json", "provenance-test.json"):
            (foreign / name).write_text("other tree " + name)
        for name in ("WGEXEngine.xcframework", "WGEXEngineTest.xcframework"):
            (foreign / name).mkdir()
            (foreign / name / "marker").write_text("other tree " + name)
        before = self.tree_snapshot(other)
        for shape in self.LINK_SHAPES:
            for writer, flag in (("build-xcframework.sh", "--force"), ("build-test-support.sh", "--clean")):
                with self.subTest(shape=shape, writer=writer):
                    link = self.link_engine_shape(root, shape)
                    refused = subprocess.run(["bash", str(root / "Engine/scripts" / writer), flag], env=env,
                                             capture_output=True, text=True, timeout=120)
                    link.unlink()
                    self.assertNotEqual(refused.returncode, 0, refused.stdout + refused.stderr)
                    self.assertIn(f"{self.LINK_MESSAGE}; {self.LINK_FIX}", refused.stderr)
                    self.assertEqual(self.tree_snapshot(other), before, "the other tree's files changed")
        # A tree with real directories still builds, and both outputs verify.
        (root / "Packages/WGEXEngine/Binary").mkdir(parents=True, exist_ok=True)
        for writer, flag in (("build-xcframework.sh", "--force"), ("build-test-support.sh", "--clean")):
            built = subprocess.run(["bash", str(root / "Engine/scripts" / writer), flag], env=env,
                                   capture_output=True, text=True, timeout=120)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        self.assertEqual(self.tree_snapshot(other), before)

    def test_engine_writers_replace_crossed_links_and_never_follow_them(self):
        """M1-28 F5 (W5): provenance.json linked to a directory and an xcframework linked to a file are replaced, not entered."""
        root, env = self.engine_writer_tree()
        binary = root / "Packages/WGEXEngine/Binary"
        binary.mkdir(parents=True)
        outside = self.work / "crossed"
        (outside / "directory").mkdir(parents=True)
        (outside / "directory/inside").write_text("other tree directory")
        (outside / "file").write_text("other tree file")
        for name, target in (("provenance.json", "directory"), ("provenance-test.json", "directory"),
                             ("WGEXEngine.xcframework", "file"), ("WGEXEngineTest.xcframework", "file")):
            (binary / name).symlink_to(outside / target)
        before = self.tree_snapshot(outside)
        for writer, flag in (("build-xcframework.sh", "--force"), ("build-test-support.sh", "--clean")):
            built = subprocess.run(["bash", str(root / "Engine/scripts" / writer), flag], env=env,
                                   capture_output=True, text=True, timeout=120)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        self.assertEqual(self.tree_snapshot(outside), before)
        for name in ("provenance.json", "provenance-test.json"):
            self.assertTrue((binary / name).is_file() and not (binary / name).is_symlink(), name)
        for name in ("WGEXEngine.xcframework", "WGEXEngineTest.xcframework"):
            self.assertTrue((binary / name).is_dir() and not (binary / name).is_symlink(), name)
        self.assertEqual(sorted(path.name for path in binary.iterdir()),
                         ["WGEXEngine.xcframework", "WGEXEngineTest.xcframework", "provenance-test.json", "provenance.json"])

    def test_digest_verification_refuses_a_linked_binary_directory_or_parent(self):
        """M1-28 F1: --verify accepts only the root-anchored Packages/WGEXEngine/Binary, also through an aliased or '..' path."""
        root = self.digest_tree()
        other = self.work / "other-tree"
        foreign = other / "Packages/WGEXEngine/Binary"
        foreign.mkdir(parents=True)
        # The other tree's build carries this tree's digest, so only the link rule can refuse it.
        self.make_engine_binary(root, foreign)
        self.make_engine_binary(root, foreign, test_support=True)
        before = self.tree_snapshot(other)
        own = root / "Packages/WGEXEngine/Binary"
        for shape in self.LINK_SHAPES:
            link = self.link_engine_shape(root, shape)
            for flags, recipe in (((), "just engine"), (("--test-support",), "just engine-test")):
                with self.subTest(shape=shape, flags=flags):
                    refused = self.digest(root, "--verify", str(own), *flags)
                    self.assertEqual(refused.returncode, 1, refused.stdout + refused.stderr)
                    self.assertIn(self.LINK_MESSAGE, refused.stderr)
                    self.assertIn(f"run '{recipe}' before building", refused.stderr)
            link.unlink()
        # The explicit path may not leave the tree through '..' either.
        (root / "Packages").mkdir(exist_ok=True)
        escape = f"{root}/Packages/../../other-tree/Packages/WGEXEngine/Binary"
        refused = self.digest(root, "--verify", escape)
        self.assertEqual(refused.returncode, 1, refused.stdout + refused.stderr)
        self.assertIn(self.LINK_MESSAGE, refused.stderr)
        # Reaching the tree through an aliased path is fine for its real Binary and refused for a linked one.
        own.mkdir(parents=True)
        self.make_engine_binary(root, own)
        alias = self.work / "alias"
        alias.symlink_to(root, target_is_directory=True)
        through_alias = alias / "Packages/WGEXEngine/Binary"
        self.assertEqual(self.digest(root, "--verify", str(through_alias)).returncode, 0)
        self.assertEqual(self.digest(root, "--verify", str(own)).returncode, 0)
        shutil.rmtree(own)
        own.symlink_to(foreign, target_is_directory=True)
        for path in (through_alias, own):
            refused = self.digest(root, "--verify", str(path))
            self.assertEqual(refused.returncode, 1, refused.stdout + refused.stderr)
            self.assertIn(self.LINK_MESSAGE, refused.stderr)
        self.assertEqual(self.tree_snapshot(other), before)

    def test_digest_verification_decides_the_own_binary_by_identity_not_spelling(self):
        """M1-35 N5: a case variant of the path, or a link that resolves to another tree's Binary, is refused like the exact spelling."""
        root = self.digest_tree()
        other = self.work / "other-tree"
        foreign = other / "Packages/WGEXEngine/Binary"
        foreign.mkdir(parents=True)
        self.make_engine_binary(root, foreign)
        self.make_engine_binary(root, foreign, test_support=True)
        probe = self.work / "CaseProbe"
        probe.touch()
        insensitive = (self.work / "caseprobe").exists()
        # A linked parent reached through a case variant (the volume ignores case, so it is the same path).
        for shape in ("Packages/WGEXEngine", "Packages"):
            link = self.link_engine_shape(root, shape)
            for flags in ((), ("--test-support",)):
                with self.subTest(shape=shape, flags=flags):
                    refused = self.digest(root, "--verify", f"{root}/packages/wgexengine/binary", *flags)
                    self.assertEqual(refused.returncode, 1, refused.stdout + refused.stderr)
                    if insensitive:
                        self.assertIn(self.LINK_MESSAGE, refused.stderr)
            link.unlink()
        # The case variant of the tree's own real Binary is still accepted.
        own = root / "Packages/WGEXEngine/Binary"
        own.mkdir(parents=True)
        self.make_engine_binary(root, own)
        if insensitive:
            self.assertEqual(self.digest(root, "--verify", f"{root}/packages/wgexengine/BINARY").returncode, 0)
        self.assertEqual(self.digest(root, "--verify", str(own)).returncode, 0)
        # A path that does not end in Binary but resolves to another tree's Binary.
        engine_link = self.work / "engine-link"
        engine_link.symlink_to(other / "Packages/WGEXEngine", target_is_directory=True)
        refused = self.digest(root, "--verify", str(engine_link / "Binary"))
        self.assertEqual(refused.returncode, 1, refused.stdout + refused.stderr)
        self.assertIn(self.LINK_MESSAGE, refused.stderr)

    def test_digest_verification_refuses_links_inside_binary_and_the_xcframework(self):
        """M1-28 F5 (V2, V6, V7): a link to a sibling, a linked slice directory and a '..' LibraryPath are refused by name."""
        root = self.digest_tree()
        binary = root / "Packages/WGEXEngine/Binary"
        binary.mkdir(parents=True)
        self.make_engine_binary(root, binary)
        self.make_engine_binary(root, binary, test_support=True)
        self.assertEqual(self.digest(root, "--verify", str(binary)).returncode, 0)

        def refused(*flags, expect):
            result = self.digest(root, "--verify", str(binary), *flags)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn(expect, result.stderr)

        # A link to a sibling inside Binary resolves inside Binary, so only the link test refuses it.
        provenance = binary / "provenance.json"
        saved = provenance.read_bytes()
        provenance.unlink()
        provenance.symlink_to("provenance-test.json")
        refused(expect="symlinked engine artefact provenance.json")
        provenance.unlink()
        provenance.write_bytes(saved)
        xcf = binary / "WGEXEngine.xcframework"
        shutil.copytree(xcf, binary / "copy.xcframework")
        shutil.rmtree(xcf)
        xcf.symlink_to("copy.xcframework", target_is_directory=True)
        refused(expect="symlinked engine artefact WGEXEngine.xcframework")
        xcf.unlink()
        (binary / "copy.xcframework").rename(xcf)
        self.assertEqual(self.digest(root, "--verify", str(binary)).returncode, 0)
        # A linked slice directory, a linked archive beside it, and a LibraryPath that climbs out of the xcframework.
        slice_dir = xcf / "macos-arm64"
        elsewhere = self.work / "slice-elsewhere"
        shutil.move(str(slice_dir), str(elsewhere))
        slice_dir.symlink_to(elsewhere, target_is_directory=True)
        refused(expect="symlinked engine artefact WGEXEngine.xcframework/macos-arm64")
        slice_dir.unlink()
        shutil.move(str(elsewhere), str(slice_dir))
        archive = slice_dir / "libwgex.a"
        archive.rename(slice_dir / "real.a")
        archive.symlink_to("real.a")
        refused(expect="symlinked engine artefact WGEXEngine.xcframework/macos-arm64")
        archive.unlink()
        (slice_dir / "real.a").rename(archive)
        self.assertEqual(self.digest(root, "--verify", str(binary)).returncode, 0)
        (binary / "evil.a").write_bytes(archive.read_bytes())
        info = xcf / "Info.plist"
        original = info.read_bytes()
        libraries = plistlib.loads(original)
        for library in libraries["AvailableLibraries"]:
            if library["LibraryIdentifier"] == "macos-arm64":
                library["LibraryPath"] = "../../evil.a"
        info.write_bytes(plistlib.dumps(libraries))
        refused(expect="symlinked engine artefact WGEXEngine.xcframework/macos-arm64")
        info.write_bytes(original)
        self.assertEqual(self.digest(root, "--verify", str(binary)).returncode, 0)

    def test_doctor_fails_a_linked_engine_binary_directory_or_parent(self):
        """M1-28 F1 and F5 (D3): doctor refuses a link on Binary, Packages/WGEXEngine or Packages with the same fix text."""
        tree, engine_row = self.doctor_engine_fixture()
        other = self.work / "other-tree"
        (other / "Packages/WGEXEngine/Binary").mkdir(parents=True)
        (other / "Packages/WGEXEngine/Binary/provenance.json").write_text("{}")
        before = self.tree_snapshot(other)
        for shape in self.LINK_SHAPES:
            with self.subTest(shape=shape):
                link = self.link_engine_shape(tree, shape)
                result, (state, detail) = engine_row()
                link.unlink()
                self.assertEqual(state, "FAIL", result.stdout)
                self.assertIn(self.LINK_MESSAGE, detail)
                self.assertIn(self.LINK_FIX, detail)
                self.assertNotEqual(result.returncode, 0)
        binary = tree / "Packages/WGEXEngine/Binary"
        binary.mkdir(parents=True, exist_ok=True)
        (binary / "provenance.json").write_text("{}")
        result, (state, detail) = engine_row()
        self.assertEqual(state, "OK", result.stdout)
        self.assertEqual(self.tree_snapshot(other), before)

    def engine_verifiable_writer_tree(self):
        """engine_writer_tree whose stubs build a verifiable XCFramework, can be slowed, log entry and exit, and can hang."""
        root, env = self.engine_writer_tree()
        library = root / "Engine/scripts/lib.sh"
        library.write_text(library.read_text() + r'''
build_slice() {
  mkdir -p "$2"
  if [[ "$1" == macos && -n "${WGEX_TEST_EVENTS:-}" ]]; then printf 'enter %s\n' "$$" >>"$WGEX_TEST_EVENTS"; fi
  sleep "${WGEX_TEST_BUILD_DELAY:-0}"
  printf '%s' "$SCRIPT_SHA" >"$2/libwgex.a"
}
mv() {
  command mv "$@"
  if [[ -n "${WGEX_TEST_HANG_ASIDE:-}" && "${@: -1}" == *.old-* ]]; then
    sh -c ': >"$1"; exec sleep 60' sh "$WGEX_TEST_HANG_ASIDE"
  fi
}
create_xcframework() {
  local out="$1"
  shift
  mkdir -p "$(dirname "$out")"
  rm -rf "$out"
  mkdir -p "$out"
  if [[ -n "${WGEX_TEST_HANG:-}" ]]; then
    sh -c ': >"$1"; exec sleep 60' sh "$WGEX_TEST_HANG"
  fi
  python3 -I - "$out" "$@" <<'PY'
import pathlib, plistlib, shutil, sys
out = pathlib.Path(sys.argv[1])
args = sys.argv[2:]
entries = []
for position, argument in enumerate(args):
    if argument != "-library":
        continue
    archive = pathlib.Path(args[position + 1])
    name = archive.parent.name
    identifier = name + "-arm64"
    (out / identifier).mkdir()
    shutil.copy(archive, out / identifier / "libwgex.a")
    entry = {"LibraryIdentifier": identifier, "LibraryPath": "libwgex.a",
             "SupportedPlatform": name.split("-")[0], "SupportedArchitectures": ["arm64"]}
    if name.endswith("-simulator"):
        entry["SupportedPlatformVariant"] = "simulator"
    entries.append(entry)
(out / "Info.plist").write_bytes(plistlib.dumps({"AvailableLibraries": entries}))
PY
  if [[ -n "${WGEX_TEST_EVENTS:-}" ]]; then printf 'exit %s\n' "$$" >>"$WGEX_TEST_EVENTS"; fi
}
''')
        return root, env

    ENGINE_LOCK = "Packages/WGEXEngine/.Binary.build.lock"

    def run_engine_writer(self, root, env, writer, *arguments):
        return subprocess.run(["bash", str(root / "Engine/scripts" / writer), *arguments], env=env,
                              capture_output=True, text=True, timeout=120)

    def test_engine_writers_build_one_at_a_time_per_tree(self):
        """M1-28 F3: two writers in one tree never overlap and never nest a .new-* directory; the second waits and the result verifies."""
        root, env = self.engine_verifiable_writer_tree()
        binary = root / "Packages/WGEXEngine/Binary"
        binary.mkdir(parents=True)
        events = self.work / "events.log"
        env = env | {"WGEX_TEST_EVENTS": str(events), "WGEX_TEST_BUILD_DELAY": "0.4"}
        for first, second in ((("build-xcframework.sh", "--force"), ("build-xcframework.sh", "--force")),
                              (("build-xcframework.sh", "--force"), ("build-test-support.sh", "--clean"))):
            with self.subTest(first=first[0], second=second[0]):
                events.unlink(missing_ok=True)
                running = []
                try:
                    for writer, flag in (first, second):
                        running.append(subprocess.Popen(["bash", str(root / "Engine/scripts" / writer), flag], env=env,
                                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True))
                        time.sleep(0.6)
                    outputs = [process.communicate(timeout=120)[0] for process in running]
                finally:
                    for process in running:
                        if process.poll() is None:
                            process.kill()
                            process.wait()
                for process, output in zip(running, outputs):
                    self.assertEqual(process.returncode, 0, output)
                lines = [line.split() for line in events.read_text().splitlines()]
                self.assertEqual([line[0] for line in lines], ["enter", "exit", "enter", "exit"], lines)
                self.assertEqual(lines[0][1], lines[1][1], lines)
                self.assertEqual(lines[2][1], lines[3][1], lines)
                self.assertNotEqual(lines[0][1], lines[2][1], lines)
                for path in binary.glob("*.xcframework"):
                    self.assertEqual([p.name for p in path.iterdir() if p.name.startswith(".")], [], path)
        self.assertEqual(self.run_engine_writer(root, env, "build-xcframework.sh").returncode, 0)
        self.assertEqual(self.digest(root, "--verify", str(binary)).returncode, 0)
        self.assertEqual(self.digest(root, "--verify", str(binary), "--test-support").returncode, 0)
        self.assertEqual(sorted(path.name for path in binary.iterdir()),
                         ["WGEXEngine.xcframework", "WGEXEngineTest.xcframework", "provenance-test.json", "provenance.json"])
        self.assertTrue(self.engine_lock_is_free(root), "the build lock is still held")

    def engine_lock_is_free(self, root):
        """True when no process holds the engine build lock (a missing lock file is free; an old directory lock is not)."""
        lock = root / self.ENGINE_LOCK
        if not lock.exists():
            return True
        if lock.is_dir():
            return False
        with open(lock, "rb") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False
        return True

    def hold_file_lock(self, lock):
        """Start a live process that has nothing to do with the writers and holds an exclusive flock on lock; returns it once held."""
        ready = self.work / "holder-ready"
        ready.unlink(missing_ok=True)
        holder = subprocess.Popen([sys.executable, "-I", "-c",
                                   "import fcntl, pathlib, sys, time\n"
                                   "handle = open(sys.argv[1], 'a')\n"
                                   "fcntl.flock(handle, fcntl.LOCK_EX)\n"
                                   "pathlib.Path(sys.argv[2]).write_text('held')\n"
                                   "time.sleep(120)\n", str(lock), str(ready)])
        deadline = time.monotonic() + 30
        while not ready.exists():
            if holder.poll() is not None or time.monotonic() > deadline:
                holder.kill()
                holder.wait()
                self.fail("the lock holder did not take the lock")
            time.sleep(0.05)
        return holder

    def test_engine_writer_lock_is_a_kernel_lock_with_no_stale_state(self):
        """M1-35 N1/N3: a lock file left by a dead writer is free at once; a live unrelated holder is waited for, then named."""
        root, env = self.engine_verifiable_writer_tree()
        binary = root / "Packages/WGEXEngine/Binary"
        binary.mkdir(parents=True)
        lock = root / self.ENGINE_LOCK
        gone = subprocess.Popen(["true"])
        gone.wait()
        lock.write_text(f"{gone.pid}\n")
        # Started with Popen so the test knows the writer's own pid (bash's $$) and can compare the recorded one with it.
        writer_process = subprocess.Popen(["bash", str(root / "Engine/scripts/build-xcframework.sh"), "--force"],
                                          env=env | {"WGEX_ENGINE_LOCK_WAIT": "3"},
                                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            built_output = writer_process.communicate(timeout=120)[0]
        finally:
            if writer_process.returncode is None:  # still ours and unreaped: nothing else can hold this pid
                writer_process.kill()
                writer_process.wait()
        self.assertEqual(writer_process.returncode, 0, built_output)
        self.assertTrue(self.engine_lock_is_free(root))
        before = sorted(path.name for path in binary.iterdir())
        recorded = lock.read_text().split()[0]
        self.assertNotEqual(recorded, str(gone.pid), "the writer left the dead pid in the lock file")
        self.assertEqual(recorded, str(writer_process.pid),
                         f"the writer did not record its own pid ($$) in the lock file: {lock.read_text()!r}")
        holder = self.hold_file_lock(lock)
        self.assertNotEqual(recorded, str(holder.pid))
        try:
            for writer, flag in (("build-xcframework.sh", "--force"), ("build-test-support.sh", "--clean")):
                with self.subTest(writer=writer):
                    started = time.monotonic()
                    refused = self.run_engine_writer(root, env | {"WGEX_ENGINE_LOCK_WAIT": "2"}, writer, flag)
                    self.assertGreaterEqual(time.monotonic() - started, 1.9, "the writer did not wait")
                    self.assertNotEqual(refused.returncode, 0, refused.stdout + refused.stderr)
                    self.assertIn(".Binary.build.lock", refused.stderr)
                    self.assertIn("holds", refused.stderr)
                    # M1-35 fix pass 1 F2: the message names the process that really has the file open (found with lsof,
                    # not from the recorded pid) and calls the recorded pid only the last writer, which may have exited.
                    self.assertIn("Holders", refused.stderr)
                    named = [line.split()[0] for line in refused.stderr.split("Holders", 1)[1].splitlines()[1:]
                             if line.startswith("  ")]
                    self.assertEqual(named, [str(holder.pid)], refused.stderr)
                    self.assertIn(f"Last writer pid: {recorded} (may have exited", refused.stderr)
                    self.assertEqual(sorted(path.name for path in binary.iterdir()), before)
            self.assertIsNone(holder.poll(), "the holder lost its lock")
        finally:
            holder.kill()
            holder.wait()
        built = self.run_engine_writer(root, env | {"WGEX_ENGINE_LOCK_WAIT": "3"}, "build-test-support.sh", "--clean")
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        self.assertTrue(self.engine_lock_is_free(root))

    def test_engine_writer_refuses_a_link_or_a_directory_at_the_lock_path(self):
        """M1-35 fix pass 1 F4: a link or a directory where the lock file belongs stops the writer with a named error; nothing is
        written through a link (not even to a missing target), and the link or directory stays as it was."""
        root, env = self.engine_verifiable_writer_tree()
        binary = root / "Packages/WGEXEngine/Binary"
        binary.mkdir(parents=True)
        lock = root / self.ENGINE_LOCK
        target = self.work / "link-target"
        for shape in ("directory", "link to a file", "link to nothing"):
            for writer, flag in (("build-xcframework.sh", "--force"), ("build-test-support.sh", "--clean")):
                with self.subTest(shape=shape, writer=writer):
                    target.unlink(missing_ok=True)
                    lock.unlink(missing_ok=True)
                    if shape == "directory":
                        lock.mkdir()
                    else:
                        if shape == "link to a file":
                            target.write_text("keep")
                        lock.symlink_to(target)
                    refused = self.run_engine_writer(root, env | {"WGEX_ENGINE_LOCK_WAIT": "2"}, writer, flag)
                    self.assertNotEqual(refused.returncode, 0, refused.stdout + refused.stderr)
                    self.assertIn("must be a plain lock file", refused.stderr)
                    self.assertEqual(list(binary.iterdir()), [], "a writer that was refused built something")
                    if shape == "directory":
                        self.assertTrue(lock.is_dir() and not lock.is_symlink())
                        self.assertEqual(list(lock.iterdir()), [])
                        lock.rmdir()
                    else:
                        self.assertTrue(lock.is_symlink(), "the link was replaced")
                        self.assertEqual(target.read_text() if target.exists() else None,
                                         "keep" if shape == "link to a file" else None,
                                         "the writer wrote through the linked lock file")
                        lock.unlink()
        built = self.run_engine_writer(root, env | {"WGEX_ENGINE_LOCK_WAIT": "3"}, "build-xcframework.sh", "--force")
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)

    def test_engine_restore_publish_aside_never_replaces_an_existing_output(self):
        """M1-35 fix pass 1 F4: the EXIT trap puts the old output back only when nothing is at the final name (not even a link);
        anything already there, and the old output beside it, stay as they are."""
        root, _ = self.engine_writer_tree()
        scratch = self.work / "restore"
        scratch.mkdir()
        library = root / "Engine/scripts/lib.sh"

        def restore(aside, final):
            return subprocess.run(["bash", "-c", f'source "{library}"; cd "{scratch}"; PUBLISH_ASIDE={aside} PUBLISH_FINAL={final}; '
                                   'restore_publish_aside; printf "[%s][%s]" "$PUBLISH_ASIDE" "$PUBLISH_FINAL"'],
                                  env=os.environ, capture_output=True, text=True, timeout=60)

        (scratch / ".old-1-final").mkdir()
        (scratch / ".old-1-final/old").write_text("old")
        (scratch / "final").mkdir()
        (scratch / "final/new").write_text("new")
        result = restore(".old-1-final", "final")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "[][]", "the aside and final names were not cleared")
        self.assertEqual(sorted(path.name for path in (scratch / "final").iterdir()), ["new"], "an existing output was replaced")
        self.assertEqual((scratch / ".old-1-final/old").read_text(), "old")
        shutil.rmtree(scratch / "final")
        (scratch / "final").symlink_to(scratch / "nowhere")
        self.assertEqual(restore(".old-1-final", "final").returncode, 0)
        self.assertTrue((scratch / "final").is_symlink(), "a link at the final name was replaced")
        self.assertEqual((scratch / ".old-1-final/old").read_text(), "old")
        (scratch / "final").unlink()
        self.assertEqual(restore(".old-1-final", "final").returncode, 0)
        self.assertEqual((scratch / "final/old").read_text(), "old", "the old output was not put back")
        self.assertFalse((scratch / ".old-1-final").exists())

    def test_engine_writers_never_overlap_on_the_lock_of_a_killed_writer(self):
        """M1-35 N1: six writers racing for the lock a SIGKILLed writer left behind run one at a time and delete nothing of each other's."""
        root, env = self.engine_verifiable_writer_tree()
        binary = root / "Packages/WGEXEngine/Binary"
        binary.mkdir(parents=True)
        events = self.work / "events.log"
        for round_number in range(3):
            with self.subTest(round=round_number):
                self.hang_engine_writer(root, env, "build-xcframework.sh", "--force", signal.SIGKILL)
                self.assertTrue((root / self.ENGINE_LOCK).exists(), "the killed writer left no lock file")
                events.unlink(missing_ok=True)
                racing = env | {"WGEX_TEST_EVENTS": str(events), "WGEX_TEST_BUILD_DELAY": "0.1"}
                running = []
                try:
                    for number in range(6):
                        writer, flag = (("build-xcframework.sh", "--force") if number % 2 == 0
                                        else ("build-test-support.sh", "--clean"))
                        running.append(subprocess.Popen(["bash", str(root / "Engine/scripts" / writer), flag], env=racing,
                                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True))
                    outputs = [process.communicate(timeout=120)[0] for process in running]
                finally:
                    for process in running:
                        if process.poll() is None:
                            process.kill()
                            process.wait()
                for process, output in zip(running, outputs):
                    self.assertEqual(process.returncode, 0, output)
                depth = peak = 0
                lines = [line.split()[0] for line in events.read_text().splitlines()]
                for kind in lines:
                    depth += 1 if kind == "enter" else -1
                    peak = max(peak, depth)
                self.assertEqual(lines.count("enter"), 6, lines)
                self.assertEqual(peak, 1, f"{peak} writers ran at once: {lines}")
                self.assertEqual([p.name for p in binary.iterdir() if p.name.startswith(".")], [])
                self.assertTrue(self.engine_lock_is_free(root))
        self.assertEqual(self.digest(root, "--verify", str(binary)).returncode, 0)
        self.assertEqual(self.digest(root, "--verify", str(binary), "--test-support").returncode, 0)

    def test_engine_leftovers_are_removed_only_while_the_lock_is_held(self):
        """M1-35 N1: remove_build_leftovers refuses to run without the lock, and still removes a dead writer's files under it."""
        root, _ = self.engine_writer_tree()
        binary = root / "Packages/WGEXEngine/Binary"
        binary.mkdir(parents=True)
        leftover = binary / ".new-1-WGEXEngine.xcframework"
        leftover.mkdir()
        library = root / "Engine/scripts/lib.sh"

        def shell(function):
            return subprocess.run(["bash", "-c", f'source "{library}"; {function}'], env=os.environ,
                                  capture_output=True, text=True, timeout=60)

        refused = shell(f'remove_build_leftovers "{binary}"')
        self.assertNotEqual(refused.returncode, 0, refused.stdout + refused.stderr)
        self.assertTrue(leftover.is_dir(), "a writer without the lock deleted another writer's temporary")
        allowed = shell(f'acquire_binary_lock "{binary}"; remove_build_leftovers "{binary}"')
        self.assertEqual(allowed.returncode, 0, allowed.stdout + allowed.stderr)
        self.assertFalse(leftover.exists())

    def test_engine_lock_wait_must_be_whole_seconds(self):
        """M1-35 N2: a malformed WGEX_ENGINE_LOCK_WAIT stops the writer with a named error before it builds anything."""
        root, env = self.engine_verifiable_writer_tree()
        binary = root / "Packages/WGEXEngine/Binary"
        binary.mkdir(parents=True)
        for value in ("1.5", "abc", "30m", "", "-1"):
            for writer, flag in (("build-xcframework.sh", "--force"), ("build-test-support.sh", "--clean")):
                with self.subTest(value=value, writer=writer):
                    refused = self.run_engine_writer(root, env | {"WGEX_ENGINE_LOCK_WAIT": value}, writer, flag)
                    self.assertNotEqual(refused.returncode, 0, refused.stdout + refused.stderr)
                    self.assertIn("WGEX_ENGINE_LOCK_WAIT must be whole seconds", refused.stderr)
                    self.assertEqual(list(binary.iterdir()), [], "a writer with a bad wait built or wrote something")
        for value in ("0", "2"):
            with self.subTest(value=value):
                built = self.run_engine_writer(root, env | {"WGEX_ENGINE_LOCK_WAIT": value}, "build-xcframework.sh", "--force")
                self.assertEqual(built.returncode, 0, built.stdout + built.stderr)

    def test_engine_lock_files_are_git_ignored(self):
        """M1-35 N4: the lock file and any sibling of it beside Binary never show up as untracked."""
        for name in ("Packages/WGEXEngine/.Binary.build.lock", "Packages/WGEXEngine/.Binary.build.lock.stale.123"):
            result = subprocess.run(["git", "-C", str(ROOT), "check-ignore", "-q", "--no-index", name],
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, f"{name} is not git-ignored: {result.stderr}")

    def test_engine_publish_never_nests_into_an_existing_directory(self):
        """M1-28 F3: the final rename refuses an existing target; publish moves the old one aside first and leaves no copy."""
        root, _ = self.engine_writer_tree()
        scratch = self.work / "publish"
        scratch.mkdir()
        (scratch / "new").mkdir()
        (scratch / "new/file").write_text("new")
        (scratch / "final").mkdir()
        (scratch / "final/keep").write_text("old")
        library = root / "Engine/scripts/lib.sh"

        def shell(function):
            return subprocess.run(["bash", "-c", f'source "{library}"; cd "{scratch}"; {function}'], env=os.environ,
                                  capture_output=True, text=True, timeout=60)

        refused = shell("rename_exclusive new final")
        self.assertEqual(refused.returncode, 1, refused.stdout + refused.stderr)
        self.assertEqual((scratch / "final/keep").read_text(), "old")
        self.assertFalse((scratch / "final/new").exists(), "the rename nested into the existing directory")
        published = shell("publish new final")
        self.assertEqual(published.returncode, 0, published.stdout + published.stderr)
        self.assertEqual((scratch / "final/file").read_text(), "new")
        self.assertEqual(sorted(path.name for path in scratch.iterdir()), ["final"])
        self.assertEqual(sorted(path.name for path in (scratch / "final").iterdir()), ["file"])
        # A writer that creates the target between the move aside and the rename makes publish fail, not nest.
        (scratch / "next").mkdir()
        (scratch / "next/file").write_text("next")
        raced = shell('mv() { command mv "$@"; case "${@: -1}" in *.old-*) mkdir -p final/blocker ;; esac; }; publish next final')
        self.assertNotEqual(raced.returncode, 0, raced.stdout + raced.stderr)
        self.assertFalse((scratch / "final/next").exists(), "the rename nested into the target that appeared")
        self.assertEqual(sorted(path.name for path in (scratch / "final").iterdir()), ["blocker"])

    def hang_engine_writer(self, root, env, writer, flag, signal_number, knob="WGEX_TEST_HANG"):
        """Start a writer that hangs at the knob's point (default: once its .new-* directory exists; WGEX_TEST_HANG_ASIDE: in
        publish, after the old output is moved aside), send it a signal to its own process group, and wait for it."""
        marker = self.work / "hang-marker"
        marker.unlink(missing_ok=True)
        process = subprocess.Popen(["bash", str(root / "Engine/scripts" / writer), flag],
                                   env=env | {knob: str(marker)}, start_new_session=True,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 60
            while not marker.exists():
                self.assertIsNone(process.poll(), "the writer exited before it reached the hang point")
                self.assertLess(time.monotonic(), deadline, "the writer never reached the hang point")
                time.sleep(0.05)
            os.killpg(process.pid, signal_number)
            # Wait for the leader to exit without reaping it: while it is a zombie it still pins the group id.
            deadline = time.monotonic() + 60
            while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is None:
                self.assertLess(time.monotonic(), deadline, "the writer did not exit after the signal")
                time.sleep(0.02)
        finally:
            self.reap_process_group(process)

    @staticmethod
    def reap_process_group(process):
        """SIGKILL whatever is left in a writer's process group, then reap the writer. A child that survives the signal is
        orphaned and keeps the writer's flock. The group is signalled only while the leader is still ours and unreaped (alive
        or a zombie), so its pid cannot have been reused and the signal reaches only the group the test created; once the
        leader is reaped nothing is signalled."""
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            process.wait(timeout=60)

    def wait_for_engine_lock_free(self, root, timeout):
        """Assert that the engine build lock becomes free within timeout seconds. The kernel can drop the flock of a
        signalled process some time after the process has left its group and lsof's view, so a single check is a race under
        load; a holder that really leaked still fails after the deadline."""
        deadline = time.monotonic() + timeout
        while not self.engine_lock_is_free(root):
            self.assertLess(time.monotonic(), deadline, f"the build lock is still held after {timeout} s")
            time.sleep(0.05)

    def test_engine_writer_next_build_removes_the_leftovers_of_a_killed_writer(self):
        """M1-28 F4: SIGKILL leaves a .new-* directory, a stale lock and provenance temporaries; the next build clears all of them."""
        root, env = self.engine_verifiable_writer_tree()
        binary = root / "Packages/WGEXEngine/Binary"
        binary.mkdir(parents=True)
        for writer, flag in (("build-xcframework.sh", "--force"), ("build-test-support.sh", "--clean")):
            with self.subTest(writer=writer):
                self.hang_engine_writer(root, env, writer, flag, signal.SIGKILL)
                self.assertTrue([p for p in binary.iterdir() if p.name.startswith(".new-")],
                                "the killed writer left no temporary directory, so the test proves nothing")
                (binary / ".provenance.json.AbC123").write_text("half")
                (binary / ".provenance-test.json.Xy9876").write_text("half")
                (binary / ".old-1-WGEXEngine.xcframework").mkdir(exist_ok=True)
                built = self.run_engine_writer(root, env, writer, flag)
                self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
                self.assertEqual([p.name for p in binary.iterdir() if p.name.startswith(".")], [])
                self.assertTrue(self.engine_lock_is_free(root))

    def test_engine_writer_leaves_no_dot_entries_after_sigterm(self):
        """M1-28 F5 (W8): a terminated writer removes its temporaries and its lock."""
        root, env = self.engine_verifiable_writer_tree()
        binary = root / "Packages/WGEXEngine/Binary"
        binary.mkdir(parents=True)
        for writer, flag in (("build-xcframework.sh", "--force"), ("build-test-support.sh", "--clean")):
            with self.subTest(writer=writer):
                self.hang_engine_writer(root, env, writer, flag, signal.SIGTERM)
                self.assertEqual([p.name for p in binary.iterdir() if p.name.startswith(".")], [])
                self.wait_for_engine_lock_free(root, 10)

    def test_engine_writer_sigterm_inside_publish_restores_the_previous_output(self):
        """M1-35 N6: a SIGTERM between the move aside and the rename puts the previous output back, so the tree is never left empty."""
        root, env = self.engine_verifiable_writer_tree()
        binary = root / "Packages/WGEXEngine/Binary"
        binary.mkdir(parents=True)
        for writer, flag, name in (("build-xcframework.sh", "--force", "WGEXEngine.xcframework"),
                                   ("build-test-support.sh", "--clean", "WGEXEngineTest.xcframework")):
            with self.subTest(writer=writer):
                built = self.run_engine_writer(root, env, writer, flag)
                self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
                before = self.tree_snapshot(binary / name)
                self.hang_engine_writer(root, env, writer, flag, signal.SIGTERM, knob="WGEX_TEST_HANG_ASIDE")
                self.assertTrue((binary / name).is_dir(), f"{name} was not restored")
                self.assertEqual(self.tree_snapshot(binary / name), before)
                self.assertEqual([p.name for p in binary.iterdir() if p.name.startswith(".")], [])
                self.wait_for_engine_lock_free(root, 10)
                self.assertEqual(self.digest(root, "--verify", str(binary),
                                             *(("--test-support",) if "Test" in name else ())).returncode, 0)

    def test_new_shell_scripts_are_linted_before_staging(self):
        scripts = [ROOT / "Config/Scripts/check.sh", ROOT / "Tools/lint/check-notices-sync.sh"]
        for command in (["shellcheck", *map(str, scripts)],
                        ["shfmt", "-i", "2", "-ci", "-d", *map(str, scripts)]):
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_lint_enumerates_only_indexed_paths(self):
        result = self.shell(f'source "{ROOT}/Tools/lint/lib.sh"; repo_files')
        self.assertEqual(result.returncode, 0, result.stderr)
        indexed = set(subprocess.check_output(["git", "-C", str(ROOT), "ls-files", "-z"]).decode().split("\0"))
        paths = result.stdout.rstrip("\0").split("\0")
        self.assertTrue(paths)
        self.assertTrue(all(str(Path(p).relative_to(ROOT)) in indexed for p in paths))

    def test_identifier_generation_renames_on_target_filesystem(self):
        root = self.work / "generated-tree"
        for name in ("lib.sh", "generate-build-identifiers.sh"):
            target = root / "Config/Scripts" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            self.copy_source(ROOT / "Config/Scripts" / name, target)
        tools = self.work / "bin"
        tools.mkdir()
        marker = self.work / "mktemp-argument"
        tool = tools / "mktemp"
        tool.write_text('#!/bin/bash\nprintf "%s" "$1" >"$WGEX_TEMP_TEST_MARKER"\nexec /usr/bin/mktemp "$@"\n')
        tool.chmod(0o755)
        env = os.environ | {"PATH": f"{tools}:{os.environ['PATH']}", "TMPDIR": str(self.work) + "/",
                            "WGEX_TEMP_TEST_MARKER": str(marker), "WGEX_BUNDLE_ID_BASE": "org.example.wgex",
                            "WGEX_TEAM": "ABCDEFGHIJ"}
        result = subprocess.run(["bash", str(root / "Config/Scripts/generate-build-identifiers.sh")],
                                 env=env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        destination = root / "Packages/WGEXCore/Sources/WGEXCore/Generated/BuildIdentifiers.generated.swift"
        self.assertEqual(Path(marker.read_text()).parent, destination.parent)

    def test_package_scratch_sharing_and_engine_flags(self):
        root = self.work / "packages-tree"
        for name in ("lib.sh", "test.sh"):
            target = root / "Config/Scripts" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            self.copy_source(ROOT / "Config/Scripts" / name, target)
        library = root / "Config/Scripts/lib.sh"
        library.write_text(library.read_text() + '\nrequire_current_engine() { return 0; }\n')
        for package in ("WGEXBackendMac", "WGEXCore", "WGEXEngine"):
            manifest = root / "Packages" / package / "Package.swift"
            manifest.parent.mkdir(parents=True)
            manifest.write_text("// fixture manifest; never compiled\n")
        tools = self.work / "bin"
        tools.mkdir()
        calls = self.work / "swift-calls"
        tool = tools / "swift"
        tool.write_text('#!/bin/bash\nprintf "%s\\0" "$WGEX_ENGINE_TEST_SUPPORT" "$@" >>"$WGEX_SWIFT_TEST_CALLS"\nprintf "\\n" >>"$WGEX_SWIFT_TEST_CALLS"\n')
        tool.chmod(0o755)
        env = os.environ | {"PATH": f"{tools}:{os.environ['PATH']}", "WGEX_SWIFT_TEST_CALLS": str(calls),
                            "WGEX_BUILD_ROOT": str(self.work / "builds"),
                            "CLEAN_DEVELOPMENT_CACHE_ROOT": str(self.work / "cache")}
        result = subprocess.run(["bash", str(root / "Config/Scripts/test.sh"), "all"],
                                 env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        invocations = [line.rstrip("\0").split("\0") for line in calls.read_text().splitlines()]
        self.assertEqual(len(invocations), 3)
        scratches = [args[args.index("--scratch-path") + 1] for args in invocations]
        self.assertEqual(scratches[0], scratches[1])
        self.assertNotEqual(scratches[1], scratches[2])
        self.assertEqual([args[0] for args in invocations], ["0", "0", "1"])
        self.assertIn("-enable-actor-data-race-checks", invocations[2])

    def test_licence_default_scans_all_product_trees(self):
        root = self.work / "licence-tree"
        for name in ("Config/Scripts/lib.sh", "Tools/lint/lib.sh", "Tools/lint/check-licences.sh"):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            self.copy_source(ROOT / name, target)
        for directory in ("Apps", "Daemon", "Extensions", "Config"):
            target = root / directory / "Planted.swift"
            target.parent.mkdir(exist_ok=True)
            self.copy_source(ROOT / "Tools/lint/tests/licences/gpl-spdx/Planted.swift", target)
        (root / "Tools/lint/notices.py").write_text("# fixture ledger; no dependencies\n")
        for module in ("gvisor.dev/gvisor", "github.com/google/btree", "golang.org/x/time"):
            licence = root / "Engine/go/vendor" / module / "LICENSE"
            licence.parent.mkdir(parents=True)
            licence.write_text("Permission is hereby granted, free of charge\n")
        tools = self.work / "bin"
        tools.mkdir()
        git = tools / "git"
        git.write_text('''#!/bin/bash
for directory in Apps Daemon Extensions Config; do
  for argument in "$@"; do
    if [[ "$argument" == "$directory" ]]; then printf '%s\\0' "$directory/Planted.swift"; fi
  done
done
''')
        git.chmod(0o755)
        result = subprocess.run(["bash", str(root / "Tools/lint/check-licences.sh")],
                                 env=os.environ | {"PATH": f"{tools}:{os.environ['PATH']}"},
                                 capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        for directory in ("Apps", "Daemon", "Extensions", "Config"):
            self.assertIn(f"licence: {directory}/Planted.swift:", result.stderr)


    def test_untracked_sources_invalidate_but_ignored_files_and_unrelated_pins_do_not(self):
        root = self.digest_tree()
        original = self.digest(root).stdout
        for name in ("Engine/go/untracked.go", "Engine/scripts/untracked.sh"):
            path = root / name
            path.write_text("new source\n")
            self.assertNotEqual(self.digest(root).stdout, original)
            path.unlink()
        (root / ".gitignore").write_text("Engine/go/ignored.go\nEngine/scripts/ignored.sh\n")
        (root / "Engine/go/ignored.go").write_text("ignored source\n")
        (root / "Engine/scripts/ignored.sh").write_text("ignored script\n")
        (root / "Config").mkdir()
        (root / "Config/Base.xcconfig").write_text("UNRELATED_SETTING = changed\n")
        lock = root / "Toolchain.lock"
        contents = lock.read_text()
        lock.write_text(contents.replace('python3="one"', 'python3="two"'))
        self.assertEqual(self.digest(root).stdout, original)
        lock.write_text(contents.replace('[go]\nversion="one"', '[go]\nversion="two"'))
        self.assertEqual(self.digest(root).stdout, original)
        lock.write_text(contents.replace('[xcode]\nversion="one"', '[xcode]\nversion="two"'))
        self.assertEqual(self.digest(root).stdout, original)
        lock.write_text(contents)
        self.assertEqual(self.digest(root).stdout, original)
        # M1-45/M1-46: minimum-version gates, the engine cache key and the integrity-record shapes; the suite
        # runs several stubbed engine builds, so its bound allows for a loaded host.
        # Each toolchain command has a 180s bound; the full regression suite has 900s, with margin for its many steps.
        try:
            result = subprocess.run(["python3", "-I", "-B", str(ROOT / "Tools/doctor/test_toolchain.py")],
                                    capture_output=True, text=True, timeout=900)
        except subprocess.TimeoutExpired:
            self.fail(f"toolchain regression suite exceeded 900s; 1-minute load average {os.getloadavg()[0]:.2f}")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_digest_hashes_resolved_version_and_build(self):
        root = self.digest_tree()
        config = root / "Config/Base.xcconfig"
        config.parent.mkdir()
        config.write_text("MARKETING_VERSION = 1.2.3\nCURRENT_PROJECT_VERSION = 42\nOTHER = one\n")
        original = self.digest(root).stdout
        for old, new in (("1.2.3", "1.2.4"), ("42", "43")):
            config.write_text(config.read_text().replace(old, new))
            self.assertNotEqual(self.digest(root).stdout, original)
            config.write_text(config.read_text().replace(new, old))
        config.write_text(config.read_text().replace("OTHER = one", "OTHER = two"))
        self.assertEqual(self.digest(root).stdout, original)
        self.assertEqual(self.digest(root, env={"WGEX_APP_VERSION": "", "WGEX_BUILD": ""}).stdout, original)
        overrides = {"WGEX_APP_VERSION": "9.8.7", "WGEX_BUILD": "99"}
        pinned = self.digest(root, env=overrides).stdout
        self.assertNotEqual(pinned, original)
        config.write_text("MARKETING_VERSION = 7.0\nCURRENT_PROJECT_VERSION = 100\n")
        self.assertEqual(self.digest(root, env=overrides).stdout, pinned)
        for key in overrides:
            self.assertNotEqual(self.digest(root, env=overrides | {key: "101"}).stdout, pinned)
        invalid = self.digest(root, env={"WGEX_APP_VERSION": "invalid value"})
        self.assertNotEqual(invalid.returncode, 0)
        self.assertIn("app version/build", invalid.stderr)

    def test_linker_version_values_use_the_digest_resolver(self):
        root = self.work / "versions"
        for name in ("Engine/scripts/lib.sh", "Engine/scripts/source-digest.py", "Config/Scripts/lib.sh"):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            self.copy_source(ROOT / name, target)
        (root / "Config/Base.xcconfig").write_text("  MARKETING_VERSION = 1.2.3 // comment\nCURRENT_PROJECT_VERSION = 42\n")
        environment = {key: value for key, value in os.environ.items()
                       if key not in ("WGEX_APP_VERSION", "WGEX_BUILD")}
        for overrides, expected in (({}, "1.2.3\n42"),
                                    ({"WGEX_APP_VERSION": "9.8.7", "WGEX_BUILD": "99"}, "9.8.7\n99")):
            result = self.shell(f'source "{root}/Engine/scripts/lib.sh"; app_version_values; '
                                'printf "%s\\n%s" "$APP_VERSION" "$APP_BUILD"', environment | overrides)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, expected)

    def test_build_root_rejects_relative_and_repository_paths(self):
        library = ROOT / "Config/Scripts/lib.sh"
        link = self.work / "repo-link"
        link.symlink_to(ROOT, target_is_directory=True)
        for override in ("relative", str(ROOT), str(ROOT / "build"), str(ROOT.parent), str(link / "build")):
            result = self.shell(f'source "{library}"; build_root', os.environ | {"WGEX_BUILD_ROOT": override})
            self.assertNotEqual(result.returncode, 0, override)
            self.assertIn("WGEX_BUILD_ROOT", result.stderr)

    def test_derived_data_and_entrypoints_propagate_invalid_build_root(self):
        library = ROOT / "Config/Scripts/lib.sh"
        env = os.environ | {"WGEX_BUILD_ROOT": "relative"}
        result = subprocess.run(["bash", "-c", f'source "{library}"; derived_data'],
                                env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("build_root:", result.stderr)
        root = self.work / "invalid-root"
        for name in ("Config/Scripts/lib.sh", "Config/Scripts/gen.sh", "Tools/lint/lib.sh",
                     "Tools/lint/check-entitlements.sh"):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            self.copy_source(ROOT / name, target)
        generator = root / "Config/Scripts/generate-build-identifiers.sh"
        generator.write_text('#!/bin/bash\necho "unexpected generation" >&2\nexit 97\n')
        for name in ("Config/Scripts/gen.sh", "Tools/lint/check-entitlements.sh"):
            result = subprocess.run(["bash", str(root / name)], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("build_root:", result.stderr)
            self.assertNotIn("unexpected generation", result.stderr)

    def test_secret_scanner_accepts_empty_file_list(self):
        result = subprocess.run(["python3", "-I", str(ROOT / "Tools/lint/secret-shapes.py")],
                                input="", capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("check-no-secrets-in-strings: ok", result.stdout)

    def test_guard_tree_copies_every_sourced_file(self):
        root = self.work / "sourced-tree"
        names = ("Config/Scripts/lib.sh", "Tools/lab/tart/build.sh", "Tools/lab/tart/lib.sh")
        for name in names:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            self.copy_source(ROOT / name, target)
        self.assertEqual(missing_sources(root, names), [], "copied scripts source files absent from the copy")
        self.assertTrue((root / "Tools/lab/harness-deadlines.sh").is_file())
        # The detector itself must fail when a sourced file is absent from a copy.
        bare = self.work / "bare-tree"
        (bare / "Tools/lab/tart").mkdir(parents=True)
        shutil.copy(ROOT / "Tools/lab/tart/lib.sh", bare / "Tools/lab/tart/lib.sh")
        self.assertEqual(missing_sources(bare, ("Tools/lab/tart/lib.sh",)),
                         [("Tools/lab/tart/lib.sh", "Tools/lab/harness-deadlines.sh")])

    # --- M1-10t part 2: begin (source-line completeness, non-.sh and non-UTF-8 sources, docstrings, self-test placement) ---
    def fake_root(self, name):
        root = self.work / name
        (root / "lib").mkdir(parents=True)
        (root / "lib/x.sh").write_text("X=1\n")
        return root

    def under_root(self, root):
        return patch.object(sys.modules[__name__], "ROOT", root)

    def test_source_parser_resolves_every_listed_shape_and_refuses_the_rest(self):
        """M1-10t (M1-10s VERIFY-B LOW-2, VERIFY F1): every source shape the earlier parser missed resolves to lib/x.sh;
        every shape it still cannot resolve is reported with a reason (never skipped); non-commands are not sources."""
        root = self.fake_root("shapes")
        (root.parent / "outside.sh").write_text("O=1\n")
        resolved = [
            '. ./x.sh', 'source "${BASH_SOURCE[0]%/*}/x.sh"', "source $D/x.sh", 'source "$D"/x.sh', 'source "$DIR2/x.sh"',
            'builtin source "$D/x.sh"', 'command . "$D/x.sh"', '[[ -f "$D/x.sh" ]] && source "$D/x.sh"',
            'if [[ -n "$D" ]]; then source "$D/x.sh"; fi', 'source "$D//x.sh"', '. "$(cd "$(dirname "$0")" && pwd)/x.sh"',
            "source $LAB_DIR/../lib/x.sh", 'source "$root"/lib/x.sh', 'source "$D/x.sh" || true', 'source "$D/x.sh" # note',
            'source "$D/x.sh"; echo ok', '( . "$D/x.sh" )', 'x=$(. "$D/x.sh"; echo "$y")', "eval '. \"$D/x.sh\"'",
            "bash -c 'source \"$D/x.sh\"'", 'source "$D/x.sh"\r', 'source \\\n  "$D/x.sh"', 'FOO=1 source "$D/x.sh"',
            'case $1 in a) source "$D/x.sh";; esac', 'f() { . "$D/x.sh"; }', 'source "${D}/x.sh"', "source 'x.sh'",
            'while read -r l; do source "$D/x.sh"; done </dev/null', '! source "$D/x.sh"', "source `dirname $0`/x.sh",
        ]
        refused = [
            "source '$D/x.sh'", 'source "$D/$name.sh"', 'source "$f"', "source /abs/x.sh", '. "${X:-.}/x.sh"', "source ~/x.sh",
            'source "$(mktemp -d)/x.sh"', 'source "$D/missing.sh"', 'source "$D/../../outside.sh"', "source $D",
            'source "$D"/"$name"', 'source "$D/x.sh$suffix"', 'source x$y.sh',
        ]
        ignored = ['# source "$D/x.sh"', 'echo source "$D/x.sh"', 'echo "source $D/x.sh"', "printf '%s\\n' \". $D/x.sh\"",
                   "cd . && ls", "find . -name x.sh", 'echo . "$D/x.sh"', "source", ".", "x.source $D/x.sh"]
        with self.under_root(root):
            for line in resolved:
                with self.subTest(resolved=line):
                    (root / "lib/s.sh").write_text(line + "\n")
                    self.assertEqual(sourced_files("lib/s.sh"), ["lib/x.sh"])
                    self.assertTrue(all(files and reason is None for _, files, reason in source_lines("lib/s.sh")))
            for line in refused:
                with self.subTest(refused=line):
                    (root / "lib/s.sh").write_text(line + "\n")
                    entries = source_lines("lib/s.sh")
                    self.assertEqual(len(entries), 1, entries)
                    self.assertEqual(entries[0][1], [])
                    self.assertTrue(entries[0][2], "a refused line must say why")
                    self.assertEqual(sourced_files("lib/s.sh"), [])
            for line in ignored:
                with self.subTest(ignored=line):
                    (root / "lib/s.sh").write_text(line + "\n")
                    self.assertEqual(source_lines("lib/s.sh"), [])

    def git_fixture(self, name, files, add, links=None):
        """A scratch git repository with files (name -> text) and symlinks (name -> target text) written, and only the names
        in add indexed."""
        root = self.work / name
        for relative, text in files.items():
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            (root / relative).write_text(text)
        for relative, target in (links or {}).items():
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            os.symlink(target, root / relative)
        for arguments in (["init", "-q"], ["add", "--", *add]):
            subprocess.run(["git", "-C", str(root), *arguments], env=os.environ, capture_output=True, text=True, check=True,
                           timeout=60)
        return root

    def test_completeness_refuses_a_sourced_file_git_does_not_track(self):
        """M1-10t fix 1 item 1 (SCRIPTS-VERIFY F1): a tracked script that sources an untracked helper (present on disk) or a
        git-ignored one resolves on disk but is absent from a clean checkout; the walk refuses both, unless the line is
        allowlisted with a reason. A tracked target and an absent target keep their old outcome."""
        helper_line = 'source "$(dirname "$0")/helper.sh"'
        ignored_line = 'source "$(dirname "$0")/helper.local"'
        root = self.git_fixture("untracked-fixture", {
            ".gitignore": "helper.local\n",
            "Tools/planted/new.sh": helper_line + "\n",
            "Tools/planted/ignored.sh": ignored_line + "\n",
            "Tools/planted/tracked.sh": 'source "$(dirname "$0")/real.sh"\n',
            "Tools/planted/absent.sh": 'source "$(dirname "$0")/absent-helper.sh"\n',
            "Tools/planted/real.sh": "R=1\n",
            "Tools/planted/helper.sh": "H=1\n",
            "Tools/planted/helper.local": "L=1\n",
        }, [".gitignore", "Tools/planted/new.sh", "Tools/planted/ignored.sh", "Tools/planted/tracked.sh",
            "Tools/planted/absent.sh", "Tools/planted/real.sh"])
        reason = "a runtime fixture written by the test itself before the script runs"
        with self.under_root(root):
            tracked = tracked_files()
            self.assertNotIn("Tools/planted/helper.sh", tracked)
            self.assertNotIn("Tools/planted/helper.local", tracked)
            self.assertEqual(sourced_files("Tools/planted/new.sh"), ["Tools/planted/helper.sh"], "the file is on disk")
            problems, walk, resolved = source_completeness(tracked, {})
            self.assertEqual(len(walk), 5, walk)  # the five tracked scripts; the two helpers are not tracked
            self.assertEqual(len([p for p in problems if "untracked" in p]), 2, problems)
            self.assertTrue(any(p.startswith("Tools/planted/new.sh: ") and "helper.sh" in p and "untracked" in p
                                for p in problems), problems)
            self.assertTrue(any(p.startswith("Tools/planted/ignored.sh: ") and "helper.local" in p and "untracked" in p
                                for p in problems), problems)
            self.assertTrue(any(p.startswith("Tools/planted/absent.sh: ") for p in problems), problems)
            self.assertFalse(any(p.startswith("Tools/planted/tracked.sh") for p in problems), problems)
            self.assertEqual(resolved, 1, "only the tracked target counts as resolved")
            allowed = {("Tools/planted/new.sh", helper_line): reason}
            problems, _, _ = source_completeness(tracked, allowed)
            self.assertFalse(any(p.startswith("Tools/planted/new.sh") for p in problems), "an allowlisted line is accepted")
            self.assertTrue(any(p.startswith("Tools/planted/ignored.sh") for p in problems), problems)
            # an allowlist entry that no longer matches a line is stale
            problems, _, _ = source_completeness(tracked, allowed | {("Tools/planted/real.sh", 'source "$D/x.sh"'): reason})
            self.assertTrue(any("matches no source line" in p for p in problems), problems)

    def test_completeness_walk_refuses_unresolved_lines_and_weak_allowlist_reasons(self):
        """M1-10t fix 1 item 7 (SCRIPTS-VERIFY I1; mutants M2b and M3a): the walk's own refusal of an unresolved line, its
        stale-entry check and its reason check run on a fake root, so none of them can be dropped unseen."""
        root = self.fake_root("walk-fixture")
        (root / "lib/unresolved.sh").write_text('source "$f"\n')
        (root / "lib/fine.sh").write_text('source "$D/x.sh"\n')
        tracked = {"lib/x.sh", "lib/unresolved.sh", "lib/fine.sh"}
        long_reason = "a runtime fixture that the script writes into its own scratch directory"
        with self.under_root(root):
            problems, walk, resolved = source_completeness(tracked, {})
            self.assertEqual((sorted(walk), resolved), (["lib/fine.sh", "lib/unresolved.sh", "lib/x.sh"], 1))
            self.assertEqual(len(problems), 1, problems)
            self.assertTrue(problems[0].startswith('lib/unresolved.sh: source "$f": '), problems)
            self.assertEqual(source_completeness(tracked, {("lib/unresolved.sh", 'source "$f"'): long_reason})[0], [])
            problems, _, _ = source_completeness(tracked, {("lib/unresolved.sh", 'source "$f"'): "too short a reason"})
            self.assertEqual(len(problems), 1, problems)
            self.assertIn("under six words", problems[0])
            problems, _, _ = source_completeness(tracked, {("lib/unresolved.sh", 'source "$f"'): long_reason,
                                                           ("lib/gone.sh", "source x"): long_reason})
            self.assertEqual(len(problems), 1, problems)
            self.assertIn("matches no source line", problems[0])

    def test_scanner_never_skips_a_source_command_it_can_see(self):
        """M1-10t fix 1 item 2 (SCRIPTS-VERIFY F2): every shape SCRIPTS-VERIFY lists as silently skipped is now resolved or
        refused with a reason; a source command the scanner cannot read at all is refused by the backstop; and the real line
        Tools/lab/tart/tests/run.sh:221 (a source inside a wrapped `bash -c`) is seen and carries an allowlist reason."""
        root = self.fake_root("never-skipped")
        resolved = [
            '\\. "$D/x.sh"', '\\source "$D/x.sh"', '"source" "$D/x.sh"', "'.' \"$D/x.sh\"", "sour''ce \"$D/x.sh\"",
            'so"ur"ce "$D/x.sh"', 's\\ou\\rce "$D/x.sh"', 'function f { source "$D/x.sh"; }', 'function f() { source "$D/x.sh"; }',
            'function f\n{\n  . "$D/x.sh"\n}', '2>/dev/null source "$D/x.sh"', '>/dev/null 2>&1 . "$D/x.sh"',
            '2> /dev/null source "$D/x.sh"', '<&3 . "$D/x.sh"', '>&2 source "$D/x.sh"', '&>/dev/null source "$D/x.sh"',
            'coproc source "$D/x.sh"', 'coproc P { source "$D/x.sh"; }', 'command -p source "$D/x.sh"',
            'command -p -- . "$D/x.sh"', 'time -p source "$D/x.sh"', "bash -c -- '. \"$D/x.sh\"'",
            "sudo bash -c '. \"$D/x.sh\"'", "env bash -c '. \"$D/x.sh\"'", "env -i bash -c '. \"$D/x.sh\"'",
            "run_x label bash -c 'source \"$D/x.sh\"' _ path", "run_x label sh -ec 'source \"$D/x.sh\"'",
            "x bash --norc -o errexit -c -- 'source \"$D/x.sh\"' _", "x /bin/bash -c $'. \"$D/x.sh\"'",
            "x bash +o posix -O extglob -c \". $D/x.sh\"", 'FOO=1 command source "$D/x.sh"', '2>/dev/null command . "$D/x.sh"',
        ]
        refused = [  # an entry with a reason, no files
            'b"; source "$D/x.sh"', "echo 'a\n'; source \"$D/x.sh\"; echo '", 'say "x"; "source" \'$D/x.sh\'',
            "bash -c 'source \"$1\"; guest_guard' _ \"$base/guest/guard.sh\"", "run_x label bash -c 'source \"$1\"' _ path",
            "x bash -c -- 'source -- \"$D/x.sh\"'",
        ]
        ignored = ['echo bash -c "source $D/x.sh"', "printf '%s\\n' 'sudo bash -c \". $D/x.sh\"'", "command -v source",
                   "command -v . ", "bash -c 'echo source'", "bash script.sh -c '. x'", "ls . ; cd .", "x=source; echo $x",
                   '"source" ', 'function f { echo ok; }', "coproc P { echo . ; }", 'echo "source x" # ; source "$D/x.sh"',
                   "perl -ne 'print \"a\" . (defined $2 ? 1 : 0) . \"\\n\"' || true", 'x=${A:-.} ; ls ${B} . ${C}']
        with self.under_root(root):
            for line in resolved:
                with self.subTest(resolved=line):
                    (root / "lib/s.sh").write_text(line + "\n")
                    entries = source_lines("lib/s.sh")
                    self.assertEqual(len(entries), 1, entries)
                    self.assertEqual((entries[0][1], entries[0][2]), (["lib/x.sh"], None))
            for line in refused:
                with self.subTest(refused=line):
                    (root / "lib/s.sh").write_text(line + "\n")
                    entries = source_lines("lib/s.sh")
                    self.assertEqual(len(entries), 1, entries)
                    self.assertEqual(entries[0][1], [])
                    self.assertTrue(entries[0][2], "a refused line must say why")
            for line in ignored:
                with self.subTest(ignored=line):
                    (root / "lib/s.sh").write_text(line + "\n")
                    self.assertEqual(source_lines("lib/s.sh"), [])
        # the real tree: the wrapped source of the guest guard is seen, and the walk accepts it only through an allowlist reason
        script = "Tools/lab/tart/tests/run.sh"
        wrapped = [entry for entry in source_lines(script) if "bash -c 'source \"$1\"; guest_guard'" in entry[0]]
        self.assertEqual(len(wrapped), 1, "the wrapped source command at run.sh:221 must be seen")
        line, files, reason = wrapped[0]
        self.assertTrue(files or (script, line) in SOURCE_ALLOWLIST, "it must resolve or carry an allowlist reason")
        self.assertTrue((ROOT / "Tools/lab/tart/guest/guard.sh").is_file())

    def test_source_anchor_accepts_only_dirname_and_cd_pwd_and_refuses_ambiguous_tails(self):
        """M1-10t fix 1 item 5 (SCRIPTS-VERIFY F5): a substitution head is a script directory only as `$(dirname WORD)` or
        `$(cd [--] DIR && pwd)`, not any $(...) that mentions dirname; a variable assigned `$(dirname ..)/sub` is refused
        (the tail would be tried against the wrong directory: the decoy lib/x.sh beside lib/sub/x.sh); and a tail that exists
        under both the script directory and ROOT as different files is refused."""
        root = self.fake_root("anchors")
        (root / "lib/sub").mkdir()
        (root / "lib/sub/x.sh").write_text("SUB=1\n")
        accepted = ['source "$(dirname "$0")/x.sh"', 'source "$(dirname -- "$0")/x.sh"', 'source $(dirname $0)/x.sh',
                    'source "$(dirname "${BASH_SOURCE[0]}")/x.sh"', 'source "$( dirname "$0" )"/x.sh',
                    '. "$(cd "$(dirname "$0")" && pwd)/x.sh"', '. "$(cd -- "$(dirname "$0")" && pwd -P)/x.sh"',
                    '. "$(CDPATH= cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)/x.sh"', "source `dirname $0`/x.sh",
                    "source \"`dirname \"$0\"`/x.sh\"", "source $(cd $(dirname $0) && pwd)/x.sh"]
        refused = ['source "$(echo dirname)/x.sh"', 'source "$(basename "$0")/x.sh"', 'source "$(dirname "$0"; echo x)/x.sh"',
                   'source "$(dirname "$0" && echo)/x.sh"', 'source "$(cd /tmp && pwd)/x.sh"',
                   'source "$(cd "$(dirname "$0")/.." && pwd)/x.sh"', 'source "$(pwd)/x.sh"', 'source "$(echo pwd)/x.sh"',
                   'source "$(dirname "$0")$(echo /sub)/x.sh"', "source `echo dirname`/x.sh", 'source "$(mktemp -d; dirname)/x.sh"']
        with self.under_root(root):
            for line in accepted:
                with self.subTest(accepted=line):
                    (root / "lib/s.sh").write_text(line + "\n")
                    self.assertEqual(sourced_files("lib/s.sh"), ["lib/x.sh"], source_lines("lib/s.sh"))
            for line in refused:
                with self.subTest(refused=line):
                    (root / "lib/s.sh").write_text(line + "\n")
                    entries = source_lines("lib/s.sh")
                    self.assertEqual([(entry[1], bool(entry[2])) for entry in entries], [([], True)], entries)
            for text in ('D="$(dirname "$0")/sub"\nsource "$D/x.sh"\n', 'D=$(dirname "$0")/sub\nsource "${D}/x.sh"\n',
                         'f() {\n  local D="$(dirname "$0")/sub"\n  source "$D/x.sh"\n}\n',
                         "D=`dirname $0`/sub\nsource $D/x.sh\n", 'export D="$(cd "$(dirname "$0")" && pwd)/sub"\n. "$D/x.sh"\n'):
                with self.subTest(decoy=text):
                    (root / "lib/s.sh").write_text(text)
                    entries = source_lines("lib/s.sh")
                    self.assertEqual([(entry[1], "sub" in (entry[2] or "")) for entry in entries], [([], True)], entries)
            for text in ('D="$(dirname "$0")"\nsource "$D/x.sh"\n', 'D="$(cd "$(dirname "$0")" && pwd)"\nsource "$D/x.sh"\n'):
                with self.subTest(plain=text):
                    (root / "lib/s.sh").write_text(text)
                    self.assertEqual(sourced_files("lib/s.sh"), ["lib/x.sh"])
            # the same tail under the script directory and ROOT, two different files: refuse, name both
            (root / "x.sh").write_text("ROOTED=1\n")
            (root / "lib/s.sh").write_text('source "$D/x.sh"\n')
            entries = source_lines("lib/s.sh")
            self.assertEqual(len(entries), 1, entries)
            self.assertEqual(entries[0][1], [])
            self.assertIn("lib/x.sh", entries[0][2])
            self.assertIn(" x.sh", entries[0][2].replace("lib/x.sh", ""))
            # a script at the root has one anchor: not ambiguous
            (root / "top.sh").write_text('source "$D/x.sh"\n')
            self.assertEqual(sourced_files("top.sh"), ["x.sh"])

    def test_a_line_continuation_joins_with_nothing(self):
        """M1-10t fix 1 item 6 (SCRIPTS-VERIFY F6): bash removes backslash-newline, so `"$D"/\\<newline>x.sh` is "$D"/x.sh."""
        root = self.fake_root("continuations")
        with self.under_root(root):
            for text in ('source "$D"/\\\nx.sh\n', 'source "$D/"\\\nx.sh\n', 'source "$D/x\\\n.sh"\n', 'source \\\n  "$D/x.sh"\n',
                         '. "$D/\\\nx.sh"\n', 'source "$D"\\\n/x.sh\n', 'source "$D/x.sh" \\\n  || true\n', 'source "$D/lib\\\n/x.sh"\n'):
                with self.subTest(text=text):
                    (root / "lib/s.sh").write_text(text)
                    entries = source_lines("lib/s.sh")
                    self.assertEqual([(entry[1], entry[2]) for entry in entries], [(["lib/x.sh"], None)], entries)
                    self.assertEqual(len(entries[0][0].splitlines()), 1)

    def test_scanner_reads_here_strings_traps_aliases_variables_and_case_arm_tails(self):
        """M1-40 item 2 (SCRIPTS-FIX1-VERIFY N2): a source command in a shell's here-string word, in the action of trap, in the
        value of an alias or in a variable that eval or `bash -c` runs is read; the tail of a multi-line string followed by a
        case arm (`x"; a) source ...;;`) is caught by the backstop; a `)` followed by a word that is not source or `.`, or by a
        `.` with a parenthesised argument (perl), is no command start."""
        root = self.fake_root("here-strings")
        resolved = [
            "bash <<<'source \"$D/x.sh\"'", 'sh <<< ". $D/x.sh"', 'bash -s <<< "source \\"$D/x.sh\\""', "zsh<<<'. \"$D/x.sh\"'",
            "/bin/bash <<<$'source \"$D/x.sh\"'", "sudo bash -s <<< '. \"$D/x.sh\"'", "FOO=1 sh <<<'source \"$D/x.sh\"'",
            "trap 'source \"$D/x.sh\"' EXIT", "trap -- '. \"$D/x.sh\"' ERR", 'trap "source \\"$D/x.sh\\"" INT TERM',
            "alias s='source \"$D/x.sh\"'", 'alias s=". $D/x.sh" t=true', "alias -- s='. \"$D/x.sh\"'",
            "c='. \"$D/x.sh\"'; eval \"$c\"", "c='source \"$D/x.sh\"'\neval $c", "c='. \"$D/x.sh\"'\nbash -c \"$c\"",
            "local c='. \"$D/x.sh\"'\nsome work\neval \"${c}\"", "bash <<<'echo a; source \"$D/x.sh\"'",
            "trap 'echo bye; source \"$D/x.sh\"' EXIT",
        ]
        refused = [  # an entry with a reason, no files
            'x"; a) source "$D/x.sh";;', "end'; a) . \"$D/x.sh\" ;;", 'tail"; b) source "$D/x.sh" ;;',
            'x"; a) source "$D/missing.sh";;', "trap 'source \"$f\"' EXIT", "alias s='source \"$D/$name.sh\"'",
            "bash <<<'source \"$D/missing.sh\"'",
        ]
        ignored = [
            "cat <<<'source \"$D/x.sh\"'", "read x <<< \". $D/x.sh\"", "trap 'echo source' EXIT", "trap - EXIT", "trap -p",
            "trap '' INT", "trap cleanup EXIT", "alias ll='ls -l'", "alias -p", "alias s='echo . x'", "c='ls'; eval \"$c\"",
            "c='source'; eval \"$c\"", "echo \"a) . b\"", "echo $(date) . ($x)", "bash <<<'echo source'", "bash <<<'ls . x'",
            "perl -ne 'print \"a\" . (defined $2 ? 1 : 0) . \"\\n\"' || true", "case $x in a) echo . ;; esac",
            "case $x in a) . ;; esac", "x=$(date) . (1)", "f) source", "f) .", 'echo "x) source"',
        ]
        with self.under_root(root):
            for line in resolved:
                with self.subTest(resolved=line):
                    (root / "lib/s.sh").write_text(line + "\n")
                    entries = source_lines("lib/s.sh")
                    self.assertEqual(len(entries), 1, entries)
                    self.assertEqual((entries[0][1], entries[0][2]), (["lib/x.sh"], None))
            for line in refused:
                with self.subTest(refused=line):
                    (root / "lib/s.sh").write_text(line + "\n")
                    entries = source_lines("lib/s.sh")
                    self.assertEqual(len(entries), 1, entries)
                    self.assertEqual(entries[0][1], [])
                    self.assertTrue(entries[0][2], "a refused line must say why")
            for line in ignored:
                with self.subTest(ignored=line):
                    (root / "lib/s.sh").write_text(line + "\n")
                    self.assertEqual(source_lines("lib/s.sh"), [])

    def test_a_reassigned_head_variable_is_refused_and_a_dirname_head_is_the_script_directory(self):
        """M1-40 item 3 (SCRIPTS-FIX1-VERIFY N3): with lib/x.sh beside the decoy lib/sub/x.sh, a head variable that is assigned
        again (NAME=, NAME+=, printf -v NAME, read NAME) or assigned a path below or above the script directory is refused
        and never resolves lib/x.sh; `$(dirname "$0")/..` is the parent directory, not a subdirectory; a head that is
        exactly dirname or cd-pwd of the script is the script directory, so a same-named file at the root is no ambiguity."""
        root = self.fake_root("reassigned")
        (root / "lib/sub").mkdir()
        (root / "lib/sub/x.sh").write_text("SUB=1\n")
        refused = {
            'D="$(cd "$(dirname "$0")/sub" && pwd)"\nsource "$D/x.sh"\n': "subdirectory",
            'D="$(dirname "$0")"\nD="$D/sub"\nsource "$D/x.sh"\n': "reassigned",
            'D="$(dirname "$0")"\nD+=/sub\nsource "$D/x.sh"\n': "reassigned",
            'D="$(dirname "$0")"\nD=${D}/sub\nsource "$D/x.sh"\n': "reassigned",
            'printf -v D "%s/sub" "$(dirname "$0")"\nsource "$D/x.sh"\n': "reassigned",
            'D="$(dirname "$0")"\nprintf -v D "%s/sub" "$D"\nsource "$D/x.sh"\n': "reassigned",
            'D="$(dirname "$0")"\nread -r D < conf\nsource "$D/x.sh"\n': "reassigned",
            'D="$(dirname "$0")"\nread D\nsource "${D}/x.sh"\n': "reassigned",
            'D=a\nD=b\nsource "$D/x.sh"\n': "reassigned",
            'D+=/sub\nsource "$D/x.sh"\n': "reassigned",
            'read -r D\nsource "$D/x.sh"\n': "reassigned",
            'f() { local D="$(dirname "$0")"; }\ng() { local D=/elsewhere; source "$D/x.sh"; }\n': "reassigned",
            'D="$(dirname "$0")/../lib"\nsource "$D/x.sh"\n': "beside",
            'D="$(cd "$(dirname "$0")/../lib" && pwd)"\nsource "$D/x.sh"\n': "beside",
            'D="$(dirname "$0")/sub"\nsource "$D/x.sh"\n': "subdirectory",
            'D=$(dirname "$0")/sub\nsource "${D}/x.sh"\n': "subdirectory",
        }
        accepted = [
            'D="$(dirname "$0")"\nsource "$D/x.sh"\n', 'D="$(cd "$(dirname "$0")" && pwd)"\nsource "$D/x.sh"\n',
            'D=$(dirname "$0")\nsource "${D}/x.sh"\n', 'D=`dirname $0`\nsource "$D"/x.sh\n', 'readonly D="$(dirname "$0")"\n. "$D/x.sh"\n',
            'D="$(dirname "$0")"\nsource "$D/x.sh"\nsource "$D/x.sh"\n', 'source "$(dirname "$0")/x.sh"\n',
            'D="$(dirname "$0")"\nf() { D="$(dirname "$0")"; source "$D/x.sh"; }\nf\n',  # the same value again is no change
            '. "$(cd "$(dirname "$0")" && pwd)/x.sh"\n', 'source $(dirname $0)/x.sh\n', "source `dirname $0`/x.sh\n",
        ]
        with self.under_root(root):
            for text, word in refused.items():
                with self.subTest(refused=text):
                    (root / "lib/s.sh").write_text(text)
                    entries = source_lines("lib/s.sh")
                    self.assertEqual([entry[1] for entry in entries], [[]] * len(entries), entries)
                    self.assertEqual(len(entries), text.count("source"), entries)
                    reasons = [entry[2] for entry in entries if entry[2]]
                    self.assertTrue(reasons and word in reasons[0], entries)
                    self.assertEqual(sourced_files("lib/s.sh"), [])
            # `$(dirname "$0")/..` is the parent directory: an ancestor is not called a subdirectory, and is not refused for it
            (root / "lib/s.sh").write_text('D="$(dirname "$0")/.."\nsource "$D/x.sh"\n')
            self.assertNotIn("subdirectory", source_lines("lib/s.sh")[0][2] or "")
            # no decoy at the root: the script directory is the only anchor of a dirname head, whatever else exists
            (root / "x.sh").write_text("ROOTED=1\n")
            for text in accepted:
                with self.subTest(accepted=text):
                    (root / "lib/s.sh").write_text(text)
                    entries = source_lines("lib/s.sh")
                    self.assertEqual([(entry[1], entry[2]) for entry in entries], [(["lib/x.sh"], None)] * len(entries), entries)
            # an unknown variable head keeps both anchors, so the same tree is still ambiguous for it
            (root / "lib/s.sh").write_text('source "$D/x.sh"\n')
            self.assertIn("ambiguous", source_lines("lib/s.sh")[0][2])
            # a script at the root: its directory is ROOT
            (root / "top.sh").write_text('source "$(dirname "$0")/x.sh"\n')
            self.assertEqual(sourced_files("top.sh"), ["x.sh"])

    def test_a_sourced_symlink_must_resolve_inside_the_repository_to_a_tracked_file(self):
        """M1-40 item 5 (SCRIPTS-FIX1-VERIFY N5): a tracked symlink whose target is untracked, ignored, absent or outside the
        repository is refused by the completeness walk; a symlink to a tracked file inside the repository is accepted."""
        files = {
            ".gitignore": "ignored-target.sh\n", "Tools/s/real.sh": "R=1\n", "Tools/s/untracked-target.sh": "U=1\n",
            "Tools/s/ignored-target.sh": "I=1\n",
            "Tools/s/in-untracked.sh": 'source "$(dirname "$0")/link-untracked.sh"\n',
            "Tools/s/in-ignored.sh": 'source "$(dirname "$0")/link-ignored.sh"\n',
            "Tools/s/in-outside.sh": 'source "$(dirname "$0")/link-outside.sh"\n',
            "Tools/s/in-absent.sh": 'source "$(dirname "$0")/link-absent.sh"\n',
            "Tools/s/in-good.sh": 'source "$(dirname "$0")/link-good.sh"\n',
            "Tools/s/in-chain.sh": 'source "$(dirname "$0")/link-chain.sh"\n',
        }
        links = {"Tools/s/link-untracked.sh": "untracked-target.sh", "Tools/s/link-ignored.sh": "ignored-target.sh",
                 "Tools/s/link-outside.sh": "../../../elsewhere/target.sh", "Tools/s/link-absent.sh": "no-such-target.sh",
                 "Tools/s/link-good.sh": "real.sh", "Tools/s/link-chain.sh": "link-untracked.sh"}
        add = [name for name in files if name not in ("Tools/s/untracked-target.sh", "Tools/s/ignored-target.sh")] + list(links)
        root = self.git_fixture("symlinks", files, add, links)
        outside = root.parent / "elsewhere"
        outside.mkdir()
        (outside / "target.sh").write_text("E=1\n")
        with self.under_root(root):
            tracked = tracked_files()
            for name in links:
                self.assertIn(name, tracked)
            problems, walk, resolved = source_completeness(tracked, {})
            by_script = {name: [p for p in problems if p.startswith(f"Tools/s/{name}.sh: ")]
                         for name in ("in-untracked", "in-ignored", "in-outside", "in-absent", "in-good", "in-chain")}
            self.assertEqual(by_script["in-good"], [], problems)
            for name in ("in-untracked", "in-ignored", "in-chain"):
                self.assertEqual(len(by_script[name]), 1, problems)
                self.assertIn("symlink", by_script[name][0])
                self.assertIn("untracked", by_script[name][0])
            self.assertEqual(len(by_script["in-outside"]), 1, problems)
            self.assertIn("outside the repository", by_script["in-outside"][0])
            self.assertEqual(len(by_script["in-absent"]), 1, problems)
            self.assertIn("no file", by_script["in-absent"][0])
            self.assertEqual(len(problems), 5, problems)
            # source_lines itself never lists the outside target as a resolved file
            self.assertEqual(source_lines("Tools/s/in-outside.sh")[0][1], [])
            self.assertEqual(source_lines("Tools/s/in-good.sh")[0][1], ["Tools/s/link-good.sh"])
            self.assertEqual(resolved, 1)

    def test_every_tracked_shell_script_source_line_resolves_or_is_allowlisted(self):
        """M1-10t (M1-10s VERIFY F1, VERIFY-B LOW-2; fix pass 1): walk `git ls-files` for every shell script (a shell suffix or a
        shell shebang, `.githooks/pre-commit` included) and every file those scripts source, whatever its suffix. Each
        source / . line must resolve to a tracked file, or sit in SOURCE_ALLOWLIST with a reason. A line the scanner cannot
        resolve is refused (a command it cannot read is refused too), never skipped; a resolved file that git does not
        track (untracked or ignored) is refused too."""
        problems, walk, resolved = source_completeness(tracked_files(), SOURCE_ALLOWLIST)
        for name in ("Config/Scripts/lib.sh", "Tools/lab/tart/lib.sh", "Tools/lab/harness-deadlines.sh", ".githooks/pre-commit",
                     "Tools/lab/cutover-rehearsal.sh", "Tools/lab/tart/tests/run.sh"):
            self.assertIn(name, walk, "the walk must cover " + name)
        self.assertEqual(problems, [], "source lines the scanner cannot resolve to a tracked file: fix the line or allowlist it "
                                       "with a reason")
        self.assertGreater(resolved, 40, "the walk resolved too few source lines to be real")

    def test_sourced_files_follow_any_suffix_and_survive_non_utf8(self):
        """M1-10t (M1-10s VERIFY-B LOW-3): a sourced file is followed whatever its suffix (conf.env, then z.sh), and bytes
        that are not UTF-8 are read with errors="replace", never raised (the j-binary.sh input)."""
        root = self.fake_root("suffixes")
        lib = root / "lib"
        (lib / "z.sh").write_text("Z=1\n")
        (lib / "i-env.sh").write_text('source "$D/conf.env"\n')
        (lib / "conf.env").write_text('source "$D/z.sh"\n')
        (lib / "j-binary.sh").write_bytes(b"\xff\xfe\x00")
        (lib / "k.sh").write_text('source "$D/j-binary.sh"\nsource "$D/x.sh"\n')
        (lib / "m-latin.sh").write_bytes(b'# latin-1 \xe9 and \xff\nsource "$D/z.sh"\n')
        (lib / "data.py").write_text('source "$D/z.sh"\n')
        with self.under_root(root):
            self.assertEqual(sourced_files("lib/i-env.sh"), ["lib/conf.env"])
            self.assertEqual(sourced_files("lib/conf.env"), ["lib/z.sh"])
            self.assertEqual(sourced_files("lib/j-binary.sh"), [])
            self.assertEqual(sourced_files("lib/m-latin.sh"), ["lib/z.sh"])
            self.assertEqual(sourced_files("lib/k.sh"), ["lib/j-binary.sh", "lib/x.sh"])
            tree = self.work / "suffix-tree"
            for name in ("lib/i-env.sh", "lib/k.sh", "lib/m-latin.sh"):
                (tree / name).parent.mkdir(parents=True, exist_ok=True)
                self.copy_source(root / name, tree / name)
            for name in ("lib/conf.env", "lib/z.sh", "lib/j-binary.sh", "lib/x.sh"):
                self.assertTrue((tree / name).is_file(), name + " was not copied")
            self.assertEqual((tree / "lib/j-binary.sh").read_bytes(), b"\xff\xfe\x00")
            self.assertEqual(missing_sources(tree, ["lib/i-env.sh", "lib/k.sh", "lib/m-latin.sh", "lib/conf.env"]), [])
            # i-env.sh alone, in a tree of its own: conf.env (not a .sh file) and, through it, z.sh must both arrive (mutant M7:
            # a copy that follows only `.sh` files stops at conf.env; m-latin.sh above sources z.sh itself and hid that)
            alone = self.work / "suffix-alone"
            (alone / "lib").mkdir(parents=True)
            self.copy_source(root / "lib/i-env.sh", alone / "lib/i-env.sh")
            self.assertEqual(sorted(path.name for path in (alone / "lib").iterdir()), ["conf.env", "i-env.sh", "z.sh"])
            self.assertEqual(missing_sources(alone, ["lib/i-env.sh", "lib/conf.env"]), [])
            bare = self.work / "suffix-bare"
            (bare / "lib").mkdir(parents=True)
            shutil.copy(lib / "i-env.sh", bare / "lib/i-env.sh")
            shutil.copy(lib / "conf.env", bare / "lib/conf.env")
            self.assertEqual(missing_sources(bare, ["lib/i-env.sh", "lib/conf.env"]), [("lib/conf.env", "lib/z.sh")])
            (bare / "lib/conf.env").unlink()
            self.assertEqual(missing_sources(bare, ["lib/i-env.sh", "lib/conf.env"]), [("lib/i-env.sh", "lib/conf.env")])
            # a file that is neither a shell script nor sourced is copied, not scanned
            plain = self.work / "plain-tree"
            (plain / "lib").mkdir(parents=True)
            self.copy_source(lib / "data.py", plain / "lib/data.py")
            self.assertEqual(sorted(path.name for path in (plain / "lib").iterdir()), ["data.py"])

    def test_source_helpers_state_what_they_check(self):
        """M1-10t (M1-10s VERIFY-B LOW-4): the docstrings say is_file() and ROOT copy, and the behaviour is exactly that."""
        self.assertIn("is_file()", sourced_files.__doc__)
        self.assertIn("tracked or not", sourced_files.__doc__)
        self.assertIn("ROOT copy", missing_sources.__doc__)
        self.assertIn("not from tree/script", missing_sources.__doc__)
        root = self.fake_root("words")  # not a git repository at all: x.sh is untracked and still counts
        (root / "lib/s.sh").write_text('source "$D/x.sh"\n')
        tree = self.work / "words-tree"
        (tree / "lib").mkdir(parents=True)
        (tree / "lib/s.sh").write_text('source "$D/y.sh"\n')  # an edited copy: its own sources are not read
        with self.under_root(root):
            self.assertEqual(sourced_files("lib/s.sh"), ["lib/x.sh"])
            self.assertEqual(missing_sources(tree, ["lib/s.sh"]), [("lib/s.sh", "lib/x.sh")])

    def test_check_runs_the_tooling_selftest_first_and_the_gate_counts_are_true(self):
        """M1-10t (M1-10s VERIFY-B NOTE-2, VERIFY F2): check.sh runs the self-test first (before lint and the build steps), a failing
        self-test stops the gate with its own status and nothing else started; check-full no longer repeats it; and
        CONTRIBUTING.md's gate-step counts equal the steps the recipes really have."""
        tree = self.work / "check-tree"
        for name in ("Config/Scripts/check.sh", "Config/Scripts/timed-step.py", "Config/Scripts/knobs.py"):
            (tree / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / name, tree / name)
        entitlements = tree / "Tools/lint/check-entitlements.sh"
        entitlements.parent.mkdir(parents=True)
        entitlements.write_text('#!/bin/bash\necho "entitlements" >>"$WGEX_TEST_CALLS"\n')
        stubs = self.work / "check-stubs"
        stubs.mkdir()
        calls = stubs / "calls"
        (stubs / "just").write_text('#!/bin/bash\necho "$*" >>"$WGEX_TEST_CALLS"\n'
                                    '[[ "$*" == "$(cat "$(dirname "$0")/fail" 2>/dev/null)" ]] && exit 3\nexit 0\n')
        (stubs / "just").chmod(0o755)
        env = {key: value for key, value in os.environ.items() if key != "WGEX_GATE_LEDGER"}
        env |= {"PATH": f"{stubs}:{env['PATH']}", "WGEX_TEST_CALLS": str(calls)}  # a WGEX_ name: gate entry drops the rest
        for failing in ("", "tooling-selftest", "lint", "engine"):
            with self.subTest(failing=failing):
                calls.write_text("")
                (stubs / "fail").write_text(failing)
                result = subprocess.run(["bash", str(tree / "Config/Scripts/check.sh")], env=env, text=True,
                                        capture_output=True, timeout=120)
                recorded = calls.read_text().splitlines()
                if failing == "tooling-selftest":
                    self.assertEqual(result.returncode, 3, result.stderr)
                    self.assertEqual(recorded, ["tooling-selftest"])
                    self.assertIn("gate-step: check/tooling-selftest exit=3", result.stdout + result.stderr)
                    continue
                self.assertEqual(recorded[0], "tooling-selftest")
                self.assertEqual(result.returncode, 0 if not failing else 1, result.stderr)
                if not failing:
                    self.assertEqual(recorded[-2:], ["test all", "test go-race"])
                    self.assertEqual(recorded.count("tooling-selftest"), 1)
        justfile = (ROOT / "justfile").read_text()
        full_steps = re.findall(r"timed-step\.py (full/[\w-]+) ", justfile)
        self.assertNotIn("full/tooling-selftest", full_steps)
        self.assertIn("full/check", full_steps)
        check_steps = re.findall(r"(?<![\w-])step ([a-z][a-z-]*) ", (ROOT / "Config/Scripts/check.sh").read_text())
        check_steps = [name for name in check_steps if name != "step"]
        self.assertEqual(check_steps[0], "tooling-selftest")
        self.assertEqual(len(check_steps) + 1, 12, "check: doctor plus the steps of check.sh")  # + check/doctor in the recipe
        contributing = (ROOT / "CONTRIBUTING.md").read_text().replace("\n", " ")
        for sentence in (f"its own {len(check_steps) + 1}-step `check: passed` line",
                         f"check-full's N counts its {len(full_steps)} `full/` steps"):
            self.assertTrue(sentence in contributing, "CONTRIBUTING.md must say: " + sentence)
    # --- M1-10t part 2: end ---

    def test_lab_library_fails_fast_when_harness_deadlines_is_absent(self):
        bare = self.work / "no-deadlines"
        (bare / "Tools/lab/tart").mkdir(parents=True)
        shutil.copy(ROOT / "Tools/lab/tart/lib.sh", bare / "Tools/lab/tart/lib.sh")
        elsewhere = self.work / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "harness-deadlines.sh").write_text("HARNESS_SCALE_DEFAULT=1\n")
        result = subprocess.run(["bash", "-c", 'source "$1"', "x", str(bare / "Tools/lab/tart/lib.sh")],
                                cwd=elsewhere, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("lab: harness deadlines missing:", result.stderr)
        self.assertIn(str(bare / "Tools/lab/harness-deadlines.sh"), result.stderr)
        self.assertNotIn("No such file or directory", result.stderr)

    def test_build_entrypoints_check_engine_before_tools(self):
        root = self.work / "guard-tree"
        for name in ("Config/Scripts/lib.sh", "Config/Scripts/build.sh", "Config/Scripts/test.sh",
                     "Config/Scripts/packages-matrix.sh", "Tools/lab/tart/build.sh", "Tools/lab/tart/lib.sh"):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            self.copy_source(ROOT / name, target)
        library = root / "Config/Scripts/lib.sh"
        library.write_text(library.read_text() + '\nrequire_current_engine() { echo "fixture stale engine" >&2; return 84; }\n')
        (root / "project.yml").write_text("  Lab: debug\n")
        for script, args in (("Config/Scripts/build.sh", ["mac", "debug"]),
                             ("Config/Scripts/test.sh", ["ios"]),
                             ("Config/Scripts/packages-matrix.sh", ["missing"]),
                             ("Tools/lab/tart/build.sh", [])):
            result = subprocess.run(["bash", str(root / script), *args],
                                    env=os.environ | {"WGEX_BUILD_ROOT": str(self.work / "builds")},
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 84, result.stdout + result.stderr)
            self.assertIn("fixture stale engine", result.stderr)

    def test_only_archive_linking_tests_require_the_matching_engine(self):
        root = self.work / "test-guards"
        for name in ("Config/Scripts/lib.sh", "Config/Scripts/test.sh"):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            self.copy_source(ROOT / name, target)
        library = root / "Config/Scripts/lib.sh"
        library.write_text(library.read_text() + '''
require_current_engine() { printf 'archive guard: %s\\n' "$*" >&2; return 84; }
''')
        for package in ("WGEXEngine", "WGEXBackendMac", "WGEXCore"):
            manifest = root / "Packages" / package / "Package.swift"
            manifest.parent.mkdir(parents=True)
            manifest.touch()
        for directory in ("Engine/go", "Tools/testpeer", "Tools/fuzz"):
            (root / directory).mkdir(parents=True)
        (root / "Tools/fuzz/run.sh").write_text('#!/bin/bash\nexit 0\n')
        tools = self.work / "bin"
        tools.mkdir()
        for name in ("go", "swift"):
            executable = tools / name
            executable.write_text('#!/bin/bash\nexit 0\n')
            executable.chmod(0o755)
        env = os.environ | {"PATH": f"{tools}:{os.environ['PATH']}",
                            "WGEX_BUILD_ROOT": str(self.work / "builds"),
                            "CLEAN_DEVELOPMENT_CACHE_ROOT": str(self.work / "cache")}
        for target in ("go-race", "fuzz", "engine", "WGEXCore"):
            result = subprocess.run(["bash", str(root / "Config/Scripts/test.sh"), target],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn("archive guard:", result.stderr)
        for target, flag in (("WGEXEngine", "--test-support"), ("tsan", "--test-support"),
                             ("WGEXBackendMac", "")):
            result = subprocess.run(["bash", str(root / "Config/Scripts/test.sh"), target],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 84, result.stdout + result.stderr)
            self.assertEqual(result.stderr.strip(), f"archive guard: {flag}".strip())

    def test_lab_build_dry_run_does_not_require_engine(self):
        root = self.work / "lab-dry"
        for name in ("Config/Scripts/lib.sh", "Tools/lab/tart/lib.sh", "Tools/lab/tart/build.sh"):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            self.copy_source(ROOT / name, target)
        library = root / "Config/Scripts/lib.sh"
        library.write_text(library.read_text() + '\nrequire_current_engine() { echo "unexpected archive guard" >&2; return 84; }\n')
        (root / "project.yml").write_text("  Lab: debug\n")
        result = subprocess.run(["bash", str(root / "Tools/lab/tart/build.sh"), "--dry-run"],
                                env=os.environ | {"WGEX_BUILD_ROOT": str(self.work / "builds")},
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("dry-run: xcodebuild build", result.stderr)
        self.assertNotIn("unexpected archive guard", result.stderr)

    def test_prose_reports_location_and_term_number(self):
        terms = [line for line in (ROOT / "Tools/lint/public-prose-denylist.txt").read_text().splitlines()
                 if line and not line.startswith("#")]
        fixture = self.work / "prose.md"
        fixture.write_text("clean\n" + terms[0] + "\n")
        result = subprocess.run(["bash", str(ROOT / "Tools/lint/check-public-prose.sh"), str(fixture)],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertRegex(result.stderr, r"denylisted term #1: .*prose\.md line(?:\(s\))? 2")
        self.assertNotIn(terms[0], result.stderr)

    # M1-23 gate log hygiene: a transcript-driven stub xcodebuild stands in for the real tool; the canaries are
    # fake values that must never reach a gate log, with or without xcbeautify.
    CANARIES = ("WGEX_CANARY", "canary-not-a-secret", "nl-two-canary", "NOTREAL", "nlname-gate-canary")
    STUB_XCODEBUILD = r"""#!/bin/bash
if [[ "${1:-}" == -list ]]; then
  echo '{"workspace": {"schemes": ["Fixture"]}}'
  exit 0
fi
echo "    export WGEX_CANARY_TOKEN=canary-not-a-secret"
echo "    export WGEX_CANARY_ESCAPED\\=canary-not-a-secret"
printf '    export WGEX_NL_CANARY="nl-one\nnl-two-canary\n    export NOTREAL=1"\n'
printf '    export "WGEX_NL_NAME\nSECOND_HALF"="nlname-gate-canary\nnlname-gate-canary-two"\n'
echo "    export WGEX_CANARY_STDERR=canary-not-a-secret" >&2
case "${STUB_SCENARIO:-pass}" in
  pass)
    echo "Test Suite 'All tests' passed at fixture."
    echo "✔ Test run with 3 tests in 1 suite passed after 0.010 seconds."
    echo "** TEST SUCCEEDED **"
    ;;
  crash)
    echo "Test Suite 'All tests' started at fixture."
    echo "WGEXiOSUnitTests (12345) encountered an error (Early unexpected exit, operation never finished bootstrapping)"
    echo "Failing tests:"
    printf '\tWGEXiOSUnitTests\n'
    echo "Testing failed:"
    printf '\tTest crashed with signal kill before starting test execution.\n'
    echo "** TEST FAILED **"
    ;;
  script)
    echo "preprocess-daemon-plist: missing input /fixture/Info.plist"
    echo "Command PhaseScriptExecution failed with a nonzero exit code"
    echo "** BUILD FAILED **"
    echo
    echo "The following build commands failed:"
    printf '\tPhaseScriptExecution Install\\ daemon\\ launchd\\ plist /fixture (in target WGEXMac from project WGEX)\n'
    echo "(1 failure)"
    ;;
  destination)
    {
      echo "xcodebuild: error: Unable to find a destination matching the provided destination specifier:"
      printf '\t\t{ id:FIXTURE-UDID }\n'
      echo
      echo "The requested device could not be found because no available devices matched the request."
    } >&2
    ;;
esac
exit "${STUB_XCODEBUILD_STATUS:-0}"
"""
    # scenario -> (text the failure tail must carry, summary lines that must be printed again after the formatter)
    SCENARIOS = {
        "pass": (None, ["Test run with 3 tests", "** TEST SUCCEEDED **"]),
        "crash": ("encountered an error", ["Testing failed:", "Failing tests:", "** TEST FAILED **"]),
        "script": ("preprocess-daemon-plist: missing input",
                   ["The following build commands failed:", "PhaseScriptExecution Install", "(1 failure)", "** BUILD FAILED **"]),
        "destination": ("The requested device could not be found", []),
    }

    def stub_bin(self, name="gate-bin"):
        stubs = self.work / name
        stubs.mkdir(exist_ok=True)
        (stubs / "xcodebuild").write_text(self.STUB_XCODEBUILD, encoding="utf-8")
        # Hosted simulator devices are WGEX-owned (M1-26): the devices are already there for build key "fixturekey" on an
        # installed iOS 27.0 runtime (a tvOS one only with STUB_TVOS), so a missing tvOS device is a missing tvOS runtime and
        # nothing is ever created.
        (stubs / "xcrun").write_text("""#!/bin/bash
tv=""
[[ "${STUB_TVOS:-0}" != 1 ]] || tv=', "com.apple.CoreSimulator.SimRuntime.tvOS-27-0": [{"name": "WGEX Apple TV fixturekey", "udid": "TV-UDID"}]'
if [[ "$1 $2 $3" == "simctl list runtimes" ]]; then
  tvrt=""
  [[ "${STUB_TVOS:-0}" != 1 ]] || tvrt=', {"identifier": "com.apple.CoreSimulator.SimRuntime.tvOS-27-0", "version": "27.0", "isAvailable": true}'
  echo '{"runtimes": [{"identifier": "com.apple.CoreSimulator.SimRuntime.iOS-27-0", "version": "27.0", "isAvailable": true}'"$tvrt"']}'
  exit 0
fi
[[ "$1 $2 $3" == "simctl list devices" ]] || { echo "stub xcrun: refused $*" >&2; exit 99; }
echo '{"devices": {"com.apple.CoreSimulator.SimRuntime.iOS-27-0": [{"name": "WGEX iPhone fixturekey", "udid": "FIXTURE-UDID"}, {"name": "iPhone 17", "udid": "SHARED-UDID"}]'"$tv"'}}'
""")
        (stubs / "rg").write_text('#!/bin/bash\nexec grep -E "$@"\n')
        for executable in stubs.iterdir():
            executable.chmod(0o755)
        return stubs

    def formatter_paths(self, stubs):
        """(label, PATH) per formatter state: absent (cat fallback) and the real xcbeautify when installed."""
        paths = [("cat fallback", f"{stubs}:/usr/bin:/bin")]
        real = shutil.which("xcbeautify")
        if real:
            paths.append(("real xcbeautify", f"{stubs}:{Path(real).parent}:/usr/bin:/bin"))
        return paths

    def gate_tree(self):
        """Guard tree with copies of every script that runs xcodebuild through xcodebuild_filter."""
        root = self.work / "gate-tree"
        for name in ("Config/Scripts/lib.sh", "Config/Scripts/test.sh", "Config/Scripts/build.sh",
                     "Config/Scripts/packages-matrix.sh", "Tools/lab/tart/build.sh"):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            self.copy_source(ROOT / name, target)
        library = root / "Config/Scripts/lib.sh"
        library.write_text(library.read_text() + '\nrequire_current_engine() { return 0; }\n')
        (root / "Config/Scripts/generate-build-identifiers.sh").write_text("#!/bin/bash\nexit 0\n")
        (root / "project.yml").write_text("name: fixture\nconfigurations:\n  Lab: debug\n")
        (root / "WGEX.xcodeproj").mkdir(exist_ok=True)
        (root / "WGEX.xcodeproj/project.pbxproj").write_text("// fixture\n")
        (root / "Packages/Fixture").mkdir(parents=True, exist_ok=True)
        (root / "Packages/Fixture/Package.swift").write_text("// fixture\n")
        return root

    def lab_bin(self, stubs):
        """Fixture-only fake tools for `lab build --dry-run`; xcodebuild is the transcript stub."""
        bin_dir = self.work / "lab-test-bin"
        bin_dir.mkdir(exist_ok=True)
        (bin_dir / "fixture-only").write_text("")
        for name in ("bash", "xcodegen"):
            (bin_dir / name).write_text("#!/bin/bash\nexit 0\n")
        shutil.copy(stubs / "xcodebuild", bin_dir / "xcodebuild")
        for executable in bin_dir.iterdir():
            executable.chmod(0o755)
        return bin_dir

    def run_gate(self, root, command, path, scenario, status, extra=None):
        environment = os.environ | {"PATH": path, "STUB_SCENARIO": scenario, "STUB_XCODEBUILD_STATUS": str(status),
                                    "CLEAN_DEV_SESSION": "x-fixturekey", "WGEX_BUILD_ROOT": str(self.work / "builds"),
                                    "CLEAN_DEVELOPMENT_CACHE_ROOT": str(self.work / "cache")} | (extra or {})
        if command[0] == "lab":
            environment["WGEX_LAB_TEST_BIN"] = str(self.work / "lab-test-bin")
            command = ["Tools/lab/tart/build.sh", "--dry-run"]
        return subprocess.run(["bash", str(root / command[0]), *command[1:]], env=environment,
                              capture_output=True, text=True)

    def assert_gate_log(self, result, scenario, status, log_name, returncode=None):
        output = result.stdout + result.stderr
        for canary in self.CANARIES:
            self.assertNotIn(canary, output)
        self.assertIsNone(re.search(r"^ +export [A-Za-z_]+=", output, re.M), output)
        self.assertEqual(result.returncode, status if returncode is None else returncode, output)
        tail, summary = self.SCENARIOS[scenario]
        for line in summary:
            self.assertIn(line, output)
        if tail is None:
            self.assertNotIn("last 80 lines", output)
        else:
            self.assertIn("last 80 lines of the env-free log", output)
            self.assertIn(tail, output.split("last 80 lines of the env-free log", 1)[1])
        logs = list((self.work / "builds").glob(f"*/logs/xcodebuild-{log_name}*.log"))
        self.assertEqual(len(logs), 1, output)
        kept = logs[0].read_text()
        for canary in self.CANARIES:
            self.assertNotIn(canary, kept)
        if tail is not None:
            self.assertIn(tail, kept)

    def test_xcodebuild_environment_dumps_never_reach_gate_logs(self):
        """M1-23: every gate caller filters xcodebuild output (single-line and multi-line values, stderr), keeps the
        failure context and run totals that xcbeautify --quiet drops, and returns xcodebuild's own status."""
        root = self.gate_tree()
        stubs = self.stub_bin()
        self.lab_bin(stubs)
        every = ("pass", "crash", "script", "destination")
        cases = [  # (command, environment, log name, scenarios)
            (["Config/Scripts/test.sh", "ios"], {}, "WGEX-iOS-test", every),
            (["Config/Scripts/test.sh", "mac"], {}, "WGEX-Mac-build-for-testing", ("pass", "script")),
            (["Config/Scripts/test.sh", "tv"], {"STUB_TVOS": "1"}, "WGEX-TV-test", ("pass", "crash")),
            (["Config/Scripts/test.sh", "tv"], {"STUB_TVOS": "0"}, "WGEX-TV-build-for-testing", ("pass", "script")),
            (["Config/Scripts/build.sh", "ios"], {}, "WGEX-iOS-build-Debug", ("pass", "script")),
            (["lab"], {}, "lab-WGEX-Mac-build", ("pass", "crash")),
            (["Config/Scripts/packages-matrix.sh", "--macos"], {}, "package-Fixture-macOS", ("pass", "script")),
        ]
        for label, path in self.formatter_paths(stubs):
            for command, extra, log_name, scenarios in cases:
                for scenario in scenarios:
                    status = 0 if scenario == "pass" else 65
                    with self.subTest(formatter=label, command=" ".join(command), tvos=extra.get("STUB_TVOS"),
                                      scenario=scenario):
                        shutil.rmtree(self.work / "builds", ignore_errors=True)
                        result = self.run_gate(root, command, path, scenario, status, extra)
                        # packages-matrix lists its failures and exits 1; every other caller returns xcodebuild's status
                        matrix = command[0].endswith("packages-matrix.sh") and status != 0
                        self.assert_gate_log(result, scenario, status, log_name, 1 if matrix else None)

    # xcodebuild 27.2 prints exported names that are not identifiers; every shape, single- and multi-line, with a
    # "leak" marker in each value (and in the multi-line continuations) that must never reach any output or log.
    ODD_NAME_TRANSCRIPT = [
        "    export 1X=single-1x-leak",
        '    export 1X="multi-1x-leak',
        'second-1x-leak"',
        "    export A.B=single-ab-leak",
        '    export A.B="multi-ab-leak',
        'second-ab-leak"',
        "    export A.B\\=escaped-ab-leak",
        "    export my-var=single-myvar-leak",
        '    export my-var="multi-myvar-leak',
        'second-myvar-leak"',
        '    export "FAKE SPACE"="single-space-leak"',
        '    export "FAKE SPACE"="multi-space-leak',
        'second-space-leak"',
        '    export "A=B"="multi-eq-leak',
        'second-eq-leak"',
        '    export "Q\\"N"\\=escaped-quoted-leak',
        '    export "BASH_FUNC_f%%"="() {  echo \\"fn-body-leak\\"',
        '}"',
        '    export odd.ml="o1',
        'odd-ml-leak"',
        # a newline inside the NAME: the name opens a quote on one line and closes it on a later one
        '    export "NL-leak-1',
        'NAME-leak-1"="single-nlname-leak"',
        '    export "NL-leak-2',
        'NAME-leak-2"="multi-nlname-leak',
        'second-nlname-leak"',
        '    export "NL-leak-3',
        'NAME-leak-3"\\=escaped-nlname-leak',
        '    export "NL-leak-4',
        'MIDDLE-leak-4',
        'NAME-leak-4"="two-newline-leak',
        'second-two-newline-leak"',
    ]

    def filter_library(self):
        library = self.work / "filter-lib/Config/Scripts/lib.sh"
        if not library.exists():
            library.parent.mkdir(parents=True)
            self.copy_source(ROOT / "Config/Scripts/lib.sh", library)
        return library

    def run_filter(self, transcript, path="/usr/bin:/bin", script="xcodebuild_filter fixture", umask=None):
        library = self.filter_library()
        prefix = f"umask {umask}; " if umask else ""
        return subprocess.run(["bash", "-c", f'{prefix}source "{library}"; {script}'],
                              input=transcript, capture_output=True, text=True,
                              env=os.environ | {"PATH": path, "WGEX_BUILD_ROOT": str(self.work / "builds")})

    def kept_logs(self, label="fixture"):
        return sorted((self.work / "builds").glob(f"*/logs/xcodebuild-{label}-*.log"))

    def test_xcodebuild_filter_drops_multi_line_values_without_a_formatter(self):
        """M1-23: continuation lines of a multi-line exported value are dropped up to the unescaped closing quote,
        whatever the exported name looks like, and nothing exported reaches stdout, stderr or the kept log."""
        transcript = "\n".join([
            "CompileSwift normal arm64 fixture.swift",
            '    export WGEX_NL_CANARY="nl-one',
            "nl-two-canary",
            '    export NOTREAL=1"',
            "kept after multi-line value",
            '    export WGEX_ESCAPED_QUOTE="ends with a backslash quote\\"',
            "continuation after escaped quote",
            'closing line"',
            '    export WGEX_ONE_LINE="complete value"',
            "kept after one-line quoted value",
            '    export WGEX_CRLF="first\r',
            'second-crlf-canary"\r',
            "kept after CRLF value",
            "    export WGEX_PLAIN=value with spaces",
            "    export WGEX_BACKSLASH\\=value",
            *self.ODD_NAME_TRANSCRIPT,
            "kept after odd names",
            "warning: kept",
            ""])
        kept = ["CompileSwift normal arm64 fixture.swift", "kept after multi-line value", "kept after one-line quoted value",
                "kept after CRLF value", "kept after odd names", "warning: kept"]
        stubs = self.stub_bin()
        for label, path in self.formatter_paths(stubs):
            with self.subTest(formatter=label):
                shutil.rmtree(self.work / "builds", ignore_errors=True)
                result = self.run_filter(transcript, path)
                self.assertEqual(result.returncode, 0, result.stderr)
                output = result.stdout + result.stderr
                for marker in ("leak", "canary", "NOTREAL", "export "):
                    self.assertNotIn(marker, output)
                logs = self.kept_logs()
                self.assertEqual(len(logs), 1, output)
                self.assertEqual(logs[0].read_text().splitlines(), kept)
                if label == "cat fallback":
                    self.assertEqual(result.stdout.splitlines(), kept)
                    self.assertEqual(result.stderr, "")

    def test_xcodebuild_filter_reports_withheld_lines_when_a_value_never_closes(self):
        """M1-23: an exported value left open at end of input is announced in the stream (so in the log and the
        output) instead of silently swallowing the rest; xcodebuild_finish tells an empty log from a missing one."""
        transcript = "\n".join(['    export X="open', "Compile foo", "error: real failure", "** BUILD FAILED **", ""])
        result = self.run_filter(transcript, script='xcodebuild_filter fixture; xcodebuild_finish fixture 65 0')
        notice = "xcodebuild_filter: 4 lines withheld after an unterminated exported value"
        self.assertEqual(result.returncode, 65, result.stderr)
        self.assertEqual(result.stdout.count(notice), 2, result.stdout)  # in the stream and in the failure tail
        self.assertEqual(self.kept_logs()[0].read_text().splitlines(), [notice])
        self.assertNotIn("no env-free log was kept", result.stdout)
        self.assertNotIn("Compile foo", result.stdout)
        # a closed value never produces the notice
        closed = self.run_filter('    export X="a\nb"\nkept\n')
        self.assertEqual(closed.stdout, "kept\n")
        # one withheld line is "1 line", never "1 lines"; an unterminated NAME is announced the same way
        shutil.rmtree(self.work / "builds", ignore_errors=True)
        single = self.run_filter('kept\n    export X="open')
        self.assertEqual(single.stdout.splitlines(), ["kept", "xcodebuild_filter: 1 line withheld after an unterminated exported value"])
        self.assertNotIn("1 lines", single.stdout)
        shutil.rmtree(self.work / "builds", ignore_errors=True)
        named = self.run_filter('    export "NL-leak\nstill-the-name-leak\n')
        self.assertEqual(named.stdout.splitlines(), ["xcodebuild_filter: 2 lines withheld after an unterminated exported value"])
        # a name that closes later is dropped together with its value, then normal output resumes
        shutil.rmtree(self.work / "builds", ignore_errors=True)
        resumed = self.run_filter('    export "NL\nNAME"="v\nw"\nafter\n')
        self.assertEqual(resumed.stdout, "after\n")
        # an empty stream is a log that was kept but is empty, which is not the same as no log
        shutil.rmtree(self.work / "builds", ignore_errors=True)
        empty = self.run_filter("", script='xcodebuild_filter fixture; xcodebuild_finish fixture 65 0')
        self.assertEqual(empty.returncode, 65, empty.stderr)
        self.assertIn("env-free log kept but empty", empty.stdout)
        self.assertNotIn("no env-free log was kept", empty.stdout)

    def test_xcodebuild_kept_log_hygiene(self):
        """M1-23: the logs directory is 0700 and the log 0600 whatever the umask; a stale log is never reported as
        this run; each run owns its file and only the newest three per label survive."""
        result = self.run_filter("kept line\n", umask="022")
        self.assertEqual(result.returncode, 0, result.stderr)
        log = self.kept_logs()[0]
        self.assertEqual(log.stat().st_mode & 0o777, 0o600)
        self.assertEqual(log.parent.stat().st_mode & 0o777, 0o700)
        # an existing, looser logs directory is tightened as well
        log.parent.chmod(0o755)
        self.run_filter("kept line\n", umask="022")
        self.assertEqual(log.parent.stat().st_mode & 0o777, 0o700)
        # stale read-only log of the same run name (pid reuse): replaced, never reported as this run
        stale = (
            'log="$(xcodebuild_log_path stale)"; mkdir -p "$(dirname "$log")"; printf "** TEST FAILED **\\n" >"$log"; '
            'chmod 0400 "$log"; printf "ok line\\n** TEST SUCCEEDED **\\n" | xcodebuild_filter stale; '
            'xcodebuild_finish stale 0 0; stat -f %Lp "$log"; grep -c "TEST FAILED" "$log" || true')
        result = self.run_filter("", script=stale)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("TEST FAILED", result.stdout.split("600")[0], result.stdout)
        self.assertIn("** TEST SUCCEEDED **", result.stdout)
        self.assertEqual(result.stdout.split()[-2:], ["600", "0"], result.stdout)
        # a log that cannot be created: one-line notice on stderr, output still passes, nothing kept
        shutil.rmtree(self.work / "builds", ignore_errors=True)
        blocked = (
            'root="$(build_root)"; mkdir -p "$root"; : >"$root/logs"; '
            'printf "through\\n** TEST FAILED **\\n" | xcodebuild_filter blocked; xcodebuild_finish blocked 65 0')
        result = self.run_filter("", script=blocked)
        self.assertEqual(result.returncode, 65, result.stderr)
        self.assertIn("through", result.stdout)
        self.assertIn("no env-free log was kept for blocked", result.stdout)
        self.assertNotIn("last 80 lines", result.stdout)
        self.assertEqual(len([line for line in result.stderr.splitlines() if line]), 1, result.stderr)
        self.assertIn("xcodebuild_filter:", result.stderr)
        # one file per run; the newest three per label survive and other labels or shapes are left alone
        shutil.rmtree(self.work / "builds", ignore_errors=True)
        seed = (
            'dir="$(dirname "$(xcodebuild_log_path lbl)")"; mkdir -p "$dir"; '
            'for n in 1 2 3 4; do : >"$dir/xcodebuild-lbl-400000$n.log"; touch -t 2001010$n"00" "$dir/xcodebuild-lbl-400000$n.log"; done; '
            ': >"$dir/xcodebuild-lbl-extra-7.log"; : >"$dir/xcodebuild-lbl-notapid.log"; '
            'touch -t 200001010000 "$dir/xcodebuild-lbl-extra-7.log" "$dir/xcodebuild-lbl-notapid.log"; '
            'echo run | xcodebuild_filter lbl; ls "$dir"')
        result = self.run_filter("", script=seed)
        self.assertEqual(result.returncode, 0, result.stderr)
        names = [line for line in result.stdout.splitlines() if line.startswith("xcodebuild-lbl")]
        self.assertEqual(len(names), 5, names)
        for gone in ("xcodebuild-lbl-4000001.log", "xcodebuild-lbl-4000002.log"):
            self.assertNotIn(gone, names)
        for kept in ("xcodebuild-lbl-4000003.log", "xcodebuild-lbl-4000004.log", "xcodebuild-lbl-extra-7.log", "xcodebuild-lbl-notapid.log"):
            self.assertIn(kept, names)
        # two concurrent runs of one label write different files and never tear each other's tail
        shutil.rmtree(self.work / "builds", ignore_errors=True)
        library = self.filter_library()
        environment = os.environ | {"PATH": "/usr/bin:/bin", "WGEX_BUILD_ROOT": str(self.work / "builds")}
        children = [subprocess.Popen(
            ["bash", "-c", f'source "{library}"; for n in $(seq 1 3000); do echo "run-{tag} $n"; done | xcodebuild_filter shared'],
            env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for tag in "AB"]
        self.assertEqual([child.wait() for child in children], [0, 0])
        logs = self.kept_logs("shared")
        self.assertEqual(len(logs), 2)
        self.assertEqual(sorted({line.split()[0] for log in logs for line in log.read_text().splitlines()}), ["run-A", "run-B"])
        for log in logs:
            self.assertEqual(len(log.read_text().splitlines()), 3000)
            self.assertEqual(len({line.split()[0] for line in log.read_text().splitlines()}), 1)

    def test_xcodebuild_retention_never_prunes_a_live_log_or_this_runs_own(self):
        """M1-23 fix 3: retention runs before this run's log exists, skips logs whose pid is alive or that are under
        an hour old (a future mtime counts), and this run's own log is created 0600 whatever the umask."""
        library = self.filter_library()
        sync = self.work / "overlap-sync"
        sync.mkdir()
        environment = os.environ | {"PATH": "/usr/bin:/bin", "WGEX_BUILD_ROOT": str(self.work / "builds"), "SYNC": str(sync)}
        script = (f'source "{library}"; {{ echo "line-$TAG"; : >"$SYNC/ready-$TAG"; '
                  'while [[ ! -e "$SYNC/go" ]]; do sleep 0.05; done; echo "tail-$TAG"; echo "** TEST FAILED **"; } '
                  '| xcodebuild_filter shared; xcodebuild_finish shared 65 0')
        children = {}
        try:
            for tag in "ABCD":  # each run starts only after the previous one has its log open, so all four overlap
                children[tag] = subprocess.Popen(["bash", "-c", script], env=environment | {"TAG": tag}, text=True,
                                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                for _ in range(400):
                    if (sync / f"ready-{tag}").exists():
                        break
                    time.sleep(0.05)
                else:
                    self.fail(f"run {tag} never opened its log")
            (sync / "go").write_text("")
            finished = {tag: child.communicate(timeout=120) for tag, child in children.items()}
        finally:
            for child in children.values():
                if child.poll() is None:
                    child.kill()
        for tag, (stdout, stderr) in finished.items():
            with self.subTest(run=tag):
                self.assertEqual(children[tag].returncode, 65, stderr)
                self.assertNotIn("no env-free log was kept", stdout)
                self.assertIn("xcodebuild summary (shared):", stdout)
                self.assertIn("** TEST FAILED **", stdout.split("xcodebuild summary (shared):", 1)[1])
                self.assertIn(f"tail-{tag}", stdout.split("last 80 lines of the env-free log", 1)[1])
                self.assertEqual(stderr, "")
        logs = self.kept_logs("shared")
        self.assertEqual(len(logs), 4)
        self.assertEqual(sorted(log.read_text().split()[0] for log in logs), [f"line-{tag}" for tag in "ABCD"])
        # three future-dated logs of other (dead) runs are under an hour old by the clock, so none is pruned and this
        # run's own log is not ranked out of existence; it is created 0600 under a permissive umask
        shutil.rmtree(self.work / "builds", ignore_errors=True)
        seed = (
            'dir="$(dirname "$(xcodebuild_log_path fut)")"; mkdir -p "$dir"; '
            'for n in 1 2 3; do : >"$dir/xcodebuild-fut-400000$n.log"; touch -t 20300101$n"000" "$dir/xcodebuild-fut-400000$n.log"; done; '
            'echo "own line" | xcodebuild_filter fut; xcodebuild_finish fut 0 0')
        result = self.run_filter("", script=seed, umask="022")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        logs = self.kept_logs("fut")
        self.assertEqual(len(logs), 4, [log.name for log in logs])
        own = [log for log in logs if not log.name.startswith("xcodebuild-fut-400000")]
        self.assertEqual(len(own), 1)
        self.assertEqual(own[0].read_text(), "own line\n")
        self.assertEqual(own[0].stat().st_mode & 0o777, 0o600)
        self.assertNotIn("no env-free log was kept", result.stdout)

    def test_xcodebuild_formatter_that_exits_early_cannot_truncate_the_kept_log(self):
        """M1-23: a formatter that quits after one line is drained, so xcodebuild is not SIGPIPEd and the kept log is
        whole; a formatter that fails is still reported through the pipeline status."""
        stubs = self.work / "early-formatter"
        stubs.mkdir()
        (stubs / "xcbeautify").write_text("#!/bin/bash\nhead -n 1\n")
        (stubs / "xcbeautify").chmod(0o755)
        flood = 'set -o pipefail; seq 1 200000 | xcodebuild_filter flood; echo "pipeline=$?" >&2'
        result = self.run_filter("", path=f"{stubs}:/usr/bin:/bin", script=flood)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("pipeline=0", result.stderr)
        self.assertEqual(len(self.kept_logs("flood")[0].read_text().splitlines()), 200000)
        failing = self.work / "failing-formatter"
        failing.mkdir()
        (failing / "xcbeautify").write_text("#!/bin/bash\nhead -n 1\nexit 3\n")
        (failing / "xcbeautify").chmod(0o755)
        result = self.run_filter("", path=f"{failing}:/usr/bin:/bin",
                                 script='set -o pipefail; seq 1 50000 | xcodebuild_filter flood3; echo "pipeline=$?" >&2')
        self.assertIn("pipeline=3", result.stderr)
        self.assertEqual(len(self.kept_logs("flood3")[0].read_text().splitlines()), 50000)

    def test_every_xcodebuild_build_or_test_call_pipes_into_the_filter(self):
        """M1-23: no xcodebuild build/test invocation under Config/Scripts, Engine/scripts or Tools bypasses the filter."""
        self.assertEqual(xcodebuild_calls_without_filter("xcodebuild build -scheme A 2>&1 | xcodebuild_filter\n"), [])
        self.assertEqual(xcodebuild_calls_without_filter('lab_mutate xcodebuild build \\\n  -scheme A 2>&1 |\n  xcodebuild_filter x\n'), [])
        self.assertEqual(xcodebuild_calls_without_filter('x="$(xcodebuild -version)"\nxcodebuild -list -json\n'), [])
        self.assertEqual(xcodebuild_calls_without_filter("xcodebuild build-for-testing -showBuildSettings >>f\n"), [])
        self.assertEqual(xcodebuild_calls_without_filter('xcodebuild -create-xcframework "$@" -output o >/dev/null\n'), [])
        self.assertEqual(xcodebuild_calls_without_filter("# xcodebuild build is described here\n"), [])
        for good in ('echo "run xcodebuild build"\n', "echo xcodebuild build next\n", 'echo "a; b"; xcodebuild -list\n',
                     'printf "; xcodebuild build\n"\n', "XCB=/usr/bin/xcodebuild\n", "XCB=xcodebuild\n",
                     'XCB=xcodebuild\n"$XCB" build -scheme A 2>&1 | xcodebuild_filter x\n',
                     "XCB=xcodebuild\n${XCB} test 2>&1 |\n  xcodebuild_filter x\n",
                     "/usr/bin/xcodebuild build 2>&1 | xcodebuild_filter lab\n",
                     'v="$(xcodebuild -version)"; echo ok\n', "xcodebuild build 2>&1 | xcodebuild_filter x; echo done\n",
                     "xcodebuild build 2>&1 | xcodebuild_filter x # xcodebuild test is not run\n",
                     'v="$(xcodebuild build 2>&1 | xcodebuild_filter x)"\n',
                     "echo x; xcodebuild build 2>&1 | xcodebuild_filter x\n",
                     'echo "$(xcodebuild -version)"\n', "echo \"see: bash -c 'xcodebuild build'\"\n",
                     'echo "use eval \\"xcodebuild build\\" here"\n', "bash -c 'xcodebuild -list'\n",
                     'eval "xcodebuild build 2>&1 | xcodebuild_filter x"\n',
                     "sh -c 'xcodebuild build 2>&1 | xcodebuild_filter x'\n",
                     'bash -c "echo hello; ls"\n', 'eval "$cmd"\n',
                     'echo "$(xcodebuild build 2>&1 | xcodebuild_filter x)"\n',
                     "xcodebuild build 2>/dev/null | xcodebuild_filter x\n",
                     "xcodebuild build 2>&1 | xcodebuild_filter x >/dev/null\n",
                     "xcodebuild build >/dev/null 2>&1 | xcodebuild_filter x\n",
                     "(cd d && xcodebuild build -scheme A) 2>&1 | xcodebuild_filter x\n",
                     "xcodebuild build 2>&1 | xcodebuild_filter x; echo done > out.txt\n",
                     # M1-10t (M1-23 FIX3-VERIFY F-1): the same shapes with the filter inside, and holders on their own
                     "/bin/bash -c 'xcodebuild build 2>&1 | xcodebuild_filter x'\n",
                     '/bin/sh -c "xcodebuild build 2>&1 | xcodebuild_filter x"\n',
                     "bash -o pipefail -c 'xcodebuild build 2>&1 | xcodebuild_filter x'\n",
                     'bash -euo pipefail -c "xcodebuild build 2>&1 | xcodebuild_filter x"\n',
                     "bash -c -- 'xcodebuild build 2>&1 | xcodebuild_filter x'\n",
                     "bash -c $'xcodebuild build 2>&1 | xcodebuild_filter x'\n",
                     "bash <<<'xcodebuild build 2>&1 | xcodebuild_filter x'\n",
                     "/bin/bash -c 'xcodebuild -list'\n", "bash -o pipefail -c 'echo hello'\n",
                     "echo \"see: /bin/bash -c 'xcodebuild build'\"\n",
                     "XCB=${XCB:-xcodebuild}\n", 'XCB="${DEV}/usr/bin/xcodebuild"\n', 'XCB="${XCB:-xcodebuild}"\n',
                     'XCB=${XCB:-xcodebuild}\n"$XCB" build 2>&1 | xcodebuild_filter x\n',
                     'XCB="${DEV}/usr/bin/xcodebuild"\n${XCB} test 2>&1 |\n  xcodebuild_filter x\n',
                     '"${DEV}/usr/bin/xcodebuild" build 2>&1 | xcodebuild_filter x\n',
                     '${XCB:-xcodebuild} build 2>&1 | xcodebuild_filter x\n',
                     # M1-10t fix 1 item 4 (SCRIPTS-VERIFY F4): a variable-led path that is not at a command position is a path
                     'mkdir -p "$LOGS/xcodebuild"\n', 'rm -rf "${BUILD}/xcodebuild"\n',
                     '[[ -x "$DEV/usr/bin/xcodebuild" ]] || exit 1\n', 'log_dir="$ROOT/logs/xcodebuild"\nmkdir -p "$log_dir"\n',
                     'log_dir=${BUILD}/xcodebuild\nrm -rf $log_dir\nls "${log_dir}"\n', 'ls "$DEV/usr/bin/xcodebuild"\n',
                     'test -x $DEV/usr/bin/xcodebuild && echo yes\n', 'cp "$A/xcodebuild" "$B/xcodebuild"\n',
                     'echo x | tee "$LOGS/xcodebuild"\n', 'VAR=1 mkdir -p "$LOGS/xcodebuild"\n',
                     # ... and the same path at a command position, with the filter after it, is a call that is filtered
                     '"${DEV}/usr/bin/xcodebuild" build 2>&1 | xcodebuild_filter x\n',
                     'env "$DEV/usr/bin/xcodebuild" build 2>&1 | xcodebuild_filter x\n',
                     'FOO=1 exec ${DEV}/usr/bin/xcodebuild build 2>&1 | xcodebuild_filter x\n',
                     'log_dir=$ROOT/xcodebuild\n$log_dir -version\n'):
            with self.subTest(good=good):
                self.assertEqual(xcodebuild_calls_without_filter(good), [])
        for bad in ("xcodebuild build -scheme A\n", "/usr/bin/xcodebuild build\n", '"/usr/bin/xcodebuild" build\n',
                    '"xcodebuild" test\n', "XCB=xcodebuild\n$XCB build\n", 'XCB=xcodebuild\n"$XCB" build\n',
                    "XCB=xcodebuild\n${XCB} test\n", 'XCB=/usr/bin/xcodebuild\n"${XCB}" test | cat\n',
                    "local XCB=xcodebuild\n$XCB build\n",
                    "echo x; xcodebuild build\n", "printf '%s\\n' x && xcodebuild test\n", "lab_die x || xcodebuild build\n",
                    'xcodebuild build >log; v="$(xcodebuild -version)"\n', "xcodebuild -version; xcodebuild build\n",
                    "xcodebuild build > log; foo | xcodebuild_filter x\n", "xcodebuild build; xcodebuild_filter x\n",
                    "xcodebuild build -showBuildSettings; xcodebuild test | tee x\n",
                    "xcodebuild test -scheme A | cat\n", "(cd d && xcodebuild test-without-building) 2>&1 | formatter\n",
                    "xcodebuild_filter <<<x; xcodebuild build\n", 'xcodebuild -create-xcframework "$@" -output o\n',
                    'lab_mutate xcodebuild "$action" -scheme A | tee log\n',
                    # quoted code that runs: eval and bash|sh|zsh -c arguments (the 59bab6d checker caught these)
                    'eval "xcodebuild build"\n', "bash -c 'xcodebuild build'\n", 'sh -c "xcodebuild test -scheme A"\n',
                    "eval 'xcodebuild test -scheme A'\n", 'bash -lc "xcodebuild build"\n', "zsh -c 'xcodebuild build'\n",
                    "eval \"xcodebuild build 2>&1 | tee log\"\n",
                    # a message that substitutes a command still runs it
                    'echo "$(xcodebuild build)"\n', "printf '%s' \"$(xcodebuild build)\"\n", 'lab_die "$(xcodebuild test)"\n',
                    'echo "`xcodebuild build`"\n', 'echo "$(xcodebuild build 2>&1 | tee log)"\n',
                    # stdout sent anywhere but /dev/null never reaches the filter
                    "xcodebuild build >/tmp/raw.log 2>&1 | xcodebuild_filter x\n",
                    "xcodebuild build > /tmp/raw.log | xcodebuild_filter x\n", "xcodebuild build >>/tmp/raw.log | xcodebuild_filter x\n",
                    "xcodebuild build &>/tmp/raw.log | xcodebuild_filter x\n", "xcodebuild build 1>/tmp/raw.log | xcodebuild_filter x\n",
                    "xcodebuild build >&2 | xcodebuild_filter x\n", "(xcodebuild build >/tmp/raw) | xcodebuild_filter x\n",
                    "(cd d && xcodebuild build -scheme A >/tmp/raw) 2>&1 | xcodebuild_filter x\n",
                    # M1-10t (M1-23 FIX3-VERIFY F-1): an absolute shell path, option arguments and `--`, $'...', a here-string
                    "/bin/bash -c 'xcodebuild build'\n", '/bin/sh -c "xcodebuild build"\n',
                    "/usr/bin/env bash -c 'xcodebuild build'\n",
                    "bash -o pipefail -c 'xcodebuild build'\n", "bash -euo pipefail -c 'xcodebuild build'\n",
                    "bash -c -- 'xcodebuild build'\n", "bash --norc -o errexit -c 'xcodebuild test'\n",
                    "bash -c $'xcodebuild build'\n", "/bin/bash -c $'cd d\\nxcodebuild build'\n", "eval $'xcodebuild build'\n",
                    "bash <<<'xcodebuild build'\n", 'bash <<< "xcodebuild build"\n', "sh<<<'xcodebuild test'\n",
                    "bash -o pipefail -c 'xcodebuild build 2>&1 | tee log'\n",
                    # the holders: a default, and a path led by a variable, then the holder is the call
                    "XCB=${XCB:-xcodebuild}\n$XCB build\n", 'XCB=${XCB:-xcodebuild}\n"$XCB" build\n',
                    'XCB="${DEV}/usr/bin/xcodebuild"\n"$XCB" build\n', 'XCB="${DEV}/usr/bin/xcodebuild"\n${XCB} test | cat\n',
                    'XCB="${XCB:-xcodebuild}"\n"$XCB" build\n', "XCB=${XCB:-/usr/bin/xcodebuild}\n$XCB build\n",
                    'XCB=$DEV/usr/bin/xcodebuild\n"$XCB" test\n',
                    '"${DEV}/usr/bin/xcodebuild" build\n', '${DEV}/usr/bin/xcodebuild build\n', '"${XCB:-xcodebuild}" build\n',
                    # M1-10t fix 1 item 4: a variable-led path at every command position still counts (segment start, after
                    # env, exec, command, time, VAR= assignments, then/do, ( and a substitution, in quoted code)
                    'env "${DEV}/usr/bin/xcodebuild" build\n', 'exec $DEV/usr/bin/xcodebuild build\n',
                    'command "${DEV}/usr/bin/xcodebuild" build\n', 'time ${DEV}/usr/bin/xcodebuild build\n',
                    'FOO=1 "$DEV/usr/bin/xcodebuild" build\n', 'env -i FOO=1 "$DEV/usr/bin/xcodebuild" test\n',
                    'if true; then "${DEV}/usr/bin/xcodebuild" build; fi\n', '(cd d && "$DEV/usr/bin/xcodebuild" build)\n',
                    'v="$($DEV/usr/bin/xcodebuild build)"\n', 'bash -c "${DEV}/usr/bin/xcodebuild build"\n',
                    "eval '$DEV/usr/bin/xcodebuild build'\n", '! "$DEV/usr/bin/xcodebuild" build\n',
                    'x && "$DEV/usr/bin/xcodebuild" build\n', '"$DEV/usr/bin/xcodebuild" build 2>&1 | tee log\n',
                    'log_dir=$DEV/usr/bin/xcodebuild\n"$log_dir" build\n', 'log_dir="$ROOT/xcodebuild"\nenv $log_dir build\n',
                    'XCB="${DEV}/usr/bin/xcodebuild"\nFOO=1 "$XCB" build\n'):
            with self.subTest(bad=bad):
                self.assertEqual(len(xcodebuild_calls_without_filter(bad)), 1)
        unfiltered, scanned = [], set()
        for directory in ("Config/Scripts", "Engine/scripts", "Tools"):
            for script in sorted((ROOT / directory).rglob("*.sh")):
                scanned.add(str(script.relative_to(ROOT)))
                for number, line in xcodebuild_calls_without_filter(script.read_text()):
                    unfiltered.append(f"{script.relative_to(ROOT)}:{number}: {line}")
        self.assertEqual(unfiltered, [])
        for caller in ("Config/Scripts/test.sh", "Config/Scripts/build.sh", "Config/Scripts/packages-matrix.sh",
                       "Tools/lab/tart/build.sh"):
            self.assertIn(caller, scanned)
            self.assertIn("| xcodebuild_filter", (ROOT / caller).read_text().replace("|\n    xcodebuild_filter", "| xcodebuild_filter"))

    def scanner_seconds(self, text):
        """Seconds the xcodebuild call scanner takes on text, measured in a child (a quadratic or exponential line would hang
        this process inside the regex engine, where no signal can interrupt it); fails the test when the child exceeds 20 s."""
        code = ("import importlib.util, sys, time\n"
                "spec = importlib.util.spec_from_file_location('scan_under_test', sys.argv[1])\n"
                "module = importlib.util.module_from_spec(spec)\n"
                "spec.loader.exec_module(module)\n"
                "started = time.monotonic()\n"
                "module.xcodebuild_calls_without_filter(sys.stdin.read())\n"
                "print(time.monotonic() - started)\n")
        try:
            result = subprocess.run([sys.executable, "-I", "-c", code, str(Path(__file__).resolve())], input=text,
                                    capture_output=True, text=True, timeout=20)
        except subprocess.TimeoutExpired:
            self.fail(f"the scanner took more than 20 s on a line of {len(text)} characters")
        self.assertEqual(result.returncode, 0, result.stderr)
        return float(result.stdout.strip().splitlines()[-1])

    def test_xcodebuild_variable_path_counts_anywhere_except_as_a_path_operand(self):
        """M1-40 item 1 (M1-10t SCRIPTS-FIX1-VERIFY N1, N6): a variable-led (or substitution-led) path to xcodebuild is a call
        at every position, so an unknown position fails loudly instead of passing silently; only the operand of a named path
        consumer (mkdir, rm, ls, cp, mv, tee, touch, chmod, stat, cat, readlink, test, [, [[), a redirection target and an
        assignment are not calls."""
        path = '"$DEV/usr/bin/xcodebuild"'
        bad = [
            # N1: every input of the finding, each one unfiltered call
            f'case x in a){path} build;; esac\n',
            f'case x in a) {path} build;; esac\n', f'env -u FOO {path} build\n', f'exec -a foo {path} build\n',
            f'2>/dev/null {path} build\n', f'lab_mutate {path} build\n', f'lab_local {path} build\n',
            f'with_deadline 600 {path} build\n', f'check "x" {path} build\n', f'run_ok "x" {path} build\n',
            f'run_refuse "x" "denied" {path} build\n',
            f"perl -e 'alarm shift; exec @ARGV' 600 {path} build\n", f'xcrun {path} build\n', f'xargs {path} build\n',
            f'caffeinate -i {path} build\n', f'arch -arm64 {path} build\n',
            'XCB="$DEV/usr/bin/xcodebuild"; lab_mutate "$XCB" build\n', 'XCB="$DEV/usr/bin/xcodebuild"\nlab_mutate "$XCB" build\n',
            'XCB="$DEV/usr/bin/xcodebuild"\nwith_deadline 600 ${XCB} test\n',
            # positions the old command-start list also missed, or that only a wrapper reaches
            f'sudo -E {path} build\n', f'nohup {path} build\n', f'time -p {path} build\n', f'command -p {path} build\n',
            f'env -i VAR=x {path} build\n', f'if x; then {path} build; fi\n', f'while x; do {path} build; done\n',
            f'( {path} build )\n', f'v="$({path} build)"\n', f'true & {path} build\n', f'for x in 1; do lab_mutate {path} build; done\n',
            f'bash -c \'lab_mutate {path} build\'\n', f"eval 'lab_mutate {path} build'\n",
            f'{path} build 2>&1 | tee log\n', f'x=1 lab_mutate $DEV/usr/bin/xcodebuild build\n',
            # N6: a command substitution leads the path
            '"$(xcode-select -p)/usr/bin/xcodebuild" build\n', '$(xcode-select -p)/usr/bin/xcodebuild build\n',
            'lab_mutate "$(xcode-select -p)/usr/bin/xcodebuild" test\n', '"`xcode-select -p`/usr/bin/xcodebuild" build\n',
            'DEV="$(xcode-select -p)"\n"$DEV/usr/bin/xcodebuild" build\n',
            # a holder is counted at every position too
            'case $m in a)XCB=/usr/bin/xcodebuild;; esac\n$XCB build\n',
            'case $m in a)XCB=$DEV/usr/bin/xcodebuild;; esac\n$XCB build\n',
            'log_dir="$ROOT/xcodebuild"\nlab_mutate "$log_dir" build\n', 'XCB=$DEV/usr/bin/xcodebuild\nxcrun $XCB build\n',
            # a consumer's operand is exempt, but the segment after the consumer is not
            f'mkdir -p "$LOGS/xcodebuild" && lab_mutate {path} build\n', f'ls x; with_deadline 5 {path} build\n',
            f'rm -rf x | xargs {path} build\n',
        ]
        for line in bad:
            with self.subTest(bad=line):
                self.assertEqual(len(xcodebuild_calls_without_filter(line)), 1)
        good = [
            'mkdir -p "$LOGS/xcodebuild"\n', 'rm -rf "${BUILD}/xcodebuild"\n', 'ls "$DEV/usr/bin/xcodebuild"\n',
            'cp "$A/xcodebuild" "$B/xcodebuild"\n', 'mv "$A/xcodebuild" "$B/xcodebuild"\n', 'echo x | tee "$LOGS/xcodebuild"\n',
            'touch "$LOGS/xcodebuild"\n', 'chmod +x "$DEV/usr/bin/xcodebuild"\n', 'stat "$DEV/usr/bin/xcodebuild"\n',
            'cat "$DEV/usr/bin/xcodebuild" >/dev/null\n', 'readlink "$DEV/usr/bin/xcodebuild"\n',
            'test -x "$DEV/usr/bin/xcodebuild" && echo yes\n', '[ -x "$DEV/usr/bin/xcodebuild" ] || exit 1\n',
            '[[ -x "$DEV/usr/bin/xcodebuild" ]] || exit 1\n', 'if [[ -x "$DEV/usr/bin/xcodebuild" ]]; then echo ok; fi\n',
            '! [[ -x "$DEV/usr/bin/xcodebuild" ]] && exit 1\n', 'VAR=1 mkdir -p "$LOGS/xcodebuild"\n',
            'sudo rm -rf "$LOGS/xcodebuild"\n', 'env FOO=1 mkdir -p "${LOGS}/xcodebuild"\n', 'x=$(mkdir -p "$A/xcodebuild")\n',
            '(cd d && mkdir -p "$A/xcodebuild")\n', 'ls "$(xcode-select -p)/usr/bin/xcodebuild"\n',
            'mkdir -p "$(xcode-select -p)/xcodebuild"\n',
            'XCB="$(xcode-select -p)/usr/bin/xcodebuild"\n', 'LOGS="$(mktemp -d)/xcodebuild"\n',
            'LOGS="$(cd "$X" && pwd)/xcodebuild"\n', 'LOGS=$(cd x; pwd)/xcodebuild\n',
            'X="$(a | b)/xcodebuild"\n',
            'XCB="$(xcode-select -p)/usr/bin/xcodebuild"\n"$XCB" build 2>&1 | xcodebuild_filter x\n',
            'log_dir="$ROOT/xcodebuild"\nmkdir -p "$log_dir"\nrm -rf $log_dir\nls "${log_dir}"\ntest -d "$log_dir"\n',
            'XCB="$DEV/usr/bin/xcodebuild"\n[[ -x "$XCB" ]] || exit 1\nls -l "$XCB"\n',
            'echo hi > "$LOGS/xcodebuild"\n', 'echo hi >"$LOGS/xcodebuild"\n', 'echo hi >> "${LOGS}/xcodebuild"\n',
            'echo hi 2> "$LOGS/xcodebuild"\n', 'sort < "$LOGS/xcodebuild"\n',
            'export LOG="$ROOT/xcodebuild"\n', 'local log_dir="$ROOT/xcodebuild"\n', 'readonly LOG=${BUILD}/xcodebuild\n',
            'echo "$DEV/usr/bin/xcodebuild"\n', f'lab_mutate {path} build 2>&1 | xcodebuild_filter x\n',
            f'with_deadline 600 {path} build 2>&1 |\n  xcodebuild_filter x\n', f'{path} -version\n',
            f'lab_mutate {path} -showBuildSettings\n', 'XCB="$DEV/usr/bin/xcodebuild"\nlab_mutate "$XCB" build 2>&1 | xcodebuild_filter x\n',
            '"$(xcode-select -p)/usr/bin/xcodebuild" build 2>&1 | xcodebuild_filter x\n',
        ]
        for line in good:
            with self.subTest(good=line):
                self.assertEqual(xcodebuild_calls_without_filter(line), [])

    def test_xcodebuild_call_inside_a_substitution_is_not_a_consumer_operand(self):
        """M1-40 fix pass 1 (R1): a path call inside $(...), <(...), >(...) or backticks is a command of its own, so a consumer
        around the substitution (`test -n "$(...)"`, `[[ -n "$(...)" ]]`, `cat <(...)`, `mkdir -p "$(...)"`) does not exempt it;
        the opener is before the path, so it opens the innermost command. A consumer's own operand stays exempt."""
        path = '"$DEV/usr/bin/xcodebuild"'
        bad = [
            f'[[ -n "$({path} build 2>&1)" ]]\n', f'test -n "$({path} build)"\n',
            f'if [[ "$({path} build 2>&1)" == *error* ]]; then exit 1; fi\n',
            f'cat <({path} build)\n', f'tee >({path} build)\n', f'cat `{path} build`\n', f'cat $({path} build) x\n',
            f'mkdir -p "$({path} build)"\n', f'[ -n "$({path} build)" ]\n', f'ls $({path} build)\n',
            f'cat "`{path} build`"\n', f'cat <(cat <({path} build))\n', f'rm -f x "$(ls "$({path} build)")"\n',
            'ls "$(xcodebuild build)/xcodebuild"\n',
            'X="$(xcodebuild build)" | xcodebuild_filter x\n',
            # N6: a substitution-led path inside a substitution
            f'cat <("$(xcode-select -p)/usr/bin/xcodebuild" build)\n', 'test -n "$("$(xcode-select -p)/usr/bin/xcodebuild" build)"\n',
            # the holder forms: a variable assigned a path to xcodebuild is the call
            'XCB="$DEV/usr/bin/xcodebuild"\n[[ -n "$("$XCB" build)" ]]\n', 'XCB="$DEV/usr/bin/xcodebuild"\ncat <($XCB build)\n',
            'XCB="$DEV/usr/bin/xcodebuild"\nls `$XCB build`\n', 'XCB="$DEV/usr/bin/xcodebuild"\ntest -n "$(${XCB} build)"\n',
            'XCB="$DEV/usr/bin/xcodebuild"\ntee >("$XCB" build)\n', 'XCB="$DEV/usr/bin/xcodebuild"\nmkdir -p "$($XCB build)"\n',
            # with a space after the opener the call was already counted
            f'cat <( {path} build)\n',
        ]
        for line in bad:
            with self.subTest(bad=line):
                self.assertEqual(len(xcodebuild_calls_without_filter(line)), 1)
        good = [
            'x=$(mkdir -p "$A/xcodebuild")\n', '(cd d && mkdir -p "$A/xcodebuild")\n', 'cat <(ls "$A/xcodebuild")\n',
            'test -n "$(ls "$A/xcodebuild")"\n', 'cat `ls "$A/xcodebuild"`\n', '[[ -n "$(stat "$DEV/usr/bin/xcodebuild")" ]]\n',
            'cat <(cat "$DEV/usr/bin/xcodebuild")\n', 'echo "$(mkdir -p "$LOGS/xcodebuild")"\n',
            'XCB="$DEV/usr/bin/xcodebuild"\ntest -n "$(ls "$XCB")"\n',
            f'[[ -n "$({path} build 2>&1 | xcodebuild_filter x)" ]]\n',
        ]
        for line in good:
            with self.subTest(good=line):
                self.assertEqual(xcodebuild_calls_without_filter(line), [])

    def test_a_dirname_head_followed_by_an_expansion_is_refused(self):
        """M1-40 fix pass 1 (R2): a variable assigned `$(dirname W)` or `$(cd "$(dirname W)/..." && pwd)` followed by any
        expansion (`/$SUB`, `/${SUB}`, `/$(echo sub)`, `/sub$N`) is a directory the scanner cannot read: refused, never
        resolved to lib/x.sh beside the decoy lib/sub/x.sh. A literal that climbs only (an ancestor) is not refused for it,
        and a head with no suffix still resolves."""
        root = self.fake_root("dynamic-suffix")
        (root / "lib/sub").mkdir()
        (root / "lib/sub/x.sh").write_text("SUB=1\n")
        refused = [
            'D="$(dirname "$0")/$SUB"\nsource "$D/x.sh"\n', 'D="$(dirname "$0")/${SUB}"\nsource "$D/x.sh"\n',
            'D="$(dirname "$0")/$(echo sub)"\nsource "$D/x.sh"\n', 'D="$(dirname "$0")/sub$N"\nsource "$D/x.sh"\n',
            'D=$(dirname "$0")/$SUB\nsource "${D}/x.sh"\n', 'D="`dirname "$0"`/$SUB"\nsource "$D/x.sh"\n',
            'D="$(dirname "$0")"/$SUB\nsource "$D/x.sh"\n', 'D="$(dirname "$0")/"$SUB\nsource "$D"/x.sh\n',
            'D="$(dirname "$0")/../$SUB"\nsource "$D/x.sh"\n', 'D="$(dirname "$0")/sub/$SUB"\nsource "$D/x.sh"\n',
            'D="$(cd "$(dirname "$0")/$SUB" && pwd)"\nsource "$D/x.sh"\n',
            'D="$(cd "$(dirname "$0")/sub$N" && pwd)"\nsource "$D/x.sh"\n',
            'D="$(cd "$(dirname "$0")/$(echo sub)" && pwd)"\nsource "$D/x.sh"\n',
            'D="$(cd "$(dirname "$0")/`echo sub`" && pwd)"\nsource "$D/x.sh"\n',
        ]
        with self.under_root(root):
            for text in refused:
                with self.subTest(refused=text):
                    (root / "lib/s.sh").write_text(text)
                    entries = source_lines("lib/s.sh")
                    self.assertEqual([entry[1] for entry in entries], [[]] * len(entries), entries)
                    self.assertEqual(len(entries), 1, entries)
                    self.assertTrue(entries[0][2] and "expansion" in entries[0][2], entries)
                    self.assertEqual(sourced_files("lib/s.sh"), [])
            for text in ('D="$(dirname "$0")"\nsource "$D/x.sh"\n', 'D="$(dirname "$0")/.."\nsource "$D/x.sh"\n'):
                with self.subTest(accepted=text):
                    (root / "lib/s.sh").write_text(text)
                    self.assertNotIn("expansion", source_lines("lib/s.sh")[0][2] or "")

    def test_an_unread_script_directory_head_is_refused(self):
        """M1-50 L2: a dirname or ${0%/*} assignment outside the read shapes must not fall back to unknown anchors."""
        root = self.fake_root("unread-script-directory")
        (root / "lib/sub").mkdir()
        (root / "lib/sub/x.sh").write_text("SUB=1\n")
        refused = [
            'D="$(dirname "$0")"$SUB',
            'D="$(dirname "${BASH_SOURCE[0]}")"$SUB',
            'D=$(cd "$(dirname "${BASH_SOURCE[0]}")"/sub && pwd)',
            'D=$(cd -P "$(dirname "${BASH_SOURCE[0]}")/$SUB" && pwd)',
            'D=$(cd "$(dirname "$0")"/$SUB && pwd)',
            'D=$(cd "$(dirname "$0")/"/sub && pwd)',
            'D=$(cd "$(dirname "$0")"/sub && pwd)',
            'D=$(cd -P "$(dirname "$0")/$SUB" && pwd)',
            'D=`cd "$(dirname "$0")/$SUB" && pwd`',
            'D="${0%/*}/$SUB"',
            'D=$(cd "$(dirname "$0")/$SUB" && pwd)/x',
        ]
        with self.under_root(root):
            for assignment in refused:
                with self.subTest(assignment=assignment):
                    (root / "lib/s.sh").write_text(assignment + '\nsource "$D/x.sh"\n')
                    entries = source_lines("lib/s.sh")
                    self.assertEqual(len(entries), 1, entries)
                    self.assertEqual(entries[0][1], [], entries)
                    self.assertIn("not a supported script-directory shape", entries[0][2] or "")
                    self.assertEqual(sourced_files("lib/s.sh"), [])

    def test_xcodebuild_scanner_is_linear_on_a_run_of_bang_and_variable_words(self):
        """M1-40 item 4 (SCRIPTS-FIX1-VERIFY N4): `!` is a command start only as its own word, so a line made of `!` and a path
        class does not cost a pass over the rest of the line at every `!` (8000 x `!/` took 5.1 s, 40000 x `!$A` over 30 s)."""
        lines = ["!/" * 8000, "!${A}" * 8000, "!$A" * 40000, "!$ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 6000, "! " * 20000, "$A/" * 20000,
                 "x!" * 40000, "!$A/xcodebuild" * 4000, 'mkdir -p ' + "!$A" * 40000]
        for line in lines:
            with self.subTest(line=line[:24], length=len(line)):
                self.assertLess(self.scanner_seconds(line + "\n"), 1.0)
        # the anchored `!` still starts a command: it is a word of its own
        self.assertEqual(len(xcodebuild_calls_without_filter('! "$DEV/usr/bin/xcodebuild" build\n')), 1)
        self.assertEqual(xcodebuild_calls_without_filter('! mkdir -p "$DEV/xcodebuild"\n'), [])

    def test_formatter_failure_never_changes_the_xcodebuild_status(self):
        """M1-23: a crashing formatter prints a clear line; failing xcodebuild stays failing, passing stays passing."""
        root = self.gate_tree()
        stubs = self.stub_bin()
        self.lab_bin(stubs)
        crashing = self.work / "crashing-formatter"
        crashing.mkdir()
        (crashing / "xcbeautify").write_text("#!/bin/bash\ncat >/dev/null\nexit 3\n")
        (crashing / "xcbeautify").chmod(0o755)
        path = f"{stubs}:{crashing}:/usr/bin:/bin"
        for command in (["Config/Scripts/test.sh", "ios"], ["Config/Scripts/test.sh", "tv"], ["Config/Scripts/build.sh", "ios"],
                        ["Config/Scripts/packages-matrix.sh", "--macos"], ["lab"]):
            for status in (0, 65):
                with self.subTest(command=" ".join(command), xcodebuild_status=status):
                    result = self.run_gate(root, command, path, "pass" if status == 0 else "crash", status)
                    output = result.stdout + result.stderr
                    self.assertIn("formatter failed", output)
                    for canary in self.CANARIES:
                        self.assertNotIn(canary, output)
                    # packages-matrix reports its own failure list with exit status 1
                    expected = 1 if status and command[0].endswith("packages-matrix.sh") else status
                    self.assertEqual(result.returncode, expected, output)

    def test_doctor_simulator_rows_do_not_depend_on_tmpdir_and_validate_the_retry_wait(self):
        """M1-23: doctor's simctl retry works with TMPDIR missing, waits only 0-30 whole seconds (else 5), reports errors."""
        tree = self.work / "doctor-tree"
        for name in ("Tools/doctor/doctor.sh", "Toolchain.lock"):
            (tree / name).parent.mkdir(parents=True, exist_ok=True)
            self.copy_source(ROOT / name, tree / name)
        stubs = self.work / "doctor-bin"
        stubs.mkdir()
        (stubs / "xcrun").write_text("""#!/bin/bash
if [[ "$1 $2 $3" == "simctl list devices" ]]; then
  echo '{"devices": {}}'
  exit 0
fi
if [[ "$1 $2 $3 $4" == "simctl list runtimes -j" ]]; then  # the WGEX device row (M1-26), not counted: it is not the retry under test
  echo '{"runtimes": [{"identifier": "com.apple.CoreSimulator.SimRuntime.iOS-27-0", "version": "27.0", "isAvailable": true}]}'
  exit 0
fi
if [[ "$1 $2 $3" == "simctl list runtimes" ]]; then
  count=$(($(cat "$STUB_COUNT" 2>/dev/null || echo 0) + 1))
  echo "$count" >"$STUB_COUNT"
  if [[ "$STUB_SIMCTL" == fail || ( "$STUB_SIMCTL" == failonce && "$count" == 1 ) ]]; then
    echo "CoreSimulatorService connection became invalid" >&2
    echo "second line SECRET=not-for-rows" >&2
    exit 1
  fi
  [[ "$STUB_SIMCTL" != silent ]] || exit 3
  echo "== Runtimes =="
  echo "iOS 27.0 (24A434) - com.apple.CoreSimulator.SimRuntime.iOS-27-0"
  exit 0
fi
exec /usr/bin/xcrun "$@"
""")
        (stubs / "sleep").write_text('#!/bin/bash\necho "$*" >>"$STUB_SLEEPS"\n')
        for executable in stubs.iterdir():
            executable.chmod(0o755)

        def doctor(index, mode, retry=None, tmpdir=None):
            counter, sleeps = self.work / f"count-{index}", self.work / f"sleeps-{index}"
            environment = os.environ | {"PATH": f"{stubs}:{os.environ['PATH']}", "STUB_SIMCTL": mode, "WGEX_OFFLINE": "1",
                                        "STUB_COUNT": str(counter), "STUB_SLEEPS": str(sleeps),
                                        "TMPDIR": tmpdir or os.environ["TMPDIR"]}
            environment.pop("WGEX_DOCTOR_SIMCTL_RETRY_SECONDS", None)
            if retry is not None:
                environment["WGEX_DOCTOR_SIMCTL_RETRY_SECONDS"] = retry
            result = subprocess.run(["bash", str(tree / "Tools/doctor/doctor.sh")], env=environment, capture_output=True, text=True)
            rows = {os_name: re.search(rf"^(OK|FAIL|WARN) +simulator {os_name} +(.*)$", result.stdout, re.M)
                    for os_name in ("iOS", "tvOS")}
            calls = int(counter.read_text()) if counter.exists() else 0
            return result, rows, calls, sleeps.read_text().split() if sleeps.exists() else []

        missing = str(self.work / "no-such-tmpdir")
        cases = {  # name -> (stub mode, retry value, TMPDIR)
            "fail once, retry 0": ("failonce", "0", None),
            "fail once, retry 30": ("failonce", "30", None),
            "fail once, default": ("failonce", None, None),
            "always fail, retry 7": ("fail", "7", None),
            "TMPDIR missing, ok": ("ok", "0", missing),
            "TMPDIR missing, fail once": ("failonce", "0", missing),
            "TMPDIR missing, always fail": ("fail", "0", missing),
            "TMPDIR missing, silent exit 3": ("silent", "0", missing),
            **{f"retry {value!r}": ("failonce", value, None) for value in ("-1", "31", "5m", "abc", "1.5", "")},
        }
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = {name: pool.submit(doctor, index, *case) for index, (name, case) in enumerate(cases.items())}
            results = {name: future.result() for name, future in futures.items()}

        def row(name, os_name):
            found = results[name][1][os_name]
            self.assertIsNotNone(found, results[name][0].stdout)
            return found.group(1), found.group(2)

        for name in ("fail once, retry 0", "fail once, retry 30", "fail once, default"):
            with self.subTest(name):
                self.assertEqual(row(name, "iOS")[0], "OK")
                self.assertEqual(results[name][2], 2)
        self.assertEqual(results["fail once, retry 0"][3], ["0"])
        self.assertEqual(results["fail once, retry 30"][3], ["30"])
        self.assertEqual(results["fail once, default"][3], ["5"])
        state, detail = row("always fail, retry 7", "iOS")
        self.assertEqual((state, detail), ("FAIL", "simctl unavailable: CoreSimulatorService connection became invalid"))
        self.assertEqual(row("always fail, retry 7", "tvOS")[0], "WARN")
        self.assertEqual(results["always fail, retry 7"][3], ["7"])
        self.assertNotIn("not-for-rows", results["always fail, retry 7"][0].stdout)
        self.assertEqual((row("TMPDIR missing, ok", "iOS")[0], results["TMPDIR missing, ok"][2]), ("OK", 1))
        self.assertEqual(row("TMPDIR missing, fail once", "iOS")[0], "OK")
        self.assertEqual(results["TMPDIR missing, fail once"][2], 2)
        self.assertEqual(row("TMPDIR missing, always fail", "iOS"), ("FAIL", "simctl unavailable: exit status 1"))
        self.assertEqual(row("TMPDIR missing, silent exit 3", "iOS"), ("FAIL", "simctl unavailable: exit status 3"))
        self.assertEqual(results["TMPDIR missing, silent exit 3"][2], 2)
        for value in ("-1", "31", "5m", "abc", "1.5", ""):
            with self.subTest(retry=value):
                self.assertEqual(results[f"retry {value!r}"][3], ["5"])
        self.assertEqual([path.name for path in Path(os.environ["TMPDIR"]).glob("wgex-doctor-simctl.*")], [])

    # Knobs (STUB_SIM, comma separated): list-sleep (a hung list), devices-empty / devices-empty-once (the device list has
    # no runtime entries, always / on its first answer), runtimes-empty / runtimes-empty-once (no runtimes listed),
    # create-fail / create-junk / create-hang (the device is registered, then the create exits 148 / prints no UDID / hangs),
    # delete-fail. STUB_SIM_TWIN="<udid>:<state>" registers a second device of the same name during the create.
    SIM_STUB = r"""#!__PYTHON__
import json, os, sys, time, uuid
state_path, log_path = os.environ["STUB_SIM_STATE"], os.environ["STUB_SIM_LOG"]
args = sys.argv[1:]
with open(log_path, "a") as log:
    log.write("\t".join(args) + "\n")
knobs = os.environ.get("STUB_SIM", "").split(",")
def seen(*words):
    return sum(1 for line in open(log_path) if line.split("\t")[:len(words)] == list(words))
def save(state):
    json.dump(state, open(state_path, "w"))
state = json.load(open(state_path))
if args[:2] == ["simctl", "list"] and "list-sleep" in knobs:
    time.sleep(30)
if args[:3] == ["simctl", "list", "devices"] and args[-1] == "-j":
    empty = "devices-empty" in knobs or ("devices-empty-once" in knobs and seen("simctl", "list", "devices") == 1)
    json.dump({"devices": {} if empty else state["devices"]}, sys.stdout)
elif args[:3] == ["simctl", "list", "runtimes"] and args[-1] == "-j":
    empty = "runtimes-empty" in knobs or ("runtimes-empty-once" in knobs and seen("simctl", "list", "runtimes") == 1)
    json.dump({"runtimes": [] if empty else state["runtimes"]}, sys.stdout)
elif args[:3] == ["simctl", "list", "devicetypes"] and args[-1] == "-j":
    json.dump({"devicetypes": state["devicetypes"]}, sys.stdout)
elif args[:2] == ["simctl", "create"] and len(args) == 5:
    name, device_type, runtime = args[2:]
    udid = str(uuid.uuid4()).upper()
    state["devices"].setdefault(runtime, []).append({"name": name, "udid": udid, "state": "Shutdown", "isAvailable": True,
                                                     "deviceTypeIdentifier": device_type})
    twin = os.environ.get("STUB_SIM_TWIN")
    if twin:
        twin_udid, twin_state = twin.split(":")
        state["devices"][runtime].append({"name": name, "udid": twin_udid, "state": twin_state, "isAvailable": True,
                                          "deviceTypeIdentifier": device_type})
    save(state)
    if "create-hang" in knobs:
        time.sleep(30)
    if "create-fail" in knobs:
        sys.stderr.write("CoreSimulator: the device could not be created\n")
        sys.exit(148)
    print("not a udid" if "create-junk" in knobs else udid)
elif args[:2] == ["simctl", "delete"] and len(args) == 3:
    if "delete-fail" in knobs:
        sys.stderr.write("CoreSimulator: delete failed\n")
        sys.exit(1)
    state["devices"] = {runtime: [device for device in group if device["udid"] != args[2]]
                        for runtime, group in state["devices"].items()}
    save(state)
else:
    sys.stderr.write("stub xcrun: refused " + " ".join(args) + "\n")
    sys.exit(99)
"""

    SHARED_UDID = "9EB62152-CDB0-47B5-AAC7-F86652615F45"

    def simulator_world(self, name, runtimes=None, devices=None, versions=None):
        """A stub `xcrun simctl` over a state file; returns (bin dir, state file, call log, environment additions).
        devices: a list (under iOS 27.0) or a whole runtime -> devices mapping; versions: iOS runtime (version, available) pairs."""
        world = self.work / name
        stubs = world / "bin"
        stubs.mkdir(parents=True)
        (stubs / "xcrun").write_text(self.SIM_STUB.replace("__PYTHON__", sys.executable))
        (stubs / "xcrun").chmod(0o755)
        (stubs / "xcodebuild").write_text('#!/bin/bash\n[[ "$1" != -version ]] || exec /usr/bin/xcodebuild "$@"\nprintf "%s\\n" "$*" >>"$STUB_XCODEBUILD_CALLS"\nexit 0\n')
        (stubs / "xcodebuild").chmod(0o755)

        def device_type(identifier, label, model):
            return {"identifier": f"com.apple.CoreSimulator.SimDeviceType.{identifier}", "name": label,
                    "productFamily": "iPhone", "modelIdentifier": model}

        types = [device_type("iPhone-17-Pro", "iPhone 17 Pro", "iPhone18,1"),
                 device_type("iPhone-17e", "iPhone 17e", "iPhone18,5"),
                 device_type("iPhone-19-Pro", "iPhone 19 Pro", "iPhone20,1"),  # newest supported, deliberately not a model the repo knows
                 device_type("iPhone-19-Pro-Max", "iPhone 19 Pro Max", "iPhone20,2"),
                 device_type("iPhone-9", "iPhone 9", "iPhone9,1"),             # not supported by the runtime below
                 device_type("iPhone-21-Unsupported", "iPhone 21", "iPhone22,1"),  # ranks first, but the runtime cannot host it
                 {"identifier": "com.apple.CoreSimulator.SimDeviceType.iPad-Pro", "name": "iPad Pro", "productFamily": "iPad",
                  "modelIdentifier": "iPad99,1"}]
        supported = [{"identifier": t["identifier"], "name": t["name"], "productFamily": t["productFamily"]}
                     for t in types if t["name"] not in ("iPhone 9", "iPhone 21")]
        if versions is not None:
            runtimes = [{"identifier": "com.apple.CoreSimulator.SimRuntime.iOS-" + version.replace(".", "-"),
                         "name": f"iOS {version}", "version": version, "platform": "iOS", "isAvailable": available,
                         "supportedDeviceTypes": supported} for version, available in versions]
        default_runtimes = [{"identifier": "com.apple.CoreSimulator.SimRuntime.iOS-27-0", "name": "iOS 27.0", "version": "27.0",
                             "platform": "iOS", "isAvailable": True, "supportedDeviceTypes": supported}]
        shared = {"name": "iPhone 18 Pro", "udid": self.SHARED_UDID, "state": "Shutdown", "isAvailable": True,
                  "deviceTypeIdentifier": "com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro"}
        if isinstance(devices, dict):
            listed = devices
        else:
            listed = {"com.apple.CoreSimulator.SimRuntime.iOS-27-0": [shared] if devices is None else devices}
        state = world / "state.json"
        state.write_text(json.dumps({
            "runtimes": default_runtimes if runtimes is None else runtimes, "devicetypes": types, "devices": listed}))
        return stubs, state, world / "simctl-calls", {"STUB_SIM_STATE": str(state), "STUB_SIM_LOG": str(world / "simctl-calls"),
                                                       "STUB_XCODEBUILD_CALLS": str(world / "xcodebuild-calls")}

    def ios_test_tree(self):
        root = self.work / "ios-tree"
        for name in ("Config/Scripts/lib.sh", "Config/Scripts/test.sh"):
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            self.copy_source(ROOT / name, root / name)
        library = root / "Config/Scripts/lib.sh"
        library.write_text(library.read_text() + '\nrequire_current_engine() { return 0; }\n')
        (root / "WGEX.xcodeproj").mkdir()
        (root / "Config/Scripts/generate-build-identifiers.sh").write_text("#!/bin/bash\nexit 0\n")
        return root

    def run_hosted(self, root, world, target, key):
        stubs, _, _, extra = world
        env = {name: value for name, value in os.environ.items() if name not in ("CLEAN_DEV_SESSION", "CODEX_THREAD_ID")}
        env |= {"PATH": f"{stubs}:{os.environ['PATH']}", "WGEX_BUILD_ROOT": str(self.work / "builds"),
                "CLEAN_DEVELOPMENT_CACHE_ROOT": str(self.work / "cache")} | extra | key
        return subprocess.run(["bash", str(root / "Config/Scripts/test.sh"), target], env=env, capture_output=True, text=True)

    def simctl_calls(self, world):
        return [line.split("\t") for line in world[2].read_text().splitlines()] if world[2].exists() else []

    def xcodebuild_destinations(self, world):
        calls = world[3]["STUB_XCODEBUILD_CALLS"]
        lines = Path(calls).read_text().splitlines() if Path(calls).exists() else []
        return [re.search(r"-destination (.+?) -derivedDataPath", line).group(1) for line in lines]

    def test_hosted_ios_tests_use_a_wgex_owned_simulator_device_and_never_the_shared_one(self):
        """M1-26: the device is chosen by exact WGEX name per build key, created once from the installed runtime."""
        root = self.ios_test_tree()
        world = self.simulator_world("sim-main")
        key = {"CLEAN_DEV_SESSION": "x-coretrack001"}
        first = self.run_hosted(root, world, "ios", key)
        self.assertEqual(first.returncode, 0, first.stderr + first.stdout)
        devices = json.loads(world[1].read_text())["devices"]["com.apple.CoreSimulator.SimRuntime.iOS-27-0"]
        owned = [device for device in devices if device["name"].startswith("WGEX ")]
        # (a) the shared device exists and is never selected; (b) one WGEX device, from the installed runtime and the
        # newest iPhone type that runtime supports (derived, not a hard-coded model)
        self.assertEqual([device["name"] for device in owned], ["WGEX iPhone coretrack001"])
        self.assertEqual(owned[0]["deviceTypeIdentifier"], "com.apple.CoreSimulator.SimDeviceType.iPhone-19-Pro")
        self.assertEqual(self.xcodebuild_destinations(world), [f"id={owned[0]['udid']}"])
        self.assertNotIn(self.SHARED_UDID, first.stdout + first.stderr + "".join(self.xcodebuild_destinations(world)))
        self.assertEqual(len(re.findall(r"WGEX iPhone coretrack001", first.stdout)), 1, first.stdout)  # printed once
        self.assertIn(owned[0]["udid"], first.stdout)
        creates = [call for call in self.simctl_calls(world) if call[1] == "create"]
        self.assertEqual(creates, [["simctl", "create", "WGEX iPhone coretrack001",
                                    "com.apple.CoreSimulator.SimDeviceType.iPhone-19-Pro",
                                    "com.apple.CoreSimulator.SimRuntime.iOS-27-0"]])
        # reused on the next run: no second create, same destination
        second = self.run_hosted(root, world, "ios", key)
        self.assertEqual(second.returncode, 0, second.stderr + second.stdout)
        self.assertEqual(len([call for call in self.simctl_calls(world) if call[1] == "create"]), 1)
        self.assertEqual(self.xcodebuild_destinations(world), [f"id={owned[0]['udid']}"] * 2)
        # nothing but list and create ever reaches simctl: no boot, shutdown, erase, delete, runtime download or restart
        self.assertEqual({call[1] + " " + call[2] for call in self.simctl_calls(world) if call[1] != "create"},
                         {"list devices", "list runtimes", "list devicetypes"})
        self.assertEqual(json.loads(world[1].read_text())["devices"]["com.apple.CoreSimulator.SimRuntime.iOS-27-0"][0]["udid"],
                         self.SHARED_UDID)

    def test_hosted_ios_simulator_is_per_build_key(self):
        """M1-26 (d): two stable build keys get two devices; the key falls back to CODEX_THREAD_ID's last 12 characters."""
        root = self.ios_test_tree()
        world = self.simulator_world("sim-keys")
        for key in ({"CLEAN_DEV_SESSION": "x-coretrack001"}, {"CLEAN_DEV_SESSION": "x-maintree0001"},
                    {"CODEX_THREAD_ID": "019a-wgexcoretrack001"}):
            result = self.run_hosted(root, world, "ios", key)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        names = sorted(device["name"] for devices in json.loads(world[1].read_text())["devices"].values() for device in devices
                       if device["name"].startswith("WGEX "))
        # coretrack001 appears once: the CLEAN_DEV_SESSION run and the CODEX_THREAD_ID run share a key and a device
        self.assertEqual(names, ["WGEX iPhone coretrack001", "WGEX iPhone maintree0001"])
        destinations = self.xcodebuild_destinations(world)
        self.assertEqual(len(destinations), 3)
        self.assertEqual(destinations[0], destinations[2])
        self.assertEqual(len(set(destinations)), 2)

    def test_interactive_session_keys_share_one_device_per_checkout(self):
        """M1-26 fix 1: a run without a stable key (c-<hex>, new every session) reuses one device named for the checkout."""
        root = self.ios_test_tree()  # the checkout directory is named ios-tree
        world = self.simulator_world("sim-interactive")
        for session in ("c-19cbe308d40f", "c-14e0dd4f8472", "c-000000000000"):
            result = self.run_hosted(root, world, "ios", {"CLEAN_DEV_SESSION": session})
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        result = self.run_hosted(root, world, "ios", {"CLEAN_DEV_SESSION": "x-coretrack001"})  # a stable key keeps its own
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        names = sorted(device["name"] for devices in json.loads(world[1].read_text())["devices"].values() for device in devices
                       if device["name"].startswith("WGEX "))
        self.assertEqual(names, ["WGEX iPhone coretrack001", "WGEX iPhone ios-tree"])
        self.assertEqual(len([call for call in self.simctl_calls(world) if call[1] == "create"]), 2)
        destinations = self.xcodebuild_destinations(world)
        self.assertEqual(len(set(destinations[:3])), 1)
        self.assertNotEqual(destinations[0], destinations[3])

    def test_simulator_key_is_ascii_distinct_and_never_empty(self):
        """M1-26 fix 6: LC_ALL=C reduction; "_" and "-" stay distinct; short keys whole; an empty key uses the checkout name."""
        root = self.ios_test_tree()
        cases = [  # (environment, expected device name)
            ({"CLEAN_DEV_SESSION": "x-coretrack001"}, "coretrack001"),
            ({"CLEAN_DEV_SESSION": "x-ab_cd-ef"}, "ab.cd-ef"),
            ({"CLEAN_DEV_SESSION": "x-abcdef"}, "abcdef"),
            ({"CLEAN_DEV_SESSION": "x-ab-cd_ef"}, "ab-cd.ef"),
            ({"CODEX_THREAD_ID": "abc"}, "abc"),
            ({"CODEX_THREAD_ID": "exactly12chr"}, "exactly12chr"),
            ({"CODEX_THREAD_ID": "019a-wgexcoretrack001"}, "wgexcoretrack001"[-12:]),
            ({"CLEAN_DEV_SESSION": "x-xxxxcaf\u00e9ab12", "LC_ALL": "en_US.UTF-8"}, "xxxxcafab12"),
            ({"CLEAN_DEV_SESSION": "x-ab.cd"}, "abcd"),
            ({"CLEAN_DEV_SESSION": "x-!!!"}, "ios-tree"),
            ({"CLEAN_DEV_SESSION": "x-"}, "ios-tree"),
            ({"CLEAN_DEV_SESSION": "c-19cbe308d40f"}, "ios-tree"),
            ({"CLEAN_DEV_SESSION": "c-"}, "ios-tree"),
            ({}, "ios-tree"),
        ]
        for extra, key in cases:
            with self.subTest(extra=extra):
                env = {name: value for name, value in os.environ.items() if name not in ("CLEAN_DEV_SESSION", "CODEX_THREAD_ID")}
                result = subprocess.run(["bash", "-c", 'source "$1/Config/Scripts/lib.sh"; simulator_name iOS', "bash", str(root)],
                                        env=env | extra, capture_output=True, text=True)
                self.assertEqual((result.returncode, result.stdout), (0, f"WGEX iPhone {key}"), result.stderr)
        self.assertNotEqual(cases[1][1], cases[2][1])

    def test_hosted_ios_simulator_without_an_ios_27_runtime_fails_without_downloading(self):
        """M1-26 (c): a missing iOS 27 runtime stops the run with a clear message; nothing is created, run or fetched."""
        root = self.ios_test_tree()
        old = [{"identifier": "com.apple.CoreSimulator.SimRuntime.iOS-26-4", "name": "iOS 26.4", "version": "26.4",
                "platform": "iOS", "isAvailable": True,
                "supportedDeviceTypes": [{"identifier": "com.apple.CoreSimulator.SimDeviceType.iPhone-17-Pro"}]},
               {"identifier": "com.apple.CoreSimulator.SimRuntime.iOS-27-0", "name": "iOS 27.0", "version": "27.0",
                "platform": "iOS", "isAvailable": False, "supportedDeviceTypes": []}]
        world = self.simulator_world("sim-no-runtime", runtimes=old)
        result = self.run_hosted(root, world, "ios", {"CLEAN_DEV_SESSION": "x-coretrack001"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("iOS 27", result.stderr)
        self.assertIn("SimRuntime.iOS-27", result.stderr)
        self.assertEqual(self.xcodebuild_destinations(world), [])
        self.assertEqual([call for call in self.simctl_calls(world) if call[1] not in ("list",)], [])
        devices = json.loads(world[1].read_text())["devices"]["com.apple.CoreSimulator.SimRuntime.iOS-27-0"]
        self.assertEqual([device["udid"] for device in devices], [self.SHARED_UDID])

    def test_simulator_selection_can_only_return_a_wgex_prefixed_device(self):
        """M1-26: the selector refuses any name outside the WGEX prefix, whatever the caller asks for."""
        root = self.ios_test_tree()
        world = self.simulator_world("sim-guard")
        env = os.environ | {"PATH": f"{world[0]}:{os.environ['PATH']}"} | world[3]
        for name in ("iPhone 18 Pro", "wgex iPhone x", "WGEXiPhone", ""):
            for mode in ("lookup", "ensure"):
                with self.subTest(name=name, mode=mode):
                    result = subprocess.run(["bash", "-c", 'source "$1/Config/Scripts/lib.sh"; simulator_select iOS "$2" "$3"',
                                             "bash", str(root), name, mode], env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(result.stdout, "")
        self.assertEqual(self.simctl_calls(world), [])

    def test_hosted_tvos_keeps_the_skip_without_a_runtime_and_uses_a_wgex_device_with_one(self):
        """M1-26: tvOS is unchanged while no tvOS runtime is installed; with one the same WGEX pattern applies."""
        root = self.ios_test_tree()
        world = self.simulator_world("sim-tv")
        result = self.run_hosted(root, world, "tv", {"CLEAN_DEV_SESSION": "x-coretrack001"})
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("tvOS bundles built; no tvOS simulator runtime is installed (P0-11), so nothing ran", result.stdout)
        self.assertEqual(self.xcodebuild_destinations(world), ["generic/platform=tvOS Simulator"])
        self.assertEqual([call for call in self.simctl_calls(world) if call[1] != "list"], [])
        runtime = "com.apple.CoreSimulator.SimRuntime.tvOS-27-0"
        tv = self.simulator_world("sim-tv-installed", runtimes=[{
            "identifier": runtime, "name": "tvOS 27.0", "version": "27.0", "platform": "tvOS", "isAvailable": True,
            "supportedDeviceTypes": [{"identifier": "com.apple.CoreSimulator.SimDeviceType.Apple-TV-4K"}]}],
            devices={runtime: [{"name": "Apple TV 4K", "udid": self.SHARED_UDID, "state": "Shutdown", "isAvailable": True}]})
        state = json.loads(tv[1].read_text())
        state["devicetypes"].append({"identifier": "com.apple.CoreSimulator.SimDeviceType.Apple-TV-4K", "name": "Apple TV 4K",
                                     "productFamily": "Apple TV", "modelIdentifier": "AppleTV14,1"})
        tv[1].write_text(json.dumps(state))
        result = self.run_hosted(root, tv, "tv", {"CLEAN_DEV_SESSION": "x-coretrack001"})
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        created = json.loads(tv[1].read_text())["devices"][runtime]
        # the shared tvOS device sits under the tvOS runtime and is never chosen: the WGEX device is a second entry
        self.assertEqual([device["name"] for device in created], ["Apple TV 4K", "WGEX Apple TV coretrack001"])
        self.assertEqual(created[0]["udid"], self.SHARED_UDID)
        self.assertEqual(self.xcodebuild_destinations(tv), [f"id={created[1]['udid']}"])

    def test_doctor_names_the_wgex_simulator_device_without_failing_for_its_absence(self):
        """M1-26: one informational row; present or "will be created on first hosted test", never a FAIL."""
        tree = self.work / "doctor-sim-tree"
        for name in ("Tools/doctor/doctor.sh", "Toolchain.lock"):
            (tree / name).parent.mkdir(parents=True, exist_ok=True)
            self.copy_source(ROOT / name, tree / name)
        owned = {"name": "WGEX iPhone coretrack001", "udid": "ABCDEF01-2345-6789-ABCD-EF0123456789", "state": "Shutdown",
                 "isAvailable": True, "deviceTypeIdentifier": "com.apple.CoreSimulator.SimDeviceType.iPhone-17-Pro"}
        rows = {}
        for case, devices in (("absent", None), ("present", [owned])):
            world = self.simulator_world(f"doctor-sim-{case}", devices=devices)
            env = os.environ | {"PATH": f"{world[0]}:{os.environ['PATH']}", "WGEX_OFFLINE": "1",
                                "CLEAN_DEV_SESSION": "x-coretrack001"} | world[3]
            result = subprocess.run(["bash", str(tree / "Tools/doctor/doctor.sh")], env=env, capture_output=True, text=True)
            found = re.findall(r"^(\w+) +wgex simulator +(.*)$", result.stdout, re.M)
            self.assertEqual(len(found), 1, result.stdout)
            self.assertEqual(found[0][0], "INFO")
            self.assertNotRegex(result.stdout, r"(?m)^FAIL +wgex simulator")
            rows[case] = found[0][1]
        self.assertEqual(rows["absent"], "WGEX iPhone coretrack001 (will be created on first hosted test)")
        self.assertEqual(rows["present"], "WGEX iPhone coretrack001 (present, ABCDEF01-2345-6789-ABCD-EF0123456789)")

    # ---- M1-26 fix pass 1: no leaked or half-made devices, runtime-checked reuse, bounded simctl calls, sim-prune ----

    IOS27 = "com.apple.CoreSimulator.SimRuntime.iOS-27-0"
    IOS27_1 = "com.apple.CoreSimulator.SimRuntime.iOS-27-1"
    NAME = "WGEX iPhone coretrack001"

    @staticmethod
    def wgex_device(udid, name=NAME, state="Shutdown", available=True, **extra):
        return {"name": name, "udid": udid, "state": state, "isAvailable": available,
                "deviceTypeIdentifier": "com.apple.CoreSimulator.SimDeviceType.iPhone-17-Pro"} | extra

    def selector(self, root, world, mode="ensure", platform="iOS", name=NAME, **extra):
        """simulator_select straight from lib.sh against the stub; the retry wait is 0 unless a test says otherwise."""
        env = os.environ | {"PATH": f"{world[0]}:{os.environ['PATH']}", "WGEX_SIMCTL_RETRY_SECONDS": "0"} | world[3] | extra
        return subprocess.run(["bash", "-c", 'source "$1/Config/Scripts/lib.sh"; simulator_select "$2" "$3" "$4"', "bash",
                               str(root), platform, name, mode], env=env, capture_output=True, text=True)

    def sim_devices(self, world):
        return [(runtime, device) for runtime, group in json.loads(world[1].read_text())["devices"].items() for device in group]

    def verbs(self, world, verb):
        return [call for call in self.simctl_calls(world) if call[1] == verb]

    def test_no_device_is_created_unless_the_list_has_an_entry_for_the_runtime(self):
        """M1-26 fix 2 (A3, B LOW-1): an empty or missing runtime entry is a simctl fault: one retry, then exit 1, no create."""
        root = self.ios_test_tree()
        existing = self.wgex_device("00000000-0000-0000-0000-0000000000AA")
        # a cold CoreSimulator lists no devices for a moment: the retry finds the device that is there, nothing is created
        world = self.simulator_world("sim-entry-once", devices=[existing])
        result = self.selector(root, world, STUB_SIM="devices-empty-once")
        self.assertEqual((result.returncode, result.stdout.split("\t")[0], result.stdout.split("\t")[-1].strip()),
                         (0, existing["udid"], "reused"), result.stderr)
        self.assertEqual(self.verbs(world, "create"), [])
        self.assertEqual(len([call for call in self.simctl_calls(world) if call[1:3] == ["list", "devices"]]), 2)
        # never answered: exit 1 naming the runtime, a second listing, nothing created
        world = self.simulator_world("sim-entry-never", devices=[existing])
        result = self.selector(root, world, STUB_SIM="devices-empty")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(self.IOS27, result.stderr)
        self.assertEqual(self.verbs(world, "create"), [])
        self.assertEqual(len([call for call in self.simctl_calls(world) if call[1:3] == ["list", "devices"]]), 2)
        # an installed runtime with an empty entry ([]) is a normal first run: the device is created
        world = self.simulator_world("sim-entry-empty", devices=[])
        result = self.selector(root, world)
        self.assertEqual((result.returncode, result.stdout.split("\t")[-1].strip()), (0, "created"), result.stderr)
        self.assertEqual(len(self.verbs(world, "create")), 1)

    def test_a_twin_made_by_a_concurrent_first_run_is_reduced_to_the_lowest_udid(self):
        """M1-26 fix 2 (A2, B NOTE-1): after a create the list is read again; the lowest UDID stays, WGEX Shutdown twins go."""
        root = self.ios_test_tree()
        low, high = "00000000-0000-0000-0000-000000000001", "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"
        for case, twin, kept_is_twin, deleted in (("low", f"{low}:Shutdown", True, "created"),
                                                  ("high", f"{high}:Shutdown", False, "twin"),
                                                  ("booted-high", f"{high}:Booted", False, None)):
            with self.subTest(case):
                world = self.simulator_world(f"sim-twin-{case}")
                result = self.selector(root, world, STUB_SIM_TWIN=twin)
                self.assertEqual(result.returncode, 0, result.stderr)
                udid, _, _, state = result.stdout.strip().split("\t")
                named = [device for _, device in self.sim_devices(world) if device["name"] == self.NAME]
                deletes = [call[2] for call in self.verbs(world, "delete")]
                if case == "low":
                    self.assertEqual((udid, state, [d["udid"] for d in named]), (low, "reused", [low]))
                    self.assertEqual(len(deletes), 1)
                elif case == "high":
                    self.assertEqual(state, "created")
                    self.assertEqual(deletes, [high])
                    self.assertEqual([d["udid"] for d in named], [udid])
                else:  # a Booted twin is never deleted, even when it is the higher UDID
                    self.assertEqual((state, deletes), ("created", []))
                    self.assertEqual({d["udid"] for d in named}, {udid, high})
                self.assertNotIn(self.SHARED_UDID, deletes)

    def test_a_failed_create_leaves_no_device_behind(self):
        """M1-26 fix 2 (A3, B NOTE-1): a create that fails, answers no UDID or hangs removes the device it left (and only that)."""
        root = self.ios_test_tree()
        older = self.wgex_device("00000000-0000-0000-0000-0000000000BB")
        for knob, message, extra in (("create-fail", "the device could not be created", {}),
                                     ("create-junk", "did not return a UDID", {}),
                                     ("create-hang", "timed out after 1 s", {"WGEX_SIMCTL_CREATE_DEADLINE": "1"})):
            with self.subTest(knob):
                # the same-named device on a runtime that is not the newest stays: it is not this run's own
                world = self.simulator_world(f"sim-fail-{knob}", versions=[("27.0", True), ("27.1", True)],
                                             devices={self.IOS27: [older], self.IOS27_1: []})
                started = time.monotonic()
                result = self.selector(root, world, STUB_SIM=knob, **extra)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(message, result.stderr)
                self.assertIn("removed the half-made device", result.stderr)
                self.assertLess(time.monotonic() - started, 25)
                self.assertEqual([(runtime, device["udid"]) for runtime, device in self.sim_devices(world)],
                                 [(self.IOS27, older["udid"])])
                self.assertEqual(len(self.verbs(world, "delete")), 1)

    def test_a_device_still_being_created_is_never_selected(self):
        """M1-26 fix 2: the selector skips state Creating (another run's device is not ours to use or delete)."""
        root = self.ios_test_tree()
        creating = self.wgex_device("00000000-0000-0000-0000-0000000000CC", state="Creating")
        world = self.simulator_world("sim-creating", devices=[creating])
        result = self.selector(root, world)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(result.stdout.split("\t")[0], creating["udid"])
        self.assertEqual(result.stdout.strip().split("\t")[-1], "created")
        self.assertEqual(self.verbs(world, "delete"), [])
        self.assertEqual(self.selector(root, world, "lookup").stdout.split("\t")[0], result.stdout.split("\t")[0])

    def test_the_generic_runtime_wins_over_a_device_specific_build_of_the_same_version(self):
        """M04-T31: iOS-27-2-iPhone19-4 (24B91016s) fails the first boot with Data Migration Failed; the generic iOS-27-2 is used,
        whatever order simctl lists them in."""
        root = self.ios_test_tree()
        generic = "com.apple.CoreSimulator.SimRuntime.iOS-27-2"
        specific = generic + "-iPhone19-4"
        shared = self.wgex_device(self.SHARED_UDID, name="iPhone 18 Pro")
        supported = [{"identifier": "com.apple.CoreSimulator.SimDeviceType.iPhone-17-Pro", "name": "iPhone 17 Pro",
                      "productFamily": "iPhone"}]
        entries = {identifier: {"identifier": identifier, "name": "iOS 27.2", "version": "27.2", "platform": "iOS",
                                "isAvailable": True, "supportedDeviceTypes": supported} for identifier in (generic, specific)}
        for position, order in enumerate(((specific, generic), (generic, specific))):
            world = self.simulator_world(f"sim-generic-{position}", runtimes=[entries[i] for i in order],
                                         devices={generic: [shared], specific: []})
            result = self.selector(root, world)
            fields = result.stdout.strip().split("\t")
            self.assertEqual((result.returncode, fields[1], fields[3]), (0, generic, "created"), result.stderr)

    def test_a_device_is_reused_only_on_the_newest_installed_ios_27_runtime(self):
        """M1-26 fix 3 (A4, B LOW-3) and fixtures M11/M12: runtime-checked reuse, the newest 27.x wins, unavailable never reused."""
        root = self.ios_test_tree()
        old, new = "00000000-0000-0000-0000-0000000000D0", "00000000-0000-0000-0000-0000000000D1"
        shared = self.wgex_device(self.SHARED_UDID, name="iPhone 18 Pro")

        def run(label, versions, devices, mode="ensure"):
            world = self.simulator_world(f"sim-rt-{label}", versions=versions, devices=devices)
            result = self.selector(root, world, mode)
            return world, result, result.stdout.strip().split("\t")

        # M12: two 27.x runtimes and no device: created on the newest, whatever order simctl lists them in
        for position, order in enumerate(([("27.0", True), ("27.1", True)], [("27.1", True), ("27.0", True)])):
            world, result, fields = run(f"newest-{position}", order, {self.IOS27: [shared], self.IOS27_1: []})
            self.assertEqual((result.returncode, fields[1:2], fields[3:]), (0, [self.IOS27_1], ["created"]), result.stderr)
        # a device on the older 27.x is not reused once a newer one is installed: a fresh device, the old one left alone
        world, result, fields = run("older", [("27.0", True), ("27.1", True)],
                                    {self.IOS27: [self.wgex_device(old)], self.IOS27_1: []})
        self.assertEqual((result.returncode, fields[1], fields[3]), (0, self.IOS27_1, "created"), result.stderr)
        self.assertEqual(sorted(device["udid"] for _, device in self.sim_devices(world)).count(old), 1)
        self.assertEqual(self.verbs(world, "delete"), [])
        # a device on the newest is reused, no create
        world, result, fields = run("newest-device", [("27.0", True), ("27.1", True)],
                                    {self.IOS27: [self.wgex_device(old)], self.IOS27_1: [self.wgex_device(new)]})
        self.assertEqual((result.returncode, fields[0], fields[3]), (0, new, "reused"), result.stderr)
        self.assertEqual(self.verbs(world, "create"), [])
        # a runtime that is not 27.x, or not available, never hosts the device
        world, result, fields = run("ios26", [("27.0", True)], {"com.apple.CoreSimulator.SimRuntime.iOS-26-4": [self.wgex_device(old)],
                                                                 self.IOS27: []})
        self.assertEqual((result.returncode, fields[1], fields[3]), (0, self.IOS27, "created"), result.stderr)
        world, result, fields = run("unavailable-runtime", [("27.0", True), ("27.1", False)],
                                    {self.IOS27: [self.wgex_device(old)], self.IOS27_1: [self.wgex_device(new)]})
        self.assertEqual((result.returncode, fields[0], fields[3]), (0, old, "reused"), result.stderr)
        # M11: an unavailable device with the exact name is not reused
        world, result, fields = run("unavailable-device", [("27.0", True)],
                                    {self.IOS27: [self.wgex_device(old, available=False)]})
        self.assertEqual((result.returncode, fields[3]), (0, "created"), result.stderr)
        self.assertNotEqual(fields[0], old)
        # lookup agrees with ensure: the older device is "not there" while a newer runtime exists
        world, result, _ = run("lookup", [("27.0", True), ("27.1", True)], {self.IOS27: [self.wgex_device(old)], self.IOS27_1: []},
                               "lookup")
        self.assertEqual((result.returncode, result.stdout), (3, ""))

    def test_the_selector_rejects_a_create_that_answers_no_udid_and_an_unsupported_device_type(self):
        """M1-26 fixtures M5 and M20: an unsupported type that would rank first is skipped; a junk create answer is a failure."""
        root = self.ios_test_tree()
        world = self.simulator_world("sim-types")
        result = self.selector(root, world)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.split("\t")[2], "com.apple.CoreSimulator.SimDeviceType.iPhone-19-Pro")
        self.assertEqual(self.verbs(world, "create")[0][3], "com.apple.CoreSimulator.SimDeviceType.iPhone-19-Pro")
        world = self.simulator_world("sim-junk")
        result = self.selector(root, world, STUB_SIM="create-junk")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")

    def test_an_empty_runtime_list_is_retried_once_before_no_runtime_is_reported(self):
        """M1-26 fix 4 (A note): a cold CoreSimulator that lists no runtime at first still reaches the device."""
        root = self.ios_test_tree()
        world = self.simulator_world("sim-cold")
        result = self.selector(root, world, STUB_SIM="runtimes-empty-once")
        self.assertEqual((result.returncode, result.stdout.strip().split("\t")[-1]), (0, "created"), result.stderr)
        self.assertEqual(len([call for call in self.simctl_calls(world) if call[1:3] == ["list", "runtimes"]]), 2)
        world = self.simulator_world("sim-cold-always")
        result = self.selector(root, world, STUB_SIM="runtimes-empty")
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertIn("SimRuntime.iOS-27", result.stderr)
        self.assertEqual(len([call for call in self.simctl_calls(world) if call[1:3] == ["list", "runtimes"]]), 2)
        self.assertEqual(self.verbs(world, "create"), [])
        # a runtime list that is not empty (no tvOS here) is answered at once: one call, silent exit 4
        world = self.simulator_world("sim-no-tv")
        result = self.selector(root, world, "ensure-if-installed", "tvOS", "WGEX Apple TV coretrack001")
        self.assertEqual((result.returncode, result.stderr), (4, ""))
        self.assertEqual(len([call for call in self.simctl_calls(world) if call[1:3] == ["list", "runtimes"]]), 1)

    def test_simctl_calls_run_under_a_deadline(self):
        """M1-26 fix 5 (B NOTE-2): a hung simctl is killed and named; doctor's runtime list and its device row are bounded too."""
        root = self.ios_test_tree()
        world = self.simulator_world("sim-hung")
        started = time.monotonic()
        result = self.selector(root, world, STUB_SIM="list-sleep", WGEX_SIMCTL_LIST_DEADLINE="1")
        self.assertEqual(result.returncode, 1)
        self.assertIn("timed out after 1 s", result.stderr)
        self.assertIn("simctl list", result.stderr)
        self.assertLess(time.monotonic() - started, 20)
        # an out-of-range override falls back to the default instead of disabling the bound
        result = subprocess.run(["bash", "-c", 'source "$1/Config/Scripts/lib.sh"; WGEX_X=0 simctl_limit WGEX_X 60 1 600; '
                                 'WGEX_X=abc simctl_limit WGEX_X 180 1 900; WGEX_X=007 simctl_limit WGEX_X 9 1 10', "bash", str(root)],
                                capture_output=True, text=True)
        self.assertEqual(result.stdout, "601807")
        tree = self.work / "doctor-hung-tree"
        for name in ("Tools/doctor/doctor.sh", "Toolchain.lock"):
            (tree / name).parent.mkdir(parents=True, exist_ok=True)
            self.copy_source(ROOT / name, tree / name)
        stubs = self.work / "doctor-hung-bin"
        stubs.mkdir()
        (stubs / "xcrun").write_text('#!/bin/bash\nif [[ "$1 $2" == "simctl list" ]]; then exec sleep 30; fi\nexec /usr/bin/xcrun "$@"\n')
        (stubs / "xcrun").chmod(0o755)
        started = time.monotonic()
        result = subprocess.run(["bash", str(tree / "Tools/doctor/doctor.sh")], capture_output=True, text=True, timeout=120,
                                env=os.environ | {"PATH": f"{stubs}:{os.environ['PATH']}", "WGEX_OFFLINE": "1", "WGEX_SIMCTL_LIST_DEADLINE": "1",
                                                  "WGEX_DOCTOR_SIMCTL_RETRY_SECONDS": "0", "CLEAN_DEV_SESSION": "x-coretrack001"})
        self.assertLess(time.monotonic() - started, 60)
        self.assertRegex(result.stdout, r"(?m)^FAIL +simulator iOS +simctl unavailable: simctl list runtimes timed out after 1 s$")
        self.assertRegex(result.stdout, r"(?m)^INFO +wgex simulator +WGEX iPhone coretrack001 \(state unknown: simctl unavailable\)$")

    def prune_world(self, name):
        """A WGEX device zoo for sim-prune; returns (world, {label: udid}); every device that must survive is listed in KEEP."""
        now = datetime.datetime.now(datetime.timezone.utc)

        def ago(days):
            return (now - datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

        def udid(number):
            return f"00000000-0000-0000-0000-{number:012d}"

        tv = "com.apple.CoreSimulator.SimRuntime.tvOS-27-0"
        old = "com.apple.CoreSimulator.SimRuntime.iOS-26-4"
        d = self.wgex_device
        zoo = {
            "fresh": d(udid(1), "WGEX iPhone fresh", lastBootedAt=ago(2)),
            "stale": d(udid(2), "WGEX iPhone stale", lastBootedAt=ago(20)),
            "booted": d(udid(3), "WGEX iPhone booted", state="Booted", lastBootedAt=ago(60)),
            "creating": d(udid(4), "WGEX iPhone creating", state="Creating", lastUsedAt=ago(60)),
            "dup-kept": d(udid(5), "WGEX iPhone dup", lastBootedAt=ago(1)),
            "dup-twin": d(udid(6), "WGEX iPhone dup", lastBootedAt=ago(1)),
            "no-time": d(udid(7), "WGEX iPhone no-time"),
            "used-stale": d(udid(8), "WGEX iPhone used-stale", lastUsedAt=ago(40)),
            # M1-10x item 7: the newer of the two stamps counts, whichever field carries it
            "newer-used": d(udid(13), "WGEX iPhone newer-used", lastBootedAt=ago(30), lastUsedAt=ago(1)),
            "newer-booted": d(udid(14), "WGEX iPhone newer-booted", lastBootedAt=ago(1), lastUsedAt=ago(30)),
            "both-stale": d(udid(15), "WGEX iPhone both-stale", lastBootedAt=ago(20), lastUsedAt=ago(30)),
            "unavailable": d(udid(11), "WGEX iPhone unavailable", available=False, lastBootedAt=ago(1)),
            "booting-twin": d(udid(12), "WGEX iPhone fresh", state="Booted", lastBootedAt=ago(1)),
            "shared": d(self.SHARED_UDID, "iPhone 18 Pro", lastBootedAt=ago(100)),
            "lookalike-case": d(udid(21), "wgex iPhone old", lastBootedAt=ago(100)),
            "lookalike-ipad": d(udid(22), "WGEX iPad old", lastBootedAt=ago(100)),
            "lookalike-bare": d(udid(23), "WGEX iPhone", lastBootedAt=ago(100)),
            "lookalike-glued": d(udid(24), "WGEXfoo", lastBootedAt=ago(100)),
        }
        world = self.simulator_world(name, devices={
            self.IOS27: [zoo[k] for k in ("fresh", "stale", "booted", "creating", "dup-twin", "dup-kept", "no-time", "used-stale",
                                          "newer-used", "newer-booted", "both-stale", "unavailable", "booting-twin", "shared", "lookalike-case", "lookalike-ipad",
                                          "lookalike-bare", "lookalike-glued")],
            old: [d(udid(10), "WGEX iPhone gone-runtime", lastBootedAt=ago(1))],
            tv: [d(udid(9), "WGEX Apple TV gone-runtime", lastBootedAt=ago(1))]})
        return world, {key: device["udid"] for key, device in zoo.items()} | {"gone-ios": udid(10), "gone-tv": udid(9)}

    def prune(self, root, world, *arguments, **extra):
        env = os.environ | {"PATH": f"{world[0]}:{os.environ['PATH']}", "WGEX_SIMCTL_RETRY_SECONDS": "0"} | world[3] | extra
        return subprocess.run(["bash", "-c", 'source "$1/Config/Scripts/lib.sh"; shift; simulator_prune "$@"', "bash", str(root),
                               *arguments], env=env, capture_output=True, text=True)

    def test_sim_prune_deletes_only_stale_duplicate_or_orphaned_shutdown_wgex_devices(self):
        """M1-26 fix 1: dry run by default, --apply deletes; never Booted/Creating, never a non-WGEX device."""
        root = self.ios_test_tree()
        world, ids = self.prune_world("sim-prune")
        dry = self.prune(root, world)
        self.assertEqual(dry.returncode, 0, dry.stderr)
        decisions = {line.split("\t")[2]: (line.split("\t")[0], line.split("\t")[3]) for line in dry.stdout.splitlines()[1:]}
        expected_delete = {"stale", "used-stale", "both-stale", "dup-twin", "unavailable", "gone-ios", "gone-tv"}
        self.assertEqual({udid for udid, (verdict, _) in decisions.items() if verdict == "would-delete"},
                         {ids[key] for key in expected_delete})
        # every WGEX device gets a line (name, UDID, reason); the non-WGEX ones get none
        wgex_keys = {key for key in ids if not key.startswith(("shared", "lookalike"))}
        self.assertEqual(set(decisions), {ids[key] for key in wgex_keys})
        for key in ("stale", "used-stale", "both-stale"):
            self.assertIn("not booted for", decisions[ids[key]][1])
        self.assertIn("lastUsedAt", decisions[ids["used-stale"]][1])
        self.assertIn("lastBootedAt", decisions[ids["both-stale"]][1])  # the newer of the two stamps is the one named
        self.assertEqual({decisions[ids[key]][0] for key in ("newer-used", "newer-booted")}, {"keep"})
        self.assertIn("duplicate of " + ids["dup-kept"], decisions[ids["dup-twin"]][1])
        self.assertIn("no longer installed or available", decisions[ids["gone-ios"]][1])
        self.assertIn("no longer installed or available", decisions[ids["gone-tv"]][1])
        self.assertIn("state Booted", decisions[ids["booted"]][1])
        self.assertIn("state Creating", decisions[ids["creating"]][1])
        self.assertIn("WGEX iPhone stale", dry.stdout)
        self.assertEqual(self.verbs(world, "delete"), [])  # a dry run deletes nothing
        before = sorted(device["udid"] for _, device in self.sim_devices(world))
        self.assertEqual(before, sorted(ids.values()))
        for bad in (["--apply", "extra"], ["--force"]):
            self.assertEqual(self.prune(root, world, *bad).returncode, 2)
        applied = self.prune(root, world, "--apply")
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertEqual({call[2] for call in self.verbs(world, "delete")}, {ids[key] for key in expected_delete})
        self.assertEqual(sorted(device["udid"] for _, device in self.sim_devices(world)),
                         sorted(udid for key, udid in ids.items() if key not in expected_delete))
        self.assertEqual(len(re.findall(r"(?m)^deleted\t", applied.stdout)), len(expected_delete))
        # nothing left to do on a second pass
        again = self.prune(root, world, "--apply")
        self.assertEqual((again.returncode, len(self.verbs(world, "delete"))), (0, len(expected_delete)))

    def test_sim_prune_refuses_to_run_when_simctl_lists_no_runtime_and_survives_a_failed_delete(self):
        """M1-26 fix 1: an empty runtime list would make every device look orphaned; a failed delete is reported, exit 1."""
        root = self.ios_test_tree()
        world, ids = self.prune_world("sim-prune-guard")
        result = self.prune(root, world, "--apply", STUB_SIM="runtimes-empty")
        self.assertEqual(result.returncode, 1)
        self.assertIn("refusing to prune", result.stderr)
        self.assertEqual(self.verbs(world, "delete"), [])
        result = self.prune(root, world, "--apply", STUB_SIM="delete-fail")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(re.findall(r"(?m)^delete-failed\t", result.stdout)), 7)  # the seven stale, duplicate or orphaned devices
        self.assertEqual(len(self.sim_devices(world)), len(ids))
        # the recipe exists, and no gate runs it
        listing = subprocess.run(["just", "--dry-run", "sim-prune", "--apply"], cwd=ROOT, capture_output=True, text=True)
        self.assertIn("simulator_prune", listing.stdout + listing.stderr)
        for gate in ("check", "check-full"):
            commands = subprocess.run(["just", "--dry-run", gate], cwd=ROOT, capture_output=True, text=True)
            self.assertNotIn("sim-prune", commands.stdout + commands.stderr)
            self.assertNotIn("simulator_prune", commands.stdout + commands.stderr)
        self.assertNotIn("prune", (ROOT / "Config/Scripts/check.sh").read_text())

    def test_sim_prune_keeps_a_fresh_device_that_shares_its_name_with_one_on_another_runtime(self):
        """M1-10x item 7 (M1-26 FIX1-VERIFY L3, mutant Mo): duplicates are judged per runtime. The same WGEX name on iOS-27-0
        (lower UDID) and iOS-27-1, both fresh, are both kept; a dry run and --apply delete nothing."""
        root = self.ios_test_tree()
        now = datetime.datetime.now(datetime.timezone.utc)
        fresh = (now - datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        low, high = "00000000-0000-0000-0000-0000000000A0", "00000000-0000-0000-0000-0000000000B0"
        world = self.simulator_world("sim-prune-runtimes", versions=[("27.0", True), ("27.1", True)],
                                     devices={self.IOS27: [self.wgex_device(low, lastBootedAt=fresh)],
                                              self.IOS27_1: [self.wgex_device(high, lastBootedAt=fresh)]})
        for arguments in ((), ("--apply",)):
            result = self.prune(root, world, *arguments)
            self.assertEqual(result.returncode, 0, result.stderr)
            verdicts = {line.split("\t")[2]: line.split("\t")[0] for line in result.stdout.splitlines()[1:]}
            self.assertEqual(verdicts, {low: "keep", high: "keep"}, result.stdout)
            self.assertEqual(self.verbs(world, "delete"), [])
        self.assertEqual(sorted(device["udid"] for _, device in self.sim_devices(world)), [low, high])

    def test_with_deadline_kills_the_whole_process_group_and_keeps_status_and_output(self):
        """M1-10x item 7 (M1-26 FIX1-VERIFY L1): a wedged tool that forked a child holding stdout cannot hang the caller past
        the deadline (doctor's runtime list); expiry is status 142 as before, and an ordinary command keeps its output
        and status, a signalled one 128+signal."""
        library = ROOT / "Config/Scripts/lib.sh"
        pidfile = self.work / "forked.pid"
        # Give the parent time to start under load; the child outlives both the deadline and the elapsed assertion.
        # The subprocess timeout also leaves the broken-group case time to fail the assertion, rather than timing out.
        script = f'''source "{library}"
started=$SECONDS
status=0
out="$(with_deadline 10 bash -c 'sleep 90 & echo $! >"$1"; echo parent-started; wait' x "{pidfile}")" || status=$?
echo "$status $((SECONDS - started)) $out"
status=0
out="$(with_deadline 5 bash -c 'echo ordinary; exit 3')" || status=$?
echo "$status $out"
status=0
out="$(with_deadline 5 bash -c 'kill -TERM $$')" || status=$?
echo "$status"
status=0
out="$(with_deadline 5 /nonexistent-wgex-tool 2>&1)" || status=$?
echo "$status $out"'''
        started = time.monotonic()
        result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=120)
        if pidfile.exists():
            self.addCleanup(lambda pid=int(pidfile.read_text()): os.kill(pid, 9) if self.alive(pid) else None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(time.monotonic() - started, 55)
        expired, ordinary, signalled, missing = result.stdout.splitlines()
        self.assertRegex(expired, r"^142 [0-9]+ parent-started$")
        self.assertEqual(ordinary, "3 ordinary")
        self.assertEqual(signalled, "143")
        self.assertRegex(missing, r"^[1-9][0-9]* exec failed$")
        self.assertFalse(self.alive(int(pidfile.read_text())), "the forked child outlived the deadline")

    @staticmethod
    def alive(pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True

    def test_doctor_removes_its_simctl_error_file_on_every_exit_path(self):
        """M1-10x item 7 (M1-26 FIX1-VERIFY N5): a doctor that ends, fails or is terminated mid-run leaves no
        $TMPDIR/wgex-doctor-simctl.* behind (an orphan turned the next tooling-selftest red)."""
        tree = self.work / "doctor-trap-tree"
        for name in ("Tools/doctor/doctor.sh", "Toolchain.lock"):
            (tree / name).parent.mkdir(parents=True, exist_ok=True)
            self.copy_source(ROOT / name, tree / name)
        stubs = self.work / "doctor-trap-bin"
        stubs.mkdir()
        scratch = self.work / "doctor-trap-tmp"
        scratch.mkdir()
        (stubs / "xcrun").write_text('#!/bin/bash\nif [[ "$1 $2" == "simctl list" ]]; then exec sleep "${STUB_SIMCTL_SLEEP:-0}"; fi\n'
                                     'exec /usr/bin/xcrun "$@"\n')
        (stubs / "xcrun").chmod(0o755)
        env = os.environ | {"PATH": f"{stubs}:{os.environ['PATH']}", "TMPDIR": str(scratch) + "/", "WGEX_OFFLINE": "1",
                            "WGEX_DOCTOR_SIMCTL_RETRY_SECONDS": "0", "CLEAN_DEV_SESSION": "x-coretrack001"}
        leftovers = lambda: sorted(path.name for path in scratch.glob("wgex-doctor-simctl.*"))
        # ended: the stub lists nothing, so the iOS runtime row fails and doctor exits non-zero
        result = subprocess.run(["bash", str(tree / "Tools/doctor/doctor.sh")], env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertEqual(leftovers(), [])
        # terminated while simctl is still running
        process = subprocess.Popen(["bash", str(tree / "Tools/doctor/doctor.sh")], env=env | {"STUB_SIMCTL_SLEEP": "4"},
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        deadline = time.monotonic() + 100
        while not leftovers() and time.monotonic() < deadline and process.poll() is None:
            time.sleep(0.05)
        self.assertEqual(len(leftovers()), 1, "doctor never reached the simctl list")
        process.terminate()  # this test's own child, by the pid Popen recorded
        self.assertEqual(process.wait(timeout=60), 143)
        self.assertEqual(leftovers(), [])

    # ---- M1-10x fix pass 1: zsh startup, the outer just, repository selectors, with_deadline ----

    def zdotdir_fixtures(self):
        """(hit file, ZDOTDIR whose .zshenv re-exports stripped knobs, ZDOTDIR whose .zshenv is `exit 0`) - VERIFY-B H1."""
        hits = self.work / "zdotdir-hits"
        bash_env = self.work / "zdotdir-bash-env.sh"
        bash_env.write_text(f'echo bash-env-hit >>"{hits}"\n')
        reexport, quiet = self.work / "zdotdir-reexport", self.work / "zdotdir-exit"
        for directory in (reexport, quiet):
            directory.mkdir()
        (reexport / ".zshenv").write_text(f'echo zshenv-hit >>"{hits}"\n'
                                          f'export BASH_ENV="{bash_env}" SHELLOPTS=xtrace GREP_OPTIONS=--count\n')
        (quiet / ".zshenv").write_text("exit 0\n")
        return hits, reexport, quiet

    def test_zdotdir_cannot_reach_a_gate_step_or_the_outer_recipe_line(self):
        """M1-10x fix 1 item 1 (VERIFY-B H1, VERIFY A L1): ZDOTDIR makes the recipe zsh read a caller's .zshenv instead of
        ~/.zshenv. A file that re-exports the stripped knobs, or that `exit 0`s, must not change any step: through
        timed-step plus a nested just recipe, and through the justfile's recipe shell on its own (the outer line)."""
        hits, reexport, quiet = self.zdotdir_fixtures()
        for directory in (reexport, quiet):
            hits.unlink(missing_ok=True)
            result = subprocess.run(self.GATE_STEP + ["probe/docs", "just", "docs-test"],
                                    cwd=ROOT, env=os.environ | {"ZDOTDIR": str(directory)},
                                    capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, (directory.name, result.stdout, result.stderr))
            self.assertIn("gate-entry: probe/docs dropped 1 inherited variables\n", result.stderr)  # ZDOTDIR
            self.assertIn("gate-step: probe/docs exit=0 ", result.stderr)
            self.assertFalse(hits.exists(), (directory.name, hits.read_text() if hits.exists() else ""))
        for directory in (reexport, quiet):  # the outer recipe line itself: no timed-step in front of it
            hits.unlink(missing_ok=True)
            result = subprocess.run(["just", "docs-test"], cwd=ROOT, env=os.environ | {"ZDOTDIR": str(directory)},
                                    capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, (directory.name, result.stdout, result.stderr))
            self.assertIn("docs tests: ok", result.stdout)  # the recipe line really ran
            self.assertFalse(hits.exists(), directory.name)

    def test_the_recipe_shell_drops_every_zsh_startup_knob(self):
        """M1-10x fix 1 item 1: the justfile's shell is /usr/bin/env -u <every knobs.ZSH_KNOB_NAMES> zsh -lc, and a recipe
        run under exactly that shell line sees none of those variables (zsh imports each as a parameter, probed)."""
        # behaviour under the justfile's own shell line (copied, not re-typed), with a hostile value per name
        literal = {"ZDOTDIR", "TMPPREFIX", "NULLCMD", "READNULLCMD", "ARGV0", "CDPATH", "TMOUT"}
        line = re.search(r"^set shell := .*$", (ROOT / "justfile").read_text(), re.M).group(0)
        scratch = self.work / "shell-probe"
        scratch.mkdir()
        (scratch / "justfile").write_text(line + "\nprobe:\n    @for n in " + " ".join(sorted(literal)) +
                                          "; do print -r -- \"$n=${(P)n}\"; done\n")
        guard = scratch / "Config/Scripts/knobs.py"
        guard.parent.mkdir(parents=True)
        shutil.copy(ROOT / "Config/Scripts/knobs.py", guard)
        result = subprocess.run(["just", "--justfile", str(scratch / "justfile"), "--working-directory", str(scratch), "probe"],
                                env=os.environ | {name: "zsh-knob-canary-not-printed" for name in literal},
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("zsh-knob-canary", result.stdout + result.stderr)
        self.assertEqual(len(result.stdout.splitlines()), len(literal))
        self.assertLessEqual(literal, knobs.ZSH_KNOB_NAMES)
        self.assertLessEqual(knobs.ZSH_KNOB_NAMES, knobs.KNOB_NAMES)
        dump = json.loads(subprocess.run(["just", "--dump", "--dump-format", "json"], cwd=ROOT, capture_output=True,
                                         text=True, check=True, timeout=60).stdout)
        shell = dump["settings"]["shell"]
        self.assertEqual(shell["command"], "/usr/bin/env")
        arguments = shell["arguments"]
        self.assertEqual(arguments[-2:], ["zsh", "-lc"])
        self.assertEqual(arguments[-6:-2], ["python3", "-I", "-B", "Config/Scripts/knobs.py"])
        self.assertEqual(arguments[0:-6:2], ["-u"] * len(knobs.ZSH_KNOB_NAMES))
        self.assertEqual(set(arguments[1:-6:2]), set(knobs.ZSH_KNOB_NAMES))

    def gate_result_accepted(self, returncode, output, label, prefix):
        """CONTRIBUTING.md's gate-result rule: status 0, one final `LABEL: passed (N gate steps, all exit=0)` line with N > 0
        equal to the number of this recipe's own gate-step lines (label prefix), every one exit=0."""
        steps = [line for line in output.splitlines() if line.startswith(f"gate-step: {prefix}")]
        final = re.findall(rf"^{re.escape(label)}: passed \((\d+) gate steps, all exit=0\)$", output, re.M)
        return (returncode == 0 and len(final) == 1 and int(final[0]) > 0 and int(final[0]) == len(steps)
                and all(" exit=0 " in line for line in steps))

    def test_a_dry_run_gate_cannot_pass_the_documented_gate_result_rule(self):
        """M1-10x fix 1 item 2 (VERIFY-B M1): JUST_DRY_RUN=true just check exited 0 with zero gate steps and printed the
        echoed `check: passed`. Now the outer just still exits 0 (it runs nothing, so nothing can refuse), but it prints no
        gate-step line, no `check: passed` text and no final line: the documented rule (gate-step lines, the final
        `N gate steps` line, status) rejects it. The real recipes' first and last lines are what make that so."""
        for recipe in ("check", "check-full"):
            result = subprocess.run(["just", recipe], cwd=ROOT, env=os.environ | {"JUST_DRY_RUN": "true"},
                                    capture_output=True, text=True, timeout=60)
            output = result.stdout + result.stderr
            self.assertEqual(result.returncode, 0, output)
            self.assertNotIn("gate-step:", output)
            self.assertNotIn(f"{recipe}: passed", output)
            self.assertNotIn("gate steps", output)
            self.assertFalse(self.gate_result_accepted(result.returncode, output, recipe, "check/" if recipe == "check" else "full/"))
            self.assertRegex(output, r"timed-step\.py --enter\n")
            self.assertRegex(output, rf"timed-step\.py --done {recipe}\n")

    def gate_recipe_lines(self, recipe):
        """(header after the recipe name, first body line, last body line) of a real justfile recipe."""
        text = (ROOT / "justfile").read_text()
        match = re.search(rf"^{recipe} (\$WGEX_GATE_LEDGER=.*):\n((?:    .*\n)+)", text, re.M)
        self.assertIsNotNone(match, recipe)
        body = match.group(2).splitlines()
        return match.group(1), body[0], body[-1]

    def test_the_gate_recipes_refuse_a_just_execution_variable_and_end_with_a_ledger_line(self):
        """M1-10x fix 1 item 2: `timed-step.py --enter` (first line of check and check-full) exits 2 naming any inherited
        JUST_* that changes what just runs (knobs.JUST_EXECUTION_NAMES and any unknown name; the presentation names pass);
        the ledger is created exclusively, filled by the steps and printed by --done, so a nested recipe has its own."""
        enter = self.GATE_STEP + ["--enter"]
        for name in ("JUST_DRY_RUN", "JUST_JUSTFILE", "JUST_WORKING_DIRECTORY"):  # VERIFY-B M1's inputs
            result = subprocess.run(enter, env=os.environ | {name: "canary-just-value-not-printed"}, capture_output=True,
                                    text=True, timeout=30)
            self.assertEqual(result.returncode, 2, (name, result.stderr))
            self.assertIn(f"gate-entry: refused: inherited {name} changes what just runs", result.stderr)
        for name in sorted(knobs.JUST_EXECUTION_NAMES) + ["JUST_NOT_A_REAL_KNOB_YET"]:
            result = subprocess.run(enter, env=os.environ | {name: "canary-just-value-not-printed"}, capture_output=True,
                                    text=True, timeout=30)
            self.assertEqual(result.returncode, 2, (name, result.stderr))
            self.assertIn(f"gate-entry: refused: inherited {name} changes what just runs", result.stderr)
            self.assertNotIn("canary", result.stdout + result.stderr)
        for name in sorted(knobs.JUST_PRESENTATION_NAMES):
            result = subprocess.run(enter, env=os.environ | {name: "x"}, capture_output=True, text=True, timeout=30)
            self.assertEqual((result.returncode, result.stderr), (0, ""), name)
        # every JUST_* name `just --help` lists is classified, so a newer just cannot add an unclassified one silently
        help_text = " ".join(subprocess.run(["just", "--help"], capture_output=True, text=True, check=True, timeout=30).stdout.split())
        listed = set(re.findall(r"JUST_[A-Z_]+", help_text))
        self.assertGreater(len(listed), 30)
        self.assertEqual(listed - knobs.JUST_EXECUTION_NAMES - knobs.JUST_PRESENTATION_NAMES, set())
        self.assertEqual(knobs.JUST_EXECUTION_NAMES & knobs.JUST_PRESENTATION_NAMES, set())
        # the real recipes: header exports the ledger, first line --enter, last line --done
        for recipe in ("check", "check-full"):
            header, first, last = self.gate_recipe_lines(recipe)
            self.assertEqual(first.strip(), "python3 -I Config/Scripts/timed-step.py --enter")
            self.assertEqual(last.strip(), f"python3 -I Config/Scripts/timed-step.py --done {recipe}")
        # shape test with the real header, first and last lines (the real steps are minutes of builds)
        header, first, last = self.gate_recipe_lines("check")
        step = "    python3 -I Config/Scripts/timed-step.py"
        scratch = self.work / "ledger-shape"
        scratch.mkdir()
        justfile = scratch / "justfile"
        justfile.write_text(re.search(r"^set shell := .*$", (ROOT / "justfile").read_text(), re.M).group(0) + "\n"
                            f"inner {header}:\n{first}\n{step} fixture/one python3 -I -c pass\n"
                            f"{step} fixture/two python3 -I -c pass\n{last.replace('--done check', '--done inner')}\n"
                            f"outer {header}:\n{first}\n{step} fixture/nested just --justfile {justfile} "
                            f"--working-directory {ROOT} inner\n{step} fixture/three python3 -I -c pass\n"
                            f"{last.replace('--done check', '--done outer')}\n")
        ledgers = self.work / "ledger-tmp"
        ledgers.mkdir()
        run = lambda recipe, **extra: subprocess.run(["just", "--justfile", str(justfile), "--working-directory", str(ROOT), recipe],
                                                     env=os.environ | {"TMPDIR": str(ledgers)} | extra, capture_output=True,
                                                     text=True, timeout=120)
        result = run("outer", WGEX_GATE_LEDGER=str(self.work / "stale-caller-ledger"))  # the recipe's own value wins
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["inner: passed (2 gate steps, all exit=0)",
                                                      "outer: passed (2 gate steps, all exit=0)"])
        self.assertEqual(len([line for line in result.stderr.splitlines() if line.startswith("gate-step: fixture/")]), 4)
        self.assertFalse((self.work / "stale-caller-ledger").exists())
        self.assertEqual(list(ledgers.glob("wgex-gate-*")), [])  # removed after a pass
        # the execution refusal works through the recipe itself, and QUIET cannot hide the failure status
        for name in ("JUST_QUIET", "JUST_NO_DEPS", "JUST_DOTENV_COMMAND"):
            result = run("outer", **{name: "true"})
            self.assertNotEqual(result.returncode, 0, name)
            self.assertNotIn("gate-step:", result.stdout + result.stderr)
            self.assertNotIn("passed", result.stdout)
        # a pre-seeded ledger is refused (exclusive create), and --done without a ledger or with none recorded fails
        seeded = self.work / "seeded-ledger"
        seeded.write_text("fixture/forged 0\n")
        result = subprocess.run(enter, env=os.environ | {"WGEX_GATE_LEDGER": str(seeded)}, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(seeded.read_text(), "fixture/forged 0\n")
        for ledger in (self.work / "no-such-ledger", None):
            env = os.environ | ({"WGEX_GATE_LEDGER": str(ledger)} if ledger else {})
            result = subprocess.run(self.GATE_STEP + ["--done", "check"], env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(result.stdout, "")
        empty = self.work / "empty-ledger"
        subprocess.run(enter, env=os.environ | {"WGEX_GATE_LEDGER": str(empty)}, check=True, timeout=30)
        result = subprocess.run(self.GATE_STEP + ["--done", "check"], env=os.environ | {"WGEX_GATE_LEDGER": str(empty)},
                                capture_output=True, text=True, timeout=30)
        self.assertEqual((result.returncode, result.stdout), (1, ""))
        # a stale WGEX_GATE_LEDGER path that does not exist is never created by a step
        stale = self.work / "stale-ledger"
        subprocess.run(self.GATE_STEP + ["fixture/x", "python3", "-I", "-c", "pass"], env=os.environ | {"WGEX_GATE_LEDGER": str(stale)},
                       capture_output=True, timeout=30, check=True)
        self.assertFalse(stale.exists())
        # the documented rule accepts what a real run prints
        passed = run("inner")
        self.assertTrue(self.gate_result_accepted(passed.returncode, passed.stdout + passed.stderr, "inner", "fixture/"))
        self.assertFalse(self.gate_result_accepted(0, "inner: passed (2 gate steps, all exit=0)\n", "inner", "fixture/"))
        self.assertFalse(self.gate_result_accepted(0, "", "inner", "fixture/"))

    def test_gate_entry_names_the_verdict_changing_opt_outs_it_keeps(self):
        """M1-10x fix 1 item 8 (VERIFY-B N1): a step that passes WGEX_OFFLINE on prints one names-only `kept from caller:` line; a clean caller gets none."""
        for arguments, label in ((["fixture"], "fixture"), (["--enter"], "enter")):
            env = os.environ | {"WGEX_OFFLINE": "canary-offline-not-printed", "WGEX_GO_RACE_COUNT": "1"}
            result = subprocess.run(self.GATE_STEP + arguments + ["python3", "-I", "-c", "pass"], env=env, capture_output=True,
                                    text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            kept = [line for line in result.stderr.splitlines() if "kept from caller" in line]
            self.assertEqual(kept, [f"gate-entry: {label} kept from caller: WGEX_OFFLINE"])
            self.assertNotIn("canary", result.stderr)
            clean = subprocess.run(self.GATE_STEP + arguments + ["python3", "-I", "-c", "pass"], env=os.environ,
                                   capture_output=True, text=True, timeout=30)
            self.assertNotIn("kept from caller", clean.stderr)
        self.assertLessEqual({"WGEX_OFFLINE"}, knobs.VERDICT_WGEX_NAMES)

    def prose_tree(self, name):
        """(tree, script, terms): a scratch git repository holding the public-prose check and a tracked doc.md whose second
        line is denylisted term #1 (read from the denylist, never printed)."""
        terms = [line for line in (ROOT / "Tools/lint/public-prose-denylist.txt").read_text().splitlines()
                 if line and not line.startswith("#")]
        tree = self.work / name
        for source in ("Tools/lint/check-public-prose.sh",):
            (tree / source).parent.mkdir(parents=True, exist_ok=True)
            self.copy_source(ROOT / source, tree / source)
        for source in ("prose-report.py", "public-prose-denylist.txt"):
            shutil.copy(ROOT / "Tools/lint" / source, tree / "Tools/lint" / source)
        (tree / "doc.md").write_text("clean\n" + terms[0] + "\n")
        for arguments in (["init", "-q"], ["add", "-A"]):
            subprocess.run(["git", "-C", str(tree), *arguments], env=os.environ, capture_output=True, text=True, check=True,
                           timeout=60)
        return tree, str(tree / "Tools/lint/check-public-prose.sh"), terms

    def test_git_repository_selectors_cannot_blind_the_gate(self):
        """M1-10x fix 1 item 3 (VERIFY-B M2): GIT_INDEX_FILE or GIT_DIR pointing at an empty index or repository made
        repo_files list nothing, so the public-prose check passed on a tracked file with a denylisted term. Gate entry and the
        self-test strip the repository selectors; since fix 3 they strip every GIT_* name, GIT_OPTIONAL_LOCKS included
        (Config/Scripts/lib.sh sets it again after entry)."""
        tree, script, terms = self.prose_tree("git-selector-tree")
        empty = self.work / "git-empty"
        subprocess.run(["git", "init", "-q", str(empty)], check=True, env=os.environ, timeout=60)
        hostile = {"GIT_INDEX_FILE": str(self.work / "no-such-index"), "GIT_DIR": str(empty / ".git"),
                   "GIT_WORK_TREE": str(empty), "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.quotepath",
                   "GIT_CONFIG_VALUE_0": "false", "GIT_LITERAL_PATHSPECS": "1", "GIT_NAMESPACE": "canary-ns"}
        for name, extra in [("control", {})] + [(name, {name: value}) for name, value in hostile.items()] + [("all", hostile)]:
            result = subprocess.run(self.GATE_STEP + ["probe/prose", "bash", script], cwd=tree, env=os.environ | extra,
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 1, (name, result.stdout, result.stderr))
            self.assertRegex(result.stderr, r"denylisted term #1: .*doc\.md")
            self.assertNotIn(terms[0], result.stdout + result.stderr)
            if extra:
                self.assertIn(f"gate-entry: probe/prose dropped {len(extra)} inherited variables\n", result.stderr)
        result = subprocess.run(self.GATE_STEP + ["probe/env", "python3", "-I", "-c", self.PRINT_ENVIRONMENT],
                                env=os.environ | {"GIT_OPTIONAL_LOCKS": "0", "GIT_DIR": "x"}, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("GIT_OPTIONAL_LOCKS", json.loads(result.stdout))
        self.assertNotIn("GIT_DIR", json.loads(result.stdout))
        for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY",
                     "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_EXEC_PATH", "GIT_CONFIG", "GIT_CONFIG_GLOBAL",
                     "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_7", "GIT_CONFIG_VALUE_7",
                     "GIT_CONFIG_PARAMETERS", "GIT_OPTIONAL_LOCKS"):
            self.assertEqual(knobs.dropped({name: "x"}), [name])

    def test_xdg_config_home_cannot_run_a_git_hook_or_blind_the_gate(self):
        """M1-10x fix 2 item 1 (FIX1-VERIFY F1): git reads $XDG_CONFIG_HOME/git/config as global configuration, the same
        channel as GIT_CONFIG_GLOBAL. A core.fsmonitor hook there ran inside the prose step, deleted the planted line and turned
        rc 1 into "check-public-prose: ok". Gate entry and the self-test now strip XDG_CONFIG_HOME (knobs.TOOL_KNOB_NAMES)."""
        tree, script, terms = self.prose_tree("xdg-config-tree")
        planted = (tree / "doc.md").read_text()
        xdg, hits = self.work / "xdg-config", self.work / "xdg-hook-hits"
        (xdg / "git").mkdir(parents=True)
        hook = self.work / "xdg-fsmonitor-hook"
        hook.write_text(f'#!/bin/sh\necho ran >>"{hits}"\n/usr/bin/sed -i "" "\\$d" "{tree / "doc.md"}"\nexit 1\n')
        hook.chmod(0o755)
        (xdg / "git/config").write_text(f"[core]\n\tfsmonitor = {hook}\n")
        # control: the input is live when nothing strips it (the hook runs and the check passes on the planted term)
        result = subprocess.run(["bash", script], cwd=tree, env=os.environ | {"XDG_CONFIG_HOME": str(xdg)},
                                capture_output=True, text=True, timeout=60)
        self.assertTrue(hits.exists(), (result.stdout, result.stderr))
        self.assertEqual((result.returncode, result.stdout.strip()), (0, "check-public-prose: ok"), result.stderr)
        hits.unlink()
        (tree / "doc.md").write_text(planted)
        # through the gate entry: the hook never runs, the file is untouched and the step fails on the planted term
        result = subprocess.run(self.GATE_STEP + ["probe/prose", "bash", script], cwd=tree,
                                env=os.environ | {"XDG_CONFIG_HOME": str(xdg)}, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 1, (result.stdout, result.stderr))
        self.assertFalse(hits.exists(), result.stderr)
        self.assertEqual((tree / "doc.md").read_text(), planted)
        self.assertRegex(result.stderr, r"denylisted term #1: .*doc\.md")
        self.assertIn("gate-entry: probe/prose dropped 1 inherited variables\n", result.stderr)
        self.assertIn("gate-step: probe/prose exit=1 ", result.stderr)
        self.assertNotIn(terms[0], result.stdout + result.stderr)
        # the self-test drops it too (one list); even the value every login shell here exports ($HOME/.config, which
        # ~/.config/wgex/env.zsh sets and git uses by default) is dropped and counted, since the list has no per-value
        # exceptions: a nested `zsh -lc` step gets it back from env.zsh (the routing test below shows it)
        self.assertFalse(knobs.allowed("XDG_CONFIG_HOME"))
        self.assertEqual(restrict_to_allowlist({"XDG_CONFIG_HOME": str(xdg), "HOME": "/h"}), ["XDG_CONFIG_HOME"])
        default = {"XDG_CONFIG_HOME": "/h/.config", "HOME": "/h"}
        self.assertEqual((restrict_to_allowlist(default), default), (["XDG_CONFIG_HOME"], {"HOME": "/h"}))
        result = subprocess.run(self.GATE_STEP + ["probe/env", "python3", "-I", "-c", self.PRINT_ENVIRONMENT],
                                env=os.environ | {"XDG_CONFIG_HOME": os.environ["HOME"] + "/.config"}, capture_output=True,
                                text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("XDG_CONFIG_HOME", json.loads(result.stdout))
        self.assertIn("gate-entry: probe/env dropped 1 inherited variables\n", result.stderr)
        # the other XDG_* base directories go the same way: env.zsh sets them again for every login-shell step
        for name in ("XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CONFIG_DIRS", "XDG_DATA_DIRS", "XDG_RUNTIME_DIR"):
            self.assertEqual(knobs.dropped({name: "x"}), [name], name)

    def test_home_and_path_are_trusted_inputs_passed_through_unchanged(self):
        """M1-10x fix 2 item 2 (FIX1-VERIFY F2, decision of 1 Nov 2026): HOME and PATH are trusted inputs of the gate.
        The rule and its reason are at the top of the keep list in Config/Scripts/knobs.py and in CONTRIBUTING.md's gate
        section; this test pins it, so changing it means changing the rule, the documents and this test together."""
        self.assertEqual(knobs.TRUSTED_NAMES, frozenset({"HOME", "PATH"}))
        for name in sorted(knobs.TRUSTED_NAMES):
            self.assertEqual(knobs.dropped({name: "x"}), [], name)
            self.assertIn(name, knobs.GATE_ALLOWED_NAMES)
            self.assertNotIn(name, knobs.KNOB_NAMES | knobs.TOOL_KNOB_NAMES)
            self.assertFalse(name.startswith(knobs.KNOB_PREFIXES + knobs.TOOL_KNOB_PREFIXES), name)
        self.assertIn("HOME and PATH are trusted inputs of the gate", (ROOT / "Config/Scripts/knobs.py").read_text())
        self.assertIn("HOME and PATH are trusted inputs of the gate", " ".join((ROOT / "CONTRIBUTING.md").read_text().split()))
        home = self.work / "caller-home"
        home.mkdir()
        show = 'import json, os; print(json.dumps([os.environ.get("HOME"), os.environ.get("PATH")]))'
        for arguments in (["probe/home"], ["--enter"]):
            result = subprocess.run(self.GATE_STEP + arguments + ["python3", "-I", "-c", show],
                                    env=os.environ | {"HOME": str(home)}, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), [str(home), os.environ["PATH"]])
            self.assertNotIn("dropped", result.stderr)

    def test_every_caller_git_variable_is_stripped_at_gate_entry(self):
        """M1-10x fix 3 item 1 (FIX2-VERIFY G1): git honours GIT_TEST_FSMONITOR=<program> in the production build, like
        core.fsmonitor. The hook ran inside the prose step, restored the clean file and turned rc 1 into
        "check-public-prose: ok". Gate entry and the self-test now strip every GIT_* name (the GIT_ prefix; the keep list is
        empty, knobs.py). Two more formerly kept names are probed with live inputs of their own: GIT_EXTERNAL_DIFF (a program
        `git diff` runs) and GIT_TEMPLATE_DIR (files `git init` copies into a new repository)."""
        tree, script, terms = self.prose_tree("git-test-fsmonitor-tree")
        planted = (tree / "doc.md").read_text()
        hits, hook = self.work / "git-fsmonitor-hits", self.work / "git-fsmonitor-hook"
        hook.write_text(f'#!/bin/sh\necho ran >>"{hits}"\nprintf "clean\\n" >"{tree / "doc.md"}"\nexit 1\n')
        hook.chmod(0o755)
        fsmonitor = {"GIT_TEST_FSMONITOR": str(hook)}
        # control: the input is live when nothing strips it (the hook runs, removes the term, and the check passes)
        result = subprocess.run(["bash", script], cwd=tree, env=os.environ | fsmonitor, capture_output=True, text=True,
                                timeout=60)
        self.assertTrue(hits.exists(), (result.stdout, result.stderr))
        self.assertEqual((result.returncode, result.stdout.strip()), (0, "check-public-prose: ok"), result.stderr)
        hits.unlink()
        (tree / "doc.md").write_text(planted)
        # through the gate entry: the hook never runs, the file is untouched and the step fails on the planted term
        result = subprocess.run(self.GATE_STEP + ["probe/prose", "bash", script], cwd=tree, env=os.environ | fsmonitor,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 1, (result.stdout, result.stderr))
        self.assertFalse(hits.exists(), result.stderr)
        self.assertEqual((tree / "doc.md").read_text(), planted)
        self.assertRegex(result.stderr, r"denylisted term #1: .*doc\.md")
        self.assertIn("gate-entry: probe/prose dropped 1 inherited variables\n", result.stderr)
        self.assertIn("gate-step: probe/prose exit=1 ", result.stderr)
        self.assertNotIn(terms[0], result.stdout + result.stderr)
        # GIT_EXTERNAL_DIFF: a program `git diff` runs in place of its own diff
        repo = self.work / "git-diff-repo"
        repo.mkdir()
        (repo / "file.txt").write_text("one\n")
        for arguments in (["init", "-q"], ["add", "file.txt"]):
            subprocess.run(["git", "-C", str(repo), *arguments], env=os.environ, capture_output=True, check=True, timeout=60)
        (repo / "file.txt").write_text("two\n")
        diff_hits, diff_hook = self.work / "git-external-diff-hits", self.work / "git-external-diff-hook"
        diff_hook.write_text(f'#!/bin/sh\necho ran >>"{diff_hits}"\n')
        diff_hook.chmod(0o755)
        external = {"GIT_EXTERNAL_DIFF": str(diff_hook)}
        diff = ["git", "-C", str(repo), "diff"]
        result = subprocess.run(diff, env=os.environ | external, capture_output=True, text=True, timeout=60)
        self.assertTrue(diff_hits.exists(), result.stderr)  # control: live
        diff_hits.unlink()
        result = subprocess.run(self.GATE_STEP + ["probe/diff"] + diff, env=os.environ | external, capture_output=True,
                                text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(diff_hits.exists(), result.stderr)
        self.assertIn("+two", result.stdout)  # git's own diff ran
        self.assertIn("gate-entry: probe/diff dropped 1 inherited variables\n", result.stderr)
        # GIT_TEMPLATE_DIR: files `git init` copies into every new repository
        template = self.work / "git-template"
        (template / "info").mkdir(parents=True)
        (template / "info/wgex-template-canary").write_text("canary\n")
        templated = {"GIT_TEMPLATE_DIR": str(template)}
        control_repo, gate_repo = self.work / "git-template-control", self.work / "git-template-gate"
        result = subprocess.run(["git", "init", "-q", str(control_repo)], env=os.environ | templated, capture_output=True,
                                text=True, timeout=60)
        self.assertTrue((control_repo / ".git/info/wgex-template-canary").exists(), result.stderr)  # control: live
        result = subprocess.run(self.GATE_STEP + ["probe/init", "git", "init", "-q", str(gate_repo)],
                                env=os.environ | templated, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((gate_repo / ".git").is_dir(), result.stderr)
        self.assertFalse((gate_repo / ".git/info/wgex-template-canary").exists(), result.stderr)
        self.assertIn("gate-entry: probe/init dropped 1 inherited variables\n", result.stderr)
        # the rule is the prefix: a name no list holds, as a newer git may add, is stripped too, by the self-test as well
        self.assertIn("GIT_", knobs.TOOL_KNOB_PREFIXES)
        for name in ("GIT_A_NAME_A_NEWER_GIT_ADDS", "GIT_ATTR_SOURCE", "GIT_SHALLOW_FILE", "GIT_TRACE", "GIT_SSH_COMMAND"):
            self.assertEqual(knobs.dropped({name: "x"}), [name])
            self.assertEqual(restrict_to_allowlist({name: "x"}), [name])
        # no keep list: GIT_OPTIONAL_LOCKS is stripped and named, and Config/Scripts/lib.sh sets it again after entry
        show = f'source "{ROOT / "Config/Scripts/lib.sh"}"; printf "%s" "$GIT_OPTIONAL_LOCKS"'
        result = subprocess.run(self.GATE_STEP + ["probe/locks", "bash", "-c", show], env=os.environ | {"GIT_OPTIONAL_LOCKS": "1"},
                                capture_output=True, text=True, timeout=60)
        self.assertEqual((result.returncode, result.stdout), (0, "0"), result.stderr)
        self.assertIn("gate-entry: probe/locks dropped 1 inherited variables\n", result.stderr)
        # GIT_EDITOR: dropped at any value, the harness's `true` included (counted like any other name; no per-value exception)
        for value in ("true", "canary-editor-not-printed"):
            result = subprocess.run(self.GATE_STEP + ["probe/editor", "python3", "-I", "-c", self.PRINT_ENVIRONMENT],
                                    env=os.environ | {"GIT_EDITOR": value}, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("GIT_EDITOR", json.loads(result.stdout))
            self.assertIn("gate-entry: probe/editor dropped 1 inherited variables\n", result.stderr)
            self.assertNotIn("canary-editor-not-printed", result.stderr)
            self.assertEqual(restrict_to_allowlist({"GIT_EDITOR": value}), ["GIT_EDITOR"])

    def test_configuration_file_redirects_of_xcodebuild_go_and_swiftpm_are_dropped(self):
        """M1-10x fix 3 item 2 (FIX2-VERIFY G2): XCODE_XCCONFIG_FILE (xcodebuild loads that file above every other setting),
        GOENV (the go environment file) and SWIFTPM_MIRROR_CONFIG (SwiftPM's dependency mirror table) each point one tool at
        a configuration file outside the repository. Since M1-44 they are dropped with everything else off the allowlist, which
        also drops the toolchain selectors FIX3 left out of the class. xcodebuild runs in its own tests; here `go env CC`, which
        only reads the file, shows a GOENV value live without the gate entry and dead through it."""
        redirects = self.work / "config-redirects"
        redirects.mkdir()
        (redirects / "canary.xcconfig").write_text("OTHER_SWIFT_FLAGS = $(inherited) -wgex-canary-unknown-flag\n")
        (redirects / "goenv").write_text("CC=/wgex-canary-cc-not-printed\n")
        (redirects / "mirrors.json").write_text('{"object": [], "version": 1}\n')
        hostile = {"XCODE_XCCONFIG_FILE": str(redirects / "canary.xcconfig"), "GOENV": str(redirects / "goenv"),
                   "SWIFTPM_MIRROR_CONFIG": str(redirects / "mirrors.json")}
        for arguments in (["probe/env"], ["--enter"]):
            result = subprocess.run(self.GATE_STEP + arguments + ["python3", "-I", "-c", self.PRINT_ENVIRONMENT],
                                    env=os.environ | hostile, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            seen = set(json.loads(result.stdout))
            for name in hostile:
                self.assertNotIn(name, seen)
            label = "probe/env" if arguments == ["probe/env"] else "enter"
            shown = "" if label == "probe/env" else ": GOENV, SWIFTPM_MIRROR_CONFIG, XCODE_XCCONFIG_FILE"
            self.assertEqual([line for line in result.stderr.splitlines() if "dropped" in line],
                             [f"gate-entry: {label} dropped 3 inherited variables{shown}"])
            self.assertNotIn(str(redirects), result.stdout + result.stderr)
        self.assertEqual(restrict_to_allowlist(dict(hostile)), sorted(hostile))
        # GOENV is live without the gate entry and dead through it (go env reads the file and runs nothing)
        base = {name: value for name, value in os.environ.items() if name not in ("CC", "GOENV")} | {"GOTOOLCHAIN": "local"}
        control = subprocess.run(["go", "env", "CC"], cwd=redirects, env=base | {"GOENV": hostile["GOENV"]},
                                 capture_output=True, text=True, timeout=60)
        self.assertEqual((control.returncode, control.stdout.strip()), (0, "/wgex-canary-cc-not-printed"), control.stderr)
        gated = subprocess.run(self.GATE_STEP + ["probe/goenv", "go", "env", "CC"], cwd=redirects,
                               env=base | {"GOENV": hostile["GOENV"]}, capture_output=True, text=True, timeout=60)
        self.assertEqual(gated.returncode, 0, gated.stderr)
        self.assertNotIn("wgex-canary-cc", gated.stdout + gated.stderr)
        self.assertIn("gate-entry: probe/goenv dropped 1 inherited variables\n", gated.stderr)
        # toolchain selectors are dropped now (M1-44), except the wrapper's own Go variables, which are on the list
        for name in ("DEVELOPER_DIR", "TOOLCHAINS", "SDKROOT", "GOROOT", "GOFLAGS", "CC", "CGO_ENABLED", "CGO_CFLAGS",
                     "SWIFT_EXEC"):
            self.assertEqual(knobs.dropped({name: "x"}), [name], name)
        for name in ("GOPROXY", "GOTOOLCHAIN", "GOSUMDB", "GOVULNDB"):
            self.assertEqual(knobs.dropped({name: "x"}), [], name)
        self.assertEqual(knobs.CONFIG_REDIRECT_NAMES, frozenset(hostile))

    def test_a_ledger_path_must_be_absolute_and_inside_tmpdir(self):
        """M1-10x fix 2 item 4 (FIX1-VERIFY L2): check and check-full take the ledger as an exported recipe parameter, so
        `just check lint` made `lint` the ledger: a relative file at the repository root, and lint never ran. --enter now
        refuses a ledger path that is relative or outside $TMPDIR, with a named error and status 2, and creates nothing."""
        dry = subprocess.run(["just", "--dry-run", "check", "lint"], cwd=ROOT, capture_output=True, text=True, timeout=60)
        self.assertEqual(dry.returncode, 0, dry.stderr)
        self.assertRegex(dry.stdout + dry.stderr, r"timed-step\.py --enter\n")
        self.assertRegex(dry.stdout + dry.stderr, r"timed-step\.py --done check\n")
        self.assertNotIn("Tools/lint/lint.sh", dry.stdout + dry.stderr)  # `lint` is the ledger argument, not a recipe
        enter = self.GATE_STEP + ["--enter"]
        tmp = Path(os.environ["TMPDIR"])
        outside, escape = Path("/tmp") / f"wgex-ledger-outside-{os.getpid()}", tmp.parent / f"wgex-ledger-escape-{os.getpid()}"
        for path in (outside, escape):  # only created if the refusal regressed
            self.addCleanup(lambda path=path: path.unlink(missing_ok=True))
        messages = set()
        for ledger in ("lint", "relative/ledger", str(outside), str(tmp / ".." / escape.name)):
            result = subprocess.run(enter, cwd=self.work, env=os.environ | {"WGEX_GATE_LEDGER": ledger}, capture_output=True,
                                    text=True, timeout=30)
            self.assertEqual(result.returncode, 2, (ledger, result.stderr))
            self.assertTrue(result.stderr.startswith("gate-entry: refused: WGEX_GATE_LEDGER is not an absolute path inside "
                                                     "$TMPDIR"), result.stderr)
            messages.add(result.stderr)
        self.assertEqual(len(messages), 1)  # one fixed line: the path itself is never echoed
        self.assertEqual(sorted(path.name for path in self.work.iterdir()), [])
        self.assertFalse(outside.exists())
        self.assertFalse(escape.exists())
        # through a recipe with the real header and first line: `RECIPE lint` stops at the first line and creates no file
        header, first, last = (line.replace("Config/Scripts/", f"{ROOT}/Config/Scripts/")
                               for line in self.gate_recipe_lines("check"))  # run from the scratch directory
        scratch, ledgers = self.work / "ledger-argument", self.work / "ledger-argument-tmp"
        scratch.mkdir()
        ledgers.mkdir()
        guard = scratch / "Config/Scripts/knobs.py"
        guard.parent.mkdir(parents=True)
        shutil.copy(ROOT / "Config/Scripts/knobs.py", guard)
        (scratch / "justfile").write_text(re.search(r"^set shell := .*$", (ROOT / "justfile").read_text(), re.M).group(0) +
                                          f"\ngate {header}:\n{first}\n    echo step-ran\n{last.replace('--done check', '--done gate')}\n")
        result = subprocess.run(["just", "--justfile", str(scratch / "justfile"), "--working-directory", str(scratch), "gate",
                                 "lint"], cwd=scratch, env=os.environ | {"TMPDIR": str(ledgers)}, capture_output=True, text=True,
                                timeout=60)
        self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
        self.assertIn("gate-entry: refused: WGEX_GATE_LEDGER is not an absolute path inside $TMPDIR", result.stderr)
        self.assertNotIn("step-ran", result.stdout)
        self.assertFalse((scratch / "lint").exists())
        self.assertFalse((ROOT / "lint").exists())
        # the recipe's own default (an absolute path under $TMPDIR) still starts and passes
        result = subprocess.run(["just", "--justfile", str(scratch / "justfile"), "--working-directory", str(scratch), "gate"],
                                cwd=scratch, env=os.environ | {"TMPDIR": str(ledgers)}, capture_output=True, text=True,
                                timeout=60)
        self.assertEqual(result.returncode, 1, (result.stdout, result.stderr))  # no gate step ran, so --done fails
        self.assertIn("step-ran", result.stdout)
        self.assertIn("gate-entry: gate: 0 gate steps recorded", result.stderr)

    def test_done_fails_on_any_failed_or_malformed_ledger_record(self):
        """M1-10x fix 2 item 5 (FIX1-VERIFY L3): just stops at the first failing line today, so --done never sees a failed
        record; this is the defence in depth for when that changes. A failed or malformed record fails --done, prints no
        `passed` line and keeps the ledger; a mutant that only checks for an empty ledger is killed here."""
        for name, records in (("failed-step", ["fixture/one 0", "fixture/two 3", "fixture/three 0"]),
                              ("malformed", ["fixture/one 0", "fixture/two"]),
                              ("signal", ["fixture/one 0", "fixture/two 137"])):
            ledger = self.work / f"done-{name}"
            env = os.environ | {"WGEX_GATE_LEDGER": str(ledger)}
            self.assertEqual(subprocess.run(self.GATE_STEP + ["--enter"], env=env, capture_output=True, timeout=30).returncode, 0)
            ledger.write_text("".join(record + "\n" for record in records))
            result = subprocess.run(self.GATE_STEP + ["--done", "check"], env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual((result.returncode, result.stdout), (1, ""), (name, result.stderr))
            self.assertIn(f"gate-entry: check: {len(records)} gate steps recorded, failed: fixture/two", result.stderr)
            self.assertTrue(ledger.exists(), name)
        # the same through real steps: a failing step's record fails --done even if the recipe carried on
        ledger = self.work / "done-real-steps"
        env = os.environ | {"WGEX_GATE_LEDGER": str(ledger)}
        subprocess.run(self.GATE_STEP + ["--enter"], env=env, check=True, capture_output=True, timeout=30)
        for label, code in (("fixture/ok", 0), ("fixture/bad", 5)):
            subprocess.run(self.GATE_STEP + [label, "python3", "-I", "-c", f"raise SystemExit({code})"], env=env,
                           capture_output=True, timeout=30)
        result = subprocess.run(self.GATE_STEP + ["--done", "check"], env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual((result.returncode, result.stdout), (1, ""), result.stderr)
        self.assertIn("2 gate steps recorded, failed: fixture/bad", result.stderr)

    def test_knobs_module_states_the_allowlist_and_keeps_a_reason_for_every_corpus_entry(self):
        """M1-44 and M1-10x: knobs.py states the allowlist, what it leaves to env.zsh and what it breaks, and keeps a reason
        line for each corpus entry (each zsh name, each named tool knob, the GIT_ prefix) the self-test still builds
        polluted callers from."""
        text = (ROOT / "Config/Scripts/knobs.py").read_text()
        for phrase in ("Gate entry is an allowlist", "The list (GATE_ALLOWED_NAMES", "GOFLAGS is not on the list",
                       "What the list leaves to env.zsh", "What it breaks, on purpose", "Trusted inputs (TRUSTED_NAMES",
                       "Nothing strips by it any more", "Corpus:"):
            self.assertIn(phrase, text)
        for name in sorted(knobs.ZSH_KNOB_NAMES - {"CDPATH", "TMOUT"}) + sorted(knobs.TOOL_KNOB_NAMES) + ["GIT_TEST_FSMONITOR"]:
            self.assertIn(name, text, name)
        for name in sorted(knobs.CONFIG_REDIRECT_NAMES | {"XDG_CONFIG_HOME", "GIT_OPTIONAL_LOCKS"}):
            self.assertRegex(text, rf"\n  {name} +\S", name)  # a reason line of its own
        self.assertIn("every GIT_* variable is hostile, not a list of names", text)
        for name in ("ROUTED_DEFAULTS", "INERT_VALUES", "KNOB_EXEMPT", "GATE_KEPT_PREFIXES"):
            self.assertNotIn(name, text, name)  # the per-value and per-prefix exceptions of the strip list are gone

    def process_ancestors(self, pid):
        """pids from pid's parent up to (not including) 1, by ps."""
        found = []
        for _ in range(8):
            out = subprocess.run(["ps", "-o", "ppid=", "-p", str(pid)], capture_output=True, text=True, timeout=10).stdout.strip()
            if not out or int(out) <= 1:
                break
            pid = int(out)
            found.append(pid)
        return found

    def with_deadline_driver(self, body, extra_env=None, secs=60):
        """Popen a bash driver that sources lib.sh and runs `with_deadline <secs> bash -c <body>` in a $(...) and prints its
        status; returns (process, pid files dict). The command writes $PPID (the wrapper perl), its own pid and a forked sleep's."""
        stamp = time.monotonic_ns()
        files = {name: self.work / f"wd-{name}-{stamp}" for name in ("perl", "command", "child")}
        script = (f'source "{ROOT / "Config/Scripts/lib.sh"}"\nstatus=0\n'
                  f'out="$(with_deadline {secs} bash -c \'{body}\' x "{files["perl"]}" "{files["command"]}" "{files["child"]}")" || status=$?\n'
                  'echo "status=$status"')
        process = subprocess.Popen(["bash", "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   env=os.environ | (extra_env or {}))
        self.addCleanup(lambda: process.poll() is None and process.kill())
        for name in ("command", "child"):  # processes this test's own commands recorded; never pid 0 or 1 (a group or init)
            self.addCleanup(self.kill_recorded, files[name])
        return process, files

    def kill_recorded(self, path):
        text = path.read_text().strip() if path.exists() else ""
        if text.isdigit() and int(text) > 1 and self.alive(int(text)):
            os.kill(int(text), 9)

    def wait_for_pids(self, process, files, names=("perl", "command", "child"), limit=60):
        deadline = time.monotonic() + limit
        while time.monotonic() < deadline and process.poll() is None:
            if all(files[name].exists() and files[name].read_text().strip().isdigit() for name in names):
                return {name: int(files[name].read_text()) for name in names}
            time.sleep(0.05)
        self.fail("the driver never recorded its pids")

    def wait_dead(self, pid, limit):
        deadline = time.monotonic() + limit
        while time.monotonic() < deadline:
            if not self.alive(pid):
                return True
            time.sleep(0.1)
        return not self.alive(pid)

    WD_BODY = 'echo $PPID >"$1"; echo $$ >"$2"; sleep 40 & echo $! >"$3"; wait'

    def test_with_deadline_signal_handlers_kill_the_group_and_report_the_signal(self):
        """M1-10x fix 1 item 5 (VERIFY-B L4, mutant M7c): HUP, INT and TERM sent to the wrapper kill the command's whole
        process group (the forked sleep too) and give 129, 130 and 143; each by the pid the command recorded as its parent,
        checked to descend from this test's own driver before it is signalled."""
        for signal_number, expected in ((1, 129), (2, 130), (15, 143)):
            process, files = self.with_deadline_driver(self.WD_BODY)
            pids = self.wait_for_pids(process, files)
            self.assertIn(process.pid, self.process_ancestors(pids["perl"]), "the wrapper is not this test's descendant")
            os.kill(pids["perl"], signal_number)
            output, _ = process.communicate(timeout=30)
            self.assertEqual(output.strip(), f"status={expected}", signal_number)
            self.assertTrue(self.wait_dead(pids["child"], 10), f"signal {signal_number}: the forked sleep outlived the wrapper")
            self.assertTrue(self.wait_dead(pids["command"], 10), f"signal {signal_number}: the command outlived the wrapper")

    def test_with_deadline_command_keeps_its_own_deadline_when_the_wrapper_is_killed(self):
        """M1-10x fix 1 item 5 (VERIFY-B L1): after SIGKILL of the wrapper the command still dies at its deadline (its own
        alarm, set before exec). Leave time for a loaded host's handshake and deliberately delay the kill."""
        secs = 30
        process, files = self.with_deadline_driver('echo $PPID >"$1"; echo $$ >"$2"; echo $$ >"$3"; exec sleep 120', secs=secs)
        pids = self.wait_for_pids(process, files, limit=15)
        time.sleep(3)  # used to exceed the wrapper's old 2s alarm, even on an idle host
        self.assertIn(process.pid, self.process_ancestors(pids["perl"]),
                      "wrapper exited before the kill or is no longer this driver's descendant; raise secs")
        started = time.monotonic()
        try:
            os.kill(pids["perl"], signal.SIGKILL)
        except ProcessLookupError:
            self.fail(f"wrapper exited before the kill; raise the {secs}s handshake budget")
        # The command's own alarm is secs+1 from launch; allow 10s scheduling margin after the kill.
        self.assertTrue(self.wait_dead(pids["command"], secs + 11), "the command ran past its deadline with no wrapper")
        self.assertLess(time.monotonic() - started, secs + 11)
        process.communicate(timeout=30)

    def test_with_deadline_child_enters_its_own_process_group_before_the_parent_can_do_it(self):
        """M1-10x fix 1 item 5 (VERIFY-B L4, mutant M7b): the child's own setpgid is what puts the command in a group of its
        own when the parent is slow. A PERL5OPT module delays the parent's setpgid($pid, $pid) by 1.5 s (the child's
        setpgid(0, 0) is untouched); the command must already lead its group when it runs. Without the child-side call it
        shares the caller's group for those 1.5 s. The elapsed time proves the delay was applied."""
        hook = self.work / "perl-hook"
        hook.mkdir()
        (hook / "DelayParentSetpgid.pm").write_text(
            "package DelayParentSetpgid; use POSIX (); no warnings 'redefine';\n"
            "my $real = \\&POSIX::setpgid;\n"
            "*POSIX::setpgid = sub { select(undef, undef, undef, 1.5) if $_[0] != 0; $real->(@_) };\n1;\n")
        script = (f'source "{ROOT / "Config/Scripts/lib.sh"}"\n'
                  "with_deadline 30 bash -c 'echo \"$$ $(ps -o pgid= -p $$ | tr -d \" \")\"'")
        started = time.monotonic()
        result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60,
                                env=os.environ | {"PERL5OPT": f"-I{hook} -MDelayParentSetpgid"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertGreaterEqual(time.monotonic() - started, 1.4, "the parent delay was not applied; the test proves nothing")
        pid, group = result.stdout.split()
        self.assertEqual(pid, group, "the command was not the leader of its own process group while the parent was slow")

    def test_full_gate_has_hosted_ios_fresh_race_and_only_lab_packages(self):
        import re
        result = subprocess.run(["just", "--dry-run", "check-full"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = result.stdout + result.stderr
        self.assertIn("just test ios", commands)
        self.assertIn("WGEX_GO_RACE_COUNT=1", commands)
        packages = re.findall(r"WGEX_LAB_BUILD=1 just test (\w+)", commands)
        self.assertEqual(set(packages), {"WGEXBackendMac", "WGEXProfileStore", "WGEXUI"})


    def test_gate_entry_refuses_inherited_build_variants(self):
        """Both entry forms refuse either build flag by presence, without printing its value or creating a ledger."""
        for name in ("WGEX_OWN_MAC_BUILD", "WGEX_LAB_BUILD"):
            for value in ("1", "0", ""):
                for command in ([], ["python3", "-I", "-c", "raise SystemExit(42)"]):
                    with self.subTest(name=name, value=value, command=bool(command)):
                        ledger = self.work / f"ledger-{name}-{value or 'empty'}-{bool(command)}"
                        result = subprocess.run(self.GATE_STEP + ["--enter"] + command,
                                                env=os.environ | {name: value, "WGEX_GATE_LEDGER": str(ledger)},
                                                capture_output=True, text=True, timeout=30)
                        self.assertEqual(result.returncode, 2, result.stderr)
                        self.assertIn(f"gate-entry: refused: inherited build variant {name}", result.stderr)
                        self.assertFalse(ledger.exists())
        result = subprocess.run(self.GATE_STEP + ["--enter", "python3", "-I", "-c", self.PRINT_ENVIRONMENT],
                                env=os.environ | {"WGEX_UNRELATED": "present", "WGEX_OFFLINE": "1"},
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("WGEX_UNRELATED", json.loads(result.stdout))
        self.assertEqual([line for line in result.stderr.splitlines() if "kept from caller" in line],
                         ["gate-entry: enter kept from caller: WGEX_OFFLINE"])
        self.assertEqual(knobs.VERDICT_WGEX_NAMES, frozenset({"WGEX_OFFLINE"}))
        both = subprocess.run(self.GATE_STEP + ["--enter"],
                              env=os.environ | {"WGEX_LAB_BUILD": "", "WGEX_OWN_MAC_BUILD": ""},
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(both.returncode, 2, both.stderr)
        self.assertIn("WGEX_LAB_BUILD, WGEX_OWN_MAC_BUILD", both.stderr)


    def test_release_link_checks_own_mac_marker_in_both_products(self):
        """Synthetic products exercise both modes and each Mac binary without launching either product."""
        import struct
        marker = "Apple Development: Example Developer (A1B2C3D4E5)"
        bins = self.work / "link-bin"
        bins.mkdir()
        for name, script in {
            "nm": "#!/bin/bash\nprintf '0000000100000000 T _main\\n'\n",
            "xcrun": "#!/bin/bash\n[[ $1 == swift-demangle ]] || exit 99\ncat\n",
            "strings": "#!/bin/bash\n[[ $1 == -a ]] || exit 99\nLC_ALL=C tr -c '[:print:]\\n' '\\n' <\"$2\"\n",
        }.items():
            path = bins / name
            path.write_text(script)
            path.chmod(0o755)
        products = self.work / "link-builds" / ROOT.name / "derived-data/Build/Products/Release/WGEX.app/Contents/MacOS"
        products.mkdir(parents=True)
        header = bytes.fromhex("cffaedfe") + struct.pack("<7I", 0x0100000C, 0, 2, 1, 16, 0, 0)
        command = struct.pack("<IIII", 0x1D, 16, 48, 32)
        signature = (struct.pack(">III", 0xFADE0CC0, 32, 1) + struct.pack(">II", 9, 20)
                     + struct.pack(">II", 0xFADE8181, 16) + bytes(8))
        env = os.environ | {"PATH": f"{bins}:{os.environ['PATH']}", "WGEX_BUILD_ROOT": str(self.work / "link-builds"),
                            "WGEX_OWN_MAC_LEAF": marker}
        for mode, daemon_marker, app_marker, expected in (
            (None, False, False, 0), (None, True, False, 1), (None, False, True, 1),
            ("ordinary", True, True, 1), ("own-mac", True, True, 0), ("own-mac", False, True, 1),
            ("own-mac", True, False, 1), ("own-mac", False, False, 1),
        ):
            with self.subTest(mode=mode, daemon_marker=daemon_marker, app_marker=app_marker):
                (products / "WGEXDaemon").write_bytes(header + command + signature +
                                                       (marker if daemon_marker else "daemon").encode() + b"\n")
                (products / "WGEX").write_text((marker if app_marker else "app") + "\n")
                arguments = ["bash", str(ROOT / "Engine/scripts/check-link.sh"), "--release", "mac"]
                result = subprocess.run(arguments + ([mode] if mode else []),
                                        env=env, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, expected, result.stderr)
                if expected:
                    self.assertIn("own-Mac", result.stderr)
        invalid = subprocess.run(arguments + ["typo"], env=env, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(invalid.returncode, 0)
        self.assertIn("release mode must be ordinary or own-mac", invalid.stderr)
        for platform in ("iphonesimulator", "appletvsimulator"):
            app = products.parents[3] / f"Release-{platform}/WGEX.app/WGEX"
            app.parent.mkdir(parents=True)
            app.write_text("ordinary simulator app\n")
        default = subprocess.run(arguments[:-1], env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(default.returncode, 0, default.stderr)
        (products / "WGEX").write_text(marker + "\n")
        contaminated = subprocess.run(arguments[:-1], env=env, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(contaminated.returncode, 0)
        self.assertIn("ordinary Release contains own-Mac marker", contaminated.stderr)
        if not (ROOT / "Config/Local.xcconfig").exists():
            # Without a configured leaf, an ordinary check still catches any Apple Development leaf name.
            bare = {k: v for k, v in env.items() if k != "WGEX_OWN_MAC_LEAF"}
            fallback = subprocess.run(arguments[:-1], env=bare, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(fallback.returncode, 0)
            self.assertIn("ordinary Release contains own-Mac marker", fallback.stderr)
            refused = subprocess.run(arguments + ["own-mac"], env=bare, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn("needs WGEX_OWN_MAC_LEAF", refused.stderr)
        dry = subprocess.run(["just", "--dry-run", "check-release-link", "mac", "own-mac"], cwd=ROOT,
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(dry.returncode, 0, dry.stderr)
        self.assertIn("--release mac own-mac", dry.stdout + dry.stderr)


    def test_ordinary_recipe_shell_refuses_own_mac_before_running_any_command(self):
        line = re.search(r"^set shell := .*$", (ROOT / "justfile").read_text(), re.M).group(0)
        tree = self.work / "ordinary-recipes"
        guard = tree / "Config/Scripts/knobs.py"
        guard.parent.mkdir(parents=True)
        shutil.copy(ROOT / "Config/Scripts/knobs.py", guard)
        (tree / "justfile").write_text(line + "\nprobe:\n    @exit 42\n")
        for value in ("1", "0", "", "canary-value-not-printed"):
            with self.subTest(value=value):
                result = subprocess.run(["just", "probe"], cwd=tree,
                                        env=os.environ | {"WGEX_OWN_MAC_BUILD": value},
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("inherited build variant WGEX_OWN_MAC_BUILD", result.stderr)
                self.assertNotIn("canary-value", result.stdout + result.stderr)
        ordinary = subprocess.run(["just", "probe"], cwd=tree, env=os.environ,
                                  capture_output=True, text=True, timeout=30)
        self.assertEqual(ordinary.returncode, 42, ordinary.stderr)

    def test_engine_link_guard_rejects_a_source_defined_test_double(self):
        source = ROOT / "Packages/WGEXBackendMac/Sources/WGEXDaemonCoreTesting/FakeEngineResolver.swift"
        self.assertRegex(source.read_text(), r"public actor FakeEngineResolver\b")
        script = ROOT / "Engine/scripts/check-link.sh"
        self.assertNotIn("StubEngineActor", script.read_text())
        bins = self.work / "engine-link-bin"
        bins.mkdir()
        nm = bins / "nm"
        nm.write_text('#!/bin/bash\ncat "$1"\n')
        nm.chmod(0o755)
        base = self.work / "engine-link-builds"
        products = base / ROOT.name / "derived-data/Build/Products"
        hosts = ("Debug/WGEXDaemon", "Debug-iphonesimulator/WGEXTunnel.appex/WGEXTunnel",
                 "Debug-appletvsimulator/WGEXTunnel.appex/WGEXTunnel")
        clients = ("Debug/WGEX.app/Contents/MacOS/WGEX", "Debug/wgex",
                   "Debug-iphonesimulator/WGEX.app/WGEX", "Debug-appletvsimulator/WGEX.app/WGEX")
        engine = "T _wgex_build_info\nT _wgex_create\nT _wgex_destroy\n"
        for name in hosts + clients:
            path = products / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(engine if name in hosts else "T _main\n")
        env = os.environ | {"PATH": f"{bins}:{os.environ['PATH']}", "WGEX_BUILD_ROOT": str(base)}
        command = ["bash", str(script)]
        clean = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(clean.returncode, 0, clean.stderr)
        for name in hosts + clients:
            with self.subTest(product=name):
                path = products / name
                original = path.read_text()
                path.write_text(original + "T _$s21WGEXDaemonCoreTesting18FakeEngineResolverCMa\n")
                rejected = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
                self.assertNotEqual(rejected.returncode, 0, rejected.stdout)
                self.assertIn("FAIL: test double in " + name, rejected.stdout + rejected.stderr)
                path.write_text(original)


class OwnMacReleaseTests(unittest.TestCase):
    """Exercise signing preflight and evidence using synthetic, scratch-only commands."""

    SCRIPT_OVERRIDE = None
    TEAM = "ABCDE12345"
    BASE = "com.magrathean.WGEXApp"
    CN = "Apple Development: Example Developer (A1B2C3D4E5)"
    PROFILE_UUID = "0b9c3a54-6f1e-4d2a-9c7b-5e8d1a2f3c40"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="wgex-own-mac-", dir=os.environ["TMPDIR"],
                                                ignore_cleanup_errors=True)
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.tree = self.work / "tree"
        self.bin = self.work / "bin"
        self.builds = self.work / "builds"
        self.private = self.work / "records/wgex"
        self.private.mkdir(parents=True, mode=0o700)
        self.private_tmp = self.private / "job-tmp"
        self.private_tmp.mkdir(mode=0o700)
        self.output = self.private / "output"
        self.tree.mkdir()
        self.bin.mkdir()
        self.builds.mkdir()
        self.home = self.work / "home"
        self.home.mkdir()
        self.certificate = b"synthetic public certificate for own-Mac tests"
        self.identity = hashlib.sha1(self.certificate).hexdigest().upper()
        self.profile = (self.home / "Library/Developer/Xcode/UserData/Provisioning Profiles" /
                        (self.PROFILE_UUID + ".provisionprofile"))
        self.profile.parent.mkdir(parents=True)
        (self.work / "certificate").write_bytes(self.certificate)
        self.calls = self.work / "calls"
        script = (self.SCRIPT_OVERRIDE or ROOT / "Config/Scripts/build-own-mac.sh").read_text()
        # Keep the caller-selected output path intact; only stand in for the
        # internal volume so the synthetic fixture can live in routed scratch.
        volume = 'Path("/System/Volumes/Data").stat().st_dev'
        self.assertEqual(script.count(volume), 1)
        script = script.replace(volume, 'Path(' + json.dumps(str(self.work)).replace("'", "\\u0027") + ').stat().st_dev', 1)
        self.put("Config/Scripts/build-own-mac.sh", script)
        self.put("Config/Scripts/generate-build-identifiers.sh", "#!/bin/bash\nexit 0\n")
        self.put("Engine/scripts/source-digest.py", "import sys\nsys.exit(0)\n")
        self.put("Engine/scripts/check-link.sh", '#!/bin/bash\nprintf "%s\\n" "$WGEX_BUILD_ROOT" "$@" >"$HOME/../link-call"\n'
                 '[[ ! -e "$HOME/../WGEX_TEST_LINK_FAILURE" ]]\n')
        self.put("Tools/lint/check-entitlements.sh", '#!/bin/bash\ncat >/dev/null\n[[ ! -e "$HOME/../WGEX_TEST_ENT_FAILURE" ]]\n')
        self.put("Config/OwnMacRelease.xcconfig", "// synthetic\n")
        self.put("Config/Local.xcconfig", "WGEX_TEAM = " + self.TEAM + "\nWGEX_OWN_MAC_LEAF = " + self.CN
                 + "\nWGEX_OWN_MAC_PROFILE = " + self.PROFILE_UUID + "\n")
        self.put("project.yml", "name: fixture\n")
        self.write_profile()
        self.env = os.environ | {
            "PATH": str(self.bin) + ":/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(self.home), "TMPDIR": str(self.private_tmp),
            "CLEAN_DEV_MODE": "external", "CLEAN_DEV_BUILDS": str(self.builds), "CODEX_THREAD_ID": "fixture",
            "WGEX_OWN_MAC_OUTPUT_ROOT": str(self.output),
            "WGEX_OWN_MAC_IDENTITY_SHA1": self.identity,
            "WGEX_OWN_MAC_BUILD_NUMBER": "10", "WGEX_TEST_CERT": base64_encode(self.certificate),
            "WGEX_TEST_PROFILE": str(self.profile), "WGEX_TEST_CALLS": str(self.calls),
        }
        self.env.pop("WGEX_BUILD_ROOT", None)
        self.env.pop("CLAUDE_CODE_SESSION_ID", None)
        self.stub("git", '''#!/usr/bin/env python3
import json, os, pathlib, sys
work = pathlib.Path(__file__).resolve().parent.parent
control = json.loads((work / "control.json").read_text())
(work / "git-env.json").write_text(json.dumps({k: v if k in ("CODEX_THREAD_ID", "CLAUDE_CODE_SESSION_ID", "TMPDIR", "DEVCACHE", "WGEX_BUILD_ROOT") or k.startswith(("CLEAN_DEV_", "CLEAN_DEVELOPMENT_")) else "<present>" for k, v in os.environ.items()}))
if control.get("WGEX_TEST_DIRTY"):
    sys.stdout.buffer.write(b" M tracked.txt\\0")
''')
        self.stub("security", '''#!/usr/bin/env python3
import base64, json, os, pathlib, sys
work = pathlib.Path(__file__).resolve().parent.parent
control = json.loads((work / "control.json").read_text())
with (work / "security-calls").open("a") as f: f.write("security\\n")
mode = control.get("WGEX_TEST_SECURITY", "")
args = sys.argv[1:]
if args[0] == "find-identity":
    digest = os.environ["WGEX_OWN_MAC_IDENTITY_SHA1"]
    if mode == "wrong": digest = "0" * 40
    name = "Apple Distribution: Test" if mode == "distribution" else "Apple Development: Example Developer (A1B2C3D4E5)"
    if mode != "missing":
        print(f'  1) {digest} "{name}"')
        if mode == "ambiguous": print(f'  2) {digest} "{name}"')
elif args[0] == "find-certificate":
    print("-----BEGIN CERTIFICATE-----\\n" + base64.b64encode((work / "certificate").read_bytes()).decode() + "\\n-----END CERTIFICATE-----")
elif args[:2] == ["cms", "-D"]:
    if len(args) != 4 or args[2] != "-i" or control.get("WGEX_TEST_NO_PROFILE"):
        sys.exit(1)
    try:
        sys.stdout.buffer.write(open(args[3], "rb").read())
    except OSError:
        sys.exit(1)
else:
    sys.exit(1)
''')
        self.stub("openssl", '''#!/usr/bin/env python3
import json, pathlib
control = json.loads((pathlib.Path(__file__).resolve().parent.parent / "control.json").read_text())
team = "WRONGTEAM1" if control.get("WGEX_TEST_SECURITY") == "wrong-team" else "ABCDE12345"
print("subject=OU=" + team + ",CN=Apple Development: Example Developer (A1B2C3D4E5)")
''')
        self.stub("xcodegen", "#!/bin/bash\nexit 0\n")
        self.stub("xcodebuild", '''#!/usr/bin/env python3
import json, os, pathlib, sys
work = pathlib.Path(__file__).resolve().parent.parent
control = json.loads((work / "control.json").read_text())
with (work / "calls").open("a") as f: f.write("xcodebuild\\n")
(work / "xcode-env.json").write_text(json.dumps({k: v if k in ("WGEX_OWN_MAC_SIGNING", "WGEX_OWN_MAC_BUILD", "CODEX_THREAD_ID", "CLAUDE_CODE_SESSION_ID", "TMPDIR", "DEVCACHE", "WGEX_BUILD_ROOT") or k.startswith(("CLEAN_DEV_", "CLEAN_DEVELOPMENT_")) else "<present>" for k, v in os.environ.items()}))
(work / "xcode-args.json").write_text(json.dumps(sys.argv[1:]))
print("synthetic signing identity " + os.environ["WGEX_OWN_MAC_IDENTITY_SHA1"])
print('    export WGEX_FAKE_CANARY="do-not-log-this-value"')
print('    export WGEX_FAKE_MULTILINE="do-not-log-first')
print('do-not-log-second"')
derived = pathlib.Path(sys.argv[sys.argv.index("-derivedDataPath") + 1])
products = derived / "Build/Products/Release"
for name in ("WGEX.app/Contents/MacOS/WGEX", "WGEX.app/Contents/MacOS/WGEXDaemon",
             "WGEX.app/Contents/Helpers/wgex", "WGEXDaemon", "wgex"):
    path = products / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()
profile = products / "WGEX.app/Contents/embedded.provisionprofile"
data = pathlib.Path(control["WGEX_TEST_PROFILE"]).read_bytes()
if control.get("WGEX_TEST_EMBEDDED") == "different": data += b" "
if control.get("WGEX_TEST_EMBEDDED") == "wrong-uuid":
    import plistlib
    parsed = plistlib.loads(data)
    parsed["UUID"] = "wrong"
    data = plistlib.dumps(parsed)
    pathlib.Path(control["WGEX_TEST_PROFILE"]).write_bytes(data)
profile.write_bytes(data)
for name in ("Logs/Build/synthetic.xcactivitylog", "Build/Intermediates.noindex/XCBuildData/synthetic.db"):
    path = derived / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(os.environ["WGEX_OWN_MAC_IDENTITY_SHA1"])
if control.get("WGEX_TEST_PROMPT"):
    print("errSecInternalComponent: User interaction is not allowed")
    sys.exit(1)
''')
        self.stub("codesign", '''#!/usr/bin/env python3
import hashlib, json, pathlib, plistlib, sys
args = sys.argv[1:]
path = pathlib.Path(args[-1])
base = "com.magrathean.WGEXApp"
identifier = base + (".daemon" if path.name == "WGEXDaemon" else ".cli" if path.name == "wgex" else "")
bad = json.loads((pathlib.Path(__file__).resolve().parent.parent / "control.json").read_text()).get("WGEX_TEST_BAD_SIGNATURE", "")
if "-dv" in args:
    value = hashlib.sha1(str(path).encode()).hexdigest()
    if bad == "identifier": identifier += ".wrong"
    authority = "Wrong Authority" if bad == "authority" else "Apple Development: Example Developer (A1B2C3D4E5)"
    team = "WRONGTEAM1" if bad == "team" else "ABCDE12345"
    flags = "adhoc" if bad == "runtime" else "runtime"
    print("Identifier=" + identifier + "\\nAuthority=" + authority + "\\nTeamIdentifier=" + team + "\\nflags=0x10000(" + flags + ")\\nCDHash=" + value)
    if bad == "timestamp": print("Timestamp=fixture")
elif "-r-" in args:
    suffix = ' and cdhash H"abcd"' if bad == "cdhash" else ''
    if bad == "dr-ou" or (bad == "different-dr" and path.parent.name == "MacOS" and path.name == "WGEXDaemon"):
        suffix += ' and certificate leaf[subject.OU] = "ABCDE12345"'
    if bad == "weak-or": suffix += ' or anchor apple'
    if bad == "weak-id": identifier += ".wrong"
    anchor = "anchor apple" if bad == "weak-anchor" else "anchor apple generic"
    cn = '' if bad == "weak-cn" else ' and certificate leaf[subject.CN] = "Apple Development: Example Developer (A1B2C3D4E5)"'
    wwdr = '' if bad == "weak-wwdr" else ' and certificate 1[field.1.2.840.113635.100.6.2.1] /* exists */'
    print('designated => identifier "' + identifier + '" and ' + anchor + cn + wwdr + suffix)
elif any(arg.startswith("--extract-certificates=") for arg in args):
    prefix = next(arg.split("=", 1)[1] for arg in args if arg.startswith("--extract-certificates="))
    cert = b"wrong certificate" if bad == "wrong-leaf" else (pathlib.Path(__file__).resolve().parent.parent / "certificate").read_bytes()
    pathlib.Path(prefix + "0").write_bytes(cert)
elif "--entitlements" in args:
    ent = {"com.apple.security.get-task-allow": True} if bad == "task" else {}
    sys.stdout.buffer.write(plistlib.dumps(ent))
elif "--verify" in args and (bad == "verify" or (bad == "strict-only" and "--deep" in args) or (bad == "policy-only" and "-R" in args)):
    sys.exit(1)
elif "--verify" not in args:
    sys.exit(1)
''')

    def put(self, name, content):
        path = self.tree / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def stub(self, name, content):
        path = self.bin / name
        path.write_text(content)
        path.chmod(0o755)

    def write_profile(self, **updates):
        appid = self.TEAM + "." + self.BASE
        data = {"Name": "Own Mac Fixture", "UUID": self.PROFILE_UUID, "TeamIdentifier": [self.TEAM],
                "Platform": ["OSX"],
                "ApplicationIdentifierPrefix": [self.TEAM], "ExpirationDate": datetime.datetime(2090, 1, 1),
                "DeveloperCertificates": [self.certificate], "Entitlements": {
                    "application-identifier": appid, "com.apple.developer.team-identifier": self.TEAM,
                    "keychain-access-groups": [self.TEAM + ".*"],
                    "com.apple.security.application-groups": [self.TEAM + ".*"]}}
        data.update(updates)
        self.profile.write_bytes(plistlib.dumps(data))

    def run_recipe(self, *args, extra=None):
        control = {k: v for k, v in (self.env | (extra or {})).items() if k.startswith("WGEX_TEST_")}
        (self.work / "control.json").write_text(json.dumps(control))
        for name in ("WGEX_TEST_LINK_FAILURE", "WGEX_TEST_ENT_FAILURE"):
            marker = self.work / name
            if control.get(name): marker.write_text("1")
            elif marker.exists(): marker.unlink()
        return subprocess.run(["bash", str(self.tree / "Config/Scripts/build-own-mac.sh"), *args], cwd=self.tree,
                              env=self.env | (extra or {}), text=True, capture_output=True, timeout=30)

    def test_output_root_is_required_before_security_or_build(self):
        self.env.pop("WGEX_OWN_MAC_OUTPUT_ROOT")
        for extra in ({}, {"WGEX_OWN_MAC_OUTPUT_ROOT": ""}):
            with self.subTest(extra=extra):
                result = self.run_recipe(extra=extra)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("WGEX_OWN_MAC_OUTPUT_ROOT is required", result.stderr)
                self.assertFalse(self.output.exists())
                self.assertFalse((self.work / "security-calls").exists())
                self.assertFalse(self.calls.exists())

    def test_output_root_selects_products_evidence_and_derived_data(self):
        selected = self.private / "chosen-output"
        result = self.run_recipe("chosen", extra={"WGEX_OWN_MAC_OUTPUT_ROOT": str(selected)})
        self.assertEqual(result.returncode, 0, result.stderr)
        attempt = selected / "chosen"
        args = json.loads((self.work / "xcode-args.json").read_text())
        self.assertEqual(args[args.index("-derivedDataPath") + 1], str(attempt / "derived-data"))
        self.assertTrue((attempt / "derived-data/Build/Products/Release/WGEX.app").is_dir())
        self.assertTrue((attempt / "PASSED").is_file())
        self.assertTrue((attempt / "app.dr").is_file())
        self.assertEqual((self.work / "link-call").read_text().splitlines(),
                         [str(attempt / "link-check"), "--release", "mac", "own-mac"])
        self.assertFalse(self.output.exists())

    def test_private_paths_reject_a_different_device_before_security(self):
        script = self.tree / "Config/Scripts/build-own-mac.sh"
        script.write_text(script.read_text().replace("internal_device = ", "internal_device = 1 + ", 1))
        result = self.run_recipe()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid private output", result.stderr)
        self.assertFalse((self.work / "security-calls").exists())
        self.assertFalse(self.calls.exists())

    def test_preflight_rejects_identity_variants_before_build(self):
        for scenario in ("missing", "ambiguous", "wrong", "distribution", "wrong-team"):
            with self.subTest(scenario=scenario):
                result = self.run_recipe(extra={"WGEX_TEST_SECURITY": scenario})
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.calls.exists(), result.stderr)
        result = self.run_recipe(extra={"WGEX_OWN_MAC_IDENTITY_SHA1": "-"})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.calls.exists())

    def test_preflight_rejects_missing_profile(self):
        self.assertNotEqual(self.run_recipe(extra={"WGEX_TEST_NO_PROFILE": "1"}).returncode, 0)
        self.assertFalse(self.calls.exists())

    def test_preflight_rejects_wrong_profile_uuid(self):
        self.write_profile(UUID="wrong")
        self.assertNotEqual(self.run_recipe().returncode, 0)
        self.write_profile()
        self.assertNotEqual(self.run_recipe(extra={"WGEX_OWN_MAC_PROFILE": "wrong"}).returncode, 0)
        self.assertFalse(self.calls.exists())

    def test_preflight_rejects_wrong_profile_team_expiry_or_certificate(self):
        for updates in ({"ExpirationDate": datetime.datetime(2000, 1, 1)},
                        {"TeamIdentifier": ["WRONGTEAM1"]}, {"DeveloperCertificates": [b"other"]},
                        {"ApplicationIdentifierPrefix": ["WRONGTEAM1"]}):
            with self.subTest(updates=updates):
                self.write_profile(**updates)
                self.assertNotEqual(self.run_recipe().returncode, 0)
        self.assertFalse(self.calls.exists())

    def test_preflight_rejects_uncovered_groups_and_wrong_application_identifier(self):
        for key, value in (("keychain-access-groups", ["WRONGTEAM1.*"]),
                           ("com.apple.security.application-groups", ["group." + self.BASE]),
                           ("com.apple.security.application-groups", [self.TEAM + ".*extra"]),
                           ("application-identifier", self.TEAM + ".wrong")):
            with self.subTest(key=key, value=value):
                self.write_profile()
                malformed = plistlib.loads(self.profile.read_bytes())
                malformed["Entitlements"][key] = value
                self.profile.write_bytes(plistlib.dumps(malformed))
                self.assertNotEqual(self.run_recipe().returncode, 0)
        self.assertFalse(self.calls.exists())

    def test_preflight_accepts_exact_profile_groups(self):
        profile = plistlib.loads(self.profile.read_bytes())
        appid = self.TEAM + "." + self.BASE
        profile["Entitlements"]["com.apple.security.application-groups"] = [appid]
        profile["Entitlements"]["keychain-access-groups"] = [appid]
        self.profile.write_bytes(plistlib.dumps(profile))
        result = self.run_recipe()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_preflight_rejects_lab_flags_dirty_tree_outside_output_and_existing_attempt(self):
        for extra in ({"WGEX_LAB_BUILD": "1"}, {"WGEX_ENGINE_TEST_SUPPORT": "1"},
                      {"CONFIGURATION": "Debug"}, {"WGEX_TEST_DIRTY": "1"},
                      {"WGEX_BUILD_ROOT": str(self.work / "outside")}, {"CLEAN_DEV_MODE": "internal"},
                      {"WGEX_OWN_MAC_BUILD_NUMBER": "1.2"}):
            with self.subTest(extra=extra):
                self.assertNotEqual(self.run_recipe(extra=extra).returncode, 0)
        self.output.mkdir(mode=0o700)
        (self.output / "A").mkdir(mode=0o700)
        self.assertNotEqual(self.run_recipe().returncode, 0)
        self.assertFalse(self.calls.exists())

    def test_private_paths_refuse_escape_symlinks_and_unsafe_permissions_before_security(self):
        outside = self.work / "outside"
        outside.mkdir(mode=0o700)
        output_link = self.private / "output-link"
        output_link.symlink_to(outside, target_is_directory=True)
        ancestor_link = self.private / "ancestor-link"
        ancestor_link.symlink_to(self.private_tmp, target_is_directory=True)
        unsafe = self.private / "unsafe"
        unsafe.mkdir(mode=0o700)
        unsafe.chmod(0o755)
        temp_container = self.private / "temp-container"
        temp_container.mkdir(mode=0o700)
        nested_tmp = temp_container / "tmp"
        nested_tmp.mkdir(mode=0o700)
        for extra in (
            {"WGEX_OWN_MAC_OUTPUT_ROOT": "relative"},
            {"WGEX_OWN_MAC_OUTPUT_ROOT": str(self.private)},
            {"WGEX_OWN_MAC_OUTPUT_ROOT": str(outside / "output")},
            {"WGEX_OWN_MAC_OUTPUT_ROOT": str(self.private / ".." / "escape")},
            {"WGEX_OWN_MAC_OUTPUT_ROOT": str(self.private / "missing" / "output")},
            {"WGEX_OWN_MAC_OUTPUT_ROOT": str(output_link)},
            {"WGEX_OWN_MAC_OUTPUT_ROOT": str(ancestor_link / "output")},
            {"WGEX_OWN_MAC_OUTPUT_ROOT": str(unsafe)},
            {"WGEX_OWN_MAC_OUTPUT_ROOT": str(unsafe / "output")},
            {"WGEX_OWN_MAC_OUTPUT_ROOT": str(self.tree / "output")},
            {"TMPDIR": str(outside)},
            {"TMPDIR": str(ancestor_link)},
            {"TMPDIR": str(unsafe)},
            {"TMPDIR": str(self.private / "missing")},
            {"WGEX_OWN_MAC_OUTPUT_ROOT": str(self.private_tmp / "output")},
            {"WGEX_OWN_MAC_OUTPUT_ROOT": str(temp_container), "TMPDIR": str(nested_tmp)},
        ):
            with self.subTest(extra=extra):
                result = self.run_recipe(extra=extra)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("invalid private output", result.stderr)
                self.assertFalse((self.work / "security-calls").exists())
                self.assertFalse(self.calls.exists())
        self.output.mkdir(mode=0o700)
        (self.output / "dangling").symlink_to(self.output / "missing", target_is_directory=True)
        self.assertNotEqual(self.run_recipe("dangling").returncode, 0)
        (self.output / "existing-file").write_text("already used")
        self.assertNotEqual(self.run_recipe("existing-file").returncode, 0)
        (self.output / "existing-derived" / "derived-data").mkdir(parents=True, mode=0o700)
        self.assertNotEqual(self.run_recipe("existing-derived").returncode, 0)
        self.assertFalse((self.work / "security-calls").exists())
        self.assertFalse(self.calls.exists())

    def test_fresh_private_attempts_reject_reuse_and_use_exact_link_root(self):
        for name, number in (("A", "10"), ("B", "11")):
            extra = {"WGEX_OWN_MAC_BUILD_NUMBER": number}
            result = self.run_recipe(name, extra=extra)
            self.assertEqual(result.returncode, 0, result.stderr)
            args = json.loads((self.work / "xcode-args.json").read_text())
            self.assertEqual(args[args.index("-derivedDataPath") + 1], str(self.output / name / "derived-data"))
            self.assertEqual((self.work / "link-call").read_text().splitlines(),
                             [str(self.output / name / "link-check"), "--release", "mac", "own-mac"])
            security_calls = (self.work / "security-calls").read_text()
            xcode_calls = self.calls.read_text()
            self.assertNotEqual(self.run_recipe(name, extra=extra).returncode, 0)
            self.assertEqual((self.work / "security-calls").read_text(), security_calls)
            self.assertEqual(self.calls.read_text(), xcode_calls)
        self.assertEqual(self.run_recipe("compare", "A", "B").returncode, 0)

    def test_keychain_prompt_has_distinct_exit(self):
        result = self.run_recipe(extra={"WGEX_TEST_PROMPT": "1"})
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertIn("NEED-USER: signing needs the maintainer at the keychain prompt", result.stderr)
        self.assertEqual(self.calls.read_text().splitlines(), ["xcodebuild"])

    def test_identity_redacted_from_output_and_every_log(self):
        result = self.run_recipe()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(self.identity, result.stdout + result.stderr)
        logs = list(self.output.rglob("*.log"))
        self.assertTrue(logs)
        self.assertTrue(any("[redacted]" in path.read_text() for path in logs))
        for path in logs:
            self.assertNotIn(self.identity, path.read_text())
            self.assertNotIn("do-not-log-", path.read_text())
        self.assertNotIn("do-not-log-", result.stdout + result.stderr)

    def test_compare_requires_equal_requirements_and_changed_cdhashes(self):
        self.assertEqual(self.run_recipe("A").returncode, 0)
        self.assertEqual(self.run_recipe("B").returncode, 0)
        self.assertEqual(self.run_recipe("compare", "A", "B").returncode, 0)
        a = self.output / "A"
        b = self.output / "B"
        original = (b / "app.dr").read_text()
        (b / "app.dr").write_text(original + "changed\n")
        self.assertNotEqual(self.run_recipe("compare", "A", "B").returncode, 0)
        (b / "app.dr").write_text(original)
        (b / "app.cdhash.sha256").write_text((a / "app.cdhash.sha256").read_text())
        self.assertNotEqual(self.run_recipe("compare", "A", "B").returncode, 0)

    def test_postbuild_rejects_timestamp_cdhash_requirement_debug_entitlement_and_failed_verify(self):
        for scenario in ("timestamp", "cdhash", "task", "verify"):
            with self.subTest(scenario=scenario):
                result = self.run_recipe(scenario, extra={"WGEX_TEST_BAD_SIGNATURE": scenario})
                self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_completion_marker_and_compare_rejects_failed_attempts(self):
        good = self.run_recipe("A")
        self.assertEqual(good.returncode, 0, good.stderr)
        bad = self.run_recipe("B", extra={"WGEX_TEST_LINK_FAILURE": "1"})
        self.assertNotEqual(bad.returncode, 0)
        root = self.output
        self.assertTrue((root / "A/PASSED").is_file())
        self.assertFalse((root / "B/PASSED").exists())
        self.assertNotEqual(self.run_recipe("compare", "A", "B").returncode, 0)
        (root / "B/PASSED").write_text("passed\n")
        (root / "A/PASSED").unlink()
        self.assertNotEqual(self.run_recipe("compare", "A", "B").returncode, 0)

    def test_incomplete_build_exit_fails_closed_and_cleans_logs(self):
        script = self.tree / "Config/Scripts/build-own-mac.sh"
        text = script.read_text()
        anchor = 'results=("${PIPESTATUS[@]}")'
        self.assertEqual(text.count(anchor), 1)
        script.write_text(text.replace(anchor, 'exit 0\n' + anchor, 1))
        result = self.run_recipe("incomplete")
        self.assertNotEqual(result.returncode, 0)
        attempt = self.output / "incomplete"
        self.assertFalse((attempt / "PASSED").exists())
        self.assertFalse((attempt / "derived-data/Logs/Build").exists())
        self.assertFalse((attempt / "derived-data/Build/Intermediates.noindex/XCBuildData").exists())

    def test_xcode_environment_allowlist_and_dangerous_inputs(self):
        for name, value in (("WGEX_ENGINE_TEST_SUPPORT", "1"), ("WGEX_LAB_BUILD", "1"), ("WGEX_LAB_BUILD", ""),
                            ("XCODE_XCCONFIG_FILE", "/fake/settings")):
            with self.subTest(name=name):
                result = self.run_recipe("bad_" + name, extra={name: value})
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(name, result.stderr)
        self.assertFalse(self.calls.exists())
        polluted = {"PYTHONPATH": "/fake", "BASH_ENV": "/fake", "GIT_CONFIG_GLOBAL": "/fake", "WGEX_LAB_BUILD": "0",
                    "GIT_WORK_TREE": "/fake", "GIT_INDEX_FILE": "/fake",
                    "WGEX_ARBITRARY": "bad", "OTHER_SWIFT_FLAGS": "-D BAD", "ARBITRARY": "bad",
                    "TeamIdentifierPrefix": "WRONG.", "AppIdentifierPrefix": "WRONG."}
        routing = {"CODEX_THREAD_ID": "codex-native", "CLAUDE_CODE_SESSION_ID": "claude-native",
                   "CLEAN_DEV_TEST_ROUTING": "dev-route", "CLEAN_DEVELOPMENT_TEST_ROUTING": "development-route",
                   "DEVCACHE": str(self.work / "cache"), "TMPDIR": str(self.private_tmp),
                   "WGEX_BUILD_ROOT": str(self.builds / "shared")}
        result = self.run_recipe("clean", extra=polluted | routing | {"WGEX_OWN_MAC_SIGNING": "0", "WGEX_OWN_MAC_BUILD": "0"})
        self.assertEqual(result.returncode, 0, result.stderr)
        child = json.loads((self.work / "xcode-env.json").read_text())
        git_env = json.loads((self.work / "git-env.json").read_text())
        for name in polluted:
            self.assertNotIn(name, child)
            self.assertNotIn(name, git_env)
        self.assertEqual(child.get("WGEX_OWN_MAC_SIGNING"), "1")
        self.assertEqual(child.get("WGEX_OWN_MAC_BUILD"), "1")
        for name, value in routing.items():
            self.assertEqual(git_env.get(name), value, name)
            self.assertEqual(child.get(name), value, name)
        allowed = {"PATH", "HOME", "TMPDIR", "DEVCACHE", "DEVELOPER_DIR", "LANG", "__CF_USER_TEXT_ENCODING",
                   "WGEX_OWN_MAC_IDENTITY_SHA1", "WGEX_OWN_MAC_BUILD_NUMBER", "WGEX_OWN_MAC_PROFILE_UUID",
                   "WGEX_OWN_MAC_SIGNING", "WGEX_OWN_MAC_BUILD", "WGEX_BUILD_ROOT", "CODEX_THREAD_ID",
                   "CLAUDE_CODE_SESSION_ID"}
        self.assertFalse([name for name in child if name not in allowed and
                          not name.startswith(("LC_", "CLEAN_DEV_", "CLEAN_DEVELOPMENT_"))])
        args = json.loads((self.work / "xcode-args.json").read_text())
        self.assertEqual(args[args.index("-xcconfig") + 1], "Config/OwnMacRelease.xcconfig")
        self.assertIn("WGEX_OWN_MAC_PROFILE=" + self.PROFILE_UUID, args)
        self.assertIn("SWIFT_ACTIVE_COMPILATION_CONDITIONS=$(inherited) WGEX_OWN_MAC_BUILD", args)

    def test_no_session_identifier_is_invented(self):
        self.env.pop("CODEX_THREAD_ID", None)
        result = self.run_recipe("no-ids")
        self.assertEqual(result.returncode, 0, result.stderr)
        for path in ("git-env.json", "xcode-env.json"):
            child = json.loads((self.work / path).read_text())
            self.assertNotIn("CODEX_THREAD_ID", child)
            self.assertNotIn("CLAUDE_CODE_SESSION_ID", child)

    def test_each_actual_session_identifier_is_carried_on_its_own(self):
        self.env.pop("CODEX_THREAD_ID", None)
        for identifier in ("CODEX_THREAD_ID", "CLAUDE_CODE_SESSION_ID"):
            with self.subTest(identifier=identifier):
                result = self.run_recipe(identifier, extra={identifier: "actual-session"})
                self.assertEqual(result.returncode, 0, result.stderr)
                for path in ("git-env.json", "xcode-env.json"):
                    child = json.loads((self.work / path).read_text())
                    self.assertEqual(child.get(identifier), "actual-session")
                    other = "CLAUDE_CODE_SESSION_ID" if identifier == "CODEX_THREAD_ID" else "CODEX_THREAD_ID"
                    self.assertNotIn(other, child)

    def test_just_and_direct_bash_keep_private_tmp_and_native_identifiers(self):
        self.env.update({"CODEX_THREAD_ID": "codex-native", "CLAUDE_CODE_SESSION_ID": "claude-native",
                         "CLEAN_DEVELOPMENT_TEST_ROUTING": "development-route"})
        direct = self.run_recipe("A")
        self.assertEqual(direct.returncode, 0, direct.stderr)
        direct_env = json.loads((self.work / "xcode-env.json").read_text())
        justfile = (ROOT / "justfile").read_text()
        recipe = re.search(r"(?m)^build-own-mac attempt=.*:\n(    .*\n)", justfile).group(1)
        self.assertEqual(set(re.findall(r"-u ([A-Z0-9_]+)", recipe)), knobs.ZSH_KNOB_NAMES | {"BASH_ENV", "ENV"})
        self.put("justfile", justfile)
        # A login zsh would replace the private job TMPDIR, as the host routing can.
        (self.home / ".zshenv").write_text('export TMPDIR="$HOME/../not-private"\n')
        hook = self.work / "bash-hook"
        hook.write_text('printf invoked >"$HOME/../bash-hook-ran"\n')
        # A matching CDPATH would redirect the script's initial relative cd before its allowlist runs.
        cdpath = self.work / "cdpath"
        (cdpath / "Config/Scripts").mkdir(parents=True)
        env = self.env | {name: str(self.work / ("hostile-" + name)) for name in knobs.ZSH_KNOB_NAMES}
        env.update({"BASH_ENV": str(hook), "ENV": str(hook), "CDPATH": str(cdpath), "TMOUT": "1",
                    "WGEX_OWN_MAC_BUILD_NUMBER": "11"})
        command = ["just", "--justfile", str(self.tree / "justfile"), "build-own-mac"]
        via_just = subprocess.run(command + ["B"], cwd=self.tree, env=env, text=True, capture_output=True, timeout=30)
        self.assertEqual(via_just.returncode, 0, via_just.stderr)
        just_env = json.loads((self.work / "xcode-env.json").read_text())
        for name in ("TMPDIR", "CODEX_THREAD_ID", "CLAUDE_CODE_SESSION_ID", "CLEAN_DEV_BUILDS",
                     "CLEAN_DEVELOPMENT_TEST_ROUTING", "WGEX_OWN_MAC_BUILD", "WGEX_OWN_MAC_SIGNING"):
            self.assertEqual(just_env.get(name), direct_env.get(name), name)
        self.assertEqual(just_env["TMPDIR"], str(self.private_tmp))
        self.assertFalse((self.work / "bash-hook-ran").exists())
        comparison = subprocess.run(command + ["compare", "A", "B"], cwd=self.tree,
                                    env=env, text=True, capture_output=True, timeout=30)
        self.assertEqual(comparison.returncode, 0, comparison.stderr)

    def test_preflight_requires_osx_platform(self):
        self.write_profile(Platform=["iOS"])
        self.assertNotEqual(self.run_recipe().returncode, 0)
        self.assertFalse(self.calls.exists())

    def test_new_profile_uuid(self):
        new_uuid = "12345678-1234-1234-1234-123456789abc"
        self.write_profile(UUID=new_uuid)
        new_profile = self.profile.with_name(new_uuid + ".provisionprofile")
        new_profile.write_bytes(self.profile.read_bytes())
        result = self.run_recipe("new", extra={"WGEX_OWN_MAC_PROFILE_UUID": new_uuid, "WGEX_TEST_PROFILE": str(new_profile)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("WGEX_OWN_MAC_PROFILE=" + new_uuid, json.loads((self.work / "xcode-args.json").read_text()))
        self.assertNotEqual(self.run_recipe("invalid", extra={"WGEX_OWN_MAC_PROFILE_UUID": "../bad"}).returncode, 0)

    def test_postbuild_signing_guards_and_call_contract(self):
        for scenario in ("authority", "team", "runtime", "identifier", "strict-only", "policy-only", "different-dr",
                         "weak-id", "weak-anchor", "weak-cn", "weak-wwdr", "weak-or", "wrong-leaf"):
            with self.subTest(scenario=scenario):
                result = self.run_recipe(scenario, extra={"WGEX_TEST_BAD_SIGNATURE": scenario})
                self.assertNotEqual(result.returncode, 0, result.stdout)
        result = self.run_recipe("entitlement-fail", extra={"WGEX_TEST_ENT_FAILURE": "1"})
        self.assertNotEqual(result.returncode, 0, result.stdout)
        valid_ou = self.run_recipe("valid-ou", extra={"WGEX_TEST_BAD_SIGNATURE": "dr-ou"})
        self.assertEqual(valid_ou.returncode, 0, valid_ou.stderr)

    def test_embedded_profile_must_match_installed_bytes_and_uuid(self):
        for mode in ("different", "wrong-uuid"):
            result = self.run_recipe(mode, extra={"WGEX_TEST_EMBEDDED": mode})
            self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_build_database_and_activity_logs_are_removed_even_on_failure(self):
        for name, extra in (("success", {}), ("prompt", {"WGEX_TEST_PROMPT": "1"})):
            result = self.run_recipe(name, extra=extra)
            self.assertEqual(result.returncode, 77 if extra else 0, result.stderr)
            derived = self.output / name / "derived-data"
            self.assertFalse((derived / "Logs/Build").exists())
            self.assertFalse((derived / "Build/Intermediates.noindex/XCBuildData").exists())
            for path in derived.rglob("*"):
                if path.is_file(): self.assertNotIn(self.identity.encode(), path.read_bytes())

    def test_redactor_ignores_pythonpath(self):
        poison = self.work / "poison"
        poison.mkdir()
        (poison / "sitecustomize.py").write_text('import sys\nif "-u" in sys.orig_argv: print("redactor poisoned", file=sys.stderr)\n')
        script = (self.SCRIPT_OVERRIDE or ROOT / "Config/Scripts/build-own-mac.sh").read_text()
        function = script.split("redact() {", 1)[1].split("\n}", 1)[0]
        result = subprocess.run(["bash", "-c", "redact() {" + function + "\n}\nredact"],
                                env=self.env | {"PYTHONPATH": str(poison)}, input=self.identity + "\n",
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("redactor poisoned", result.stdout + result.stderr)
        self.assertNotIn(self.identity, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "[redacted]\n")

    def test_inherited_xtrace_never_exposes_identity(self):
        result = self.run_recipe("trace", extra={"SHELLOPTS": "braceexpand:hashall:interactive-comments:xtrace"})
        self.assertNotIn(self.identity, result.stdout + result.stderr)

    def test_ordinary_build_refuses_own_mac_environment(self):
        for name in ("Config/Scripts/build.sh", "Config/Scripts/lib.sh", "Config/Scripts/build_root.py"):
            self.put(name, (ROOT / name).read_text())
        for name in ("WGEX_OWN_MAC_PROFILE", "WGEX_OWN_MAC_PROFILE_UUID", "WGEX_OWN_MAC_UNKNOWN",
                     "WGEX_OWN_MAC_BUILD", "WGEX_OWN_MAC_SIGNING", "WGEX_OWN_MAC_OUTPUT_ROOT"):
            for value in ("1", "0", ""):
                with self.subTest(name=name, value=value):
                    env = {key: val for key, val in self.env.items() if not key.startswith("WGEX_OWN_MAC_")}
                    env[name] = value
                    result = subprocess.run(["bash", str(self.tree / "Config/Scripts/build.sh"), "mac", "release"],
                                            cwd=self.tree, env=env, text=True, capture_output=True, timeout=30)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("WGEX_OWN_MAC_", result.stderr)

    def test_release_link_accepts_clean_and_rejects_engine_test_symbols(self):
        for name in ("Engine/scripts/check-link.sh", "Engine/scripts/lib.sh", "Config/Scripts/lib.sh",
                     "Config/Scripts/build_root.py"):
            self.put(name, (ROOT / name).read_text())
        fixture = (ROOT / "Tools/lint/tests/check-link/run.sh").read_text()
        fixture = fixture.replace('rm -rf "$work"\nprintf', '''make_products '_wgex_test_ping' 'WGEX app'
expect engine-test-symbol rejected 'Release contains lab/testing'
make_products 'WGEX daemon' 'CWGEXEngineTest'
expect engine-test-module rejected 'Release contains lab/testing'
rm -rf "$work"
printf''')
        self.put("Tools/lint/tests/check-link/run.sh", fixture)
        result = subprocess.run(["bash", str(self.tree / "Tools/lint/tests/check-link/run.sh")], cwd=self.tree,
                                env=self.env, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("clean-products", result.stdout)
        self.assertIn("engine-test-symbol", result.stdout)
        self.assertIn("engine-test-module", result.stdout)

    def test_entitlements_own_mac_and_default_group_expectations(self):
        for name in ("Tools/lint/check-entitlements.sh", "Tools/lint/lib.sh", "Config/Scripts/lib.sh",
                     "Config/Scripts/build_root.py", "Config/Base.xcconfig", "Apps/WGEXMac/WGEXMac.entitlements",
                     "Apps/WGEXMac/WGEXMac.adhoc.entitlements"):
            self.put(name, (ROOT / name).read_text())
        self.stub("find", '#!/bin/bash\nexec /usr/bin/find "$@"\n')
        self.stub("codesign", '''#!/usr/bin/env python3
import os, pathlib, plistlib, sys
args = sys.argv[1:]
path = pathlib.Path(args[-1])
base, team = "com.magrathean.WGEXApp", "ABCDE12345"
identifier = base + (".daemon" if path.name == "WGEXDaemon" else ".cli" if path.name == "wgex" else "")
if "-dv" in args:
    print("Identifier=" + identifier + "\\nSignature=1234")
elif "--entitlements" in args:
    variant = os.environ.get("WGEX_TEST_ENT_VARIANT", "unrestricted")
    ent = {}
    if path.name in ("WGEXDaemon", "wgex"):
        tool = os.environ.get("WGEX_TEST_ENT_TOOL", "prefixed" if variant in ("own-mac", "extra") else "bare")
        ent["com.apple.application-identifier"] = identifier if tool == "bare" else team + "." + identifier
        if tool in ("team", "wrong-team"):
            ent["com.apple.developer.team-identifier"] = team if tool == "team" else "WRONGTEAM1"
        if tool == "extra": ent["com.apple.security.network.client"] = True
    elif variant in ("full", "default", "own-mac", "extra"):
        group = team + "." + base if variant in ("own-mac", "extra") else "group." + base
        ent = {"com.apple.security.application-groups": [group], "keychain-access-groups": [team + "." + base]}
        if variant != "default":
            ent.update({"com.apple.application-identifier": team + "." + base,
                        "com.apple.developer.team-identifier": team})
        if variant == "extra": ent["com.apple.security.network.client"] = True
    if path.name not in ("WGEXDaemon", "wgex"):
        ent["com.apple.security.personal-information.location"] = True
    sys.stdout.buffer.write(plistlib.dumps(ent))
else:
    sys.exit(1)
''')
        self.stub("segedit", '''#!/usr/bin/env python3
import pathlib, plistlib, sys
base = "com.magrathean.WGEXApp"
name = pathlib.Path(sys.argv[1]).name
pathlib.Path(sys.argv[-1]).write_bytes(plistlib.dumps({"CFBundleIdentifier": base + (".daemon" if name == "WGEXDaemon" else ".cli"), "CFBundleVersion": "1"}))
''')
        products = self.work / "products"
        app = products / "Release/WGEX.app"
        for name in ("Contents/MacOS/WGEX", "Contents/MacOS/WGEXDaemon", "Contents/Helpers/wgex"):
            path = app / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch(mode=0o755)
        info = {"CFBundleIdentifier": self.BASE, "CFBundleExecutable": "WGEX", "NSLocalNetworkUsageDescription": "fixture",
                "NSLocationUsageDescription": "fixture", "NSLocationWhenInUseUsageDescription": "fixture",
                "NSBonjourServices": ["_wgex-pair._tcp"], "CFBundleDocumentTypes": [{"LSItemContentTypes": ["com.wireguard.config"]}],
                "UTImportedTypeDeclarations": [{"UTTypeIdentifier": "com.wireguard.config",
                                                "UTTypeTagSpecification": {"public.filename-extension": ["conf"]}}]}
        (app / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
        daemon = app / "Contents/Library/LaunchDaemons" / (self.BASE + ".daemon.plist")
        daemon.parent.mkdir(parents=True)
        daemon.write_bytes(plistlib.dumps({"Label": self.BASE + ".daemon", "BundleProgram": "Contents/MacOS/WGEXDaemon",
                                          "MachServices": {self.BASE + ".daemon": True}, "AssociatedBundleIdentifiers": [self.BASE]}))
        command = ["bash", str(self.tree / "Tools/lint/check-entitlements.sh"), "--configuration", "Release",
                   "--products", str(products), "--require", "mac"]

        def check(variant, arguments, extra=None):
            return subprocess.run(command + arguments, env=self.env | {"WGEX_TEST_ENT_VARIANT": variant} | (extra or {}),
                                  input=self.profile.read_text() if arguments[-2:] == ["--profile", "-"] else None,
                                  text=True, capture_output=True, timeout=30)

        unrestricted = check("unrestricted", ["--variant", "unrestricted"])
        self.assertEqual(unrestricted.returncode, 0, unrestricted.stderr)
        self.assertNotEqual(check("unrestricted", []).returncode, 0)  # auto retains the existing real-signature default
        default = check("default", ["--variant", "full"])
        self.assertEqual(default.returncode, 0, default.stderr)
        own_args = ["--variant", "full", "--own-mac", "--profile", str(self.profile)]
        own = check("own-mac", own_args)
        self.assertEqual(own.returncode, 0, own.stderr)
        own_stdin = check("own-mac", ["--variant", "full", "--own-mac", "--profile", "-"])
        self.assertEqual(own_stdin.returncode, 0, own_stdin.stderr)
        both = check("own-mac", own_args, {"WGEX_TEST_ENT_TOOL": "team"})
        self.assertEqual(both.returncode, 0, both.stderr)
        for bad_tool in ("bare", "wrong-team", "extra"):
            self.assertNotEqual(check("own-mac", own_args, {"WGEX_TEST_ENT_TOOL": bad_tool}).returncode, 0)
        self.assertNotEqual(check("full", own_args).returncode, 0)
        self.assertNotEqual(check("own-mac", ["--variant", "full", "--profile", str(self.profile)]).returncode, 0)
        self.assertNotEqual(check("own-mac", ["--variant", "full", "--own-mac"]).returncode, 0)
        self.write_profile()
        profile = plistlib.loads(self.profile.read_bytes())
        profile["Entitlements"]["com.apple.security.application-groups"].append("group." + self.BASE)
        self.profile.write_bytes(plistlib.dumps(profile))
        full = check("full", ["--variant", "full", "--profile", str(self.profile)])
        self.assertEqual(full.returncode, 0, full.stderr)
        self.assertNotEqual(check("extra", own_args).returncode, 0)
        self.write_profile(TeamIdentifier=["WRONGTEAM1"])
        self.assertNotEqual(check("full", ["--variant", "full", "--profile", str(self.profile)]).returncode, 0)
        self.assertNotEqual(check("full", ["--variant", "auto", "--profile", str(self.profile)]).returncode, 0)
        for key, value in (("TeamIdentifier", ["WRONGTEAM1"]), ("ApplicationIdentifierPrefix", ["WRONGTEAM1"]),
                           ("com.apple.developer.team-identifier", "WRONGTEAM1"), ("application-identifier", self.TEAM + ".wrong"),
                           ("keychain-access-groups", ["WRONGTEAM1.*"]), ("com.apple.security.application-groups", ["group.wrong"])):
            with self.subTest(profile_guard=key):
                self.write_profile()
                profile = plistlib.loads(self.profile.read_bytes())
                (profile if key in ("TeamIdentifier", "ApplicationIdentifierPrefix") else profile["Entitlements"])[key] = value
                self.profile.write_bytes(plistlib.dumps(profile))
                rejected = check("own-mac", own_args)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn("profile does not authorise", rejected.stderr)


class IOSDeviceBuildTests(unittest.TestCase):
    """M06-T09: the Development-signed device build, its installer and its entitlement check, with synthetic xcodebuild,
    codesign and xcrun stand-ins only (no real build, signing or devicectl)."""

    TEAM = "ABCDE12345"
    BASE = "com.magrathean.WGEXApp.dev"
    UDID = "00008110-001A2B3C4D5E801E"
    IDENTIFIER = "4C1E7A52-0B9D-4F35-9C1A-2D6B8E0F1A3C"
    SOURCES = ("Config/Scripts/build.sh", "Config/Scripts/lib.sh", "Config/Scripts/build_root.py",
               "Config/Scripts/install-ios-device.sh", "Config/Base.xcconfig", "Tools/lint/check-entitlements.sh",
               "Tools/lint/lib.sh", "Apps/WGEXiOS/WGEXiOS.entitlements", "Extensions/WGEXTunnel-iOS/WGEXTunnel-iOS.entitlements")
    CODESIGN = '''#!/usr/bin/env python3
import json, os, pathlib, plistlib, sys
work = pathlib.Path(os.environ["WGEX_TEST_WORK"])
control = json.loads((work / "control.json").read_text())
args = sys.argv[1:]
path = pathlib.Path(args[-1])
team, base = "ABCDE12345", "com.magrathean.WGEXApp.dev"
identifier = {"WGEXTunnel.appex": base + ".tunnel", "WGEXLiveActivity.appex": base + ".liveactivity"}.get(path.name, base)
signature = control.get("signature", "development")
if "-dvv" in args:
    lines = ["Executable=" + str(path), "Identifier=" + identifier]
    if signature == "adhoc":
        lines += ["Signature=adhoc", "TeamIdentifier=not set"]
    else:
        authority = {"distribution": "Apple Distribution: Fixture (ABCDE12345)",
                     "developer-id": "Developer ID Application: Fixture (ABCDE12345)",
                     "app-store": "Apple iPhone OS Application Signing"}.get(signature, "Apple Development: Fixture (ABCDE12345)")
        lines += ["Authority=" + authority, "Authority=Apple Worldwide Developer Relations Certification Authority",
                  "Authority=Apple Root CA", "TeamIdentifier=" + ("WRONGTEAM1" if signature == "wrong-team" else team)]
    print("\\n".join(lines), file=sys.stderr)
elif "--entitlements" in args:
    mode = control.get("entitlements", "good")
    ent = {"application-identifier": team + "." + identifier, "com.apple.developer.team-identifier": team,
           "get-task-allow": True}
    if path.name != "WGEXLiveActivity.appex":
        ent.update({"com.apple.security.application-groups": ["group." + base],
                    "com.apple.developer.networking.networkextension": ["packet-tunnel-provider"],
                    "keychain-access-groups": [team + "." + base]})
        if path.name == "WGEX.app":
            ent["com.apple.developer.networking.wifi-info"] = True
    else:
        ent["keychain-access-groups"] = [team + "." + identifier]
    if mode == "extra" and path.name == "WGEX.app": ent["com.apple.security.network.client"] = True
    if mode == "no-ne" and path.name == "WGEXTunnel.appex": del ent["com.apple.developer.networking.networkextension"]
    if mode == "wrong-group" and path.name == "WGEX.app": ent["com.apple.security.application-groups"] = ["group.com.magrathean.WGEXApp"]
    if mode == "wrong-keychain" and path.name == "WGEXTunnel.appex": ent["keychain-access-groups"] = [team + ".other"]
    if mode == "no-task-allow": del ent["get-task-allow"]
    if mode == "distribution-profile": ent["get-task-allow"] = False
    if mode == "no-team-id" and path.name == "WGEXLiveActivity.appex": del ent["com.apple.developer.team-identifier"]
    sys.stdout.buffer.write(plistlib.dumps(ent))
else:
    sys.exit(1)
'''
    XCRUN = '''#!/usr/bin/env python3
import json, os, pathlib, sys
work = pathlib.Path(os.environ["WGEX_TEST_WORK"])
control = json.loads((work / "control.json").read_text())
args = sys.argv[1:]
with (work / "xcrun-calls").open("a") as calls:
    calls.write(json.dumps(args) + "\\n")
if args[:3] == ["devicectl", "list", "devices"]:
    listing = control.get("list", "ok")
    if listing == "fail":
        print("ERROR: fixture CoreDevice failure", file=sys.stderr)
        sys.exit(1)
    target = pathlib.Path(args[args.index("--json-output") + 1])
    target.write_text("{not json" if listing == "garbage" else json.dumps({"result": {"devices": control.get("devices", [])}}))
elif args[:4] == ["devicectl", "device", "install", "app"]:
    sys.exit(control.get("install", 0))
else:
    sys.exit(64)
'''

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="wgex-ios-device-", dir=os.environ["TMPDIR"],
                                                ignore_cleanup_errors=True)
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.tree = self.work / "tree"
        self.bin = self.work / "bin"
        self.builds = self.work / "builds"
        self.scratch = self.work / "tmp"
        for directory in (self.tree, self.bin, self.builds, self.scratch):
            directory.mkdir()
        for name in self.SOURCES:
            self.put(name, (ROOT / name).read_text())
        (self.tree / "Config/Scripts/install-ios-device.sh").chmod(0o755)
        record = '#!/bin/bash\nprintf "%s\\n" "$0 $*" >>"$WGEX_TEST_WORK/steps"\n'
        self.put("Engine/scripts/source-digest.py", "import sys\nsys.exit(0)\n")
        self.put("Config/Scripts/gen.sh", record)
        self.put("Config/Scripts/generate-build-identifiers.sh", record)
        self.put("project.yml", "name: fixture\n")
        self.stub("xcodebuild", '''#!/usr/bin/env python3
import json, os, pathlib, sys
with (pathlib.Path(os.environ["WGEX_TEST_WORK"]) / "xcodebuild-calls").open("a") as calls:
    calls.write(json.dumps(sys.argv[1:]) + "\\n")
print("** BUILD SUCCEEDED **")
''')
        self.stub("codesign", self.CODESIGN)
        self.stub("xcrun", self.XCRUN)
        self.control({})
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("WGEX_")}
        self.env |= {"PATH": str(self.bin) + ":/usr/bin:/bin:/usr/sbin:/sbin", "TMPDIR": str(self.scratch),
                     "CLEAN_DEV_BUILDS": str(self.builds), "WGEX_TEST_WORK": str(self.work)}
        self.app = self.builds / "tree/derived-data/Build/Products/Debug-iphoneos/WGEX.app"

    def put(self, name, content):
        path = self.tree / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def stub(self, name, content):
        path = self.bin / name
        path.write_text(content)
        path.chmod(0o755)

    def control(self, data):
        (self.work / "control.json").write_text(json.dumps(data))

    def run_script(self, name, *args, extra=None, drop=()):
        env = {key: value for key, value in (self.env | (extra or {})).items() if key not in drop}
        return subprocess.run(["bash", str(self.tree / name), *args], cwd=self.tree, env=env, text=True,
                              capture_output=True, timeout=60)

    def calls(self, name):
        path = self.work / name
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def make_device_build(self, profile=True, missing_profile=None):
        info = {"CFBundleIdentifier": self.BASE, "CFBundleExecutable": "WGEX", "NSLocalNetworkUsageDescription": "fixture",
                "NSCameraUsageDescription": "fixture", "NSSupportsLiveActivities": True,
                "CFBundleDocumentTypes": [{"LSItemContentTypes": ["com.wireguard.config"]}],
                "UTImportedTypeDeclarations": [{"UTTypeIdentifier": "com.wireguard.config",
                                                "UTTypeTagSpecification": {"public.filename-extension": ["conf"]}}]}
        bundles = {self.app: info,
                   self.app / "PlugIns/WGEXTunnel.appex": {"NSExtension": {
                       "NSExtensionPointIdentifier": "com.apple.networkextension.packet-tunnel"}},
                   self.app / "PlugIns/WGEXLiveActivity.appex": {"NSExtension": {
                       "NSExtensionPointIdentifier": "com.apple.widgetkit-extension"}}}
        for bundle, plist in bundles.items():
            bundle.mkdir(parents=True, exist_ok=True)
            (bundle / "Info.plist").write_bytes(plistlib.dumps(plist))
            if profile and bundle.name != missing_profile:
                (bundle / "embedded.mobileprovision").write_bytes(b"synthetic profile")

    def snapshot(self, root):
        return sorted((str(path.relative_to(root)), path.read_bytes() if path.is_file() else b"")
                      for path in root.rglob("*")) if root.exists() else []

    def device(self, **overrides):
        device = {"identifier": self.IDENTIFIER,
                  "hardwareProperties": {"udid": self.UDID, "platform": "iOS"},
                  "connectionProperties": {"pairingState": "paired", "tunnelState": "disconnected"},
                  "deviceProperties": {"name": "Fixture iPhone"}}
        for key, value in overrides.items():
            if "__" in key:
                section, field = key.split("__")
                device[section][field] = value
            else:
                device[key] = value
        return device

    # --- just build ios-device -------------------------------------------------------------------------------------------

    def test_device_build_uses_development_signing_only(self):
        for args in ((), ("debug",)):
            with self.subTest(args=args):
                (self.work / "xcodebuild-calls").unlink(missing_ok=True)
                result = self.run_script("Config/Scripts/build.sh", "ios-device", *args)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                calls = self.calls("xcodebuild-calls")
                self.assertEqual(len(calls), 1, calls)
                call = calls[0]
                self.assertEqual(call[0], "build")
                pairs = {call[index]: call[index + 1] for index in range(len(call) - 1) if call[index].startswith("-")}
                self.assertEqual(pairs["-scheme"], "WGEX-iOS")
                self.assertEqual(pairs["-configuration"], "Debug")
                self.assertEqual(pairs["-destination"], "generic/platform=iOS")
                self.assertTrue(Path(pairs["-derivedDataPath"]).is_relative_to(self.builds), pairs["-derivedDataPath"])
                for setting in ("-allowProvisioningUpdates", "CODE_SIGN_STYLE=Automatic", "DEVELOPMENT_TEAM=" + self.TEAM,
                                "CODE_SIGN_IDENTITY=Apple Development", "PROVISIONING_PROFILE_SPECIFIER=",
                                "WGEX_RESTRICTED_ENTITLEMENTS=YES"):
                    self.assertIn(setting, call)
                for word in call:
                    self.assertNotRegex(word, r"(?i)archive|export|distribution|developer id|WGEX_BUNDLE_ID_BASE")
                self.assertIn("Debug-iphoneos", result.stdout)
                self.assertIn("--configuration Debug", (self.work / "steps").read_text())

    def test_simulator_build_is_unchanged(self):
        result = self.run_script("Config/Scripts/build.sh", "ios")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        (call,) = self.calls("xcodebuild-calls")
        self.assertIn("generic/platform=iOS Simulator", call)
        self.assertEqual([word for word in call if "=" in word and not word.startswith("generic/")], [])
        self.assertNotIn("-allowProvisioningUpdates", call)

    def test_device_build_refusals_build_nothing(self):
        cases = (
            (("ios-device", "release"), {}, (), "builds Debug only"),
            (("ios-device", "Release"), {}, (), "builds Debug only"),
            (("ios-device",), {}, ("CLEAN_DEV_BUILDS",), "needs an absolute CLEAN_DEV_BUILDS"),
            (("ios-device",), {"CLEAN_DEV_BUILDS": "relative/builds"}, (), "needs an absolute CLEAN_DEV_BUILDS"),
            (("ios-device",), {"WGEX_BUILD_ROOT": str(self.work / "elsewhere")}, (), "is not under CLEAN_DEV_BUILDS"),
        )
        for args, extra, drop, message in cases:
            with self.subTest(args=args, extra=extra, drop=drop):
                result = self.run_script("Config/Scripts/build.sh", *args, extra=extra, drop=drop)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn(message, result.stderr)
                self.assertEqual(self.calls("xcodebuild-calls"), [])
                self.assertFalse((self.work / "steps").exists())
                self.assertEqual(self.snapshot(self.builds), [])
                self.assertFalse((self.work / "elsewhere").exists())
                self.assertEqual(list(self.scratch.iterdir()), [])
        unknown = self.run_script("Config/Scripts/build.sh", "ios-devices")
        self.assertEqual(unknown.returncode, 2)
        self.assertIn("expected mac, ios, ios-device, tv or all", unknown.stderr)

    def test_justfile_install_recipe_passes_one_quoted_argument(self):
        text = (ROOT / "justfile").read_text()
        self.assertIn('[positional-arguments]\ninstall-ios-device udid:\n    bash Config/Scripts/install-ios-device.sh "$@"\n', text)
        self.assertIn("build platform configuration=\"debug\":\n    bash Config/Scripts/build.sh {{platform}} {{configuration}}\n", text)

    # --- just install-ios-device ---------------------------------------------------------------------------------------

    def assert_nothing_installed(self, result, code, message):
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        self.assertIn(message, result.stderr)
        self.assertNotIn(["devicectl", "device", "install"], [call[:3] for call in self.calls("xcrun-calls")])
        self.assertEqual(list(self.scratch.iterdir()), [], "a temporary file was left behind")

    def test_install_argument_handling(self):
        self.make_device_build()
        for args in ((), (self.UDID, self.UDID), ("",), ("../../etc",), ("$(touch pwned)",), ("0000-0000",),
                     (self.UDID + "; true",), ("-" + "0" * 40,)):
            with self.subTest(args=args):
                result = self.run_script("Config/Scripts/install-ios-device.sh", *args)
                self.assert_nothing_installed(result, 2, "usage: install-ios-device.sh <udid>")
                self.assertEqual(self.calls("xcrun-calls"), [])
        self.assertFalse((self.tree / "pwned").exists())

    def test_install_without_a_build_or_signing_changes_nothing(self):
        result = self.run_script("Config/Scripts/install-ios-device.sh", self.UDID)
        self.assert_nothing_installed(result, 1, "no device build at")
        self.assertIn("run 'just build ios-device' first (nothing installed)", result.stderr)
        self.assertEqual(self.calls("xcrun-calls"), [])
        self.make_device_build()
        for signature in ("adhoc", "distribution", "developer-id", "app-store", "wrong-team"):
            with self.subTest(signature=signature):
                self.control({"signature": signature, "devices": [self.device()]})
                before = self.snapshot(self.app)
                result = self.run_script("Config/Scripts/install-ios-device.sh", self.UDID)
                self.assert_nothing_installed(result, 1, "is not Development-signed on team " + self.TEAM)
                self.assertEqual(self.calls("xcrun-calls"), [])
                self.assertEqual(self.snapshot(self.app), before)
        for missing in ("WGEX.app", "WGEXTunnel.appex", "WGEXLiveActivity.appex"):
            with self.subTest(missing_profile=missing):
                shutil.rmtree(self.app)
                self.make_device_build(missing_profile=missing)
                self.control({"devices": [self.device()]})
                result = self.run_script("Config/Scripts/install-ios-device.sh", self.UDID)
                self.assert_nothing_installed(result, 1, missing + " is not Development-signed")
        shutil.rmtree(self.app)
        self.make_device_build(profile=False)
        result = self.run_script("Config/Scripts/install-ios-device.sh", self.UDID)
        self.assert_nothing_installed(result, 1, "with an embedded profile (ad hoc or simulator build?)")

    def test_install_without_a_device_changes_nothing(self):
        self.make_device_build()
        before = self.snapshot(self.app)
        cases = (
            ({"devices": []}, "no device " + self.UDID + " is known to devicectl"),
            ({"devices": [self.device(hardwareProperties__udid="00008110-0000000000000000")]}, "is known to devicectl"),
            ({"devices": [self.device(connectionProperties__tunnelState="unavailable")]}, "is not connected"),
            ({"devices": [self.device(connectionProperties__pairingState="unpaired")]}, "is not paired with this Mac"),
            ({"devices": [self.device(hardwareProperties__platform="tvOS")]}, "is not an iPhone or iPad (tvOS)"),
            ({"list": "fail"}, "could not list devices with 'xcrun devicectl list devices'"),
            ({"list": "garbage"}, "could not read the device list from devicectl"),
        )
        for control, message in cases:
            with self.subTest(control=control):
                (self.work / "xcrun-calls").unlink(missing_ok=True)
                self.control(control)
                result = self.run_script("Config/Scripts/install-ios-device.sh", self.UDID)
                self.assert_nothing_installed(result, 1, message)
                self.assertIn("(nothing installed)", result.stderr)
                self.assertEqual([call[:3] for call in self.calls("xcrun-calls")], [["devicectl", "list", "devices"]])
                self.assertEqual(self.snapshot(self.app), before)
        self.control({"list": "fail"})
        self.assertIn("fixture CoreDevice failure",
                      self.run_script("Config/Scripts/install-ios-device.sh", self.UDID).stderr)

    def test_install_on_a_connected_device(self):
        self.make_device_build()
        for wanted, tunnel in ((self.UDID, "disconnected"), (self.IDENTIFIER.lower(), "connected")):
            with self.subTest(wanted=wanted):
                (self.work / "xcrun-calls").unlink(missing_ok=True)
                other = self.device(hardwareProperties__udid="00008110-0000000000000000", identifier="0" * 36,
                                    connectionProperties__tunnelState="unavailable")
                self.control({"devices": [other, self.device(connectionProperties__tunnelState=tunnel)]})
                result = self.run_script("Config/Scripts/install-ios-device.sh", wanted)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                install = [call for call in self.calls("xcrun-calls") if call[:3] == ["devicectl", "device", "install"]]
                self.assertEqual(install, [["devicectl", "device", "install", "app", "--device", wanted, str(self.app)]])
                self.assertIn("installed WGEX.app on " + wanted, result.stdout)
                self.assertEqual(list(self.scratch.iterdir()), [])
        self.control({"devices": [self.device()], "install": 7})
        failed = self.run_script("Config/Scripts/install-ios-device.sh", self.UDID)
        self.assertEqual(failed.returncode, 7)
        self.assertNotIn("installed WGEX.app", failed.stdout)
        self.assertEqual(list(self.scratch.iterdir()), [])

    # --- check-entitlements on the device build --------------------------------------------------------------------------

    def check(self, *extra):
        products = self.builds / "tree/derived-data/Build/Products"
        return self.run_script("Tools/lint/check-entitlements.sh", "--configuration", "Debug", "--products", str(products),
                               *extra)

    def test_entitlements_accept_the_device_build(self):
        self.make_device_build()
        for extra in (("--require", "ios-device"), ("--require", "ios-device", "--variant", "unrestricted"), ()):
            with self.subTest(extra=extra):
                result = self.check(*extra)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertRegex(result.stdout, r"check-entitlements: ok \(\d+ checks; Debug; ios-device\)")

    def test_entitlements_reject_bonjour_services_on_the_ios_build(self):
        self.make_device_build()
        path = self.app / "Info.plist"
        info = plistlib.loads(path.read_bytes())
        info["NSBonjourServices"] = ["_wgex-pair._tcp"]
        path.write_bytes(plistlib.dumps(info))
        result = self.check("--require", "ios-device")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("NSBonjourServices must not exist", result.stderr)

    def test_entitlements_reject_a_wrong_device_build(self):
        self.make_device_build()
        cases = (
            ({"signature": "adhoc"}, "ad hoc signature on a device build"),
            ({"signature": "distribution"}, "not signed with an Apple Development certificate"),
            ({"signature": "developer-id"}, "not signed with an Apple Development certificate"),
            ({"signature": "app-store"}, "not signed with an Apple Development certificate"),
            ({"signature": "wrong-team"}, "team is not " + self.TEAM),
            ({"entitlements": "extra"}, "unexpected com.apple.security.network.client"),
            ({"entitlements": "no-ne"}, "com.apple.developer.networking.networkextension is null"),
            ({"entitlements": "wrong-group"}, 'com.apple.security.application-groups is ["group.com.magrathean.WGEXApp"]'),
            ({"entitlements": "wrong-keychain"}, "keychain-access-groups is"),
            ({"entitlements": "no-task-allow"}, "get-task-allow is null"),
            ({"entitlements": "distribution-profile"}, "get-task-allow is false"),
            ({"entitlements": "no-team-id"}, "WGEXLiveActivity.appex: device entitlements differ"),
        )
        for control, message in cases:
            with self.subTest(control=control):
                self.control(control)
                result = self.check("--require", "ios-device")
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(message, result.stderr)
        self.control({})
        (self.app / "PlugIns/WGEXTunnel.appex/embedded.mobileprovision").unlink()
        result = self.check("--require", "ios-device")
        self.assertEqual(result.returncode, 1)
        self.assertIn("WGEXTunnel.appex: embedded.mobileprovision is missing", result.stderr)

    def test_entitlements_require_the_restricted_entitlements_in_the_source(self):
        self.make_device_build()
        source = self.tree / "Extensions/WGEXTunnel-iOS/WGEXTunnel-iOS.entitlements"
        data = plistlib.loads(source.read_bytes())
        del data["com.apple.developer.networking.networkextension"]
        source.write_bytes(plistlib.dumps(data))
        self.control({"entitlements": "no-ne"})
        result = self.check("--require", "ios-device")
        self.assertEqual(result.returncode, 1)
        self.assertIn("the entitlements file names no com.apple.developer.networking.networkextension", result.stderr)

    def test_entitlements_require_a_device_build_when_asked(self):
        result = self.check("--require", "ios-device")
        self.assertEqual(result.returncode, 1)
        self.assertIn("ios-device: no Debug product", result.stderr)


def base64_encode(value):
    import base64
    return base64.b64encode(value).decode()


if __name__ == "__main__":
    unittest.main(verbosity=2)
