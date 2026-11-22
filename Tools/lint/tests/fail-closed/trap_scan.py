#!/usr/bin/env python3
"""List every EXIT trap in shell scripts and say whether it has the one injectable form.

Usage: python3 -I trap_scan.py <script>...

One tab-separated line per trap statement that has EXIT (any case, SIGEXIT) or a numeric zero among its signals, or that
is the one-argument `trap EXIT` (a command named `trap`, indented or not, inside a function or an `if`, one line or
several), also after a NAME=value prefix:

    <canonical|noncanonical> <file> <first line> <reason>

and one `account` line per region the lexer accounted for, so that the caller can compare it with a plain search for the
word `trap` and fail on any disagreement:

    account <file> <first line> <last line> <trap|heredoc|string|comment>

`trap` is a trap statement of any kind (INT, `-p`, ...); `heredoc` a here-document body (data); `string` a word on one
physical line that contains the word (but not as command text after `;`, `&&`, `||`, `|`, a backtick or `$(`);
`comment` a comment that does. A line with the word that none of these covers (for
example text swallowed by a quote that spans lines) is a disagreement.

Canonical means the whole statement is one physical line that starts at column 0 and is exactly
`trap '<action>' EXIT` (optionally `trap -- '<action>' EXIT`), with no trailing space, comment or second command.
fail-closed/run.sh probes and injects only canonical lines, so any other trap form must fail the suite instead of
slipping past it.

The lexer is a small one for the shell syntax these scripts use: quotes, backslash escapes and continuations, comments,
here-documents (their bodies are data) and command position after `;`, `&&`, `||`, `|`, `&`, `(`, `)`, newlines and
the reserved words that start a command. A `trap` inside `$( )` is still found. `<<` inside `$((`/`((` is a shift. The
here-document delimiter is the whole word with its quotes removed (`E"O"F` and `'E'OF` both mean EOF). A `$( )` inside
a double-quoted string is lexed with its own quotes (a quote inside it does not end the string). An unterminated quote,
`$( )` or here-document is an error. Unquoted or double-quoted backticks are unsupported and raise LexError, including
inside substitutions. Single-quoted or escaped backticks, comments and here-document bodies do not trigger this error.
Exit status 2 on a file it cannot read or lex.

Known limits (what no lexer-based inventory sees; fail-closed/run.sh's plain search for the word `trap` catches only
some of them, and none of them occurs in Tools/lint):
- `eval`: `eval "trap '...' EXIT"` and `eval "$cmd"` run a trap this scanner never sees as a statement. The text is one
  `string` account, which the plain search accepts silently.
- A trap built at run time (`T=trap; $T '...' EXIT`, `${T:-trap} '...' EXIT`, `command` or `builtin` with a variable)
  and a trap in a here-document or file that is later executed as a script: the word is data here.
- `SIGEXIT` is matched (as EXIT) although bash 3.2 does not accept it; the scanner is generous on purpose.
- Inside a double-quoted `$( )` the lexer counts parentheses and quotes only: a `case` pattern `a)` or a here-document
  with an unbalanced quote there ends the substitution at the wrong place (a wrong end is an error when the file
  runs out, otherwise the text is read as ordinary words). Backtick substitutions fail the scan with status 2 rather
  than risking quote desynchronisation across words or quote-split trap spellings.
- `$[ ... ]` (legacy arithmetic) is not tracked: a `<<` in it reads as a here-document (an error when never closed).
- Plain ANSI-C quoted here-document delimiters (`$'EOF'`) close on EOF. Escapes in these delimiters are unsupported
  and fail the scan with status 2.
"""

import re
import sys

KEEP_CMDPOS = {"then", "do", "else", "elif", "if", "while", "until", "{", "!", "time", "builtin", "command"}
CANONICAL = re.compile(r"^trap (-- )?'[^']*' EXIT$")
TRAP_WORD = re.compile(r"\btrap\b")
# Command-position text inside a raw word is not safe to account as a literal string.
# Backtick substitutions are rejected by the lexer before any string account can be emitted.
HIDDEN_TRAP = re.compile(r"(?:;|&&|\|\||\||`|\$\()\s*trap\b")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=")


class LexError(Exception):
    pass


def is_exit(signal):
    """EXIT in any case, SIGEXIT, or a number that is zero (0, 00): what a shell treats as the exit condition."""
    return signal.upper() in ("EXIT", "SIGEXIT") or (re.fullmatch(r"[0-9]+", signal) is not None and int(signal) == 0)


LINENO_ERR = "line %d: %s"


def lineno(text, i):
    return text.count("\n", 0, i) + 1


def skip_dq(text, i):
    """i is just after an opening double quote: the index just after the closing one. `$( )` inside is skipped whole."""
    n = len(text)
    start = i
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
        elif c == "`":
            raise LexError(LINENO_ERR % (lineno(text, i), "backtick substitution is unsupported"))
        elif c == '"':
            return i + 1
        elif c == "$" and text[i + 1 : i + 2] == "(":
            i = skip_paren(text, i + 1)
        else:
            i += 1
    raise LexError(LINENO_ERR % (lineno(text, start), "unterminated double quote"))


def skip_paren(text, i):
    """i is at the `(` of a `$(`: the index just after the matching `)`. Quotes, `$'..'`, comments and nested `$( )`
    are honoured; case patterns and here-documents are not (see the known limits)."""
    n = len(text)
    start = i
    depth = 0
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
        elif c == "'":
            j = text.find("'", i + 1)
            if j < 0:
                raise LexError(LINENO_ERR % (lineno(text, i), "unterminated single quote in $( )"))
            i = j + 1
        elif c == '"':
            i = skip_dq(text, i + 1)
        elif c == "$" and text[i + 1 : i + 2] == "'":
            i += 2
            while i < n and text[i] != "'":
                i += 2 if text[i] == "\\" else 1
            if i >= n:
                raise LexError(LINENO_ERR % (lineno(text, start), "unterminated $'...' string in $( )"))
            i += 1
        elif c == "`":
            raise LexError(LINENO_ERR % (lineno(text, i), "backtick substitution is unsupported"))
        elif c == "#" and text[i - 1 : i] in (" ", "\t", "\n", "("):
            while i < n and text[i] != "\n":
                i += 1
        else:
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
    raise LexError(LINENO_ERR % (lineno(text, start), "unterminated $( )"))


def heredoc_delimiter(text, i):
    """The here-document delimiter whose word starts at i: (delimiter, end). Bash takes the whole word with its quotes
    removed, so E"O"F, 'E'OF and EO\\F all mean EOF. Returns None when no word follows."""
    n = len(text)
    buf = []
    start = i
    while i < n:
        c = text[i]
        if c == "$" and text[i + 1 : i + 2] == "'":
            j = text.find("'", i + 2)
            if j < 0 or "\\" in text[i + 2 : j]:
                raise LexError(LINENO_ERR % (lineno(text, i), "unsupported escaped or unterminated ANSI-C delimiter"))
            buf.append(text[i + 2 : j])
            i = j + 1
        elif c == "\\":
            buf.append(text[i + 1 : i + 2])
            i += 2
        elif c == "'":
            j = text.find("'", i + 1)
            if j < 0:
                raise LexError(LINENO_ERR % (lineno(text, i), "unterminated single quote in a here-document delimiter"))
            buf.append(text[i + 1 : j])
            i = j + 1
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                if text[j] == "\\" and text[j + 1 : j + 2] in ('"', "\\", "$", "`"):
                    buf.append(text[j + 1])
                    j += 2
                else:
                    buf.append(text[j])
                    j += 1
            if j >= n:
                raise LexError(LINENO_ERR % (lineno(text, i), "unterminated double quote in a here-document delimiter"))
            i = j + 1
        elif c in " \t\n;|&()<>":
            break
        else:
            buf.append(c)
            i += 1
    if i == start:
        return None
    return "".join(buf), i


def lex(text):
    """Yield (kind, value, first line, offset, last line, raw) with kind word, op, heredoc or comment.

    'word' values have quotes removed; 'heredoc' covers the body and delimiter lines (value is the delimiter)."""
    i, n, line = 0, len(text), 1
    pending_heredocs = []  # (delimiter, tab-stripped, line of the operator)
    arith = 0  # open parentheses of the current $(( )) or (( )) (a here-document operator is a shift there)
    while i < n:
        c = text[i]
        if c == "\n":
            yield ("op", "\n", line, i, line, "\n")
            i += 1
            line += 1
            # here-document bodies start on the next line and are data
            for delim, strip, op_line in pending_heredocs:
                first, found = line, False
                while i < n:
                    j = text.find("\n", i)
                    j = n if j < 0 else j
                    body = text[i:j]
                    i = min(j + 1, n)
                    line += 1
                    if (body.lstrip("\t") if strip else body) == delim:
                        found = True
                        break
                if not found:
                    raise LexError("line %d: here-document with delimiter %r is never closed" % (op_line, delim))
                yield ("heredoc", delim, first, i, line - 1, "")
            pending_heredocs = []
            continue
        if c in " \t":
            i += 1
            continue
        if c == "\\" and text[i + 1 : i + 2] == "\n":
            i += 2
            line += 1
            continue
        if c == "#":
            start = i
            while i < n and text[i] != "\n":
                i += 1
            yield ("comment", text[start:i], line, start, line, text[start:i])
            continue
        if c in ";|&()":
            if c == "(" and not arith and text[i + 1 : i + 2] == "(":
                arith = 2
                yield ("op", "((", line, i, line, "((")
                i += 2
                continue
            if arith and c == "(":
                arith += 1
            elif arith and c == ")":
                arith -= 1
            j = i + 1
            if c in "|&;" and text[j : j + 1] == c:
                j += 1
            yield ("op", text[i:j], line, i, line, text[i:j])
            i = j
            continue
        # a word: runs to unquoted whitespace or an operator character
        start, start_line, buf = i, line, []
        while i < n:
            c = text[i]
            if c == "\\":
                if text[i + 1 : i + 2] == "\n":
                    i += 2
                    line += 1
                    continue
                buf.append(text[i + 1 : i + 2])
                i += 2
                continue
            if c == "`":
                raise LexError("line %d: backtick substitution is unsupported" % line)
            if c == "'":
                j = text.find("'", i + 1)
                if j < 0:
                    raise LexError("line %d: unterminated single quote" % line)
                buf.append(text[i + 1 : j])
                line += text.count("\n", i, j)
                i = j + 1
                continue
            if c == '"':
                q_line = line
                i += 1
                while i < n and text[i] != '"':
                    if text[i] == "\\" and i + 1 < n:
                        buf.append(text[i + 1])
                        line += text[i + 1] == "\n"
                        i += 2
                        continue
                    if text[i] == "`":
                        raise LexError("line %d: backtick substitution is unsupported" % line)
                    if text[i] == "$" and text[i + 1 : i + 2] == "(":
                        j = skip_paren(text, i + 1)  # the substitution has its own quotes
                        buf.append(text[i:j])
                        line += text.count("\n", i, j)
                        i = j
                        continue
                    line += text[i] == "\n"
                    buf.append(text[i])
                    i += 1
                if i >= n:
                    raise LexError("line %d: unterminated double quote" % q_line)
                i += 1
                continue
            if c == "$" and text[i + 1 : i + 2] == "'":
                j = i + 2
                while j < n and text[j] != "'":
                    j += 2 if text[j] == "\\" else 1
                if j >= n:
                    raise LexError("line %d: unterminated $'...' string" % line)
                buf.append(text[i + 2 : j])
                line += text.count("\n", i, j)
                i = j + 1
                continue
            if c in " \t\n;|&()":
                break
            if c == "<" and text[i : i + 2] == "<<" and text[i : i + 3] != "<<<" and text[i - 1 : i] != "<" and not arith:
                # here-document operator (outside an arithmetic expression `<<` is always a redirection, even in `cat<<X`; the
                # second and third `<` of a here-string `<<<` are not one): the delimiter is the next word, quotes removed
                j = i + 2
                strip = text[j : j + 1] == "-"
                j += strip
                while text[j : j + 1] in (" ", "\t"):
                    j += 1
                got = heredoc_delimiter(text, j)
                if got:
                    pending_heredocs.append((got[0], strip, line))
                    buf.append(text[i : got[1]])
                    i = got[1]
                    continue
            buf.append(c)
            i += 1
        yield ("word", "".join(buf), start_line, start, line, text[start:i])


def scan(path):
    """Return (traps, accounts): traps are (kind, path, first line, reason), accounts (first, last, what)."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    lines = text.split("\n")
    line_start = [0]
    for ln in lines:
        line_start.append(line_start[-1] + len(ln) + 1)
    found = []
    accounts = []
    cmdpos = True
    stmt = None  # [first line, offset, words, last token offset, last token's last line]

    def finish():
        nonlocal stmt
        if stmt is None:
            return
        first, off, words, last_off, end_line = stmt
        stmt = None
        accounts.append((first, end_line, "trap"))
        args = words[:]
        while args and args[0].startswith("-") and args[0] != "-":
            opt = args.pop(0)
            if opt == "--":
                break
            if opt in ("-p", "-l"):
                return  # prints traps, sets none
        signals = args[1:]
        reasons = []
        if len(args) == 1 and is_exit(args[0]):
            # `trap EXIT`: one argument that is a signal resets it, which removes the fail-closed handler
            signals = args
            reasons.append("one argument: resets the EXIT trap")
        elif not any(is_exit(s) for s in signals):
            return
        # the physical line that holds the statement's last token, to its end (trailing space and comments included)
        raw_first = lines[first - 1]
        if end_line != first:
            reasons.append("spans several lines")
        if off != line_start[first - 1]:
            reasons.append("indented or preceded by another word on its line")
        if signals != ["EXIT"] and not (len(args) == 1 and signals == args):
            reasons.append("signals are %s, not exactly EXIT" % " ".join(signals))
        if not CANONICAL.match(raw_first):
            if raw_first != raw_first.rstrip():
                reasons.append("trailing whitespace")
            elif re.search(r"\s#", raw_first):
                reasons.append("trailing comment")
            elif not reasons:
                reasons.append("not exactly trap '<action>' EXIT on one line")
        found.append(("noncanonical" if reasons else "canonical", path, first, "; ".join(reasons) or "ok"))

    for kind, value, line, off, end_line, raw in lex(text):
        if kind == "heredoc":
            accounts.append((line, end_line, "heredoc"))
            continue
        if kind == "comment":
            if TRAP_WORD.search(value):
                accounts.append((line, line, "comment"))
            continue
        if kind == "op":
            finish()
            cmdpos = True
            continue
        if kind == "word" and line == end_line and TRAP_WORD.search(raw) and not HIDDEN_TRAP.search(raw):
            accounts.append((line, line, "string"))
        if stmt is not None:
            stmt[2].append(value)
            stmt[3], stmt[4] = off, end_line
            continue
        if cmdpos and value == "trap":
            stmt = [line, off, [], off, end_line]
            cmdpos = False
            continue
        if cmdpos and ASSIGNMENT.match(value):
            continue  # NAME=value prefix: the next word is still the command
        cmdpos = value in KEEP_CMDPOS
    finish()
    return found, accounts


def main(argv):
    status = 0
    for path in argv:
        try:
            found, accounts = scan(path)
        except (OSError, UnicodeDecodeError) as exc:
            print("trap_scan: %s" % exc, file=sys.stderr)
            status = 2
        except LexError as exc:
            print("trap_scan: %s: %s" % (path, exc), file=sys.stderr)
            status = 2
        else:
            for kind, p, first, reason in found:
                print("%s\t%s\t%d\t%s" % (kind, p, first, reason))
            for first, last, what in accounts:
                print("account\t%s\t%d\t%d\t%s" % (path, first, last, what))
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
