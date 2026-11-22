# SPDX-License-Identifier: MIT
"""Fail-closed check of the tracked docs source: it must exist, be non-empty,
cite only repo paths that exist and contain only relative link targets that
resolve. Python stdlib only.

Supported forms, exactly:
- inline links and images, with or without a title in any quote form
  ("t", 't', (t));
- angle-bracket destinations (<a b.md>) in inline links and definitions;
- full ([text][label]), collapsed ([label][]) and shortcut ([label]) reference
  links and their definitions ([label]: target), with or without a title; a
  full or collapsed link must use a defined label, and a shortcut link takes
  its target from its definition (an undefined shortcut is plain text);
- backticked repo-path citations: words under an existing top-level entry,
  under any hidden root (.githooks/..., .github/...) and every explicitly
  relative word (./x, ../x).

Each form is recognised at top level and inside blockquotes (any depth) and
list items: container markers are stripped before scanning, keeping line
numbers. Fenced and indented code blocks are ignored. URLs with a scheme,
protocol-relative URLs and fragment-only targets are skipped; a fragment's
file part must exist. Raw HTML and autolinks (<https://...>) are out of
scope.

Contract (DEC-003). The checker reads a strict subset of CommonMark. A
construct it cannot settle is rejected with the file, the line and the plain
rewrite; an ambiguous construct is an error, never a silent pass.
Parsed: lines end at LF, CRLF or CR only, and a blank line holds only spaces
and tabs; only "1." or a bullet with content interrupts a paragraph, and a
list item may open with indented code; backslash escapes are read left to
right (an escaped backslash leaves the next character live), are never
brackets, parentheses or backticks, and are decoded before a destination is
resolved; code spans are found on their own line, before link destinations;
full and collapsed labels may span lines and match after folding case and
runs of spaces, tabs and line ends only, and a [^label] there is an ordinary
label; a target or citation ending in "/" must be a directory and every
component of a path must be a directory; a citation is checked literally in
any alphabet, with * and ? as a glob that must match something, and a code
span that is one existing path with spaces passes whole; any root that starts
with "." is hidden; *.md and *.markdown files count in any letter case. A bare
file name (no "/") is not a citation; cite a top-level file as ./NAME. In a
code span that starts with an absolute path (/ or ~), a word after a space
continues that path and needs no repo root.
Rejected as unsupported style, with the rewrite: a backtick run with no
partner on its line (keep a code span on one line, or escape the backtick);
a backtick in a link destination (percent-encode it as %60); a character
reference such as &copy; in a link destination (write the character, or
percent-encode it); a reference definition that continues a paragraph (put a
blank line before it); a reference definition whose label spans lines (write
the label on one line); a line that starts like a definition ([label]:) but
does not parse as one, including a title over several lines (write
[label]: target "title" with the title on one line); quotes or punctuation
inside the backticks around a cited path (move them outside, or cite the path
alone); and a file-like path (a final segment with an extension, or a
trailing "/") whose plain first segment is not in the repo (cite it from its
top-level directory, or write a non-repo path from its bundle or domain, or
as <sys/x.h>)."""
import argparse
import glob
import os
from pathlib import Path
import re
import sys
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[2]
IGNORED_NAMES = {".gitkeep", ".DS_Store"}
MARKDOWN_SUFFIXES = {".md", ".markdown"}
TOP_LEVEL = {p.name for p in ROOT.iterdir() if not p.name.startswith(".")}
FENCE_OPEN = re.compile(r"^ {0,3}(`{3,}|~{3,})")
FENCE_CLOSE = re.compile(r"^ {0,3}(`{3,}|~{3,})[ \t]*$")
QUOTE = re.compile(r"^ {0,3}> ?")
LIST_MARKER = re.compile(r"^( {0,3})([-*+]|(\d{1,9})[.)])( +|$)")
THEMATIC = re.compile(r"^ {0,3}([-*_])(?:[ \t]*\1){2,}[ \t]*$")
ATX = re.compile(r"^ {0,3}#{1,6}([ \t]|$)")
PUNCT = frozenset("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
MASK = "\x01"
REF_DEF = re.compile(
    r"^ {0,3}\[([^\[\]\n]+)\]:[ \t]*\n?[ \t]*(<[^<>\n]*>|[^ \t\n]+)"
    r"(?:[ \t]*\n?[ \t]*(\"[^\"\n]*\"|'[^'\n]*'|\([^()\n]*\)))?[ \t]*$",
    re.M,
)
DEF_LIKE = re.compile(r"^ {0,3}\[(?!\^)[^\]\n]*\]:", re.M)
DEF_MULTILINE = re.compile(r"^ {0,3}\[[^\[\]]*\n[^\[\]]*\]:", re.M)
FULL_REF = re.compile(r"\]\[([^\[\]]*)\]")
ENTITY = re.compile(r"&(?:#[0-9]{1,7}|#[xX][0-9A-Fa-f]{1,6}|[A-Za-z][A-Za-z0-9]{0,31});")
SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
LINE_SUFFIX = re.compile(r"(:\d+(-\d+)?(:\d+)?|#L\d+(-L?\d+)?)$")
MD_SPACE = re.compile(r"[ \t\n]+")
PLAIN_ROOT = re.compile(r"^[\w-]+$")
EXTENSION = re.compile(r"\.[A-Za-z][A-Za-z0-9]*$")
LEAD = "\"'([{"
TRAIL = "\"')]},.;:"


def is_blank(line):
    return not line.strip(" \t")


def indent_width(line):
    return len(line) - len(line.lstrip(" "))


def open_containers(rest, para):
    """Strip new blockquote and list-item markers from the start of rest.
    Return (containers, rest): "q" for a blockquote, an int content indent
    for a list item. With para set the line would continue a paragraph, so
    only "1." or a bullet with content may open a list item there."""
    new = []
    while not THEMATIC.match(rest):
        match = QUOTE.match(rest)
        if match:
            new.append("q")
            rest = rest[match.end():]
            para = False
            continue
        match = LIST_MARKER.match(rest)
        if not match:
            break
        body = rest[match.end():]
        if para and (is_blank(body) or (match.group(3) and int(match.group(3)) != 1)):
            break
        width = len(match.group(1)) + len(match.group(2))
        if is_blank(body):
            new.append(width + 1)
            rest = ""
        elif len(match.group(4)) > 4:
            new.append(width + 1)
            rest = rest[width + 1 :]
        else:
            new.append(width + len(match.group(4)))
            rest = body
        para = False
    return new, rest


def normalise_blocks(text):
    """Return (lines, cont): one line per input line with blockquote markers
    and list-item indentation stripped and fenced and indented code emptied,
    so every form is scanned the same way in any container and line numbers
    survive; cont[i] is true when line i continues a paragraph.

    A light CommonMark block pass: a line continues each open container it
    matches (">" for a quote, the content indent for a list item), may open
    new ones, and otherwise closes the unmatched ones unless it lazily
    continues a paragraph. A fence ends at its closing fence or when its
    container closes; indented code cannot interrupt a paragraph."""
    out = []
    cont = []
    stack = []
    fence = None
    code_stack = None
    para = False
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        rest = raw.expandtabs(4)
        matched = 0
        for container in stack:
            if container == "q":
                match = QUOTE.match(rest)
                if not match:
                    break
                rest = rest[match.end():]
            elif is_blank(rest):
                rest = ""
            elif indent_width(rest) >= container:
                rest = rest[container:]
            else:
                break
            matched += 1
        if fence:
            if matched == len(stack):
                close = FENCE_CLOSE.match(rest)
                if close and close.group(1)[0] == fence[0] and len(close.group(1)) >= len(fence):
                    fence = None
                out.append("")
                cont.append(False)
                continue
            fence = None
        new, rest = open_containers(rest, para and matched == len(stack))
        lazy = (
            not new
            and matched < len(stack)
            and para
            and not is_blank(rest)
            and not FENCE_OPEN.match(rest)
            and not THEMATIC.match(rest)
            and not ATX.match(rest)
        )
        if not lazy:
            del stack[matched:]
        stack.extend(new)
        cont.append(para and not new)
        if is_blank(rest):
            para = False
            out.append("")
            continue
        if code_stack == stack and indent_width(rest) >= 4:
            out.append("")
            continue
        code_stack = None
        if indent_width(rest) >= 4 and not lazy and (not para or new):
            code_stack = list(stack)
            out.append("")
            continue
        match = FENCE_OPEN.match(rest)
        if match and not (match.group(1)[0] == "`" and "`" in rest[match.end():]):
            fence = match.group(1)
            para = False
            out.append("")
            continue
        para = not (THEMATIC.match(rest) or ATX.match(rest))
        out.append(rest)
    return out, cont


def scan_inline(line):
    """Read one block line left to right. Return (code, struct, spans,
    unpaired): code masks backslash escapes, struct also blanks code spans,
    spans holds each code span's content and unpaired the column of each
    backtick run with no partner on the line. Escapes do not apply inside a
    code span; an escaped backtick opens nothing."""
    code = list(line)
    struct = list(line)
    spans = []
    unpaired = []
    i, n = 0, len(line)
    while i < n:
        if line[i] == "\\" and i + 1 < n and line[i + 1] in PUNCT:
            code[i] = code[i + 1] = struct[i] = struct[i + 1] = MASK
            i += 2
            continue
        if line[i] != "`":
            i += 1
            continue
        j = i
        while j < n and line[j] == "`":
            j += 1
        run, k, close = j - i, j, -1
        while k < n:
            if line[k] != "`":
                k += 1
                continue
            m = k
            while m < n and line[m] == "`":
                m += 1
            if m - k == run:
                close = k
                break
            k = m
        if close < 0:
            unpaired.append(i)
            i = j
            continue
        spans.append(line[j:close])
        for p in range(i, close + run):
            struct[p] = " "
        i = close + run
    return "".join(code), "".join(struct), spans, unpaired


def blank(text, start, end):
    """Replace text[start:end] with spaces, keeping newlines."""
    return text[:start] + re.sub(r"[^\n]", " ", text[start:end]) + text[end:]


def line_of(text, offset):
    return text.count("\n", 0, offset) + 1


def path_exists(base, rel, globs=False):
    """True when rel exists under base. The OS resolves the joined string, so
    a trailing "/" needs a directory and every component must be one; with
    globs, * and ? make rel a glob that must match."""
    if globs and ("*" in rel or "?" in rel):
        pattern = glob.escape(str(base)) + "/" + rel.replace("[", "[[]")
        return bool(glob.glob(pattern, recursive=True))
    return os.path.exists(os.path.join(str(base), rel))


def citation_bases(core, doc):
    """Return the base directories a citation core resolves against, "rootless"
    for a file-like path whose plain first segment is not in the repo, or None
    when the word is not a repo-path citation."""
    if "/" not in core or core.startswith(("/", "~", "$", "-")) or "://" in core:
        return None
    first = core.split("/", 1)[0]
    if first == ".":
        return [ROOT, doc.parent]
    if first == "..":
        return [doc.parent]
    if first.startswith(".") or first in TOP_LEVEL:
        return [ROOT]
    if PLAIN_ROOT.match(first) and (core.endswith("/") or EXTENSION.search(core.rsplit("/", 1)[-1])):
        return "rootless"
    return None


def word_problem(word, doc, absolute=False):
    """Return a problem string for one code-span word, or None. In a span
    that starts with an absolute path, a rootless word continues that path."""
    stripped = word.lstrip(LEAD).rstrip(TRAIL)
    core = LINE_SUFFIX.sub("", stripped)
    bases = citation_bases(core, doc)
    if bases is None:
        return None
    if stripped != word:
        return (
            f"unsupported style: punctuation inside the backticks around cited path {word}; "
            "move quotes, brackets and punctuation outside the backticks or cite the path alone"
        )
    if bases == "rootless":
        if absolute:
            return None
        return (
            f"unsupported style: path has no repo root: {word}; cite it from its top-level "
            "directory, or write a non-repo path from its bundle or domain, or as <sys/x.h>"
        )
    rel = core[2:] if core.startswith("./") else core
    if not any(path_exists(base, rel, globs=True) for base in bases):
        return f"cited path does not exist: {core}"
    return None


def span_problems(content, doc):
    """Return the problems of the citations in one code span's content."""
    if len(content) > 2 and content[0] == " " and content[-1] == " ":
        content = content[1:-1]
    words = [w for w in MD_SPACE.split(content) if w]
    if len(words) > 1:
        whole = content.strip(" \t")
        bases = citation_bases(LINE_SUFFIX.sub("", whole), doc)
        if isinstance(bases, list):
            core = LINE_SUFFIX.sub("", whole)
            rel = core[2:] if core.startswith("./") else core
            if any(path_exists(base, rel, globs=True) for base in bases):
                return []
    absolute = content.lstrip(" \t").startswith(("/", "~"))
    return [p for p in (word_problem(w, doc, absolute) for w in words) if p]


def decode_destination(raw):
    """Return (destination, problem) for a raw link destination: backslash
    escapes decoded, a backtick or a character reference rejected."""
    if raw.startswith("<") and raw.endswith(">"):
        raw = raw[1:-1]
    out = []
    i = 0
    while i < len(raw):
        c = raw[i]
        if c == "\\" and i + 1 < len(raw) and raw[i + 1] in PUNCT:
            out.append(raw[i + 1])
            i += 2
            continue
        if c == "`":
            return None, (
                f"unsupported style: backtick in link destination: {raw}; percent-encode it as %60"
            )
        if c == "&" and ENTITY.match(raw, i):
            return None, (
                f"unsupported style: character reference in link destination: {raw}; "
                "write the character or percent-encode it"
            )
        out.append(c)
        i += 1
    return "".join(out), None


def target_problem(raw, doc):
    """Return a problem string for a raw link destination, or None when it
    resolves or is out of scope (scheme, protocol-relative, fragment-only)."""
    target, problem = decode_destination(raw)
    if problem:
        return problem
    if not target:
        return "empty link target"
    if SCHEME.match(target) or target.startswith(("//", "#")):
        return None
    path = unquote(target.split("#", 1)[0].split("?", 1)[0])
    if not path:
        return None
    if path.startswith("/"):
        return f"absolute link target: {target}"
    if not path_exists(doc.parent, path):
        return f"relative link does not resolve: {path}"
    return None


def parse_inline(text, start):
    """Parse an inline destination and title after the "](" at start, on a
    view with escapes masked. Return (dest_start, dest_end) or None."""
    i = start + 2
    n = len(text)

    def skip_ws(i):
        newline = False
        while i < n and text[i] in " \t\n":
            if text[i] == "\n":
                if newline:
                    return None
                newline = True
            i += 1
        return i

    i = skip_ws(i)
    if i is None:
        return None
    if i < n and text[i] == "<":
        j = i + 1
        while j < n and text[j] not in "<>\n":
            j += 1
        if j >= n or text[j] != ">":
            return None
        span, i = (i, j + 1), j + 1
    else:
        depth, j = 0, i
        while j < n and text[j] not in " \t\n":
            if text[j] == "(":
                depth += 1
            elif text[j] == ")":
                if depth == 0:
                    break
                depth -= 1
            j += 1
        span, i = (i, j), j
    after = skip_ws(i)
    if after is None:
        return None
    if after < n and text[after] in "\"'(" and after > i:
        close = ")" if text[after] == "(" else text[after]
        j = text.find(close, after + 1)
        if j < 0 or re.search(r"\n[ \t]*\n", text[after:j]):
            return None
        after = skip_ws(j + 1)
        if after is None:
            return None
    if after < n and text[after] == ")":
        return span
    return None


def opening_bracket(text, close):
    """Return the index of the "[" matching the "]" at close, or -1."""
    depth = 0
    for k in range(close, -1, -1):
        if text[k] == "]":
            depth += 1
        elif text[k] == "[":
            depth -= 1
            if depth == 0:
                return k
    return -1


def normalise(label):
    """Fold a label as CommonMark does: case, and runs of spaces, tabs and
    line ends (no other whitespace)."""
    return MD_SPACE.sub(" ", label.strip(" \t\n")).casefold()


def check_file(path, errors):
    lines, cont = normalise_blocks(path.read_text(encoding="utf-8"))
    code_lines, struct_lines = [], []
    for number, line in enumerate(lines, 1):
        code, struct, spans, unpaired = scan_inline(line)
        code_lines.append(code)
        struct_lines.append(struct)
        if unpaired:
            errors.append(
                f"{path}:{number}: unsupported style: unpaired backtick; keep a code span on "
                "one line or escape the backtick"
            )
        for content in spans:
            for problem in span_problems(content, path):
                errors.append(f"{path}:{number}: {problem}")
    orig = "\n".join(lines)
    code = "\n".join(code_lines)
    struct = "\n".join(struct_lines)

    labels = set()
    def_lines = set()
    for match in list(REF_DEF.finditer(code)):
        label = orig[match.start(1) : match.end(1)]
        if label.startswith("^") or is_blank(label):
            continue
        first = line_of(code, match.start())
        last = line_of(code, match.end())
        code = blank(code, match.start(), match.end())
        if cont[first - 1] and first - 1 not in def_lines:
            errors.append(
                f"{path}:{first}: unsupported style: reference definition continues a "
                "paragraph; put a blank line before it"
            )
            continue
        def_lines.update(range(first, last + 1))
        labels.add(normalise(label))
        struct = blank(struct, match.start(), match.end())
        problem = target_problem(orig[match.start(2) : match.end(2)], path)
        if problem:
            errors.append(f"{path}:{line_of(code, match.start(2))}: {problem}")
    for match in DEF_MULTILINE.finditer(code):
        if re.search(r"\n[ \t]*\n", match.group()):
            continue
        errors.append(
            f"{path}:{line_of(code, match.start())}: unsupported style: reference definition "
            "label spans lines; write [label]: target with the label on one line"
        )
    for match in DEF_LIKE.finditer(code):
        errors.append(
            f"{path}:{line_of(code, match.start())}: unsupported style: unparsed reference "
            'definition; write [label]: target "title" with the title on one line'
        )

    for match in re.finditer(r"\]\(", struct):
        if opening_bracket(struct, match.start()) < 0:
            continue
        number = line_of(struct, match.start())
        span = parse_inline(code, match.start())
        if span is None:
            errors.append(f"{path}:{number}: malformed inline link or image")
            continue
        problem = target_problem(orig[span[0] : span[1]], path)
        if problem:
            errors.append(f"{path}:{number}: {problem}")

    for match in FULL_REF.finditer(struct):
        if re.search(r"\n[ \t]*\n", match.group(1)):
            continue
        label = orig[match.start(1) : match.end(1)]
        if is_blank(label.replace("\n", "")):
            opening = opening_bracket(struct, match.start())
            if opening < 0:
                continue
            label = orig[opening + 1 : match.start()]
        if normalise(label) not in labels:
            number = line_of(struct, match.start())
            errors.append(f"{path}:{number}: undefined reference label: {normalise(label)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--docs", type=Path, default=ROOT / "docs")
    args = parser.parse_args()
    docs = args.docs.resolve()
    if not docs.is_dir():
        print(f"docs-check: FAIL; docs source missing: {args.docs}", file=sys.stderr)
        return 1
    files = sorted(p for p in docs.rglob("*") if p.is_file() and p.name not in IGNORED_NAMES)
    markdown = [p for p in files if p.suffix.lower() in MARKDOWN_SUFFIXES]
    if not markdown or not any(p.stat().st_size for p in markdown):
        print(f"docs-check: FAIL; docs source empty: {args.docs}", file=sys.stderr)
        return 1
    errors = []
    for path in markdown:
        check_file(path, errors)
    if errors:
        for error in errors:
            print(f"docs-check: {error}", file=sys.stderr)
        print(f"docs-check: FAIL; {len(errors)} problem(s)", file=sys.stderr)
        return 1
    print(f"docs-check: ok ({len(markdown)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
