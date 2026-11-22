#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Regression tests for Tools/docs/check.py. Every negative fixture must exit
# non-zero with its diagnostic and never print "skipped": a missing or empty
# source, each dangling citation form and each broken link, image or reference
# form, each at top level and inside blockquotes, list items and nested
# containers. Each DEC-003 bypass class
# has a negative fixture in every container form. The positive fixtures show
# the valid forms, code blocks and skipped targets pass at top level and
# inside containers; the tracked docs/ source must pass.
# Fixture bodies are literal Markdown; their backticks must not expand.
# shellcheck disable=SC2016
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CHECK=(python3 -I "$ROOT/Tools/docs/check.py")
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wgex-docs-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

expect_ok() { # <label> <docs-dir>
  if out="$("${CHECK[@]}" --docs "$2" 2>&1)" && ! grep -qi skipped <<<"$out"; then
    echo "ok: $1"
  else
    echo "FAIL: $1: $out" >&2
    exit 1
  fi
}
expect_fail() { # <label> <docs-dir> <expected text>
  local rc=0
  out="$("${CHECK[@]}" --docs "$2" 2>&1)" || rc=$?
  if ((rc == 0)); then
    echo "FAIL: $1: accepted" >&2
    exit 1
  fi
  if grep -qi skipped <<<"$out"; then
    echo "FAIL: $1: printed skipped" >&2
    exit 1
  fi
  if ! grep -qF -- "$3" <<<"$out"; then
    echo "FAIL: $1: missing '$3' in: $out" >&2
    exit 1
  fi
  echo "ok: $1 (exit $rc)"
}
N=0
NAME=a.md   # file the fixture body goes into
EXTRA=      # optional extra file next to it
fixture() { # <label> <markdown body> <expected text>; body starts on line 3
  N=$((N + 1))
  mkdir -p "$WORK/neg$N/docs"
  printf '# Fixture\n\n%s\n' "$2" >"$WORK/neg$N/docs/$NAME"
  printf '# Present\n' >"$WORK/neg$N/docs/b.md"
  if [[ -n $EXTRA ]]; then printf 'x\n' >"$WORK/neg$N/docs/$EXTRA"; fi
  expect_fail "$1" "$WORK/neg$N/docs" "$3"
}
quote() { printf '> %s\n' "${1//$'\n'/$'\n'> }"; }  # blockquote
item() { sed '1s/^/- /; 2,$s/^/  /' <<<"$1"; }      # list item, continuation indented
ordered() { sed '1s/^/1. /; 2,$s/^/   /' <<<"$1"; } # ordered list item
negative() {                                        # <label> <markdown body> <expected text>; every container form
  fixture "$1" "$2" "$3"
  fixture "$1, blockquote" "$(quote "$2")" "$3"
  fixture "$1, nested blockquote" "$(quote "$(quote "$2")")" "$3"
  fixture "$1, list item" "$(item "$2")" "$3"
  fixture "$1, ordered list item" "$(ordered "$2")" "$3"
  fixture "$1, quote in list item" "$(item "$(quote "$2")")" "$3"
  fixture "$1, list item in quote" "$(quote "$(item "$2")")" "$3"
}

expect_ok "tracked docs source passes" "$ROOT/docs"

expect_fail "missing source" "$WORK/absent" "docs source missing"
mkdir "$WORK/empty"
expect_fail "empty directory" "$WORK/empty" "docs source empty"
: >"$WORK/empty/README.md"
expect_fail "zero-byte files only" "$WORK/empty" "docs source empty"

# Valid forms pass; code blocks and out-of-scope targets are ignored.
mkdir -p "$WORK/good/docs/sub"
printf '# B\n' >"$WORK/good/docs/b.md"
printf '# C\n' >"$WORK/good/docs/b c.md"
printf 'png' >"$WORK/good/docs/img.png"
printf '# Parens\n' >"$WORK/good/docs/c().md"
printf '# Sib\n' >"$WORK/good/sibling.md"
cat >"$WORK/good/docs/a.md" <<'MD'
# Good

Cites `Tools/docs/check.py`, `./Tools/docs/check.py`, `Tools/docs/check.py:12`,
`.githooks/pre-commit`, `../sibling.md`, `Tools/docs/**` and
`python3 -I Tools/docs/check.py`; prose like `iOS/tvOS` is no citation.

[plain](b.md) [double](b.md "t") [single](b.md 't') [paren](b.md (t))
![image](img.png "t") [angle](<b c.md>) [angle titled](<b c.md> 't')
[fragment](b.md#section) [query](b.md?x=1) [encoded](b%20c.md)
[[nested] text](b.md) [![badge](img.png)](b.md) [`code`](b.md)
[url](https://example.org/x) [mail](mailto:someone@example.org)
[proto](//example.org/x) [frag](#local) [up](../sibling.md)
[escaped](c\(\).md) [escaped hash](b.md\#x) and a literal \` backtick,
\\`Tools/docs/check.py` after an escaped backslash, `./b c.md` whole,
`/Library/Application Support/WGEX/profiles/` absolute, `<sys/kern_control.h>`,
`WGEX.app/Contents/Helpers/` and `Tools/docs/` as a directory; [multi][line
label] spans lines.

[full][one] [collapsed][] [Shortcut] [Two]
[^note] and [plain brackets] and [ ] stay text.

[one]: b.md
[collapsed]: <b c.md> "t"
[shortcut]: b.md 't'
[two]: sub/../b.md (t)
[line label]: b.md
[^note]: a footnote, not a link target

```text
[gone](missing-in-fence.md) `Tools/absent-in-fence`
```

~~~~
[gone](missing-in-tilde-fence.md)
~~~~

    [gone](missing-in-indented-code.md) `Tools/absent-indented`

- list item
    continuation [list](b.md) cites `Tools/docs`
MD
expect_ok "valid forms pass" "$WORK/good/docs"

# The same valid forms pass inside every container, and code blocks inside
# containers stay ignored.
mkdir -p "$WORK/goodbox/docs/sub"
cp "$WORK/good/docs/b.md" "$WORK/good/docs/b c.md" "$WORK/good/docs/img.png" "$WORK/good/docs/c().md" \
  "$WORK/goodbox/docs/"
cp "$WORK/good/sibling.md" "$WORK/goodbox/"
FORMS="$(sed -n '3,/^\[\^note\]: /p' "$WORK/good/docs/a.md")"
{
  printf '# Containers\n\n%s\n\n' "$(quote "$FORMS")"
  printf '%s\n\n' "$(quote "$(quote "$FORMS")")"
  printf '%s\n\n' "$(item "$FORMS")"
  printf '%s\n\n' "$(ordered "$FORMS")"
  printf '%s\n\n' "$(item "$(quote "$FORMS")")"
  printf '%s\n\n' "$(quote "$(item "$FORMS")")"
  cat <<'MD'
> ```text
> [gone](missing-in-quoted-fence.md) `Tools/absent-in-quoted-fence`
> ```
>
>     [gone](missing-in-quoted-indented-code.md)

- item
  ```
  [gone](missing-in-item-fence.md)
  ```

      [gone](missing-in-item-indented-code.md)

> lazy [continuation](b.md)
of a quoted paragraph [ok](b.md)

1. first
2. sibling [item](b.md)
MD
} >"$WORK/goodbox/docs/a.md"
expect_ok "valid forms pass inside containers" "$WORK/goodbox/docs"

# Citations.
negative "dangling citation" 'Cites `Engine/go/absent/thing`.' \
  "cited path does not exist: Engine/go/absent/thing"
negative "dangling ./ citation, existing root" 'Cites `./Engine/go/absent/thing`.' \
  "cited path does not exist: ./Engine/go/absent/thing"
negative "dangling ./ citation, absent root" 'Cites `./absent-directory/file.md`.' \
  "cited path does not exist: ./absent-directory/file.md"
negative "dangling ../ citation" 'Cites `../absent-directory/file.md`.' \
  "cited path does not exist: ../absent-directory/file.md"
negative "dangling hidden-root citation" 'Cites `.githooks/absent-hook`.' \
  "cited path does not exist: .githooks/absent-hook"
negative "dangling absent hidden root" 'Cites `.github/workflows/absent.yml`.' \
  "cited path does not exist: .github/workflows/absent.yml"
negative "dangling line-suffixed citation" 'Cites `Tools/docs/absent.py:12`.' \
  "cited path does not exist: Tools/docs/absent.py"
negative "dangling citation inside a command" 'Run `python3 -I Tools/docs/absent.py`.' \
  "cited path does not exist: Tools/docs/absent.py"
negative "dangling glob prefix" 'Owns `Tools/absent-directory/**`.' \
  "cited path does not exist: Tools/absent-directory/**"

# Inline links and images.
negative "broken link" '[gone](missing.md)' "relative link does not resolve: missing.md"
negative "broken link, double-quoted title" '[gone](missing.md "t")' \
  "relative link does not resolve: missing.md"
negative "broken link, single-quoted title" "[gone](missing.md 't')" \
  "relative link does not resolve: missing.md"
negative "broken link, parenthesised title" '[gone](missing.md (t))' \
  "relative link does not resolve: missing.md"
negative "broken image" '![gone](missing.png)' "relative link does not resolve: missing.png"
negative "broken image, double-quoted title" '![gone](missing.png "t")' \
  "relative link does not resolve: missing.png"
negative "broken image, single-quoted title" "![gone](missing.png 't')" \
  "relative link does not resolve: missing.png"
negative "broken image, parenthesised title" '![gone](missing.png (t))' \
  "relative link does not resolve: missing.png"
negative "broken angle-bracket destination" '[gone](<missing file.md>)' \
  "relative link does not resolve: missing file.md"
negative "broken angle-bracket destination, title" "[gone](<missing file.md> 't')" \
  "relative link does not resolve: missing file.md"
negative "broken fragment file part" '[gone](missing.md#section)' \
  "relative link does not resolve: missing.md"
negative "broken link inside nested image link" '[![badge](missing.png)](b.md)' \
  "relative link does not resolve: missing.png"
negative "absolute link target" '[gone](/b.md)' "absolute link target: /b.md"
negative "empty link target" '[gone]()' "empty link target"
negative "malformed inline link" '[gone](missing.md "unterminated)' \
  "malformed inline link or image"

# Reference definitions and labels.
negative "broken definition" $'[gone][x]\n\n[x]: missing.md' \
  "relative link does not resolve: missing.md"
negative "broken definition, double-quoted title" $'[gone][x]\n\n[x]: missing.md "t"' \
  "relative link does not resolve: missing.md"
negative "broken definition, single-quoted title" $'[gone][x]\n\n[x]: missing.md \'t\'' \
  "relative link does not resolve: missing.md"
negative "broken definition, parenthesised title" $'[gone][x]\n\n[x]: missing.md (t)' \
  "relative link does not resolve: missing.md"
negative "broken angle-bracket definition" $'[gone][x]\n\n[x]: <missing file.md>' \
  "relative link does not resolve: missing file.md"
negative "broken collapsed reference definition" $'[x][]\n\n[x]: missing.md' \
  "relative link does not resolve: missing.md"
negative "broken shortcut reference definition" $'[x]\n\n[x]: missing.md' \
  "relative link does not resolve: missing.md"
negative "broken multi-line definition" $'[x]\n\n[x]:\n  missing.md\n  "t"' \
  "relative link does not resolve: missing.md"
negative "undefined full reference label" '[gone][nowhere]' \
  "undefined reference label: nowhere"
negative "undefined collapsed reference label" '[nowhere][]' \
  "undefined reference label: nowhere"

# Container ends close what they hold, and line numbers survive stripping.
fixture "unclosed fence ends with its blockquote" $'> ```\n> code\n\n[gone](missing.md)' \
  "a.md:6: relative link does not resolve: missing.md"
fixture "unclosed fence ends with its list item" $'- ```\n  code\n\n[gone](missing.md)' \
  "a.md:6: relative link does not resolve: missing.md"
fixture "lazy fence opener leaves the blockquote" $'> para\n```\nx\n```\n[gone](missing.md)' \
  "a.md:7: relative link does not resolve: missing.md"
fixture "quoted definition keeps its line number" "$(quote $'[gone][x]\n\n[x]: missing.md')" \
  "a.md:5: relative link does not resolve: missing.md"
fixture "review case: quoted shortcut reference" $'> [guide]\n>\n> [guide]: missing.md' \
  "a.md:5: relative link does not resolve: missing.md"

# DEC-003: each bypass class is parsed
# correctly or rejected as unsupported style, in every container form.
negative "class 1 escape kept in destination" '[x](b.md\(\))' \
  "relative link does not resolve: b.md()"
negative "class 1 escape kept in definition" $'[x]\n\n[x]: b.md\\(\\)' \
  "relative link does not resolve: b.md()"
negative "class 2 backtick in destination" '[x](b.md`gone`)' "backtick in link destination"
negative "class 2 backtick in definition destination" $'[x]\n\n[x]: b.md`gone`' \
  "backtick in link destination"
negative "class 2 code span across lines" $'# Heading `x\n[x](missing.md) `' "unpaired backtick"
negative "class 3 escaped backslash before a code span" '\\`Tools/missing`' \
  "cited path does not exist: Tools/missing"
negative "class 4 ordered marker cannot interrupt a paragraph" $'p\n2.     [x](missing.md)' \
  "relative link does not resolve: missing.md"
negative "class 4 vertical tab is no line end" $'p\v\v    [x](missing.md)' \
  "relative link does not resolve: missing.md"
negative "class 4 no-break space line is not blank" $'p\n\xc2\xa0\n    [x](missing.md)' \
  "relative link does not resolve: missing.md"
negative "class 5 title cannot cross a blank line" $'[a]: b.md\n"\n\n[x](missing.md)\n"' \
  "relative link does not resolve: missing.md"
negative "class 5 inline title cannot cross a blank line" $'[a](b.md "\n\n[x](missing.md)\n")' \
  "malformed inline link or image"
negative "class 6 definition inside a paragraph" $'p\n[a]: b.md\n\n[x][a]' \
  "reference definition continues a paragraph"
negative "class 7 label over two lines" $'[x][a\nb]' "undefined reference label: a b"
negative "class 7 collapsed label over two lines" $'[a\nb][]' "undefined reference label: a b"
negative "class 7 definition label over two lines" $'[a b]\n\n[a\nb]: missing.md' \
  "reference definition label spans lines"
negative "class 7 caret definition label over two lines" $'[^a b]\n\n[^a\nb]: missing.md' \
  "reference definition label spans lines"
negative "class 7 definition label over two lines in a paragraph" $'p\n[a\nb]: missing.md' \
  "reference definition label spans lines"
negative "class 7 caret label" $'[x][^a]\n\n[^a]: b.md' "undefined reference label: ^a"
negative "class 7 Unicode whitespace alias" $'[x][a\xe2\x80\x83b]\n\n[a b]: b.md' \
  "undefined reference label: a"
negative "class 7 unparsed definition" $'[x]\n\n[x]: b.md "two\nline title"' "unparsed reference definition"
EXTRA='a&copy;.md' negative "class 8 character reference" '[x](a&copy;.md)' \
  "character reference in link destination"
EXTRA='a&copy;.md' negative "class 8 character reference in definition" \
  $'[x]\n\n[x]: a&copy;.md' "character reference in link destination"
negative "class 9 file used as a directory" '[x](b.md/)' "relative link does not resolve: b.md/"
negative "class 9 file as a path component" '[x](b.md/../b.md)' \
  "relative link does not resolve: b.md/../b.md"
negative "class 9 definition file used as a directory" $'[x]\n\n[x]: b.md/' \
  "relative link does not resolve: b.md/"
negative "class 9 cited file used as a directory" 'Cites `Tools/docs/check.py/`.' \
  "cited path does not exist: Tools/docs/check.py/"
negative "class 10 hidden root spelling" 'Cites `.-missing/file`.' \
  "cited path does not exist: .-missing/file"
negative "class 10 absent visible root" 'Cites `Absent/file.md`.' "path has no repo root: Absent/file.md"
negative "class 11 non-ASCII file name" 'Cites `Tools/míssing`.' "cited path does not exist: Tools/míssing"
negative "class 11 brackets are literal" 'Cites `Tools/[absent].md`.' \
  "cited path does not exist: Tools/[absent].md"
negative "class 11 placeholder is literal" 'Cites `Tools/<absent>.md`.' \
  "cited path does not exist: Tools/<absent>.md"
negative "class 11 glob must match" 'Cites `Tools/docs/*.absent`.' \
  "cited path does not exist: Tools/docs/*.absent"
negative "class 12 trailing dot inside the backticks" 'Cites `Tools/docs/check.py.`.' \
  "punctuation inside the backticks"
negative "class 12 quoted path with a space" 'Run `cat "Tools/docs absent.md"`.' \
  "punctuation inside the backticks"
NAME=a.MD negative "class 13 upper-case extension" '[x](missing.md)' \
  "relative link does not resolve: missing.md"

echo "docs tests: ok"
