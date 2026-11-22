#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
root="$1"
out="$2/scope"
mkdir -p "$out/repo/Tools/lint" "$out/repo/Config/Scripts" "$out/repo/.plan/nested" "$out/repo/Sources" "$out/bin" "$out/global"
cp "$root/Tools/lint/"{lib.sh,check-public-prose.sh,prose-report.py,public-prose-denylist.txt,check-no-secrets-in-strings.sh,secret-shapes.py,non-secret-shapes.tsv} "$out/repo/Tools/lint/"
cp "$root/Config/Scripts/lib.sh" "$out/repo/Config/Scripts/"
cp "$root/typos.toml" "$out/repo/typos.toml"
cp "$root/Tools/lint/tests/prose/denylisted.md" "$out/repo/.plan/nested/prose.md"
cp "$root/Tools/lint/tests/secrets/base64.swift" "$out/repo/.plan/nested/secret.swift"
cp "$root/Tools/lint/tests/typos/misspelled.md" "$out/repo/.plan/nested/typo.md"
printf 'Clean text.\n' >"$out/repo/Sources/clean.md"
git -C "$out/repo" -c init.defaultBranch=main init -q
git -C "$out/repo" add -f .
(cd "$out/repo" && Tools/lint/check-public-prose.sh && Tools/lint/check-no-secrets-in-strings.sh && typos --force-exclude .plan/nested/typo.md Sources/clean.md)
"$out/repo/Tools/lint/check-public-prose.sh" "$out/repo/.plan/nested/prose.md"
"$out/repo/Tools/lint/check-no-secrets-in-strings.sh" "$out/repo/.plan/nested/secret.swift"
cp "$out/repo/.plan/nested/prose.md" "$out/repo/Sources/prose.md"
cp "$out/repo/.plan/nested/secret.swift" "$out/repo/Sources/secret.swift"
cp "$out/repo/.plan/nested/typo.md" "$out/repo/Sources/typo.md"
if "$out/repo/Tools/lint/check-public-prose.sh" "$out/repo/Sources/prose.md" >/dev/null 2>&1; then exit 1; fi
if "$out/repo/Tools/lint/check-no-secrets-in-strings.sh" "$out/repo/Sources/secret.swift" >/dev/null 2>&1; then exit 1; fi
if typos --config "$out/repo/typos.toml" --force-exclude "$out/repo/Sources/typo.md" >/dev/null 2>&1; then exit 1; fi
cat >"$out/bin/git" <<STUB
#!/bin/sh
printf '%s\\n' '$out/global'
STUB
cat >"$out/global/pre-commit" <<STUB
#!/bin/sh
printf global > '$out/global-ran'
STUB
chmod +x "$out/bin/git" "$out/global/pre-commit"
if PATH="$out/bin:/usr/bin:/bin" /bin/bash "$root/.githooks/pre-commit" >"$out/hook.log" 2>&1; then exit 1; fi
[ -f "$out/global-ran" ] && grep -q 'refusing commit' "$out/hook.log"
cat >"$out/bin/pre-commit" <<STUB
#!/bin/sh
printf framework > '$out/framework-ran'
STUB
chmod +x "$out/bin/pre-commit"
PATH="$out/bin:/usr/bin:/bin" /bin/bash "$root/.githooks/pre-commit"
[ -f "$out/framework-ran" ]
