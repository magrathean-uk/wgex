# SPDX-License-Identifier: MIT
"""Report secret-shaped strings by location only, with exact reviewed exceptions."""
import hashlib
from pathlib import Path
import re
import sys

B64 = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/]{43}=?(?![A-Za-z0-9+/=_-])")
HEX = re.compile(r"(?<![0-9A-Za-z_])[0-9a-fA-F]{64}(?![0-9A-Za-z_])")
EXTENSIONS = {".swift", ".go", ".yml", ".yaml", ".json", ".plist", ".py", ".sh", ".md"}
EXCLUDED = (".plan/", "Tests/Fixtures/", "Tools/testpeer/testdata/", "Vendor/", "Engine/go/vendor/",
            "Design/.work/", "Design/.taste-skill/")


def main():
    allowlist = set()
    for line in Path(__file__).with_name("non-secret-shapes.tsv").read_text().splitlines():
        if line and not line.startswith("#"):
            path, fingerprint, _reason = line.split("\t", 2)
            allowlist.add((path, fingerprint))
    records = sys.stdin.buffer.read().decode().rstrip("\0")
    paths = records.split("\0") if records else []
    found = False
    for name, relative in zip(paths[::2], paths[1::2], strict=True):
        path = Path(name)
        relative = relative.removeprefix("./")
        if path.suffix not in EXTENSIONS or relative.startswith(EXCLUDED):
            continue
        lines = []
        for number, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            matches = B64.findall(line) + HEX.findall(line)
            if any((relative, hashlib.sha256(value.encode()).hexdigest()) not in allowlist for value in matches):
                lines.append(str(number))
        if lines:
            sys.stderr.write(f"secret-shaped string: {relative} line(s) {','.join(lines)}\n")
            found = True
    if found:
        sys.stderr.write("check-no-secrets-in-strings: FAIL (move test keys to Tests/Fixtures/keys)\n")
        return 1
    print("check-no-secrets-in-strings: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
