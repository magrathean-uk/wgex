# SPDX-License-Identifier: MIT
"""M1-13 attended host build proof; restores the Go source in all cases."""
import hashlib
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[3]


def main():
    build_root = Path(subprocess.check_output(
        ["bash", "-c", 'source "$1"; build_root', "_", str(ROOT / "Config/Scripts/lib.sh")], text=True))
    logs = build_root / "verification"
    logs.mkdir(parents=True, exist_ok=True)

    def run(label, *command, refusal=False):
        started = time.monotonic()
        with (logs / f"{label}.log").open("wb") as output:
            result = subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
        if refusal:
            if result.returncode == 0 or b"run 'just engine' before building" not in (logs / f"{label}.log").read_bytes():
                raise RuntimeError("changed Go source was not refused before compilation")
        elif result.returncode:
            raise RuntimeError(f"{label} failed with exit {result.returncode}; inspect routed log")
        print(f"{label}: expected exit {result.returncode}, {time.monotonic() - started:.2f}s")

    source = ROOT / "Engine/go/bridge/main.go"
    original = source.read_bytes()
    try:
        source.write_bytes(original + b"\n// M1-13: temporary source-digest invalidation proof.\n")
        run("digest-refusal", "just", "build", "mac", "debug", refusal=True)
        run("digest-rebuild", "just", "engine")
        run("digest-build", "just", "build", "mac", "debug")
    finally:
        source.write_bytes(original)
        run("digest-restored", "just", "engine")
    run("digest-force", "just", "engine", "--force")
    binary = ROOT / "Packages/WGEXEngine/Binary"

    def production_hashes():
        files = list((binary / "WGEXEngine.xcframework").rglob("*")) + [binary / "provenance.json"]
        return {str(p.relative_to(binary)): hashlib.sha256(p.read_bytes()).digest() for p in files if p.is_file()}

    before = production_hashes()
    run("digest-single-slice", "just", "engine", "macos")
    if production_hashes() != before:
        raise RuntimeError("single-slice build changed the production archive or provenance")
    run("digest-warm-skip", "just", "engine")
    print("digest proof: source restored; forced rebuild, warm reuse and slice isolation passed")


if __name__ == "__main__":
    main()
