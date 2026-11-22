# SPDX-License-Identifier: MIT
"""Prove indexed lint against a fully staged disposable copy, never the real index."""
import os
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[3]
NEW_PATHS = ["CONTRIBUTING.md", "Config/Scripts", "Engine/scripts", "Tools/lint", "Tools/docs",
             "Tools/doctor", "Tools/fuzz/run.sh", "Tools/lab/tart", "Toolchain.lock", ".githooks",
             ".swiftlint.yml", "justfile", "docs"]


def listed(*arguments):
    data = subprocess.check_output(["git", "-C", str(ROOT), "ls-files", "-z", *arguments])
    return {name for name in data.decode().split("\0") if name}


def main():
    started = time.monotonic()
    index_name = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "--git-path", "index"], text=True).strip()
    index = Path(index_name) if Path(index_name).is_absolute() else ROOT / index_name
    original_index = hashlib.sha256(index.read_bytes()).digest()
    build = Path(subprocess.check_output(
        ["bash", "-c", 'source "$1"; build_root', "_", str(ROOT / "Config/Scripts/lib.sh")], text=True))
    logs = build / "verification"
    logs.mkdir(parents=True, exist_ok=True)
    tracked = listed("--cached", "--deduplicate")
    new = listed("--others", "--exclude-standard", "--", *NEW_PATHS)
    with tempfile.TemporaryDirectory(prefix="wgex-staged-proof-", dir=os.environ["TMPDIR"]) as directory:
        work = Path(directory)
        tree = work / "staged-tree"
        tree.mkdir()
        copied = set()
        for name in sorted(tracked | new):
            source = ROOT / name
            if not source.is_file():
                continue
            destination = tree / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination, follow_symlinks=True)
            copied.add(name)
        # Manifest evaluation can inspect ignored binary target paths; never stage these products.
        binary = ROOT / "Packages/WGEXEngine/Binary"
        if binary.is_dir():
            shutil.copytree(binary, tree / "Packages/WGEXEngine/Binary", dirs_exist_ok=True)
        subprocess.run(["git", "init", "-q", "--template=", str(tree)], check=True)
        subprocess.run(["git", "-C", str(tree), "add", "-A"], check=True)
        staged = set(subprocess.check_output(["git", "-C", str(tree), "ls-files", "-z"]).decode().split("\0"))
        if not copied <= staged or not new <= staged:
            raise RuntimeError("snapshot did not stage every copied/new file")
        env = os.environ | {"WGEX_BUILD_ROOT": str(work / "builds")}
        results = []
        for label, command in (("licences", ["bash", "Tools/lint/check-licences.sh"]),
                               ("lint", ["just", "lint"])):
            step = time.monotonic()
            with (logs / f"staged-tree-{label}.log").open("wb") as output:
                result = subprocess.run(command, cwd=tree, env=env, stdout=output, stderr=subprocess.STDOUT)
            elapsed = time.monotonic() - step
            print(f"staged-tree: {label} exit={result.returncode} seconds={elapsed:.2f}", flush=True)
            results.append(result.returncode)
        if hashlib.sha256(index.read_bytes()).digest() != original_index:
            raise RuntimeError("real index changed during the disposable-tree proof")
        print(f"staged-tree: {len(copied)} files, {len(new)} new files all staged; real index byte hash unchanged", flush=True)
        print(f"staged-tree: total seconds={time.monotonic() - started:.2f}", flush=True)
        return 1 if any(results) else 0


if __name__ == "__main__":
    sys.exit(main())
