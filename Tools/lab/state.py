# SPDX-License-Identifier: MIT
"""Persistent, non-secret lab runtime state; independent of session/cache routing."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parents[2]
_build_spec = importlib.util.spec_from_file_location("lab_build_root", ROOT / "Config/Scripts/build_root.py")
_build_module = importlib.util.module_from_spec(_build_spec)
_build_spec.loader.exec_module(_build_module)
build_root = _build_module.build_root


def state_directory(root=ROOT, home=None):
    root = Path(root).resolve()
    name = re.sub(r"[^A-Za-z0-9_-]", "-", root.name)
    identity = hashlib.sha256(os.fsencode(root)).hexdigest()[:12]
    return (Path(home) if home else Path.home()) / ".local/state/wgex-lab" / (name + "-" + identity)


def ensure_directory(directory):
    for path in [directory, *directory.parents]:
        if path.is_symlink():
            raise ValueError("lab state may not traverse a symlink")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)


def guest_binaries(root=ROOT):
    directory = state_directory(root) / "helpers"
    return {name: directory / name for name in ["leakprobe", "foreign-utun"]}


def publish_helpers(build):
    sources = {"leakprobe": build / "spm/leakprobe/debug/leakprobe", "foreign-utun": build / "lab-tools/foreign-utun"}
    targets = guest_binaries()
    directory = state_directory() / "helpers"
    ensure_directory(directory)
    manifest = {}
    for name, source in sources.items():
        if not source.is_file():
            raise ValueError("build guest helpers with just test tools first")
        target = targets[name]
        temporary = directory / (name + ".next")
        if target.is_symlink() or temporary.is_symlink():
            raise ValueError("unsafe helper target")
        shutil.copyfile(source, temporary)
        temporary.chmod(0o700)
        temporary.replace(target)
        manifest[name] = hashlib.sha256(target.read_bytes()).hexdigest()
    target, temporary = directory / "manifest.json", directory / "manifest.next"
    if target.is_symlink() or temporary.is_symlink():
        raise ValueError("unsafe helper manifest")
    temporary.write_text(json.dumps(manifest, sort_keys=True) + "\n")
    temporary.replace(target)


if __name__ == "__main__":
    if sys.argv[1:] == ["path"]:
        sys.stdout.write(str(state_directory()) + "\n")
    elif sys.argv[1:] == ["publish-helpers"]:
        publish_helpers(build_root(ROOT))
    else:
        raise SystemExit("usage: state.py path|publish-helpers")
