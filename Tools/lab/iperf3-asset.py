#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pinned static iperf3 client for the macOS lab guest (IPERF3 row).

Fetched host-side from a known release, verified against the pinned SHA-256 before
it is stored or staged, and kept in the shared versioned tools directory, never in the
repository. The binary links only libSystem (checked with otool -L, never run on the
host). Prepare copies it to ~/lab/bin/iperf3 in the guest after every restore.
"""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tomllib
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
_state_spec = importlib.util.spec_from_file_location("iperf3_lab_state", ROOT / "Tools/lab/state.py")
STATE = importlib.util.module_from_spec(_state_spec)
_state_spec.loader.exec_module(STATE)

with (ROOT / "Toolchain.lock").open("rb") as handle:
    PIN = tomllib.load(handle)["iperf3"]
MAX_BYTES = 16 * 1024 * 1024


def asset_path():
    return Path(os.environ.get("WGEX_LAB_TOOLS") or Path.home() / ".wgex-lab/tools") / "iperf3-static" / PIN["version"] / "iperf3"


def verified(path):
    """Return the stored bytes only when they are the pinned release; otherwise None."""
    path = Path(path)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
                return None
            data = handle.read(MAX_BYTES + 1)
    except OSError:
        return None
    return data if len(data) <= MAX_BYTES and hashlib.sha256(data).hexdigest() == PIN["sha256"] else None


def fetch(target=None, opener=None):
    """Download once, verify, then publish atomically; a verified copy is never fetched again."""
    target = Path(target) if target else asset_path()
    if verified(target) is not None:
        return target
    STATE.ensure_directory(target.parent)
    temporary = target.with_name(target.name + ".next")
    if target.is_symlink() or temporary.is_symlink():
        raise ValueError("unsafe iperf3 asset path")
    with (opener or urllib.request.urlopen)(PIN["url"], timeout=120) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES or hashlib.sha256(data).hexdigest() != PIN["sha256"]:
        raise ValueError("downloaded iperf3 does not match the pinned SHA-256; nothing was stored")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o700)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        os.chmod(temporary, 0o700)
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
    if verified(target) is None:
        raise ValueError("stored iperf3 failed verification")
    return target


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("action", choices=["fetch", "path"], help="fetch: download, verify and store; path: print the verified path")
    parser.add_argument("--dry-run", action="store_true", help="print the pinned release and destination; no network or writes")
    args = parser.parse_args(argv)
    target = asset_path()
    if args.dry_run:
        sys.stdout.write(f"dry-run: iperf3 {PIN['version']} {PIN['url']} sha256 {PIN['sha256']} -> {target}\n")
        return 0
    if args.action == "path":
        if verified(target) is None:
            sys.stderr.write("iperf3: no verified asset; run just lab iperf3 fetch\n")
            return 1
    else:
        try:
            fetch(target)
        except (OSError, ValueError) as error:
            sys.stderr.write(f"iperf3: fetch failed ({type(error).__name__}); nothing published\n")
            return 1
    sys.stdout.write(f"{target}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
