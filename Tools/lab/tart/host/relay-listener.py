#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only UDP listener inventory, also tested against an owned scratch port."""
import ipaddress
import subprocess
import sys


def listener_pids(address, port):
    ipaddress.ip_address(address)
    if not 1 <= port <= 65535:
        raise ValueError("invalid UDP port")
    result = subprocess.run(["lsof", "-nP", f"-iUDP:{port}", "-Fpn"], capture_output=True, check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError("unable to inspect UDP listener")
    pids, pid = set(), None
    for line in result.stdout.decode().splitlines():
        if line.startswith("p") and line[1:].isdigit():
            pid = int(line[1:])
        elif pid is not None and line in (f"n{address}:{port}", f"n*:{port}"):
            pids.add(pid)
    return sorted(pids)


if __name__ == "__main__":
    try:
        sys.stdout.write("\n".join(map(str, listener_pids(sys.argv[1], int(sys.argv[2])))))
    except (OSError, ValueError, RuntimeError, IndexError):
        sys.stderr.write("relay: unable to inspect UDP listener\n")
        sys.exit(1)
