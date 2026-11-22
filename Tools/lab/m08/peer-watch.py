#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""M08-T04: records the IPv4 headers seen on the lab peer's wg0 (the inside of the tunnel) for one row window.

Run only on wg-peer, as root, by m08-rows.py (`sudo -n python3 -I -B peer-watch.py --iface wg0 --record R --ready F
--stop S --seconds N`). A Linux packet socket on wg0 only: no payload is kept, only protocol, addresses and ports, at
most LIMIT packets. The ready file is written once the socket is bound; the record when the stop file appears or the
bound ends.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import struct
import time

ETH_P_ALL = 0x0003
LIMIT = 20000


def header(packet):
    """(proto, src, sport, dst, dport) of one IPv4 packet, or None. Ports are None for protocols without them."""
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    length = (packet[0] & 15) * 4
    proto = packet[9]
    src, dst = socket.inet_ntoa(packet[12:16]), socket.inet_ntoa(packet[16:20])
    sport = dport = None
    if proto in (6, 17) and len(packet) >= length + 4:
        sport, dport = struct.unpack("!HH", packet[length:length + 4])
    return {6: "tcp", 17: "udp", 1: "icmp"}.get(proto, str(proto)), src, sport, dst, dport


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iface", required=True, choices=("wg0",))
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--ready", type=Path, required=True)
    parser.add_argument("--stop", type=Path, required=True)
    parser.add_argument("--seconds", type=int, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_ALL))
    sock.bind((args.iface, 0))
    sock.settimeout(0.5)
    started = time.time()
    args.ready.write_text(json.dumps(dict(ready=True, started=started, iface=args.iface)))
    packets, dropped = [], 0
    deadline = time.monotonic() + args.seconds
    while time.monotonic() < deadline and not args.stop.exists():
        try:
            data, address = sock.recvfrom(256)
        except socket.timeout:
            continue
        found = header(data)
        if found is None:
            continue
        if len(packets) >= LIMIT:
            dropped += 1
            continue
        packets.append([round(time.time(), 6), *found, address[2]])
    sock.close()
    record = dict(iface=args.iface, started=started, ended=time.time(), packets=packets, dropped=dropped,
                  fields=["time", "proto", "src", "sport", "dst", "dport", "pkttype"])
    temporary = args.record.with_name(args.record.name + ".next")
    temporary.write_text(json.dumps(record))
    temporary.replace(args.record)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
