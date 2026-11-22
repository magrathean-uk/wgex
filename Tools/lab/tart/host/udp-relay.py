#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""User-space UDP relay for the lab: the Tart guest and the Lima peer sit on the
same vmnet shared bridge but its members are isolated (PRIVATE flag), while both
reach the host. The relay listens on the host's vmnet address only and forwards
datagrams to the peer, mapping replies back to the client address that sent the
last datagram on that back socket. No routes, pf rules or interfaces are touched.
Standard library only.

usage: udp-relay.py LISTEN_ADDR:PORT TARGET_ADDR:PORT
"""
import select
import json
from pathlib import Path
import socket
import sys
import time

IDLE_SECONDS = 300


def endpoint(text: str) -> tuple[str, int]:
    host, _, port = text.rpartition(":")
    return host, int(port)


MAX_CLIENTS = 256


class RelayControl:
    """Poll metadata once a second; read JSON only after an atomic-file change."""
    def __init__(self, path):
        self.path = path
        self.next_check = 0
        self.fingerprint = None

    def refresh(self, relay, now):
        if now < self.next_check:
            return
        self.next_check = now + 1
        try:
            stat = self.path.stat()
            fingerprint = (stat.st_mtime_ns, stat.st_size, stat.st_ino)
            if fingerprint == self.fingerprint:
                return
            value = json.loads(self.path.read_bytes())
            if not isinstance(value, dict) or value.get("maxDatagram") not in (None, 1252):
                raise ValueError("invalid row limit")
            relay.max_datagram = value.get("maxDatagram")
            self.fingerprint = fingerprint
        except (OSError, ValueError, TypeError):
            pass  # Retain the current impairment until a valid control update.


class Relay:
    def __init__(self, front, target, max_datagram=None):
        self.front, self.target = front, target
        self.backs = {}
        self.max_datagram = max_datagram
        self.dropped_oversize = 0

    def allowed_size(self, data):
        if self.max_datagram is not None and len(data) > self.max_datagram:
            self.dropped_oversize += 1
            return False
        return True

    def discard(self, client):
        back = self.backs.pop(client, None)
        if back:
            back[0].close()

    def trim(self, now, reserve=False):
        for client, (_, last) in list(self.backs.items()):
            if now - last > IDLE_SECONDS:
                self.discard(client)
        while self.backs and len(self.backs) > MAX_CLIENTS - int(reserve):
            self.discard(min(self.backs, key=lambda key: self.backs[key][1]))

    def receive_front(self, now):
        try:
            data, client = self.front.recvfrom(65535)
        except OSError:
            return
        if not self.allowed_size(data):
            return
        # Clients must also be on vmnet, so this cannot be used as an open relay.
        if not client[0].startswith("192.168.64."):
            return
        if client not in self.backs:
            self.trim(now, reserve=True)
            back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                back.connect(self.target)
            except OSError:
                back.close()
                return
            self.backs[client] = (back, now)
        back, _ = self.backs[client]
        try:
            back.send(data)
            self.backs[client] = (back, now)
        except OSError:
            # Connected UDP sockets report asynchronous ICMP refusals here too.
            self.discard(client)

    def receive_back(self, sock, now):
        for client, (back, _) in list(self.backs.items()):
            if back is sock:
                try:
                    data = back.recv(65535)
                    if not self.allowed_size(data):
                        return
                    self.front.sendto(data, client)
                    self.backs[client] = (back, now)
                except OSError:
                    self.discard(client)
                return

    def close(self):
        for client in list(self.backs):
            self.discard(client)
        self.front.close()


def main() -> int:
    if len(sys.argv) not in (3, 5) or (len(sys.argv) == 5 and sys.argv[3] != "--control"):
        sys.stderr.write(__doc__)
        return 2
    listen, target = endpoint(sys.argv[1]), endpoint(sys.argv[2])
    if listen != ("192.168.64.1", 51820) or target != ("192.168.64.12", 51820):
        sys.stderr.write("refusing addresses outside the dedicated vmnet relay pair\n")
        return 2
    front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    front.bind(listen)
    relay = Relay(front, target)
    control = RelayControl(Path(sys.argv[4])) if len(sys.argv) == 5 else None
    try:
        while True:
            if control is not None:
                control.refresh(relay, time.monotonic())
            ready, _, _ = select.select([front] + [sock for sock, _ in relay.backs.values()], [], [], 0.1)
            now = time.monotonic()
            for sock in ready:
                if sock is front:
                    relay.receive_front(now)
                else:
                    relay.receive_back(sock, now)
            relay.trim(now)
    finally:
        relay.close()


if __name__ == "__main__":
    sys.exit(main())
