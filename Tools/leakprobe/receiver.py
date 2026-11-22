#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""M1-10 ordinary marker sockets for the vmnet host and Linux peer; no capture APIs.

Every binding is control-tested before readiness and after the stop file arrives.
Coverage describes the actual listening lifetime, not a coordinator assertion.
Run with python3 -I. Only explicit numeric addresses are accepted.
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import selectors
import socket
import struct
import time


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def marker(data):
    text = data.decode("ascii", errors="ignore")
    for pattern, proto in [(r"^WGEXLEAK ([a-z0-9-]{1,63})$", "udp"),
                           (r"^GET /(?:leak|marker)/([a-z0-9-]{1,63}) HTTP/1.1\r\n", "http")]:
        match = re.search(pattern, text)
        if match:
            return match[1], proto
    question = dns_question(data)
    return (question[0], "dns") if question else None


def dns_question(data):
    if len(data) < 17 or data[2] & 128 or data[4:6] != b"\0\1" or data[6:10] != b"\0" * 4:
        return None
    labels, cursor = [], 12
    while cursor < len(data):
        length = data[cursor]
        cursor += 1
        if not length:
            break
        if length > 63 or cursor + length > len(data):
            return None
        labels.append(data[cursor:cursor + length].decode("ascii", errors="replace"))
        cursor += length
    end = cursor + 4
    if (len(labels) != 4 or not re.fullmatch(r"[a-z0-9-]{1,63}", labels[0])
            or labels[1] not in ("marker", "leak") or labels[2:] != ["wgex", "test"]
            or data[cursor:end] not in (b"\0\1\0\1", b"\0\x1c\0\1")):
        return None
    additional = int.from_bytes(data[10:12], "big")
    if additional == 0 and len(data) == end:
        return labels[0], end
    # System resolver queries may include one bounded EDNS OPT record.
    if additional == 1 and len(data) >= end + 11 and data[end:end+3] == b"\0\0\x29":
        length = int.from_bytes(data[end+9:end+11], "big")
        if len(data) == end + 11 + length and data[end+5:end+7] == b"\0\0":
            return labels[0], end
    return None


def dns_reply(data, address):
    question = dns_question(data)
    if not question:
        raise ValueError("not a marker DNS question")
    end = question[1]
    response = bytearray(data[:end])
    response[2:4] = bytes([0x84 | (data[2] & 1), 0])
    response[6:12] = b"\0" * 6
    ip = ipaddress.ip_address(address)
    if data[end-4:end-2] == struct.pack("!H", 1 if ip.version == 4 else 28):
        response[6:8] = b"\0\1"
        response += b"\xc0\x0c" + data[end-4:end] + struct.pack("!IH", 0, len(ip.packed)) + ip.packed
    return bytes(response)


def payload(proto, nonce):
    if proto == "dns":
        labels = [nonce, "marker", "wgex", "test"]
        return b"WG\x01\0\0\x01\0\0\0\0\0\0" + b"".join(bytes([len(s)]) + s.encode() for s in labels) + b"\0\0\1\0\1"
    if proto == "http":
        return f"GET /marker/{nonce} HTTP/1.1\r\nHost: lab\r\n\r\n".encode()
    return f"WGEXLEAK {nonce}".encode()


POLL_GAP_SECONDS = 1.5


class Receiver:
    # M1-57 (run 9b F2): why healthy turned false, so a record that reads unhealthy also says which rule tripped. Class-level
    # defaults keep a Receiver built without __init__ (the tests) valid. The 1.5 s rule and the healthy flag are unchanged.
    health_cause = None
    max_gap = 0.0
    max_gap_at = None

    def __init__(self, configuration, scope):
        self.config = configuration
        self.scope = scope
        self.digest = hashlib.sha256(canonical(configuration)).hexdigest()
        self.selector = selectors.DefaultSelector()
        self.bindings, self.observations, self.controls = [], [], set()
        self.start = time.time()
        self.healthy = False
        self.last_poll = time.monotonic()
        try:
            for target in configuration["targets"]:
                if target["scope"] != scope:
                    continue
                for proto, key in [("dns", "dnsPort"), ("http", "httpPort"), ("udp", "udpPort")]:
                    address = target.get("resolver", target["address"]) if proto == "dns" else target["address"]
                    ip = ipaddress.ip_address(address)
                    if ip.is_unspecified or (scope == "outside_tunnel" and ip.is_loopback):
                        raise ValueError("explicit non-loopback receiver required")
                    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
                    sock = socket.socket(family, socket.SOCK_STREAM if proto == "http" else socket.SOCK_DGRAM)
                    self.bindings.append((sock, address, target[key], proto))
                    if family == socket.AF_INET6:
                        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    sock.bind((address, target[key]))
                    if proto == "http":
                        sock.listen(32)
                    sock.setblocking(False)
                    self.selector.register(sock, selectors.EVENT_READ, (address, target[key], proto))
            if not self.bindings:
                raise ValueError("no receiver bindings")
        except BaseException:
            self.close()
            raise

    def close(self):
        for sock, *_ in self.bindings:
            sock.close()
        self.selector.close()

    def poll(self, timeout=0.02):
        now = time.monotonic()
        gap = now - self.last_poll
        if gap > POLL_GAP_SECONDS:
            self.healthy = False
            if gap > self.max_gap:
                self.max_gap, self.max_gap_at = gap, time.time()
        self.last_poll = now
        for key, _ in self.selector.select(timeout):
            address, port, binding_proto = key.data
            if binding_proto == "http":
                client, _ = key.fileobj.accept()
                with client:
                    client.settimeout(0.2)
                    try:
                        data = client.recv(4096)
                    except OSError:
                        continue
                    try:
                        client.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                    except OSError:
                        pass  # Receiving the marker is independent of response delivery.
            else:
                data, source = key.fileobj.recvfrom(4096)
                if binding_proto == "dns" and marker(data):
                    key.fileobj.sendto(dns_reply(data, address), source)
            parsed = marker(data)
            if not parsed:
                continue
            nonce, proto = parsed
            if binding_proto == "http" and proto == "udp":
                proto = "tcp"
            elif binding_proto != proto:
                continue
            if nonce.startswith("health-"):
                self.controls.add((address, port, proto, nonce))
                continue
            self.observations.append(dict(timestamp=time.time(), nonce=nonce, kind="received", scope=self.scope,
                                          family="ipv6" if ":" in address else "ipv4", proto=proto, address=address, port=port))
            if len(self.observations) > 100000:
                raise ValueError("receiver observation limit")

    def control(self, label):
        nonce = "health-" + label
        expected = set()
        for sock, address, port, proto in self.bindings:
            for actual in (["http", "tcp"] if proto == "http" else [proto]):
                expected.add((address, port, actual, nonce))
                with socket.socket(sock.family, sock.type) as probe:
                    probe.settimeout(0.3)
                    if sock.type == socket.SOCK_STREAM:
                        probe.connect((address, port))
                        probe.sendall(payload(actual, nonce))
                        self.poll(0.01)
                    else:
                        probe.sendto(payload(actual, nonce), (address, port))
                        self.poll(0.01)
        deadline = time.monotonic() + 2
        while not expected.issubset(self.controls) and time.monotonic() < deadline:
            self.poll()
        return expected.issubset(self.controls)

    def begin(self):
        """The start control exchange. A gap seen while it runs never counted against health (the control result replaces
        healthy), so the largest-gap record restarts here."""
        self.healthy = self.control("start")
        self.max_gap, self.max_gap_at = 0.0, None
        if not self.healthy:
            self.health_cause = "startControl"
        return self.healthy

    def finish(self):
        """The end control exchange; same short-circuit as before: a receiver already unhealthy skips it."""
        was_healthy = self.healthy
        self.healthy = was_healthy and self.control("end")
        if was_healthy and not self.healthy:
            self.health_cause = "endControl"

    def health(self):
        """Cause fields for the record: absent while healthy. A failed control exchange names itself; otherwise the cause is the
        poll gap (largest, in seconds, with the wall-clock time it was seen)."""
        if self.healthy:
            return {}
        if self.health_cause:
            return dict(healthCause=self.health_cause)
        if self.max_gap_at is not None:
            return dict(healthCause="pollGap", healthPollGapSeconds=round(self.max_gap, 3), healthPollGapAt=self.max_gap_at)
        return {}

    def record(self, end):
        coverage = []
        for _, address, port, proto in self.bindings:
            for actual in (["http", "tcp"] if proto == "http" else [proto]):
                coverage.append(dict(address=address, port=port, proto=actual, scope=self.scope, start=self.start,
                                     end=end, healthy=self.healthy, configurationSHA256=self.digest))
        return dict(schemaVersion=1, nonce="receiver", configuration=self.config, configurationSHA256=self.digest,
                    observations=self.observations, windows=[], receiverCoverage=coverage, **self.health())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--scope", choices=["outside_tunnel", "in_tunnel"], required=True)
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--ready", type=Path, required=True)
    parser.add_argument("--stop", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=180)
    args = parser.parse_args()
    receiver = Receiver(json.loads(args.config.read_bytes()), args.scope)
    try:
        if not receiver.begin():
            # M1-57: the record names startControl; readiness is still never written, so the driver's wait fails as before.
            args.record.write_bytes(canonical(receiver.record(time.time())))
            raise ValueError("receiver control failed")
        args.ready.write_bytes(canonical(dict(ready=True, timestamp=time.time(), configurationSHA256=receiver.digest)))
        deadline = time.monotonic() + args.seconds
        while not args.stop.exists() and time.monotonic() < deadline:
            receiver.poll()
        receiver.finish()
        args.record.write_bytes(canonical(receiver.record(time.time())))
    finally:
        receiver.close()


if __name__ == "__main__":
    main()
