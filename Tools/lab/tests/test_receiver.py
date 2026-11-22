# SPDX-License-Identifier: MIT
"""Receiver protocol and lifetime coverage, without opening network sockets."""
import importlib.util
from pathlib import Path
import unittest
import time
from unittest.mock import Mock, MagicMock

SPEC = importlib.util.spec_from_file_location("receiver", Path(__file__).resolve().parents[2] / "leakprobe/receiver.py")
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)


class ReceiverTests(unittest.TestCase):
    def test_a_received_tcp_marker_survives_a_closed_client_response(self):
        receiver = R.Receiver.__new__(R.Receiver)
        receiver.scope, receiver.controls, receiver.observations = "outside_tunnel", set(), []
        receiver.last_poll, receiver.healthy = time.monotonic(), True
        client = MagicMock()
        client.__enter__.return_value = client
        client.recv.return_value = b"WGEXLEAK fixture-received"
        client.sendall.side_effect = BrokenPipeError()
        listener = Mock()
        listener.accept.return_value = (client, None)
        key = Mock(fileobj=listener, data=("192.168.64.1", 8088, "http"))
        receiver.selector = Mock()
        receiver.selector.select.return_value = [(key, 1)]
        receiver.poll()
        self.assertEqual(receiver.observations[0]["proto"], "tcp")

    def test_system_resolver_edns_query_gets_a_well_formed_answer(self):
        query = bytearray(R.payload("dns", "fixture-system"))
        query[10:12] = b"\0\1"
        query += b"\0\0\x29\x04\xd0\0\0\0\0\0\0"
        self.assertEqual(R.marker(bytes(query)), ("fixture-system", "dns"))
        response = R.dns_reply(bytes(query), "10.77.0.1")
        self.assertEqual(response[6:8], b"\0\1")
        self.assertEqual(response[10:12], b"\0\0")
        self.assertEqual(response[-4:], bytes([10, 77, 0, 1]))
        self.assertIsNone(R.marker(bytes(query) + b"\0"))

    def test_wire_formats_match_guest_generator(self):
        for proto in ["dns", "http", "udp", "tcp"]:
            expected = "udp" if proto == "tcp" else proto
            self.assertEqual(R.marker(R.payload(proto, "lab-fixture")), ("lab-fixture", expected))
        self.assertIsNone(R.marker(b"GET /marker/bad?nonce HTTP/1.1\r\n\r\n"))
        self.assertIsNone(R.marker(b"WGEXLEAK INVALID"))
        self.assertIsNone(R.marker(R.payload("dns", "fixture")[:-1]))

    def test_coverage_reports_health_and_tcp_http_binding_separately(self):
        receiver = R.Receiver.__new__(R.Receiver)
        receiver.bindings = [(None, "192.168.64.1", 8088, "http")]
        receiver.scope, receiver.digest = "outside_tunnel", "digest"
        receiver.start, receiver.healthy = 1, False
        receiver.config, receiver.observations = {}, []
        record = receiver.record(9)
        self.assertEqual({item["proto"] for item in record["receiverCoverage"]}, {"http", "tcp"})
        self.assertTrue(all(not item["healthy"] for item in record["receiverCoverage"]))
        self.assertEqual(record["receiverCoverage"][0]["end"], 9)
