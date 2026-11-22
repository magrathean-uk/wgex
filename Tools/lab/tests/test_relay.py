# SPDX-License-Identifier: MIT
"""Relay errors and expiry are tested with fake sockets, never the vmnet bridge."""
import errno
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("relay", Path(__file__).resolve().parents[1] / "tart/host/udp-relay.py")
RELAY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELAY)


class RelayTests(unittest.TestCase):
    def test_icmp_refusal_discards_only_failed_mapping(self):
        front, back = Mock(), Mock()
        relay = RELAY.Relay(front, ("192.168.64.12", 51820))
        relay.backs[("192.168.64.5", 1234)] = (back, 10)
        back.recv.side_effect = OSError(errno.ECONNREFUSED, "fixture")
        relay.receive_back(back, 11)
        self.assertEqual(relay.backs, {})
        back.close.assert_called_once()
        front.close.assert_not_called()

    def test_idle_and_capacity_trim_close_sockets(self):
        relay = RELAY.Relay(Mock(), ("192.168.64.12", 51820))
        first, second = Mock(), Mock()
        relay.backs[("a", 1)] = (first, 1)
        relay.backs[("b", 2)] = (second, 400)
        relay.trim(401)
        first.close.assert_called_once()
        self.assertEqual(len(relay.backs), 1)
        with patch.object(RELAY, "MAX_CLIENTS", 1):
            relay.trim(401, reserve=True)
        second.close.assert_called_once()
        self.assertEqual(relay.backs, {})
