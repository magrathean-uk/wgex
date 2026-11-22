# SPDX-License-Identifier: MIT
"""No networking: synthetic receiver records plus CLI/hash integration tests."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "verdict.py"
SPEC = importlib.util.spec_from_file_location("wgex_verdict", SCRIPT)
VERDICT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERDICT)
TABLE = json.loads(SCRIPT.with_name("leak-expectations.json").read_bytes())


def fixture(state="protected"):
    targets = []
    for scope, addresses in [("in_tunnel", ["10.77.0.1", "fd77::1"]),
                             ("outside_tunnel", ["192.0.2.1", "2001:db8::1"])]:
        for address in addresses:
            targets.append(dict(address=address, scope=scope, dnsPort=53 if state == "captiveWindow" else 5354, httpPort=80, udpPort=8088, allowedLAN=False))
    config = dict(targets=targets, format="marker", intervalMilliseconds=500)
    record = dict(schemaVersion=1, nonce="test-123", configuration=config,
                  configurationSHA256=VERDICT.sha256(VERDICT.canonical(config)),
                  observations=[], inputHashes={}, windows=[dict(state=state, start=1, end=10,
                  receiversComplete=True, allowLAN=False, requiredFamilies=["ipv4", "ipv6"])])
    for target in targets:
        for proto in ["dns", "http", "udp", "tcp"]:
            record["observations"].append(observation(target, proto, "sent"))
    record["receiverCoverage"] = [dict(scope=t["scope"], proto=p, address=t["address"], port=t[k],
        start=0, end=11, healthy=True, configurationSHA256=record["configurationSHA256"])
        for t in targets for p,k in dict(dns="dnsPort",http="httpPort",tcp="httpPort",udp="udpPort").items()]
    return record


def observation(target, proto, kind="received"):
    return dict(timestamp=5, nonce="test-123", kind=kind, scope=target["scope"],
                family="ipv6" if ":" in target["address"] else "ipv4", proto=proto,
                address=target["address"], port=target[dict(dns="dnsPort", http="httpPort", tcp="httpPort", udp="udpPort")[proto]], allowedLAN=False)


def receive(record, scope, protocols=("dns", "http", "udp", "tcp")):
    for target in record["configuration"]["targets"]:
        if target["scope"] == scope:
            record["observations"].extend(observation(target, proto) for proto in protocols)


def check(record):
    receiver = copy.deepcopy(record)
    receiver["nonce"], receiver["windows"] = "receiver", []
    receiver["observations"] = [item for item in record["observations"] if item["kind"] == "received"]
    return VERDICT.evaluate(record, TABLE, [receiver])["states"][0]


class VerdictTests(unittest.TestCase):
    def test_dns_tunnel_requires_system_suffix_for_each_protected_window(self):
        record = fixture()
        record.update(action="dns", dns="resolver #1\n  nameserver[0] : 10.77.0.1\n")
        record["configuration"]["targets"][0]["dnsPort"] = 53
        record["configurationSHA256"] = VERDICT.sha256(VERDICT.canonical(record["configuration"]))
        for source in [record["observations"], record["receiverCoverage"]]:
            for item in source:
                if item["address"] == "10.77.0.1" and item["proto"] == "dns":
                    item["port"] = 53
                if "configurationSHA256" in item:
                    item["configurationSHA256"] = record["configurationSHA256"]
        receive(record, "in_tunnel")
        self.assertFalse(check(record).get("expectationMet", False))
        receipt = observation(record["configuration"]["targets"][0], "dns")
        receipt.update(nonce=record["nonce"] + "-system")
        record["observations"].append(receipt)
        self.assertTrue(check(record)["expectationMet"])
        for bad in ["test-123-system-extra", "test-1234-system", "prefix-test-123-system"]:
            record["observations"][-1]["nonce"] = bad
            self.assertFalse(check(record).get("expectationMet", False))
        record["observations"][-1]["nonce"] = "test-123-system"
        record["dns"] = "  nameserver[0] : 10.77.0.10\n"
        self.assertFalse(check(record).get("expectationMet", False))
        record["dns"] = "  nameserver[0] : 10.77.0.1\n"
        record["windows"].append(dict(record["windows"][0], start=10, end=20))
        result = check(record)
        self.assertTrue(result["expectationMet"])
        receiver = copy.deepcopy(record)
        for binding in receiver["receiverCoverage"]:
            binding.update(start=0, end=21)
        receiver["observations"] = [dict(o, timestamp=15) for o in record["observations"] if o["kind"] == "received" and not o["nonce"].endswith("-system")]
        record["observations"].extend(dict(o, timestamp=15) for o in record["observations"][:] if o["kind"] == "sent")
        first_receiver = copy.deepcopy(record)
        first_receiver["observations"] = [o for o in record["observations"] if o["kind"] == "received"]
        result = VERDICT.evaluate(record, TABLE, [first_receiver, receiver])
        self.assertTrue(result["states"][0]["expectationMet"])
        self.assertFalse(result["states"][1].get("expectationMet", False))
        self.assertIn("received:in_tunnel:dns:system", result["states"][1]["missing"])

    def test_clock_uncertainty_expands_forbidden_receipt_window(self):
        record = fixture("blocked")
        record["clockToleranceSeconds"] = 1
        bad = observation(record["configuration"]["targets"][2], "udp")
        bad["timestamp"] = 0.5
        record["observations"].append(bad)
        self.assertEqual(check(record)["offendingObservations"], [bad])

    def test_local_socket_failure_is_not_evidence_of_filtering(self):
        record = fixture("blocked")
        record["observations"][8].update(kind="failure", detail="socket(24)")
        self.assertEqual(check(record)["verdict"], "unknown")
        record["observations"][8]["detail"] = "socket(60)"
        self.assertEqual(check(record)["verdict"], "blocked")

    def test_protected_requires_tunnel_and_complete_dual_stack_receiver_evidence(self):
        record = fixture()
        receive(record, "in_tunnel")
        self.assertEqual(check(record)["verdict"], "protected")
        record["receiverCoverage"][0]["healthy"] = False
        self.assertEqual(check(record)["verdict"], "unknown")

    def test_every_outside_protocol_is_offending_while_protected(self):
        for proto in ["dns", "http", "udp", "tcp"]:
            with self.subTest(proto=proto):
                record = fixture()
                receive(record, "in_tunnel")
                bad = observation(record["configuration"]["targets"][2], proto)
                record["observations"].append(bad)
                result = check(record)
                self.assertEqual(result["verdict"], "unprotected")
                self.assertEqual(result["offendingObservations"], [bad])

    def test_blocked_silence_requires_successful_probes_and_receiver_coverage(self):
        record = fixture("blocked")
        self.assertEqual(check(record)["verdict"], "blocked")
        record["observations"] = []
        self.assertEqual(check(record)["verdict"], "unknown")
        record = fixture("blocked")
        record["observations"][8]["kind"] = "missing"
        self.assertEqual(check(record)["verdict"], "unknown")

    def test_ipv6_leak_is_never_hidden_by_ipv4_success(self):
        record = fixture()
        receive(record, "in_tunnel")
        bad = observation(record["configuration"]["targets"][3], "udp")
        record["observations"].append(bad)
        self.assertEqual(check(record)["offendingObservations"], [bad])

    def test_lan_exception_requires_authoritative_config_and_never_allows_dns(self):
        record = fixture("blocked")
        target = record["configuration"]["targets"][2]
        bad = observation(target, "udp")
        bad["allowedLAN"] = True
        record["windows"][0]["allowLAN"] = True
        record["observations"].append(bad)
        self.assertEqual(check(record)["verdict"], "unprotected")
        target["allowedLAN"] = True
        record["configurationSHA256"] = VERDICT.sha256(VERDICT.canonical(record["configuration"]))
        for binding in record["receiverCoverage"]:
            binding["configurationSHA256"] = record["configurationSHA256"]
        self.assertEqual(check(record)["verdict"], "blocked")
        record["observations"].append(observation(target, "dns"))
        self.assertEqual(check(record)["verdict"], "unprotected")

    def test_gateway_dns_is_always_offending_in_blocked_state(self):
        record = fixture("blocked")
        bad = observation(record["configuration"]["targets"][2], "dns")
        bad["scope"] = "gateway"
        record["observations"].append(bad)
        self.assertEqual(check(record)["offendingObservations"], [bad])

    def test_captive_accepts_narrow_http_dns_and_rejects_udp(self):
        record = fixture("captiveWindow")
        receive(record, "outside_tunnel", ("dns", "http"))
        self.assertEqual(check(record)["verdict"], "unprotected")
        self.assertTrue(check(record)["expectationMet"])
        receive(record, "outside_tunnel", ("udp",))
        self.assertFalse(check(record)["expectationMet"])

    def test_captive_port_8088_cannot_prove_narrow_web_access(self):
        record = fixture("captiveWindow")
        for target in record["configuration"]["targets"]:
            target["httpPort"] = 8088
        record["configurationSHA256"] = VERDICT.sha256(VERDICT.canonical(record["configuration"]))
        receive(record, "outside_tunnel", ("dns", "http"))
        self.assertFalse(check(record).get("expectationMet", False))

    def test_unprotected_needs_all_outside_protocols_on_both_families(self):
        record = fixture("unprotected")
        receive(record, "outside_tunnel")
        self.assertEqual(check(record)["verdict"], "unprotected")
        record["observations"].pop()
        self.assertEqual(check(record)["verdict"], "unknown")

    def test_wrong_nonce_or_time_never_proves_delivery(self):
        for field, value in [("nonce", "other"), ("timestamp", 11), ("timestamp", float("nan"))]:
            with self.subTest(field=field):
                record = fixture()
                receive(record, "in_tunnel")
                for item in record["observations"]:
                    if item["kind"] == "received":
                        item[field] = value
                self.assertEqual(check(record)["verdict"], "unknown")

    def test_invalid_window_and_unknown_state_fail_closed(self):
        for state in ["unknown", "active", "connected"]:
            self.assertEqual(check(fixture(state))["verdict"], "unknown")
        record = fixture("blocked")
        record["windows"][0]["end"] = 0
        self.assertEqual(check(record)["verdict"], "unknown")

    def test_no_lan_targets_does_not_prove_a_block(self):
        record = fixture("blocked")
        record["configuration"]["targets"] = record["configuration"]["targets"][:2]
        record["configurationSHA256"] = VERDICT.sha256(VERDICT.canonical(record["configuration"]))
        self.assertEqual(check(record)["verdict"], "unknown")

    def test_config_hash_mismatch_is_rejected(self):
        record = fixture()
        record["configurationSHA256"] = "0" * 64
        with self.assertRaises(ValueError):
            check(record)

    def test_receiver_files_are_merged_and_all_input_bytes_are_hashed(self):
        record = fixture()
        receiver = copy.deepcopy(record)
        receiver["nonce"] = "receiver"
        receiver["windows"] = []
        receiver["observations"] = []
        receive(receiver, "in_tunnel")
        with tempfile.TemporaryDirectory() as directory:
            run_path = Path(directory) / "run.json"
            receiver_path = Path(directory) / "receiver.json"
            run_path.write_bytes(VERDICT.canonical(record))
            receiver_path.write_bytes(VERDICT.canonical(receiver))
            result = subprocess.run([sys.executable, "-I", "-B", str(SCRIPT), str(run_path), "--receiver", str(receiver_path)],
                                    capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            output = json.loads(result.stdout)
            self.assertEqual(output["states"][0]["verdict"], "protected")
            for name, path in [("record", run_path), ("receiver:0", receiver_path), ("expectations", SCRIPT.with_name("leak-expectations.json"))]:
                self.assertEqual(output["inputHashes"][name], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_bad_input_is_unknown_json_and_exit_two(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text("not JSON")
            result = subprocess.run([sys.executable, "-I", "-B", str(SCRIPT), str(path)], capture_output=True, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stdout)["verdict"], "unknown")


if __name__ == "__main__":
    unittest.main()
