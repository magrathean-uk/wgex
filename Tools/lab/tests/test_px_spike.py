# SPDX-License-Identifier: MIT
"""M08-T16: the port-exclusion spike driver's pure parts (rule text generation, pfctl read-back and state parsing, probe
plans, wire judgement and the go/no-go verdict) and the guest scripts' guards. Never a VM, never a guest, never a socket."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


P = load("px_spike", ROOT / "Tools/lab/m08/px-spike.py")
U = "192.168.64.5"
A = P.TUNNEL_ADDRESS
ECHO = ("1.1.1.1", 80)
STUN = ("162.159.207.0", 3478)


def flow(dst, dport, proto="udp", src=U, sport=1911):
    return dict(time=1.0, family="IP", src=src, sport=sport, dst=dst, dport=dport, proto=proto)


def window(probes, en0=(), utun=(), peer=(), results=None):
    return dict(en0=list(en0), utun=list(utun), peer=list(peer), result=dict(probes=results or {}))


def good_measurements():
    """A run in which every check holds (the shape Spike.run fills)."""
    probes = P.main_probes(U, ECHO, STUN)
    en0, peer, results = [], [], {}
    for item in probes:
        ident = item["id"]
        results[ident] = {"attempts": 1, "sent": 1}
        if ident.startswith("d-"):
            peer.append(flow(item["dst"], item["dport"], item["proto"], src=A, sport=item["sport"]))
        else:
            for _ in range(P.FLOW_SENDS if ident.startswith("k-") else 1):
                en0.append(flow(item["dst"], item["dport"], item["proto"], sport=item["sport"]))
    results["k-flow-1911"]["sent"] = P.FLOW_SENDS
    results["b-tcp-echo"].update(connected=1, response=1, status="HTTP/1.1 301", local=f"{A}:1911")
    results["b-stun"].update(response=1, mappedPort=1911)
    main = P.wire(probes, window(probes, en0, (), peer, results), U)
    h_items = P.h_probes()
    h = P.wire(h_items, window(h_items, results={i["id"]: {"attempts": 3, "sent": 3} for i in h_items}), U)
    text = P.rule_text("utun4", "192.168.64.1")
    nat = [line for line in text.splitlines() if line.startswith("nat ")]
    rules = [line for line in text.splitlines() if line.startswith("pass ")]
    states = ([f"en0 udp {U}:1911 ({A}:1911) -> 203.0.113.9:50109 MULTIPLE:SINGLE"],
              [f"en0 udp {U}:1911 ({A}:1911) -> 203.0.113.9:50109 MULTIPLE:SINGLE"], [])
    return dict(main=main, h=h, hTunnelSourced=0, loaded=(nat, rules), rendered=P.rule_counts(text), emptied=([], []),
                states=states, ipv6=["default fe80::1%en0 en0"])


class RuleTextTests(unittest.TestCase):
    def test_design_example_lines_for_1911_udp(self):
        text = P.rule_text("utun4", "192.168.64.1")
        for line in (
                "nat on en0 inet proto udp from 10.77.0.2 port 1911 to any tag WGEX_PX -> (en0:0) static-port",
                "pass out quick on utun4 inet proto udp from 10.77.0.2 port 1911 to 10.77.0.0/24 no state",
                "pass out quick on utun4 inet proto udp from 10.77.0.2 port 1911 to 10.77.0.1 no state",
                "pass out quick on utun4 inet proto udp from 10.77.0.2 port 1911 to any port 53 no state",
                "pass out quick on utun4 inet proto udp from 10.77.0.2 port 1911 to any port 853 no state",
                "pass out quick on utun4 route-to (en0 192.168.64.1) inet proto udp from 10.77.0.2 port 1911 to any no state",
                "pass out quick on utun4 route-to (en0 192.168.64.1) inet proto udp from (en0) port 1911 to any no state",
                "pass out quick on en0 inet proto udp from (en0) port 1911 to any tagged WGEX_PX keep state (if-bound)",
                "pass out quick on en0 inet proto udp from (en0) port 1911 to any no state",
                "pass in quick on en0 inet proto udp from any to (en0) port 1911 no state"):
            self.assertIn(line + "\n", text)

    def test_tcp_flags_range_and_udp_only_range(self):
        text = P.rule_text("utun4", "192.168.64.1")
        self.assertIn("from (en0) port 1911 to any flags S/SA tagged WGEX_PX keep state (if-bound)", text)
        self.assertIn("port 6881:6889", text)
        self.assertNotIn("proto tcp from 10.77.0.2 port 6881:6889", text)

    def test_translation_precedes_filtering_and_counts(self):
        text = P.rule_text("utun4", "192.168.64.1")
        lines = [line for line in text.splitlines() if not line.startswith("#")]
        last_nat = max(i for i, line in enumerate(lines) if line.startswith("nat "))
        first_pass = min(i for i, line in enumerate(lines) if line.startswith("pass "))
        self.assertLess(last_nat, first_pass)
        # Three (transport, port) pairs: 1 nat, 6 tunnel and 3 physical rules each.
        self.assertEqual(P.rule_counts(text), (3, 27))

    def test_no_nat_variant_keeps_route_to(self):
        text = P.rule_text("utun4", "192.168.64.1", nat=False)
        self.assertEqual(P.rule_counts(text), (0, 27))
        self.assertIn("route-to (en0 192.168.64.1)", text)

    def test_tagged_pass_precedes_the_untagged_pass(self):
        lines = P.rule_text("utun4", "192.168.64.1").splitlines()
        tagged = lines.index("pass out quick on en0 inet proto udp from (en0) port 1911 to any tagged WGEX_PX keep state (if-bound)")
        plain = lines.index("pass out quick on en0 inet proto udp from (en0) port 1911 to any no state")
        self.assertLess(tagged, plain)

    def test_bad_values_refused(self):
        for args in (("utun4;", "192.168.64.1"), ("utun4", "192.168.64.1 any"), ("lo0", "192.168.64.1")):
            with self.assertRaises(ValueError):
                P.rule_text(*args)


class ReadbackTests(unittest.TestCase):
    def test_parse_show_sections(self):
        text = "# nat\nNo ALTQ support in kernel\nnat on en0 inet proto udp from 10.77.0.2 port = 1911 to any tag WGEX_PX -> (en0:0) static-port\n" \
               "# rules\npass out quick on utun4 route-to (en0 192.168.64.1) inet proto udp from 10.77.0.2 port = 1911 to any no state\n# end\n"
        nat, rules = P.parse_show(text)
        self.assertEqual(len(nat), 1)
        self.assertEqual(len(rules), 1)
        self.assertEqual(P.parse_show("# nat\n# rules\n# end\n"), ([], []))

    def test_state_lines(self):
        table = "\n".join([
            f"en0 udp {U}:1911 ({A}:1911) -> 203.0.113.9:50109       MULTIPLE:SINGLE",
            f"utun4 udp {A}:52000 -> 10.77.0.1:53       SINGLE:NO_TRAFFIC",
            f"en0 tcp {U}:22 <- 192.168.64.1:53000       ESTABLISHED:ESTABLISHED",
            "en0 udp 110.77.0.2:9 -> 1.2.3.4:9  SINGLE:NO_TRAFFIC",
        ])
        self.assertEqual(len(P.state_lines(table, A)), 2)
        self.assertEqual(len(P.nat_state_lines(table, A, U)), 1)

    def test_endpoint_literal(self):
        self.assertEqual(P.endpoint_literal("1.1.1.1:80"), ("1.1.1.1", 80))
        for value in ("10.0.0.1:80", "203.0.113.9:80", "1.1.1.1", "1.1.1.1:0", "example.com:80"):
            with self.assertRaises(ValueError):
                P.endpoint_literal(value)


class PlanTests(unittest.TestCase):
    def test_lab_probes_ttl_one_and_round_trips_listed(self):
        probes = P.main_probes(U, ECHO, STUN)
        plan = P.plan(probes, public=(ECHO[0], STUN[0]))
        self.assertEqual(plan["ttl"], 1)
        self.assertEqual(plan["public"], [ECHO[0], STUN[0]])
        modes = {item["id"]: item["mode"] for item in plan["probes"]}
        self.assertEqual(modes["b-tcp-echo"], "tcp-echo")
        self.assertEqual(modes["b-stun"], "stun")
        self.assertEqual(modes["k-flow-1911"], "flow")
        self.assertNotIn("expect", plan["probes"][0])

    def test_unlisted_public_or_outside_destination_refused(self):
        with self.assertRaises(ValueError):
            P.plan(P.main_probes(U, ECHO, STUN), public=(ECHO[0],))
        with self.assertRaises(ValueError):
            P.plan([P.probe("x", "udp", "8.8.8.8", 9, 1911)])

    def test_probe_keys_unique(self):
        probes = P.main_probes(U, ECHO, STUN) + P.h_probes()
        keys = [(p["proto"], p["dst"], p["dport"]) for p in probes]
        self.assertEqual(len(keys), len(set(keys)))


class VerdictTests(unittest.TestCase):
    def test_all_good_is_go(self):
        checks = P.judge(good_measurements())
        for key in ("a", "b", "c", "d", "e", "f", "g", "h", "k"):
            self.assertEqual(checks[key]["state"], "PASS", (key, checks[key]))
        self.assertEqual(checks["i"]["state"], "notMeasured")
        self.assertEqual(P.gate(checks), "go")

    def test_untranslated_packet_on_en0_fails_h_and_the_gate(self):
        m = good_measurements()
        m["hTunnelSourced"] = 1
        checks = P.judge(m)
        self.assertEqual(checks["h"]["state"], "FAIL")
        self.assertEqual(P.gate(checks), "no-go")

    def test_packet_in_the_tunnel_fails_a(self):
        m = good_measurements()
        m["main"]["a-tcp-1911"]["peer"] = 1
        self.assertEqual(P.judge(m)["a"]["state"], "FAIL")
        self.assertEqual(P.gate(P.judge(m)), "no-go")

    def test_no_round_trip_fails_b(self):
        m = good_measurements()
        m["main"]["b-stun"]["result"].pop("response")
        self.assertEqual(P.judge(m)["b"]["state"], "FAIL")

    def test_later_flow_packets_in_the_tunnel_fail_k(self):
        m = good_measurements()
        m["main"]["k-flow-1911"]["en0Translated"] = 1
        m["main"]["k-flow-1911"]["peer"] = 4
        self.assertEqual(P.judge(m)["k"]["state"], "FAIL")

    def test_kill_leaving_states_fails_g(self):
        m = good_measurements()
        m["states"] = (m["states"][0], m["states"][1], m["states"][0])
        self.assertEqual(P.judge(m)["g"]["state"], "FAIL")

    def test_nothing_measured(self):
        checks = P.judge(dict(cause="Precondition: no nat-anchor"))
        self.assertTrue(all(checks[key]["state"] == "notMeasured" for key in P.CHECKS))
        self.assertEqual(P.gate(checks), "no-go")

    def test_evidence_page_lists_every_check(self):
        record = dict(attempt=1, verdict="go", result="go", cause=None, startedAt="t0", endedAt="t1", physical=U,
                      router="192.168.64.1", tunnelIf="utun4", echo="1.1.1.1:80", stun="162.159.207.0:3478",
                      checks=P.judge(good_measurements()), ruleText=P.rule_text("utun4", "192.168.64.1"), notes=["n"])
        page = P.evidence(record)
        self.assertIn("Gate verdict: **go**", page)
        for key in P.CHECKS:
            self.assertIn(f"| {key} | ", page)


class RoundThreeTests(unittest.TestCase):
    def test_reply_to_variants_touch_only_the_stateful_pass(self):
        base = P.rule_text("utun4", "192.168.64.1").splitlines()
        for name in ("v1", "v2"):
            lines = P.rule_text("utun4", "192.168.64.1", reply=P.REPLY_TO[name]).splitlines()
            changed = [(a, b) for a, b in zip(base, lines) if a != b]
            self.assertEqual(len(changed), 3)
            for old, new in changed:
                self.assertIn("keep state (if-bound)", old)
                self.assertEqual(new, old.replace("on en0 ", f"on en0 reply-to {P.REPLY_TO[name]} "))
        with self.assertRaises(ValueError):
            P.rule_text("utun4", "192.168.64.1", reply="(en0 1.2.3.4)")

    def test_log_marks_block_b_only(self):
        lines = P.rule_text("utun4", "192.168.64.1", log=True).splitlines()
        logged = [line for line in lines if "log (all)" in line]
        self.assertEqual(len(logged), 9)
        self.assertTrue(all(" on en0" in line for line in logged))

    def test_counters_and_drop_lines(self):
        before = "# sysctl\nnet.inet.ip.check_interface: 1\n# ip\n\t10 packets for this host\n\t0 input packet with no interface address match\n# udp\n\t3 dropped due to no socket\n# end\n"
        after = before.replace("\t0 input packet with no", "\t4 input packet with no").replace("\t10 packets", "\t12 packets")
        self.assertEqual(P.stack_sections(before)["sysctl"], ["net.inet.ip.check_interface: 1"])
        delta = P.counter_delta(P.counters(before), P.counters(after))
        self.assertEqual(delta, {"ip: packets for this host": 2, "ip: input packet with no interface address match": 4})
        self.assertIn("ip: input packet with no interface address match: +4", P.drop_lines(delta))

    def test_replies_and_gate(self):
        flows = [flow(U, 1911, "tcp", src="1.1.1.1", sport=80), flow(U, 1911, "tcp", src="1.1.1.1", sport=443)]
        self.assertEqual(len(P.replies(flows, "1.1.1.1", 80, U)), 1)
        good = P.judge(good_measurements())
        bad = dict(good, b=P.judged("FAIL", "x"))
        self.assertEqual(P.round3_gate({"v1": {"checks": bad}, "v2": {"checks": good}}), ("go", "v2"))
        self.assertEqual(P.round3_gate({"v0": {"checks": good}, "v1": {"checks": bad}}), ("no-go", None))


class GuestScriptTests(unittest.TestCase):
    def test_spike_script_writes_only_its_anchor(self):
        text = (ROOT / "Tools/lab/m08/guest/px-spike.sh").read_text()
        self.assertIn("guest_guard", text)
        self.assertIn("anchor=com.apple/100.wgex-px", text)
        for line in text.splitlines():
            if "pfctl" in line and (" -f " in line or " -F " in line):
                self.assertIn('-a "$anchor"', line)
        self.assertNotIn("com.apple/wgex ", text)
        self.assertIn("^10\\.77\\.0\\.[0-9]{1,3}$", text)

    def test_probe_round_trips_need_a_listed_literal(self):
        text = (ROOT / "Tools/lab/m08/guest/excl-probe.pl").read_text()
        self.assertIn("round-trip destination not listed in the plan", text)
        self.assertIn('die "ttl must be 1\\n" unless $ttl == 1;', text)
        self.assertIn("mappedPort", text)


if __name__ == "__main__":
    unittest.main()
