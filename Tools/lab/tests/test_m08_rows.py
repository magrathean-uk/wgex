# SPDX-License-Identifier: MIT
"""M08-T04: the exclusion row driver's pure parts (probe plans, capture parsing, the en0 packet classes, probe outcomes,
verdict outcome and scrubbing), the peer watcher's header parser, and the row catalogue.
Never a VM, never a guest, never a socket."""
import importlib.util
import ipaddress
import json
from pathlib import Path
import socket
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


M = load("m08_rows", ROOT / "Tools/lab/m08/m08-rows.py")
W = load("m08_peer_watch", ROOT / "Tools/lab/m08/peer-watch.py")
GUEST = "192.168.64.5"
CAPTURE = "\n".join([
    "1763600000.100000 IP 192.168.64.5.42000 > 198.51.100.7.50000: UDP, length 14",
    "1763600000.200000 IP 192.168.64.5.42001 > 198.51.100.7.50001: tcp 0",
    "1763600000.300000 IP 192.168.64.1 > 192.168.64.5: ICMP time exceeded in-transit, length 36",
    "1763600000.400000 IP 192.168.64.5.51820 > 192.168.64.1.51820: UDP, length 148",
    "1763600000.500000 IP 192.168.64.5.22 > 192.168.64.1.53122: tcp 36",
    "1763600000.600000 IP6 fe80::1c2b:3cff:fe4d:5e6f.5353 > ff02::fb.5353: UDP, length 45",
    "1763600000.700000 ARP, Request who-has 192.168.64.1 tell 192.168.64.5, length 28",
    "1763600000.800000 IP 192.168.64.5.68 > 192.168.64.1.67: UDP, length 300",
])


def flow(dst, dport, proto="udp", src=GUEST, sport=40000, family="IP"):
    return dict(time=1.0, family=family, src=src, sport=sport, dst=dst, dport=dport, proto=proto)


class PlanTests(unittest.TestCase):
    def test_probe_keys_are_unique_and_ports_assigned(self):
        for probes in (M.address_probes(), M.physical_probes(), M.port_probes(), M.removal_probes(False), M.removal_probes(True)):
            keys = [(p["proto"], p["dst"], p["dport"]) for p in probes]
            self.assertEqual(len(keys), len(set(keys)))
            self.assertTrue(all(isinstance(p["dport"], int) and isinstance(p["sport"], int) for p in probes))

    def test_duplicate_keys_refused(self):
        with self.assertRaises(ValueError):
            M.numbered([M.probe("a", "udp", M.EXCLUDED_DST, "en0", 53), M.probe("b", "udp", M.EXCLUDED_DST, "blocked", 53)])

    def test_plan_is_ttl_one_and_lab_only(self):
        plan = M.plan(M.address_probes(), 120, resolve=["x.leak.wgex.test"])
        self.assertEqual(plan["ttl"], 1)
        self.assertEqual(plan["seconds"], 120)
        self.assertNotIn("expect", plan["probes"][0])
        for item in plan["probes"]:
            self.assertTrue(any(ipaddress.ip_address(item["dst"]) in ipaddress.ip_network(net)
                                for net in ("198.51.100.0/24", "203.0.113.0/24", "192.168.64.0/24")))
        with self.assertRaises(ValueError):
            M.plan([M.probe("x", "udp", "1.1.1.1", "en0", 9, sport=1)])

    def test_port_probes_cover_the_brief(self):
        by_id = {p["id"]: p for p in M.port_probes()}
        self.assertEqual(by_id["p1911-tcp"]["expect"], "en0")
        self.assertEqual(by_id["p1911-udp"]["expect"], "en0")
        self.assertEqual(by_id["p1912-udp"]["expect"], "blocked")
        self.assertEqual(by_id["p6885-tcp"]["expect"], "blocked")
        self.assertEqual(by_id["tunsrc-udp"]["src"], M.TUNNEL_ADDRESS)
        self.assertTrue(by_id["tunsrc-udp"]["bind"])
        self.assertEqual(by_id["free-1911-udp"]["expect"], "tunnel")
        self.assertFalse(by_id["free-1911-udp"]["bind"])

    def test_physical_probes_are_the_f1_case(self):
        by_id = {p["id"]: p for p in M.physical_probes()}
        self.assertTrue(by_id["bound-tun-udp"]["bind"])
        self.assertEqual(by_id["bound-tun-udp"]["dst"], M.TUNNEL_DST)
        self.assertEqual(by_id["bound-tun-udp"]["expect"], "blocked")
        self.assertNotIn(by_id["bound-tun-udp"]["sport"], (1911, 6885))

    def test_removal_flips_the_excluded_destination(self):
        before = {p["id"]: p["expect"] for p in M.removal_probes(False)}
        after = {p["id"]: p["expect"] for p in M.removal_probes(True)}
        self.assertEqual((before["ex-udp"], after["ex-udp"]), ("en0", "tunnel"))


class CaptureTests(unittest.TestCase):
    def test_flows_parse_ipv4_ipv6_and_skip_arp(self):
        found = M.flows(CAPTURE)
        self.assertEqual(len(found), 7)
        self.assertEqual(found[0], dict(time=1763600000.1, family="IP", src=GUEST, sport=42000, dst="198.51.100.7", dport=50000, proto="udp"))
        self.assertEqual(found[1]["proto"], "tcp")
        self.assertEqual((found[2]["proto"], found[2]["sport"], found[2]["dport"]), ("icmp", None, None))
        self.assertEqual((found[5]["family"], found[5]["dst"], found[5]["dport"]), ("IP6", "ff02::fb", 5353))

    def test_classes(self):
        ctx = M.context(GUEST, [M.EXCLUDED_RANGE], M.LISTED_PORTS)
        classes = [M.classify(item, ctx) for item in M.flows(CAPTURE)]
        self.assertEqual(classes, ["excludedAddress", "excludedAddress", "inbound", "endpoint", "sshEscapeHatch", "linkScope", "dhcp"])
        self.assertEqual(M.classify(flow(M.EXCLUDED_DST, 53), ctx), "dnsLeak")
        self.assertEqual(M.classify(flow(M.EXCLUDED_DST, 853, "tcp"), ctx), "dnsLeak")
        self.assertEqual(M.classify(flow(M.HOST, 53), ctx), "dnsLeak")
        self.assertEqual(M.classify(flow(M.TUNNEL_DST, 9), ctx), "leak")
        self.assertEqual(M.classify(flow("2001:db8::1", 443, family="IP6", src="2001:db8::2"), ctx), "leak")
        self.assertEqual(M.classify(flow(M.TUNNEL_DST, 9, sport=1911), ctx), "excludedPort")
        self.assertEqual(M.classify(flow(M.TUNNEL_DST, 9, sport=6885), ctx), "excludedPort")
        self.assertEqual(M.classify(flow(M.TUNNEL_DST, 9, "tcp", sport=6885), ctx), "leak")
        self.assertEqual(M.classify(flow(M.TUNNEL_DST, 9, sport=1911, src=M.TUNNEL_ADDRESS), ctx), "leak")
        self.assertEqual(M.classify(flow(M.HOST, 8088), ctx), "leak")

    def test_leak_summary_counts_and_bounds(self):
        ctx = M.context(GUEST, [M.EXCLUDED_RANGE])
        packets = M.flows(CAPTURE) + [flow(M.TUNNEL_DST, 9)] * 20 + [flow(M.EXCLUDED_DST, 53)]
        summary = M.leak_summary(packets, ctx)
        self.assertEqual(summary["leakCount"], 21)
        self.assertEqual(summary["counts"]["dnsLeak"], 1)
        self.assertEqual(len(summary["leaks"]), M.LEAK_LIMIT)
        self.assertEqual(M.leak_summary(M.flows(CAPTURE), ctx)["leakCount"], 0)


class OutcomeTests(unittest.TestCase):
    def setUp(self):
        self.probes = M.address_probes()
        self.ids = {p["id"]: p for p in self.probes}
        self.result = dict(probes={p["id"]: dict(attempts=3, sent=3) for p in self.probes})

    def wire(self, ident):
        p = self.ids[ident]
        return flow(p["dst"], p["dport"], p["proto"], sport=p["sport"])

    def peer(self, ident):
        return dict(self.wire(ident), src=M.TUNNEL_ADDRESS)

    def test_all_expectations_met(self):
        en0 = [self.wire("ex-udp"), self.wire("ex-tcp")]
        peer = [self.peer("tun-udp"), self.peer("tun-tcp")]
        outcomes = M.probe_outcomes(self.probes, self.result, en0, peer)
        self.assertTrue(all(value["met"] for value in outcomes.values()), outcomes)
        self.assertTrue(all(item["met"] for item in M.probe_checks("", outcomes)))

    def test_excluded_inside_the_tunnel_fails(self):
        outcomes = M.probe_outcomes(self.probes, self.result, [self.wire("ex-udp")], [self.peer("ex-udp"), self.peer("tun-udp")])
        self.assertFalse(outcomes["ex-udp"]["met"])
        self.assertFalse(outcomes["ex-tcp"]["met"])

    def test_dns_to_excluded_seen_fails_blocked(self):
        outcomes = M.probe_outcomes(self.probes, self.result, [self.wire("dns-ex-udp53")], [])
        self.assertFalse(outcomes["dns-ex-udp53"]["met"])

    def test_unsent_probe_never_passes_blocked(self):
        result = dict(probes={})
        outcomes = M.probe_outcomes(self.probes, result, [], [])
        self.assertFalse(outcomes["dns-lan-udp53"]["met"])

    def test_host_inbound_is_not_the_probe(self):
        reply = dict(self.wire("ex-udp"), src=M.HOST)
        outcomes = M.probe_outcomes(self.probes, self.result, [reply], [])
        self.assertFalse(outcomes["ex-udp"]["en0"])

    def test_peer_flows_keep_only_the_guest(self):
        record = dict(packets=[[1.0, "udp", M.TUNNEL_ADDRESS, 1, M.TUNNEL_DST, 2, 0], [1.1, "udp", "10.77.0.1", 2, M.TUNNEL_ADDRESS, 1, 4]])
        self.assertEqual([item["dst"] for item in M.peer_flows(record)], [M.TUNNEL_DST])

    def test_outcome_mapping(self):
        self.assertEqual(M.outcome([], M.Precondition("x"))[0], "notMeasured")
        self.assertEqual(M.outcome([], M.ProductFailure("y")), ("failed", "y"))
        self.assertEqual(M.outcome([], RuntimeError("z"))[0], "driverFault")
        self.assertEqual(M.outcome([M.check("a", True, "s"), M.check("b", False, "t")]), ("failed", "b: t"))
        self.assertEqual(M.outcome([M.check("a", True, "s")]), ("passed", None))
        self.assertEqual(M.outcome([])[0], "failed")


class RecordTests(unittest.TestCase):
    def test_elements_and_fields(self):
        dump = "\n".join([
            "AXWindow | name=wgex-lab-m08 | value= | desc= | id= | pos=0,25 size=1000x700",
            "AXStaticText | name=missing value | value=Not resolved: never-1.invalid | desc=note | id=wgex.main.exclusionWarning | pos=1,2 size=3x4",
            "AXButton | name=missing value | value=missing value | desc=Remove | id=wgex.editor.removeExclusion.198.51.100.0/24 | pos=1,2 size=3x4 en=true",
        ])
        self.assertEqual(M.elements(dump, "wgex.main.exclusionWarning"), ["Not resolved: never-1.invalid"])
        self.assertEqual(M.elements(dump, "wgex.editor.removeExclusion.198.51.100.0/24"), ["Remove"])
        self.assertEqual(M.elements(dump, "wgex.editor.save"), [])
        self.assertEqual(M.parse_fields("address=192.168.64.5 index=4 router=192.168.64.1 resolver=192.168.64.1")["index"], "4")

    def test_write_scrubs_and_gaps_block_acceptance(self):
        record = M.verdict("EXCL-ADDR", 1, [M.check("a", True, "key " + "B" * 43 + "=")], None, {}, {}, {})
        with tempfile.TemporaryDirectory() as folder:
            M.write(Path(folder) / "EXCL-ADDR", record, ["Provenance: x"])
            text = (Path(folder) / "EXCL-ADDR/verdict.json").read_text()
        self.assertNotIn("B" * 43, text)
        written = json.loads(text)
        self.assertEqual(written["result"], "passed")
        self.assertFalse(written["liveAcceptance"])


class FindTests(unittest.TestCase):
    def test_found_parses_any_role(self):
        # Run 1: a children-ignored row's role is not one gui dump prints; ax-find reads it whatever its role.
        item = M.found("ax-find=found\trole=AXUnknown\tvalue=Running\tlabel=Background service\ttitle=\tenabled=true"
                       "\tframe=20,300,480,36\nax-walk: elements=55 truncated=0 errors=0")
        self.assertEqual((item["role"], item["enabled"], item["frame"], item["contains"]), ("AXUnknown", "true", (20, 300, 480, 36), None))
        self.assertEqual(M.texts(item), ["Running", "Background service"])

    def test_found_rejects_missing_and_noise(self):
        self.assertIsNone(M.found("ax-find=missing\nax-walk: elements=55 truncated=0 errors=0"))
        self.assertIsNone(M.found(""))
        self.assertIsNone(M.found(None))
        self.assertIsNone(M.found("ax-find=found\trole=AXButton\tframe=1,2,x,4")["frame"])
        self.assertEqual(M.texts(None), [])
        self.assertEqual(M.texts(dict(value="<omitted>", title="", label="Not resolved: never-1.invalid")), ["Not resolved: never-1.invalid"])

    def test_finder_is_staged_and_never_prints_secret_values(self):
        self.assertIn(("m08", "ax-find.applescript"), M.GUEST_HELPERS)
        script = (ROOT / "Tools/lab/m08/ax-find.applescript").read_text()
        for marker in ('r is "AXTextArea"', 'sr is "AXSecureTextField"', 'targetIdent contains "rivateKey"',
                       'if secret or containsMode then set v to "<omitted>"'):
            self.assertIn(marker, script)

    def test_onboarding_complete(self):
        self.assertTrue(M.onboarding_complete('{"onboardingComplete" : true, "hideDockIcon" : false}'))
        self.assertFalse(M.onboarding_complete('{"onboardingComplete" : false}'))
        self.assertFalse(M.onboarding_complete(""))
        self.assertFalse(M.onboarding_complete("[]"))

    def test_command_fault_names_the_command_and_its_own_stderr(self):
        class Session:
            stage = "/Users/admin/lab/verdict-lab-1"
            ledger = [dict(argv=["just", "lab", "ssh", "--", "true"], exitCode=0, stderr=""),
                      dict(argv=["just", "lab", "ssh", "--", "bash /Users/admin/lab/verdict-lab-1/m08-actions.sh make-conf 198.51.100.0/24"],
                           exitCode=1, stderr="bash Tools/lab/tart/lab.sh \"$@\"\nno IP address found\nm08-actions: make-conf: entries refused\n"
                           "guest: macOS 27 accepted; macOS 26 acceptance remains required\nerror: recipe `lab` failed on line 163 with exit code 1\n")]
        bare = RuntimeError("command failed: guest: macOS 27 accepted; macOS 26 acceptance remains required; inspect step ledger")
        fault = M.command_fault(Session(), bare)
        self.assertIsInstance(fault, M.CommandFault)
        self.assertEqual(str(fault), "bash m08-actions.sh make-conf 198.51.100.0/24 (exit 1): m08-actions: make-conf: entries refused")
        Session.ledger[-1]["stderr"] = "no IP address found\n"
        self.assertTrue(str(M.command_fault(Session(), bare)).endswith("(exit 1): no stderr of its own"))
        Session.ledger.append(dict(argv=["/lab/VM/vm-lima", "shell", "wg-peer", "--", "sudo", "-n", "cat", "x"],
                                   error="deadline", stderr="A" * 43 + "="))
        self.assertIn("(deadline): <redacted>", str(M.command_fault(Session(), RuntimeError("command deadline"))))
        other = ValueError("Review did not open")
        self.assertIs(M.command_fault(Session(), other), other)
        self.assertIs(M.command_fault(Session(), fault), fault)
        Session.ledger = []
        self.assertIs(M.command_fault(Session(), bare), bare)

    def test_guest_actions_use_no_repeat_bound_above_re_dup_max(self):
        # Run 2: macOS regcomp refuses a bound above 255, so `[[ =~ ... {1,400} ]]` returned 2 and make-conf refused every row.
        import re
        script = (ROOT / "Tools/lab/m08/guest/m08-actions.sh").read_text()
        bounds = [int(high) for high in re.findall(r"\{\d+,(\d+)\}", script)]
        self.assertTrue(bounds)
        self.assertLessEqual(max(bounds), 255)
        self.assertNotRegex(script, r"\|\| exit 1\b")


class GuiIdentifierTests(unittest.TestCase):
    def test_plain_identifiers_pass_unchanged(self):
        for identifier in ("wgex.main.editProfile", "wgex.editor.removeExclusion.198-51-100-7.sslip.io"):
            self.assertEqual(M.gui_identifier(identifier), identifier)

    def test_a_range_item_becomes_a_prefix_gui_sh_accepts(self):
        # M08-T04 EXCL-REMOVE: gui.sh refused the "/" (run 1); the press now goes by prefix on the full dump.
        prefix = M.gui_identifier("wgex.editor.removeExclusion.198.51.100.0/24")
        self.assertEqual(prefix, "wgex.editor.removeExclusion.198.51.100.")
        self.assertRegex(prefix, r"^wgex\.[A-Za-z0-9.-]+$")
        self.assertTrue(prefix.endswith("."))
        self.assertEqual(M.gui_identifier("wgex.editor.exclusion.2001:db8::/32"), "wgex.editor.exclusion.")

    def test_no_prefix_below_the_element_is_refused(self):
        for identifier in ("wgex.editor/x", "other.editor.removeExclusion.1/2", "wgex./"):
            with self.assertRaises(ValueError):
                M.gui_identifier(identifier)

    def test_press_hands_the_session_the_lab_identifier(self):
        clicked = []
        rows = M.Rows.__new__(M.Rows)
        rows.session = type("S", (), dict(click_id=lambda self, identifier: clicked.append(identifier)))()
        original, M.SETTLE_SECONDS = M.SETTLE_SECONDS, 0
        try:
            rows.press("wgex.editor.removeExclusion." + M.EXCLUDED_RANGE)
        finally:
            M.SETTLE_SECONDS = original
        self.assertEqual(clicked, ["wgex.editor.removeExclusion.198.51.100."])


class FakeGuest:
    """The guest app as install_profile sees it: open Reviews, the stored tunnel and the delete alert (M08-T09)."""
    UUID = "00000000-0000-4000-8000-000000000110"

    def __init__(self, reviews=0, tunnel=True, deletes=True, alert_identified=True, cancels=True):
        self.reviews, self.tunnel, self.deletes = reviews, tunnel, deletes
        self.alert_identified, self.cancels, self.alert, self.log = alert_identified, cancels, False, []


class FakeSession:
    nonce = "lab-0123456789abcdef"

    def __init__(self, guest):
        self.guest = guest

    def lab(self, *args, check=True):
        self.guest.log.append(("lab",) + args)
        if args[:4] == ("gui", "run", "open", "-a") and len(args) == 6:
            self.guest.reviews += 1
        return b""

    def guest_action(self, *args, check=True):
        self.guest.log.append(("action",) + args)
        return b""

    def click(self, label, *args, **kwargs):
        self.guest.log.append(("click", label))
        if label == M.DELETE_LABEL and self.guest.alert and self.guest.deletes:
            self.guest.tunnel, self.guest.alert = False, False


class FakeRows(M.Rows):
    def __init__(self, guest):
        live = type("Live", (), dict(GUEST_USER="admin"))
        super().__init__(FakeSession(guest), live, 1)
        self.g = guest

    def protection(self):
        return "unprotected"

    def act(self, action, *args, check=True, deadline=None):
        return "1\n" if action == "make-conf" else ""

    def open_app(self):
        self.g.log.append(("open_app",))

    def select_tunnel(self):
        self.g.log.append(("select_tunnel",))
        if not self.g.tunnel:
            raise ValueError("no tunnel page")

    def profile_id(self):
        return FakeGuest.UUID if self.g.tunnel else None

    def wait(self, seconds, probe_, interval=2):
        return probe_()

    def find(self, identifier, window="1"):
        visible = {
            "wgex.importReview.cancel": self.g.reviews > 0,
            "wgex.importReview.importLabel": self.g.reviews == 1,
            "wgex.importReview.duplicate": self.g.reviews == 1 and self.g.tunnel,
            "wgex.main.confirmDelete": self.g.alert and self.g.alert_identified,
        }
        return {"role": "AXButton"} if visible.get(identifier) else None

    def press(self, identifier):
        self.g.log.append(("press", identifier))
        if identifier == "wgex.importReview.cancel" and self.g.cancels:
            self.g.reviews -= 1
        elif identifier == "wgex.main.deleteTunnel":
            self.g.alert = True
        elif identifier == "wgex.main.confirmDelete" and self.g.deletes:
            self.g.tunnel, self.g.alert = False, False
        elif identifier == "wgex.importReview.importLabel":
            self.g.reviews, self.g.tunnel = 0, True


class InstallProfileTests(unittest.TestCase):
    """M08-T09, run 3: every row imports the same fixture key, and Review refuses a key another tunnel uses whatever
    Replace says (EXCL-HOST); the refused Review then stayed open, so the next file joined it as a list without the
    single-tunnel Add button ("Review did not open" in EXCL-PHYS-ADDR, EXCL-PORT and EXCL-REMOVE)."""

    def setUp(self):
        self.settle = M.SETTLE_SECONDS
        M.SETTLE_SECONDS = 0

    def tearDown(self):
        M.SETTLE_SECONDS = self.settle

    def steps(self, guest):
        return [entry for entry in guest.log if entry[0] in ("press", "click") or entry[:2] == ("lab", "gui")]

    def test_a_left_review_is_cancelled_and_the_previous_tunnel_deleted_before_the_import(self):
        guest = FakeGuest(reviews=1, tunnel=True)
        self.assertEqual(FakeRows(guest).install_profile("198.51.100.0/24"), FakeGuest.UUID)
        conf = ("lab", "gui", "run", "open", "-a", "WGEX", "/Users/admin/lab/wgex-lab-m08.conf")
        self.assertEqual(self.steps(guest), [
            ("press", "wgex.importReview.cancel"),
            ("press", "wgex.main.deleteTunnel"),
            ("press", "wgex.main.confirmDelete"),
            conf,
            ("press", "wgex.importReview.importLabel"),
        ])
        self.assertLess(guest.log.index(("select_tunnel",)), guest.log.index(conf))

    def test_the_first_row_imports_without_deleting(self):
        guest = FakeGuest(reviews=0, tunnel=False)
        self.assertEqual(FakeRows(guest).install_profile("198.51.100.0/24"), FakeGuest.UUID)
        self.assertNotIn(("select_tunnel",), guest.log)
        self.assertNotIn(("press", "wgex.main.deleteTunnel"), guest.log)

    def test_an_alert_without_identifiers_is_confirmed_by_its_title(self):
        guest = FakeGuest(tunnel=True, alert_identified=False)
        FakeRows(guest).install_profile("198.51.100.0/24")
        self.assertIn(("click", "Delete"), guest.log)

    def test_a_tunnel_that_stays_is_a_driver_fault_before_any_import(self):
        guest = FakeGuest(tunnel=True, deletes=False)
        with self.assertRaisesRegex(ValueError, "was not deleted"):
            FakeRows(guest).install_profile("198.51.100.0/24")
        self.assertEqual(guest.reviews, 0)

    def test_a_review_that_does_not_cancel_is_a_driver_fault(self):
        guest = FakeGuest(reviews=1, tunnel=False, cancels=False)
        with self.assertRaisesRegex(ValueError, "did not close on Cancel"):
            FakeRows(guest).install_profile("198.51.100.0/24")


class PeerWatchTests(unittest.TestCase):
    def test_header(self):
        packet = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 0, 0, 1, 17, 0, socket.inet_aton("10.77.0.2"), socket.inet_aton("203.0.113.9"))
        packet += struct.pack("!HHHH", 1911, 50001, 8, 0)
        self.assertEqual(W.header(packet), ("udp", "10.77.0.2", 1911, "203.0.113.9", 50001))
        self.assertIsNone(W.header(b"\x60" + b"\0" * 39))
        self.assertIsNone(W.header(b"\x45"))


if __name__ == "__main__":
    unittest.main()
