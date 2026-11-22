#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""M08-T16 (PX-SPIKE): the go/no-go measurement of the port-exclusion mechanism of design M08-T15 section 1 (pf
route-to on the tunnel interface plus NAT on the physical interface) in the macOS 27 guest. Lab tooling only.

  px-spike.py run --report-root DIR [--attempt 1|2]
  px-spike.py render --tunnel-if utun4 --router 192.168.64.1 [--no-nat]

Run by the lab job script through the M04-T22 row runner after the M08 job's restore, Lab build, `just lab
install`, peer (full4 fixture), relay start and `m08-rows.py setup`. The row imports the M08 port profile (the full4
fixture plus `# WGEX-Exclude = 1911, 6881-6889/udp`) through m08-rows.py's own path, activates it, then loads the
section 1 rules by hand into the sibling anchor com.apple/100.wgex-px (guest/px-spike.sh), which sorts before the
daemon's com.apple/wgex: its quick rules match first and the daemon's anchor and read-back are untouched. It measures:

- a. unbound UDP and TCP from 1911 (and UDP from 6885) to TEST-NET with TTL 1 leave en0 as U:port, nothing on utun;
- b. a round trip from local port 1911: a TCP handshake plus HTTP HEAD to WGEX_PX_TCP_ECHO (default 1.1.1.1:80) and a
  STUN binding (WGEX_PX_STUN, default the first A record of stun.cloudflare.com through the guest's physical resolver,
  looked up before the tunnel is up);
- c. a socket bound to U's address (not the interface) on 1911 leaves en0;
- d. an unlisted port, TCP on the UDP-only range, DNS from 1911 and the tunnel network from 1911 go through the tunnel;
- e. the anchor's -sn and -sr texts; f. an empty load flushes both; g. `pfctl -k A` removes the NAT states;
- h. route-to without the nat rule sends no A-sourced packet out of en0;
- k. later packets of one UDP flow from 1911 still leave en0 (if-bound state);
- i. IPv6: notMeasured (the full4 fixture carries no IPv6), with the guest's IPv6 router facts.

Gate: go only when a, b, h and k pass. Exit: 0 go, 1 no-go, 2 driver fault (the job retries once), 3 not measured.
The verdict (DIR/PX-SPIKE/verdict.json) and an evidence page (DIR/PX-SPIKE/evidence.md) carry the measured lines.
"""
import argparse
from datetime import datetime, timezone
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
LAB = ROOT / "Tools/lab"
ROW = "PX-SPIKE"
ANCHOR = "com.apple/100.wgex-px"
TAG = "WGEX_PX"
PHYSICAL = "en0"
TUNNEL_ADDRESS = "10.77.0.2"
TUNNEL_NETS = ("10.77.0.0/24",)
TUNNEL_DNS = ("10.77.0.1",)
DNS_PORTS = (53, 853)
ENTRIES = ((1911, 1911, None), (6881, 6889, "udp"))
PROFILE_ENTRIES = "1911, 6881-6889/udp"
TEST_DST = "203.0.113.9"
STUN_NAME = "stun.cloudflare.com"
STUN_PORT = 3478
FLOW_SENDS = 5
GATE = ("a", "b", "h", "k")
CHECKS = ("a", "b", "c", "d", "e", "f", "g", "h", "k", "i")
TITLES = dict(
    a="unbound UDP and TCP from a listed port leave en0 as U:port, nothing on utun",
    b="round trip from local port 1911 (TCP handshake + HTTP HEAD, UDP STUN binding)",
    c="a socket bound to U's address (not the interface) on 1911 leaves en0",
    d="unlisted port and DNS (and tunnel-only destinations) from 1911 go through the tunnel",
    e="-sn and -sr texts recorded for canonicalisation",
    f="an empty load flushes the nat ruleset",
    g="pfctl -k A removes the NAT states",
    h="route-to without the nat rule: no A-sourced packet on en0",
    k="later packets of one flow still leave en0 (if-bound state)",
    i="IPv6 forms of a and b and the NAT66 target choice",
)
EXIT = dict(go=0, noGo=1, driverFault=2, notMeasured=3)
LITERAL = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})")


# Pure parts (Tools/lab/tests/test_px_spike.py).

def port_text(low, high):
    return str(low) if low == high else f"{low}:{high}"


def transports(transport):
    return ("tcp", "udp") if transport is None else (transport,)


def per_entry(entries):
    """(transport, port text) pairs sorted by port then transport, so pf skip steps apply."""
    pairs = [(low, transport, port_text(low, high)) for low, high, entry in entries for transport in transports(entry)]
    return [(transport, text) for _, transport, text in sorted(pairs)]


def nat_rules(entries, physical, address):
    return [f"nat on {physical} inet proto {proto} from {address} port {port} to any tag {TAG} -> ({physical}:0) static-port"
            for proto, port in per_entry(entries)]


def tunnel_rules(entries, tunnel_if, physical, router, address, nets=TUNNEL_NETS, dns=TUNNEL_DNS):
    """Block A: keeps for tunnel-only destinations and DNS, then the route-to passes (no state on the tunnel)."""
    lines = []
    for proto, port in per_entry(entries):
        head = f"pass out quick on {tunnel_if}"
        source = f"inet proto {proto} from {address} port {port}"
        lines += [f"{head} {source} to {net} no state" for net in nets]
        lines += [f"{head} {source} to {server} no state" for server in dns]
        lines += [f"{head} {source} to any port {dns_port} no state" for dns_port in DNS_PORTS]
        lines.append(f"{head} route-to ({physical} {router}) {source} to any no state")
        lines.append(f"{head} route-to ({physical} {router}) inet proto {proto} from ({physical}) port {port} to any no state")
    return lines


# Round 3 reply-path variants: the reply-to target on block B's stateful pass (None keeps the T15 rules). The replies
# of a translated flow arrive on en0 addressed to A, which lives on the tunnel interface; reply-to sends them through
# lo0, where the stack accepts any local address.
REPLY_TO = {"v0": None, "v1": "(lo0 127.0.0.1)", "v2": "lo0"}


def physical_rules(entries, physical, reply=None, log=False):
    """Block B: the tagged if-bound stateful pass for translated packets, then the DEC-126 passes. reply: a reply-to
    target for the stateful pass (its inbound replies); log: `log (all)` on every block B rule (diagnostic only)."""
    if reply is not None and reply not in REPLY_TO.values():
        raise ValueError("reply-to target refused")
    lg = " log (all)" if log else ""
    rt = f" reply-to {reply}" if reply else ""
    lines = []
    for proto, port in per_entry(entries):
        flags = " flags S/SA" if proto == "tcp" else ""
        lines.append(f"pass out{lg} quick on {physical}{rt} inet proto {proto} from ({physical}) port {port} to any{flags} "
                     f"tagged {TAG} keep state (if-bound)")
        lines.append(f"pass out{lg} quick on {physical} inet proto {proto} from ({physical}) port {port} to any no state")
        lines.append(f"pass in{lg} quick on {physical} inet proto {proto} from any to ({physical}) port {port} no state")
    return lines


def rule_text(tunnel_if, router, address=TUNNEL_ADDRESS, physical=PHYSICAL, entries=ENTRIES, nat=True, reply=None, log=False):
    """The spike anchor's text: translation first (pfctl's order), then blocks A and B."""
    for value in (tunnel_if, physical):
        if not re.fullmatch(r"(utun|en)\d+", value):
            raise ValueError("interface name refused")
    for value in (router, address):
        ipaddress.IPv4Address(value)
    lines = ["# M08-T16 spike anchor " + ANCHOR]
    if nat:
        lines += nat_rules(entries, physical, address)
    lines += tunnel_rules(entries, tunnel_if, physical, router, address) + physical_rules(entries, physical, reply, log)
    return "\n".join(lines) + "\n"


def rule_counts(text):
    """(nat, filter) rule line counts of a rendered text."""
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    nat = sum(1 for line in lines if line.startswith("nat "))
    return nat, len(lines) - nat


def parse_show(text):
    """px-spike.sh show output as (nat lines, filter lines); pfctl's ALTQ/notice lines are dropped."""
    section, out = None, {"nat": [], "rules": []}
    for line in (text or "").splitlines():
        if line in ("# nat", "# rules", "# end"):
            section = line[2:] if line != "# end" else None
            continue
        if section and line.strip() and not line.startswith(("No ALTQ", "ALTQ")):
            out[section].append(line.rstrip())
    return out["nat"], out["rules"]


def state_lines(text, address):
    """State table lines naming address as a host (address:port or (address:port))."""
    pattern = re.compile(r"(?<![\d.])" + re.escape(address) + r"(?::\d+|\[\d+\])")
    return [line.strip() for line in (text or "").splitlines() if pattern.search(line)]


def nat_state_lines(text, address, physical_address):
    """The NAT states: lines naming both the tunnel and the physical address."""
    return [line for line in state_lines(text, address) if physical_address in line]


def endpoint_literal(text):
    match = LITERAL.fullmatch(text or "")
    if not match:
        raise ValueError("literal must be IPv4:port")
    address, port = match[1], int(match[2])
    value = ipaddress.IPv4Address(address)
    if not value.is_global or not 0 < port < 65536:
        raise ValueError("literal must be a public IPv4 address and a port")
    return address, port


def probe(ident, proto, dst, dport, sport, src=None, mode="probe", count=3, **extra):
    return dict(id=ident, proto=proto, dst=dst, dport=dport, sport=sport, src=src, bind=False, mode=mode, count=count, **extra)


def main_probes(physical_address, echo, stun):
    """The connected-window probes (checks a, b, c, d, k). Destination ports are unique so every probe is found on the
    wire by (proto, dst, dport)."""
    base = 50100
    items = [
        probe("a-udp-1911", "udp", TEST_DST, base + 0, 1911),
        probe("a-tcp-1911", "tcp", TEST_DST, base + 1, 1911),
        probe("a-udp-6885", "udp", TEST_DST, base + 2, 6885),
        probe("c-udp-1911", "udp", TEST_DST, base + 3, 1911, src=physical_address),
        probe("c-tcp-1911", "tcp", TEST_DST, base + 4, 1911, src=physical_address),
        probe("d-udp-1912", "udp", TEST_DST, base + 5, 1912),
        probe("d-tcp-1912", "tcp", TEST_DST, base + 6, 1912),
        probe("d-tcp-6885", "tcp", TEST_DST, base + 7, 6885),
        probe("d-dns-udp53", "udp", TEST_DST, 53, 1911),
        probe("d-dns-tcp853", "tcp", TEST_DST, 853, 1911),
        probe("d-tunnel-net", "udp", TUNNEL_DNS[0], base + 8, 1911),
        probe("k-flow-1911", "udp", TEST_DST, base + 9, 1911, mode="flow", count=1, sends=FLOW_SENDS, gap=1),
        probe("b-tcp-echo", "tcp", echo[0], echo[1], 1911, mode="tcp-echo", count=1),
        probe("b-stun", "udp", stun[0], stun[1], 1911, mode="stun", count=2),
    ]
    keys = [(item["proto"], item["dst"], item["dport"]) for item in items]
    if len(set(keys)) != len(keys):
        raise ValueError("probe keys must be unique")
    return items


def h_probes():
    return [probe("h-udp-1911", "udp", TEST_DST, 50200, 1911), probe("h-tcp-1911", "tcp", TEST_DST, 50201, 1911)]


def plan(probes, public=()):
    """excl-probe.pl's plan: TTL 1 for every lab probe; the round-trip modes only to the listed public literals."""
    lab = [ipaddress.ip_network(net) for net in ("203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24", "10.77.0.0/24", "192.168.64.0/24")]
    for item in probes:
        address = ipaddress.ip_address(item["dst"])
        if item["mode"] in ("tcp-echo", "stun"):
            if item["dst"] not in public:
                raise ValueError("round-trip destination not listed")
        elif not any(address in net for net in lab):
            raise ValueError("probe destination outside the lab and TEST-NET ranges")
    keys = ("id", "proto", "dst", "dport", "sport", "bind", "src", "count", "mode", "sends", "gap")
    return dict(ttl=1, seconds=0, interval=1, resolve=[], public=list(public),
                probes=[{key: item[key] for key in keys if key in item} for item in probes])


def matching(flows, item, src=None, sport=None):
    return [flow for flow in flows if flow["proto"] in (item["proto"], "other") and flow["dst"] == item["dst"]
            and flow["dport"] == item["dport"] and (src is None or flow["src"] == src)
            and (sport is None or flow["sport"] == sport)]


def wire(items, window, physical_address, address=TUNNEL_ADDRESS):
    """Per probe: en0 packets as U:sport, en0 packets sourced A, any en0 packet, utun packets and peer packets."""
    out = {}
    for item in items:
        out[item["id"]] = dict(
            en0Translated=len(matching(window["en0"], item, physical_address, item["sport"])),
            en0TunnelSource=len(matching(window["en0"], item, address)),
            en0Any=len(matching(window["en0"], item)),
            utun=len(matching(window["utun"], item)),
            peer=len(matching(window["peer"], item)),
            result={key: value for key, value in (window["result"].get("probes", {}).get(item["id"]) or {}).items()})
    return out


def judged(state, summary, lines=()):
    return dict(state=state, summary=summary, lines=[str(line)[:300] for line in lines][:40])


def judge_outside(ids, measured):
    """Every probe left en0 translated and was seen neither on utun nor at the peer."""
    rows = [measured[ident] for ident in ids]
    ok = all(r["en0Translated"] > 0 and r["en0TunnelSource"] == 0 and r["utun"] == 0 and r["peer"] == 0 for r in rows)
    return ok, [f"{ident}: en0 as U {measured[ident]['en0Translated']}, en0 as A {measured[ident]['en0TunnelSource']}, "
                f"utun {measured[ident]['utun']}, peer {measured[ident]['peer']}, probe {measured[ident]['result']}" for ident in ids]


def judge_b(w):
    """Check b from one window: both round trips answered, sent on en0 as U, never at the peer."""
    echo, stun = w["b-tcp-echo"], w["b-stun"]
    echo_ok = "response" in echo["result"] and echo["en0Translated"] > 0 and echo["peer"] == 0
    stun_ok = "response" in stun["result"] and stun["en0Translated"] > 0 and stun["peer"] == 0
    return judged("PASS" if echo_ok and stun_ok else "FAIL", f"TCP echo {'ok' if echo_ok else 'failed'}, STUN {'ok' if stun_ok else 'failed'}",
                  [f"b-tcp-echo: {echo}", f"b-stun: {stun}"])


def judge(m):
    """The checks from one run's measurements (dict m, see Spike.run); each PASS, FAIL or notMeasured."""
    out = {}
    w = m.get("main")
    if w is None:
        cause = m.get("cause", "the connected window was not measured")
        for key in CHECKS:
            out[key] = judged("notMeasured", cause)
    else:
        ok, lines = judge_outside(("a-udp-1911", "a-tcp-1911", "a-udp-6885"), w)
        out["a"] = judged("PASS" if ok else "FAIL", "unbound sockets on 1911 (UDP, TCP) and 6885 (UDP)", lines)
        echo = w["b-tcp-echo"]
        out["b"] = judge_b(w)
        ok, lines = judge_outside(("c-udp-1911", "c-tcp-1911"), w)
        out["c"] = judged("PASS" if ok else "FAIL", "sockets bound to U's address, not to en0", lines)
        tunnel_ids = ("d-udp-1912", "d-tcp-1912", "d-tcp-6885", "d-dns-udp53", "d-dns-tcp853", "d-tunnel-net")
        ok = all(w[i]["peer"] > 0 and w[i]["en0Any"] == 0 for i in tunnel_ids)
        out["d"] = judged("PASS" if ok else "FAIL", "seen at the peer (inside the tunnel), not on en0",
                          [f"{i}: peer {w[i]['peer']}, en0 {w[i]['en0Any']}, utun {w[i]['utun']}" for i in tunnel_ids])
        flow = w["k-flow-1911"]
        sent = flow["result"].get("sent", 0)
        ok = sent >= FLOW_SENDS and flow["en0Translated"] >= sent and flow["peer"] == 0 and flow["utun"] == 0 and flow["en0TunnelSource"] == 0
        out["k"] = judged("PASS" if ok else "FAIL", f"one UDP socket, {sent} datagrams {FLOW_SENDS - 1} s apart",
                          [f"k-flow-1911: sent {sent}, en0 as U {flow['en0Translated']}, en0 as A {flow['en0TunnelSource']}, "
                           f"utun {flow['utun']}, peer {flow['peer']}", f"b-tcp-echo packets on en0 as U (whole connection): {echo['en0Translated']}"])
    nat, rules = m.get("loaded", ([], []))
    want = m.get("rendered", (0, 0))
    if m.get("loaded") is None:
        out["e"] = judged("notMeasured", "rules were not loaded")
    else:
        ok = (len(nat), len(rules)) == tuple(want) and all(TAG in line for line in nat) and any("route-to" in line for line in rules)
        out["e"] = judged("PASS" if ok else "FAIL", f"read back {len(nat)} nat and {len(rules)} filter lines (rendered {want[0]} and {want[1]})",
                          ["-sn: " + line for line in nat] + ["-sr: " + line for line in rules])
    if m.get("emptied") is None:
        out["f"] = judged("notMeasured", "the empty load was not reached")
    else:
        nat, rules = m["emptied"]
        out["f"] = judged("PASS" if not nat and not rules else "FAIL", f"after the empty load: {len(nat)} nat, {len(rules)} filter lines",
                          nat + rules)
    if m.get("states") is None:
        out["g"] = judged("notMeasured", "the state table was not read")
    else:
        before, nat_before, after = m["states"]
        ok = len(nat_before) > 0 and not after
        out["g"] = judged("PASS" if ok else "FAIL", f"before the kill {len(before)} states name A ({len(nat_before)} NAT); after {len(after)}",
                          ["before: " + line for line in before] + ["after: " + line for line in after])
    if m.get("h") is None:
        out["h"] = judged("notMeasured", m.get("hCause", "the route-to-only window was not measured"))
    else:
        h = m["h"]
        tunnel_source = m.get("hTunnelSourced", 0)
        lines = [f"{i}: en0 any {h[i]['en0Any']}, en0 as A {h[i]['en0TunnelSource']}, peer {h[i]['peer']}, utun {h[i]['utun']}, "
                 f"probe {h[i]['result']}" for i in h] + [f"en0 packets sourced {TUNNEL_ADDRESS} in the window: {tunnel_source}"]
        ok = tunnel_source == 0 and all(r["en0Any"] == 0 and r["peer"] == 0 for r in h.values())
        out["h"] = judged("PASS" if ok else "FAIL", "filter rules only (no nat section): the redirected packets die at the final block", lines)
    out["i"] = judged("notMeasured", "the full4 fixture routes no IPv6 into the tunnel (no tunnel IPv6 address); guest IPv6 facts recorded",
                      m.get("ipv6", []))
    return out


def gate(checks):
    return "go" if all(checks[key]["state"] == "PASS" for key in GATE) else "no-go"


def evidence(record):
    """The evidence page (markdown) of one verdict record."""
    lines = [f"# M08-T16 PX-SPIKE evidence (attempt {record['attempt']})", "",
             f"- Gate verdict: **{record['verdict']}** (go only if a, b, h and k pass); run result {record['result']}"
             + (f"; first cause: {record['cause']}" if record.get("cause") else ""),
             f"- Measured {record['startedAt']} to {record['endedAt']} in {record.get('guest', 'the macOS 27 guest')}; "
             f"U={record.get('physical')}, R={record.get('router')}, N={record.get('tunnelIf')}, A={TUNNEL_ADDRESS}; "
             f"anchor {ANCHOR}; profile entries `{PROFILE_ENTRIES}`",
             f"- Round-trip literals: TCP echo {record.get('echo')}, STUN {record.get('stun')}", ""]
    lines += ["| Check | State | Summary |", "|---|---|---|"]
    for key in CHECKS:
        item = record["checks"][key]
        lines.append(f"| {key} | {item['state']} | {TITLES[key]}: {item['summary']} |")
    for key in CHECKS:
        item = record["checks"][key]
        if item["lines"]:
            lines += ["", f"## {key}. {TITLES[key]}", "", "```"] + item["lines"] + ["```"]
    for name, text in (("Rendered rules (connected window)", record.get("ruleText")), ("Rendered rules (check h)", record.get("hRuleText")),
                       ("Main ruleset translation anchors (pfctl -s nat)", record.get("mainNat"))):
        if text:
            lines += ["", f"## {name}", "", "```", text.rstrip(), "```"]
    if record.get("notes"):
        lines += ["", "## Notes", ""] + [f"- {note}" for note in record["notes"]]
    return "\n".join(lines) + "\n"


# Round 3 pure parts: where the replies of a translated flow die.

DROP_HINTS = re.compile(r"interface address match|weak ES|bad checksum|checksum|no socket|no matching|dropped|discarded|"
                        r"not for hashed|full socket|for this host|not forwardable|out-of-order|duplicate", re.I)
ROUND3_WINDOWS = ("baseline", "v0", "v1", "v2", "diag-checkif0")


def stack_sections(text):
    """px-spike.sh stack output as {section: [lines]} (sysctl, ip, tcp, udp)."""
    section, out = None, {}
    for line in (text or "").splitlines():
        if line.startswith("# "):
            section = None if line == "# end" else line[2:]
            if section:
                out.setdefault(section, [])
            continue
        if section:
            out[section].append(line)
    return out


def counters(text):
    """netstat -s counters as {"proto: text with numbers as #": value}; a repeated text gets a suffix."""
    out = {}
    for section, lines in stack_sections(text).items():
        if section not in ("ip", "tcp", "udp"):
            continue
        for line in lines:
            match = re.match(r"\s*(\d+)\s+(.*\S)", line)
            if not match:
                continue
            key = f"{section}: " + re.sub(r"\d+", "#", match[2])
            unique, n = key, 2
            while unique in out:
                unique, n = f"{key} [{n}]", n + 1
            out[unique] = int(match[1])
    return out


def counter_delta(before, after):
    return {key: after[key] - before.get(key, 0) for key in after if after[key] != before.get(key, 0)}


def drop_lines(delta):
    """The counter changes that can name where an inbound packet died."""
    return [f"{key}: +{value}" for key, value in sorted(delta.items()) if DROP_HINTS.search(key)]


def replies(flows_, peer_address, peer_port, to_address, to_port=1911):
    """Packets from the round-trip server back to to_address:to_port."""
    return [flow for flow in flows_ if flow["src"] == peer_address and flow["sport"] == peer_port
            and flow["dst"] == to_address and flow["dport"] == to_port]


def b_items(probes):
    return [item for item in probes if item["id"].startswith("b-")]


def round3_gate(variants):
    """go when one candidate variant passes a, b, h and k; returns (verdict, the passing variant or None)."""
    for name in ("v1", "v2"):
        checks = variants.get(name, {}).get("checks")
        if checks and all(checks[key]["state"] == "PASS" for key in GATE):
            return "go", name
    return "no-go", None


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def stamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


M08 = load("px_m08_rows", LAB / "m08/m08-rows.py")


# Live driver.

class Spike(M08.Rows):
    def stage(self):
        super().stage()
        self.session.guest_file((LAB / "m08/guest/px-spike.sh").read_bytes(), "px-spike.sh")

    def px(self, action, *args, check=True):
        return self.session.ssh(shlex.join(["bash", self.session.stage + "/px-spike.sh", action, *args]),
                                check=check).decode(errors="replace")

    def capture(self, label, probes, public=(), after_probe=None):
        """One window: guest captures on en0 and the tunnel interface, the peer's wg0 watch, the probe plan; after_probe
        runs before the captures stop (the state table while the NAT states live)."""
        s = self.session
        s.captures = {}
        s.start_capture("en0", "px-" + label)
        for iface in self.live.tunnel_interfaces(s.ssh("/sbin/ifconfig", check=False).decode(errors="replace")):
            s.start_capture(iface, "px-" + label)
        stage = shlex.quote(self.peer_stage)
        s.peer("bash", "-c", f"nohup sudo -n python3 -I -B {stage}/peer-watch.py --iface wg0 --record {stage}/{label}.json "
               f"--ready {stage}/{label}.ready --stop {stage}/{label}.stop --seconds 300 >/dev/null 2>&1 </dev/null &")
        if not self.wait(M08.PEER_READY_SECONDS, lambda: s.peer("sudo", "-n", "cat", f"{self.peer_stage}/{label}.ready", check=False).strip(), interval=1):
            raise RuntimeError("peer watch not ready")
        time.sleep(1)
        name = f"plan-px-{label}.json"
        s.guest_file(json.dumps(plan(probes, public)).encode(), name)
        result = json.loads(self.act("probe", name, deadline=M08.PROBE_EXTRA_SECONDS))
        extra = after_probe() if after_probe else None
        time.sleep(2)
        s.ssh(shlex.join(["bash", s.stage + "/stop-capture.sh"]))
        texts = {}
        for remote, iface in s.captures.items():
            path = s.output / f"px-{label}-{iface}.pcap"
            path.write_bytes(s.ssh(shlex.join(["sudo", "-n", "cat", remote])))
            texts.setdefault(iface, []).append(s.command(["tcpdump", "-nn", "-tt", "-q", "-r", str(path)], timeout=120).decode(errors="replace"))
        s.captures = {}
        s.peer("sudo", "-n", "touch", f"{self.peer_stage}/{label}.stop")
        record = self.wait(30, lambda: s.peer("sudo", "-n", "cat", f"{self.peer_stage}/{label}.json", check=False), interval=1)
        if not record:
            raise RuntimeError("peer watch record missing")
        (s.output / f"px-{label}-peer.json").write_bytes(record)
        skipped = {key: value["skipped"] for key, value in result.get("probes", {}).items() if value.get("skipped")}
        if skipped:
            raise M08.Precondition("probes not sent: " + "; ".join(f"{k}: {v}" for k, v in skipped.items()))
        en0 = M08.flows("\n".join(texts.get("en0", [])))
        utun = M08.flows("\n".join(t for iface, items in texts.items() if iface != "en0" for t in items))
        return dict(en0=en0, utun=utun, peer=M08.peer_flows(json.loads(record)), result=result), extra

    def literals(self, resolver):
        echo = endpoint_literal(os.environ.get("WGEX_PX_TCP_ECHO", "1.1.1.1:80"))
        if os.environ.get("WGEX_PX_STUN"):
            return echo, endpoint_literal(os.environ["WGEX_PX_STUN"])
        answers = [a for a in self.act("lookup", STUN_NAME, resolver, check=False).split() if re.fullmatch(r"\d+(\.\d+){3}", a)]
        for answer in answers:
            try:
                return echo, endpoint_literal(f"{answer}:{STUN_PORT}")
            except ValueError:
                continue
        raise M08.Precondition(f"{STUN_NAME} did not resolve through the guest's physical resolver; set WGEX_PX_STUN")

    def run(self, m, notes):
        self.ensure_service()
        fields = self.en0()
        m["physical"], m["router"] = self.guest, fields.get("router", "none")
        if not re.fullmatch(r"\d+(\.\d+){3}", m["router"]):
            raise M08.Precondition("the guest's en0 router is unreadable")
        if self.protection() not in ("unprotected", None):
            self.deactivate()
        resolver = fields.get("resolver", "none").split(",")[0]
        echo, stun = self.literals(resolver)
        m["echo"], m["stun"] = f"{echo[0]}:{echo[1]}", f"{stun[0]}:{stun[1]}"
        m["ipv6"] = self.px("ipv6", check=False).splitlines()
        uuid = self.install_profile(PROFILE_ENTRIES)
        self.activate_or_diagnose(uuid, notes)
        tunnels = self.live.tunnel_interfaces(self.session.ssh("/sbin/ifconfig", check=False).decode(errors="replace"))
        if len(tunnels) != 1:
            raise M08.Precondition(f"expected one utun carrying {TUNNEL_ADDRESS}, found {tunnels}")
        m["tunnelIf"] = tunnels[0]
        main_nat = self.px("main-nat", check=False)
        m["mainNat"] = main_nat
        if 'nat-anchor "com.apple/*"' not in main_nat:
            raise M08.Precondition('the main ruleset has no nat-anchor "com.apple/*"')
        text = rule_text(m["tunnelIf"], m["router"])
        m["ruleText"], m["rendered"] = text, rule_counts(text)
        self.session.guest_file(text.encode(), "px-rules-full.conf")
        self.cleanup_rules()
        notes.append("load (nat and filter): " + " | ".join(self.px("load", "px-rules-full.conf").splitlines()[:4]))
        m["loaded"] = parse_show(self.px("show"))
        probes = main_probes(self.guest, echo, stun)

        def states():
            text = self.px("states", check=False)
            (self.session.output / "px-states-before.txt").write_text(text)
            return text
        window, before = self.capture("main", probes, public=(echo[0], stun[0]), after_probe=states)
        m["main"] = wire(probes, window, self.guest)
        m["mainTunnelSourced"] = sum(1 for flow in window["en0"] if flow["src"] == TUNNEL_ADDRESS)
        notes.append(f"en0 packets sourced {TUNNEL_ADDRESS} in the connected window: {m['mainTunnelSourced']}")
        notes.append(f"still protected after the connected window: {self.protection()}")
        kill = self.px("kill", TUNNEL_ADDRESS, check=False)
        after = self.px("states", check=False)
        m["states"] = (state_lines(before, TUNNEL_ADDRESS), nat_state_lines(before, TUNNEL_ADDRESS, self.guest), state_lines(after, TUNNEL_ADDRESS))
        notes.append("pfctl -k A: " + " | ".join(kill.splitlines()[:3]))
        notes.append("empty load: " + " | ".join(self.px("empty").splitlines()[:3]))
        m["emptied"] = parse_show(self.px("show"))
        try:
            h_text = rule_text(m["tunnelIf"], m["router"], nat=False)
            m["hRuleText"] = h_text
            self.session.guest_file(h_text.encode(), "px-rules-no-nat.conf")
            notes.append("load (filter only): " + " | ".join(self.px("load", "px-rules-no-nat.conf").splitlines()[:4]))
            loaded = parse_show(self.px("show"))
            if loaded[0] or not loaded[1]:
                raise M08.Precondition(f"the filter-only load read back {len(loaded[0])} nat and {len(loaded[1])} filter lines")
            items = h_probes()
            window, _ = self.capture("h", items)
            m["h"] = wire(items, window, self.guest)
            m["hTunnelSourced"] = sum(1 for flow in window["en0"] if flow["src"] == TUNNEL_ADDRESS)
        finally:
            self.cleanup_rules()
        notes.append(f"still protected at the end: {self.protection()}")

    # Round 3 (brief-reply-path.md): baseline, the T15 rules with logging and stack counters, two reply-to variants
    # and one diagnostic window with the input interface check off.
    def stack(self, label):
        text = self.px("stack", check=False)
        (self.session.output / f"stack-{label}.txt").write_text(text)
        return text

    def aux(self, label):
        """pflog0 and lo0 for one window; returns a stop function giving {iface: decoded lines}."""
        started = self.px("aux-start", label, check=False)
        paths = dict(re.findall(r"^aux (pflog0|lo0) (/var/tmp/wgex-px-aux/[a-z0-9-]+\.pcap)$", started, re.M))
        failures = [line for line in started.splitlines() if " failed" in line]

        def stop():
            self.px("aux-stop", check=False)
            out = {"failures": failures}
            for iface, remote in paths.items():
                local = self.session.output / f"px-{label}-{iface}.pcap"
                local.write_bytes(self.session.ssh(shlex.join(["sudo", "-n", "cat", remote]), check=False))
                flags = ["-nn", "-tt", "-e"] if iface == "pflog0" else ["-nn", "-tt", "-q"]
                try:
                    out[iface] = self.session.command(["tcpdump", *flags, "-r", str(local)], timeout=120).decode(errors="replace").splitlines()
                except (RuntimeError, OSError):
                    out[iface] = ["(unreadable)"]
            return out
        return stop

    def r3_window(self, label, probes, public, echo, stun, extra=None):
        """One measured window: counters before and after, the en0/utun/peer captures, pflog0 and lo0, the states."""
        before = self.stack(label + "-before")
        stop = self.aux(label)
        after_text = {}

        def after():
            after_text["states"] = self.px("states", check=False)
            after_text["stack"] = self.stack(label + "-after")
            (self.session.output / f"px-states-{label}.txt").write_text(after_text["states"])
        try:
            window, _ = self.capture(label, probes, public=public, after_probe=after)
        finally:
            aux = stop()
        delta = counter_delta(counters(before), counters(after_text.get("stack", "")))
        (self.session.output / f"stack-delta-{label}.json").write_text(json.dumps(delta, indent=2, sort_keys=True))
        u = self.guest
        wire_ = dict(
            echoRepliesOnEn0=len(replies(window["en0"], echo[0], echo[1], u)),
            stunRepliesOnEn0=len(replies(window["en0"], stun[0], stun[1], u)),
            echoRepliesOnLo0=len(replies(M08.flows("\n".join(aux.get("lo0", []))), echo[0], echo[1], TUNNEL_ADDRESS)),
            stunRepliesOnLo0=len(replies(M08.flows("\n".join(aux.get("lo0", []))), stun[0], stun[1], TUNNEL_ADDRESS)),
            echoRepliesOnUtun=len(replies(window["utun"], echo[0], echo[1], TUNNEL_ADDRESS)))
        pflog = [line for line in aux.get("pflog0", []) if re.search(re.escape(echo[0]) + "|" + re.escape(stun[0]), line)]
        states = [line for line in state_lines(after_text.get("states", ""), TUNNEL_ADDRESS)]
        return dict(window=wire(probes, window, u), wire=wire_, drops=drop_lines(delta), pflog=pflog[:30],
                    pflogFailures=aux.get("failures", []), lo0=[line for line in aux.get("lo0", [])][:20], states=states,
                    tunnelSourcedOnEn0=sum(1 for flow in window["en0"] if flow["src"] == TUNNEL_ADDRESS), extra=extra or {})

    def round3(self, r, notes):
        self.ensure_service()
        fields = self.en0()
        r["physical"], r["router"] = self.guest, fields.get("router", "none")
        if not re.fullmatch(r"\d+(\.\d+){3}", r["router"]):
            raise M08.Precondition("the guest's en0 router is unreadable")
        if self.protection() not in ("unprotected", None):
            self.deactivate()
        resolver = fields.get("resolver", "none").split(",")[0]
        echo, stun = self.literals(resolver)
        public = (echo[0], stun[0])
        r["echo"], r["stun"] = f"{echo[0]}:{echo[1]}", f"{stun[0]}:{stun[1]}"
        r["sysctl"] = stack_sections(self.stack("start")).get("sysctl", [])
        probes = main_probes(self.guest, echo, stun)
        bs = b_items(probes)
        self.cleanup_rules()
        r["windows"]["baseline"] = self.r3_window("baseline", bs, public, echo, stun)
        r["windows"]["baseline"]["checks"] = {"b": judge_b(r["windows"]["baseline"]["window"])}
        uuid = self.install_profile(PROFILE_ENTRIES)
        self.activate_or_diagnose(uuid, notes)
        tunnels = self.live.tunnel_interfaces(self.session.ssh("/sbin/ifconfig", check=False).decode(errors="replace"))
        if len(tunnels) != 1:
            raise M08.Precondition(f"expected one utun carrying {TUNNEL_ADDRESS}, found {tunnels}")
        r["tunnelIf"] = tunnel_if = tunnels[0]
        if 'nat-anchor "com.apple/*"' not in self.px("main-nat", check=False):
            raise M08.Precondition('the main ruleset has no nat-anchor "com.apple/*"')
        for name in ("v0", "v1", "v2", "diag-checkif0"):
            reply = REPLY_TO.get(name)
            text = rule_text(tunnel_if, r["router"], reply=reply, log=True)
            rec = dict(reply=reply, ruleText=text)
            r["windows"][name] = rec
            self.session.guest_file(text.encode(), f"px-rules-{name}.conf")
            self.cleanup_rules()
            rec["load"] = " | ".join(self.px("load", f"px-rules-{name}.conf").splitlines()[:4])
            nat, rules = parse_show(self.px("show"))
            rec["loaded"] = (len(nat), len(rules))
            if (len(nat), len(rules)) != rule_counts(text):
                raise M08.Precondition(f"{name}: read back {len(nat)} nat and {len(rules)} filter lines, rendered {rule_counts(text)}")
            items = probes if name in ("v1", "v2") else bs
            if name == "diag-checkif0":
                rec["checkif"] = self.px("checkif", "0", check=False).splitlines()[:3]
                try:
                    rec.update(self.r3_window(name, items, public, echo, stun))
                finally:
                    restore = re.search(r"previous (\d)", "\n".join(rec["checkif"]))
                    rec["checkifRestore"] = self.px("checkif", restore[1] if restore else "1", check=False).splitlines()[:3]
            else:
                rec.update(self.r3_window(name, items, public, echo, stun))
            rec["checks"] = judge(dict(main=rec["window"])) if name in ("v1", "v2") else {"b": judge_b(rec["window"])}
            rec["kill"] = " | ".join(self.px("kill", TUNNEL_ADDRESS, check=False).splitlines()[:3])
            if name in ("v1", "v2"):
                h_text = rule_text(tunnel_if, r["router"], nat=False, reply=reply, log=True)
                rec["hRuleText"] = h_text
                self.session.guest_file(h_text.encode(), f"px-rules-{name}-h.conf")
                self.cleanup_rules()
                self.px("load", f"px-rules-{name}-h.conf")
                loaded = parse_show(self.px("show"))
                if loaded[0] or not loaded[1]:
                    raise M08.Precondition(f"{name}: the filter-only load read back {len(loaded[0])} nat and {len(loaded[1])} filter lines")
                h_items = h_probes()
                window, _ = self.capture(f"{name}-h", h_items)
                rec["checks"]["h"] = judge(dict(h=wire(h_items, window, self.guest),
                                                hTunnelSourced=sum(1 for flow in window["en0"] if flow["src"] == TUNNEL_ADDRESS)))["h"]
            self.cleanup_rules()
            notes.append(f"{name}: still {self.protection()} after the window")

    def diagnose(self, label, notes):
        """Why the tunnel did not come up (run 3: phase failed, no cause): the daemon status line, the WGEX log lines of
        the last minutes (com.magrathean subsystems, scrubbed) and the peer's latest handshake."""
        s = self.session
        self.keep_dump(f"window-{label}")
        try:
            status = json.loads(s.ssh(self.live.CLI + " status --json", check=False).decode(errors="replace") or "{}")
            notes.append(f"{label}: status phase {status.get('phase')}, protection {status.get('protection')}, "
                         f"journalPolicy {status.get('journalPolicy')}, note {status.get('protectionNote')}")
        except (RuntimeError, ValueError, AttributeError, OSError) as error:
            notes.append(f"{label}: status unreadable ({type(error).__name__})")
        log = s.ssh("/usr/bin/log show --last 4m --style compact --predicate 'subsystem BEGINSWITH \"com.magrathean\"' 2>/dev/null "
                    "| grep -viE 'privatekey|presharedkey' | tail -n 40", check=False).decode(errors="replace")
        (s.output / f"daemon-log-{label}.txt").write_text(M08.scrub(log))
        notes += [f"{label} log: {M08.scrub(line)[:240]}" for line in log.splitlines()[-25:]]
        handshake = s.peer("sudo", "-n", "wg", "show", "wg0", "latest-handshakes", check=False)
        notes.append(f"{label}: peer latest handshake epoch {[w for w in handshake.decode(errors='replace').split() if w.isdigit()]}")

    def activate_or_diagnose(self, uuid, notes):
        """activate(); on failure, the diagnosis, the tunnel down and one more start. The spike measures the mechanism, so
        a tunnel that never comes up leaves it notMeasured, never no-go."""
        try:
            self.activate(uuid)
            return
        except M08.ProductFailure:
            self.diagnose("first-start", notes)
        self.deactivate()
        time.sleep(10)
        try:
            self.activate(uuid, "activatedRetry")
        except M08.ProductFailure:
            self.diagnose("second-start", notes)
            raise M08.Precondition("the tunnel did not reach protected on two starts (diagnosis in the notes)") from None

    def cleanup_rules(self):
        self.px("flush", check=False)
        self.px("kill", TUNNEL_ADDRESS, check=False)


def run(args):
    if os.environ.get("WGEX_LAB_VM") != "macos27-wgex" or os.environ.get("WGEX_LAB_USER") != "admin":
        raise SystemExit("PX-SPIKE runs on WGEX_LAB_VM=macos27-wgex with WGEX_LAB_USER=admin")
    live = load("px_verdict_live", LAB / "verdict-live.py")
    auth = load("px_auth_real", LAB / "auth-real.py")
    session = live.Session(ROW, {}, no_install=True)
    spike = Spike(session, live, args.attempt, auth)
    m, notes, error, started = {}, spike.notes, None, stamp()
    try:
        spike.stage()
        session.measure_provenance()
        spike.run(m, notes)
    except (M08.Precondition, M08.ProductFailure) as caught:
        error = caught
    except (live.RowFailure, live.PollDeadline, RuntimeError, OSError, ValueError, KeyError, TypeError) as caught:
        error = M08.command_fault(session, caught)
    finally:
        try:
            spike.cleanup_rules()
        except (RuntimeError, OSError, ValueError):
            notes.append("spike anchor cleanup at the end failed")
        try:
            spike.deactivate()
        except (RuntimeError, OSError, ValueError):
            notes.append("deactivate at the end failed")
        warnings = session.cleanup()
    if error is not None and "main" not in m:
        m["cause"] = f"{type(error).__name__}: {error}"[:300]
    if error is not None and "h" not in m:
        m["hCause"] = f"{type(error).__name__}: {error}"[:300]
    checks = judge(m)
    verdict = gate(checks)
    if isinstance(error, (M08.Precondition, M08.ProductFailure)) and "main" not in m:
        result = "notMeasured"
    elif error is not None and "main" not in m:
        result = "driverFault"
    else:
        result = "go" if verdict == "go" else "noGo"
    guest = session.provenance.get("guestOS", {}) if isinstance(session.provenance, dict) else {}
    record = dict(schemaVersion=1, row=ROW, attempt=args.attempt, startedAt=started, endedAt=stamp(), result=result, verdict=verdict,
                  cause=f"{type(error).__name__}: {error}"[:300] if error else None, checks=checks,
                  guest=f"macOS {guest.get('productVersion', '?')} ({guest.get('buildVersion', '?')}) guest macos27-wgex",
                  physical=m.get("physical"), router=m.get("router"), tunnelIf=m.get("tunnelIf"), echo=m.get("echo"), stun=m.get("stun"),
                  ruleText=m.get("ruleText"), hRuleText=m.get("hRuleText"), mainNat=m.get("mainNat"), notes=notes,
                  cleanupWarnings=warnings, buildRoot=str(session.output), provenance=session.provenance)
    directory = args.report_root / ROW
    directory.mkdir(parents=True, exist_ok=True)
    text = M08.scrub(json.dumps(record, indent=2, sort_keys=True, default=str)) + "\n"
    (directory / f"verdict-{args.attempt}.json").write_text(text)
    (directory / "verdict.json").write_text(text)
    (directory / "evidence.md").write_text(M08.scrub(evidence(record)))
    print(f"{ROW}: {result} (gate {verdict}, attempt {args.attempt})" + (f"; {record['cause']}" if record["cause"] else ""))
    return EXIT[result]


def round3_evidence(record):
    """The raw round 3 page (the evidence write-up is generated from it)."""
    lines = [f"# M08-T16 PX-SPIKE round 3 (attempt {record['attempt']})", "",
             f"- Gate verdict: **{record['verdict']}** (variant {record.get('variant')}); result {record['result']}"
             + (f"; cause: {record['cause']}" if record.get("cause") else ""),
             f"- {record['startedAt']} to {record['endedAt']}, {record.get('guest')}; U={record.get('physical')}, R={record.get('router')}, "
             f"N={record.get('tunnelIf')}, A={TUNNEL_ADDRESS}; echo {record.get('echo')}, STUN {record.get('stun')}",
             f"- guest sysctl: {'; '.join(record.get('sysctl') or [])}", ""]
    for name in ROUND3_WINDOWS:
        rec = record["windows"].get(name)
        if not rec:
            continue
        lines += [f"## {name}" + (f" (reply-to {rec['reply']})" if rec.get("reply") else ""), ""]
        for key, item in (rec.get("checks") or {}).items():
            lines.append(f"- {key}: {item['state']}: {item['summary']}")
        for key in ("wire", "tunnelSourcedOnEn0", "load", "loaded", "checkif", "checkifRestore", "kill", "pflogFailures"):
            if key in rec:
                lines.append(f"- {key}: {rec[key]}")
        for key in ("drops", "states", "pflog", "lo0"):
            if rec.get(key):
                lines += ["", f"{key}:", "", "```"] + [str(x)[:300] for x in rec[key]] + ["```"]
        for key, item in (rec.get("checks") or {}).items():
            if item.get("lines"):
                lines += ["", f"check {key} lines:", "", "```"] + item["lines"] + ["```"]
        if rec.get("ruleText"):
            lines += ["", "rules:", "", "```", rec["ruleText"].rstrip(), "```"]
        lines.append("")
    if record.get("notes"):
        lines += ["## Notes", ""] + [f"- {note}" for note in record["notes"]]
    return "\n".join(lines) + "\n"


def run_round3(args):
    if os.environ.get("WGEX_LAB_VM") != "macos27-wgex" or os.environ.get("WGEX_LAB_USER") != "admin":
        raise SystemExit("PX-SPIKE runs on WGEX_LAB_VM=macos27-wgex with WGEX_LAB_USER=admin")
    live = load("px_verdict_live", LAB / "verdict-live.py")
    auth = load("px_auth_real", LAB / "auth-real.py")
    session = live.Session(ROW, {}, no_install=True)
    spike = Spike(session, live, args.attempt, auth)
    r, notes, error, started = {"windows": {}}, spike.notes, None, stamp()
    try:
        spike.stage()
        session.measure_provenance()
        spike.round3(r, notes)
    except (M08.Precondition, M08.ProductFailure) as caught:
        error = caught
    except (live.RowFailure, live.PollDeadline, RuntimeError, OSError, ValueError, KeyError, TypeError) as caught:
        error = M08.command_fault(session, caught)
    finally:
        for name, call in (("spike anchor cleanup", spike.cleanup_rules), ("aux stop", lambda: spike.px("aux-stop", check=False)),
                           ("deactivate", spike.deactivate)):
            try:
                call()
            except (RuntimeError, OSError, ValueError):
                notes.append(f"{name} at the end failed")
        warnings = session.cleanup()
    verdict, variant = round3_gate(r["windows"])
    measured = any(name in r["windows"] and r["windows"][name].get("checks") for name in ("v1", "v2"))
    if verdict == "go":
        result = "go"
    elif measured and error is None:
        result = "noGo"
    elif isinstance(error, (M08.Precondition, M08.ProductFailure)):
        result = "notMeasured"
    elif error is not None:
        result = "driverFault"
    else:
        result = "noGo"
    guest = session.provenance.get("guestOS", {}) if isinstance(session.provenance, dict) else {}
    record = dict(schemaVersion=1, row=ROW + "-R3", attempt=args.attempt, startedAt=started, endedAt=stamp(), result=result,
                  verdict=verdict, variant=variant, cause=f"{type(error).__name__}: {error}"[:300] if error else None,
                  guest=f"macOS {guest.get('productVersion', '?')} ({guest.get('buildVersion', '?')}) guest macos27-wgex",
                  notes=notes, cleanupWarnings=warnings, buildRoot=str(session.output), provenance=session.provenance, **r)
    directory = args.report_root / (ROW + "-R3")
    directory.mkdir(parents=True, exist_ok=True)
    text = M08.scrub(json.dumps(record, indent=2, sort_keys=True, default=str)) + "\n"
    (directory / f"verdict-{args.attempt}.json").write_text(text)
    (directory / "verdict.json").write_text(text)
    (directory / "evidence.md").write_text(M08.scrub(round3_evidence(record)))
    print(f"{ROW}-R3: {result} (gate {verdict}, variant {variant}, attempt {args.attempt})" + (f"; {record['cause']}" if record["cause"] else ""))
    return EXIT[result]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    live = sub.add_parser("run")
    live.add_argument("--report-root", type=Path, required=True)
    live.add_argument("--attempt", type=int, choices=(1, 2), default=1)
    third = sub.add_parser("round3")
    third.add_argument("--report-root", type=Path, required=True)
    third.add_argument("--attempt", type=int, choices=(1, 2), default=1)
    render = sub.add_parser("render")
    render.add_argument("--tunnel-if", required=True)
    render.add_argument("--router", required=True)
    render.add_argument("--no-nat", action="store_true")
    render.add_argument("--variant", choices=sorted(REPLY_TO), default="v0")
    args = parser.parse_args(argv)
    if args.command == "render":
        sys.stdout.write(rule_text(args.tunnel_if, args.router, nat=not args.no_nat, reply=REPLY_TO[args.variant]))
        return 0
    return run_round3(args) if args.command == "round3" else run(args)


if __name__ == "__main__":
    sys.exit(main())
