#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""M08-T04: the five tunnel-exclusion rows (DEC-087, reduced port exclusions DEC-126, F1 regression DEC-127) in the
macOS 27 guest, one row per run, plus the one-off service setup the rows need.

  m08-rows.py setup --report-root DIR [--attempt 1|2]
  m08-rows.py ROW --report-root DIR [--attempt 1|2]
  m08-rows.py --summary DIR ROW...

Run by the lab job script through the M04-T22 row runner (guest-only login input, DEC-034) after the job's
restore of macos27-base, Lab build, `just lab install`, peer (full4 fixture) and relay start. `setup` takes the fresh
install to a running, approved daemon with onboarding complete through the lab registration path (bring_up_service: the
redesigned setup sheet registers the service on entering step 2, whose Continue stays disabled until the service runs;
then AUTH-REAL's Login Items approval, DEC-034). A row that finds the daemon not answering runs the same path first, so a
setup fault does not cost the rows. Elements are found and read by ax-find.applescript (any role, raw attributes; live run
1: gui dump prints listed roles only and System Events' description is the role description). Each
row then imports one profile, the lab full4 fixture (AllowedIPs 0.0.0.0/1 and 128.0.0.0/1, so the kill switch holds the
whole of IPv4) plus one `# WGEX-Exclude =` line, through Review as the single tunnel `wgex-lab-m08` (the previous
row's tunnel is deleted first: Review refuses a key another tunnel uses), activates it with the guest CLI and measures:

- the guest's en0 and utun captures (Tools/lab/tart/capture, tcpdump in the guest; read back on the host with tcpdump -r),
- the peer's wg0 (peer-watch.py: the inside of the tunnel as the peer sees it),
- probes from guest/excl-probe.pl: UDP datagrams and TCP SYNs with IP TTL 1 to TEST-NET destinations only
  (198.51.100.7 excluded, 203.0.113.9 not excluded), so a probe that leaves en0 dies at the vmnet gateway and never
  travels past the host. Nothing is sent to the VPS or the maintainer's network. The resolvable host name of EXCL-HOST is a wildcard
  DNS name for 198.51.100.7 (the lab's full4-name precedent, override WGEX_M08_RESOLVABLE_NAME); its one lookup at
  activation is the daemon's own.

A probe expectation is one of: en0 (seen leaving the guest's en0, not inside the tunnel at the peer), tunnel (seen at
the peer, not on en0) or blocked (on neither; pf drops before the en0 tap). Every outbound en0 packet in a window is
classified (endpoint, SSH escape hatch, DHCP, link scope, excluded address, excluded local port); anything else is a
leak, and DNS (53/853) to anywhere is a DNS leak, excluded addresses included.

Exit: 0 passed, 1 failed (a product check not met), 2 driver fault (the job retries once, DEC-118), 3 not measured
(precondition missing). The verdict (DIR/ROW/verdict.json) carries the checks, the first cause and the measured build
and guest provenance that the unchanged check-verdicts.py reads; captures and the step ledger stay under the build root.
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
import uuid as uuidlib

ROOT = Path(__file__).resolve().parents[3]
LAB = ROOT / "Tools/lab"
ROWS = {
    "EXCL-ADDR": "Excluded address range leaves on en0 with the kill switch on; nothing else leaks",
    "EXCL-HOST": "Excluded host name resolved at activation; an unresolvable name warns and activation succeeds",
    "EXCL-PHYS-ADDR": "Range containing the physical address passes no unlisted en0-bound traffic (F1 regression)",
    "EXCL-PORT": "Listed local ports pass for an en0-bound app; unlisted and tunnel-sourced traffic stay blocked",
    "EXCL-REMOVE": "Removing the exclusions puts the destination back into the tunnel at the next filter load",
}
EXIT = dict(passed=0, failed=1, driverFault=2, notMeasured=3)
GUEST_HELPERS = (("tart/guest", "guard.sh"), ("tart/guest", "verdict-actions.sh"), ("tart/guest", "profile-id.sh"),
                 ("tart/capture", "start-capture.sh"), ("tart/capture", "stop-capture.sh"),
                 ("m08/guest", "m08-actions.sh"), ("m08/guest", "excl-probe.pl"), ("m08", "ax-find.applescript"))
TUNNEL = "wgex-lab-m08"
TUNNEL_ADDRESS = "10.77.0.2"
HOST = "192.168.64.1"
ENDPOINT_PORT = 51820
EXCLUDED_RANGE = "198.51.100.0/24"
EXCLUDED_DST = "198.51.100.7"
TUNNEL_DST = "203.0.113.9"
PORT_ENTRIES = "1911, 6881-6889/udp"
LISTED_PORTS = ((1911, 1911, None), (6881, 6889, "udp"))
RESOLVABLE = os.environ.get("WGEX_M08_RESOLVABLE_NAME", "198-51-100-7.sslip.io")
WATCH_SECONDS = 120
DNS_PORTS = (53, 853)
LINK_SCOPE = [ipaddress.ip_network(value) for value in ("169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32", "fe80::/10", "ff00::/8")]
CAPTURE_LINE = re.compile(r"^(\d+\.\d+) (IP6?) (\S+) > (\S+): (.*)$")
LEAK_LIMIT = 16
# Bounds (seconds).
APP_SECONDS = 60
TUNNEL_SECONDS = 90
SHEET_SECONDS = 45
# Reviews an earlier row may have left open, cancelled one at a time; the delete alert's confirm title (MacStrings.deleteAction).
REVIEW_CANCELS = 4
DELETE_LABEL = "Delete"
STEP_SECONDS = 120
ONBOARDING_SECONDS = 300
SERVICE_SECONDS = 180
FIND_FIELDS = ("role", "value", "label", "title", "enabled", "frame", "contains")
# The redesigned setup sheet (MacOnboardingView): step 2 alone shows these; Continue is held there until the service runs.
STEP2 = ("wgex.onboarding.openSystemSettings", "wgex.onboarding.serviceState")
PEER_READY_SECONDS = 30
PROBE_EXTRA_SECONDS = 180
SETTLE_SECONDS = 2
KEY_SHAPE = re.compile(r"[A-Za-z0-9+/]{43}=")


class Precondition(Exception):
    """The row's starting state is missing: notMeasured."""


class ProductFailure(Exception):
    """A product check was not met: failed, with this first cause."""


class CommandFault(RuntimeError):
    """A guest, peer or lab command failed: names the command and its own stderr (driver fault)."""


# The lab wrapper's own lines around every `just lab` command; never the failing command's cause (run 2: verdict-live's
# command_cause took the last line, the guest-version note, and lost the script's refusal).
WRAPPER_NOISE = ("bash Tools/lab/tart/lab.sh", "no IP address found", "acceptance remains required", "error: recipe")


def command_fault(session, error):
    """verdict-live's bare "command failed/deadline" error rewritten from the step ledger's last failed item: the command
    (stage path dropped) and its exit status, with the last stderr lines once the wrapper noise is set aside. Called where
    the error is caught, before cleanup appends its own commands. Any other error is returned unchanged."""
    if not isinstance(error, RuntimeError) or isinstance(error, CommandFault) or not str(error).startswith("command "):
        return error
    item = next((entry for entry in reversed(getattr(session, "ledger", None) or [])
                 if entry.get("error") or entry.get("exitCode") not in (0, None)), None)
    if item is None:
        return error
    argv = [str(word) for word in item.get("argv") or []]
    command = argv[-1] if argv[:4] == ["just", "lab", "ssh", "--"] else " ".join(argv)
    stage = getattr(session, "stage", None)
    if stage:
        command = command.replace(stage + "/", "")
    lines = [line.strip() for line in str(item.get("stderr") or "").splitlines()
             if line.strip() and not any(noise in line for noise in WRAPPER_NOISE)]
    status = item["error"] if item.get("error") else f"exit {item.get('exitCode')}"
    return CommandFault(scrub(f"{command[:140]} ({status}): {' | '.join(lines[-3:])[:200] or 'no stderr of its own'}"))


# Pure parts (Tools/lab/tests/test_m08_rows.py).

def probe(ident, proto, dst, expect, dport, bind=False, src=None, sport=None, count=3):
    if proto not in ("udp", "tcp") or expect not in ("en0", "tunnel", "blocked"):
        raise ValueError("probe kind")
    return dict(id=ident, proto=proto, dst=dst, dport=dport, sport=sport, bind=bind, src=src, count=count, expect=expect)


def numbered(items, sport_base=42000, dport_base=50000):
    """Give each probe a unique destination port (DNS probes keep 53/853) and, where none is set, a unique unlisted source
    port, so every probe is found on the wire by (proto, dst, dport)."""
    out = []
    for index, item in enumerate(items):
        item = dict(item)
        if item["dport"] is None:
            item["dport"] = dport_base + index
        if item["sport"] is None:
            item["sport"] = sport_base + index
        out.append(item)
    keys = [(item["proto"], item["dst"], item["dport"]) for item in out]
    if len(set(keys)) != len(keys):
        raise ValueError("probe keys must be unique")
    return out


def address_probes():
    """EXCL-ADDR and EXCL-HOST: excluded and tunnel destinations, and DNS that must stay blocked."""
    return numbered([
        probe("ex-udp", "udp", EXCLUDED_DST, "en0", None), probe("ex-tcp", "tcp", EXCLUDED_DST, "en0", None),
        probe("tun-udp", "udp", TUNNEL_DST, "tunnel", None), probe("tun-tcp", "tcp", TUNNEL_DST, "tunnel", None),
        probe("dns-ex-udp53", "udp", EXCLUDED_DST, "blocked", 53), probe("dns-ex-tcp853", "tcp", EXCLUDED_DST, "blocked", 853),
        probe("dns-lan-udp53", "udp", HOST, "blocked", 53),
    ])


def physical_probes():
    """EXCL-PHYS-ADDR (F1): an en0-bound app on an unlisted port to a non-excluded destination is blocked; controls: the
    same app to the excluded range leaves on en0, an unbound app goes through the tunnel."""
    return numbered([
        probe("bound-tun-udp", "udp", TUNNEL_DST, "blocked", None, bind=True),
        probe("bound-tun-tcp", "tcp", TUNNEL_DST, "blocked", None, bind=True),
        probe("bound-ex-udp", "udp", EXCLUDED_DST, "en0", None, bind=True),
        probe("tun-udp", "udp", TUNNEL_DST, "tunnel", None),
    ])


def port_probes():
    """EXCL-PORT (DEC-126): listed ports pass for an en0-bound app (1911 both transports, 6881-6889 UDP only), unlisted
    ports and tunnel-sourced traffic on en0 stay blocked, an unbound app on a listed port still uses the tunnel."""
    return numbered([
        probe("p1911-tcp", "tcp", TUNNEL_DST, "en0", None, bind=True, sport=1911),
        probe("p1911-udp", "udp", TUNNEL_DST, "en0", None, bind=True, sport=1911),
        probe("p6885-udp", "udp", TUNNEL_DST, "en0", None, bind=True, sport=6885),
        probe("p6885-tcp", "tcp", TUNNEL_DST, "blocked", None, bind=True, sport=6885),
        probe("p1912-udp", "udp", TUNNEL_DST, "blocked", None, bind=True, sport=1912),
        probe("p1912-tcp", "tcp", TUNNEL_DST, "blocked", None, bind=True, sport=1912),
        probe("tunsrc-udp", "udp", TUNNEL_DST, "blocked", None, bind=True, src=TUNNEL_ADDRESS, sport=1911),
        probe("tunsrc-tcp", "tcp", TUNNEL_DST, "blocked", None, bind=True, src=TUNNEL_ADDRESS, sport=1911),
        probe("free-1911-udp", "udp", TUNNEL_DST, "tunnel", None, sport=1911),
    ])


def removal_probes(after):
    """EXCL-REMOVE: the excluded destination leaves on en0 before the removal and goes through the tunnel after it."""
    where = "tunnel" if after else "en0"
    return numbered([probe("ex-udp", "udp", EXCLUDED_DST, where, None), probe("ex-tcp", "tcp", EXCLUDED_DST, where, None),
                     probe("tun-udp", "udp", TUNNEL_DST, "tunnel", None)])


def plan(probes, seconds=0, interval=1, resolve=()):
    """The guest probe's plan (excl-probe.pl): TTL 1 always; only lab and TEST-NET destinations."""
    for item in probes:
        if not any(ipaddress.ip_address(item["dst"]) in ipaddress.ip_network(net)
                   for net in ("198.51.100.0/24", "203.0.113.0/24", "192.0.2.0/24", "10.77.0.0/24", "192.168.64.0/24")):
            raise ValueError("probe destination outside the lab and TEST-NET ranges")
    return dict(ttl=1, seconds=seconds, interval=interval, resolve=list(resolve),
                probes=[{key: item[key] for key in ("id", "proto", "dst", "dport", "sport", "bind", "src", "count")} for item in probes])


def endpoint(text):
    """tcpdump's address.port (or bare address) as (address, port|None)."""
    if text.count(".") == 4 or (":" in text and re.search(r"\.\d+$", text)):
        address, port = text.rsplit(".", 1)
        return address, int(port)
    return text, None


def flows(text):
    """Packets of `tcpdump -nn -tt -q -r` text as dicts (time, family, src, sport, dst, dport, proto); ARP and other
    non-IP lines are skipped."""
    found = []
    for line in (text or "").splitlines():
        match = CAPTURE_LINE.match(line.strip())
        if not match:
            continue
        stamp, family, source, destination, rest = match.groups()
        src, sport = endpoint(source)
        dst, dport = endpoint(destination)
        rest = rest.strip()
        proto = "tcp" if rest.startswith("tcp") else "udp" if rest.startswith("UDP") else "icmp" if rest.startswith("ICMP") else "other"
        found.append(dict(time=float(stamp), family=family, src=src, sport=sport, dst=dst, dport=dport, proto=proto))
    return found


def peer_flows(record, source=TUNNEL_ADDRESS):
    """The peer record's packets sent by the guest's tunnel address, as flow dicts."""
    found = []
    for item in (record or {}).get("packets", []):
        stamp, proto, src, sport, dst, dport = item[:6]
        if src == source:
            found.append(dict(time=stamp, family="IP", src=src, sport=sport, dst=dst, dport=dport, proto=proto))
    return found


def matches(flow, item):
    """A packet of this probe: its destination and port, and its transport unless tcpdump printed none (counted as seen,
    so an undecoded leak can never pass a blocked expectation)."""
    return flow["proto"] in (item["proto"], "other") and flow["dst"] == item["dst"] and flow["dport"] == item["dport"]


def in_networks(address, networks):
    try:
        value = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(value.version == net.version and value in net for net in networks)


def context(guest, ranges=(), ports=()):
    return dict(host=HOST, guest=guest, ranges=[ipaddress.ip_network(value, strict=False) for value in ranges], ports=list(ports))


def classify(flow, ctx):
    """One en0 packet: 'inbound' (from the host), an allowed outbound class, or 'leak' / 'dnsLeak'."""
    if flow["src"] == ctx["host"]:
        return "inbound"
    if in_networks(flow["dst"], LINK_SCOPE):
        return "linkScope"
    if flow["family"] == "IP6":
        return "dnsLeak" if flow["dport"] in DNS_PORTS else "leak"
    if flow["proto"] == "udp" and flow["dst"] == ctx["host"] and flow["dport"] == ENDPOINT_PORT:
        return "endpoint"
    if flow["proto"] == "tcp" and flow["dst"] == ctx["host"] and flow["sport"] == 22:
        return "sshEscapeHatch"
    if flow["proto"] == "udp" and flow["sport"] == 68 and flow["dport"] == 67:
        return "dhcp"
    if flow["dport"] in DNS_PORTS:
        return "dnsLeak"
    if in_networks(flow["dst"], ctx["ranges"]):
        return "excludedAddress"
    if flow["src"] == ctx["guest"] and flow["proto"] in ("tcp", "udp") and any(
            low <= (flow["sport"] or -1) <= high and transport in (None, flow["proto"]) for low, high, transport in ctx["ports"]):
        return "excludedPort"
    return "leak"


def leak_summary(en0, ctx):
    """Counts per class and the first LEAK_LIMIT leaks (dnsLeak and leak) of the outbound en0 packets."""
    counts, leaks = {}, []
    for flow in en0:
        kind = classify(flow, ctx)
        counts[kind] = counts.get(kind, 0) + 1
        if kind in ("leak", "dnsLeak") and len(leaks) < LEAK_LIMIT:
            leaks.append(dict(kind=kind, **{key: flow[key] for key in ("time", "src", "sport", "dst", "dport", "proto")}))
    return dict(counts=counts, leaks=leaks, leakCount=counts.get("leak", 0) + counts.get("dnsLeak", 0))


def probe_outcomes(probes, result, en0, peer, utun=()):
    """Per probe: attempts, errors, where it was seen and whether its expectation held."""
    outcomes = {}
    records = (result or {}).get("probes", {})
    for item in probes:
        record = records.get(item["id"], {})
        on_en0 = any(matches(flow, item) and flow["src"] != HOST for flow in en0)
        at_peer = any(matches(flow, item) for flow in peer)
        in_utun = any(matches(flow, item) for flow in utun)
        attempts = record.get("attempts", 0)
        expect = item["expect"]
        met = attempts > 0 and {"en0": on_en0 and not at_peer, "tunnel": at_peer and not on_en0,
                                "blocked": not on_en0 and not at_peer}[expect]
        outcomes[item["id"]] = dict(expect=expect, attempts=attempts, en0=on_en0, peer=at_peer, utun=in_utun, met=met,
                                    skipped=record.get("skipped"),
                                    results={key: value for key, value in record.items() if key not in ("attempts", "skipped")})
    return outcomes


def check(name, met, summary):
    return dict(name=name, met=bool(met), summary=summary)


def probe_checks(prefix, outcomes):
    words = dict(en0="leaves on en0 and is not inside the tunnel at the peer", tunnel="goes through the tunnel (peer) and not on en0",
                 blocked="is blocked (neither on en0 nor at the peer)")
    return [check(f"{prefix}{ident}", value["met"],
                  f"{ident} {words[value['expect']]} (attempts {value['attempts']}, en0 {value['en0']}, peer {value['peer']})")
            for ident, value in outcomes.items()]


def parse_fields(text):
    """key=value words of one line (m08-actions.sh en0 and route)."""
    return dict(word.split("=", 1) for word in (text or "").split() if "=" in word)


def outcome(checks, error=None):
    """(result, firstCause) from the checks and the exception that stopped the row, if any."""
    if isinstance(error, Precondition):
        return "notMeasured", "precondition: " + str(error)
    if isinstance(error, ProductFailure):
        return "failed", str(error)
    if error is not None:
        return "driverFault", f"driver: {type(error).__name__}: {error}"[:300]
    unmet = [item for item in checks if not item["met"]]
    if unmet:
        return "failed", f"{unmet[0]['name']}: {unmet[0]['summary']}"
    return ("passed", None) if checks else ("failed", "no checks recorded")


def scrub(text):
    return KEY_SHAPE.sub("<redacted>", text)


def elements(dump, identifier):
    """(id, text) of the dump lines whose id is identifier (the verdict-live dump format: ... | value=V | desc=D | id=I | ...)."""
    found = []
    for line in (dump or "").splitlines():
        fields = dict(re.findall(r"(name|value|desc|id)=(.*?)(?= \| |\s*$)", line))
        if fields.get("id", "").strip() == identifier:
            text = next((fields[key] for key in ("value", "desc", "name") if fields.get(key) and fields[key] != "missing value"), "")
            found.append(text)
    return found


# Tools/lab/tart/gui.sh refuses an identifier outside this shape ("identifier must be a wgex accessibility identifier").
GUI_IDENTIFIER = re.compile(r"wgex\.[A-Za-z0-9.-]+")


def gui_identifier(identifier):
    """The identifier the lab helper takes for a press. An item identifier that carries a character gui.sh refuses (the
    "/" of wgex.editor.removeExclusion.198.51.100.0/24, M08-T12: run 1 refused, the retry found no control) becomes the
    longest prefix ending in "." before that character, which verdict-live matches by prefix on a full dump; ValueError
    when no such prefix is left below the screen and element."""
    if GUI_IDENTIFIER.fullmatch(identifier):
        return identifier
    head = re.match(r"[A-Za-z0-9.-]*", identifier).group(0)
    prefix = head[:head.rfind(".") + 1]
    if not GUI_IDENTIFIER.fullmatch(prefix) or prefix.count(".") < 3:
        raise ValueError(f"no lab identifier for {identifier!r}")
    return prefix


def found(text):
    """ax-find.applescript output as a dict (role, value, label, title, enabled, frame (x, y, w, h) or None, contains
    True/False/None), or None when the element was not found or the output did not parse."""
    first = next((line for line in (text or "").splitlines() if line.startswith("ax-find=")), "")
    parts = first.split("\t")
    if parts[0] != "ax-find=found":
        return None
    item = dict(role="", value="", label="", title="", enabled="", frame=None, contains=None)
    for part in parts[1:]:
        key, _, value = part.partition("=")
        if key in FIND_FIELDS:
            item[key] = value
    try:
        item["frame"] = tuple(int(n) for n in item["frame"].split(",")) if item["frame"] else None
    except ValueError:
        item["frame"] = None
    if item["frame"] is not None and len(item["frame"]) != 4:
        item["frame"] = None
    item["contains"] = {"yes": True, "no": False}.get(item["contains"])
    return item


def texts(item):
    """The readable texts of a found element in reading order: AXValue (unless omitted), AXTitle, AXDescription."""
    if not item:
        return []
    values = [item.get("value"), item.get("title"), item.get("label")]
    return [v for v in values if v and v not in ("missing value", "<omitted>")]


def onboarding_complete(text):
    """mac-preferences.json says onboarding is complete (ready-snapshot.py's test)."""
    try:
        return json.loads(text).get("onboardingComplete") is True
    except (ValueError, AttributeError):
        return False


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def stamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# Live driver.

class Rows:
    def __init__(self, session, live, attempt, auth=None):
        self.session, self.live, self.attempt = session, live, attempt
        self.auth_module = auth
        self.checks, self.notes, self.windows, self.evidence = [], [], {}, {}
        self.peer_stage = "/var/tmp/wgex-m08-" + session.nonce
        self.guest = None

    # Guest and peer plumbing.
    def stage(self):
        s = self.session
        s.ssh("umask 077; mkdir -p " + shlex.quote(s.stage))
        for folder, name in GUEST_HELPERS:
            s.guest_file((LAB / folder / name).read_bytes(), name)
        s.peer("bash", "-c", "set -eu; test \"$(uname -s)\" = Linux; case \"$(hostname)\" in wg-peer | lima-wg-peer) ;; *) exit 1 ;; esac; "
               "umask 077; mkdir " + shlex.quote(self.peer_stage))
        s.cleanups.append(self.live.named("peer-stage", lambda: s.peer("sudo", "-n", "rm", "-rf", self.peer_stage)))
        s.peer("bash", "-c", "umask 077; cat > " + shlex.quote(self.peer_stage + "/peer-watch.py"), data=(LAB / "m08/peer-watch.py").read_bytes())

    def act(self, action, *args, check=True, deadline=None):
        return self.session.ssh(shlex.join(["bash", self.session.stage + "/m08-actions.sh", action, *args]), check=check,
                                deadline=deadline).decode(errors="replace")

    def en0(self):
        fields = parse_fields(self.act("en0"))
        if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", fields.get("address", "")):
            raise RuntimeError("guest en0 address unreadable")
        self.guest = fields["address"]
        return fields

    def route(self, dst):
        return parse_fields(self.act("route", dst)).get("interface", "none")

    def protection(self):
        try:
            return self.session.status(budget=20)["protection"]
        except (RuntimeError, ValueError):
            return None

    def wait(self, seconds, probe_, interval=2):
        deadline = time.monotonic() + seconds
        while True:
            value = probe_()
            if value:
                return value
            if time.monotonic() > deadline:
                return None
            time.sleep(interval)

    def ensure_service(self):
        """Every row needs the running daemon; when it does not answer (M08-SETUP failed), the row brings it up itself
        through the lab registration path and records notMeasured only when that fails too."""
        if self.protection() is not None:
            return
        failure = self.auth_module.Failure if self.auth_module else RuntimeError
        try:
            self.bring_up_service()
        except (failure, self.live.RowFailure, self.live.PollDeadline, RuntimeError, ValueError, OSError) as error:
            raise Precondition(f"the daemon did not answer wgex status and the lab registration path failed: {error}"[:300]) from None
        if self.wait(30, lambda: self.protection() is not None) is None:
            raise Precondition("the daemon did not answer wgex status after the lab registration path")
        self.notes.append("the daemon did not answer at the row's start; brought up through the lab registration path")

    def profile_id(self):
        raw = self.session.guest_action("profile-id", TUNNEL, check=False).decode(errors="replace").strip()
        return raw if re.fullmatch(self.live.UUID_PATTERN, raw) else None

    def anchor(self, label):
        text = self.act("anchor", check=False)
        (self.session.output / f"anchor-{label}.txt").write_text(text)
        return text

    # GUI plumbing.
    def dump(self, identifier=None):
        try:
            return self.session.walk_read("1", identifier, check=False)
        except RuntimeError:
            return ""

    def find(self, identifier, window="1"):
        """The element carrying identifier, whatever its role (ax-find.applescript in the console session), as found()'s
        dict; None when it is not shown."""
        try:
            return found(self.session.lab("gui", "run", "osascript", self.session.stage + "/ax-find.applescript", "WGEX",
                                          window, identifier, check=False).decode(errors="replace"))
        except RuntimeError:
            return None

    def shown(self, identifier):
        return self.find(identifier) is not None

    def read(self, identifier):
        """The text of one element (its value, else its title, else its label); None when it is not shown."""
        item = self.find(identifier)
        return None if item is None else (texts(item) or [""])[0]

    def await_id(self, identifier, seconds=SHEET_SECONDS):
        """The element carrying identifier (found()'s dict) once it shows, or None at the bound."""
        return self.wait(seconds, lambda: self.find(identifier))

    def keep_dump(self, name):
        """A full dump of the main window, scrubbed, kept under the build root for diagnosis (never in the verdict)."""
        try:
            path = Path(self.session.output) / f"{name}-a{self.attempt}.txt"
            path.write_text(scrub(self.dump()))
            self.notes.append(f"window dump kept at {path.name} under the build root")
        except (OSError, TypeError):
            pass

    def press(self, identifier):
        self.session.click_id(gui_identifier(identifier))
        time.sleep(SETTLE_SECONDS)

    def open_app(self):
        self.session.lab("gui", "run", "open", "-a", "WGEX")
        self.session.lab("gui", "activate", "WGEX")
        if not self.wait(APP_SECONDS, lambda: "AXWindow" in self.dump("wgex.main.surface")):
            raise RuntimeError("WGEX showed no window after open -a")

    def select_tunnel(self):
        """The tunnel page of wgex-lab-m08, the only tunnel the rows keep: the first sidebar row by arrow keys (SwiftUI rows
        ignore AXPress, L14); the window then names the tunnel and shows its action."""
        self.session.lab("gui", "activate", "WGEX")
        self.session.lab("gui", "keys", "WGEX", "1", "wgex.main.profiles", "up", "64", "fallback")
        dump = self.wait(20, lambda: (lambda d: d if TUNNEL in d and (elements(d, "wgex.main.action") or self.find("wgex.main.action"))
                                      else None)(self.dump("wgex.main.action")))
        if not dump:
            raise ValueError("the tunnel page of " + TUNNEL + " did not show")
        return dump

    # Tunnel steps.
    def dismiss_reviews(self):
        """Cancels any Review an earlier row left open. A refused import is never added, so its Review stays; the next
        file then joins it and the sheet shows the several-tunnels list, which has no wgex.importReview.importLabel
        (M08-T09: run 3 "Review did not open for the profile" after EXCL-HOST)."""
        for _ in range(REVIEW_CANCELS):
            if not self.shown("wgex.importReview.cancel"):
                return
            self.press("wgex.importReview.cancel")
            self.notes.append("cancelled a Review left open before the import")
        if self.shown("wgex.importReview.cancel"):
            raise ValueError("an earlier Review did not close on Cancel")

    def delete_previous(self):
        """Deletes the previous row's wgex-lab-m08 through its tunnel page. Review refuses a file whose key another tunnel
        uses, Replace or Keep Both (keyInUseElsewhere is a validation error), and every row imports the same fixture key
        (M08-T09: run 3 EXCL-HOST "Another tunnel uses this key")."""
        if not self.profile_id():
            return
        self.select_tunnel()
        self.press("wgex.main.deleteTunnel")
        if self.await_id("wgex.main.confirmDelete", 20):
            self.press("wgex.main.confirmDelete")
        else:
            self.session.click(DELETE_LABEL)
            time.sleep(SETTLE_SECONDS)
        if not self.wait(30, lambda: self.profile_id() is None):
            raise ValueError("the previous " + TUNNEL + " was not deleted")
        self.notes.append("deleted the previous " + TUNNEL + " before the import")

    def install_profile(self, entries):
        """The full4 fixture plus `# WGEX-Exclude = entries`, imported through Review as wgex-lab-m08 after any Review left
        open is cancelled and the previous row's tunnel is deleted."""
        s = self.session
        if self.protection() not in ("unprotected", None):
            s.guest_action("down", check=False)
        s.lab("profile", "full4")
        if self.act("make-conf", entries).strip() != "1":
            raise RuntimeError("profile file without one exclusion line")
        self.open_app()
        self.dismiss_reviews()
        self.delete_previous()
        s.lab("gui", "run", "open", "-a", "WGEX", f"/Users/{self.live.GUEST_USER}/lab/{TUNNEL}.conf")
        review = self.await_id("wgex.importReview.importLabel")
        if not review:
            raise ValueError("Review did not open for the profile")
        if self.shown("wgex.importReview.duplicate"):
            raise ValueError("Review still matches an existing tunnel after the previous one was deleted")
        problem = self.find("wgex.importReview.problems")
        problems = [" ".join(texts(problem))] if problem else []
        self.checks.append(check("importAccepted", not problems, f"Review lists no problem for the exclusions {entries!r}"))
        if problems:
            raise ProductFailure(f"Review refused the exclusions {entries!r}: {problems[0][:160]}")
        self.press("wgex.importReview.importLabel")
        uuid = self.wait(30, self.profile_id)
        if not uuid:
            raise ProductFailure("the profile was not stored after Add")
        return uuid

    def activate(self, uuid, name="activated"):
        """CLI start (the app running hands over the keys); the tunnel page's action is the fallback."""
        self.session.ssh(shlex.join([self.live.CLI, "up", uuid, "--json"]), check=False)
        on = self.wait(TUNNEL_SECONDS, lambda: self.protection() == "protected", interval=1)
        if not on:
            self.notes.append("CLI start did not reach protected; pressed the tunnel page's action")
            self.select_tunnel()
            self.press("wgex.main.action")
            on = self.wait(TUNNEL_SECONDS, lambda: self.protection() == "protected", interval=1)
        self.checks.append(check(name, on, "the tunnel is active with the kill switch on (daemon protection protected)"))
        if not on:
            raise ProductFailure("the tunnel did not reach protected")

    def deactivate(self):
        self.session.guest_action("down", check=False)
        return self.wait(60, lambda: self.protection() == "unprotected", interval=1)

    def routes(self, prefix, excluded, tunnel=TUNNEL_DST):
        a, b = self.route(EXCLUDED_DST), self.route(tunnel)
        self.evidence[prefix + "routes"] = {EXCLUDED_DST: a, tunnel: b}
        if excluded:
            self.checks.append(check(prefix + "excludedRoute", a == "en0", f"route to {EXCLUDED_DST} uses en0 ({a})"))
        else:
            self.checks.append(check(prefix + "excludedRouteTunnel", a.startswith("utun"), f"route to {EXCLUDED_DST} uses the tunnel ({a})"))
        self.checks.append(check(prefix + "tunnelRoute", b.startswith("utun"), f"route to {tunnel} uses the tunnel ({b})"))

    # One measured window: captures on en0 and the tunnel interface, the peer watch, the probe plan.
    def window(self, label, probes, ctx, seconds=0, resolve=()):
        s = self.session
        s.captures = {}
        s.start_capture("en0", "m08-" + label)
        for iface in self.live.tunnel_interfaces(s.ssh("/sbin/ifconfig", check=False).decode(errors="replace")):
            s.start_capture(iface, "m08-" + label)
        stage = shlex.quote(self.peer_stage)
        bound = seconds + PROBE_EXTRA_SECONDS + 60
        s.peer("bash", "-c", f"nohup sudo -n python3 -I -B {stage}/peer-watch.py --iface wg0 --record {stage}/{label}.json "
               f"--ready {stage}/{label}.ready --stop {stage}/{label}.stop --seconds {bound} >/dev/null 2>&1 </dev/null &")
        if not self.wait(PEER_READY_SECONDS, lambda: s.peer("sudo", "-n", "cat", f"{self.peer_stage}/{label}.ready", check=False).strip(), interval=1):
            raise RuntimeError("peer watch not ready")
        time.sleep(1)
        name = f"plan-{label}.json"
        s.guest_file(json.dumps(plan(probes, seconds, resolve=resolve)).encode(), name)
        # The plan runs for seconds (plus TCP waits of up to 1 s per attempt): the SSH deadline covers it, not the 90 s default.
        raw = self.act("probe", name, deadline=seconds + PROBE_EXTRA_SECONDS)
        result = json.loads(raw)
        time.sleep(2)
        # Collect before any cleanup: guest captures, then the peer record. A failure before this point leaves
        # Session.stop_captures (registered by start_capture) to stop and copy them at the row's cleanup.
        s.ssh(shlex.join(["bash", s.stage + "/stop-capture.sh"]))
        texts = {}
        for remote, iface in s.captures.items():
            path = s.output / f"{label}-{iface}.pcap"
            path.write_bytes(s.ssh(shlex.join(["sudo", "-n", "cat", remote])))
            texts.setdefault(iface, []).append(s.command(["tcpdump", "-nn", "-tt", "-q", "-r", str(path)], timeout=120).decode(errors="replace"))
        s.captures = {}
        s.peer("sudo", "-n", "touch", f"{self.peer_stage}/{label}.stop")
        record = self.wait(30, lambda: s.peer("sudo", "-n", "cat", f"{self.peer_stage}/{label}.json", check=False), interval=1)
        if not record:
            raise RuntimeError("peer watch record missing")
        (s.output / f"{label}-peer.json").write_bytes(record)
        en0 = flows("\n".join(texts.get("en0", [])))
        utun = flows("\n".join(text for iface, items in texts.items() if iface != "en0" for text in items))
        peer = peer_flows(json.loads(record))
        skipped = {ident: value["skipped"] for ident, value in result.get("probes", {}).items() if value.get("skipped")}
        if skipped:
            raise Precondition("probes not sent: " + "; ".join(f"{key}: {value}" for key, value in skipped.items()))
        outcomes = probe_outcomes(probes, result, en0, peer, utun)
        leaks = leak_summary(en0, ctx)
        self.windows[label] = dict(seconds=round(result.get("ended", 0) - result.get("started", 0), 1), rounds=result.get("rounds"),
                                   lookups=result.get("lookups"), en0Packets=len(en0), peerPackets=len(peer), probes=outcomes, **leaks)
        return outcomes, leaks, result

    def traffic(self, label, probes, ctx, seconds=0, resolve=()):
        outcomes, leaks, result = self.window(label, probes, ctx, seconds, resolve)
        prefix = "" if label == "main" else label + ":"
        self.checks.extend(probe_checks(prefix, outcomes))
        watched = result.get("ended", 0) - result.get("started", 0)
        self.checks.append(check(prefix + "noLeak", leaks["leakCount"] == 0,
                                 f"no other outbound packet left en0 in {watched:.0f} s, DNS 53/853 included "
                                 f"({leaks['leakCount']} leaks; first: {leaks['leaks'][:1]})"))
        if seconds:
            self.checks.append(check(prefix + "watchLength", watched >= seconds, f"the watch lasted {watched:.0f} s (at least {seconds} s)"))
        self.checks.append(check(prefix + "stillProtected", self.protection() == "protected", "the kill switch held through the window"))

    # Rows.
    def row_address(self):
        self.ensure_service()
        self.en0()
        uuid = self.install_profile(EXCLUDED_RANGE)
        self.activate(uuid)
        self.notes.append(f"anchor lines naming {EXCLUDED_RANGE}: {self.anchor('active').count('198.51.100.0/24')}")
        self.routes("", excluded=True)
        lookup = f"m08-{self.session.nonce[-12:]}.leak.wgex.test"
        self.traffic("main", address_probes(), context(self.guest, [EXCLUDED_RANGE]), WATCH_SECONDS, resolve=[lookup])

    def row_host(self):
        self.ensure_service()
        fields = self.en0()
        if self.protection() != "unprotected":
            self.deactivate()
        resolver = fields.get("resolver", "none").split(",")[0]
        if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", resolver):
            raise Precondition("the guest's physical resolver is unreadable")
        answers = self.act("lookup", RESOLVABLE, resolver, check=False).split()
        self.evidence["resolvableLookup"] = dict(name=RESOLVABLE, resolver=resolver, answers=answers[:8])
        if EXCLUDED_DST not in answers:
            raise Precondition(f"{RESOLVABLE} does not resolve to {EXCLUDED_DST} through the guest's resolver ({answers[:4]})")
        unresolvable = f"never-{uuidlib.uuid4().hex[:16]}.invalid"
        uuid = self.install_profile(f"{RESOLVABLE}, {unresolvable}")
        self.activate(uuid, "activationSucceeded")
        self.open_app()
        self.select_tunnel()
        warning = self.await_id("wgex.main.exclusionWarning", 20)
        text = " ".join(texts(warning))
        self.evidence["warning"] = text[:300]
        self.checks.append(check("unresolvedWarning", unresolvable in text, "the tunnel page warns that the unresolvable name was not resolved"))
        self.checks.append(check("resolvedNotWarned", RESOLVABLE not in text, "the resolved name is not in the warning"))
        self.notes.append(f"anchor lines naming {EXCLUDED_DST}: {self.anchor('active').count(EXCLUDED_DST)}")
        self.routes("", excluded=True)
        self.traffic("main", address_probes(), context(self.guest, [EXCLUDED_DST + "/32"]), WATCH_SECONDS)

    def row_physical(self):
        self.ensure_service()
        self.en0()
        own = self.guest + "/32"
        uuid = self.install_profile(f"{own}, {EXCLUDED_RANGE}")
        self.activate(uuid)
        self.anchor("active")
        self.routes("", excluded=True)
        self.traffic("main", physical_probes(), context(self.guest, [own, EXCLUDED_RANGE]))

    def row_ports(self):
        self.ensure_service()
        self.en0()
        uuid = self.install_profile(PORT_ENTRIES)
        self.activate(uuid)
        self.notes.append(f"anchor lines naming port 1911: {self.anchor('active').count('1911')}")
        self.routes("", excluded=False)
        self.traffic("main", port_probes(), context(self.guest, ports=LISTED_PORTS))

    def row_remove(self):
        self.ensure_service()
        self.en0()
        uuid = self.install_profile(EXCLUDED_RANGE)
        self.activate(uuid, "before:activated")
        self.routes("before:", excluded=True)
        self.traffic("before", removal_probes(after=False), context(self.guest, [EXCLUDED_RANGE]))
        if not self.deactivate():
            raise ProductFailure("the tunnel did not go down before the edit")
        self.open_app()
        self.select_tunnel()
        self.press("wgex.main.editProfile")
        remove = "wgex.editor.removeExclusion." + EXCLUDED_RANGE
        if not self.await_id(remove):
            raise ProductFailure("the editor did not list the exclusion with its Remove control")
        self.press(remove)
        self.checks.append(check("removedInEditor", not self.shown(remove), "Remove takes the exclusion off the editor's list"))
        self.press("wgex.editor.save")
        closed = self.wait(20, lambda: not self.shown("wgex.editor.save"))
        self.checks.append(check("saved", closed, "Save closes the editor"))
        page = self.read("wgex.main.detail.exclusions")
        self.evidence["pageExclusions"] = page
        self.checks.append(check("pageShowsNone", page is not None and "198.51.100" not in page,
                                 f"the tunnel page no longer lists the range ({page!r})"))
        self.activate(uuid, "after:activated")
        lines = self.anchor("after").count("198.51.100.0/24")
        self.checks.append(check("after:passesGone", lines == 0, f"the loaded filter has no pass for the range ({lines} lines)"))
        self.routes("after:", excluded=False)
        self.traffic("after", removal_probes(after=True), context(self.guest))

    def bring_up_service(self):
        """The lab registration path (M07-T08b's bring_up_service, ready-snapshot.py, AUTH-REAL): bundle owner root:wheel
        and codesign verified, open WGEX; on the setup sheet, Continue from Welcome to step 2 (entering it registers the
        service; its Continue stays disabled until the service runs, the run 1 fault), Register Again only when offered;
        outside setup, Settings > Background Service > Register Again. Then the background item is approved in Login Items
        & Extensions (AuthReal.approve_background_item, DEC-034), the daemon awaited and setup finished with Continue and
        Not Now. A rerun after a fault finds the sheet already on step 2 and carries on from there."""
        auth, s = self.auth_module, self.session
        probe_ = auth.AuthReal(s, self.live)
        probe_.stage()
        probe_.approval, probe_.start_clock = {}, s.ssh("date '+%Y-%m-%d %H:%M:%S'").decode().strip()
        s.ssh("set -eu; sudo -n chown -R root:wheel /Applications/WGEX.app; codesign --verify --deep --strict /Applications/WGEX.app")
        s.lab("gui", "run", "open", "-a", "WGEX")
        s.lab("gui", "activate", "WGEX")
        if not self.wait(APP_SECONDS, lambda: "AXWindow" in self.dump("wgex.onboarding.surface")):
            raise RuntimeError("WGEX showed no window after open -a")
        setup = self.await_id("wgex.onboarding.surface", 15)
        if setup:
            on_step2 = lambda: any(self.find(identifier) for identifier in STEP2)  # noqa: E731
            if not on_step2():
                step = texts(self.find("wgex.onboarding.step"))
                self.notes.append(f"setup sheet: {'; '.join(texts(setup) + step)[:120]}")
                self.press("wgex.onboarding.continue")
                if not self.wait(STEP_SECONDS, on_step2, interval=3):
                    self.keep_dump("setup-step2")
                    raise auth.Failure("setup step 2 (Open System Settings or the service row) did not appear after Continue")
            if self.shown("wgex.onboarding.registerBackgroundService"):
                self.notes.append("Register Again was offered on step 2 and pressed once")
                self.press("wgex.onboarding.registerBackgroundService")
        else:
            # Onboarding was finished but the daemon is not running: Register Again where the window shows it (the
            # Background Service page); a missing control fails this path with its own cause.
            self.notes.append("no setup sheet; Register Again (wgex.settings.reRegisterBackgroundService)")
            self.press("wgex.settings.reRegisterBackgroundService")
        probe_.approve_background_item()
        if probe_.console_step:
            raise auth.Failure("background-item approval stopped: " + probe_.console_step)
        probe_.wait("daemon running", SERVICE_SECONDS, probe_.daemon_running, interval=3)
        self.notes.append(f"background item approval {probe_.approval}")
        if setup:
            self.finish_setup()

    def finish_setup(self):
        """Continue (enabled once the service runs) until step 3, then Not Now; done when the preferences say onboarding
        is complete or the setup sheet is gone."""
        path = shlex.quote(f"/Users/{self.live.GUEST_USER}/Library/Application Support/WGEX/mac-preferences.json")
        presses, deadline = 0, time.monotonic() + ONBOARDING_SECONDS
        while not onboarding_complete(self.session.ssh("cat " + path, check=False).decode(errors="replace")):
            if not self.find("wgex.onboarding.surface"):
                self.notes.append("the setup sheet closed before the preferences said onboarding complete")
                break
            if presses >= 10 or time.monotonic() > deadline:
                self.keep_dump("setup-finish")
                raise RuntimeError(f"onboarding not complete after {presses} presses")
            if self.find("wgex.importReview.createEmpty"):
                self.press("wgex.importReview.cancel")  # Not Now
                presses += 1
            else:
                gate = self.find("wgex.onboarding.continue")
                if gate and gate["enabled"] != "false":
                    self.press("wgex.onboarding.continue")
                    presses += 1
            time.sleep(3)
        self.notes.append(f"onboarding finished after {presses} presses")

    def setup(self, auth, ready):
        """Fresh install to a running, approved daemon with onboarding complete (bring_up_service). Secure install is
        noted, not required: the rows need a running service, and the lab install keeps its wrapping-key fallback."""
        self.auth_module = auth
        if self.protection() is not None:
            self.notes.append("the daemon already answered wgex status; registration skipped")
            if self.find("wgex.onboarding.surface"):
                self.finish_setup()
        else:
            self.bring_up_service()
        if self.wait(60, lambda: self.protection() is not None, interval=3) is None:
            raise auth.Failure("the daemon does not answer wgex status after the approval")
        state = ready.secure_install_state(self.session.guest_action("secure-install-status", check=False).decode(errors="replace"))
        self.notes.append(f"secure install: {state}")

RUNS = {"EXCL-ADDR": Rows.row_address, "EXCL-HOST": Rows.row_host, "EXCL-PHYS-ADDR": Rows.row_physical,
        "EXCL-PORT": Rows.row_ports, "EXCL-REMOVE": Rows.row_remove}


def verdict(row, attempt, checks, error, provenance, installation, extra):
    result, cause = outcome(checks, error)
    completed = (result in ("passed", "failed") and error is None) or isinstance(error, ProductFailure)
    return dict(schemaVersion=1, row=row, title=ROWS[row], attempt=attempt, dryRun=False, result=result, firstCause=cause,
                checks=checks, rowCompleted=bool(completed), prepareCompleted=result != "notMeasured",
                expectationsMet=result == "passed", **provenance, installation=installation, **extra)


def write(directory, record, gaps):
    record["gaps"] = gaps
    record["liveAcceptance"] = record["result"] == "passed" and record["rowCompleted"] and not gaps
    directory.mkdir(parents=True, exist_ok=True)
    text = scrub(json.dumps(record, indent=2, sort_keys=True)) + "\n"
    json.loads(text)
    (directory / f"verdict-{record['attempt']}.json").write_text(text)
    (directory / "verdict.json").write_text(text)


def summary(root, rows):
    for row in rows:
        try:
            record = json.loads((Path(root) / row / "verdict.json").read_text())
        except (OSError, ValueError):
            print(f"- {row}: no verdict")
            continue
        met = sum(1 for item in record.get("checks", []) if item.get("met"))
        cause = "; first cause: " + str(record["firstCause"])[:200] if record.get("firstCause") else ""
        print(f"- {row}: {record.get('result')} (attempt {record.get('attempt')}, {met}/{len(record.get('checks', []))} checks, "
              f"liveAcceptance {record.get('liveAcceptance')}){cause}")
    return 0


def environment(parser):
    if os.environ.get("WGEX_LAB_VM") != "macos27-wgex" or os.environ.get("WGEX_LAB_USER") != "admin":
        parser.error("M08 rows run on WGEX_LAB_VM=macos27-wgex with WGEX_LAB_USER=admin")
    if not re.fullmatch(r"[a-z0-9.-]{1,200}", RESOLVABLE):
        parser.error("WGEX_M08_RESOLVABLE_NAME must be a plain host name")


def run_setup(args, live, auth, ready):
    session = live.Session("M08-SETUP", {}, no_install=True)
    rows = Rows(session, live, args.attempt)
    error = None
    try:
        rows.stage()
        rows.setup(auth, ready)
    except (auth.Failure, live.RowFailure, live.PollDeadline, RuntimeError, OSError, ValueError, KeyError, TypeError) as caught:
        error = command_fault(session, caught)
    finally:
        warnings = session.cleanup()
    record = dict(step="M08-SETUP", attempt=args.attempt, at=stamp(), ok=error is None,
                  error=f"{type(error).__name__}: {error}"[:300] if error else None, notes=rows.notes, cleanupWarnings=warnings,
                  buildRoot=str(session.output))
    args.report_root.mkdir(parents=True, exist_ok=True)
    (args.report_root / f"setup-{args.attempt}.json").write_text(scrub(json.dumps(record, indent=2, sort_keys=True)) + "\n")
    print("M08-SETUP: " + ("ready" if error is None else "driver fault: " + record["error"]))
    return 0 if error is None else EXIT["driverFault"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("row", nargs="?")
    parser.add_argument("--report-root", type=Path)
    parser.add_argument("--attempt", type=int, choices=(1, 2), default=1)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("rows", nargs="*")
    args = parser.parse_args(argv)
    if args.summary:
        return summary(args.summary, ([args.row] if args.row else []) + args.rows)
    if (args.row not in ROWS and args.row != "setup") or args.report_root is None or args.rows:
        parser.error("setup or one row from ROWS, and --report-root, are required")
    environment(parser)
    run = load("m08_verdict_run", LAB / "verdict-run.py")
    live = load("m08_verdict_live", LAB / "verdict-live.py")
    if args.row == "setup":
        return run_setup(args, live, load("m08_auth_real", LAB / "auth-real.py"), load("m08_ready_snapshot", LAB / "ready-snapshot.py"))
    load_start = run.HARNESS.host_load()
    session = live.Session(args.row, {}, no_install=True)
    rows = Rows(session, live, args.attempt, load("m08_auth_real", LAB / "auth-real.py"))
    error, gaps, started = None, [], stamp()
    try:
        rows.stage()
        session.measure_provenance()
        RUNS[args.row](rows)
    except (Precondition, ProductFailure) as caught:
        error = caught
    except (live.RowFailure, live.PollDeadline, RuntimeError, OSError, ValueError, KeyError, TypeError) as caught:
        error = command_fault(session, caught)
    finally:
        try:
            rows.deactivate()
        except (RuntimeError, OSError, ValueError):
            gaps.append("deactivate at the row's end failed")
        try:
            if session.provenance.get("sourceCommit"):
                live.finish_provenance(session, args.row, {})
        except (live.RowFailure, RuntimeError, OSError, ValueError) as caught:
            gaps.append("provenance re-measure: " + type(caught).__name__)
        warnings = session.cleanup()
    major = str(session.provenance.get("guestOS", {}).get("productVersion", "")).split(".")[0] or "27"
    extra = dict(startedAt=started, endedAt=stamp(), notes=rows.notes, windows=rows.windows, evidence=rows.evidence,
                 cleanupWarnings=warnings, buildRoot=str(session.output),
                 hostLoad=run.HARNESS.load_record(load_start, run.HARNESS.host_load()),
                 fixtures=dict(excludedRange=EXCLUDED_RANGE, excludedDestination=EXCLUDED_DST, tunnelDestination=TUNNEL_DST,
                               ports=PORT_ENTRIES, resolvableName=RESOLVABLE, probeTTL=1, watchSeconds=WATCH_SECONDS),
                 transport="headless Tart guest (VNC console), guarded SSH, guest tcpdump on en0 and utun, peer wg0 packet socket")
    record = verdict(args.row, args.attempt, rows.checks, error, session.provenance, session.installation, extra)
    gaps.extend("Provenance: " + failure for failure in run.PROVENANCE.provenance_errors(record, major))
    write(args.report_root / args.row, record, gaps)
    print(f"{args.row}: {record['result']} (attempt {args.attempt}){'; ' + record['firstCause'] if record['firstCause'] else ''}")
    return EXIT[record["result"]]


if __name__ == "__main__":
    sys.exit(main())
