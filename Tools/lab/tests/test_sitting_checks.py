# SPDX-License-Identifier: MIT
"""M04-T01 / DEC-026: the sitting helper's checks against fixtures in the real formats of macOS 27's tools.

A fake runner stands in for every command, so nothing here runs a capture, a lookup, sudo, WGEX or a network change.
The fixture formats come from this Mac's read-only tools (netstat -rn, route get, scutil --dns, scutil --nc list,
networksetup -listallhardwareports, ifconfig, log show --style compact, security authorizationdb read, codesign -dv,
tcpdump 4.99.1 Apple version 161 banners) and from WGEX's own sources (WGEXCLICore.swift status, doctor and error JSON).
Each review finding of rounds 1 to 5 (REV-M04-T01) appears below as a failing input.
"""
import contextlib
import importlib.util
import io
import json
import os
import shutil
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("sitting_checks", ROOT / "Tools/lab/sitting/checks.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)

CLI = C.CLI
PROFILE = "6F1C2A3B-4D5E-4F60-8A7B-9C0D1E2F3A4B"
OTHER = "11111111-2222-4333-8444-555555555555"
VPS4 = "203.0.113.7"
VPS6 = "2001:db8::7"
ISP4 = "198.51.100.23"
DNSIP = "10.66.0.1"

# ---- real-format fixtures ----------------------------------------------------------------------------------------

NETSTAT_OFFICIAL = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
default            link#31            UCSIg               utun8
default            link#34            UCSIg           bridge100      !
127                127.0.0.1          UCS                   lo0
127.0.0.1          127.0.0.1          UH                    lo0
169.254            link#14            UCS                   en0      !
192.168.1/24       link#14            UCS                   en0      !
"""
NETSTAT_WGEX = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
0/1                10.66.0.2          UGSc                utun4
default            192.168.1.1        UGScg                 en0
128.0/1            10.66.0.2          UGSc                utun4
192.0.2.1          192.168.1.1        UGHS2I                en0
"""
NETSTAT_ETHERNET = NETSTAT_WGEX.replace("en0", "en7").replace("192.168.1.1", "192.168.2.1")
NETSTAT_SCOPED_ONLY = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScIg                en0
default            link#31            UCSIg               utun8
"""
# M04-T11: the maintainer's sitting, 14 Nov, step 2d, official app connected (full tunnel): the tunnel default is interface-scoped
# and `route get 9.9.9.9` names en0, yet traffic leaves through utun8.
NETSTAT_SITTING_SCOPED = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            172.17.17.1        UGScg                 en0
default            link#32            UCSIg               utun8
127                127.0.0.1          UCS                   lo0
172.17.17/24       link#14            UCS                   en0      !
"""
# The same with the Ethernet cable in: the unscoped default moves to the wired adapter.
NETSTAT_SITTING_ETHERNET = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            172.17.17.1        UGScg                 en7
default            172.17.17.1        UGScIg                en0
default            link#32            UCSIg               utun8
"""
NETSTAT_NO_TUNNEL = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            172.17.17.1        UGScg                 en0
172.17.17/24       link#14            UCS                   en0      !
"""
NETSTAT_TWO_SCOPED = NETSTAT_SITTING_SCOPED.replace(
    "default            link#32            UCSIg               utun8\n",
    "default            link#32            UCSIg               utun8\ndefault            link#33            UCSIg               utun9\n")
NETSTAT_TUNNEL_ONLY = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            link#31            UCSg                utun8
"""


def route_get(interface):
    return """   route to: 9.9.9.9
destination: 0.0.0.0
       mask: 128.0.0.0
    gateway: 10.66.0.2
  interface: %s
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1420         0
""" % interface


def scutil_dns(first, interface="utun4"):
    return """DNS configuration

resolver #1
  nameserver[0] : %s
  if_index : 31 (%s)
  flags    : Request A records
  reach    : 0x00000002 (Reachable)
  order    : 100000

resolver #2
  nameserver[0] : 192.168.1.1
  if_index : 14 (en0)
  flags    : Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)
  order    : 200000

resolver #3
  domain   : local
  options  : mdns
  timeout  : 5
""" % (first, interface)


NC_DISCONNECTED = """Available network connection services in the current set (*=enabled):
* (Disconnected)   00000000-0000-4000-8000-000000000112 VPN (com.wireguard.macos) "Example VPN A"               [VPN:com.wireguard.macos]
* (Disconnected)   00000000-0000-4000-8000-000000000113 VPN (com.wireguard.macos) "Example VPN B"               [VPN:com.wireguard.macos]
"""
NC_ONE_CONNECTED = NC_DISCONNECTED.replace("* (Disconnected)   00000000-0000-4000-8000-000000000113",
                                            "* (Connected)      00000000-0000-4000-8000-000000000113")
NC_EMPTY = "Available network connection services in the current set (*=enabled):\n"

HARDWARE_PORTS = """
Hardware Port: Ethernet Adapter (en4)
Device: en4
Ethernet Address: 02:00:5e:10:00:02

Hardware Port: USB 10/100/1000 LAN
Device: en7
Ethernet Address: 02:00:5e:10:00:03

Hardware Port: Thunderbolt Bridge
Device: bridge0
Ethernet Address: 02:00:00:00:00:00

Hardware Port: Wi-Fi
Device: en0
Ethernet Address: 02:00:5e:10:00:04

Hardware Port: Thunderbolt 1
Device: en1
Ethernet Address: 02:00:5e:10:00:05

VLAN Configurations
===================
"""


def ifconfig(name, status):
    return ("%s: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
            "\tether 02:00:5e:10:00:03\n\tmedia: autoselect (1000baseT <full-duplex>)\n\tstatus: %s\n" % (name, status))


LOG_HEADER = "Timestamp               Ty Process[PID:TID]\n"
LOG_CLEAN = LOG_HEADER + (
    "2026-11-20 10:00:03.120 Df WGEXDaemon[412:1a2b] [com.magrathean.WGEXApp:daemon] secure install verified\n")
LOG_PREAMBLE = ('Filtering the log data using "process == \\"WGEXDaemon\\""\n'
                "Skipping info and debug messages, pass --info and/or --debug to include.\n")
LOG_DENIED = LOG_CLEAN + (
    "2026-11-20 10:00:04.010 E  WGEXDaemon[412:1a2b] [com.magrathean.WGEXApp:daemon] key read failed: "
    "CSSMERR_CSP_OPERATION_AUTH_DENIED\n")

BANNER_VERBOSE = "tcpdump: verbose output suppressed, use -v[v]... for full protocol decode\n"


def banner(interface):
    link = "NULL (BSD loopback)" if interface.startswith("utun") else "EN10MB (Ethernet)"
    return BANNER_VERBOSE + "listening on %s, link-type %s, snapshot length 524288 bytes\n" % (interface, link)


def query_line(name, server=DNSIP, port=53):
    return "10:00:01.%06d IP 10.66.0.2.53211 > %s.%d: 4242+ A? %s. (46)\n" % (len(name), server, port, name)


RIGHT_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>class</key>
	<string>rule</string>
	<key>comment</key>
	<string>WGEX administrator authorisation; authenticate-admin-nonshared, not shared, 30 seconds</string>
	<key>created</key>
	<real>815991105.48942602</real>
	<key>identifier</key>
	<string>com.magrathean.WGEXApp.daemon</string>
	<key>modified</key>
	<real>815991105.48942602</real>
	<key>requirement</key>
	<string>identifier "com.magrathean.WGEXApp.daemon" and anchor apple generic</string>
	<key>rule</key>
	<array>
		<string>%s</string>
	</array>
	<key>version</key>
	<integer>0</integer>
</dict>
</plist>
"""


def codesign_text(cdhash="ab" * 20, authority="Apple Development: Test Person (ABCDE12345)", team="ABCDE12345",
                  identifier="com.magrathean.WGEXApp"):
    return ("Executable=/Applications/WGEX.app/Contents/MacOS/WGEX\nIdentifier=%s\n"
            "Format=app bundle with Mach-O thin (arm64)\nCodeDirectory v=20500 size=9999 flags=0x10000(runtime) "
            "hashes=300+7 location=embedded\nHash type=sha256 size=32\nCDHash=%s\nSignature size=4797\n"
            "Authority=%s\nAuthority=Apple Worldwide Developer Relations Certification Authority\n"
            "Authority=Apple Root CA\nSigned Time=20 Nov 2026 at 10:00:00\nInfo.plist entries=30\n"
            "TeamIdentifier=%s\nSealed Resources version=2 rules=13 files=40\n" % (identifier, cdhash, authority, team))


def status(**changes):
    """A valid `wgex status --json` document (WGEXCLICore.swift publicationFields), changed by dotted keys."""
    doc = {
        "activeProfileID": None, "cutover": {"state": "none"}, "cutoverRollbackFailures": [], "journalPolicy": None,
        "measuredAt": "2026-11-20T10:00:00Z", "measuredAtContinuous": 12.5, "onDemand": None, "operationInFlight": False,
        "phase": "idle", "policyEnforcing": False, "protection": "unprotected", "protectionNote": None, "sequence": 3,
        "startup": None, "verifiedAt": None, "verifiedAtContinuous": None,
    }
    for key, value in changes.items():
        target = doc
        parts = key.split("__")
        for part in parts[:-1]:
            target = target[part]
        target[parts[-1]] = value
    return doc


def on_demand(armed=PROFILE, decision="connect"):
    return {"activated": armed is not None, "armedProfileID": armed,
            "decision": None if decision is None else {"state": decision},
            "evaluatedAtContinuous": 40.0, "network": "wifi", "ssid": {"state": "known"}}


def active_status(**changes):
    base = {"phase": "active", "protection": "protected", "activeProfileID": PROFILE, "policyEnforcing": True,
            "cutover": {"state": "confirmed"}, "journalPolicy": "connected"}
    base.update(changes)
    return status(**base)


def js(doc):
    return json.dumps(doc, sort_keys=True) + "\n"


# ---- fake runner -------------------------------------------------------------------------------------------------

class FakeProc:
    """A capture in fake time. Spec keys: err (written at spawn), out (str or callable(dig names), written when it ends),
    rc (exit when it ends by itself, None = never), end (seconds after spawn, default the alarm), term (exit on SIGTERM,
    None = ignores it), vanish (its output file is gone when it ends)."""

    def __init__(self, fake, argv, out_path, err_path, spec):
        self.fake, self.argv, self.out_path, self.spec = fake, argv, out_path, spec
        self.pid = 4000 + len(fake.spawned)
        self.born, self.done, self.rc = fake.t, False, None
        with open(err_path, "w", encoding="utf-8") as handle:
            handle.write(spec.get("err", ""))
        with open(out_path, "w", encoding="utf-8") as handle:
            handle.write("")

    def end_time(self):
        return None if self.spec.get("rc", -14) is None else self.born + self.spec.get("end", C.CAPTURE_SECONDS)

    def finish(self, rc):
        out = self.spec.get("out", "")
        if callable(out):
            out = out(self.fake.dig_names())
        with open(self.out_path, "w", encoding="utf-8") as handle:
            handle.write(out)
        if self.spec.get("vanish"):
            os.remove(self.out_path)
        if self.spec.get("vanish_err"):
            os.remove(self.out_path[:-len(".txt")] + ".err")
        self.done, self.rc = True, rc
        self.fake.record(C.Result(self.argv, rc))

    def poll(self):
        if not self.done and self.end_time() is not None and self.fake.t >= self.end_time():
            self.finish(self.spec.get("rc", -14))
        return self.rc

    def wait(self, timeout):
        if self.poll() is None:
            end = self.end_time()
            self.fake.t = end if end is not None and end <= self.fake.t + timeout else self.fake.t + timeout
        return self.poll()

    def signal(self, name):
        if self.done:
            return
        if name == "-KILL":
            self.finish(-9)
        elif self.spec.get("term", -15) is not None:
            self.finish(self.spec.get("term", -15))


class Fake(C.Runner):
    """Rules map an argv prefix to a Result, a list of Results (one per call) or a callable(argv, fake). Every timeout
    passed to run() is kept in `timeouts`."""

    def __init__(self, rules=(), captures=None):
        super().__init__(io.StringIO())
        self.rules = [(tuple(prefix), answer) for prefix, answer in rules]
        self.captures = captures or {}
        self.spawned = []
        self.procs = []
        self.timeouts = []
        self.starts = []  # the fake clock at each run() call, parallel to `timeouts`
        self.t = 0.0

    def run(self, argv, cwd=None, env=None, timeout=None, data=None, interactive=False):
        self.timeouts.append((list(argv), timeout))
        self.starts.append(self.t)
        if argv[:3] == ["/usr/bin/sudo", "-n", "/bin/kill"]:
            targets = [proc for proc in self.procs if str(proc.pid) == argv[4]]
            if len(targets) != 1:
                raise AssertionError("kill of a pid this check did not spawn: %r" % (argv,))
            targets[0].signal(argv[3])
            return self.record(C.Result(argv, 0))
        for prefix, answer in self.rules:
            if tuple(argv[:len(prefix)]) == prefix:
                if isinstance(answer, list):
                    answer = answer.pop(0) if len(answer) > 1 else answer[0]
                if callable(answer):
                    answer = answer(argv, self)
                rc, out, err = answer
                self.t += 0.1
                return self.record(C.Result(argv, rc, out, err))
        raise AssertionError("unexpected command: %r" % (argv,))

    def spawn(self, argv, out_path, err_path):
        interface = argv[argv.index("-i") + 1]
        self.spawned.append(argv)
        proc = FakeProc(self, argv, out_path, err_path, self.captures.get(interface, {}))
        self.procs.append(proc)
        return proc

    def monotonic(self):
        return self.t

    def sleep(self, seconds):
        self.t += seconds

    def clock(self):
        return "10:00:00"

    def dig_names(self):
        return [result.argv[-1] for result in self.log if result.argv[0] == "/usr/bin/dig"]

    def ran(self, program):
        return [result for result in self.log if result.argv[0] == program]


def ok(out="", err=""):
    return (0, out, err)


def dig_ok(argv, fake):
    return (0, "\n; <<>> DiG 9.10.6 <<>> +time=2 +tries=1 A %s\n;; global options: +cmd\n;; Got answer:\n"
               ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 4242\n" % argv[-1], "")


def tunnel_queries(names):
    return "".join(query_line(name) for name in names)


def healthy_captures(phys="en0", utun="utun4"):
    return {phys: {"err": banner(phys), "out": "", "rc": -14},
            utun: {"err": banner(utun), "out": tunnel_queries, "rc": -14}}


def network_rules(netstat=NETSTAT_WGEX, utun="utun4", resolver=DNSIP, dig=dig_ok, sudo=ok(), resolver_on="utun4"):
    return [
        (["/usr/sbin/netstat"], ok(netstat)),
        (["/sbin/route"], ok(route_get(utun))),
        (["/usr/bin/sudo", "-n", "/usr/bin/true"], sudo),
        (["/usr/bin/dig"], dig),
        (["/usr/sbin/scutil", "--dns"], ok(scutil_dns(resolver, resolver_on))),
    ]


def curl_rules(v4=ok(VPS4 + "\n"), v6=(7, "", "curl: (7) Failed to connect to ifconfig.me port 443 after 3 ms: "
                                         "Could not connect to server\n")):
    return [(["/usr/bin/curl", "-4"], v4), (["/usr/bin/curl", "-6"], v6)]


def status_rule(*docs, rc=0):
    return ([CLI, "status", "--json"], [(rc, js(doc) if isinstance(doc, dict) else doc, "") for doc in docs])


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        quiet = contextlib.ExitStack()
        quiet.enter_context(contextlib.redirect_stderr(io.StringIO()))  # argparse usage errors
        self.addCleanup(quiet.close)

    def check(self, argv, fake):
        out = io.StringIO()
        if argv[0] in ("s3", "s123", "baseline") and "--workdir" not in argv:
            argv = list(argv) + ["--workdir", os.path.join(self.tmp.name, "cap-%d" % len(os.listdir(self.tmp.name)))]
        code = C.main(list(argv), runner=fake, out=out)
        text = out.getvalue()
        verdicts = [line for line in text.splitlines() if re.match(r"^%s: (PASS|FAIL) - " % argv[0], line)]
        self.assertEqual(len(verdicts), 1, text)
        return code, text, verdicts[0]

    def passes(self, argv, fake):
        code, text, verdict = self.check(argv, fake)
        self.assertEqual(code, 0, text)
        return text

    def fails(self, argv, fake, needle):
        code, text, verdict = self.check(argv, fake)
        self.assertEqual(code, 1, text)
        self.assertIn(needle, text)
        return text


# ---- status validation (round 3 item 2, round 4 item 1) ----------------------------------------------------------

class StatusValidation(Base):
    def test_a_valid_status_passes_with_expectations(self):
        fake = Fake([status_rule(active_status())])
        text = self.passes(["status", "phase", "--expect", "protection=protected", "--expect",
                            "cutover.state=armed|confirmed"], fake)
        self.assertIn("phase=active", text)
        self.assertIn("protection=protected", text)

    def test_an_unexpected_value_fails(self):
        fake = Fake([status_rule(status())])
        self.fails(["status", "--expect", "protection=protected"], fake, "protection=unprotected, expected protected")

    def test_the_armed_trial_check(self):
        # VER-M04-SITTING: C2 also needs the active phase and no operation in flight (RUNBOOK trial flow step 2).
        argv = ["status", "cutover.state", "protection", "phase", "operationInFlight", "--expect", "cutover.state=armed",
                "--expect", "protection=protected", "--expect", "phase=active", "--expect", "operationInFlight=false"]
        armed = {"cutover": {"state": "armed", "deadline": "2026-11-20T10:10:00Z"}}
        text = self.passes(argv, Fake([status_rule(active_status(**armed))]))
        self.assertIn("operationInFlight=false", text)
        self.fails(argv, Fake([status_rule(active_status(operationInFlight=True, **armed))]),
                   "operationInFlight=true, expected false")
        self.fails(argv, Fake([status_rule(active_status(phase="configuring", **armed))]),
                   "phase=configuring, expected active")

    def test_malformed_field_types_fail(self):
        # Round 4 item 1: every field null passed the old field-presence check.
        nulls = {"phase": None, "protection": None, "cutover": None, "onDemand": None}
        for doc in (status(**nulls), status(phase="sleeping"), status(protection=True), status(sequence="3"),
                    status(sequence=True), status(activeProfileID="not-a-uuid"), status(operationInFlight="no"),
                    status(cutover={"state": "rolledBack"}), status(cutover={"state": "rolledBack", "reason": "x"}),
                    status(cutover={"state": "armed"}), status(cutoverRollbackFailures="none"),
                    status(journalPolicy=7), status(onDemand="none"), status(onDemand={"armedProfileID": None}),
                    status(onDemand=dict(on_demand(), armedProfileID=5)),
                    status(onDemand=dict(on_demand(), decision={"state": "hold"})),
                    status(onDemand=dict(on_demand(), network="cellular")),
                    status(onDemand=dict(on_demand(), ssid={"state": "unavailable"})), status(startup=[])):
            with self.subTest(doc=doc):
                self.fails(["status", "phase"], Fake([status_rule(doc)]), "invalid status")

    def test_missing_fields_and_non_objects_fail(self):
        doc = status()
        del doc["onDemand"]
        self.fails(["status"], Fake([status_rule(doc)]), "the reply has no onDemand")
        self.fails(["status"], Fake([status_rule("[1, 2]\n")]), "did not print a JSON object")
        self.fails(["status"], Fake([status_rule("not json\n")]), "did not print JSON")
        self.fails(["status"], Fake([status_rule("")]), "did not print JSON")

    def test_error_json_fails_with_either_exit(self):
        # Round 3 item 2: the CLI prints {"error": ...} on stdout (WGEXCLICore.swift failure()).
        self.fails(["status"], Fake([status_rule({"error": "daemonUnavailable"}, rc=1)]),
                   "exited 1 (daemonUnavailable)")
        self.fails(["status"], Fake([status_rule({"error": "protocolMismatch"}, rc=17)]), "exited 17")
        self.fails(["status"], Fake([status_rule({"error": "system"})]), "replied with error system")

    def test_on_demand_null_is_legitimate(self):
        # The daemon publishes no on-demand status when nothing is armed (TunnelController+OnDemand.swift).
        text = self.passes(["status", "onDemand.armedProfileID"], Fake([status_rule(status(onDemand=None))]))
        self.assertIn("onDemand.armedProfileID=null", text)

    def test_malformed_containers_fail_with_a_verdict(self):
        # Round 5 item 4: phase=[] raised TypeError; enum membership is now guarded by type.
        for doc in (status(phase=[]), status(protection={}), status(protectionNote=["dnsUnverified"]),
                    status(cutover={"state": []}), status(cutover={"state": "rolledBack", "reason": {}}),
                    status(journalPolicy=[]), status(onDemand=dict(on_demand(), network=[])),
                    status(onDemand=dict(on_demand(), ssid={"state": {}})),
                    status(onDemand=dict(on_demand(), ssid={"state": "unavailable", "reason": []})),
                    status(onDemand=dict(on_demand(), decision={"state": []})),
                    status(onDemand=dict(on_demand(), decision={"state": "hold", "reason": {}})),
                    status(onDemand=dict(on_demand(), decision=[])), status(cutover=[]), status(onDemand=[]),
                    status(measuredAtContinuous="12"), status(verifiedAt=5), status(recoveryFailureReason=[])):
            with self.subTest(doc=doc):
                self.fails(["status", "phase"], Fake([status_rule(doc)]), "invalid status")
        self.fails(["status"], Fake([status_rule({"error": []}, rc=1)]), "exited 1")

    def test_missing_publication_fields_and_startup(self):
        # Round 5 item 4: startup={"phase": null} and missing measurement fields passed.
        publication = status()
        del publication["startup"]
        self.passes(["status"], Fake([status_rule(status(startup=dict(publication)))]))
        for field in ("measuredAt", "measuredAtContinuous", "verifiedAt", "verifiedAtContinuous", "sequence",
                      "startup"):
            doc = status()
            del doc[field]
            with self.subTest(field=field):
                self.fails(["status"], Fake([status_rule(doc)]), "the reply has no %s" % field)
        self.fails(["status"], Fake([status_rule(status(startup={"phase": None}))]), "the reply has no startup.")
        no_measure = dict(publication)
        del no_measure["measuredAt"]
        self.fails(["status"], Fake([status_rule(status(startup=no_measure))]), "the reply has no startup.measuredAt")
        self.fails(["status"], Fake([status_rule(status(startup=dict(publication, phase=[])))]),
                   "startup.phase is not a known phase")
        self.fails(["status"], Fake([status_rule(status(startup=[]))]), "startup is not a JSON object")
        self.fails(["status"], Fake([status_rule(status(startup="none"))]), "startup is not a JSON object")

    def test_an_unknown_key_fails(self):
        self.fails(["status", "nosuch.key"], Fake([status_rule(status())]), "the reply has no nosuch.key")


# ---- disarm and abort (round 2 item 2, round 3 item 2, round 4 items 1 and 3) ------------------------------------

class DisarmAndAbort(Base):
    def disarm(self, reply, docs, rc=0):
        return Fake([([CLI, "on-demand", PROFILE, "off", "--json"], (rc, js(reply), "")), status_rule(*docs)])

    def test_verified_disarm(self):
        for doc in (status(onDemand=None), status(onDemand=on_demand(armed=None, decision=None))):
            with self.subTest(doc=doc):
                text = self.passes(["disarm", "--profile", PROFILE], self.disarm({"result": "disarmed"}, [doc]))
                self.assertIn("armed-empty", text)

    def test_disarm_failures(self):
        cases = [
            ({"error": "daemonUnavailable"}, [status(onDemand=None)], 1, "exited 1 (daemonUnavailable)"),
            ({"error": "busy"}, [status(onDemand=None)], 13, "exited 13"),
            ({"result": "armed"}, [status(onDemand=None)], 0, "not disarmed"),
            ({"result": "disarmed"}, [status(onDemand=on_demand())], 0, "still armed for " + PROFILE),
            ({"result": "disarmed"}, [status(phase=None, protection=None, cutover=None, onDemand=None)], 0,
             "invalid status"),
            ({"result": "disarmed"}, ["{\"error\":\"daemonUnavailable\"}\n"], 0, "replied with error"),
        ]
        for reply, docs, rc, needle in cases:
            with self.subTest(reply=reply, needle=needle):
                text = self.fails(["disarm", "--profile", PROFILE], self.disarm(reply, docs, rc), needle)
                self.assertIn("NOT-DISARMED", text)
                self.assertNotIn("armed-empty", text)

    def abort(self, reply_rc, docs):
        return Fake([([CLI, "cutover", "abort", "--json"], (reply_rc, js(docs[0]), "")), status_rule(*docs)])

    def test_abort_accepts_completed_rollback_reasons_and_no_trial(self):
        # Round 4 item 3: timeout and startFailed rollbacks are already complete; abort returns without a new reason.
        for reason in ("aborted", "timeout", "startFailed", "daemonRestart"):
            with self.subTest(reason=reason):
                doc = status(cutover={"state": "rolledBack", "reason": reason})
                text = self.passes(["abort"], self.abort(0, [doc]))
                self.assertIn("rolled back (%s)" % reason, text)
        text = self.passes(["abort"], self.abort(0, [status()]))
        self.assertIn("no trial exists", text)
        failures = status(cutover={"state": "rolledBack", "reason": "aborted"}, cutoverRollbackFailures=["removeDNS"])
        self.passes(["abort"], self.abort(0, [failures]))

    def test_abort_failures(self):
        rolled = {"state": "rolledBack", "reason": "aborted"}
        cases = [
            (12, [status(cutover=rolled)], "exited 12"),
            (1, [{"error": "daemonUnavailable"}], "exited 1 (daemonUnavailable)"),
            (0, [active_status(cutover={"state": "armed", "deadline": "2026-11-20T10:10:00Z"})], "state is armed"),
            (0, [active_status()], "state is confirmed"),
            (0, [status(cutover=rolled, activeProfileID=PROFILE)], "a profile is still active"),
            (0, [status(cutover=rolled, operationInFlight=True)], "still in flight"),
            (0, [status(cutover={"state": "rolledBack", "reason": None})], "invalid status"),
        ]
        for rc, docs, needle in cases:
            with self.subTest(needle=needle):
                self.fails(["abort"], self.abort(rc, docs), needle)

    def test_arm(self):
        rule = [CLI, "on-demand", PROFILE, "on", "--json"]
        self.passes(["arm", "--profile", PROFILE], Fake([(rule, ok(js({"result": "armed"})))]))
        self.fails(["arm", "--profile", PROFILE], Fake([(rule, (13, js({"error": "busy"}), ""))]), "exited 13")
        self.assertEqual(C.main(["arm", "--profile", "not-a-uuid"], runner=Fake(), out=io.StringIO()), 2)


# ---- C2 and C3 through the helper (round 5 item 6), bootout (round 5 item 1) ---------------------------------------

class TrialCommands(Base):
    START = [CLI, "cutover", "start", PROFILE, "--confirm-within", "10m", "--json"]
    CONFIRM = [CLI, "cutover", "confirm", "--json"]
    ARMED = {"state": "armed", "deadline": "2026-11-20T10:10:00Z"}

    def test_start_passes_only_on_an_armed_trial_for_the_profile(self):
        argv = ["cutover-start", "--profile", PROFILE.lower(), "--confirm-within", "10m"]
        text = self.passes(argv, Fake([(self.START, ok(js(active_status(cutover=self.ARMED))))]))
        self.assertIn("cutover.state=armed", text)
        fake = Fake([(self.START, (3, js({"error": "secretsUnavailable"}), ""))])
        self.fails(argv, fake, "exited 3")
        self.assertIn("[exit 3] " + " ".join(self.START), fake.echo.getvalue())
        cases = [
            ((3, js({"error": "secretsUnavailable"}), ""), "exited 3 (secretsUnavailable)"),
            ((4, js({"error": "authorisation"}), ""), "exited 4"),
            ((13, "", ""), "exited 13"),
            (ok(js({"error": "system"})), "replied with error system"),
            (ok("not json\n"), "did not print JSON"),
            (ok(js(status())), "cutover.state is none, not armed"),
            (ok(js(active_status(cutover=self.ARMED, activeProfileID=OTHER))), "the active profile is " + OTHER),
            (ok(js(active_status(cutover=self.ARMED, phase=[]))), "invalid status"),
            (ok(js(status(cutover={"state": "rolledBack", "reason": "startFailed"}))), "not armed"),
        ]
        for reply, needle in cases:
            with self.subTest(needle=needle):
                self.fails(argv, Fake([(self.START, reply)]), needle)
        for window in ("10", "59s", "61m", "1h", "<window>"):
            with self.subTest(window=window):
                self.assertEqual(C.main(["cutover-start", "--profile", PROFILE, "--confirm-within", window],
                                        runner=Fake(), out=io.StringIO()), 2)

    def test_confirm_passes_only_on_a_confirmed_trial(self):
        self.passes(["cutover-confirm"], Fake([(self.CONFIRM, ok(js(active_status())))]))
        cases = [
            ((8, js({"error": "timedOut"}), ""), "exited 8 (timedOut)"),
            ((12, js({"error": "protectionUnknown"}), ""), "exited 12"),
            (ok(js(active_status(cutover=self.ARMED))), "cutover.state is armed, not confirmed"),
            (ok(js(active_status(cutover=[]))), "invalid status"),
        ]
        for reply, needle in cases:
            with self.subTest(needle=needle):
                self.fails(["cutover-confirm"], Fake([(self.CONFIRM, reply)]), needle)

    def test_bootout_needs_the_service_gone(self):
        bootout = ["/usr/bin/sudo", "-n", "/bin/launchctl", "bootout"]
        printed = ["/usr/bin/sudo", "-n", "/bin/launchctl", "print"]
        gone = (113, "", "Could not find service \"com.magrathean.WGEXApp.daemon\" in domain for system\n")
        text = self.passes(["bootout"], Fake([(bootout, ok()), (printed, gone)]))
        self.assertIn("not-loaded", text)
        # Already booted out: bootout itself fails, the service is still absent, so it passes.
        self.passes(["bootout"], Fake([(bootout, (3, "", "Boot-out failed: 3: No such process\n")), (printed, gone)]))
        self.fails(["bootout"], Fake([(bootout, (5, "", "Boot-out failed: 5\n")), (printed, ok("state = running\n"))]),
                   "is still loaded")
        self.fails(["bootout"], Fake([(bootout, (1, "", "sudo: a password is required\n")),
                                      (printed, (1, "", "sudo: a password is required\n"))]), "launchctl print exited 1")

    def test_bootout_polls_until_the_service_is_gone(self):
        bootout = ["/usr/bin/sudo", "-n", "/bin/launchctl", "bootout"]
        printed = ["/usr/bin/sudo", "-n", "/bin/launchctl", "print"]
        gone = (113, "", "Could not find service\n")
        listed = ok("state = running\n")
        # Immediate absence: one print, no sleep.
        fake = Fake([(bootout, ok()), (printed, gone)])
        self.passes(["bootout"], fake)
        self.assertEqual(len(fake.ran("/usr/bin/sudo")), 2)
        # Absent after a delay: listed twice, then gone.
        fake = Fake([(bootout, ok()), (printed, [listed, listed, gone])])
        self.assertIn("not-loaded", self.passes(["bootout"], fake))
        self.assertEqual(len(fake.ran("/usr/bin/sudo")), 4)
        # Never leaves: fails after the 20 s window with the last output.
        fake = Fake([(bootout, ok()), (printed, ok("state = running\n"))])
        self.fails(["bootout"], fake, "still loaded after 20s: state = running")
        self.assertGreaterEqual(fake.t, 20)
        self.assertLess(fake.t, 23)
        # Each print takes several seconds: the whole wait still ends within the bound, and no call outlasts it.
        def slow(argv, fake):
            fake.t += min(7, fake.timeouts[-1][1])  # a real print is killed at its timeout
            return ok("state = running\n")
        fake = Fake([(bootout, ok()), (printed, slow)])
        self.fails(["bootout"], fake, "still loaded after 20s: state = running")
        self.assertLessEqual(fake.t, 20.5)
        for argv, timeout in fake.timeouts:
            if "print" in argv:
                self.assertLessEqual(timeout, 20)
        # A fractional remainder: the first print takes 18.5 s, so every later timeout fits in the time left.
        def first_slow(argv, fake):
            prints = [r for r in fake.timeouts if "print" in r[0]]
            fake.t += min(18.5 if len(prints) == 1 else 7, fake.timeouts[-1][1])
            return ok("state = running\n")
        fake = Fake([(bootout, ok()), (printed, first_slow)])
        self.fails(["bootout"], fake, "still loaded after 20s: state = running")
        self.assertLessEqual(fake.t, 20.5)
        later = [timeout for argv, timeout in fake.timeouts if "print" in argv][1:]
        self.assertTrue(later)
        for timeout in later:
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 1.5 + 1e-9)
        # Every scenario: each print timeout is at most the time left at that call, and the whole wait is at most 20 s.
        for scenario in (slow, first_slow, ok("state = running\n")):
            fake = Fake([(bootout, ok()), (printed, scenario)])
            self.fails(["bootout"], fake, "still loaded after 20s")
            calls = [(start, timeout) for (argv, timeout), start in zip(fake.timeouts, fake.starts) if "print" in argv]
            begin = calls[0][0]
            for start, timeout in calls:
                self.assertLessEqual(timeout, begin + 20 - start + 1e-9)
            self.assertLessEqual(fake.t - begin, 20.1 + 1e-9)  # the fake adds 0.1 s per call, even past a timeout


# ---- S1, S2 ------------------------------------------------------------------------------------------------------

class AddressChecks(Base):
    def test_s1(self):
        self.passes(["s1", "--vps4", VPS4], Fake(curl_rules()))
        self.fails(["s1", "--vps4", VPS4], Fake(curl_rules(v4=ok(ISP4 + "\n"))), "a leak")
        self.fails(["s1", "--vps4", VPS4], Fake(curl_rules(v4=(28, "", "curl: (28) timed out\n"))), "exit 28")
        self.fails(["s1", "--vps4", VPS4], Fake(curl_rules(v4=(0, "", ""))), "could not measure")

    def test_s2_blocked_and_through_the_vps(self):
        self.passes(["s2", "--vps6", "none"], Fake(curl_rules()))
        self.fails(["s2", "--vps6", "none"], Fake(curl_rules(v6=ok("2001:db8:99::1\n"))), "a leak")
        self.fails(["s2", "--vps6", "none"], Fake(curl_rules(v6=ok(""))), "exited 0 with no address")
        self.passes(["s2", "--vps6", VPS6], Fake(curl_rules(v6=ok(VPS6 + "\n"))))
        self.fails(["s2", "--vps6", VPS6], Fake(curl_rules(v6=ok("2001:db8:99::1\n"))), "a leak")
        self.fails(["s2", "--vps6", VPS6], Fake(curl_rules()), "could not measure")

    def test_direct(self):
        self.passes(["direct", "--vps4", VPS4], Fake(curl_rules(v4=ok(ISP4 + "\n"))))
        self.fails(["direct", "--vps4", VPS4], Fake(curl_rules()), "the address is VPS4")
        self.fails(["direct", "--vps4", VPS4], Fake(curl_rules(v4=(7, "", "curl: (7) failed\n"))), "exit 7")

    def test_ready_checks_the_terminal_variables(self):
        text = self.passes(["ready", "--vps4", VPS4, "--vps6", "none", "--phys", "en0", "--dns", DNSIP, "--profile",
                            PROFILE.lower(), "--eth", "en7"], Fake())
        self.assertIn("profile=%s ok" % PROFILE, text)
        for argv in (["--dns", "<the DNS server of WGEX dedicated>"], ["--profile", ""], ["--phys", "utun4"],
                     ["--vps6", "<VPS6 or none>"]):
            with self.subTest(argv=argv):
                self.assertEqual(C.main(["ready"] + argv, runner=Fake(), out=io.StringIO()), 2)

    def test_bad_arguments_are_usage_errors(self):
        for argv in (["s1", "--vps4", "<VPS4>"], ["s2", "--vps6", "203.0.113.7"], ["s3", "--phys", "en0", "--dns",
                                                                                 "<the DNS server>"]):
            with self.subTest(argv=argv):
                self.assertEqual(C.main(argv, runner=Fake(), out=io.StringIO()), 2)


# ---- S3 DNS capture (round 2 item 3, round 3 item 1, round 4 item 2) ---------------------------------------------

class DnsCapture(Base):
    def s3(self, captures=None, **rules):
        return Fake(network_rules(**rules), captures if captures is not None else healthy_captures())

    def test_healthy_capture_with_native_banners(self):
        fake = self.s3()
        text = self.passes(["s3", "--phys", "en0", "--dns", DNSIP], fake)
        self.assertIn("physical lines: 0", text)
        self.assertIn("utun queries: 5 of 5", text)
        self.assertIn("resolver #1: %s" % DNSIP, text)
        self.assertEqual(len(fake.ran("/usr/bin/dig")), 5)
        for argv in fake.spawned:
            self.assertEqual(argv[:5], ["/usr/bin/sudo", "-n", "/usr/bin/perl", "-e", "alarm 20; exec @ARGV"])
            self.assertEqual(argv[5:9], ["/usr/sbin/tcpdump", "-n", "-l", "-i"])
            self.assertEqual(argv[-1], "port 53 or port 853")

    def test_warning_lines_are_allowed_and_the_shell_alarm_exit_counts(self):
        captures = healthy_captures()
        captures["utun4"]["err"] = "tcpdump: WARNING: utun4: That device doesn't support promiscuous mode\n" + banner(
            "utun4")
        captures["en0"]["rc"] = 142
        self.passes(["s3", "--phys", "en0", "--dns", DNSIP], self.s3(captures))

    def test_capture_failures(self):
        def broken(interface, **spec):
            captures = healthy_captures()
            captures[interface].update(spec)
            return captures

        cases = [
            (broken("en0", err="tcpdump: en0: You don't have permission to capture on that device\n"
                    "((cannot open BPF device) /dev/bpf0: Permission denied)\n", rc=1), "did not start"),
            (broken("en0", err="tcpdump: en9: No such device exists\n(BIOCSETIF failed: Device not configured)\n",
                    rc=1), "did not start"),
            (broken("en0", err="", rc=-14), "physical capture on en0 did not start"),
            (broken("utun4", err=""), "tunnel capture on utun4 did not start"),
            (broken("en0", err="sudo: a password is required\n", rc=1), "did not start"),
            (broken("en0", err="Can't exec \"/usr/sbin/tcpdump\": No such file or directory at -e line 1.\n", rc=0),
             "did not start"),
            (broken("en0", err="tcpdump: listening on en0, link-type EN10MB (Ethernet), snapshot length 524288 bytes\n"),
             "did not start"),
            (broken("en0", err=banner("en1")), "did not start"),
            (broken("en0", err=banner("en0").replace("listening on en0", "listening on en01")), "did not start"),
            (broken("en0", rc=0), "exited 0, not at its 20-second alarm"),
            (broken("en0", rc=-15), "exited -15"),
            (broken("en0", rc=None), "still running after its bound"),
            (broken("en0", err=banner("en0") + "tcpdump: pcap_loop: The interface went down\n", rc=1),
             "printed: tcpdump: pcap_loop"),
            (broken("en0", err=banner("en0") + "12 packets captured\n"), "printed: 12 packets captured"),
            (broken("en0", out=lambda names: query_line(names[0], "192.168.1.1")), "on the physical interface: a leak"),
            (broken("en0", out=lambda names: query_line("dns.google", "8.8.8.8", 853)), "a leak"),
            (broken("utun4", out=lambda names: tunnel_queries(names[:4])), "only 4 of 5 lookups"),
            (broken("utun4", out=lambda names: tunnel_queries(["wgex-s3-deadbeef.example.net"] * 5)), "only 0 of 5"),
            (broken("utun4", out=lambda names: "".join(query_line(n, "10.66.0.9") for n in names)), "only 0 of 5"),
        ]
        for captures, needle in cases:
            with self.subTest(needle=needle):
                self.fails(["s3", "--phys", "en0", "--dns", DNSIP], self.s3(captures), needle)

    def test_capture_file_read_errors_fail(self):
        # Round 5 item 5: an unreadable physical capture read as empty and passed with `physical lines: 0`.
        for interface, spec, needle in (("en0", {"vanish": True}, "cannot read the physical capture"),
                                        ("utun4", {"vanish": True}, "cannot read the tunnel capture"),
                                        ("en0", {"vanish_err": True}, "cannot read the physical capture's messages")):
            captures = healthy_captures()
            captures[interface].update(spec)
            with self.subTest(needle=needle):
                text = self.fails(["s3", "--phys", "en0", "--dns", DNSIP], self.s3(captures), needle)
                if interface == "en0" and "vanish" in spec:
                    self.assertNotIn("physical lines: 0", text)

    def test_both_windows_must_cover_the_lookups(self):
        # Round 5 item 5: the alarm exit alone established the window.
        for interface, name in (("en0", "physical"), ("utun4", "tunnel")):
            captures = healthy_captures()
            captures[interface]["end"] = 0.3
            with self.subTest(name=name):
                self.fails(["s3", "--phys", "en0", "--dns", DNSIP], self.s3(captures),
                           "the %s capture ended before the lookups finished" % name)
        text = self.passes(["s3", "--phys", "en0", "--dns", DNSIP], self.s3())
        self.assertIn("window: physical +", text)
        self.assertIn("window: tunnel +", text)

    def test_overrunning_captures_are_stopped_within_a_bound(self):
        # Round 5 item 5: a capture past its bound was left running.
        captures = healthy_captures()
        captures["en0"].update(rc=None)
        fake = self.s3(captures)
        text = self.fails(["s3", "--phys", "en0", "--dns", DNSIP], fake, "still running after its bound")
        self.assertIn("capture stopped: physical pid 4001, final exit -15", text)
        self.assertIn("capture exit: physical=-15", text)
        self.assertEqual([r.argv[3:] for r in fake.log if r.argv[:3] == ["/usr/bin/sudo", "-n", "/bin/kill"]],
                         [["-TERM", "4001"]])
        stubborn = healthy_captures()
        stubborn["utun4"].update(rc=None, term=None)
        fake = self.s3(stubborn)
        text = self.fails(["s3", "--phys", "en0", "--dns", DNSIP], fake, "still running after its bound")
        self.assertIn("capture stopped: tunnel pid 4002, final exit -9", text)
        self.assertLessEqual(fake.t, C.CAPTURE_SECONDS + 10 + 2 * C.STOP_GRACE + 1)

    def test_a_capture_that_did_not_start_stops_both_at_once(self):
        captures = healthy_captures()
        captures["en0"]["err"] = ""
        fake = self.s3(captures)
        text = self.fails(["s3", "--phys", "en0", "--dns", DNSIP], fake, "did not start")
        self.assertIn("capture stopped: physical pid 4001, final exit -15", text)
        self.assertIn("capture stopped: tunnel pid 4002, final exit -15", text)
        self.assertLess(fake.t, 10)

    def test_failed_lookups_fail(self):
        # Round 4 item 2: dig's exit was discarded. dig exits 9 when no reply arrives.
        no_reply = (9, ";; connection timed out; no servers could be reached\n", "")
        self.fails(["s3", "--phys", "en0", "--dns", DNSIP], self.s3(dig=no_reply), "exited 9")
        self.fails(["s3", "--phys", "en0", "--dns", DNSIP], self.s3(dig=(0, "", "")), "without an answer header")

    def test_no_lookup_runs_when_a_capture_did_not_start(self):
        captures = healthy_captures()
        captures["en0"]["err"] = ""
        fake = self.s3(captures)
        self.fails(["s3", "--phys", "en0", "--dns", DNSIP], fake, "did not start")
        self.assertEqual(fake.ran("/usr/bin/dig"), [])

    def test_resolver_and_route_failures(self):
        self.fails(["s3", "--phys", "en0", "--dns", DNSIP], self.s3(resolver="192.168.1.1"), "resolver #1 is 192.168.1.1")
        fake = Fake([(["/usr/sbin/scutil", "--dns"], (1, "", "scutil: failed\n"))] + network_rules(),
                    healthy_captures())
        self.fails(["s3", "--phys", "en0", "--dns", DNSIP], fake, "scutil --dns exited 1")
        self.fails(["s3", "--phys", "en0", "--dns", DNSIP], self.s3(utun="en0"), "routes through en0, not a utun")
        fake = Fake([(["/sbin/route"], (1, "", "route: writing to routing socket: not in table\n"))] + network_rules(),
                    healthy_captures())
        self.fails(["s3", "--phys", "en0", "--dns", DNSIP], fake, "route get exited 1")

    def test_sudo_without_a_ticket_fails_before_any_capture(self):
        # DEC-026: the helper uses sudo -n; the maintainer runs `sudo -v` once (a cached ticket is fine).
        fake = self.s3(sudo=(1, "", "sudo: a password is required\n"))
        self.fails(["s3", "--phys", "en0", "--dns", DNSIP], fake, "run `sudo -v`")
        self.assertEqual(fake.spawned, [])


# ---- physical interface, Ethernet, s123 (round 1 item 4, round 4 item 5) -----------------------------------------

class InterfaceChecks(Base):
    def test_physical_interface_from_real_tables(self):
        self.assertEqual(C.physical_from_netstat(NETSTAT_OFFICIAL), "en0")
        self.assertEqual(C.physical_from_netstat(NETSTAT_WGEX), "en0")
        self.assertEqual(C.physical_from_netstat(NETSTAT_ETHERNET), "en7")
        self.assertEqual(C.physical_from_netstat(NETSTAT_SCOPED_ONLY), "en0")
        self.assertIsNone(C.physical_from_netstat(NETSTAT_TUNNEL_ONLY))

    def test_physif(self):
        self.passes(["physif", "--expect", "en0"], Fake([(["/usr/sbin/netstat"], ok(NETSTAT_WGEX))]))
        self.fails(["physif", "--expect", "en7"], Fake([(["/usr/sbin/netstat"], ok(NETSTAT_WGEX))]), "not en7")
        self.fails(["physif"], Fake([(["/usr/sbin/netstat"], ok(NETSTAT_TUNNEL_ONLY))]), "no default route")
        self.fails(["physif"], Fake([(["/usr/sbin/netstat"], (1, "", "netstat: sysctl: Operation not permitted\n"))]),
                   "netstat exited 1")

    def test_ethernet_adapter(self):
        def fake(status_text="active", device="en7"):
            return Fake([(["/usr/sbin/networksetup"], ok(HARDWARE_PORTS)),
                         (["/sbin/ifconfig"], ok(ifconfig(device, status_text)))])

        self.passes(["ethernet", "--device", "en7"], fake())
        self.fails(["ethernet", "--device", "en7"], fake("inactive"), "no active link")
        self.fails(["ethernet", "--device", "en0"], fake(device="en0"), "is Wi-Fi, not a wired Ethernet adapter")
        self.fails(["ethernet", "--device", "en9"], fake(), "en9 is not a hardware port")
        self.assertEqual(C.main(["ethernet", "--device", "bridge0"], runner=fake(), out=io.StringIO()), 2)
        listed = self.passes(["ethernet"], Fake([(["/usr/sbin/networksetup"], ok(HARDWARE_PORTS))]))
        self.assertIn("en7: USB 10/100/1000 LAN", listed)
        self.assertIn("en0: Wi-Fi", listed)
        broken = Fake([(["/usr/sbin/networksetup"], (4, "", "** Error: unknown\n"))])
        self.fails(["ethernet", "--device", "en7"], broken, "networksetup exited 4")

    def s123(self, netstat=NETSTAT_WGEX, phys="en0", status_doc=None, v4=ok(VPS4 + "\n")):
        return Fake(network_rules(netstat=netstat) + curl_rules(v4=v4) + [status_rule(status_doc or active_status())],
                    healthy_captures(phys=phys))

    def test_s123_runs_s1_s2_s3_and_protection(self):
        fake = self.s123()
        text = self.passes(["s123", "--vps4", VPS4, "--vps6", "none", "--dns", DNSIP], fake)
        self.assertIn("physical=en0 tunnel=utun4", text)
        self.assertEqual(len(fake.ran("/usr/bin/curl")), 4)  # IPv4 from the first service; IPv6 asks all three
        self.assertEqual(len(fake.ran("/usr/bin/dig")), 5)

    def test_s123_ethernet_leg_needs_the_ethernet_adapter(self):
        # Round 4 item 5: with Wi-Fi still preferred the Ethernet leg must fail.
        args = ["s123", "--vps4", VPS4, "--vps6", "none", "--dns", DNSIP, "--phys", "en7"]
        self.fails(args, self.s123(), "the physical interface is en0, not en7")
        self.passes(args, self.s123(netstat=NETSTAT_ETHERNET, phys="en7"))

    def test_s123_failures(self):
        args = ["s123", "--vps4", VPS4, "--vps6", "none", "--dns", DNSIP]
        self.fails(args, self.s123(status_doc=active_status(protection="blocked")), "protection is blocked")
        self.fails(args, self.s123(v4=ok(ISP4 + "\n")), "a leak")
        self.fails(args, self.s123(netstat=NETSTAT_TUNNEL_ONLY), "no default route")


# ---- tunnel layouts (M04-T11) -------------------------------------------------------------------------------------

class TunnelLayouts(Base):
    """Unscoped tunnel default (WGEX) and interface-scoped tunnel default (the official app on macOS 27)."""

    def baseline(self, netstat=NETSTAT_SITTING_SCOPED, route="en0", resolver_on="utun8", phys="en0", utun="utun8",
                 v4=ok(VPS4 + "\n"), captures=None):
        return Fake(network_rules(netstat=netstat, utun=route, resolver_on=resolver_on) + curl_rules(v4=v4),
                    captures if captures is not None else healthy_captures(phys=phys, utun=utun))

    ARGS = ["baseline", "--vps4", VPS4, "--dns", DNSIP]

    def test_parsers(self):
        self.assertEqual(C.tunnel_defaults(NETSTAT_SITTING_SCOPED), ["utun8"])
        self.assertEqual(C.tunnel_defaults(NETSTAT_SITTING_SCOPED, scoped=True), ["utun8"])
        self.assertEqual(C.tunnel_defaults(NETSTAT_SITTING_SCOPED, scoped=False), [])
        self.assertEqual(C.tunnel_defaults(NETSTAT_OFFICIAL, scoped=True), ["utun8"])  # bridge100 is no tunnel
        self.assertEqual(C.tunnel_defaults(NETSTAT_WGEX), [])  # 0/1 and 128/1, no default line
        self.assertEqual(C.tunnel_defaults(NETSTAT_TUNNEL_ONLY, scoped=False), ["utun8"])
        self.assertEqual(C.tunnel_defaults(NETSTAT_TWO_SCOPED, scoped=True), ["utun8", "utun9"])
        self.assertEqual(C.tunnel_defaults(NETSTAT_NO_TUNNEL), [])
        self.assertEqual(C.physical_from_netstat(NETSTAT_SITTING_SCOPED), "en0")
        self.assertEqual(C.physical_from_netstat(NETSTAT_SITTING_ETHERNET), "en7")
        self.assertEqual(C.resolver_interface(scutil_dns(DNSIP, "utun8")), "utun8")
        self.assertIsNone(C.resolver_interface("DNS configuration\n\nresolver #1\n  nameserver[0] : 1.1.1.1\n"))

    def test_baseline_scoped_layout_of_14_nov_passes(self):
        fake = self.baseline()
        text = self.passes(self.ARGS, fake)
        self.assertIn("physical=en0 tunnel=utun8", text)
        self.assertIn("tunnel layout: scoped (9.9.9.9 routes through en0; scoped default and resolver #1 on utun8)", text)
        self.assertEqual(sorted(argv[argv.index("-i") + 1] for argv in fake.spawned), ["en0", "utun8"])
        self.passes(self.ARGS, self.baseline(netstat=NETSTAT_OFFICIAL))

    def test_baseline_scoped_layout_on_ethernet(self):
        text = self.passes(self.ARGS, self.baseline(netstat=NETSTAT_SITTING_ETHERNET, route="en7", phys="en7"))
        self.assertIn("physical=en7 tunnel=utun8", text)

    def test_baseline_unscoped_layout_passes(self):
        text = self.passes(self.ARGS, self.baseline(netstat=NETSTAT_WGEX, route="utun4", resolver_on="utun4",
                                                    utun="utun4"))
        self.assertIn("tunnel layout: unscoped (9.9.9.9 routes through utun4)", text)
        self.assertIn("physical=en0 tunnel=utun4", text)

    def test_baseline_fails_without_a_tunnel(self):
        fake = self.baseline(netstat=NETSTAT_NO_TUNNEL)
        self.fails(self.ARGS, fake, "0 utun(s) hold a scoped default (none): no single tunnel carries the traffic")
        self.assertEqual(fake.spawned, [])
        self.assertEqual(fake.ran("/usr/bin/curl"), [])

    def test_baseline_scoped_layout_failures(self):
        self.fails(self.ARGS, self.baseline(netstat=NETSTAT_TWO_SCOPED), "2 utun(s) hold a scoped default (utun8, utun9)")
        self.fails(self.ARGS, self.baseline(resolver_on="en0"), "resolver #1 is on en0, not on utun8")
        self.fails(self.ARGS, self.baseline(route="en7"), "routes through en7, neither a utun nor the physical interface en0")
        # A stray unscoped utun default beside the scoped one: route get would name it, so en0 here is inconsistent.
        mixed = NETSTAT_SITTING_SCOPED + "default            link#40            UCSg                utun9\n"
        self.fails(self.ARGS, self.baseline(netstat=mixed), "no single tunnel carries the traffic")
        fake = Fake([(["/usr/sbin/scutil", "--dns"], (1, "", "scutil: failed\n"))] + network_rules(
            netstat=NETSTAT_SITTING_SCOPED, utun="en0"), healthy_captures(utun="utun8"))
        self.fails(self.ARGS, fake, "scutil --dns exited 1")

    def test_baseline_scoped_layout_cannot_pass_when_traffic_skips_the_tunnel(self):
        # The routes and resolver look right, but IPv4 leaves with the ISP address, or DNS leaves on en0.
        self.fails(self.ARGS, self.baseline(v4=ok(ISP4 + "\n")), "a leak")
        captures = healthy_captures(utun="utun8")
        captures["en0"]["out"] = tunnel_queries
        captures["utun8"]["out"] = ""
        text = self.fails(self.ARGS, self.baseline(captures=captures), "on the physical interface: a leak")
        self.assertIn("only 0 of 5 lookups reached %s on utun8" % DNSIP, text)

    def test_wgex_checks_reject_the_scoped_layout(self):
        # s3 and s123 support the unscoped layout only; under the scoped one they never take en0 for the tunnel.
        fake = Fake(network_rules(netstat=NETSTAT_SITTING_SCOPED, utun="en0", resolver_on="utun8"),
                    healthy_captures(utun="utun8"))
        self.fails(["s3", "--phys", "en0", "--dns", DNSIP], fake, "routes through en0, not a utun")
        self.assertEqual(fake.spawned, [])
        fake = Fake(network_rules(netstat=NETSTAT_SITTING_SCOPED, utun="en0", resolver_on="utun8") + curl_rules()
                    + [status_rule(active_status())], healthy_captures(utun="utun8"))
        self.fails(["s123", "--vps4", VPS4, "--vps6", "none", "--dns", DNSIP], fake, "routes through en0, not a utun")
        self.assertEqual(fake.spawned, [])
        fake = Fake(network_rules(netstat=NETSTAT_NO_TUNNEL, utun="en0") + curl_rules() + [status_rule(active_status())],
                    healthy_captures())
        self.fails(["s123", "--vps4", VPS4, "--vps6", "none", "--dns", DNSIP], fake, "routes through en0, not a utun")


# ---- watches (round 4 item 6, round 1 item 5) --------------------------------------------------------------------

def timed_probe(script):
    """curl answers from (until_time, rc, out) rows; each probe costs its --max-time when it fails, 0.3 s otherwise."""

    def answer(argv, fake):
        max_time = float(argv[argv.index("--max-time") + 1])
        for until, rc, out in script:
            if fake.t < until:
                fake.t += 0.3 if rc == 0 else max_time
                return (rc, out, "" if rc == 0 else "curl: (%d) failed\n" % rc)
        raise AssertionError("no row for t=%s" % fake.t)

    return answer


class Watches(Base):
    def watch(self, script, window="120"):
        return Fake([(["/usr/bin/curl", "-4"], timed_probe(script))])

    def test_leakwatch_is_bounded_by_elapsed_time(self):
        # The old loop (60 x 3 s curl + 2 s sleep) could run about 300 s; this one stops at 120 s even when every
        # probe times out.
        fake = self.watch([(1e9, 28, "")])
        self.fails(["leakwatch", "--vps4", VPS4], fake, "VPS4 did not return within 120 seconds")
        self.assertLessEqual(fake.t, 121)
        for result in fake.ran("/usr/bin/curl"):
            self.assertLessEqual(int(result.argv[result.argv.index("--max-time") + 1]), 3)

    def test_leakwatch_reports_recovery_within_the_window(self):
        fake = self.watch([(10, 0, VPS4 + "\n"), (40, 7, ""), (1e9, 0, VPS4 + "\n")])
        text = self.passes(["leakwatch", "--vps4", VPS4], fake)
        self.assertRegex(text, r"leakwatch: PASS - recovered: outage from \+\d+s, VPS4 back at \+\d+s, within 120")
        self.assertLessEqual(fake.t, 121)

    def test_leakwatch_no_outage_and_late_recovery(self):
        self.assertIn("no outage seen", self.passes(["leakwatch", "--vps4", VPS4], self.watch([(1e9, 0, VPS4 + "\n")])))
        late = self.watch([(5, 0, VPS4 + "\n"), (1e9, 6, "")])
        self.fails(["leakwatch", "--vps4", VPS4], late, "did not return within 120")

    def test_leakwatch_leak_fails_at_once(self):
        fake = self.watch([(10, 0, VPS4 + "\n"), (1e9, 0, ISP4 + "\n")])
        self.fails(["leakwatch", "--vps4", VPS4], fake, ISP4 + " printed")
        self.assertLess(fake.t, 30)

    def test_leakwatch_reply_after_the_window_fails(self):
        # Round 5 item 3: a probe answering at +121 s passed the 120-second watch.
        def answer(argv, fake):
            if fake.t < 117:
                fake.t += float(argv[argv.index("--max-time") + 1])
                return (28, "", "curl: (28) timed out\n")
            fake.t += 4.1
            return (0, VPS4 + "\n", "")

        fake = Fake([(["/usr/bin/curl", "-4"], answer)])
        text = self.fails(["leakwatch", "--vps4", VPS4], fake, "VPS4 did not return within 120 seconds")
        self.assertIn("(after the window)", text)
        for _, timeout in fake.timeouts:
            self.assertIsNotNone(timeout)
            self.assertLessEqual(timeout, 120)

    def test_phasewatch_reply_after_the_window_fails(self):
        def answer(argv, fake):
            if fake.t < 58:
                return (0, js(status()), "")
            fake.t += 3.1
            return (0, js(active_status()), "")

        fake = Fake([([CLI, "status", "--json"], answer)])
        text = self.fails(["phasewatch", "--until", "active"], fake, "never reached active within 60")
        self.assertIn("after the window, not counted", text)
        self.assertTrue(all(timeout is not None and timeout <= 60 for _, timeout in fake.timeouts))

    def test_phasewatch_hold_reply_after_the_window_fails(self):
        # Round 6 item 1: an `active` snapshot taken before the deadline arrived at +62 s and the hold passed.
        def answer(argv, fake):
            if fake.t < 58:
                return (0, js(status()), "")
            fake.t += 4
            return (0, js(active_status()), "")

        fake = Fake([([CLI, "status", "--json"], answer)])
        text = self.fails(["phasewatch", "--hold", "idle"], fake, "status answered at +62s, after the 60-second window")
        self.assertNotIn("stayed idle", text)
        self.assertTrue(all(timeout is not None and timeout <= 60 for _, timeout in fake.timeouts))

    def test_restart_reply_after_the_window_fails(self):
        doctor = {"daemonReachable": True, "secureInstall": "verified"}

        def answer(argv, fake):
            if fake.t < 28:
                return (1, js({"error": "daemonUnavailable"}), "")
            fake.t += 4
            return (0, js(doctor), "")

        fake = Fake([(["/usr/bin/sudo", "-n", "/bin/launchctl"], ok()), ([CLI, "doctor", "--json"], answer),
                     status_rule(status())])
        self.fails(["restart"], fake, "doctor answered after 30 seconds")
        doctor_timeouts = [timeout for argv, timeout in fake.timeouts if argv[:2] == [CLI, "doctor"]]
        self.assertTrue(doctor_timeouts)
        self.assertTrue(all(timeout is not None and timeout <= 30 for timeout in doctor_timeouts))
        never = Fake([(["/usr/bin/sudo", "-n", "/bin/launchctl"], ok()),
                      ([CLI, "doctor", "--json"], (1, js({"error": "daemonUnavailable"}), "")), status_rule(status())])
        self.fails(["restart"], never, "exited 1")
        self.assertLessEqual(never.t, 31)

    def phase_fake(self, phases):
        docs = [active_status(phase=phase) if phase == "active" else status(phase=phase) for phase in phases]
        return Fake([status_rule(*docs)])

    def test_phasewatch_include_reaches_active(self):
        fake = self.phase_fake(["idle", "preparing", "configuring", "active"])
        self.passes(["phasewatch", "--until", "active"], fake)
        self.fails(["phasewatch", "--until", "active"], self.phase_fake(["idle"]), "never reached active within 60")

    def test_phasewatch_exclude_holds_idle(self):
        fake = self.phase_fake(["idle"])
        text = self.passes(["phasewatch", "--hold", "idle"], fake)
        self.assertIn("stayed idle for 60 seconds", text)
        self.assertGreaterEqual(fake.t, 60)
        self.fails(["phasewatch", "--hold", "idle"], self.phase_fake(["idle", "idle", "preparing"]),
                   "phase=preparing")
        bad = Fake([status_rule(status(), {"error": "daemonUnavailable"})])
        bad.rules[0][1][1] = (1, js({"error": "daemonUnavailable"}), "")
        self.fails(["phasewatch", "--hold", "idle"], bad, "exited 1")


# ---- E1 to E4, C1, S7, S8 ----------------------------------------------------------------------------------------

class EarlyChecks(Base):
    def test_keylog(self):
        rule = ["/usr/bin/log", "show", "--start", "2026-11-20 10:00:00"]
        self.passes(["keylog", "--since", "2026-11-20 10:00:00"], Fake([(rule, ok(LOG_CLEAN))]))
        self.passes(["keylog", "--since", "2026-11-20 10:00:00"], Fake([(rule, ok(LOG_HEADER))]))
        # Round 5 item 2: log(1) can print its filter, and the skipped-levels note, before the header.
        self.passes(["keylog", "--since", "2026-11-20 10:00:00"], Fake([(rule, ok(LOG_PREAMBLE + LOG_CLEAN))]))
        self.fails(["keylog", "--since", "2026-11-20 10:00:00"], Fake([(rule, ok(LOG_PREAMBLE + LOG_DENIED))]),
                   "1 line(s) name CSSMERR_CSP_OPERATION_AUTH_DENIED")
        self.fails(["keylog", "--since", "2026-11-20 10:00:00"], Fake([(rule, ok(LOG_PREAMBLE))]), "no compact header")
        self.fails(["keylog", "--since", "2026-11-20 10:00:00"], Fake([(rule, (64, LOG_PREAMBLE, "log: bad\n"))]),
                   "log show exited 64")
        self.fails(["keylog", "--since", "2026-11-20 10:00:00"],
                   Fake([(rule, ok("Something else entirely\n" + LOG_CLEAN))]), "no compact header")
        self.fails(["keylog", "--since", "2026-11-20 10:00:00"], Fake([(rule, ok(LOG_DENIED))]),
                   "1 line(s) name CSSMERR_CSP_OPERATION_AUTH_DENIED")
        for signal in ("Wrapping key is unavailable", "secretsUnavailable"):
            self.fails(["keylog", "--since", "2026-11-20 10:00:00"],
                       Fake([(rule, ok(LOG_CLEAN + "2026-11-20 10:00:05.000 E  WGEXDaemon[412:1a2b] %s\n" % signal))]),
                       signal)
        failed = (0, "", "log: Failed conversion of '2026-11-20 10:00:00' using format '%Y-%m-%d %H:%M:%S'\n")
        self.fails(["keylog", "--since", "2026-11-20 10:00:00"], Fake([(rule, failed)]), "no compact header")
        self.fails(["keylog", "--since", "2026-11-20 10:00:00"], Fake([(rule, (64, "", "log: bad\n"))]),
                   "log show exited 64")
        self.fails(["keylog", "--since", ""], Fake(), "--since must be")

    def recorded(self, definition):
        path = os.path.join(self.tmp.name, "verdict.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"row": "AUTH-REAL", "rightDefinition": definition}, handle)
        return path

    def test_e3_compares_policy_fields(self):
        lab = {"class": "rule", "comment": "WGEX administrator authorisation; authenticate-admin-nonshared, not "
               "shared, 30 seconds", "created": 814991105.489426, "identifier": "com.magrathean.WGEXApp.dev.daemon",
               "modified": 815724327.901619, "requirement": "cdhash H\"" + "0" * 40 + "\"",
               "rule": ["authenticate-admin-nonshared"], "version": 0}
        read = ["/usr/bin/security", "authorizationdb", "read", "com.magrathean.WGEXApp.manage-protection"]
        good = Fake([(read, ok(RIGHT_PLIST % "authenticate-admin-nonshared", "YES (0)\n"))])
        self.assertIn("equal", self.passes(["e3", "--recorded", self.recorded(lab)], good))
        as_text = Fake([(read, ok(RIGHT_PLIST % "authenticate-admin-nonshared", "YES (0)\n"))])
        self.passes(["e3", "--recorded", self.recorded(RIGHT_PLIST % "authenticate-admin-nonshared")], as_text)
        loose = Fake([(read, ok(RIGHT_PLIST % "authenticate-session-owner-or-admin", "YES (0)\n"))])
        self.fails(["e3", "--recorded", self.recorded(lab)], loose, "differs from AUTH-REAL in rule")
        extra = dict(lab, shared=True)
        self.fails(["e3", "--recorded", self.recorded(extra)], Fake([(read, ok(RIGHT_PLIST % "authenticate-admin-"
                                                                                          "nonshared"))]), "shared")
        # DEC-027: comment and version are printed for information; class, rule, shared and timeout are compared.
        other_comment = dict(lab, comment="older wording", version=1)
        text = self.passes(["e3", "--recorded", self.recorded(other_comment)],
                           Fake([(read, ok(RIGHT_PLIST % "authenticate-admin-nonshared"))]))
        self.assertIn("info comment: this Mac", text)
        self.assertIn("info identifier: this Mac com.magrathean.WGEXApp.daemon; AUTH-REAL "
                      "com.magrathean.WGEXApp.dev.daemon", text)
        self.fails(["e3", "--recorded", self.recorded(dict(lab, timeout=30))],
                   Fake([(read, ok(RIGHT_PLIST % "authenticate-admin-nonshared"))]), "differs from AUTH-REAL in timeout")
        self.fails(["e3", "--recorded", self.recorded(dict(lab, **{"class": "user"}))],
                   Fake([(read, ok(RIGHT_PLIST % "authenticate-admin-nonshared"))]), "differs from AUTH-REAL in class")
        # Round 4 item 2: the `security` producer's exit was hidden by its pipeline.
        missing = Fake([(read, (255, "", "NO (-60005)\n"))])
        self.fails(["e3", "--recorded", self.recorded(lab)], missing, "security authorizationdb read exited 255")
        self.fails(["e3", "--recorded", self.recorded(lab)], Fake([(read, ok("garbage"))]), "not a dictionary")
        self.fails(["e3", "--recorded", os.path.join(self.tmp.name, "absent.json")], Fake(), "cannot read")

    def profiles(self, docs):
        folder = os.path.join(self.tmp.name, "Application Support", "WGEX", "profiles")
        os.makedirs(folder, exist_ok=True)
        for name, doc in docs.items():
            with open(os.path.join(folder, name), "w", encoding="utf-8") as handle:
                handle.write(doc if isinstance(doc, str) else json.dumps(doc))
        return folder

    def test_profile_selection_is_path_safe(self):
        # Round 1 item 1: `xargs basename` split the "Application Support" path.
        def doc(uuid, name, key="TUFDUFVCS0VZ"):
            return {"schemaVersion": 1, "profile": {"id": uuid, "name": name, "interface": {"publicKey": key}}}

        folder = self.profiles({PROFILE + ".json": doc(PROFILE, "WGEX dedicated"), OTHER + ".json": doc(OTHER, "home"),
                                "broken.json": "{", "notes.txt": "x"})
        text = self.passes(["profile", "--dir", folder, "--pubkey", "TUFDUFVCS0VZ"], Fake())
        self.assertIn("PROFILE=" + PROFILE, text)
        self.fails(["profile", "--dir", folder, "--pubkey", "T1RIRVI="], Fake(), "saved public key is not")
        self.profiles({OTHER + ".json": doc(OTHER, "WGEX dedicated")})
        self.fails(["profile", "--dir", folder, "--pubkey", "TUFDUFVCS0VZ"], Fake(), "2 profiles")
        empty = os.path.join(self.tmp.name, "empty dir")
        os.makedirs(empty)
        self.fails(["profile", "--dir", empty, "--pubkey", "TUFDUFVCS0VZ"], Fake(), "0 profiles")
        odd = os.path.join(self.tmp.name, "odd")
        os.makedirs(odd)
        with open(os.path.join(odd, "dedicated.json"), "w", encoding="utf-8") as handle:
            json.dump(doc(PROFILE, "WGEX dedicated"), handle)
        self.fails(["profile", "--dir", odd, "--pubkey", "TUFDUFVCS0VZ"], Fake(), "not the profile's UUID")
        self.fails(["profile", "--dir", os.path.join(self.tmp.name, "absent"), "--pubkey", "x"], Fake(), "cannot list")

    def test_retained_profile_can_be_rechecked_after_repair(self):
        doc = {"profile": {"id": PROFILE, "name": "WGEX dedicated", "interface": {"publicKey": "old-key"}}}
        folder = self.profiles({PROFILE + ".json": doc})
        argv = ["profile", "--dir", folder, "--name", "WGEX dedicated", "--pubkey", "vps-confirmed-key"]
        self.fails(argv, Fake(), "the saved public key is not the key added on the VPS")
        doc["profile"]["interface"]["publicKey"] = "vps-confirmed-key"
        self.profiles({PROFILE + ".json": doc})
        self.assertIn("matches=1", self.passes(argv, Fake()))
        duplicate = {"profile": dict(doc["profile"], id=OTHER)}
        self.profiles({OTHER + ".json": duplicate})
        self.fails(argv, Fake(), "2 profiles are named 'WGEX dedicated'")
        duplicate["profile"]["name"] = "other profile"
        self.profiles({OTHER + ".json": duplicate})
        self.assertIn("PROFILE=" + PROFILE, self.passes(argv, Fake()))

    def test_c1(self):
        def fake(nc=ok(NC_DISCONNECTED), pgrep=(1, "", ""), route="en0", netstat=ok(NETSTAT_NO_TUNNEL)):
            return Fake([(["/usr/sbin/scutil", "--nc"], nc), (["/usr/bin/pgrep"], pgrep),
                         (["/sbin/route"], ok(route_get(route))), (["/usr/sbin/netstat"], netstat)])

        self.assertIn("tunnel defaults: none", self.passes(["c1", "--phys", "en0"], fake()))
        # M04-T11: either layout of a tunnel still up fails; the scoped one leaves `route get` on en0.
        self.fails(["c1", "--phys", "en0"], fake(netstat=ok(NETSTAT_SITTING_SCOPED)),
                   "a tunnel still holds a default route: utun8")
        self.fails(["c1", "--phys", "en0"], fake(netstat=ok(NETSTAT_OFFICIAL)), "default route: utun8")
        self.fails(["c1", "--phys", "en0"], fake(route="utun4", netstat=ok(NETSTAT_WGEX)),
                   "routes through utun4, not en0")  # 0/1 and 128/1: route get names the utun
        self.fails(["c1", "--phys", "en0"], fake(netstat=(1, "", "netstat: failed\n")), "netstat exited 1")
        self.fails(["c1", "--phys", "en0"], fake(nc=ok(NC_ONE_CONNECTED)), "still not disconnected")
        self.fails(["c1", "--phys", "en0"], fake(nc=ok(NC_EMPTY)), "no official WireGuard configuration")
        self.fails(["c1", "--phys", "en0"], fake(nc=(1, "", "")), "scutil --nc list exited 1")
        self.fails(["c1", "--phys", "en0"], fake(pgrep=ok("812\n")), "still running (pid 812)")
        self.fails(["c1", "--phys", "en0"], fake(pgrep=(3, "", "pgrep: error\n")), "pgrep exited 3")
        self.fails(["c1", "--phys", "en0"], fake(route="utun8"), "routes through utun8, not en0")

    def test_s8(self):
        def fake(nc=NC_DISCONNECTED, doc=None, pgrep=(1, "", "")):
            return Fake([(["/usr/sbin/scutil", "--nc"], ok(nc)), (["/usr/bin/pgrep", "-x", "WireGuard"], pgrep),
                         status_rule(doc or active_status())] + curl_rules())

        self.passes(["s8", "--profile", PROFILE, "--vps4", VPS4], fake())
        # VER-M04-SITTING: S8 rechecks that the official app is still quit (M04 Definition of Done).
        self.fails(["s8", "--profile", PROFILE, "--vps4", VPS4], fake(pgrep=ok("812\n")), "still running (pid 812)")
        self.fails(["s8", "--profile", PROFILE, "--vps4", VPS4], fake(pgrep=(3, "", "pgrep: error\n")),
                   "pgrep exited 3")
        self.fails(["s8", "--profile", PROFILE, "--vps4", VPS4], fake(nc=NC_EMPTY), "configurations are gone")
        self.fails(["s8", "--profile", PROFILE, "--vps4", VPS4], fake(doc=active_status(activeProfileID=OTHER)),
                   "active profile is not")
        self.fails(["s8", "--profile", PROFILE, "--vps4", VPS4],
                   fake(doc=active_status(cutover={"state": "rolledBack", "reason": "aborted"})), "not confirmed")

    def test_airdrop_receipt(self):
        # Round 1 item 6 and round 4 item 2: the receipt is checked on the Mac, and a failed listing fails.
        downloads = os.path.join(self.tmp.name, "Downloads")
        os.makedirs(downloads)
        with open(os.path.join(downloads, "old.pdf"), "w", encoding="utf-8") as handle:
            handle.write("x")
        mark = os.path.join(self.tmp.name, "s7.mark")
        argv = ["--mark", mark, "--downloads", downloads]
        self.passes(["airdrop", "mark"] + argv, Fake())
        self.fails(["airdrop", "check"] + argv, Fake(), "no new file")
        photo = os.path.join(downloads, "IMG_0001.HEIC")
        with open(photo, "w", encoding="utf-8") as handle:
            handle.write("x")
        os.utime(photo, (1000, 1000))  # AirDrop can keep the photo's original date
        text = self.passes(["airdrop", "check"] + argv, Fake())
        self.assertIn("received: IMG_0001.HEIC", text)
        self.assertNotIn("old.pdf", text)
        self.fails(["airdrop", "check", "--mark", mark, "--downloads", os.path.join(self.tmp.name, "nope")], Fake(),
                   "cannot read")
        self.fails(["airdrop", "check", "--mark", os.path.join(self.tmp.name, "nomark"), "--downloads", downloads],
                   Fake(), "cannot read")

    def test_addresses(self):
        text = self.passes(["addresses"], Fake(curl_rules(v6=ok(VPS6 + "\n"))))
        self.assertIn("VPS4=" + VPS4, text)
        self.assertIn("IPv6 seen: " + VPS6, text)
        self.assertIn("IPv6 seen: none (exit 7)", self.passes(["addresses"], Fake(curl_rules())))
        self.fails(["addresses"], Fake(curl_rules(v4=(6, "", "curl: (6) Could not resolve host\n"))), "exit 6")
        self.fails(["addresses"], Fake(curl_rules(v4=ok("<html>\n"))), "no IPv4 address")

    def test_protocol(self):
        folder = os.path.join(self.tmp.name, "rc", os.path.dirname(C.PROTOCOL_FILE))
        os.makedirs(folder)
        path = os.path.join(self.tmp.name, "rc", C.PROTOCOL_FILE)
        for text, good in (("    public static let currentProtocolVersion = 8\n", True),
                           ("    public static let currentProtocolVersion = 7\n", False),
                           ("    public static let currentProtocolVersion = 80\n", False)):
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)
            code, out, _ = self.check(["protocol", "--worktree", os.path.join(self.tmp.name, "rc")], Fake())
            self.assertEqual(code, 0 if good else 1, out)
        self.fails(["protocol", "--worktree", os.path.join(self.tmp.name, "absent")], Fake(), "cannot read")

    def test_doctor(self):
        rule = [CLI, "doctor", "--json"]
        good = {"app": "x", "cli": "y", "daemon": "z", "daemonReachable": True, "secureInstall": "verified",
                "serviceState": "enabled"}
        self.passes(["doctor"], Fake([(rule, ok(js(good)))]))
        self.fails(["doctor"], Fake([(rule, (1, js(dict(good, daemonReachable=False, secureInstall="unknown",
                                                         error="daemonUnavailable")), ""))]), "exited 1")
        self.fails(["doctor"], Fake([(rule, ok(js(dict(good, secureInstall="needsAttention(wrappingKeyUnavailable)"))))]),
                   "not verified")


class BuildAndInstall(Base):
    def setUp(self):
        super().setUp()
        self.home = os.path.join(self.tmp.name, "home")
        os.makedirs(self.home)
        patcher = mock.patch.dict(os.environ, {"CLEAN_DEV_MODE": "external", "HOME": self.home})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.rc = os.path.join(self.tmp.name, "M04-rc9")

    def e1_rules(self, **over):
        sha = "c0ffee" * 6 + "abcd"
        rules = {
            "tag": ok(sha + "\n"), "add": ok(), "head": ok(sha + "\n"), "engine": ok(), "build": ok(),
            "compare": ok("build-own-mac: designated requirements match and all CDHashes changed\n"),
            "identity": ok("  1) %s \"Apple Development: Test Person (ABCDE12345)\"\n     1 valid identities found\n"
                           % ("AA" * 20)),
        }
        rules.update(over)
        return Fake([
            (["/usr/bin/git", "-C", os.path.expanduser("~/src/wgex"), "rev-parse"], rules["tag"]),
            (["/usr/bin/git", "-C", os.path.expanduser("~/src/wgex"), "worktree"], rules["add"]),
            (["/usr/bin/git", "-C", self.rc, "rev-parse"], rules["head"]),
            (["just", "engine"], rules["engine"]),
            (["just", "build-own-mac", "compare"], rules["compare"]),
            (["just", "build-own-mac"], rules["build"]),
            (["/usr/bin/security", "find-identity"], rules["identity"]),
            (["/usr/bin/security", "find-certificate"], ok("")),
        ])

    def test_e1_stops_on_each_failed_step(self):
        # Round 4 item 2: the worktree and build commands' exits were unchecked.
        cases = [
            ({"tag": (128, "", "fatal: ambiguous argument 'M04-rc9^{commit}'\n")}, "tag M04-rc9 not found; the lead tags it"),
            ({"add": (128, "", "fatal: '/x' already exists\n")}, "git worktree add exited 128"),
            ({"head": ok("deadbeef\n")}, "is not at M04-rc9"),
            ({"engine": (1, "", "")}, "just engine exited 1"),
            ({"identity": (1, "", "security: SecKeychainSearchCopyNext\n")}, "security find-identity exited 1"),
            ({}, "found 0"),
        ]
        for over, needle in cases:
            with self.subTest(needle=needle):
                if over.keys() & {"identity"} or not over:
                    self.pin()
                else:
                    shutil.rmtree(self.rc, ignore_errors=True)
                fake = self.e1_rules(**over)
                self.fails(["e1", "--worktree", self.rc], fake, needle)
                self.assertEqual([r for r in fake.log if r.argv[:2] == ["just", "build-own-mac"]], [])

    def test_e1_builds_rc9_and_retries_with_new_attempt_names(self):
        self.pin()
        output = Path(self.home) / ".wgex-own-mac" / "out"
        for attempt in ("A", "C"):
            (output / attempt).mkdir(parents=True)
            (output / attempt / "app.dr").write_text(C.WWDR_MARKER, encoding="utf-8")
        identity = ("AA" * 20, "Apple Development: Test (X)")
        with mock.patch.object(C, "select_identity", return_value=identity):
            failed = self.e1_rules(build=(77, "", ""))
            self.fails(["e1", "--worktree", self.rc, "--attempts", "A", "B"], failed,
                       "rerun with new attempt names")
            self.assertFalse(any(r.argv[:3] == ["just", "build-own-mac", "B"] for r in failed.log))
            retried = self.e1_rules()
            retried.rules.append((("/usr/bin/codesign", "-dv"),
                                  (0, "", codesign_text(authority=identity[1]))))
            self.passes(["e1", "--worktree", self.rc, "--attempts", "C", "D"], retried)
            self.assertEqual(retried.log[0].argv[-1], "M04-rc9^{commit}")
            self.assertEqual([r.argv for r in retried.log if r.argv[:2] == ["just", "build-own-mac"]],
                             [["just", "build-own-mac", "C"], ["just", "build-own-mac", "D"],
                              ["just", "build-own-mac", "compare", "C", "D"]])

    def pin(self, text="WGEX_OWN_MAC_LEAF = Apple Development: Test (X)\n"):
        folder = os.path.join(self.rc, "Config")
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, "Local.xcconfig"), "w", encoding="utf-8") as handle:
            handle.write("WGEX_TEAM = ABCDE12345\n" + text)

    def test_e1_pinned_leaf(self):
        # VER-M04-SITTING: a leaf the build script does not pin fails before any build, not inside it.
        self.pin()
        cases = [
            (("AA" * 20, "Apple Development: Other Name (ZZZZZ99999)"), "accepts only Apple Development: Test (X)"),
        ]
        for identity, needle in cases:
            with mock.patch.object(C, "select_identity", return_value=identity):
                fake = self.e1_rules()
                self.fails(["e1", "--worktree", self.rc], fake, needle)
                self.assertEqual([r for r in fake.log if r.argv[:2] == ["just", "build-own-mac"]], [])
        with mock.patch.object(C, "select_identity", return_value=("AA" * 20, "Apple Development: Test (X)")):
            for text, needle in (("", "defines 0 WGEX_OWN_MAC_LEAF values"),
                                 ("WGEX_OWN_MAC_LEAF = Apple Development: A (1)\nWGEX_OWN_MAC_LEAF = Apple Development: B (2)\n",
                                  "defines 2 WGEX_OWN_MAC_LEAF values")):
                self.pin(text)
                fake = self.e1_rules()
                self.fails(["e1", "--worktree", self.rc], fake, needle)
                self.assertEqual([r for r in fake.log if r.argv[:2] == ["just", "build-own-mac"]], [])
            os.remove(os.path.join(self.rc, C.LOCAL_CONFIG))
            self.fails(["e1", "--worktree", self.rc], self.e1_rules(), "cannot read")

    def test_e1_setting_names_match_the_build_script(self):
        # The helper reads the same Local.xcconfig keys the candidate's build script requires.
        with open(ROOT / "Config/Scripts/build-own-mac.sh", encoding="utf-8") as handle:
            script = handle.read()
        for name in ("WGEX_TEAM", "WGEX_OWN_MAC_LEAF", "WGEX_OWN_MAC_PROFILE"):
            self.assertIn(name, script)
        self.assertTrue((ROOT / "Config/Local.xcconfig.example").is_file())

    def test_e1_build_failures(self):
        self.pin()
        with mock.patch.object(C, "select_identity", return_value=("AA" * 20, "Apple Development: Test (X)")):
            self.fails(["e1", "--worktree", self.rc], self.e1_rules(build=(77, "", "")), "needs the maintainer at the keychain")
            self.fails(["e1", "--worktree", self.rc], self.e1_rules(build=(1, "", "")), "build-own-mac A exited 1")
            self.fails(["e1", "--worktree", self.rc], self.e1_rules(compare=(1, "", "")), "compare exited 1")
            self.fails(["e1", "--worktree", self.rc], self.e1_rules(compare=ok("something else\n")),
                       "did not report matching")

    def test_e1_not_external(self):
        with mock.patch.dict(os.environ, {"CLEAN_DEV_MODE": "internal"}):
            self.fails(["e1", "--worktree", self.rc], Fake(), "not external")

    def install(self, ditto=ok(), installed_hash="ab" * 20, exists=False, loaded=(113, "", "Could not find service")):
        target_exists = mock.patch.object(C.os.path, "lexists", return_value=exists)
        target_exists.start()
        self.addCleanup(target_exists.stop)
        return Fake([
            (["/usr/bin/sudo", "-n", "/bin/launchctl", "print", C.DAEMON_SERVICE], loaded),
            (["/usr/bin/codesign", "-dv", "--verbose=4", "/build/A/WGEX.app"], (0, "", codesign_text())),
            (["/usr/bin/sudo", "-n", "/usr/bin/ditto"], ditto),
            (["/usr/bin/codesign", "--verify"], ok()),
            (["/usr/bin/codesign", "-dv", "--verbose=4", "/Applications/WGEX.app"],
             (0, "", codesign_text(cdhash=installed_hash))),
        ])

    def test_install(self):
        # Round 4 item 4: a cached sudo ticket is fine; the helper uses sudo -n and never asks for a password.
        self.passes(["install", "--app", "/build/A/WGEX.app"], self.install())
        self.fails(["install", "--app", "/build/A/WGEX.app"], self.install(exists=True), "TARGET-EXISTS")
        # VER-M04-SITTING (macOS 27): a registered older WGEX is uninstalled first, never replaced in place.
        for loaded, needle in ((ok("system/com.magrathean.WGEXApp.daemon = {\n"), "an older WGEX is registered"),
                               ((1, "", "sudo: a password is required\n"), "launchctl print exited 1")):
            fake = self.install(loaded=loaded)
            self.fails(["install", "--app", "/build/A/WGEX.app"], fake, needle)
            self.assertEqual([r for r in fake.log if r.argv[:3] == ["/usr/bin/sudo", "-n", "/usr/bin/ditto"]], [])
        self.fails(["install", "--app", "/build/A/WGEX.app"], self.install(ditto=(1, "", "sudo: a password is "
                                                                                       "required\n")),
                   "sudo ditto exited 1")
        self.fails(["install", "--app", "/build/A/WGEX.app"], self.install(installed_hash="cd" * 20),
                   "not build A's")

    def test_restart(self):
        doctor = {"daemonReachable": True, "secureInstall": "verified"}
        rules = [(["/usr/bin/sudo", "-n", "/bin/launchctl"], ok()),
                 ([CLI, "doctor", "--json"], [(1, js({"error": "daemonUnavailable"}), ""), ok(js(doctor))]),
                 status_rule(status())]
        self.passes(["restart"], Fake(rules))
        rules[0] = (["/usr/bin/sudo", "-n", "/bin/launchctl"], (1, "", "sudo: a password is required\n"))
        self.fails(["restart"], Fake(rules), "kickstart exited 1")
        mismatch = [(["/usr/bin/sudo", "-n", "/bin/launchctl"], ok()), ([CLI, "doctor", "--json"], ok(js(doctor))),
                    status_rule({"error": "protocolMismatch"}, rc=17)]
        self.fails(["restart"], Fake(mismatch), "exited 17")


class Runner(unittest.TestCase):
    def test_every_command_is_recorded_with_its_exit(self):
        out = io.StringIO()
        runner = C.Runner(out)
        self.assertEqual(runner.run(["/usr/bin/false"]).rc, 1)
        self.assertEqual(runner.run(["/nonexistent/tool"]).rc, 127)
        self.assertEqual([r.rc for r in runner.log], [1, 127])
        self.assertIn("[exit 1] /usr/bin/false", out.getvalue())

    def test_an_unexpected_exception_still_ends_in_a_fail_verdict(self):
        out = io.StringIO()
        with mock.patch.dict(C.COMMANDS, {"doctor": mock.Mock(side_effect=TypeError("boom"))}):
            self.assertEqual(C.main(["doctor"], runner=Fake(), out=out), 1)
        self.assertRegex(out.getvalue(), r"(?m)^doctor: FAIL - internal error TypeError: boom$")

    def test_verdict_line_and_exit_codes(self):
        out = io.StringIO()
        self.assertEqual(C.main(["ready"], runner=Fake(), out=out), 0)
        self.assertRegex(out.getvalue(), r"(?m)^ready: PASS - ")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(C.main(["nosuch"], runner=Fake(), out=io.StringIO()), 2)
            self.assertEqual(C.main([], runner=Fake(), out=io.StringIO()), 2)


# ---- M04-T12 address probe with fallbacks (DEC-079) ----------------------------------------------------------------

CHALLENGE = ("<!DOCTYPE html><html lang=\"en-US\"><head><title>Just a moment...</title></head>\n"
             "<body><noscript>Enable JavaScript and cookies to continue</noscript></body></html>\n")
ME, IDENT, IPME = C.PROBE_URLS


def http(body, status="200"):
    """curl exit 0 with the body and the --write-out status line the probe asks for."""
    return (0, body + "\n" + C.HTTP_MARK + status + "\n", "")


DNS_FAIL = (6, "\n" + C.HTTP_MARK + "000\n", "curl: (6) Could not resolve host: ifconfig.me\n")
NO_ROUTE = (7, "\n" + C.HTTP_MARK + "000\n", "curl: (7) Failed to connect: No route to host\n")


def by_url(answers, cost=0.2):
    """curl answers per URL (the probe's last argument); a missing URL is an unexpected command."""

    def answer(argv, fake):
        fake.t += cost
        return answers[argv[-1]]

    return answer


def probe_fake(v4=None, v6=None):
    rules = []
    if v4 is not None:
        rules.append((["/usr/bin/curl", "-4"], by_url(v4)))
    if v6 is not None:
        rules.append((["/usr/bin/curl", "-6"], by_url(v6)))
    return Fake(rules)


class ProbeFallbacks(Base):
    def urls(self, fake, family):
        return [result.argv[-1] for result in fake.ran("/usr/bin/curl") if result.argv[1] == "-%d" % family]

    def caller_fake(self, command, answers):
        rules = [(["/usr/bin/curl", "-4"], by_url(answers)),
                 (["/usr/bin/curl", "-6"], by_url({u: NO_ROUTE for u in C.PROBE_URLS}))]
        if command == "s123":
            rules += network_rules() + [status_rule(active_status())]
        elif command == "s8":
            rules += [(["/usr/sbin/scutil", "--nc"], ok(NC_DISCONNECTED)),
                      (["/usr/bin/pgrep", "-x", "WireGuard"], (1, "", "")), status_rule(active_status())]
        return Fake(rules, healthy_captures() if command == "s123" else None)

    def test_order_and_command(self):
        self.assertEqual(C.PROBE_URLS, ("https://ifconfig.me/ip", "https://ident.me", "https://ip.me"))
        fake = probe_fake(v4={ME: http(VPS4)})
        self.passes(["s1", "--vps4", VPS4], fake)
        self.assertEqual(self.urls(fake, 4), [ME])
        argv = fake.ran("/usr/bin/curl")[0].argv
        self.assertEqual(argv[:5], ["/usr/bin/curl", "-4", "-sS", "--max-time", "10"])
        self.assertIn("--write-out", argv)

    def test_challenge_page_is_not_an_address(self):
        # 15 Nov: the Cloudflare challenge page; HTML is never an address and never a leak.
        fake = probe_fake(v4={ME: http(CHALLENGE), IDENT: http(VPS4)})
        self.passes(["s1", "--vps4", VPS4], fake)
        self.assertEqual(self.urls(fake, 4), [ME, IDENT])
        text = self.fails(["s1", "--vps4", VPS4], probe_fake(v4={u: http(CHALLENGE) for u in C.PROBE_URLS}),
                          "could not measure the IPv4 address")
        self.assertNotIn("a leak", text)
        self.assertIn("body '<!DOCTYPE html>", text)

    def test_http_403_is_not_an_address(self):
        fake = probe_fake(v4={ME: http(CHALLENGE, "403"), IDENT: http(VPS4)})
        self.passes(["s1", "--vps4", VPS4], fake)
        # Even a 403 whose body looks like an address is no reply to take.
        text = self.fails(["s1", "--vps4", VPS4], probe_fake(v4={u: http(ISP4, "403") for u in C.PROBE_URLS}),
                          "could not measure")
        self.assertIn("HTTP 403", text)
        self.assertNotIn("a leak", text)

    def test_dns_failure_then_success(self):
        fake = probe_fake(v4={ME: DNS_FAIL, IDENT: http(VPS4)})
        self.assertIn("S1 printed '%s', exit=0" % VPS4, self.passes(["s1", "--vps4", VPS4], fake))
        self.assertEqual(self.urls(fake, 4), [ME, IDENT])
        fake = probe_fake(v4={ME: DNS_FAIL, IDENT: DNS_FAIL, IPME: http(ISP4)})
        self.fails(["s1", "--vps4", VPS4], fake, "S1 printed %s, not VPS4 %s: a leak" % (ISP4, VPS4))

    def test_all_failing_is_could_not_measure_in_every_caller(self):
        down = {ME: DNS_FAIL, IDENT: http(CHALLENGE, "403"), IPME: (28, "", "curl: (28) timed out\n")}
        for argv in (["s1", "--vps4", VPS4], ["direct", "--vps4", VPS4], ["addresses"]):
            text = self.fails(argv, probe_fake(v4=dict(down), v6={u: NO_ROUTE for u in C.PROBE_URLS}),
                              "could not measure the IPv4 address")
            self.assertNotIn("a leak", text)
            for url in C.PROBE_URLS:
                self.assertIn(url + " exit", text)
            self.assertIn("exit 6", text)
            self.assertIn("HTTP 403", text)
            self.assertIn("exit 28", text)
        self.assertNotIn("VPS4=", self.fails(["addresses"], probe_fake(v4=dict(down), v6={u: NO_ROUTE for u in
                                                                                             C.PROBE_URLS}), "FAIL"))
        text = self.fails(["leakwatch", "--vps4", VPS4], probe_fake(v4=dict(down)), "VPS4 did not return within 120")
        self.assertNotIn("a leak", text)
        self.assertIn("could not measure", text)

    def test_s123_and_s8_callers_use_the_probe(self):
        # s123 reaches S1 through s1_into; a challenge page there is "could not measure", not a leak.
        fake = Fake(network_rules() + [(["/usr/bin/curl", "-4"], by_url({u: http(CHALLENGE) for u in C.PROBE_URLS})),
                                       (["/usr/bin/curl", "-6"], by_url({u: NO_ROUTE for u in C.PROBE_URLS}))]
                    + [status_rule(active_status())], healthy_captures())
        text = self.fails(["s123", "--vps4", VPS4, "--vps6", "none", "--dns", DNSIP], fake, "could not measure")
        self.assertNotIn("a leak", text)

    def test_failed_transfers_are_not_measurements_in_any_ipv4_caller(self):
        # One complete leakwatch probe isolates transfer handling from a final sample's shrinking time budget.
        callers = (["s1", "--vps4", VPS4], ["leakwatch", "--vps4", VPS4, "--window", "3"],
                   ["s123", "--vps4", VPS4, "--vps6", "none", "--dns", DNSIP],
                   ["direct", "--vps4", VPS4], ["s8", "--profile", PROFILE, "--vps4", VPS4], ["addresses"])
        for rc in (18, 28):
            for body in (VPS4, ISP4):
                for argv in callers:
                    with self.subTest(rc=rc, body=body, command=argv[0]):
                        failed = (rc, http(body)[1], "curl: transfer failed\n")
                        fake = self.caller_fake(argv[0], {u: failed for u in C.PROBE_URLS})
                        text = self.fails(argv, fake, "could not measure the IPv4 address")
                        self.assertNotIn("a leak", text)
                        self.assertNotIn("VPS4=", text)
                        for url in C.PROBE_URLS:
                            self.assertIn("%s exit %d HTTP 200 body '%s'" % (url, rc, body), text)
                        # Failed bodies neither certify the expected address nor hide later measurements.
                        address = ISP4 if argv[0] == "direct" else VPS4
                        fake = self.caller_fake(argv[0], {ME: failed, IDENT: failed, IPME: http(address)})
                        self.passes(argv, fake)
                        self.assertEqual(self.urls(fake, 4)[:3], list(C.PROBE_URLS))

    def test_leakwatch_challenge_is_an_outage_not_a_leak(self):
        def answer(argv, fake):
            fake.t += 0.2
            if fake.t < 20:
                return http(CHALLENGE, "403")
            return http(VPS4)

        text = self.passes(["leakwatch", "--vps4", VPS4], Fake([(["/usr/bin/curl", "-4"], answer)]))
        self.assertRegex(text, r"leakwatch: PASS - recovered: outage from \+\d+s, VPS4 back at \+\d+s")
        self.assertIn("FAIL exit=0 could not measure", text)

    def test_multi_line_reply_is_not_an_address(self):
        fake = probe_fake(v4={ME: http(VPS4 + "\n" + ISP4), IDENT: http("ip=" + ISP4), IPME: http(VPS4)})
        self.passes(["s1", "--vps4", VPS4], fake)
        self.assertEqual(self.urls(fake, 4), [ME, IDENT, IPME])
        self.fails(["direct", "--vps4", VPS4], probe_fake(v4={u: http(ISP4 + "\n" + ISP4) for u in C.PROBE_URLS}),
                   "could not measure")

    def test_ipv6_reply_to_an_ipv4_request_is_not_an_address(self):
        fake = probe_fake(v4={ME: http(VPS6), IDENT: http(VPS4)})
        self.passes(["s1", "--vps4", VPS4], fake)
        text = self.fails(["s1", "--vps4", VPS4], probe_fake(v4={u: http(VPS6) for u in C.PROBE_URLS}),
                          "could not measure")
        self.assertNotIn("a leak", text)
        # and the reverse: an IPv4 reply to an IPv6 request is no IPv6 address
        self.fails(["s2", "--vps6", VPS6], probe_fake(v6={u: http(VPS4) for u in C.PROBE_URLS}), "could not measure")

    def test_s2_without_an_ipv6_reply_passes(self):
        self.passes(["s2", "--vps6", "none"], probe_fake(v6={u: NO_ROUTE for u in C.PROBE_URLS}))
        self.passes(["s2", "--vps6", "none"], probe_fake(v6={ME: DNS_FAIL, IDENT: NO_ROUTE,
                                                             IPME: (28, "", "curl: (28) timed out\n")}))

    def test_s2_with_an_ipv6_reply_fails(self):
        for url in C.PROBE_URLS:
            answers = {u: NO_ROUTE for u in C.PROBE_URLS}
            answers[url] = http("2001:db8:99::1")
            self.fails(["s2", "--vps6", "none"], probe_fake(v6=answers), "2001:db8:99::1 although IPv6 must be blocked")
        # any reply over IPv6 at all (exit 0) is IPv6 reaching out, address or not
        answers = {u: NO_ROUTE for u in C.PROBE_URLS}
        answers[IDENT] = http(CHALLENGE, "403")
        self.fails(["s2", "--vps6", "none"], probe_fake(v6=answers), "exited 0 with no address")
        # 15 Nov, full tunnel: `curl -6 https://ifconfig.me/ip` exits 0 and prints an IPv4 address; S2 fails
        fake = probe_fake(v6={ME: http(VPS4), IDENT: NO_ROUTE, IPME: NO_ROUTE})
        text = self.fails(["s2", "--vps6", "none"], fake, "exited 0 with no address")
        self.assertIn("%s exit 0 HTTP 200 body '%s" % (ME, VPS4), text)
        # VPS6 set: VPS6 from the second service passes, any other IPv6 address fails as a leak
        self.passes(["s2", "--vps6", VPS6], probe_fake(v6={ME: NO_ROUTE, IDENT: http(VPS6)}))
        self.fails(["s2", "--vps6", VPS6], probe_fake(v6={ME: NO_ROUTE, IDENT: http("2001:db8:99::1")}), "a leak")

    def test_s2_failed_ipv6_transfers_still_prove_reachability(self):
        for rc in (18, 28):
            for url in C.PROBE_URLS:
                for status in (None, "200", "403"):
                    with self.subTest(rc=rc, url=url, status=status):
                        answers = {u: NO_ROUTE for u in C.PROBE_URLS}
                        body = " \t2001:DB8:99::1\r\n"
                        answers[url] = (rc, body if status is None else http(body, status)[1],
                                        "curl: transfer failed\n")
                        fake = probe_fake(v6=answers)
                        text = self.fails(["s2", "--vps6", "none"], fake,
                                          "2001:db8:99::1 although IPv6 must be blocked")
                        self.assertIn("%s exit %d" % (url, rc), text)
                        self.assertIn("S2 printed '',", text)  # no accepted measurement
                        self.assertEqual(self.urls(fake, 6), list(C.PROBE_URLS))

    def test_s2_reachability_and_accepted_measurements_stay_separate(self):
        for rc in (18, 28):
            with self.subTest(rc=rc):
                failed = (rc, http("2001:db8:99::1")[1], "curl: transfer failed\n")
                # A later accepted reply cannot erase the earlier reachability evidence.
                answers = {ME: failed, IDENT: http(VPS6)}
                self.fails(["s2", "--vps6", "none"], probe_fake(v6=answers), "2001:db8:99::1 although")
                self.passes(["s2", "--vps6", VPS6], probe_fake(v6=answers))
                # An expected IPv6 body with a failed transfer cannot certify VPS6 either.
                answers = {u: (rc, http(VPS6)[1], "curl: transfer failed\n") for u in C.PROBE_URLS}
                self.fails(["s2", "--vps6", VPS6], probe_fake(v6=answers), "could not measure")
                # Without exit 0 or exactly one IPv6 address there is no reachability evidence.
                for body in ("", CHALLENGE, VPS4, VPS6 + "\n" + VPS6):
                    self.passes(["s2", "--vps6", "none"],
                                probe_fake(v6={u: (rc, http(body)[1], "curl: transfer failed\n")
                                               for u in C.PROBE_URLS}))

    def test_s123_keeps_failed_ipv6_transfer_evidence(self):
        for rc in (18, 28):
            with self.subTest(rc=rc):
                fake = self.caller_fake("s123", {ME: http(VPS4)})
                answers = {ME: NO_ROUTE, IDENT: NO_ROUTE,
                           IPME: (rc, http(VPS6)[1], "curl: transfer failed\n")}
                fake.rules[1] = (("/usr/bin/curl", "-6"), by_url(answers))
                self.fails(["s123", "--vps4", VPS4, "--vps6", "none", "--dns", DNSIP], fake,
                           "%s although IPv6 must be blocked" % VPS6)

    def test_s2_keeps_reachability_when_the_probe_budget_runs_out(self):
        def partial_timeout(argv, fake):
            fake.t += float(argv[argv.index("--max-time") + 1])
            return (28, VPS6 + "\n", "curl: (28) timed out\n")

        fake = Fake([(["/usr/bin/curl", "-6"], partial_timeout)])
        text = self.fails(["s2", "--vps6", "none"], fake, "%s although IPv6 must be blocked" % VPS6)
        self.assertIn("not asked: no time left", text)
        self.assertEqual(self.urls(fake, 6), [ME])
        self.assertLessEqual(fake.t, 10.1)

    def test_addresses_does_not_accept_failed_ipv6_transfers(self):
        for rc in (18, 28):
            with self.subTest(rc=rc):
                answers = {u: (rc, http(VPS6)[1], "curl: transfer failed\n") for u in C.PROBE_URLS}
                text = self.passes(["addresses"], probe_fake(v4={ME: http(VPS4)}, v6=answers))
                self.assertIn("IPv6 seen: none (exit %d)" % rc, text)
                self.assertIn("could not measure the IPv6 address", text)
                for url in C.PROBE_URLS:
                    self.assertIn("%s exit %d HTTP 200 body '%s'" % (url, rc, VPS6), text)

    def test_total_stays_within_the_bound(self):
        # The first service hangs for its whole --max-time: no time is left for the others within 10 seconds.
        def hang(argv, fake):
            fake.t += float(argv[argv.index("--max-time") + 1])
            return (28, "", "curl: (28) timed out\n")

        fake = Fake([(["/usr/bin/curl", "-4"], hang)])
        text = self.fails(["s1", "--vps4", VPS4], fake, "could not measure")
        self.assertLessEqual(fake.t, 10.1)  # the fake adds 0.1 s per command
        self.assertEqual(len(fake.ran("/usr/bin/curl")), 1)
        self.assertIn("not asked: no time left", text)
        self.assertNotIn("a leak", text)

        # A slow first failure leaves the remaining whole seconds to the next service.
        def slow(argv, fake):
            if argv[-1] == ME:
                fake.t += 6.5
                return DNS_FAIL
            fake.t += 0.2
            return http(VPS4)

        fake = Fake([(["/usr/bin/curl", "-4"], slow)])
        self.passes(["s1", "--vps4", VPS4], fake)
        self.assertEqual(fake.ran("/usr/bin/curl")[1].argv[4], "3")
        # A fast first failure (DNS or HTTP error) leaves almost the whole bound to the next service.
        for first in (DNS_FAIL, http(CHALLENGE, "403")):
            fake = Fake([(["/usr/bin/curl", "-4"], by_url({ME: first, IDENT: http(VPS4)}))])
            self.passes(["s1", "--vps4", VPS4], fake)
            runs = fake.ran("/usr/bin/curl")
            self.assertEqual([run.argv[-1] for run in runs], [ME, IDENT])
            self.assertEqual(runs[1].argv[4], "9")
            self.assertLessEqual(fake.t, 10)
        # leakwatch: each probe, fallbacks included, stays within its --max-time of 3 and the window
        def leak_hang(argv, fake):
            fake.t += float(argv[argv.index("--max-time") + 1])
            return (28, "", "curl: (28) timed out\n")

        fake = Fake([(["/usr/bin/curl", "-4"], leak_hang)])
        self.fails(["leakwatch", "--vps4", VPS4], fake, "VPS4 did not return within 120")
        self.assertLessEqual(fake.t, 121)
        for _, timeout in fake.timeouts:
            self.assertLessEqual(timeout, 120)

    def test_parse_address_edges(self):
        self.assertEqual(C.parse_address(4, " %s \r\n" % VPS4), VPS4)
        self.assertEqual(C.parse_address(6, "2001:DB8::7\n"), VPS6)
        for body in ("", "\n", CHALLENGE, VPS4 + "\n" + VPS4, VPS4 + " " + VPS4, "ip=" + VPS4, VPS6, "999.1.1.1",
                     "203.0.113.007", "fe80::1%en0"):
            self.assertIsNone(C.parse_address(4, body), body)
        for body in (VPS4, "fe80::1%en0", VPS6 + "\n" + VPS6, "<html>"):
            self.assertIsNone(C.parse_address(6, body), body)
        self.assertEqual(C.split_status("x\n" + C.HTTP_MARK + "403\n"), ("x", "403"))
        self.assertEqual(C.split_status(VPS4 + "\n"), (VPS4 + "\n", None))


if __name__ == "__main__":
    unittest.main()
