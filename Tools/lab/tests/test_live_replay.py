# SPDX-License-Identifier: MIT
"""Exercise the real Session driver using recorded just/Lima replies, never VMs."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "Tools/lab/tests/fixtures"


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "Tools/lab" / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


LIVE = module("recorded_live", "verdict-live.py")
V = module("recorded_verdict", "verdict.py")
TABLE = json.loads((ROOT / "Tools/lab/leak-expectations.json").read_text())
ROWS = json.loads((ROOT / "Tools/lab/rows.json").read_text())["rows"]
# Public fixture key only; tests compare 12-hex digests and never print the key.
SERVER_PUBLIC = next(line.strip() for line in (ROOT / "Tests/Fixtures/keys/server.pub").read_text().splitlines()
                     if line.strip() and not line.startswith("#"))
FIXTURE_KEY_HASH = hashlib.sha256(SERVER_PUBLIC.encode()).hexdigest()[:12]
FIXTURE_IPERF3 = b"fixture iperf3 client, never executed"
PROVENANCE = dict(sourceCommit="a" * 40, buildConfiguration="Lab",
                  buildInputs=dict(configuration="Lab", compilationConditions="$(inherited) DEBUG WGEX_LAB_BUILD",
                                   bundleVersionOverride="", targets={target: dict(CONFIGURATION="Lab", CODE_SIGN_IDENTITY="lab", EXPANDED_CODE_SIGN_IDENTITY="-",
                                       CURRENT_PROJECT_VERSION="1", SWIFT_ACTIVE_COMPILATION_CONDITIONS="DEBUG WGEX_LAB_BUILD")
                                       for target in ("WGEXMac", "WGEXDaemon", "WGEXCLI")}),
                  artefacts=dict(app="b" * 40, daemon="c" * 40, cli="d" * 40))


def actuations(commands):
    """(x, y) strings of every control the driver actuated, in order: `gui click X Y` and the element path's
    `gui press APP WINDOW IDENTIFIER press X Y ROLE [LABEL]` (M1-10j), whose X Y is the frame centre fallback."""
    found = []
    for argv in commands:
        if argv[:4] == ["just", "lab", "gui", "click"]:
            found.append(argv[4:6])
        elif argv[:4] == ["just", "lab", "gui", "press"]:
            found.append(argv[8:10])
    return found


def actuates(line, x, y):
    """True when one joined command line clicks or presses the control at (x, y)."""
    if re.search(rf"gui (?:click|press \S+ \S+ \S+ \S+) {x} {y}(?: |$)", line) is not None:
        return True
    # M1-38: a compared toggle is pressed `press-only ROLE frame=X,Y,WxH`, which acts at the frame's centre.
    frame = re.search(r"gui press \S+ \S+ \S+ press-only \S+ frame=(-?\d+),(-?\d+),(\d+)x(\d+)(?: |$)", line)
    return frame is not None and (int(frame[1]) + int(frame[3]) // 2, int(frame[2]) + int(frame[4]) // 2) == (x, y)


class Process:
    def __init__(self, runner, kind):
        self.runner, self.kind, self.returncode = runner, kind, None

    def wait(self, timeout=None):
        if self.returncode is None:
            if self.kind == "generate":
                self.runner.clock += 12
            elif self.kind == "receiver":
                self.runner.write_host_record()
            self.returncode = 0
        return self.returncode

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = 0


def press_point(args):
    """The point a recorded `gui click` or `gui press` acts at. `press` carries it (APP WINDOW IDENTIFIER press X Y ROLE). M1-38: a
    compared toggle is pressed `press-only ROLE frame=X,Y,WxH` (no point), which acts on the element at that frame, i.e. at its
    centre; any other press-only has no frame and no point (None, which no fixture position equals)."""
    if args[1] == "click":
        return tuple(map(int, args[2:4]))
    if args[5] == "press":
        return tuple(map(int, args[6:8]))
    frame = re.fullmatch(r"frame=(-?\d+),(-?\d+),(\d+)x(\d+)", args[-1])
    return (int(frame[1]) + int(frame[3]) // 2, int(frame[2]) + int(frame[4]) // 2) if frame else None


class RecordedRunner:
    def __init__(self):
        self.fixture = json.loads((FIXTURES / "commands.json").read_text())
        self.clock = 1000.0
        self.commands, self.records, self.files = [], [], {}
        self.relay, self.connected, self.blocked, self.status_calls = True, False, False, 0
        self.host_output = None
        self.selected = None
        self.drop_guest_outside = False
        self.fail_generator = False
        self.boot_secret_mode = False
        # M1-10v: the guest's prevent-relaunch reply for BOOT-SECRETS: "ok", "failed" (a key reads back unconfirmed) or "silent".
        self.relaunch_prevention = "ok"
        self.boot_status_count = None
        self.boot_restores_protected = False
        self.cutover_state = "none"   # M03-T07: the status reply's cutover.state
        self.boot_outside_leak = False
        self.drop_system_dns = False
        self.wrong_dns_configuration = False
        self.quit_still_running = False
        self.recovery_delay = 0
        self.recovery_at = 0
        self.environments = []
        self.fail_prepare = False
        self.review_delay = 0
        self.review_remaining = 0
        # Fifth-run seams: the live wg0 key digest, sidebar selection and the guest's ~/lab/bin.
        self.peer_key_hash, self.peer_key_code = FIXTURE_KEY_HASH, 0
        self.auto_select, self.keys_work = True, True
        # Sixth-run seams: AppKit appends " – <subtitle>" to the title (L16); SwiftUI may expose no
        # wgex.main.profiles element, so only the helper's window fallback can press keys (L17).
        self.title_status, self.profiles_identifier = None, True
        self.names, self.importing_name = {}, None
        self.guest_files = {}
        self.corrupt_guest_copy = False
        self.diagnostics_tail = ("start failed, type: DaemonPortError case: system code: 5\n" * 50).encode()
        # Run 6 slice 1 seams (M1-10e): with the path lost (relay down, or the wrong-key profile) the daemon shows
        # preparing/unknown, configuring/blocked for 0.4 s, active/protected until `loss_reassert_after`, then
        # reasserting/blocked and never failed; one guest status query takes `status_cost` seconds over SSH.
        self.loss_model, self.loss_reassert_after, self.status_cost, self.connect_at = False, 13.0, 0.0, None
        # A split profile's probes to the underlay host 192.168.64.1 arrive outside the tunnel in protected windows.
        self.underlay_receipts = False
        # M1-10m guest-load settle: `sysctl -n vm.loadavg` replies in order (the last repeats); a quiet guest by default.
        self.guest_loads = [b"{ 0.52 0.61 0.70 }\n"]
        # M01-T04: the reinstalled daemon's `wgex doctor --json` secureInstall value and the line guest/wrapping-key.sh prints
        # during `lab install` (the escrow re-trusts the new ad hoc daemon by default).
        self.secure_install = "verified"
        self.wrapping_key_line = b"wrapping key re-trusted for com.magrathean.WGEXApp.dev.daemon; decrypt ACL trusts installed daemon cdhash " + b"d" * 40 + b"\n"

    def row_order(self):
        rows = [(y, x) for _, identifier, x, y in self.fixture["controls"] if identifier.startswith("wgex.main.tunnel.")]
        return [(x + 10, y + 10) for y, x in sorted(rows)]

    def title(self):
        title = self.names.get(self.selected, "WGEX") if self.selected else "WGEX"
        return title + " \u2013 " + self.title_status if self.title_status else title

    def status_reply(self):
        """M03-T07: the reply carries the cutover object and, while connected, the imported profile's id, as `wgex status --json` does."""
        status = dict(self.status())
        status.setdefault("cutover", dict(state=self.cutover_state))
        profile = next((p for p in self.fixture["profiles"] if p["name"] == self.importing_name), None) if self.connected else None
        status.setdefault("activeProfileID", profile["id"] if profile else None)
        return status

    def imported(self):
        self.names[self.importing_profile] = self.importing_name
        if self.auto_select:
            self.selected = self.importing_profile

    def now(self):
        return self.clock

    def monotonic(self):
        return self.clock

    def sleep(self, seconds):
        self.clock += seconds

    def reply(self, argv, output=b"", code=0, stderr=b""):
        return subprocess.CompletedProcess(argv, code, output, stderr)

    def receiver(self, scope):
        config = self.config
        observations = [dict(o, timestamp=o["timestamp"] - 0.1) for record in self.records for receiver in record["receiverRecords"]
                        for o in receiver["observations"] if o["scope"] == scope]
        if self.drop_guest_outside and scope == "outside_tunnel":
            observations = []
        coverage = []
        for target in config["targets"]:
            if target["scope"] != scope:
                continue
            for proto, key in dict(dns="dnsPort", http="httpPort", tcp="httpPort", udp="udpPort").items():
                coverage.append(dict(scope=scope, address=target["address"], port=target[key], proto=proto,
                                     start=900, end=self.clock + 20, healthy=True, configurationSHA256=V.sha256(V.canonical(config))))
        return dict(schemaVersion=1, nonce="receiver", configuration=config, configurationSHA256=V.sha256(V.canonical(config)),
                    observations=observations, windows=[], receiverCoverage=coverage)

    def write_host_record(self):
        (self.host_output / "host.json").write_bytes(V.canonical(self.receiver("outside_tunnel")))

    def status(self):
        self.status_calls += 1
        self.clock += self.status_cost
        if self.loss_model and self.connected and self.connect_at is not None and (not self.relay or self.selected == (170, 110)):
            elapsed = self.clock - self.connect_at
            if elapsed < 0.5:
                return dict(phase="preparing", protection="unknown")
            if elapsed < 0.9:
                return dict(phase="configuring", protection="blocked")
            if elapsed < self.loss_reassert_after:
                return dict(self.fixture["active"])
            return dict(phase="reasserting", protection="blocked")
        if not self.connected:
            return self.fixture["idle"]
        if self.boot_status_count is not None:
            self.boot_status_count += 1
            if self.boot_secret_mode and self.boot_status_count > 1:
                self.blocked = False
        if self.blocked:
            return dict(self.fixture["blocked"], phase="preparing" if self.status_calls == 1 else "failed")
        if self.clock < self.recovery_at:
            return self.fixture["blocked"]
        return self.fixture["active"]

    def start(self, argv, env=None):
        self.commands.append(list(argv))
        self.environments.append(env)
        if "--scope" in argv:
            path = Path(argv[argv.index("--record") + 1])
            self.host_output = path.parent
            (self.host_output / "host.ready").write_text('{"ready":true}')
            return Process(self, "receiver")
        if self.fail_generator:
            raise RuntimeError("recorded generator failure")
        words = shlex.split(argv[-1])
        state, nonce = words[words.index("--state") + 1], words[words.index("--nonce") + 1]
        record = json.loads((FIXTURES / (state + ".json")).read_text())
        record["configuration"] = copy.deepcopy(self.config)
        record["configurationSHA256"] = V.sha256(V.canonical(self.config))
        record["nonce"] = nonce
        record["windows"][0].update(start=self.clock + 0.1, end=self.clock + 12.1)
        if self.underlay_receipts and state == "protected":
            underlay = json.loads((FIXTURES / "unprotected.json").read_text())["receiverRecords"][0]["observations"]
            record["receiverRecords"][0]["observations"].extend(underlay)
        for source in [record, *record["receiverRecords"]]:
            source["configuration"] = copy.deepcopy(self.config)
            source["configurationSHA256"] = record["configurationSHA256"]
            for observation in source["observations"]:
                observation.update(nonce=nonce, timestamp=self.clock + 5.1)
        if self.boot_status_count is not None and state == "blocked":
            protected = json.loads((FIXTURES / "protected.json").read_text())
            record["receiverRecords"][0]["observations"].extend(
                dict(o, nonce=nonce, timestamp=self.clock + 5.1) for o in protected["receiverRecords"][0]["observations"])
            if self.boot_outside_leak:
                record["receiverRecords"][0]["observations"].append(dict(
                    record["observations"][0], kind="received"))
        self.records.append(record)
        self.generator = record
        return Process(self, "generate")

    def run(self, argv, data=None, timeout=100, env=None):
        self.commands.append(list(argv))
        self.environments.append(env)
        self.clock += 0.01
        if "--inspect-build" in argv:
            return self.reply(argv, json.dumps(PROVENANCE).encode())
        if argv[:3] == ["just", "lab", "ssh"] and "sw_vers -productVersion; sw_vers -buildVersion" in argv[-1]:
            return self.reply(argv, ("26.1\n25B12\n" + "\n".join("CDHash=" + value for value in PROVENANCE["artefacts"].values()) + "\n").encode())
        if argv[0] == "tcpdump":
            lines = []
            for record in self.records:
                if record["windows"][0]["state"] == "unprotected":
                    stamp = record["windows"][0]["start"] + 2
                    lines.append(f'{stamp:.6f} IP 192.168.64.5.1234 > 192.168.64.1.53: UDP\n{record["nonce"]}-system\n')
            return self.reply(argv, "".join(lines).encode())
        if argv[0] != "just":
            if Path(argv[0]).name != "vm-lima":
                raise AssertionError("unexpected executable")
            command = " ".join(argv[4:])
            if self.fail_prepare and "peer-fault.sh check" in command:
                return self.reply(argv, code=1, stderr=b"peer: wg0 ownership missing; run just lab peer up --adopt after verifying dedicated ownership\n")
            if "wg show wg0 public-key" in command:
                return self.reply(argv, (self.peer_key_hash + "\n").encode(), code=self.peer_key_code)
            if command.endswith("/peer.ready"):
                return self.reply(argv, b'{"ready":true,"timestamp":1}')  # deliberately old; not a clock sample
            if command.endswith("/peer.json"):
                return self.reply(argv, V.canonical(self.receiver("in_tunnel")))
            if "ss -H -ltn" in command:
                return self.reply(argv, b"LISTEN 0 1 10.77.0.1:5201\n")
            if "config.json" in command and data:
                self.config = json.loads(data)
            if "peer-fault.sh latency" in command or "peer-fault.sh loss" in command:
                self.blocked = False
            if "peer-fault.sh cleanup" in command:
                self.blocked = not self.relay and self.connected
            return self.reply(argv)
        args = argv[2:]
        if args[:2] == ["relay", "stop"]:
            self.relay, self.blocked = False, self.connected
            self.status_calls = 0
        if args[:1] == ["install"]:
            return self.reply(argv, b"Contents/MacOS/WGEXDaemon: OK\n" + self.wrapping_key_line)
        if args[:2] == ["relay", "start"]:
            self.relay, self.blocked = True, False
            if self.connected:
                self.recovery_at = self.clock + self.recovery_delay
        if args[:2] == ["ssh", "--clock"]:
            return self.reply(argv, V.canonical(dict(start=self.clock, end=self.clock + 0.04, timestamp=self.clock + 0.12)))
        if args[:2] == ["gui", "dump"]:
            controls = self.fixture["controls"]
            if self.review_remaining:
                self.review_remaining -= 1
                controls = [c for c in controls if not c[1].startswith("wgex.importReview.") and c[0] != "Replace"]
            lines = [f'{"AXRadioGroup" if identifier == "wgex.importReview.duplicate" else "AXRadioButton" if name == "Replace" else "AXStaticText" if identifier.startswith("wgex.main.tunnel.") else "AXButton"} | name={name} | desc= | id={identifier} | pos={x},{y} size=20x20 en=true' for name,identifier,x,y in controls]
            # ax-dump.applescript leads with the window; its title is the selected profile name.
            lines.insert(0, f"AXWindow | name={self.title()} | value= | desc= | id= | pos=0,0 size=800x600 en=")
            return self.reply(argv, ("\n".join(lines) + "\n").encode())
        if args[:2] == ["gui", "keys"]:
            # args: gui keys APP WINDOW IDENTIFIER up|down COUNT [fallback]; SwiftUI rows follow arrow keys only.
            path = b"path=identifier\n"
            if args[4] == "wgex.main.profiles" and not self.profiles_identifier:
                if args[7:] != ["fallback"]:
                    return self.reply(argv, code=1, stderr=b"arrow-keys.applescript: identifier not found (3)\n")
                path = b"path=window\n"
            if self.keys_work:
                order, count = self.row_order(), int(args[6])
                index = order.index(self.selected) if self.selected in order else None
                if args[5] == "up":
                    index = 0 if index is None else max(0, index - count)
                else:
                    index = min(len(order) - 1, count - 1 if index is None else index + count)
                self.selected = order[index]
            return self.reply(argv, path)
        if args[:2] == ["gui", "run"] and any("exists menu" in arg for arg in args):
            return self.reply(argv, b"true")
        if args[:2] in (["gui", "click"], ["gui", "press"]):
            # gui press APP WINDOW IDENTIFIER press X Y ROLE [LABEL]: the element path actuates the control at its fallback point.
            xy = press_point(args)
            if xy == (35, 20):
                # The Import and Connect review button selects the profile being imported.
                self.imported()
                self.connected, self.blocked, self.status_calls = True, not self.relay, 0
                self.connect_at = self.clock
            if xy == (30, 20):
                # Import without connecting also selects the fresh profile.
                self.imported()
            if xy == (40, 20):
                if self.selected is None:
                    raise AssertionError("Connect before explicit profile selection")
                self.connected, self.blocked, self.status_calls = True, not self.relay, 0
                self.connect_at = self.clock
            if xy in [(110,110),(140,110),(170,110),(200,110)]:
                raise AssertionError("sidebar row clicks do not select in SwiftUI (L14)")
            return self.reply(argv, b"path=element\n" if args[1] == "press" else b"")
        if args[:2] == ["gui", "run"] and args[2:5] == ["open", "-a", "WGEX"] and len(args) > 5:
            self.review_remaining = self.review_delay
            profile = Path(args[-1]).stem
            self.importing_name = profile
            self.importing_profile = {"wgex-lab-default": (110,110), "wgex-lab-full4": (110,110), "wgex-lab-dual": (110,110), "wgex-lab-dns": (140,110),
                                      "wgex-lab-wrong-key": (170,110), "wgex-lab-lockdown": (200,110)}[profile]
        if args[:2] != ["ssh", "--"]:
            return self.reply(argv)
        command = args[2]
        if "pgrep -x WGEX" in command:
            return self.reply(argv, b"running" if self.quit_still_running else b"exited")
        digest = re.search(r"\b[0-9a-f]{64}\b", command)
        if "printf present" in command:
            staged = self.guest_files.get(LIVE.GUEST_IPERF3)
            present = staged is not None and digest is not None and hashlib.sha256(staged).hexdigest() == digest[0]
            return self.reply(argv, b"present" if present else b"missing")
        if "mv -f" in command and LIVE.GUEST_IPERF3 in command:
            staged = self.guest_files.pop(LIVE.GUEST_IPERF3 + ".next", None)
            if self.corrupt_guest_copy and staged:
                staged = staged[:-1]
            if staged is None or digest is None or hashlib.sha256(staged).hexdigest() != digest[0]:
                return self.reply(argv, code=1)
            self.guest_files[LIVE.GUEST_IPERF3] = staged
            return self.reply(argv)
        if command.startswith(LIVE.GUEST_IPERF3 + " "):
            return self.reply(argv, b'{"end":{"sum_received":{"bits_per_second":42000000}}}')
        if data:
            if command.endswith("/config.json"):
                self.config = json.loads(data)
            target = re.search(r"cat > (\S+)$", command)
            if target:
                self.guest_files[target[1]] = data
            return self.reply(argv)
        if command.endswith(" status --json"):
            return self.reply(argv, V.canonical(self.status_reply()))
        words = shlex.split(command)
        if words[-1] == "diagnostics-tail":
            return self.reply(argv, self.diagnostics_tail)
        if words[-1] == "prevent-relaunch" and "verdict-actions.sh" in command:
            replies = {"ok": b"mechanism=loginwindow-reopen-state\nusermatch=yes\nrelaunchlistbefore=1\nrelaunchlistwgex=yes\nsavesstate=false\nrelaunchapps=false\nrelaunchlist=0\napp=none\n",
                       "failed": b"mechanism=loginwindow-reopen-state\nusermatch=yes\nrelaunchlistbefore=0\nrelaunchlistwgex=no\nsavesstate=unconfirmed\nrelaunchapps=false\nrelaunchlist=0\napp=none\n",
                       "usermismatch": b"mechanism=loginwindow-reopen-state\nusermatch=no\napp=none\n",
                       "silent": b""}
            return self.reply(argv, replies[self.relaunch_prevention], code=0 if self.relaunch_prevention == "ok" else 1)
        if words[-1] == "guest-load" and "verdict-actions.sh" in command:
            return self.reply(argv, self.guest_loads.pop(0) if len(self.guest_loads) > 1 else self.guest_loads[0])
        if "profile-id" in words:
            name = words[-1]
            profile = next((p for p in self.fixture["profiles"] if p["name"] == name), None)
            return self.reply(argv, (profile["id"] + "\n").encode() if profile else b"", code=0 if profile else 1)
        if "system-resolve" in words:
            nonce = words[words.index("--nonce") + 1]
            path = words[words.index("--record") + 1]
            self.files[path] = dict(timestamp=self.clock + 0.1, nonce=nonce, name=nonce + "-system.leak.wgex.test")
            if self.selected == (140, 110) and not self.drop_system_dns and self.generator["windows"][0]["state"] == "protected":
                receipt = next(o for o in self.generator["receiverRecords"][0]["observations"] if o["proto"] == "dns" and o["scope"] == "in_tunnel")
                self.generator["receiverRecords"][0]["observations"].append(dict(receipt, nonce=nonce + "-system"))
        if words[0] == "cat":
            path = words[1]
            value = self.generator if path.endswith("generator.json") else self.files[path]
            return self.reply(argv, V.canonical(value))
        if words[:3] == ["sudo", "-n", "cat"]:
            return self.reply(argv, b"recorded-pcap-placeholder")
        if "start-capture.sh" in command:
            iface = words[-2]
            return self.reply(argv, f'captureFile=/Users/lab/pcap/{len(self.commands)}-{iface}.pcap\n'.encode())
        if "interface-index" in command:
            return self.reply(argv, b'{"index":12}')
        if words[-1] == "secure-install-status" and "verdict-actions.sh" in command:
            doctor = dict(app="com.magrathean.WGEXApp.dev", daemonReachable=True, secureInstall=self.secure_install)
            return self.reply(argv, (json.dumps(doctor) + "\n").encode())
        if words[-1] == "down" and "verdict-actions.sh" in command:
            self.connected, self.blocked = False, False
        if words[-1] in ("kill-app", "kill-no-app", "term") and "verdict-actions.sh" in command:
            self.connected, self.blocked = True, True
        if words[-1] == "reboot" and "verdict-actions.sh" in command:
            self.connected, self.blocked = True, not self.boot_restores_protected
            self.boot_status_count = 0
        if words[-1] == "observe" and "verdict-actions.sh" in command:
            status = V.canonical(self.status()).decode()
            refs = (ROOT / "Tests/Fixtures/pfctl/macos26/references-with-token.txt").read_text()
            text = f'__WGEX_STATUS__\n{status}\n__WGEX_REFERENCES__\n{refs}\n__WGEX_PFINFO__\nStatus: Enabled\n'
            for key, source in [("IFCONFIG","ifconfig"),("ROUTES","routes"),("DNS","dns")]:
                value = self.fixture[source]
                if source == "dns" and self.selected == (140, 110) and self.connected and not self.wrong_dns_configuration:
                    value = "resolver #1\n  nameserver[0] : 10.77.0.1\n"
                text += f'__WGEX_{key}__\n{value}\n'
            text += '__WGEX_RULES__\nblock drop quick all\n__WGEX_LOG__\nevents=1; rawMessagesOmitted=1\n'
            return self.reply(argv, text.encode())
        return self.reply(argv)


class LiveReplayTests(unittest.TestCase):
    def run_recorded(self, row_name, runner=None, accepted=True, no_install=False, iperf3=True):
        runner = runner or RecordedRunner()
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            probe, helper = Path(directory)/"leakprobe", Path(directory)/"foreign-utun"
            probe.write_bytes(b"fixture binary, never executed")
            helper.write_bytes(b"fixture helper, never executed")
            # A fixture stands in for the pinned host asset; absent means "never fetched".
            client = Path(directory) / "iperf3"
            if iperf3:
                client.write_bytes(FIXTURE_IPERF3)
            pinned = dict(sha256=hashlib.sha256(FIXTURE_IPERF3).hexdigest())
            with patch.dict(os.environ, WGEX_LAB_SNAPSHOT="ready"), patch.dict(LIVE.IPERF3.PIN, pinned), patch.object(subprocess, "run", side_effect=AssertionError("real command from replay")), patch.object(subprocess, "Popen", side_effect=AssertionError("real process from replay")):
                result = LIVE.run(row_name, ROWS[row_name], TABLE, V, {}, runner=runner, probe_path=probe, foreign_helper_path=helper,
                                  no_install=no_install, iperf3_path=client)
        self.assertEqual(result["expectationsMet"], accepted, result.get("gaps"))
        if accepted:
            self.assertTrue(result["tailControl"]["met"])
            self.assertEqual(result["familiesCovered"], ["ipv4"])
        return runner, result

    def test_prepare_leak_row_and_fault_cleanup_use_only_recorded_commands(self):
        runner, result = self.run_recorded("M5.1-04")
        commands = [" ".join(argv) for argv in runner.commands]
        restore = next(i for i,c in enumerate(commands) if "lab relay start" in c and i > next(j for j,d in enumerate(commands) if "lab relay stop" in d))
        down = next(i for i,c in enumerate(commands) if i > restore and "verdict-actions.sh down" in c)
        self.assertTrue(any("status --json" in c for c in commands[restore:down]))
        self.assertFalse(any("gui click" in c or "gui press" in c for c in commands[restore:down]))
        self.assertTrue(result["phasesDuringFault"])
        self.assertTrue(any("peer-fault.sh cleanup" in c for c in commands))
        self.assertLess(next(i for i,c in enumerate(commands) if "lab restore ready" in c), next(i for i,c in enumerate(commands) if "lab profile full4" in c))

    def test_crash_row_runs_real_driver_and_positive_tail(self):
        runner, result = self.run_recorded("M5.3-02")
        self.assertTrue(any("verdict-actions.sh kill-app" in " ".join(command) for command in runner.commands))
        self.assertTrue(result["captureChecks"]["tailSystemResolverObserved"])

    def test_blackhole_is_installed_before_connect(self):
        runner, _ = self.run_recorded("M5.1-08")
        commands = [" ".join(argv) for argv in runner.commands]
        stop = next(i for i,c in enumerate(commands) if "lab relay stop" in c)
        connect = next(i for i,c in enumerate(commands) if actuates(c, 40, 20))
        self.assertLess(stop, connect)

    def test_post_boot_probe_precedes_first_status_without_opening_the_app(self):
        runner, result = self.run_recorded("REBOOT-INTENT", accepted=False) # M1-10u fix pass 1: REBOOT-INTENT needs launchd runs == 1; this runner has no boot-observe, so the row is not accepted
        commands = [" ".join(argv) for argv in runner.commands]
        boot = next(i for i,c in enumerate(commands) if "verdict-actions.sh reboot" in c)
        first = next(i for i,c in enumerate(commands) if i > boot and "status --json" in c)
        self.assertTrue(any(" generate " in c for c in commands[boot:first]))
        self.assertFalse(any("open -a" in c for c in commands[boot:first]))
        self.assertTrue(next(check for check in result["checks"] if check["name"]=="zeroReceiptsBeforeFirstStatus")["met"])

    def test_dead_guest_path_cannot_pass_on_host_receiver_health(self):
        runner = RecordedRunner()
        runner.drop_guest_outside = True
        _, result = self.run_recorded("M5.3-02", runner, accepted=False)
        self.assertFalse(result["tailControl"]["met"])

    def test_failed_fault_run_still_restores_the_relay(self):
        runner = RecordedRunner()
        runner.fail_generator = True
        self.run_recorded("M5.1-08", runner, accepted=False)
        commands = [" ".join(argv) for argv in runner.commands]
        stop = next(i for i,c in enumerate(commands) if "lab relay stop" in c)
        self.assertTrue(any("lab relay start" in c for c in commands[stop+1:]))

    def test_netem_budget_and_interface_identity_fixture(self):
        runner, _ = self.run_recorded("M5.1-06")
        self.assertEqual(runner.config["tcpTimeoutMilliseconds"], 1500)
        runner, result = self.run_recorded("M5.2-04")
        self.assertTrue(any(check["name"] == "interfaceIdentityAfter" for check in result["checks"]))
        self.assertTrue(any("verdict-actions.sh interface-cycle" in " ".join(command) for command in runner.commands))

    def test_foreign_fixture_teardown_is_scoped(self):
        runner, _ = self.run_recorded("M5.4-01")
        commands = [" ".join(argv) for argv in runner.commands]
        self.assertTrue(any("verdict-actions.sh foreign-up" in c for c in commands))
        self.assertTrue(any("verdict-actions.sh foreign-down" in c for c in commands))

    def test_boot_variants_use_the_never_open_driver(self):
        # REBOOT-LOCKDOWN and BOOT-SECRETS are live since M1-10h; test_run8_rows.py replays them with the GUI,
        # journal and boot-observation seams this recorded runner lacks.
        _, result = self.run_recorded("REBOOT-INTENT", accepted=False) # M1-10u fix pass 1: REBOOT-INTENT needs launchd runs == 1; this runner has no boot-observe, so the row is not accepted
        self.assertTrue(any(check["name"] == "zeroReceiptsBeforeFirstStatus" for check in result["checks"]))

    def test_app_quit_is_a_menu_command(self):
        runner, _ = self.run_recorded("M5.3-01")
        commands = [" ".join(argv) for argv in runner.commands]
        self.assertTrue(any('click menu item "Quit WGEX"' in c for c in commands))
        self.assertTrue(any("pgrep -x WGEX" in c for c in commands))
        self.assertFalse(any("pkill" in c for c in commands))

    def test_dns_row_requires_system_receipt_and_scutil_nameserver(self):
        _, result = self.run_recorded("DNS-TUNNEL")
        protected = [w for w in result["states"] if w["state"] == "protected"]
        self.assertTrue(protected)
        self.assertTrue(all(w["systemResolverReceiptCount"] >= 1 and w["nameserverConfigured"] for w in protected))
        for flag in ["drop_system_dns", "wrong_dns_configuration"]:
            runner = RecordedRunner()
            setattr(runner, flag, True)
            _, result = self.run_recorded("DNS-TUNNEL", runner, accepted=False)
            self.assertTrue(any(w["missing"] for w in result["states"] if w["state"] == "protected"))

    def test_post_boot_tunnel_receipts_pass_and_outside_receipts_fail(self):
        runner = RecordedRunner()
        runner.boot_restores_protected = True
        _, result = self.run_recorded("REBOOT-INTENT", runner, accepted=False) # M1-10u fix pass 1: REBOOT-INTENT needs launchd runs == 1; this runner has no boot-observe, so the row is not accepted
        check = next(c for c in result["checks"] if c["name"] == "zeroReceiptsBeforeFirstStatus")
        self.assertEqual(check["receiptCount"], 0)
        self.assertGreater(check["inTunnelReceiptCount"], 0)
        self.assertEqual(check["firstStatus"]["protection"], "protected")
        runner = RecordedRunner()
        runner.boot_outside_leak = True
        _, result = self.run_recorded("REBOOT-INTENT", runner, accepted=False)
        self.assertFalse(next(c for c in result["checks"] if c["name"] == "zeroReceiptsBeforeFirstStatus")["met"])

    def test_failed_rows_allow_sixty_second_backoff_without_user_reconnect(self):
        for name in ["M5.1-01", "M5.1-08"]:
            runner = RecordedRunner()
            runner.recovery_delay = 65
            _, result = self.run_recorded(name, runner)
            self.assertTrue(any(w.get("role") == "automaticRecovery" for w in result["states"]))

    def test_quit_that_leaves_the_app_running_fails_closed(self):
        runner = RecordedRunner()
        runner.quit_still_running = True
        self.run_recorded("M5.3-01", runner, accepted=False)

    def test_iperf_has_no_capture_and_snaplen_is_bounded(self):
        runner, result = self.run_recorded("IPERF3")
        self.assertFalse(any("start-capture.sh " in " ".join(c) for c in runner.commands))
        self.assertEqual(result["captureChecks"]["skipped"], "IPERF3 throughput measurement")
        script = (ROOT / "Tools/lab/tart/capture/start-capture.sh").read_text()
        self.assertRegex(script, r"tcpdump[^\n]* -s 256 ")

    def test_offline_tcpdump_reads_a_file_without_capture(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            path=Path(directory)/"en0.pcap"
            payload=b"fixture-tail-system"
            udp=struct.pack("!HHHH",1234,53,8+len(payload),0)+payload
            ip=bytes.fromhex("450000000000000040110000c0a84005c0a84001")
            ip=ip[:2]+struct.pack("!H",20+len(udp))+ip[4:]
            packet=ip+udp
            path.write_bytes(struct.pack("<IHHIIII",0xa1b2c3d4,2,4,0,0,65535,101)+struct.pack("<IIII",35,0,len(packet),len(packet))+packet)
            result=subprocess.run(["tcpdump","-nn","-tt","-A","-r",str(path),"port 53"],capture_output=True,check=False)
            self.assertEqual(result.returncode,0)
            parsed=LIVE.inspect_capture_text(result.stdout.decode(),[dict(nonce="fixture-tail",windows=[dict(start=30,end=40,state="unprotected")])])
            self.assertTrue(parsed["tailSystemResolverObserved"])
