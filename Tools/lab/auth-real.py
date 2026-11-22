#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""M03-T11 AUTH-REAL: the WGEX admin right on a real macOS 27 guest, with no right pre-allowed and no password typed into
the WGEX right's sheet.

Started by `just lab verdict AUTH-REAL --report-root DIR` (verdict-run.py hands rows with "driver": "auth-real" here) with
WGEX_LAB_VM=macos27-wgex WGEX_LAB_USER=admin WGEX_LAB_SNAPSHOT_PREFIX=macos27-. From the `macos27-base` snapshot it
checks that no WGEX right exists, builds and installs the Lab app, registers the daemon and approves its background item
by guest GUI automation (DEC-034: macOS asks for an administrator there, and the driver fills that Login Items sheet with
the image's public default from WGEX_LAB_GUEST_PASSWORD_FILE, a 0600 file under TMPDIR it removes after reading), reads the right the daemon wrote (rightDefinition, as `security authorizationdb read` returns
it), presses Secure Install and records the authentication sheet for the WGEX right (sheetShown), cancels it and records
that Secure Install stays unverified, the loosening settings write is refused (the criteria's "settings writes
refused"; the tightening write that startup recovery accepts is recorded only) and the normalised route, DNS, resolver
and pf records equal the baseline, every source readable (cancelFailsClosed). check-verdicts.py is the only judge; test_auth_real compares rightDefinition with the M01-T02
read-back fixture. The granted path is sitting check E3 (maintainer).
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "Tools/lab"
ROW = "AUTH-REAL"
SNAPSHOT = "base"
RIGHT = "com.magrathean.WGEXApp.manage-protection.dev"  # Lab builds carry the .dev right (AuthorisationTable.adminRightName).
FIXTURE = ROOT / "Packages/WGEXBackendMac/Tests/AdminRight/admin-right-readback.json"
COMPARED_KEYS = ("class", "rule", "shared", "timeout")
REPORT_LIMIT = 50000
HELPERS = ("guard.sh", "asu.sh", "auth-real.sh", "authd-lines.pl", "approve-item.applescript", "fill-sheet.applescript",
           "verdict-actions.sh", "journal-replay.pl")
CONTINUE = "wgex.onboarding.continue"
REGISTER = "wgex.onboarding.registerBackgroundService"
SECURE_INSTALL = "wgex.service.actionTitle"
ALLOW_LAN = "wgex.protection.allowLocalNetwork"
ALLOW_LAN_SETTINGS = "wgex.settings.allowLAN"
LOGIN_ITEMS_PANE = "x-apple.systempreferences:com.apple.LoginItems-Settings.extension"
SHEET_SECONDS = 45
DAEMON_SECONDS = 120
SETTLE_SECONDS = 20
APPROVE_SECONDS = 300
APPROVAL_SHEET_SECONDS = 30
TOGGLE_READS = 4
PASSWORD_FILE_ENV = "WGEX_LAB_GUEST_PASSWORD_FILE"
PASSWORD_LIMIT = 128
APPROVAL_RIGHT = "com.apple.backgroundtaskmanagement.manage-daemons"
FILL_MODES = ("set", "keys")
FILL_CLOSE_SECONDS = 30
FILL_LINE = re.compile(r"fill=(entered|no-sheet|no-field|unreadable|error|empty|unrecognised)( mode=(set|keys))?"
                       r"( field=(secure|default-focus))?( pressed=(modify|no))?")
AUTHENTICATE = re.compile(r"engine (\d+): running mechanism builtin:authenticate")
CANCELLED = re.compile(r"Failed to authorize right '" + re.escape(RIGHT) + r"' by client '([^']+)' \[\d+\] .*\(-60006\) \(engine (\d+)\)")
NET_KEYS = ("utun", "routes", "dns", "resolver", "pf", "pfReferences", "wgexAnchorRules", "wgexAnchors")
NET_PF_KEYS = ("pf", "pfReferences", "wgexAnchorRules", "wgexAnchors")
NET_SECTIONS = ("sudo",) + NET_KEYS
NET_HEADER = re.compile(r"==wgex-net (\w+) (\d+)")
NET_DIFF_LIMIT = 40
LLADDR = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,2}:){5}[0-9A-Fa-f]{1,2}(?![0-9A-Fa-f:])")
ROUTE_FAMILIES = {"Internet:": "inet", "Internet6:": "inet6"}
PF_NOISE = ("No ALTQ support in kernel", "ALTQ related functions disabled")
PF_TOKEN = re.compile(r"(\d+)\s+(\S+)\s+(\d+)\s+\d+ days \d+:\d+:\d+")
RECOVERING_MESSAGE = re.compile(r"Service is recovering\. .+")  # MacErrorCopy(.serviceRecovering).message: title + ". " + ...


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def absent(value):
    return "absent" if value is None else value


def right_differences(observed, fixture):
    """The keys of COMPARED_KEYS whose value differs between the guest's read-back and the fixture's rightDefinition; a
    key missing on one side differs from any value on the other. Each entry names the key and both values."""
    if not isinstance(observed, dict) or not isinstance(fixture, dict):
        return [dict(key="rightDefinition", fixture="object", observed=type(observed).__name__)]
    return [dict(key=key, fixture=absent(fixture.get(key)), observed=absent(observed.get(key)))
            for key in COMPARED_KEYS if (key in observed, observed.get(key)) != (key in fixture, fixture.get(key))]


def fixture_right():
    return json.loads(FIXTURE.read_text())["rightDefinition"]


def net_sections(text):
    """auth-real.sh net-state output split into its sections: each NET_SECTIONS name exactly once, with its exit code
    and raw lines; anything else is a malformed reply (ValueError)."""
    sections, current = {}, None
    for line in text.splitlines():
        header = NET_HEADER.fullmatch(line)
        if header:
            if header[1] not in NET_SECTIONS or header[1] in sections:
                raise ValueError("net-state sections")
            current = sections[header[1]] = dict(rc=int(header[2]), lines=[])
        elif current is not None:
            current["lines"].append(line)
        elif line.strip():
            raise ValueError("net-state preamble")
    if set(sections) != set(NET_SECTIONS):
        raise ValueError("net-state sections")
    return sections


def squeeze(text):
    return " ".join(LLADDR.sub("<lladdr>", text).split())


def utun_records(lines):
    names = " ".join(lines).split()
    return sorted(name for name in names if re.fullmatch(r"utun\d+", name)) if names else None


def route_records(lines):
    """netstat -rn rows as "family destination gateway flags netif". The Expire column and cloned host entries (flag W:
    the ARP and neighbour cache, which traffic alone adds and expires) are dropped; a row outside a family table or
    with fewer than four columns, or no row at all, is unreadable (None)."""
    family, records = None, []
    for line in lines:
        text = line.strip()
        if text in ROUTE_FAMILIES:
            family = ROUTE_FAMILIES[text]
            continue
        if not text or text == "Routing tables" or text.startswith("Destination "):
            continue
        fields = text.split()
        if family is None or len(fields) < 4:
            return None
        if "W" in fields[2]:
            continue
        records.append(squeeze(" ".join([family, *fields[:4]])))
    return sorted(records) or None


def dns_records(lines):
    """scutil --dns as "configuration | resolver #N | key : value" for every resolver line except reach (a live
    reachability flag); any other text is kept as it stands. Output without a DNS configuration heading is unreadable."""
    section = resolver = None
    records = []
    for line in lines:
        text = line.rstrip()
        if text.startswith("DNS configuration"):
            section, resolver = squeeze(text), None
            continue
        if number := re.fullmatch(r"resolver #(\d+)", text):
            resolver = number[1]
            continue
        pair = re.fullmatch(r"\s+(\S.*?)\s*:\s?(.*)", text)
        if pair and section and resolver:
            if pair[1] != "reach":
                records.append(f"{section} | resolver #{resolver} | {squeeze(pair[1])} : {squeeze(pair[2])}")
        elif text.strip():
            records.append(f"{section} | {squeeze(text)}")
    return sorted(records) if section else None


def resolver_records(lines):
    """/etc/resolver files as "name:" plus "name: line" for each line without comments and with whitespace squeezed;
    text before the first file heading is unreadable."""
    name, records = None, []
    for line in lines:
        if heading := re.fullmatch(r"==wgex-file (.+)", line):
            name = heading[1]
            records.append(name + ":")
            continue
        text = squeeze(line.split("#", 1)[0])
        if not text:
            continue
        if name is None:
            return None
        records.append(f"{name}: {text}")
    return sorted(records)


def pf_records(lines):
    status = [match[1] for line in lines if (match := re.match(r"Status: (\S+)", line.strip()))]
    return status[:1] or None


def reference_records(lines):
    """pfctl -s References rows as "pid process token" (the age column moves on its own); other text is kept."""
    records = []
    for line in lines:
        text = line.strip()
        if not text or text in PF_NOISE or text == "TOKENS:" or text.startswith("PID "):
            continue
        token = PF_TOKEN.fullmatch(text)
        records.append(" ".join(token.groups()) if token else squeeze(text))
    return sorted(records)


def anchor_records(lines):
    return sorted(squeeze(line) for line in lines if "wgex" in line.lower())


NET_RECORDS = dict(utun=utun_records, routes=route_records, dns=dns_records, resolver=resolver_records, pf=pf_records,
                   pfReferences=reference_records, wgexAnchors=anchor_records)


def parse_net_state(text):
    """Each NET_KEYS source as dict(status="ok", records=[...]) or dict(status="unreadable", records=[]): a non-zero
    exit, output the normaliser cannot read, or (for the pf sources) a refused sudo is unreadable. The WGEX anchor's
    rules keep pfctl's exit as a record, since an anchor that does not exist yet makes pfctl fail."""
    sections = net_sections(text)
    state = {}
    for key in NET_KEYS:
        section = sections[key]
        if key in NET_PF_KEYS and sections["sudo"]["rc"] != 0:
            records = None
        elif key == "wgexAnchorRules":
            records = sorted(squeeze(line) for line in section["lines"] if line.strip() and line.strip() not in PF_NOISE)
            records += [f"exit={section['rc']}"] if section["rc"] else []
        elif section["rc"] != 0:
            records = None
        else:
            records = NET_RECORDS[key](section["lines"])
        state[key] = dict(status="unreadable", records=[]) if records is None else dict(status="ok", records=records)
    return state


def net_comparison(before, after):
    """The keys either side could not read, the readable keys whose records differ, and those records (added and
    removed, at most NET_DIFF_LIMIT each)."""
    unreadable = [key for key in NET_KEYS if before[key]["status"] != "ok" or after[key]["status"] != "ok"]
    changed = [key for key in NET_KEYS if key not in unreadable and before[key]["records"] != after[key]["records"]]
    diff = {}
    for key in changed:
        old, new = before[key]["records"], after[key]["records"]
        diff[key] = dict(added=[item for item in new if item not in old][:NET_DIFF_LIMIT],
                         removed=[item for item in old if item not in new][:NET_DIFF_LIMIT])
        if not diff[key]["added"] and not diff[key]["removed"]:
            diff[key]["repeated"] = True
    return changed, unreadable, diff


def net_digest(state):
    return {key: dict(status=value["status"], records=len(value["records"]),
                      digest=hashlib.sha256("\n".join(value["records"]).encode()).hexdigest()[:16])
            for key, value in state.items()}


def sheet_evidence(lines):
    """From authd-lines output: the engines that ran the authentication mechanism for the WGEX right, and the cancelled
    evaluations (errAuthorizationCanceled) with their client path."""
    engines = sorted({int(match[1]) for line in lines if (match := AUTHENTICATE.search(line))})
    cancelled = [dict(engine=int(match[2]), client=match[1]) for line in lines if (match := CANCELLED.search(line))]
    return engines, cancelled


def read_guest_password(path, tmpdir):
    """The guest administrator's password for the Login Items approval sheet (DEC-034), read at the moment of use from
    PASSWORD_FILE_ENV: an absolute path to a regular file (not a link) under TMPDIR, owned by this user, mode 0600 and
    one line. The file is removed straight after reading. A refusal names the rule, never the content."""
    if not path:
        raise Failure(PASSWORD_FILE_ENV + " is not set")
    if not tmpdir:
        raise Failure("TMPDIR is not set")
    candidate = Path(path)
    if not candidate.is_absolute() or Path(tmpdir).resolve() not in candidate.resolve().parents:
        raise Failure(PASSWORD_FILE_ENV + " must name a file under TMPDIR")
    try:
        info = os.lstat(candidate)
    except OSError:
        raise Failure(PASSWORD_FILE_ENV + " names no file") from None
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise Failure(PASSWORD_FILE_ENV + " must be a regular 0600 file of this user")
    try:
        data = candidate.read_bytes()
    finally:
        candidate.unlink()
    data = data[:-1] if data.endswith(b"\n") else data
    if not data or len(data) > PASSWORD_LIMIT or b"\n" in data or b"\r" in data or b"\0" in data:
        raise Failure(PASSWORD_FILE_ENV + " must hold one non-empty line")
    return data


def redact(text, secret):
    """Captured output of the fill path with the secret replaced, so nothing derived from it reaches the verdict."""
    return text.replace(secret.decode(errors="replace"), "<redacted>") if secret else text


def fill_outcome(line):
    """The guest helper's fill line, or "unrecognised" when it is not one of the fixed forms."""
    return line if FILL_LINE.fullmatch(line) else "fill=unrecognised"


def bounded(result):
    """The verdict as JSON under REPORT_LIMIT: the authd lines are cut to 10 first, then the baseline network records
    are dropped (their digests in netBefore and netAfter stay, with any difference in netDiff)."""
    payload = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
    if len(payload) >= REPORT_LIMIT:
        result = dict(result, authdLines=result.get("authdLines", [])[-10:], truncated=True)
        payload = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
    closed = (result.get("checks") or {}).get("cancelFailsClosed") or {}
    if len(payload) >= REPORT_LIMIT and "netRecords" in closed:
        closed = {key: value for key, value in closed.items() if key != "netRecords"}
        result = dict(result, checks=dict(result["checks"], cancelFailsClosed=dict(closed, netRecordsDropped=True)))
        payload = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
    if len(payload) >= REPORT_LIMIT:
        raise ValueError("verdict over 50 KB")
    return payload


def readme(result):
    checks = result.get("checks", {})
    lines = [f"# {ROW}: admin right on a real macOS 27 guest", "",
             f"Guest: {result.get('guest')} (macOS {result.get('guestOS', {}).get('productVersion', 'unknown')}, "
             f"build {result.get('guestOS', {}).get('buildVersion', 'unknown')}); snapshot {result.get('snapshot')}; "
             f"SIP {result.get('sip', 'unknown')}.",
             f"Live acceptance: {str(result.get('liveAcceptance')).lower()}.", ""]
    for key in ("rightAbsentAtStart", "daemonWroteRight", "rightMatchesFixture", "sheetShown", "cancelFailsClosed"):
        check = checks.get(key, {})
        lines.append(f"- {key}: {'met' if check.get('met') else 'not met'}; {check.get('summary', 'not reached')}")
    filled = (result.get("approval") or {}).get("passwordEntered")
    lines += ["", "\"Settings writes refused\" means loosening writes: the Allow local network on request must be refused, with "
              "the switch read off before it and the refusal seen. The tightening write (Allow local network off) that the "
              "daemon's startup recovery accepts is by design and recorded only.",
              "The network comparison is on normalised records (routes, DNS configuration, /etc/resolver contents, pf status, "
              "references and WGEX anchors), not counts; an unreadable source fails it.",
              "", "No password was typed into the WGEX right's sheet and no right was pre-allowed. The granted path is sitting check E3.",
              ("The Login Items approval sheet (" + APPROVAL_RIGHT + ") was filled with the image's public default administrator "
               "password (DEC-034, " + str(filled) + "); it never reached a command line, log or this report.") if filled else
              "No password was entered into the Login Items approval sheet.",
              "check-verdicts.py is the judge; Tools/lab/tests/test_auth_real.py compares rightDefinition with the M01-T02 fixture.",
              "", "```sh", "export WGEX_LAB_VM=macos27-wgex WGEX_LAB_USER=admin WGEX_LAB_SNAPSHOT_PREFIX=macos27-",
              "export WGEX_LAB_GUEST_PASSWORD_FILE=\"$TMPDIR/...\"  # 0600, one line, removed by the driver after reading",
              "just lab verdict AUTH-REAL --report-root Tests/Reports/v2/macos27", "```", ""]
    for gap in result.get("gaps", []):
        lines.insert(-7, f"Gap: {gap}")
    if result.get("consoleStep"):
        approval = result.get("approval") or {}
        lines.insert(-7, f"Console step: {result['consoleStep']} (sheet closed after cancel: "
                         f"{str(approval.get('sheetClosed')).lower()}).")
    return "\n".join(lines)


def write_report(directory, result, run):
    directory.mkdir(parents=True, exist_ok=True)
    if not result["liveAcceptance"]:
        result["attempt"] = run.next_attempt(directory)
        with (directory / f"verdict-{result['attempt']}.json").open("xb") as handle:
            handle.write(bounded(result))
    (directory / "verdict.json").write_bytes(bounded(result))
    (directory / "README.md").write_text(readme(result))
    return directory / "verdict.json"


class Failure(Exception):
    """A step's own failure, with a short public reason."""


class AuthReal:
    def __init__(self, session, live):
        self.session, self.live = session, live
        self.checks = {key: dict(met=False, summary="not reached")
                       for key in ("rightAbsentAtStart", "daemonWroteRight", "rightMatchesFixture", "sheetShown", "cancelFailsClosed")}
        self.right = self.baseline = self.after = self.start_clock = None
        self.authd, self.notes, self.approval = [], [], None
        self.console_step = None
        self.toggle_reads = 0

    def act(self, action, *args, check=True, deadline=None):
        command = shlex.join(["bash", self.session.stage + "/auth-real.sh", action, *args])
        return self.session.ssh(command, check=check, deadline=deadline).decode(errors="replace").strip()

    def stage(self):
        self.session.ssh("umask 077; mkdir -p " + shlex.quote(self.session.stage))
        for name in HELPERS:
            self.session.guest_file((LAB / "tart/guest" / name).read_bytes(), name)

    def read_right(self):
        raw = self.act("right-read", RIGHT, check=False)
        code = self.session.ledger[-1].get("exitCode")
        if code == 3:
            return None
        if code != 0:
            raise Failure(f"right-read exited {code}")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise Failure("right-read returned no object")
        return value

    def wait(self, what, seconds, probe, interval=2):
        deadline = time.monotonic() + seconds
        while True:
            value = probe()
            if value:
                return value
            if time.monotonic() > deadline:
                raise Failure(f"{what} not seen within {seconds} s")
            time.sleep(interval)

    def press(self, identifier, window="1"):
        self.session.click_id(identifier, window=window)

    def daemon_running(self):
        state = self.act("daemon-state", check=False)
        return state if " state=running " in state + " " else None

    def approve_background_item(self):
        """Approve WGEX's background item in System Settings > General > Login Items & Extensions by guest GUI
        automation. macOS 27 asks for an administrator there (live run 5): the Login Items sheet on System Settings is
        filled with the guest password (DEC-034, fill_approval_sheet); any other sheet is cancelled and stops the row."""
        self.session.lab("gui", "open-pane", LOGIN_ITEMS_PANE)
        # The AX walk of System Settings is slow under host load (a full dump took over 100 s at host load 200).
        line = self.wait("WGEX background item", APPROVE_SECONDS, lambda: (lambda value: value if value.startswith("item=background-switch-") else None)(
            self.act("approve-item", check=False, deadline=APPROVE_SECONDS)), interval=3)
        self.approval = dict(item=line)
        if "pressed=yes" in line:
            # Live run 5: the sheet came up about 6 s after the press, on System Settings (not SecurityAgent); WGEX was
            # then activated over it and the row waited for a daemon that macOS had not allowed. Look before moving on.
            sheet = self.wait_approval_sheet()
            if sheet == "System Settings" and self.login_items_sheet():
                self.fill_approval_sheet()
            elif sheet:
                self.cancel_approval_sheet(sheet)
                raise Failure("approving the background item raised a password sheet (" + sheet + "; cancelled); a console step for the maintainer")
        self.session.lab("gui", "activate", "WGEX")

    def login_items_sheet(self):
        """The sheet is the Login Items approval (and so the only one DEC-034 lets the driver fill) when
        LocalAuthenticationRemoteService draws it and authd evaluated APPROVAL_RIGHT since the row started."""
        log = self.act("approval-log", self.start_clock, check=False).splitlines()
        self.approval["authd"] = log
        return self.approval.get("settings", "").endswith(" la=running") and any(APPROVAL_RIGHT in line for line in log)

    def fill_approval_sheet(self):
        """Enter the guest administrator's password into the Login Items sheet and press Modify Settings: first as the
        secure field's AXValue, then as key events if the sheet stays up. The password is read from the 0600 file at
        this moment, sent only on the guest helper's stdin and kept out of every record. If neither way closes the sheet,
        it is cancelled and the row stops: the VM console route is then the one left (follow-up B3)."""
        self.approval["sheet"] = "System Settings: Login Items (" + APPROVAL_RIGHT + ")"
        try:
            secret = read_guest_password(os.environ.get(PASSWORD_FILE_ENV), os.environ.get("TMPDIR"))
        except Failure as error:
            self.approval["passwordFile"] = str(error)
            self.cancel_approval_sheet("System Settings")
            raise Failure("the Login Items approval sheet needs the guest password: " + str(error)) from None
        attempts = self.approval["fill"] = []
        try:
            for mode in FILL_MODES:
                command = shlex.join(["bash", self.session.stage + "/auth-real.sh", "settings-sheet-fill", mode])
                try:
                    raw = self.session.ssh(command, data=secret, check=False, deadline=90).decode(errors="replace").strip()
                except (RuntimeError, OSError, self.live.RowFailure) as error:
                    raw = "fill=error " + type(error).__name__
                attempt = dict(mode=mode, outcome=fill_outcome(redact(raw, secret)))
                attempts.append(attempt)
                if attempt["outcome"].startswith("fill=entered"):
                    try:
                        self.wait("approval sheet closed", FILL_CLOSE_SECONDS, lambda: not self.approval_sheet(), interval=3)
                        attempt["sheetClosed"] = True
                    except Failure:
                        attempt["sheetClosed"] = False
                if attempt.get("sheetClosed") or attempt["outcome"] == "fill=no-sheet":
                    break
        finally:
            secret = None
        done = next((item for item in attempts if item.get("sheetClosed")), None)
        if done is None:
            self.cancel_approval_sheet("System Settings")
            raise Failure("the Login Items approval sheet did not accept the synthetic password entry ("
                          + "; ".join(item["outcome"] for item in attempts) + "; cancelled); the VM console route is next")
        self.approval["passwordEntered"] = "mode " + done["mode"]
        self.approval["sheetClosed"] = True
        self.approval["authd"] = self.act("approval-log", self.start_clock, check=False).splitlines()[-10:]
        self.approval["btm"] = self.act("btm-state", check=False).splitlines()[:6]

    def approval_sheet(self):
        """The password sheet an approval can raise: SecurityAgent's window, or a sheet on System Settings."""
        agent = self.act("agent-state", check=False)
        settings = self.act("settings-sheet", check=False)
        self.approval.update(agent=agent, settings=settings)
        if agent.startswith("agent=running windows=1"):
            return "SecurityAgent"
        match = re.fullmatch(r"settings-sheet=([1-9]\d*) la=\w+", settings)
        return "System Settings" if match else None

    def wait_approval_sheet(self):
        deadline = time.monotonic() + APPROVAL_SHEET_SECONDS
        while True:
            sheet = self.approval_sheet()
            if sheet or time.monotonic() > deadline:
                return sheet
            time.sleep(3)

    def cancel_approval_sheet(self, sheet):
        """Cancel (Escape, no text typed), confirm the sheet closed and record what authd and the background-task
        database show; this is the row's stop for a console step."""
        self.console_step = "background-item approval: " + sheet
        self.approval["sheet"] = sheet
        try:
            self.approval["cancel"] = self.act("agent-cancel" if sheet == "SecurityAgent" else "settings-sheet-cancel", deadline=60)
            self.wait("approval sheet closed", SHEET_SECONDS, lambda: not self.approval_sheet(), interval=3)
            self.approval["sheetClosed"] = True
        except (Failure, RuntimeError, OSError, self.live.RowFailure) as error:
            self.approval.update(sheetClosed=False, cancelError=type(error).__name__)
        self.approval["authd"] = self.act("approval-log", self.start_clock, check=False).splitlines()[-10:]
        self.approval["btm"] = self.act("btm-state", check=False).splitlines()[:6]
        self.approval["daemon"] = self.act("daemon-state", check=False)

    def run(self):
        session = self.session
        sip = session.ssh("csrutil status").decode(errors="replace").strip()
        self.sip = "enabled" if sip.endswith("enabled.") else "disabled" if sip.endswith("disabled.") else "unknown"
        self.stage()
        before = self.read_right()
        self.checks["rightAbsentAtStart"] = dict(met=before is None, summary="no WGEX right before install" if before is None
                                                 else "a WGEX right existed before install")
        if before is not None:
            raise Failure("a WGEX right existed before install; the snapshot is not clean")
        self.baseline = parse_net_state(self.act("net-state"))
        self.start_clock = session.ssh("date '+%Y-%m-%d %H:%M:%S'").decode().strip()
        session.lab("build", timeout=1800)
        session.installation["buildCompleted"] = True
        # A first install: no lab wrapping key; the daemon provisions its own during Secure Install (wrapping-key.sh).
        installed = session.command(["just", "lab", "install"], timeout=900, env=dict(os.environ, WGEX_WRAPPING_KEY_FALLBACK="0"))
        session.installation.update(installCompleted=True, wrappingKeyFallback=False,
                                    wrappingKey=self.live.wrapping_key_outcome(installed) if b"wrapping key present" in installed else "absent")
        session.measure_provenance()
        session.lab("gui", "run", "open", "-a", "WGEX")
        session.lab("gui", "activate", "WGEX")
        self.press(CONTINUE)  # welcome
        self.press(CONTINUE)  # background service
        self.press(REGISTER)
        self.approve_background_item()
        self.wait("daemon running", DAEMON_SECONDS, self.daemon_running)
        self.right = self.wait("WGEX right written", DAEMON_SECONDS, self.read_right)
        identifier = self.right.get("identifier")
        self.checks["daemonWroteRight"] = dict(met=identifier == "com.magrathean.WGEXApp.dev.daemon",
                                               summary=f"the right's creator identifier is {identifier}")
        differences = right_differences(self.right, fixture_right())
        self.checks["rightMatchesFixture"] = dict(met=not differences, differences=differences,
                                                  summary="class, rule, shared and timeout equal the M01-T02 fixture" if not differences
                                                  else "differs from the M01-T02 fixture: " + ", ".join(item["key"] for item in differences))
        self.wait("service step ready", DAEMON_SECONDS, lambda: self.try_press(CONTINUE))
        self.press(SECURE_INSTALL)
        agent = self.wait("authentication sheet", SHEET_SECONDS, lambda: (lambda value: value if value.startswith("agent=running windows=1") else None)(self.act("agent-state", check=False)))
        self.act("agent-cancel")
        self.wait("sheet closed", SHEET_SECONDS, lambda: self.act("agent-state", check=False) in ("agent=absent", "agent=running windows=0"))
        time.sleep(SETTLE_SECONDS)
        self.fail_closed(agent)

    def try_press(self, identifier):
        try:
            self.press(identifier)
            return True
        except (ValueError, RuntimeError, self.live.RowFailure):
            return False

    def fail_closed(self, agent):
        """sheetShown and cancelFailsClosed from authd's lines read after the cancel: on macOS 27.2 (live run 8) the
        first line naming the WGEX right in its engine is the Failed line written at the cancel, so a read while the sheet
        is up finds no engine for the right."""
        session = self.session
        lines = self.act("authd-log", self.start_clock, RIGHT, check=False).splitlines()
        engines, cancelled = sheet_evidence(lines)
        self.checks["sheetShown"] = sheet_shown(agent, engines)
        doctor_lines = session.guest_action("secure-install-status").decode(errors="replace").strip().splitlines()
        doctor = json.loads(doctor_lines[-1]) if doctor_lines else {}
        secure = doctor.get("secureInstall") if isinstance(doctor, dict) else None
        settings_write = self.settings_write()
        self.after = parse_net_state(self.act("net-state"))
        changed, unreadable, diff = net_comparison(self.baseline, self.after)
        self.authd = lines[-30:]
        met = (bool(cancelled) and isinstance(secure, str) and secure != "verified" and settings_write["refused"]
               and not changed and not unreadable)
        self.checks["cancelFailsClosed"] = dict(
            met=met, cancelledEngines=cancelled, secureInstall=secure, settingsWrite=settings_write,
            netBefore=net_digest(self.baseline), netAfter=net_digest(self.after), netChanged=changed, netUnreadable=unreadable,
            netDiff=diff, netRecords={key: value["records"] for key, value in self.baseline.items()},
            summary=fail_closed_summary(cancelled, secure, settings_write, changed, unreadable))

    def settings_write(self):
        """Settings writes after the cancel, through Settings > Network's Allow local network switch (the main window's
        Protection toggle first, as verdict-live set_allow_lan_off). Live run 7 (macOS 27.2): before Secure Install the
        daemon is in startup recovery (status phase=failed reason=backendUnavailable), where setGlobalSettings takes
        setRecoverySettings and AuthorisationTable.recoveryAllows accepts a tightening change, so Allow local network
        off is recorded (tightening) but does not decide the check. The refused write is the loosening one: Allow local
        network back on, which needs the WGEX right in the app and is refused by recovery in the daemon. Its sheet, if
        any, is cancelled like the Secure Install one (no password is typed). The daemon journal is the read-back of both.
        On is requested only after a fresh read shows the switch off, and the loosening write counts as refused only when
        the journal keeps allowLAN=false and the refusal itself was seen: the app's recovery copy appearing under the form
        (absent before the press), or a WGEX right sheet that was cancelled."""
        session = self.session
        session.lab("gui", "run", "open", "-a", "WGEX")
        session.lab("gui", "activate", "WGEX")
        control, window = ALLOW_LAN, "1"
        toggle = session.toggle_value(ALLOW_LAN)
        if toggle is None:
            window = session.open_settings()
            session.select_settings_tab(window, "Network")
            control = ALLOW_LAN_SETTINGS
            toggle = self.settings_toggle(window, control)
        record = dict(control=control, window=window, toggleBefore=toggle, toggleReads=self.toggle_reads, journalBefore=self.lan_state())
        tightening = dict(requested="allowLAN=false", pressed=False)
        if toggle is True:
            session.click_id(control, window=window)
            tightening.update(pressed=True, **self.after_press())
        record["tightening"] = tightening
        # Review finding 2: on is requested only after a fresh read shows the switch off. An unreadable switch, or one
        # still on (a stale read or a press that did not move it), would turn the press into another tightening request.
        loosening = dict(requested="allowLAN=true", pressed=False, switchBefore=self.read_switch(control, window),
                         journalBefore=self.lan_state())
        if loosening["switchBefore"] is not False:
            loosening["notPressed"] = "switch unreadable" if loosening["switchBefore"] is None else "switch not confirmed off"
        elif loosening["journalBefore"] != "allowLAN=false":
            loosening["notPressed"] = "journal not allowLAN=false"
        else:
            message_before = self.recovery_message(control, window)
            session.click_id(control, window=window)
            loosening.update(pressed=True, **self.after_press())
            message_after = self.recovery_message(control, window)
            loosening["refusal"] = dict(
                journalKept=loosening.get("journal") == "allowLAN=false", switchAfter=self.read_switch(control, window),
                messageBefore=message_before, messageAfter=message_after,
                recoveryMessage=message_before == [] and bool(message_after), sheetCancelled=bool(loosening.get("sheetCancelled")))
        record["loosening"] = loosening
        refusal = loosening.get("refusal") or {}
        record["refused"] = bool(loosening["pressed"] and refusal.get("journalKept")
                                 and (refusal.get("recoveryMessage") or refusal.get("sheetCancelled")))
        return record

    def read_switch(self, control, window):
        """A fresh read of the Allow local network switch: False as soon as a read shows it off, else the last readable
        value (True) or None, after up to TOGGLE_READS reads three seconds apart."""
        value = None
        for attempt in range(TOGGLE_READS):
            if attempt:
                time.sleep(3)
            read = self.session.toggle_value(control) if control == ALLOW_LAN else self.settings_toggle(window, control, reads=1)
            if read is False:
                return False
            value = read if read is not None else value
        return value

    def recovery_message(self, control, window):
        """The window's static texts carrying the app's refusal copy for a request the daemon turned down in recovery
        (MacErrorCopy(.serviceRecovering).message, shown under the Settings form), or None when the dump is unreadable
        (it must carry the switch's own line)."""
        try:
            dump = self.session.read_dump(window, check=False)
        except RuntimeError:
            return None
        if not re.search(r"\| id=" + re.escape(control) + r" \|", dump or ""):
            return None
        names = []
        for line in dump.splitlines():
            name = re.search(r"\| name=([^|]*?) \|", line) if line.startswith("AXStaticText |") else None
            if name and RECOVERING_MESSAGE.fullmatch(name[1]) and name[1] not in names:
                names.append(name[1][:200])
        return names

    def settings_toggle(self, window, control, reads=TOGGLE_READS):
        """The Settings switch's value, read up to reads times: live run 9's one targeted read right after the Network
        tab switch failed in System Events (an AX execution error), so the row pressed nothing."""
        for attempt in range(1, reads + 1):
            if reads > 1:
                self.toggle_reads = attempt
            try:
                value = dump_toggle(self.session.read_dump(window, check=False, identifier=control, targeted=True), control, self.live)
            except RuntimeError:
                value = None
            if value is not None:
                return value
            if attempt < reads:
                time.sleep(3)
        return None

    def lan_state(self):
        return self.session.guest_action("allow-lan-state", check=False).decode(errors="replace").strip() or "unreadable"

    def after_press(self):
        """After a settings press: a WGEX right sheet that comes up within SETTLE_SECONDS is cancelled (Escape, no text
        typed) and waited out; then the daemon journal's allowLAN is read."""
        outcome = dict(sheet="agent=absent")
        deadline = time.monotonic() + SETTLE_SECONDS
        while time.monotonic() <= deadline:
            agent = self.act("agent-state", check=False)
            if agent.startswith("agent=running windows=1"):
                outcome["sheet"] = agent
                self.act("agent-cancel")
                self.wait("settings sheet closed", SHEET_SECONDS,
                          lambda: self.act("agent-state", check=False) in ("agent=absent", "agent=running windows=0"), interval=3)
                outcome["sheetCancelled"] = True
                self.notes.append("a settings write raised an authentication sheet; it was cancelled")
                break
            time.sleep(3)
        time.sleep(5)
        outcome["journal"] = self.lan_state()
        return outcome


def sheet_shown(agent, engines):
    """SecurityAgent's window was up after the Secure Install press, and authd ran builtin:authenticate in an engine
    that evaluated the WGEX right."""
    met = agent.startswith("agent=running windows=1") and bool(engines)
    return dict(met=met, agent=agent, authenticateEngines=engines,
                summary=f"SecurityAgent sheet up ({agent}); authd ran builtin:authenticate for {RIGHT} in engine(s) {engines}"
                if met else f"no authd authentication for the WGEX right ({agent}; engines {engines})")


def fail_closed_summary(cancelled, secure, write, changed, unreadable=()):
    tightening, loosening = write.get("tightening", {}), write.get("loosening", {})
    evidence = loosening.get("refusal") or {}
    shown = ", ".join(name for name in ("recoveryMessage", "sheetCancelled") if evidence.get(name)) or "none"
    network = ("unreadable: " + ", ".join(unreadable) if unreadable else "") + ("; " if unreadable and changed else "") + \
        ("changed: " + ", ".join(changed) if changed else "")
    return (f"cancel {'recorded' if cancelled else 'not recorded'} by authd; Secure Install {secure}; loosening write (Allow local "
            f"network on) {'refused' if write.get('refused') else 'not refused'} (switch {loosening.get('switchBefore')}, "
            f"{loosening.get('journalBefore')} -> {loosening.get('journal', 'not pressed: ' + str(loosening.get('notPressed')))}; "
            f"refusal shown: {shown}); tightening write (off, recorded only: recovery accepts it) "
            f"{'-> ' + str(tightening.get('journal')) if tightening.get('pressed') else 'not pressed'}; "
            f"network records {network or 'unchanged'}")


def report_destination(completed, console_step, report_root, build_root):
    """A completed row, or a stop for a console step (the row's recorded outcome, which check-verdicts fails), goes to the
    report root; any other stop is a fault, kept out of the tree under the build root."""
    if completed or console_step is not None:
        return Path(report_root).resolve()
    return (Path(build_root) / "lab-verdict-failures").resolve()


def dump_toggle(dump, identifier, live):
    return live.dump_toggle_value(dump, identifier)

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-root", type=Path, required=True)
    args = parser.parse_args(argv)
    guest = os.environ.get("WGEX_LAB_VM", "")
    if not re.fullmatch(r"macos27-wgex", guest) or os.environ.get("WGEX_LAB_USER") != "admin":
        parser.error("AUTH-REAL runs on WGEX_LAB_VM=macos27-wgex with WGEX_LAB_USER=admin")
    os.environ["WGEX_LAB_SNAPSHOT"] = SNAPSHOT
    run = load_module("auth_real_verdict_run", LAB / "verdict-run.py")
    harness, provenance, state = run.HARNESS, run.PROVENANCE, run.STATE
    live = load_module("auth_real_live", LAB / "verdict-live.py")
    load_start = harness.host_load()
    session = live.Session(ROW, {})
    probe = AuthReal(session, live)
    result = dict(schemaVersion=1, row=ROW, date=datetime.now(timezone.utc).isoformat(), dryRun=False, guest=guest, snapshot=guest.removesuffix("wgex") + SNAPSHOT,
                  right=RIGHT, wgexSheetPasswordTyped=False, rightPreAllowed=False, grantedPath="sitting check E3 (maintainer)")
    completed = False
    gaps = []
    try:
        session.lab("restore", SNAPSHOT, timeout=harness.seconds("RESTORE"))
        session.await_guest()
        probe.run()
        initial = dict(session.provenance)
        session.measure_provenance()
        if session.provenance != initial:
            gaps.append("provenanceChanged: build or guest provenance changed during the row")
        completed = True
    except (Failure, live.RowFailure, RuntimeError, OSError, ValueError, KeyError, TypeError) as error:
        gaps.append("row stopped: " + (str(error) if isinstance(error, Failure) else type(error).__name__ + "; see the step ledger under buildRoot"))
    finally:
        warnings = session.cleanup()
    result.update(session.provenance, installation=session.installation, checks=probe.checks, sip=getattr(probe, "sip", "unknown"),
                  rightDefinition=probe.right, authdLines=probe.authd, approval=probe.approval, notes=probe.notes, cleanupWarnings=warnings,
                  buildRoot=str(session.output), rowCompleted=completed, hostLoad=harness.load_record(load_start, harness.host_load()),
                  transport="guarded Tart SSH, console-session GUI automation (asu.sh) and authd's log")
    major = str(result.get("guestOS", {}).get("productVersion", "")).split(".")[0]
    gaps.extend("Provenance: " + failure for failure in provenance.provenance_errors(result, major))
    result["approvalPasswordEntered"] = bool((probe.approval or {}).get("passwordEntered"))
    result["gaps"] = gaps
    result["expectationsMet"] = all(check.get("met") is True for check in probe.checks.values())
    result["liveAcceptance"] = completed and not gaps and result["expectationsMet"]
    for key in ("sheetShown", "cancelFailsClosed"):
        result[key] = probe.checks[key].get("met") is True
    if probe.console_step:
        result["consoleStep"] = probe.console_step
    destination = report_destination(completed, probe.console_step, args.report_root, state.build_root(ROOT))
    try:
        written = write_report(destination / ROW, result, run)
    except (OSError, ValueError, TypeError):
        sys.stderr.write("AUTH-REAL: unable to write permitted report output\n")
        return 2
    met = sum(check.get("met") is True for check in probe.checks.values())
    sys.stdout.write(f"{ROW}: {'PASS' if result['liveAcceptance'] else 'FAIL'} ({met}/{len(probe.checks)} checks met); {written}\n")
    return 0 if result["liveAcceptance"] else 1


if __name__ == "__main__":
    sys.exit(main())
