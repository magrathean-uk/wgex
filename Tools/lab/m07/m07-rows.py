#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""M07-T08b: the eleven M07 touched-screen rows of the redesigned Mac app, one row per run, in the macOS 27 guest.

  m07-rows.py ROW --report-root DIR [--attempt 1|2]
  m07-rows.py --summary DIR ROW...

Run by the lab job script through the M04-T22 row runner, after the job's restore of macos27-base, Lab build,
`just lab install` (no launchd bootstrap; the lab wrapping key as every M04 row: live run 4 showed that without it the
daemon refuses to store secrets until Secure Install, DaemonRuntimeMessage.swift:8), peer and relay start. Rows run in ROWS order and build on
each other's guest state (setup, then secure install, imports, tunnels, protection, uninstall); a row that finds the
background service not running brings it up first through the lab registration path (bring_up_service: setup or Register
Again, then AUTH-REAL's Login Items approval), and records notMeasured only when that or another precondition fails.
Every row measures build and guest provenance (verdict-live.Session.measure_provenance) at its start and again at its
end, drives only WGEX's own accessibility identifiers (WGEXAccessibility*.swift), found and read
role-agnostically by ax-find.applescript (live run 3: gui dump prints listed roles only and System Events' description is
the role description, so the setup sheet's Background service row never showed there). Text is read in one place
(ax-find's text field, Rows.read); live run 4 showed SwiftUI buttons and combined or ignored rows expose no label to
System Events in the guest, so a check that rests on such a label also takes the product state the code ties to it
(file:line in the check), and a label that alone carries a check and reads empty becomes a named gap (no acceptance)
rather than a product failure. The menu bar item's NSMenu
(menu.applescript) and, for the background-item approval, AUTH-REAL's Login Items routine. Administrator
dialogs (SecurityAgent) are typed by the self-driven guest console (DEC-034) only while SecurityAgent shows its window,
with the job's guest-only login file (WGEX_LAB_LOGIN_FILE from the row runner; live run 4: the default lab-login file names
another user).
The guest is headless (DEC-112); nothing here touches a host app or the host network.

Exit: 0 passed, 1 failed (a product check not met), 2 driver fault (the job retries once, DEC-118), 3 not measured
(precondition missing). The verdict (DIR/ROW/verdict.json, scrubbed of key shapes) names the first cause; the step ledger
stays under the build root. Synthetic tunnels carry random keys made in the guest and TEST-NET endpoints; no key is read
back to the host: key fields are compared by digest inside the guest dump only and never written.
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
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
LAB = ROOT / "Tools/lab"
ROWS = {
    "M07-SETUP": "Three-step onboarding to running service",
    "M07-SECURE-INSTALL": "Secure install from Background Service",
    "M07-IMPORT-CONF": ".conf import through Review",
    "M07-IMPORT-ZIP": "Multi-tunnel zip tick list through Review",
    "M07-CREATE-EMPTY": "Create Empty Tunnel and Generate keypair",
    "M07-EDIT-TEXT": "Edit as Text round trip",
    "M07-TUNNEL-ACTIONS": "Tunnel-page activate and deactivate",
    "M07-MENU-ACTIONS": "Menu activate and deactivate",
    "M07-MENU-LIVE": "Open menu live detail lines and rates",
    "M07-PROTECTION": "Protection settings with administrator sheet",
    "M07-UNINSTALL": "Uninstall from Background Service",
}
EXIT = dict(passed=0, failed=1, driverFault=2, notMeasured=3)
GUEST_HELPERS = (("tart/guest", "guard.sh"), ("tart/guest", "asu.sh"), ("tart/guest", "verdict-actions.sh"),
                 ("tart/guest", "profile-id.sh"), ("tart/guest", "journal-replay.pl"), ("tart/guest", "gap-actions.sh"),
                 ("uninstall", "guest-uninstall.sh"), ("m07", "menu.applescript"), ("m07", "ax-find.applescript"))
# The lab peer's split profile (Tools/lab/profile.sh default): the tunnel the activation rows use.
LAB_TUNNEL = "wgex-lab-default"
PEER_ADDRESS = "10.77.0.1"
# Settings pages in the unified window's sidebar (MacSettingsTab.sidebarPages) and an identifier only that page shows.
PAGES = {"general": ("wgex.settings.hideDockIcon", 0), "protection": ("wgex.protection.lockdown", 1),
         "service": ("wgex.service.uninstallOpen", 2)}
SERVICE_RUNNING = "Running"
INSTALL_VERIFIED = "Verified"
# Bounds (seconds). The approval waits match AUTH-REAL and the UNINSTALL row.
APP_SECONDS = 60
SERVICE_SECONDS = 180
ADMIN_SECONDS = 300
TUNNEL_SECONDS = 90
SHEET_SECONDS = 45
SETTLE_SECONDS = 2
MENU_GAP_SECONDS = 4
TEXT = re.compile(r"[A-Za-z0-9 ./=:,_-]{1,80}")
DUMP_LINE = re.compile(r"^(AX[A-Za-z]+) \| name=(.*?) \| value=(.*?) \| desc=(.*?) \| id=([^|\n]*?) \| "
                       r"pos=(-?\d+),(-?\d+) size=(\d+)x(\d+)(?: en=(\S+))?\s*$")
FIND_FIELDS = ("role", "value", "label", "title", "enabled", "frame", "contains", "text", "attrs")
MENU_LINE = re.compile(r"^item=(.*)\tmark=(.*)\tenabled=(\S*)$")
TRANSFER = re.compile(r"^(Download|Upload): (\S+(?: \S+)?/s|Unavailable) \((\d+(?:\.\d+)? [kMGT]?B|Unavailable)\)$")
KEY_SHAPE = re.compile(r"[A-Za-z0-9+/]{43}=")
# Tools/lab/tart/guest/profile-id.sh: the only names it resolves.
PROFILE_NAME = re.compile(r"wgex-lab-[a-z0-9-]+")


class Precondition(Exception):
    """The row's starting state is missing: notMeasured."""


class ProductFailure(Exception):
    """A product check was not met: failed, with this first cause."""


# Pure parts (Tools/lab/tests/test_m07_rows.py).

def elements(dump):
    """The dump's element lines as dicts (role, name, value, desc, id, frame, enabled); lines that do not parse are skipped."""
    found = []
    for line in (dump or "").splitlines():
        match = DUMP_LINE.match(line)
        if match:
            role, name, value, desc, ident, x, y, w, h, enabled = match.groups()
            found.append(dict(role=role, name=name, value=value, desc=desc, id=ident.strip(), frame=(int(x), int(y), int(w), int(h)),
                              enabled=enabled))
    return found


def by_id(dump, identifier, prefix=False):
    """Elements whose identifier is exactly identifier (or starts with it when prefix)."""
    return [item for item in elements(dump) if (item["id"].startswith(identifier) if prefix else item["id"] == identifier)]


def text_of(item):
    """The readable text of one element: its value, else its description, else its name (System Events order)."""
    for key in ("value", "desc", "name"):
        value = item.get(key) or ""
        if value and value != "missing value":
            return value
    return ""


def found(text):
    """ax-find.applescript output as a dict (role, value, label, title, enabled, frame (x, y, w, h) or None, contains
    True/False/None), or None when the element was not found or the output did not parse."""
    first = next((line for line in (text or "").splitlines() if line.startswith("ax-find=")), "")
    parts = first.split("\t")
    if parts[0] != "ax-find=found":
        return None
    item = dict(role="", value="", label="", title="", enabled="", frame=None, contains=None, text="", attrs="")
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
    """The readable texts of a found element in reading order, each once: AXValue (unless omitted), AXTitle,
    AXDescription, then ax-find's text (those, AXValueDescription, AXHelp, else the descendants' texts)."""
    if not item:
        return []
    values = [item.get("value"), item.get("title"), item.get("label"), item.get("text")]
    readable = []
    for value in values:
        if value and value not in ("missing value", "<omitted>") and value not in readable:
            readable.append(value)
    return readable


def label_check(name, label, expected, state, state_summary, summary):
    """A check that rests on a control's label: met by the label when it is readable, else by the product state the code
    derives that label from (state_summary names it with file:line)."""
    if label:
        return check(name, label == expected if isinstance(expected, str) else expected(label), f"{summary} ({label!r})")
    return check(name, state, f"{summary} (label not exposed to accessibility; {state_summary})")


def text_check(name, text, met, summary):
    """A check that only a shown text can carry: (check, None) when the text is readable, else (None, gap): a named gap
    keeps the row from acceptance without calling the product failed."""
    if text:
        return check(name, met(text), f"{summary} ({text[:80]!r})"), None
    return None, f"{name}: {summary}: the text is not exposed to accessibility in the guest; not measured"


def centre(frame):
    x, y, w, h = frame
    return x + w // 2, y + h // 2


def public_key_digest(dump, frame=None):
    """SHA-256 of the public key shown inside the editor's wgex.editor.publicKey row (its child text), or None. The row's
    frame comes from the dump, else from frame (ax-find, when the row's role is not one gui dump prints). The key itself
    is never returned or written."""
    rows = by_id(dump, "wgex.editor.publicKey")
    if len(rows) == 1:
        frame = rows[0]["frame"]
    elif rows or frame is None:
        return None
    gx, gy, gw, gh = frame
    for item in elements(dump):
        x, y, w, h = item["frame"]
        text = text_of(item)
        if item["role"] == "AXStaticText" and gx <= x and gy <= y and x + w <= gx + gw and y + h <= gy + gh and KEY_SHAPE.fullmatch(text):
            return hashlib.sha256(text.encode()).hexdigest()
    return None


FOCUS_SCRIPT = ('tell application "System Events" to tell process "WGEX"\n'
                'try\nset f to value of attribute "AXFocusedUIElement"\non error\nreturn "focus=none"\nend try\n'
                'if f is missing value then return "focus=none"\n'
                'set out to "focus=found"\n'
                'try\nset out to out & tab & "role=" & (value of attribute "AXRole" of f as text)\nend try\n'
                'set e to f\nrepeat with n from 0 to 2\nset i to ""\n'
                'try\nset i to value of attribute "AXIdentifier" of e as text\nend try\n'
                'set out to out & tab & "id" & n & "=" & i\n'
                'try\nset e to value of attribute "AXParent" of e\non error\nexit repeat\nend try\nend repeat\n'
                'return out\nend tell')


def focus_reading(raw):
    """FOCUS_SCRIPT's line as dict(role, ids) (the focused element's identifier first, then its parent's and grandparent's),
    or None when nothing is focused."""
    line = next((line for line in (raw or "").splitlines() if line.startswith("focus=")), "")
    parts = line.split("\t")
    if parts[0] != "focus=found":
        return None
    fields = dict(part.split("=", 1) for part in parts[1:] if "=" in part)
    ids = [fields[key] for key in ("id0", "id1", "id2") if fields.get(key) and fields[key] != "missing value"]
    return dict(role=fields.get("role", ""), ids=ids)


def focus_on(reading, identifier):
    return bool(reading) and identifier in reading["ids"]


def describe_focus(reading):
    return "nothing" if not reading else f"{reading['role'] or 'unknown role'} {'/'.join(reading['ids']) or 'without id'}"


def window_name(dump):
    match = re.search(r"(?m)^AXWindow \| name=([^|\n]*?)\s*\|", dump or "")
    return match[1].strip() if match else ""


def menu_items(text):
    """menu.applescript read output as (title, checked, enabled) triples; None when the read did not finish."""
    lines = (text or "").splitlines()
    if not lines or lines[-1].strip() != "menu=read":
        return None
    items = []
    for line in lines[:-1]:
        match = MENU_LINE.match(line)
        if match:
            items.append((match[1], match[2] not in ("", "missing value"), match[3] == "true"))
    return items


def transfer_lines(items):
    """The Download and Upload detail lines of a menu read: {name: (rate, total)}."""
    found = {}
    for title, _, _ in items or []:
        match = TRANSFER.match(title.strip())
        if match:
            found[match[1]] = (match[2], match[3])
    return found


def live_checks(first, second, tunnel):
    """MENU-LIVE: the ticked tunnel row, its detail lines in both reads, and transfer totals that moved between them."""
    def ticked(items):
        return any(title == tunnel and checked for title, checked, _ in items or [])

    def has(items, label):
        return any(title.strip().startswith(label + ": ") and title.strip() != label + ": Unavailable" for title, _, _ in items or [])

    a, b = transfer_lines(first), transfer_lines(second)
    moved = any(a.get(name, (None, None))[1] != b.get(name, (None, None))[1] for name in ("Download", "Upload") if name in a and name in b)
    return [
        check("tunnelTicked", ticked(first) and ticked(second), "the active tunnel's menu row carries the check mark in both reads"),
        check("statusLine", any(title.startswith("Status: ") for title, _, _ in first or []), "the menu leads with a Status line"),
        check("interfaceLine", has(first, "Interface") and has(second, "Interface"), "Interface detail line with a value"),
        check("handshakeLine", has(first, "Handshake") and has(second, "Handshake"), "Handshake detail line with a value"),
        check("rateLines", set(a) == set(b) == {"Download", "Upload"} and all("/s" in rate for rate, _ in list(a.values()) + list(b.values())),
              "Download and Upload lines show a rate per second and a total in both reads"),
        check("ratesLive", moved, f"a transfer total changed between two reads {MENU_GAP_SECONDS} s apart while traffic ran"),
        check("killSwitchLine", any(title.strip() == "Kill Switch: On" for title, _, _ in first or []), "Kill Switch: On line"),
    ]


def check(name, met, summary):
    return dict(name=name, met=bool(met), summary=summary)


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
    """Key shapes never leave the guest; anything that looks like one is cut before a report is written."""
    return KEY_SHAPE.sub("<redacted>", text)


def synthetic_conf_script(directory, names, start):
    """Guest shell that writes one synthetic tunnel per name (random keys from the guest's urandom, TEST-NET endpoint,
    private 10.200+ addresses), 0600, never printed. start numbers the address blocks so names never share one."""
    lines = ["set -eu", "umask 077", f"mkdir -p {shlex.quote(directory)}"]
    for offset, name in enumerate(names):
        n = start + offset
        path = shlex.quote(f"{directory}/{name}.conf")
        lines.append(
            "k=$(head -c 32 /dev/urandom | base64); p=$(head -c 32 /dev/urandom | base64); "
            f"printf '[Interface]\\nPrivateKey = %s\\nAddress = 10.{200 + n % 50}.{n // 50}.2/32\\n\\n[Peer]\\nPublicKey = %s\\n"
            f"AllowedIPs = 10.{200 + n % 50}.{n // 50}.0/24\\nEndpoint = 192.0.2.{1 + n % 250}:51820\\n' \"$k\" \"$p\" > {path}")
    return "; ".join(lines)


def tunnel_name(base, attempt):
    """The name of a tunnel a row adds. It must sit in the wgex-lab- namespace: profile-id.sh answers only for names
    matching ^wgex-lab-[a-z0-9-]+$ (live run 5: m07-<base> names never resolved, so CREATE-EMPTY's save, IMPORT-ZIP's
    ticked tunnels and EDIT-TEXT's synthetic tunnel all read as not stored)."""
    name = f"wgex-lab-m07-{base}-a{attempt}"
    if not PROFILE_NAME.fullmatch(name):
        raise ValueError("tunnel names must match profile-id.sh's pattern")
    return name


def with_login_file(console, login_file):
    """Hands the console's administrator step the job's guest-only login file (a path; the password never passes through
    this process). console.py defaults to the VM owner's lab-login file, which names another user than the macOS 27 guest's
    admin (live run 4: "login file names another user")."""
    if console is None or not login_file:
        return console
    popen = console.popen
    console.popen = lambda argv, **kwargs: popen(list(argv) + ["--login-file", login_file], **kwargs)
    return console


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# Live driver.

class Rows:
    def __init__(self, session, live, auth, attempt):
        self.session, self.live, self.auth, self.attempt = session, live, auth, attempt
        self.checks, self.notes, self.gaps = [], [], []
        self.approvals = []
        self.auth_failure = RuntimeError

    # Guest plumbing.
    def stage(self):
        self.session.ssh("umask 077; mkdir -p " + shlex.quote(self.session.stage))
        for folder, name in GUEST_HELPERS:
            self.session.guest_file((LAB / folder / name).read_bytes(), name)

    def services(self):
        return self.session.uninstall_fields("services")

    def service_running(self):
        state = self.services()
        return state.get("launchdJob") == "present" and str(state.get("daemonPid", "")).isdigit()

    def profile_id(self, name):
        raw = self.session.guest_action("profile-id", name, check=False).decode(errors="replace").strip()
        return raw if re.fullmatch(self.live.UUID_PATTERN, raw) else None

    def protection(self):
        try:
            return self.session.status(budget=20)["protection"]
        except (RuntimeError, ValueError):
            return None

    def wait(self, what, seconds, probe, interval=2):
        deadline = time.monotonic() + seconds
        while True:
            value = probe()
            if value:
                return value
            if time.monotonic() > deadline:
                return None
            time.sleep(interval)

    # GUI plumbing.
    def open_app(self):
        self.session.lab("gui", "run", "open", "-a", "WGEX")
        self.session.lab("gui", "activate", "WGEX")
        if not self.wait("main window", APP_SECONDS, lambda: "AXWindow" in self.dump("wgex.main.surface")):
            raise RuntimeError("WGEX showed no window after open -a")

    def dump(self, identifier=None, window="1"):
        """One dump of the main window (sheets included): the helper's targeted walk for identifier (the AXWindow line and
        the first element carrying it; full walks of the main window took minutes under load), else the full walk."""
        try:
            return self.session.walk_read(window, identifier, check=False)
        except RuntimeError:
            return ""

    def find(self, identifier, contains=None, window="1"):
        """The element carrying identifier, whatever its role (ax-find.applescript in the console session), as found()'s
        dict; None when it is not shown. With contains, only whether its text holds that string comes back (contains)."""
        args = [self.session.stage + "/ax-find.applescript", "WGEX", window, identifier] + (["contains", contains] if contains else [])
        try:
            raw = self.session.lab("gui", "run", "osascript", *args, check=False).decode(errors="replace")
        except RuntimeError:
            return None
        self.find_log(identifier, raw)
        return found(raw)

    def find_log(self, identifier, raw):
        """Every ax-find answer (attributes, text, frame), scrubbed, kept under the build root for diagnosis only."""
        try:
            with open(Path(self.session.output) / f"ax-find-a{self.attempt}.log", "a") as log:
                log.write(f"{stamp()} {identifier}\t{scrub(raw.strip())}\n")
        except (OSError, TypeError):
            pass

    def await_id(self, identifier, seconds=SHEET_SECONDS, prefix=False):
        """The element carrying identifier (found()'s dict) once it shows, or None at the bound. A prefix needs the full
        dump and returns it (the tick list's rows are check boxes, a role gui dump prints)."""
        if prefix:
            return self.wait(identifier, seconds, lambda: (lambda d: d if by_id(d, identifier, prefix) else None)(self.dump()))
        return self.wait(identifier, seconds, lambda: self.find(identifier))

    def shown(self, identifier):
        return self.find(identifier) is not None

    def read(self, identifier):
        """The text of one element, read in one place (texts(): value, title, label, then ax-find's text); "" when it
        shows but exposes no text, None when it is not shown."""
        item = self.find(identifier)
        if item is None:
            return None
        return (texts(item) or [""])[0]

    def keep_dump(self, name):
        """A full dump of the main window, scrubbed, kept under the build root for diagnosis (never in the verdict)."""
        try:
            path = Path(self.session.output) / f"{name}-a{self.attempt}.txt"
            path.write_text(scrub(self.dump()))
            self.notes.append(f"window dump kept at {path.name} under the build root")
        except (OSError, TypeError):
            pass

    def measure_text(self, name, text, met, summary):
        item, gap = text_check(name, text, met, summary)
        if item:
            self.checks.append(item)
        else:
            self.gaps.append(gap)

    def shot(self, name):
        """M07-T15: a full-screen guest capture kept under the row's build-root folder (best effort; never fails a row)."""
        path = Path(self.session.output) / f"shot-{name}-a{self.attempt}.png"
        try:
            self.session.lab("gui", "shot", str(path))
            self.notes.append(f"screenshot {name}: {path}")
        except (RuntimeError, OSError, ValueError) as error:
            self.notes.append(f"screenshot {name} failed: {type(error).__name__}")

    def appearance(self, dark):
        """M07-T17: switch the guest's appearance through System Events inside the guest (never the host); best effort."""
        script = f'tell application "System Events" to tell appearance preferences to set dark mode to {"true" if dark else "false"}'
        try:
            self.session.lab("gui", "run", "osascript", "-e", script)
            time.sleep(SETTLE_SECONDS)
            return True
        except (RuntimeError, OSError, ValueError) as error:
            self.notes.append(f"appearance {'dark' if dark else 'light'} failed: {type(error).__name__}")
            return False

    def shot_modes(self, name):
        """M07-T17: the same screen in light and then dark (guest appearance), back to light afterwards."""
        self.appearance(False)
        self.shot(f"{name}-light")
        if self.appearance(True):
            self.shot(f"{name}-dark")
        self.appearance(False)

    def after_save_state(self, name, tag):
        """M07-T15 diagnostic for CREATE-EMPTY: whether WGEX still runs, the sheet, alert and window lines in front, the
        stored profile names in the guest's profiles directory and a screenshot, all into notes (scrubbed, no key text)."""
        def note(text):
            self.notes.append(scrub(f"{tag}: {text}")[:900])
        try:
            alive = self.session.ssh("pgrep -lx WGEX || echo not-running").decode(errors="replace").strip()
        except (RuntimeError, OSError, ValueError) as error:
            alive = f"unreadable ({type(error).__name__})"
        note(f"WGEX process: {alive}")
        dump = self.dump()
        fronts = [line for line in dump.splitlines() if re.match(r"AX(Sheet|Dialog|SystemDialog|Alert|Window)\b", line)]
        note(f"sheet/alert/window lines: {len(fronts)}: " + " || ".join(line[:160] for line in fronts[:6]))
        statics = [line for line in dump.splitlines() if line.startswith("AXStaticText |")]
        note(f"static texts in the dump: {len(statics)}: " + " || ".join(" ".join(line.split("|")[1:3]).strip()[:80] for line in statics[:14]))
        ids = sorted({m[1].strip() for m in (re.search(r"\| id=([^|]*)", line) for line in dump.splitlines()) if m and m[1].strip()})
        note(f"ids shown ({len(ids)}): " + ", ".join(ids[:40]))
        self.keep_dump(f"{tag}-dump")
        try:
            listing = self.session.ssh(
                'd="$HOME/Library/Application Support/WGEX/profiles"; ls -l "$d" 2>&1 | head -20; '
                'for f in "$d"/*.json; do [ -e "$f" ] && printf "name=%s file=%s\\n" "$(plutil -extract profile.name raw -o - "$f" 2>&1)" "$(basename "$f")"; done; true'
            ).decode(errors="replace")
        except (RuntimeError, OSError, ValueError) as error:
            listing = f"unreadable ({type(error).__name__})"
        note(f"stored profiles (expected name {name}): " + " | ".join(listing.strip().splitlines())[:700])
        self.shot(tag)

    def prime_capture(self):
        """M07-T15: the first guest screencapture raises a screen-recording permission dialog for com.apple.sshd-session that
        covers the window and may take keystrokes; take one capture, press Allow when that dialog shows (guest only), note it."""
        self.shot("prime")
        time.sleep(3)  # the dialog appears a moment after the capture
        # Every process, background ones included (the dialog belongs to a system agent): press the Allow button of the first window
        # that has one, and say which process owned it.
        script = ('tell application "System Events"\nrepeat with p in (every process)\ntry\nrepeat with w in (every window of p)\n'
                  'if exists (button "Allow" of w) then\nclick button "Allow" of w\nreturn "allowed in " & name of p\nend if\n'
                  'try\nif exists (button "Allow" of group 1 of w) then\nclick button "Allow" of group 1 of w\nreturn "allowed in group of " & name of p\nend if\nend try\n'
                  'end repeat\nend try\nend repeat\nreturn "no permission dialog"\nend tell')
        try:
            out = self.session.lab("gui", "run", "osascript", "-e", script, check=False).decode(errors="replace").strip()
        except (RuntimeError, OSError, ValueError) as error:
            out = f"failed ({type(error).__name__})"
        self.notes.append(f"capture permission dialog: {scrub(out)[:160]}")
        time.sleep(SETTLE_SECONDS)
        self.shot("prime-after")

    def editor_probe(self, tag):
        """M07-T15 diagnostic for EDIT-TEXT: which editor controls exist now, and the text view's size and markers (never its
        text: it holds the private key). Into notes."""
        state = {i: bool(self.shown(i)) for i in ("wgex.editor.save", "wgex.editor.editAsText", "wgex.editor.editAsForm", "wgex.main.editProfile")}
        view = self.find("wgex.editor.configurationText")
        has = lambda marker: bool(self.find("wgex.editor.configurationText", contains=marker))
        extra = (f"text view frame {view['frame']}, [Interface] {has('[Interface]')}, MTU = 1380 {has('MTU = 1380')}" if view else "no text view")
        self.notes.append(scrub(f"{tag}: " + ", ".join(f"{k.split('.', 1)[1]}={v}" for k, v in state.items()) + f"; {extra}")[:600])

    def press(self, identifier):
        self.session.click_id(identifier)
        time.sleep(SETTLE_SECONDS)

    def type_into(self, identifier, text, replace=True):
        """Focus a text control by a click at its frame centre (inside the window), then type plain text (no key shapes)."""
        if not TEXT.fullmatch(text):
            raise ValueError("typed text must be plain")
        item = self.find(identifier)
        if not item or not item["frame"]:
            raise ValueError("missing accessible control")
        x, y = centre(item["frame"])
        self.session.lab("gui", "click", str(x), str(y))
        self.ensure_focus(identifier, "after click")
        if replace:
            self.session.keystroke("a", command=True)
        self.session.keystroke(text)

    def focused(self):
        """M07-T16: the WGEX element with the keyboard focus, read through AXFocusedUIElement (not through typed text, which
        ax-find's contains cannot show): its role and the identifiers of it and its two ancestors (a text editor's id sits on
        its scroll area). None when nothing is focused or the read fails."""
        try:
            raw = self.session.lab("gui", "run", "osascript", "-e", FOCUS_SCRIPT, check=False).decode(errors="replace")
        except (RuntimeError, OSError, ValueError):
            return None
        return focus_reading(raw)

    def ensure_focus(self, identifier, tag):
        """The keyboard focus is on identifier (or a child of it) before anything is typed. A click that did not take it is a
        driver matter: give the focus through AXFocused (ax-find focus) and read it again. Notes say which path held."""
        reading = self.focused()
        if focus_on(reading, identifier):
            self.notes.append(f"focus {tag}: on {identifier} ({reading['role']})")
            return True
        args = [self.session.stage + "/ax-find.applescript", "WGEX", "1", identifier, "focus"]
        try:
            raw = self.session.lab("gui", "run", "osascript", *args, check=False).decode(errors="replace")
        except RuntimeError:
            raw = ""
        self.find_log(identifier, raw)
        time.sleep(1)
        again = self.focused()
        held = focus_on(again, identifier)
        self.notes.append(scrub(f"focus {tag}: click left it on {describe_focus(reading)}; AX focus {'took' if held else 'did not take'}"
                                f" ({describe_focus(again)})")[:300])
        return held

    def key(self, code, modifiers=""):
        using = f" using {{{modifiers}}}" if modifiers else ""
        self.session.lab("gui", "run", "osascript", "-e", f'tell application "System Events" to key code {int(code)}{using}')

    def sidebar_select(self, index, verify, marker):
        """Select the sidebar row at index (tunnels first, then the Settings pages) with arrow keys (SwiftUI rows ignore
        AXPress, L14): up to the first row, then down; verify(dump) on a targeted walk for marker confirms the page."""
        self.session.lab("gui", "activate", "WGEX")
        self.session.lab("gui", "keys", "WGEX", "1", "wgex.main.profiles", "up", "64", "fallback")
        if index:
            self.session.lab("gui", "keys", "WGEX", "1", "wgex.main.profiles", "down", str(index), "fallback")
        dump = self.wait("sidebar selection", 20, lambda: (lambda d: d if verify(d) else None)(self.dump(marker)))
        if not dump:
            raise ValueError("sidebar selection did not show the page")
        return dump

    def tunnels(self, dump=None):
        return [item["id"].removeprefix("wgex.main.tunnel.") for item in by_id(dump or self.dump(), "wgex.main.tunnel.", prefix=True)]

    def select_tunnel(self, uuid, name):
        """The tunnel page of uuid: its sidebar row by arrow keys; the window (titled with the tunnel) shows its action."""
        order = self.tunnels()
        if uuid not in order:
            raise ValueError("tunnel row missing from the sidebar")
        return self.sidebar_select(order.index(uuid), lambda d: bool(by_id(d, "wgex.main.action")) and name in window_name(d),
                                   "wgex.main.action")

    def open_page(self, page):
        """A Settings page of the sidebar: a click at the centre of its sidebar title (an AXStaticText that ignores AXPress;
        live run 4: the press failed with "missing or ambiguous accessible control" and the arrow-key fallback missed),
        then the arrow keys as before."""
        marker, offset = PAGES[page]
        self.session.lab("gui", "activate", "WGEX")
        tab = self.find("wgex.settings.tab." + page)
        if tab and tab["frame"]:
            x, y = centre(tab["frame"])
            self.session.lab("gui", "click", str(x), str(y))
            shown = self.await_id(marker, 10)
            if shown:
                return shown
        return self.sidebar_select(len(self.tunnels()) + offset, lambda d: bool(by_id(d, marker)), marker)

    def value(self, dump, identifier):
        found = by_id(dump, identifier)
        return text_of(found[0]) if found else None

    def admin(self, done, seconds=ADMIN_SECONDS):
        """Wait for done() while the console types the administrator approval once SecurityAgent shows its window.
        Returns (sheetSeen, consoleResult, done value)."""
        deadline, approval_deadline, started, value = time.monotonic() + seconds, time.time() + seconds, False, None
        try:
            while time.monotonic() < deadline:
                if not started:
                    started = self.session.console_approval(approval_deadline)
                value = done()
                if value:
                    break
                time.sleep(2)
        finally:
            step = self.session.console_finish()
        result = step.get("result") if step else "notStarted"
        self.approvals.append(dict(sheetSeen=started, console=result))
        return started, result, value

    def menu(self, *args):
        output = self.session.lab("gui", "run", "osascript", self.session.stage + "/menu.applescript", *args, check=False)
        return output.decode(errors="replace")

    def ensure_service(self):
        """Every row after M07-SETUP needs the running service; when it is not running (M07-SETUP failed or did not run),
        the row brings it up itself through the lab registration path instead of depending on M07-SETUP."""
        if self.service_running():
            return
        try:
            self.bring_up_service()
        except (self.auth_failure, self.live.RowFailure, RuntimeError, ValueError, OSError) as error:
            raise Precondition(f"the background service was not running and the lab registration path failed: {error}"[:300]) from None
        if not self.service_running():
            raise Precondition("the background service was not running and did not start after the lab registration path")
        self.notes.append("the background service was not running at the row's start; brought up through the lab registration path")

    def bring_up_service(self):
        """The lab registration path (ready-snapshot.py, AUTH-REAL, verdict-live's uninstall_reinstall): open WGEX; on
        first-run setup, Continue to step 2 (entering it registers the service; Register Again only when offered), else
        Background Service > Register Again; then the background item is approved in Login Items & Extensions
        (AuthReal.approve_background_item, DEC-034) and the daemon awaited. Setup is then finished with Continue and
        Not Now so the row starts on the main window."""
        self.auth.approval, self.auth.start_clock = {}, self.session.ssh("date '+%Y-%m-%d %H:%M:%S'").decode().strip()
        self.open_app()
        setup = self.await_id("wgex.onboarding.surface", 10)
        if setup:
            if not self.find("wgex.onboarding.openSystemSettings"):
                self.press("wgex.onboarding.continue")
                if not self.await_id("wgex.onboarding.openSystemSettings"):
                    raise ValueError("setup step 2 did not appear after Continue")
            if self.shown("wgex.onboarding.registerBackgroundService"):
                self.press("wgex.onboarding.registerBackgroundService")
        else:
            self.open_page("service")
            self.press("wgex.settings.reRegisterBackgroundService")
        self.auth.stage()
        self.auth.approve_background_item()
        if not self.wait("service running", SERVICE_SECONDS, self.service_running, interval=3):
            raise ValueError("the daemon did not run after the background item approval")
        if setup:
            for _ in range(5):
                if self.find("wgex.importReview.createEmpty"):
                    self.press("wgex.importReview.cancel")  # Not Now
                    break
                if self.find("wgex.onboarding.continue"):
                    self.press("wgex.onboarding.continue")
                time.sleep(3)

    def import_file(self, path):
        """Hand one file to WGEX as Finder would (onOpenURL routes it to Add a Tunnel and its review)."""
        self.session.lab("gui", "run", "open", "-a", "WGEX", path)

    def synthetic(self, names, start):
        directory = f"/Users/{self.live.GUEST_USER}/lab/m07"
        self.session.ssh(synthetic_conf_script(directory, names, start))
        return directory

    def name(self, base):
        return tunnel_name(base, self.attempt)

    def ensure_tunnel(self, base, start):
        """A synthetic tunnel for rows that edit one: imported through Review once, reused afterwards."""
        name = self.name(base)
        uuid = self.profile_id(name)
        if uuid:
            return name, uuid
        directory = self.synthetic([name], start)
        self.import_file(f"{directory}/{name}.conf")
        if not self.await_id("wgex.importReview.importLabel"):
            raise ValueError("review sheet did not open for the synthetic tunnel")
        self.press("wgex.importReview.importLabel")
        uuid = self.wait("profile stored", 30, lambda: self.profile_id(name))
        if not uuid:
            raise Precondition(f"the synthetic tunnel {name} could not be added")
        return name, uuid

    # Rows.
    def setup(self):
        self.auth.approval, self.auth.start_clock = {}, self.session.ssh("date '+%Y-%m-%d %H:%M:%S'").decode().strip()
        if self.service_running():
            raise Precondition("the background service already runs; the row needs a fresh install")
        self.open_app()
        welcome = self.await_id("wgex.onboarding.surface", APP_SECONDS)
        if not welcome:
            self.checks.append(check("welcomeShown", False, "first launch shows the setup sheet on its Welcome step"))
            self.keep_dump("setup-welcome")
            raise ProductFailure("the setup sheet did not appear on first launch (wgex.onboarding.surface)")
        step = self.find("wgex.onboarding.step")
        words = texts(welcome) + texts(step)
        # The sheet has three steps (MacOnboardingView.swift:38-63): only step 2 shows Open System Settings… and the
        # service row, only step 3 the Add a Tunnel rows; with no title exposed (live run 4), Welcome is the step left.
        later = self.find("wgex.onboarding.openSystemSettings") or self.find("wgex.importReview.createEmpty")
        on_welcome = any("Welcome" in text or "1 of" in text for text in words) or (not words and not later)
        self.checks.append(check("welcomeShown", on_welcome and not later,
                                 "first launch shows the setup sheet on its Welcome step (" +
                                 ("; ".join(words)[:120] if words else "title not exposed; neither step 2 nor step 3 controls shown") + ")"))
        self.press("wgex.onboarding.continue")
        # Step 2 alone shows the Background service row and Open System Settings… (MacOnboardingView).
        step2 = self.await_id("wgex.onboarding.serviceState")
        settings = self.find("wgex.onboarding.openSystemSettings")
        self.checks.append(check("serviceStepShown", step2 and settings,
                                 "Continue leads to Allow WGEX in the Background with the service row and Open System Settings…"))
        if not step2 and not settings:
            self.keep_dump("setup-step2")
            raise ProductFailure("step 2 (wgex.onboarding.serviceState) did not appear after Continue")
        if not step2:
            self.keep_dump("setup-step2")
            self.notes.append("step 2 showed Open System Settings… but ax-find did not find wgex.onboarding.serviceState")
        if self.shown("wgex.onboarding.registerBackgroundService"):
            self.notes.append("Register Again was offered on step 2 and pressed once")
            self.press("wgex.onboarding.registerBackgroundService")
        # Continue is held until the service runs: disabled unless serviceState == .enabled && daemonRunning
        # (MacOnboardingView.swift:106, MacShellModel.swift:414-417), the same pair the row's word Running needs
        # (MacPreferences.swift:110-113). Live run 4: the row's value read '' while Continue ended enabled.
        gate_before = (self.find("wgex.onboarding.continue") or {}).get("enabled")
        self.auth.stage()
        self.auth.approve_background_item()
        self.checks.append(check("backgroundItemApproved", "pressed=" in str(self.auth.approval.get("item")),
                                 "WGEX's background item was found in Login Items & Extensions and switched on"))
        seen = {}

        def shows_running():
            seen["word"] = self.read("wgex.onboarding.serviceState") if step2 else None
            seen["gate"] = (self.find("wgex.onboarding.continue") or {}).get("enabled")
            return seen["word"] == SERVICE_RUNNING or (gate_before == "false" and seen["gate"] == "true")
        running = self.wait("service running", SERVICE_SECONDS, shows_running, interval=3)
        word = seen.get("word")
        if word:
            self.checks.append(check("serviceRunningShown", word == SERVICE_RUNNING, f"the service row reads Running ({word!r})"))
        else:
            self.checks.append(check("serviceRunningShown", running, "the service row's word is not exposed to accessibility; "
                                     f"Continue, held until the service runs, went from enabled={gate_before} to {seen.get('gate')}"))
        if running:
            gate = self.find("wgex.onboarding.continue")
            self.checks.append(check("continueEnabled", gate and gate["enabled"] == "true", "Continue is enabled once the service runs"))
        self.checks.append(check("daemonRunning", self.service_running(), "launchd has the daemon job and the daemon process runs"))
        if not running:
            self.keep_dump("setup-running")
            raise ProductFailure("the setup service row never read Running after the approval")
        self.press("wgex.onboarding.continue")
        step3 = self.await_id("wgex.importReview.createEmpty")
        self.checks.append(check("addTunnelStepShown", step3, "Continue leads to the Add a Tunnel step"))
        if not step3:
            raise ProductFailure("step 3 (Add a Tunnel) did not appear")
        self.press("wgex.importReview.cancel")  # Not Now
        closed = self.wait("setup closed", 20, lambda: not self.shown("wgex.onboarding.surface") and self.shown("wgex.main.sidebarImport"))
        self.checks.append(check("setupClosed", closed, "Not Now closes setup onto the main window"))

    def secure_install(self):
        self.ensure_service()
        self.open_app()
        self.open_page("service")
        before = self.read("wgex.service.fact.installed")
        doctor = self.session.uninstall_fields("secure-install").get("secureInstall")
        action = self.shown("wgex.service.actionTitle")
        if before == INSTALL_VERIFIED or (doctor == "verified" and not action):
            # The lab install (lab wrapping key) can already be verified: the row asserts what the lab can prove, the page
            # and the daemon agreeing on Verified with no action offered (MacBackgroundServicePage.swift:66-74).
            self.notes.append(f"secure install read Verified before any press (doctor {doctor}); the press flow was not exercised")
            self.checks.append(check("pageShowsVerified", before == INSTALL_VERIFIED, f"the Installed fact reads Verified ({before!r})"))
            self.checks.append(check("secureInstallVerified", doctor == "verified", f"wgex doctor reports secureInstall verified ({doctor})"))
            self.checks.append(check("noActionWhenVerified", not action, "no secure install action beside a verified Installed fact"))
            return
        self.checks.append(check("actionOffered", action, f"the Installed fact ({before}) offers its action button"))
        if not action:
            raise ProductFailure(f"no secure install action beside the Installed fact ({before})")
        self.press("wgex.service.actionTitle")
        seen, console, state = self.admin(lambda: (lambda v: v if v == "verified" else None)(
            self.session.uninstall_fields("secure-install").get("secureInstall")))
        self.checks.append(check("adminSheetShown", seen, f"the administrator dialog appeared (console {console})"))
        self.checks.append(check("secureInstallVerified", state == "verified", "wgex doctor reports secureInstall verified"))
        shown = self.wait("fact verified", 30, lambda: self.read("wgex.service.fact.installed") == INSTALL_VERIFIED)
        self.checks.append(check("pageShowsVerified", shown, "the Installed fact reads Verified"))

    def import_conf(self):
        self.ensure_service()
        if self.profile_id(LAB_TUNNEL):
            raise Precondition(f"{LAB_TUNNEL} is already stored")
        self.session.lab("profile", "default")
        self.open_app()
        self.import_file(f"/Users/{self.live.GUEST_USER}/lab/{LAB_TUNNEL}.conf")
        review = self.await_id("wgex.importReview.importLabel")
        self.checks.append(check("reviewShown", review, "opening the .conf shows Review Tunnel with Add"))
        if not review:
            raise ProductFailure("Review Tunnel (wgex.importReview.importLabel) did not appear for the .conf")
        self.checks.append(check("reviewName", LAB_TUNNEL in " ".join(texts(self.find("wgex.importReview.name"))),
                                 "the review names the tunnel after its file"))
        # Both rows are combined elements carrying their value (MacImportSheet.swift:259-265).
        shown = " ".join(texts(self.find("wgex.importReview.endpoint")) + texts(self.find("wgex.importReview.addresses")))
        self.measure_text("reviewServer", shown, lambda t: "10.77." in t and ":" in t, "the review shows the server and addresses")
        self.checks.append(check("noProblems", not self.shown("wgex.importReview.problems"), "no problems listed for a valid file"))
        self.press("wgex.importReview.importLabel")
        uuid = self.wait("stored", 30, lambda: self.profile_id(LAB_TUNNEL))
        self.checks.append(check("tunnelStored", uuid, "Add stores the tunnel"))
        self.checks.append(check("sidebarRow", uuid and self.await_id("wgex.main.tunnel." + str(uuid), 20),
                                 "the sidebar lists the new tunnel"))

    def import_zip(self):
        self.ensure_service()
        names = [self.name("zip-" + letter) for letter in "abc"]
        directory = self.synthetic(names, 10 * self.attempt)
        archive = f"{directory}/wgex-lab-m07-tunnels-a{self.attempt}.zip"
        self.session.ssh(f"set -eu; cd {shlex.quote(directory)}; rm -f {shlex.quote(archive)}; "
                         f"/usr/bin/zip -q {shlex.quote(archive)} " + " ".join(shlex.quote(n + ".conf") for n in names))
        self.open_app()
        self.import_file(archive)
        listed = self.await_id("wgex.importReview.itemTick.", prefix=True)
        if not listed:
            # The app declares no zip document type; fall back to Import from File (NSOpenPanel, Go to Folder).
            self.notes.append("open -a did not show the tick list; used Import from File and Go to Folder")
            self.session.keystroke("i", command=True)
            time.sleep(3)
            self.session.lab("gui", "run", "osascript", "-e", 'tell application "System Events" to keystroke "g" using {command down, shift down}')
            time.sleep(2)
            self.session.keystroke(archive)
            self.key(36)
            time.sleep(2)
            self.key(36)
            listed = self.await_id("wgex.importReview.itemTick.", prefix=True)
        self.checks.append(check("tickListShown", listed, "the zip shows the several-files list with one tick per tunnel"))
        if not listed:
            raise ProductFailure("the tick list (wgex.importReview.itemTick.<n>) did not appear for the zip")
        items = by_id(listed, "wgex.importReview.item.", prefix=True)
        self.checks.append(check("threeItems", len(by_id(listed, "wgex.importReview.itemTick.", prefix=True)) == 3,
                                 "three rows for three tunnels"))
        # Each item row is one combined element (MacImportSheet.swift:232-234): its server text is inside it.
        servers = [" ".join(texts(self.find(f"wgex.importReview.item.{n}"))) for n in range(3)]
        # The row carries its server as its accessibility value (M07-T11); the endpoint's own element is the fallback.
        servers = [t if "192.0.2." in t else " ".join([t] + texts(self.find(f"wgex.importReview.itemEndpoint.{n}"))).strip()
                   for n, t in enumerate(servers)]
        self.measure_text("serversShown", " | ".join(t for t in servers if t), lambda _: all("192.0.2." in t for t in servers),
                          "each row shows its server")
        before = self.read("wgex.importReview.addAll")
        tick_before = (self.find("wgex.importReview.itemTick.2") or {}).get("value")
        self.press("wgex.importReview.itemTick.2")
        after = self.wait("Add 2", 10, lambda: (lambda v: v if v and "2" in v else None)(self.read("wgex.importReview.addAll"))) if before else None
        tick_after = (self.find("wgex.importReview.itemTick.2") or {}).get("value")
        # The button title follows the ticks (MacImportSheet.swift:203); unexposed, the untick is measured on the check box.
        self.checks.append(label_check("addCountFollowsTicks", before and after and f"{before} -> {after}",
                                       lambda _: "All" in before and "2" in after, tick_before == "1" and tick_after == "0",
                                       f"the third check box went from {tick_before} to {tick_after}",
                                       "the button reads Add All, then Add 2 after one untick"))
        self.press("wgex.importReview.addAll")
        stored = [bool(self.wait("stored", 30 if i < 2 else 5, lambda n=n: self.profile_id(n))) for i, n in enumerate(names)]
        self.checks.append(check("tickedAdded", stored[:2] == [True, True], "the two ticked tunnels are stored"))
        self.checks.append(check("untickedSkipped", stored[2] is False, "the unticked tunnel is not stored"))
        self.notes.append(f"zip items listed: {len(items)}")

    def create_empty(self):
        self.ensure_service()
        name = self.name("empty")
        self.open_app()
        self.prime_capture()
        self.press("wgex.main.sidebarImport")
        sheet = self.await_id("wgex.importReview.createEmpty")
        self.checks.append(check("addSheetShown", sheet, "Add Tunnel shows the Create Empty Tunnel row"))
        if not sheet:
            raise ProductFailure("Add a Tunnel (wgex.importReview.createEmpty) did not appear")
        self.press("wgex.importReview.createEmpty")
        editor = self.await_id("wgex.editor.publicKey")
        self.checks.append(check("editorShown", editor, "Create Empty Tunnel opens the editor with a public key"))
        if not editor:
            raise ProductFailure("the editor (wgex.editor.publicKey) did not open for an empty tunnel")
        first = public_key_digest(self.dump(), (editor or {}).get("frame"))
        self.checks.append(check("keyGenerated", first is not None, "a new tunnel starts with a key pair (public key shown)"))
        self.press("wgex.editor.generateKeypair")
        if self.await_id("wgex.editor.generate", 10):
            self.press("wgex.editor.generate")
        changed = self.wait("new key", 15, lambda: (lambda d: d is not None and d != first)(
            public_key_digest(self.dump(), (self.find("wgex.editor.publicKey") or {}).get("frame"))))
        self.checks.append(check("keypairRegenerated", changed, "Generate Key Pair replaces the public key (compared by digest)"))
        # M07-T15 run 3: per-character typing with a read-back after each, to see where the Name field stops taking input.
        self.type_into("wgex.editor.field.name", name[:1])
        self.notes.append(f"name char 1 {name[:1]!r}: field reads {scrub(self.read('wgex.editor.field.name') or '')!r}")
        for position, char in enumerate(name[1:4], 2):
            time.sleep(1)
            self.session.keystroke(char)
            self.notes.append(f"name char {position} {char!r}: field reads {scrub(self.read('wgex.editor.field.name') or '')!r}")
        time.sleep(1)
        self.session.keystroke(name[4:])
        self.notes.append(scrub(f"after typing the name (typed {name!r}): field reads {self.read('wgex.editor.field.name')!r}")[:300])
        self.type_into("wgex.editor.field.addresses", "10.250.0.2/32")
        self.notes.append(scrub(f"after typing the addresses: name reads {self.read('wgex.editor.field.name')!r}, addresses read {self.read('wgex.editor.field.addresses')!r}")[:300])
        problems = self.read("wgex.editor.problems")
        self.press("wgex.editor.save")
        uuid = self.wait("stored", 30, lambda: self.profile_id(name))
        self.checks.append(check("saved", uuid, "Save stores the empty tunnel" + (f" (problems shown: {problems[:120]})" if problems else "")))
        # Measured on its own, so a run tells a save that never left the editor from a stored tunnel the lookup missed.
        closed = self.wait("editor closed", 15, lambda: not self.shown("wgex.editor.save"))
        self.checks.append(check("editorClosed", closed, "the editor closes after Save"))
        self.after_save_state(name, "create-empty-after-save")
        if not uuid and not closed:
            after = self.read("wgex.editor.problems")
            self.notes.append("editor still open after Save" + (f"; problems: {after[:120]}" if after else ""))

    def edit_text(self):
        self.ensure_service()
        name, uuid = self.ensure_tunnel("text", 40 + self.attempt)
        self.open_app()
        self.prime_capture()
        self.select_tunnel(uuid, name)
        self.shot_modes("main-tunnel-selected")
        self.press("wgex.main.editProfile")
        if not self.await_id("wgex.editor.editAsText"):
            raise ProductFailure("the editor did not open from Edit… on the tunnel page")
        self.appearance(False)
        self.shot("editor-open")
        self.press("wgex.editor.editAsText")
        text = self.await_id("wgex.editor.configurationText")
        if text:
            text = self.find("wgex.editor.configurationText", contains="[Interface]") or text
        self.checks.append(check("textShown", text and text["contains"], "Edit as Text shows the configuration text"))
        if not text or not text["frame"]:
            raise ProductFailure("Edit as Text showed no text view (wgex.editor.configurationText)")
        x, y = centre(text["frame"])
        self.session.lab("gui", "click", str(x), str(y))
        # M07-T16: focus is read through AXFocusedUIElement (the contains read cannot show typed text, M07-T15 finding 3). Return
        # is pressed only with the text view focused; without that it would press Save, the sheet's default action.
        if not self.ensure_focus("wgex.editor.configurationText", "after click"):
            raise ValueError("the configuration text view did not take the keyboard focus")
        self.key(126, "command down")  # to the top: [Interface]
        self.key(124, "command down")  # end of that line
        if not self.ensure_focus("wgex.editor.configurationText", "before Return"):
            raise ValueError("the configuration text view lost the keyboard focus before Return")
        self.key(36)
        # M07-T16: one probe only (each costs about seven guest AX reads; four of them took the row past its bound under load).
        self.editor_probe("after Return")
        self.session.keystroke("MTU = 1380")
        self.shot("editor-text-after-typing")
        self.press("wgex.editor.editAsForm")
        form = self.await_id("wgex.editor.field.mtu")
        self.checks.append(check("formParsedText", form and form["value"] == "1380",
                                 "Edit as Form shows the MTU typed in the text"))
        self.checks.append(check("noProblems", form and not self.shown("wgex.editor.problems"), "the edited text parses without problems"))
        self.press("wgex.editor.save")
        closed = self.wait("editor closed", 20, lambda: not self.shown("wgex.editor.save"))
        self.checks.append(check("saved", closed, "Save closes the editor"))
        self.press("wgex.main.editProfile")
        self.await_id("wgex.editor.editAsText")
        self.press("wgex.editor.editAsText")
        again = self.await_id("wgex.editor.configurationText") and self.find("wgex.editor.configurationText", contains="MTU = 1380")
        self.checks.append(check("roundTrip", again and again["contains"], "reopened as text, the saved configuration carries MTU = 1380"))
        self.press("wgex.editor.cancelChanges")
        if self.await_id("wgex.editor.discard", 5):
            self.press("wgex.editor.discard")

    def activation_precondition(self):
        self.ensure_service()
        uuid = self.profile_id(LAB_TUNNEL)
        if not uuid:
            raise Precondition(f"{LAB_TUNNEL} is not stored (M07-IMPORT-CONF)")
        if self.protection() not in ("unprotected", None):
            self.session.guest_action("down")
        return uuid

    def tunnel_actions(self):
        uuid = self.activation_precondition()
        self.open_app()
        self.select_tunnel(uuid, LAB_TUNNEL)
        self.shot_modes("tunnel-selected-protected-off")
        # The page's button title and status word follow the tunnel's state (MacTunnelPage.swift:86-94); when the guest
        # exposes no label, the check takes the daemon state and the button's presence and enabled state instead.
        def action_state():
            item = self.find("wgex.main.action") or {}
            return self.read("wgex.main.action") or "", item.get("enabled") == "true"
        label, enabled = action_state()
        down = self.protection() == "unprotected"
        self.checks.append(label_check("activateOffered", label, "Activate", enabled and down,
                                       f"daemon unprotected {down}, action enabled {enabled}", "the tunnel page offers Activate"))
        self.press("wgex.main.action")
        on = self.wait("protected", TUNNEL_SECONDS, lambda: self.protection() == "protected", interval=1)
        self.checks.append(check("activated", on, "Activate brings the tunnel up (daemon status protected)"))
        self.wait("page active", 20, lambda: action_state()[0] == "Deactivate" or not action_state()[0])
        label, enabled = action_state()
        status = self.read("wgex.main.status") or ""
        self.checks.append(label_check("pageShowsActive", label and f"{label}; {status}",
                                       lambda _: label == "Deactivate" and "Active" in status, bool(on) and enabled,
                                       f"daemon protected {bool(on)}, action enabled {enabled}", "the page reads Active and offers Deactivate"))
        self.press("wgex.main.action")
        off = self.wait("unprotected", TUNNEL_SECONDS, lambda: self.protection() == "unprotected", interval=1)
        self.checks.append(check("deactivated", off, "Deactivate takes the tunnel down (daemon status unprotected)"))
        self.wait("page inactive", 20, lambda: action_state()[0] == "Activate" or not action_state()[0])
        label, enabled = action_state()
        self.checks.append(label_check("pageShowsInactive", label, "Activate", bool(off) and enabled,
                                       f"daemon unprotected {bool(off)}, action enabled {enabled}", "the page offers Activate again"))

    def menu_actions(self):
        self.activation_precondition()
        self.open_app()
        self.shot_modes("menubar-icon-unprotected")
        items = menu_items(self.menu("read"))
        self.checks.append(check("menuLists", items and any(t == LAB_TUNNEL for t, _, _ in items), "the menu lists the tunnel"))
        if not items:
            raise ValueError("menu read failed")
        self.menu("click", LAB_TUNNEL)
        on = self.wait("protected", TUNNEL_SECONDS, lambda: self.protection() == "protected", interval=1)
        self.checks.append(check("activated", on, "choosing the tunnel in the menu activates it"))
        time.sleep(SETTLE_SECONDS)
        self.shot_modes("menubar-icon-protected")
        items = menu_items(self.menu("read")) or []
        self.checks.append(check("ticked", any(t == LAB_TUNNEL and c for t, c, _ in items), "the active tunnel carries the check mark"))
        self.menu("click", LAB_TUNNEL)
        off = self.wait("unprotected", TUNNEL_SECONDS, lambda: self.protection() == "unprotected", interval=1)
        self.checks.append(check("deactivated", off, "choosing it again deactivates it"))

    def menu_live(self):
        self.activation_precondition()
        self.open_app()
        self.menu("click", LAB_TUNNEL)
        if not self.wait("protected", TUNNEL_SECONDS, lambda: self.protection() == "protected", interval=1):
            raise ProductFailure("the tunnel did not come up from the menu")
        try:
            self.session.ssh(f"nohup /sbin/ping -c 60 -i 0.2 {PEER_ADDRESS} >/dev/null 2>&1 &")
            time.sleep(3)
            first = menu_items(self.menu("read"))
            time.sleep(MENU_GAP_SECONDS)
            second = menu_items(self.menu("read"))
            if first is None or second is None:
                raise ValueError("menu read failed")
            self.checks.extend(live_checks(first, second, LAB_TUNNEL))
            self.notes.append("detail lines: " + "; ".join(t.strip() for t, _, _ in first if ": " in t and not t.startswith("Status"))[:400])
        finally:
            self.session.guest_action("down", check=False)

    def protection_row(self):
        self.ensure_service()
        self.open_app()
        self.open_page("protection")
        before = self.session.guest_action("allow-lan-state", check=False).decode(errors="replace").strip()
        if before != "allowLAN=false":
            # Live run 4: the lab state starts with Allow local network on. Turning it off is a tightening change with no
            # administrator prompt (verdict-live set_allow_lan_off, M1-10q); the row then measures off -> on -> off.
            self.notes.append(f"Allow local network started {before or 'unreadable'}; turned off first with the page's toggle")
            try:
                self.session.set_allow_lan_off()
            except self.live.RowFailure as error:
                raise Precondition(f"Allow local network could not be turned off first: {error}"[:300]) from None
            self.open_page("protection")
        self.checks.append(check("killSwitchShown", self.shown("wgex.protection.killSwitch"), "the page shows the kill switch state"))
        self.press("wgex.protection.allowLocalNetwork")
        lan = lambda: self.session.guest_action("allow-lan-state", check=False).decode(errors="replace").strip() == "allowLAN=true"  # noqa: E731
        seen, console, on = self.admin(lan)
        self.checks.append(check("adminSheetShown", seen, f"turning Allow local network on asks for an administrator (console {console})"))
        self.checks.append(check("settingOn", on, "the daemon's setting reads on after the approval"))
        toggle = self.read("wgex.protection.allowLocalNetwork")
        self.checks.append(check("toggleOn", toggle == "1", f"the toggle reads on ({toggle!r})"))
        self.press("wgex.protection.allowLocalNetwork")
        off = self.wait("off", 30, lambda: self.session.guest_action("allow-lan-state", check=False).decode(errors="replace").strip() == "allowLAN=false")
        if not off and self.session.gap_action("agent-state", check=False).strip().startswith(b"agent=running windows=1"):
            self.notes.append("turning the setting off also asked for an administrator")
            _, _, off = self.admin(lambda: self.session.guest_action("allow-lan-state", check=False).decode(errors="replace").strip() == "allowLAN=false")
        self.checks.append(check("settingOff", off, "turning it off again restores the setting"))

    def uninstall(self):
        self.ensure_service()
        self.session.guest_action("down", check=False)
        self.open_app()
        self.open_page("service")
        self.press("wgex.service.uninstallOpen")
        sheet = self.await_id("wgex.service.uninstallConfirm")
        self.checks.append(check("sheetShown", sheet, "Uninstall WGEX… opens the confirmation sheet"))
        if not sheet:
            raise ProductFailure("the uninstall sheet (wgex.service.uninstallConfirm) did not open")
        self.checks.append(check("purgeOffOffered", self.read("wgex.service.uninstallPurge") == "0",
                                 "Also remove profiles and settings is offered and off"))
        self.press("wgex.service.uninstallConfirm")
        seen, console, final = self.admin(lambda: self.shown("wgex.service.uninstallQuit"))
        self.checks.append(check("adminSheetShown", seen, f"the uninstall asks for an administrator (console {console})"))
        self.checks.append(check("finalScreen", final, "the sheet ends on WGEX is uninstalled with Quit WGEX"))
        state = self.services()
        self.checks.append(check("serviceRemoved", state.get("launchdJob") == "absent", f"launchd has no daemon job ({state.get('launchdJob')})"))
        if final:
            self.press("wgex.service.uninstallQuit")
        quit_ok = self.wait("app exited", 20, lambda: self.session.uninstall_fields("app-state").get("app") == "exited")
        self.checks.append(check("appQuit", quit_ok, "Quit WGEX ends the app"))
        if not quit_ok:
            self.notes.append("driver stopped the app: " + str(self.session.uninstall_fields("stop-app").get("stopped")))
        self.checks.append(check("profilesKept", self.profile_id(LAB_TUNNEL) is not None, "profiles are kept without the purge option"))


RUNS = {"M07-SETUP": Rows.setup, "M07-SECURE-INSTALL": Rows.secure_install, "M07-IMPORT-CONF": Rows.import_conf,
        "M07-IMPORT-ZIP": Rows.import_zip, "M07-CREATE-EMPTY": Rows.create_empty, "M07-EDIT-TEXT": Rows.edit_text,
        "M07-TUNNEL-ACTIONS": Rows.tunnel_actions, "M07-MENU-ACTIONS": Rows.menu_actions, "M07-MENU-LIVE": Rows.menu_live,
        "M07-PROTECTION": Rows.protection_row, "M07-UNINSTALL": Rows.uninstall}


def verdict(row, attempt, checks, error, provenance, installation, extra):
    result, cause = outcome(checks, error)
    completed = result in ("passed", "failed") and error is None or isinstance(error, ProductFailure)
    record = dict(schemaVersion=1, row=row, title=ROWS[row], attempt=attempt, dryRun=False, result=result, firstCause=cause,
                  checks=checks, rowCompleted=bool(completed), prepareCompleted=result != "notMeasured",
                  expectationsMet=result == "passed", **provenance, installation=installation, **extra)
    return record


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
        path = Path(root) / row / "verdict.json"
        try:
            record = json.loads(path.read_text())
        except (OSError, ValueError):
            print(f"- {row}: no verdict")
            continue
        met = sum(1 for item in record.get("checks", []) if item.get("met"))
        print(f"- {row}: {record.get('result')} (attempt {record.get('attempt')}, {met}/{len(record.get('checks', []))} checks, "
              f"liveAcceptance {record.get('liveAcceptance')}){'; first cause: ' + str(record['firstCause'])[:200] if record.get('firstCause') else ''}")
    return 0


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
    if args.row not in ROWS or args.report_root is None or args.rows:
        parser.error("one row from ROWS and --report-root are required")
    if os.environ.get("WGEX_LAB_VM") != "macos27-wgex" or os.environ.get("WGEX_LAB_USER") != "admin":
        parser.error("M07 rows run on WGEX_LAB_VM=macos27-wgex with WGEX_LAB_USER=admin")
    run = load("m07_verdict_run", LAB / "verdict-run.py")
    live = load("m07_verdict_live", LAB / "verdict-live.py")
    auth = load("m07_auth_real", LAB / "auth-real.py")
    load_start = run.HARNESS.host_load()
    session = live.Session(args.row, {}, no_install=True)
    with_login_file(getattr(session, "console", None), os.environ.get("WGEX_LAB_LOGIN_FILE"))
    rows = Rows(session, live, None, args.attempt)
    rows.auth, rows.auth_failure = auth.AuthReal(session, live), auth.Failure
    error, started = None, stamp()
    gaps = rows.gaps
    try:
        rows.stage()
        session.measure_provenance()
        RUNS[args.row](rows)
    except (Precondition, ProductFailure) as caught:
        error = caught
    except (auth.Failure, live.RowFailure, live.PollDeadline, RuntimeError, OSError, ValueError, KeyError, TypeError) as caught:
        error = caught
    finally:
        if error is not None and not isinstance(error, (Precondition, ProductFailure)):
            rows.notes.append(scrub(f"driver error in full: {type(error).__name__}: {error}")[:1800])
        try:
            if session.provenance.get("sourceCommit"):
                live.finish_provenance(session, args.row, {})
        except (live.RowFailure, RuntimeError, OSError, ValueError) as caught:
            gaps.append("provenance re-measure: " + type(caught).__name__)
        warnings = session.cleanup()
    major = str(session.provenance.get("guestOS", {}).get("productVersion", "")).split(".")[0] or "27"
    extra = dict(startedAt=started, endedAt=stamp(), notes=rows.notes, approvals=rows.approvals, cleanupWarnings=warnings,
                 buildRoot=str(session.output), hostLoad=run.HARNESS.load_record(load_start, run.HARNESS.host_load()),
                 transport="headless Tart guest (VNC console), guarded SSH, console-session accessibility (gui.sh, asu.sh)")
    record = verdict(args.row, args.attempt, rows.checks, error, session.provenance, session.installation, extra)
    gaps.extend("Provenance: " + failure for failure in run.PROVENANCE.provenance_errors(record, major))
    write(args.report_root / args.row, record, gaps)
    print(f"{args.row}: {record['result']} (attempt {args.attempt}){'; ' + record['firstCause'] if record['firstCause'] else ''}")
    return EXIT[record["result"]]


if __name__ == "__main__":
    sys.exit(main())
