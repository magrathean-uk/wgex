#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guest orchestration with an injectable runner; imports never contact a VM."""
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
PEER = os.path.join(os.environ.get("WGEX_LAB_VM_ROOT") or os.path.expanduser("~/wgex-lab-vm"), "vm-lima")
CLI = "/Applications/WGEX.app/Contents/Helpers/wgex"
# The guest's lab user (M03-T11), as WGEX_LAB_USER in Tools/lab/tart/lib.sh: labuser on the macOS 26 guests, admin on macOS 27.
GUEST_USER = os.environ.get("WGEX_LAB_USER") or "labuser"
if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", GUEST_USER):
    raise ValueError("WGEX_LAB_USER must be a short account name")
GUEST_BIN = f"/Users/{GUEST_USER}/lab/bin"
GUEST_IPERF3 = GUEST_BIN + "/iperf3"
UUID_PATTERN = r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}"
# Runs on wg-peer: only a 12-hex digest of the live wg0 public key leaves the peer.
PEER_KEY_DIGEST_SCRIPT = 'set -eu; key="$(sudo -n wg show wg0 public-key)"; printf %s "$key" | sha256sum | cut -c1-12'
# Blocked during loss (M1-10e): a held tunnel without a usable path reports reasserting/blocked and keeps retrying
# (M1-05: 5/15/60 s, then 60 s, never giving up), so `failed` is accepted but not required. M1-05 guest D1 saw
# reasserting/blocked about 29 s after relay stop; run 6 saw it 13-17 s after Connect, after 12-15 s of active/protected.
# The wait covers that detection plus one saturated 60 s retry interval.
LOSS_BLOCKED_SECONDS = 90
LOSS_BLOCKED_PHASES = ("reasserting", "failed")
# Polls are 250 ms apart; a phase shorter than one SSH status query (configuring lasted 0.4 s in run 6) is kept
# from the daemon's status stream, whose allowlisted tail daemon-log-tail.pl publishes.
STATUS_POLL_SECONDS = 0.25
# Guest run 8 (M1-10h). Settings radio title for startup=boot (MacStrings.connectAtBootBeforeLogin) and the captive
# duration popup titles (MacStrings.text1Minute, minutes(n)); identifiers come from WGEXAccessibility.
BOOT_STARTUP_LABEL = "Activate at boot before login"
# Its radio group (MacStartupSettingsView, wgexControl(.main, "startupOption"), MacTunnelPage start-up sheet); the buttons carry no identifier.
BOOT_STARTUP_GROUP = "wgex.main.startupOption"
# M1-10r (guest run 8f, BOOT-SECRETS section 6): every radio button in that group exposes the group's label "Connection
# at startup" as its name, with no title or identifier of its own, so the label lookup never matches. The options in
# the order the radio Picker lists them: MacStartupOption (Packages/WGEXUI/Sources/WGEXUI/Screens/Mac/MacPreferences.swift:6,
# `case off, login, boot`) through ForEach(MacStartupOption.allCases) in MacStartupSettingsView
# (Packages/WGEXUI/Sources/WGEXUI/Screens/Mac/MacOnboardingView.swift:211-213). The N-th AXRadioButton child in x order.
STARTUP_OPTIONS = ("off", "login", "boot")
# Settings window detection (M1-10m, guest run 8d): macOS 26 exposed neither wgex.settings.surface (MacSettingsView sets
# it on the TabView) nor any wgex.settings.tab.* identifier; the window is titled after its selected tab
# (MacSettingsTab.title) and the General tab's toggles keep their identifiers. The surface stays the first choice, so a
# build that exposes it is still recognised by it; no other WGEX window (main, onboarding, debug) carries a tab title.
SETTINGS_SURFACE = "wgex.settings.surface"
SETTINGS_TAB_TITLES = ("General", "Protection", "Network", "Service", "Transports", "Updates", "Diagnostics", "About")
SETTINGS_IDENTIFIERS = ("wgex.settings.showStatusInMenuBar", "wgex.settings.hideDockIcon")
# Guest-load settle (M1-10m): readings of the guest's vm.loadavg this far apart, pacing only; the threshold and the bound
# are HARNESS_GUEST_SETTLE_LOAD and HARNESS_GUEST_SETTLE.
GUEST_SETTLE_POLL_SECONDS = 5
GUEST_LOAD = re.compile(r"\{ ?([0-9]+(?:\.[0-9]+)?) ([0-9]+(?:\.[0-9]+)?) ([0-9]+(?:\.[0-9]+)?) ?\}\s*")
CAPTIVE_SECONDS_DEFAULT = 300
CAPTIVE_OPEN_SECONDS = 20
CAPTIVE_KILL_AFTER_SECONDS = 10
# M1-10o fix pass: row check kinds that turn lockdown on; the driver never turns it off (Session.lockdown_off_needed), so
# their positive control leads (role unprotectedLead, before the lockdown press) instead of trailing.
LEAD_CONTROL_KINDS = ("captive", "reboot-lockdown", "ondemand-eth")
LOCKDOWN_TOGGLE = "wgex.protection.lockdown"
# M03-T09: the Mac app's On-Demand toggle (arms and disarms the selected profile; its identifier carries the profile UUID, as the
# guest dump shows: wgex.main.onDemandToggle.<UUID>) and the editor's Ethernet checkbox.
ONDEMAND_TOGGLE = "wgex.main.onDemandToggle"
ONDEMAND_ETHERNET = "wgex.editor.onDemandEthernet"
ONDEMAND_SAVE = "wgex.editor.save"
ALLOW_LAN_TOGGLE = "wgex.protection.allowLocalNetwork"
# M1-10q unexplainedOutsideFlow: a header-only offline read of the post-boot en0 capture, outbound IPv4 leaving the
# underlay subnet and any IPv6 beyond link scope; verdict.outside_flows applies the same exclusions again.
OUTSIDE_FLOW_FILTER = ("(ip and src net 192.168.64.0/24 and not dst net 192.168.64.0/24 and not dst net 169.254.0.0/16 "
                       "and not dst net 224.0.0.0/4 and not dst host 255.255.255.255) or (ip6 and not dst net fe80::/10 and not dst net ff00::/8)")
EN0_OBSERVER_EXTRA_SECONDS = 45
# M1-47: the guest's power-observe sampler runs this long past the injected sleep (the guest sleeps neither: SSH stays up).
POWER_OBSERVER_EXTRA_SECONDS = 45
# M1-47: after the injected wake the daemon must be protected again on its own within this wait (the verdict's own bound is 3 s).
POWER_RECOVERY_WAIT_SECONDS = 60
# M03-T07: REBOOT-INTENT waits this long after the first post-boot status for the persisted intent to be active and protected.
INTENT_RESTORE_WAIT_SECONDS = 120
# M03-T07 LOGIN-SILENT (DEC-021): the Hide Dock icon toggle (Settings, General), how long the login item may take to start the app
# after the console login, the settle before a presentation sample series, and the series (count, spacing in seconds).
HIDE_DOCK_TOGGLE = "wgex.settings.hideDockIcon"
MENU_OPEN_WINDOW = "wgex.menu.openWindow"
LOGIN_LAUNCH_SECONDS = 60
PRESENTATION_SETTLE_SECONDS = 3
PRESENTATION_SAMPLES = 3
PRESENTATION_SPACING_SECONDS = 2
STATUS_STREAM_LINE = re.compile(r"(?:(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?) )?status: phase=([a-z]{1,32}) "
                                r"protection=(protected|blocked|unprotected|unknown) reason=([A-Za-z]{1,40})")
_state_spec = importlib.util.spec_from_file_location("live_lab_state", ROOT / "Tools/lab/state.py")
STATE = importlib.util.module_from_spec(_state_spec)
_state_spec.loader.exec_module(STATE)
_verdict_spec = importlib.util.spec_from_file_location("live_lab_verdict", ROOT / "Tools/lab/verdict.py")
VERDICT = importlib.util.module_from_spec(_verdict_spec)
_verdict_spec.loader.exec_module(VERDICT)
_iperf3_spec = importlib.util.spec_from_file_location("live_lab_iperf3", ROOT / "Tools/lab/iperf3-asset.py")
IPERF3 = importlib.util.module_from_spec(_iperf3_spec)
_iperf3_spec.loader.exec_module(IPERF3)
# Harness deadlines (M1-10i): every bound on a host-side, SSH or GUI step is HARNESS.seconds(NAME), base x
# WGEX_LAB_HARNESS_SCALE from harness-deadlines.sh. Literal seconds left in this file are verdict expectations.
_harness_spec = importlib.util.spec_from_file_location("live_lab_harness", ROOT / "Tools/lab/harness.py")
HARNESS = importlib.util.module_from_spec(_harness_spec)
_harness_spec.loader.exec_module(HARNESS)
# M03-T03. M5.3-07 is the one row that installs a different bundle on purpose (check-verdicts.UPDATE_ROW; a test keeps the
# two equal): its end-of-row installed re-measure is replaced by the update bundle's own hashes and receipt.
UPDATE_ROW = "M5.3-07"
UPDATE_BUILD_SECONDS = 3600
UPDATE_TRANSFER_SECONDS = 900
UPDATE_OFFER_SECONDS = 120
# Finish update raises the administrator prompt; the lab user or the maintainer approves it at the guest console, never this driver.
UPDATE_APPROVAL_SECONDS = 300
UPDATE_RECOVERY_SECONDS = 120
# The hand-off probes: overlapping marker generators of UPDATE_PROBE_ROUNDS markers 500 ms apart (about 60 s each), a new
# one every UPDATE_PROBE_STEP_SECONDS, from before the Finish update press until the new daemon is confirmed protected.
# Each overlaps the next by about 30 s, so a slow driver step cannot open a gap; update.handoff_covered checks that none did.
UPDATE_PROBE_ROUNDS = 120
UPDATE_PROBE_STEP_SECONDS = 30
# The first generator is started over `just lab ssh`, which can take more than a second to reach the guest; the start
# (probedFrom) is taken only once its process runs there, polled every 0.5 s up to this bound (M03-T07 phase C2).
UPDATE_PROBE_START_SECONDS = 30
FINISH_UPDATE = "wgex.service.finishUpdate"
# M03-T15 (UNINSTALL): the app's finish offer and final screen (MacUninstallSheet), and the Service tab's register and secure
# install controls that bring the daemon back.
UNINSTALL_CONFIRM = "wgex.service.uninstallConfirm"
UNINSTALL_QUIT = "wgex.service.uninstallQuit"
REGISTER_SERVICE = "wgex.onboarding.registerBackgroundService"
SECURE_INSTALL_ACTION = "wgex.service.actionTitle"
MAIN_ACTION = "wgex.main.action"
UPDATE_MEASURE = ("set -eu; codesign --verify --deep --strict /Applications/WGEX.app; "
                  "for binary in /Applications/WGEX.app/Contents/MacOS/WGEX /Applications/WGEX.app/Contents/MacOS/WGEXDaemon "
                  "/Applications/WGEX.app/Contents/Helpers/wgex; do codesign --verify --strict \"$binary\"; "
                  "codesign -d --verbose=4 \"$binary\" 2>&1; done; printf 'CFBundleVersion=%s\\n' "
                  "\"$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' /Applications/WGEX.app/Contents/Info.plist)\"")
CORPUS_CLIENT = "wgex-corpus-client"
CORPUS_CLIENT_X86 = CORPUS_CLIENT + "-x86_64"
CORPUS_STEP_SECONDS = 180


def named(name, operation):
    """A cleanup operation carrying the name its cleanupWarning reports (M1-10o fix pass 2, F5: most cleanups are
    lambdas, all reported as "<lambda>"); the same object is returned, so cleanups.remove still finds it."""
    operation.cleanupName = name
    return operation


def tunnel_interfaces(ifconfig):
    """The utun interfaces carrying the lab tunnel address 10.77.0.2 in ifconfig text, in output order."""
    return [block.split(":", 1)[0] for block in re.findall(r"^utun[0-9]+:.*?(?=^\S|\Z)", ifconfig, re.M | re.S) if "10.77.0.2" in block]


def guest_binary_paths(build):
    """Stable host staging catalogue, independent of the active build root."""
    return STATE.guest_binaries(ROOT)


# M01-T04: `wgex doctor --json` secureInstall values (verified, inProgress, needsAttention(reason)) and the outcome line
# guest/wrapping-key.sh prints during `lab install`; only the fixed outcome word reaches the verdict.
SECURE_INSTALL_STATE = re.compile(r"[A-Za-z]{1,32}(?:\([A-Za-z]{1,64}\))?")
WRAPPING_KEY_OUTCOMES = (("wrapping key re-trusted", "re-trusted"), ("wrapping key unchanged", "unchanged"),
                         ("wrapping key restored from the lab escrow", "restored"),
                         ("wrapping key provisioned and escrowed", "provisioned"),
                         ("not escrowed by the lab", "unescrowed"), ("wrapping key present", "present"),
                         ("wrapping key absent", "absent"))


def wrapping_key_outcome(output):
    text = output.decode(errors="replace") if isinstance(output, bytes) else str(output or "")
    return next((word for marker, word in WRAPPING_KEY_OUTCOMES if marker in text), "unreported")


def control_position(dump, label, calibrated, identifier=None):
    calibrated = {key.casefold(): value for key, value in calibrated.items()}
    if label is not None and label.casefold() in calibrated and identifier is None:
        value = calibrated[label.casefold()]
        if not isinstance(value, list) or len(value) != 2 or any(type(n) is not int or not 0 <= n <= 8192 for n in value):
            raise ValueError("invalid control position")
        return tuple(value)
    x, y, width, height = control_frame(dump, label, identifier)
    return (x + width // 2, y + height // 2)


def control_frame(dump, label, identifier=None):
    """(x, y, width, height) of the one enabled control matching label and identifier; ValueError when missing or ambiguous."""
    found = control_frames(dump, label, identifier)
    if len(found) != 1:
        raise ValueError("missing or ambiguous accessible control")
    return found[0]


# The roles control_frames accepts for an element press (the helper presses identifier plus role).
CONTROL_ROLES = ("AXButton", "AXCheckBox", "AXSwitch", "AXRadioButton", "AXRow", "AXCell", "AXGroup", "AXPopUpButton")


def control_frames(dump, label, identifier=None, roles=None):
    """Frames of every enabled control matching label and identifier, in dump order; roles (a tuple of AX roles, M1-10n)
    narrows the lines to those roles, else the usual control roles."""
    allowed = tuple(role + " |" for role in (roles or CONTROL_ROLES))
    if not roles and identifier and identifier.startswith("wgex.main.tunnel."):
        allowed += ("AXStaticText |",)
    found = []
    for line in dump.splitlines():
        if not line.startswith(allowed) or "en=true" not in line:
            continue
        fields = {key: value.strip() for key, value in re.findall(r"(name|desc|id)=([^|]*)", line)}
        if label is not None and label.casefold() not in [value.casefold() for key, value in fields.items() if key != "id"]:
            continue
        actual_id = fields.get("id", "")
        if identifier and not (actual_id.startswith(identifier) if identifier.endswith(".") else actual_id == identifier):
            continue
        # Negative origins (M1-10j F4): a control scrolled above the screen top is off-screen, not missing.
        match = re.search(r"pos=(-?\d+),(-?\d+) size=(\d+)x(\d+)", line)
        if match:
            found.append(tuple(map(int, match.groups())))
    return found


DUMP_FRAME = re.compile(r"\bpos=(-?\d+),(-?\d+) size=(\d+)x(\d+)")


def element_target(dump, identifier, label=None):
    """The control the element path acts on (M1-10j): (frame, child). The enabled control with this identifier (and
    label), else, with a label, the one control so labelled inside the identified element's frame: SwiftUI radio
    buttons carry no identifier of their own, their group does. child=True: the helper looks the label up under it."""
    try:
        return control_frame(dump, label, identifier), False
    except ValueError:
        if label is None:
            raise
    groups = [DUMP_FRAME.search(line) for line in dump.splitlines() if re.search(r"\| id=" + re.escape(identifier) + r" \|", line)]
    if len(groups) != 1 or groups[0] is None:
        raise ValueError("missing or ambiguous accessible control")
    gx, gy, gw, gh = map(int, groups[0].groups())
    inside = []
    for line in dump.splitlines():
        match = DUMP_FRAME.search(line)
        if match:
            x, y, width, height = map(int, match.groups())
            if gx <= x and gy <= y and x + width <= gx + gw and y + height <= gy + gh:
                inside.append(line)
    return control_frame("\n".join(inside), label), True


def group_lines(dump, identifier):
    """The dump lines of the one element carrying this identifier and of every element whose frame lies inside its frame,
    in dump order (M1-10r): the radio group and its children. Without exactly one such line with a frame, the lines
    carrying the identifier (at most 8), so a gap still shows what the dump held."""
    lines = dump.splitlines()
    carrying = [line for line in lines if re.search(r"\| id=" + re.escape(identifier) + r" \|", line)]
    match = DUMP_FRAME.search(carrying[0]) if len(carrying) == 1 else None
    if match is None:
        return carrying[:8]
    bounds = tuple(map(int, match.groups()))
    return [line for line in lines if (frame := DUMP_FRAME.search(line)) and frame_inside(tuple(map(int, frame.groups())), bounds)]


def radio_options(dump, identifier):
    """The AXRadioButton children of the one element carrying this identifier, in x order (then y), each as dict(frame,
    value, enabled) from its dump line (M1-10r: SwiftUI radio buttons in a Form carry neither an identifier nor their own
    title, so an option is resolved by position). Empty when the identifier is missing or ambiguous."""
    lines = group_lines(dump, identifier)
    if sum(1 for line in lines if re.search(r"\| id=" + re.escape(identifier) + r" \|", line)) != 1:
        return []
    options = []
    for line in lines:
        frame = DUMP_FRAME.search(line)
        if not line.startswith("AXRadioButton |") or frame is None:
            continue
        value = re.search(r"\| value=([^|]*?)\s*\|", line)
        options.append(dict(frame=tuple(map(int, frame.groups())), value=value[1] if value else None, enabled="en=true" in line,
                            order=len(options)))
    return sorted(options, key=lambda option: (option["frame"][0], option["frame"][1]))


def option_selected(options, index, count):
    """True when there are count options, the one at index reads value=1 and every other value=0 (M1-10r)."""
    return len(options) == count and all(option["value"] == ("1" if i == index else "0") for i, option in enumerate(options))


# M1-10t (M1-10r VERIFY-B N6): group lines in a gap message or the ledger are capped in count and width and pass the credential
# filter; a group identifier on a container as large as the window can never embed the whole dump.
GAP_LINES = 8
GAP_LINE_WIDTH = 160


def gap_lines(lines):
    """At most GAP_LINES of the dump lines, each printable, GAP_LINE_WIDTH wide at most and through safe_stderr's credential
    and key-pattern filter; a trailing "(+N more lines)" says how many were left out."""
    shown = []
    for line in lines[:GAP_LINES]:
        text = safe_stderr("".join(char if char.isprintable() else " " for char in line)).strip()
        shown.append(text if len(text) <= GAP_LINE_WIDTH else text[:GAP_LINE_WIDTH - 3] + "...")
    return shown + ([f"(+{len(lines) - GAP_LINES} more lines)"] if len(lines) > GAP_LINES else [])


def radio_layout(options):
    """"row" when every option shares one y and the x values strictly increase, "column" when they share one x and the y values
    strictly increase, else None (M1-10t, M1-10r VERIFY-B L1): a wrapped group, or one that is neither, has no position that
    means "the Nth option". Also None unless the dump lists the buttons in that same order (`order`, the index among the
    group's radio buttons in dump order): the accessibility tree lists the Picker's options in declared order, so a
    right-to-left mirror, whose x values run backwards, disagrees (inference from the tree order, never seen on a guest;
    it fails closed: the gap, no press)."""
    if len(options) < 2 or [option["order"] for option in options] != sorted(option["order"] for option in options):
        return None
    xs, ys = [option["frame"][0] for option in options], [option["frame"][1] for option in options]
    if len(set(ys)) == 1 and all(a < b for a, b in zip(xs, xs[1:])):
        return "row"
    if len(set(xs)) == 1 and all(a < b for a, b in zip(ys, ys[1:])):
        return "column"
    return None


def dump_toggle_value(dump, identifier, frame=None, role=None):
    """True for value=1, False for value=0 on the line carrying this identifier, None when there is no such line or it shows
    another value or none (M1-10t: shared by toggle_value and the press-time compare). With neither frame nor role: the first
    line carrying the identifier (toggle_value's targeted read, and a child-label target's compare). M1-36 (LAB3-VERIFY G-1,
    N-1): the press-time compare passes the frame and the role the press targets, so it reads only the lines of that role at
    exactly that frame (x, y, width and height), whatever their enabled state, and an earlier line with another frame or role
    is never read. A frame that more than one such line carries is no value (None): the helper presses the first match, so
    which line it would act on is unknown."""
    lines = [line for line in dump.splitlines() if re.search(r"\| id=" + re.escape(identifier) + r" \|", line)
             and (role in (None, "-") or line.split(" |", 1)[0] == role)
             and (frame is None or ((match := DUMP_FRAME.search(line)) and tuple(map(int, match.groups())) == tuple(frame)))]
    if not lines or (frame is not None and len(lines) > 1):
        return None
    value = re.search(r"\| value=([^|]*?)\s*\|", lines[0])
    return {"1": True, "0": False}.get(value[1] if value else None)


def identifier_frames(dump, identifier, role):
    """Frames of the enabled dump lines carrying exactly this identifier in this role ("-": any role), in dump order
    (M1-10k fix pass 1, F3): tells an ambiguous post-scroll dump apart from one without the element."""
    frames = []
    for line in dump.splitlines():
        if not re.search(r"\| id=" + re.escape(identifier) + r" \|", line) or "en=true" not in line:
            continue
        match = DUMP_FRAME.search(line)
        if match and (role == "-" or line.split(" |", 1)[0] == role):
            frames.append(tuple(map(int, match.groups())))
    return frames


# titled_control's role preference inside the container (M1-10m verify F2), most preferred first.
TITLED_CONTROL_ROLES = ("AXButton", "AXRadioButton", "AXToggle")


def titled_control(dump, label, container_role="AXToolbar"):
    """(x, y, width, height) of the one enabled control titled label inside a container of this role (M1-10m): the
    Settings toolbar buttons carry no identifier (guest run 8d), so a tab is found by its title within the toolbar's
    frame. ValueError when the dump has no such container or the label is missing or ambiguous inside it. M1-10m verify
    F2: an AXButton so titled is preferred, then an AXRadioButton, then an AXToggle, over any other role with that title
    (a wrapper group or a static text repeating the name); more than one in the first role that has any is ambiguous."""
    containers = [tuple(map(int, match.groups())) for match in
                  (DUMP_FRAME.search(line) for line in dump.splitlines() if line.startswith(container_role + " |")) if match]
    if not containers:
        raise ValueError("missing accessible container")
    inside = []
    for line in dump.splitlines():
        match = DUMP_FRAME.search(line)
        if match and any(frame_inside(tuple(map(int, match.groups())), container) for container in containers):
            inside.append(line)
    for role in TITLED_CONTROL_ROLES:
        found = control_frames("\n".join(inside), label, roles=(role,))
        if len(found) > 1:
            raise ValueError("missing or ambiguous accessible control")
        if found:
            return found[0]
    return control_frame("\n".join(inside), label)


def settings_evidence(dump):
    """How one window dump shows the Settings window (M1-10m), else None: the wgex.settings.surface identifier first,
    then a window title naming a Settings tab, then a General-tab identifier known to reach the tree (guest run 8d)."""
    if dump_carries(dump, SETTINGS_SURFACE):
        return "identifier:" + SETTINGS_SURFACE
    title = window_title(dump)
    if title in SETTINGS_TAB_TITLES:
        return "title:" + title
    for identifier in SETTINGS_IDENTIFIERS:
        if dump_carries(dump, identifier):
            return "identifier:" + identifier
    return None


def guest_load1(output):
    """The guest's 1-minute load from `sysctl -n vm.loadavg` ("{ 1.52 2.10 3.40 }"), else None."""
    match = GUEST_LOAD.fullmatch(output.decode(errors="replace"))
    return float(match[1]) if match else None


def frame_argument(frame):
    """The helper's frame=X,Y,WxH argument (gui.sh press, label slot): match identifier, role and this exact frame."""
    return "frame={},{},{}x{}".format(*frame)


def element_role(dump, identifier, frame=None, controls=False):
    """The AX role of the dumped line carrying this identifier (and frame) (M1-10j F5): the helper matches identifier
    plus role, so a container that repeats the control's identifier is never pressed instead; "-" when unknown.
    controls (M1-36, LAB3-VERIFY G-1 a; the enabled half pinned by M1-38, VERIFY H-1): the role of the first enabled control line
    (CONTROL_ROLES), so a static text or a disabled control line (an AXSwitch showing the other value) ahead of it at the same
    frame does not become the press role. That is what element_target found on a pre-scroll dump; on after_scroll's
    identifier_frames path an enabled control of another role ahead of the remembered one is a role mismatch, so that dump is
    skipped (a gap, nothing pressed). With no enabled control line, the first line's role as before."""
    first = None
    for line in dump.splitlines():
        match = DUMP_FRAME.search(line)
        if re.search(r"\| id=" + re.escape(identifier) + r" \|", line) and match and (frame is None or tuple(map(int, match.groups())) == tuple(frame)):
            role = line.split(" |", 1)[0]
            if re.fullmatch(r"AX[A-Za-z]{1,40}", role):
                if not controls:
                    return role
                if role in CONTROL_ROLES and "en=true" in line:
                    return role
                first = first or role
    return first or "-"


def window_frame(dump):
    """Visible bounds for the off-screen check (M1-10j): the AXWindow line's frame (ax-dump.applescript since M1-10j),
    else the union of the window's first group (the content group of earlier dumps, guest run 8b: 0,30 1024x752) and
    its toolbars, so Settings tabs in the toolbar above the content group are inside (F2); None if neither."""
    lines = dump.splitlines()
    line = next((line for line in lines if line.startswith("AXWindow |")), None)
    match = DUMP_FRAME.search(line) if line else None
    if match:
        return tuple(map(int, match.groups()))
    candidates = [next((line for line in lines if line.startswith("AXGroup |")), "")] + [line for line in lines if line.startswith("AXToolbar |")]
    frames = [tuple(map(int, match.groups())) for match in map(DUMP_FRAME.search, candidates) if match]
    if not frames:
        return None
    left, top = min(x for x, _, _, _ in frames), min(y for _, y, _, _ in frames)
    right, bottom = max(x + w for x, _, w, _ in frames), max(y + h for _, y, _, h in frames)
    return (left, top, right - left, bottom - top)


def frame_inside(frame, bounds):
    """True when the whole element frame lies inside the window bounds; unknown bounds are never inside."""
    if bounds is None:
        return False
    x, y, width, height = frame
    bx, by, bw, bh = bounds
    return bx <= x and by <= y and x + width <= bx + bw and y + height <= by + bh


def frame_text(frame):
    return "unknown" if frame is None else "{},{} {}x{}".format(*frame)


# gui.sh dump and press end with this fixed line when osascript or SSH failed (M1-10k fix pass 1, F1).
HELPER_FAILED = re.compile(r"(?m)^ax-(?:dump|action)=failed exit=\d+\s*$")
# ax-dump.applescript's last line since M1-10l (guest run 8d): elements walked, truncated=1 when the depth limit or the
# element budget left elements unread, errors = elements or subtrees that could not be read. A dump without it comes
# from an older helper (the recorded fixtures) or a failed read and keeps the M1-10k rules. M1-10o (guest run 8e: a
# complete walk of the connected main window took 142-161 s, about 1 s per element): a targeted read (gui dump APP WINDOW
# IDENTIFIER) ends the line with target=found (the walk stopped at the first described element carrying the identifier)
# or target=missing (it walked everything it could without one).
WALK_LINE = re.compile(r"(?m)^ax-walk: elements=(\d+) truncated=([01]) errors=(\d+)(?: target=(found|missing))?\s*$")
# A dump whose walk line reports truncated=1 or errors is read again up to this many times, a short settle between reads,
# within the caller's deadline: GUI_SEARCH by default, GUI_SEARCH_SHORT per window after a scroll (M1-10l fix pass 1, F5).
# The best read seen stands (read_dump, dump_rank), not the last; a best read still incomplete is unreadable to dump_summary.
DUMP_RETRIES = 3
DUMP_RETRY_SETTLE_SECONDS = 0.5


def dump_walk(dump):
    """The helper's walk summary as dict(elements, truncated, errors), plus target (found or missing) for a targeted
    read (M1-10o); None when the dump carries no ax-walk line."""
    match = WALK_LINE.search(dump)
    if not match:
        return None
    walk = dict(elements=int(match[1]), truncated=match[2] == "1", errors=int(match[3]))
    if match[4]:
        walk["target"] = match[4]
    return walk


def dump_incomplete(dump):
    """True when the walk summary reports a truncated walk or unread elements: part of the tree may be missing."""
    walk = dump_walk(dump)
    return walk is not None and (walk["truncated"] or walk["errors"] > 0)


def dump_carries(dump, identifier, role="-"):
    """True when a dump line carries exactly this identifier in this role ("-": any role), enabled or not (M1-10l fix
    pass 1, F1): read_dump stops re-reading once the caller's target is in the tree, complete or not."""
    for line in dump.splitlines():
        if re.search(r"\| id=" + re.escape(identifier) + r" \|", line) and (role == "-" or line.split(" |", 1)[0] == role):
            return True
    return False


def dump_rank(dump):
    """How good one read of a window is (M1-10l fix pass 1, F1), larger is better: a read gui.sh marked failed or that
    printed nothing is the worst; then truncated=0 (or no walk line) before truncated=1, then the most element lines
    (the walk line not counted), then the fewest errors."""
    if not dump.strip() or HELPER_FAILED.search(dump):
        return (0, 0, 0, 0)
    walk = dump_walk(dump)
    lines = sum(1 for line in dump.splitlines() if line.strip() and not WALK_LINE.fullmatch(line))
    return (1, 0 if walk and walk["truncated"] else 1, lines, -(walk["errors"] if walk else 0))


def dump_summary(dump, identifier):
    """Bounded ledger summary of one AX dump (M1-10k): window title and frame, line count, and each line carrying the
    identifier as role, enabled flag and frame (at most 8); no other dump content. dump=unreadable when gui.sh reported
    an osascript or SSH failure or printed nothing (a readable dump always has its AXWindow line), or (M1-10l) when its
    ax-walk line still reports truncated=1 or errors after the retries, else ok. walk: that line's counts, when present;
    lines never counts it."""
    walk = dump_walk(dump)
    lines = [line for line in dump.splitlines() if not WALK_LINE.fullmatch(line)]
    matches = []
    for line in lines:
        if re.search(r"\| id=" + re.escape(identifier) + r" \|", line):
            role, frame, enabled = line.split(" |", 1)[0], DUMP_FRAME.search(line), re.search(r"\ben=([^|\n]*?)\s*$", line)
            matches.append(dict(role=role if re.fullmatch(r"AX[A-Za-z]{1,40}", role) else "unknown", enabled=enabled[1] if enabled else None,
                                frame=list(map(int, frame.groups())) if frame else None))
    bounds = window_frame(dump)
    readable = dump.strip() and not HELPER_FAILED.search(dump) and not dump_incomplete(dump)
    summary = dict(dump="ok" if readable else "unreadable", windowTitle=window_title(dump), windowFrame=list(bounds) if bounds else None,
                   lines=len(lines), matches=matches[:8])
    if walk is not None:
        summary["walk"] = walk
    return summary


def control_candidates(dump, identifier):
    """(exact, near) for a missed identifier (M07-T15): how many dump lines carry exactly that id, and the ids that share
    its prefix up to the last dot (sorted, at most 40), so the error names what the window did offer."""
    ids = [match[1].strip() for match in (re.search(r"\| id=([^|]*)", line) for line in dump.splitlines()) if match]
    prefix = identifier.rsplit(".", 1)[0] + "." if "." in identifier else ""
    exact = sum(1 for item in ids if item == identifier)
    near = sorted({item for item in ids if item != identifier and item.startswith(prefix)})
    return exact, near[:40]


def dump_summary_text(summary):
    """One post-scroll dump in a gap message: its line and identifier-line counts, or why it could not be read (with the
    helper's walk counts when it reported them, M1-10l)."""
    if summary.get("dump", "ok") != "ok":
        walk = summary.get("walk")
        detail = (f" (ax-walk elements={walk['elements']} truncated={int(walk['truncated'])} errors={walk['errors']})"
                  if walk else "")
        return f"window {summary['window']}: {summary['dump']}{detail}"
    return f"window {summary['window']}: {summary['lines']} lines, {len(summary['matches'])} identifier lines"


# miss and error (M1-10m): press-only found no element, or AXPress on it threw (with the AppleScript error number,
# press_error); none is an older helper's report for either.
ACTION_PATHS = ("element", "element-timeout", "coordinate", "miss", "error", "none")
PRESS_ERROR = re.compile(r"path=error number=(-?\d{1,10})\s*")
# M1-10o fix pass 2 (F1, guest run 8e: the End press command took 4.93 s, mostly the helper's own element walk, and
# manualEndCloses read 15.61 s from its issue): ax-action.applescript's line before the path of a press that acted, the
# guest-clock instant it delivered AXPress, AXConfirm or the fallback click. A stamp outside the press command's own
# issue and return instants (widened by the clock uncertainty plus this slack) is impossible and is not used.
PRESSED_AT = re.compile(r"(?m)^pressedAt=(\d{9,11}\.\d{1,6})[ \t\r]*(?:\n|\Z)")
PRESS_STAMP_SLACK_SECONDS = 1.0
# The paths of a press that acted: AXPress (or a popup's timed-out AXPress) or the guest-side click inside the window.
PRESSED_PATHS = ("element", "element-timeout", "coordinate")
# scroll=missing: the helper found no element to scroll (M1-10k), told apart from scroll=none (no scroll available).
SCROLL_PATHS = ("action", "bar", "missing", "none")
# Every WGEX window index the post-scroll lookup searches (M1-10k): the main window and Settings, as open_settings.
# Two-window limit (verify F4): a third WGEX window (a sheet, an alert, a second document window) at index 1 or 2 can
# push the main window to index 3, which is never dumped; press-only then goes to the dumped index and may miss.
POST_SCROLL_WINDOWS = ("1", "2")
# Press-only (M1-10k fix pass 1, F1): up to this many helper calls within GUI_SEARCH_SHORT while the helper answers
# path=none, nothing or ax-action=failed, with a short settle between them; the guest tree read is flaky under load.
# Only for a press nobody compared (lockdown, F3): a compared press retries path=miss alone (M1-38 fix pass 1, VERIFY F-1),
# since every other failed reply may have landed.
PRESS_ONLY_ATTEMPTS = 3
PRESS_ONLY_SETTLE_SECONDS = 1.0


def press_stamp(output):
    """The helper's pressedAt delivery stamp (guest clock, F1), else None (an older helper, a miss, a failed clock read)."""
    match = PRESSED_AT.search(output.decode(errors="replace"))
    return float(match[1]) if match else None


def press_report(output):
    """The helper's report text without its pressedAt line, for the fixed path and error parsers."""
    return PRESSED_AT.sub("", output.decode(errors="replace"))


def press_reply(output):
    """The press helper's path, "failed" when gui.sh reported an osascript or SSH failure (F1), else None."""
    path = action_path(output)
    if path is None and HELPER_FAILED.search(output.decode(errors="replace")):
        return "failed"
    return path


def press_error(output):
    """The AppleScript error number of a press-only path=error report (M1-10m), else None."""
    match = PRESS_ERROR.fullmatch(press_report(output))
    return int(match[1]) if match else None


def press_outcome(path, number=None):
    """One failed press-only attempt in a gap message (M1-10m): a lookup miss and a swallowed AXPress error differ."""
    return {"miss": "lookup miss", "error": f"AXPress error {number}", "none": "path=none (older helper: miss or error)",
            "failed": "helper failed"}.get(path, "no path reported")


def action_path(output, kind="path", values=ACTION_PATHS):
    """The element helper's fixed report (path=element|element-timeout|coordinate|miss|error number=N|none,
    scroll=action|bar|missing|none); None for anything else. element-timeout: a popup press whose Apple Event timed out
    (F3); miss and error: press-only found no element or its AXPress threw (M1-10m); none: an older helper's press-only
    failure (F1). A pressedAt line before the path (M1-10o fix pass 2) is not part of the report."""
    text = press_report(output)
    if kind == "path" and PRESS_ERROR.fullmatch(text):
        return "error"
    match = re.fullmatch(kind + r"=(" + "|".join(values) + r")\s*", text)
    return match[1] if match else None


# M03-T07 phase B: one stderr line per console moment, so the person running the row can tell the maintainer when to act (the console
# login, the administrator approval). Fixed words and UTC clock times only; never a guest reply.
G_SIGNAL_EVENTS = ("logged-out", "login-wait", "logged-in", "approval-wait", "approval-seen")


def g_signal(event, seconds=None, now=None, stream=None):
    """Writes `WGEX-G <event> at=HH:MM:SSZ[ deadline=HH:MM:SSZ]` to stderr (flushed); the deadline is now + seconds."""
    if event not in G_SIGNAL_EVENTS:
        raise ValueError("unknown console event")
    now = time.time() if now is None else now
    clock = lambda value: time.strftime("%H:%M:%SZ", time.gmtime(value))
    line = f"WGEX-G {event} at={clock(now)}" + ("" if seconds is None else f" deadline={clock(now + seconds)}")
    stream = sys.stderr if stream is None else stream
    stream.write(line + "\n")
    stream.flush()
    return line


# M03-T07 phase B (DEC-034): the self-driven console. With WGEX_LAB_VNC_FILE set, Tools/lab/tart/snapshot.sh starts the
# restored guest with Tart's VNC server and writes its address there, and the driver types the console login and the
# administrator approval itself through Tools/lab/console/console.py at the moments g_signal names. Unset, the maintainer does them.
CONSOLE_SCRIPT = ROOT / "Tools/lab/console/console.py"
CONSOLE_LOGIN_SETTLE_SECONDS = 30  # g-console.md: wait 30 s after the login window appears,
CONSOLE_LOGIN_TYPE_SECONDS = 90    # then log in within the next 90 s
CONSOLE_FINISH_SECONDS = 30
CONSOLE_RESULT = re.compile(r"console=(login|approve) result=(typed|failed)(?: reason=([^\n]{0,120}))?")


class ConsoleDriver:
    """Runs console.py for one console step at a time and keeps a secret-free record of each (action, times, result).
    The password never passes through this process: console.py reads it from the lab login file itself."""

    def __init__(self, vnc_file, shots=None, popen=subprocess.Popen, clock=time.time, python=sys.executable):
        self.vnc_file, self.shots, self.popen, self.clock, self.python = vnc_file, shots, popen, clock, python
        self.process, self.current, self.log = None, None, []

    @classmethod
    def from_environment(cls, nonce, environ=None):
        environ = os.environ if environ is None else environ
        vnc_file = environ.get("WGEX_LAB_VNC_FILE")
        if not vnc_file:
            return None
        if not os.path.isabs(vnc_file):
            raise ValueError("WGEX_LAB_VNC_FILE must be an absolute path")
        tmp = environ.get("TMPDIR")
        return cls(vnc_file, shots=os.path.join(tmp, "wgex-console", nonce) if tmp else None)

    @staticmethod
    def stamp(value):
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(value))

    def start(self, action, not_before, deadline):
        if self.process is not None:
            self.finish()
        argv = [self.python, "-I", str(CONSOLE_SCRIPT), action, "--vnc-file", self.vnc_file, "--user", GUEST_USER,
                "--not-before", f"{not_before:.3f}", "--deadline", f"{deadline:.3f}"]
        if self.shots:
            argv += ["--shots", self.shots]
        self.current = dict(action=action, startedAt=self.stamp(self.clock()), notBefore=self.stamp(not_before),
                            deadline=self.stamp(deadline), result="running")
        self.log.append(self.current)
        self.process = self.popen(argv, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return self.current

    def finish(self, timeout=CONSOLE_FINISH_SECONDS):
        """Reaps the running step (killing it after timeout) and records its result word; None when nothing ran."""
        if self.process is None:
            return None
        process, item = self.process, self.current
        self.process = self.current = None
        try:
            out, _ = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            out, _ = process.communicate()
            item["result"] = "killed"
        match = CONSOLE_RESULT.search((out or b"").decode(errors="replace"))
        if item["result"] != "killed":
            item["result"] = match[2] if match else "unreadable"
        if match and match[3]:
            item["reason"] = match[3].strip()
        item.update(exitCode=process.returncode, endedAt=self.stamp(self.clock()))
        return item


def safe_stderr(data, limit=4096):
    """Retain bounded diagnostics, omitting credential lines and encoded key patterns."""
    text = (data or b"").decode(errors="replace") if isinstance(data, (bytes, type(None))) else str(data)
    text = re.sub(r"(?im)^.*(?:private.?key|preshared.?key|password|authorization|wrapping.?key).*$", "<redacted credential line>", text)
    text = re.sub(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}=|\b[0-9a-fA-F]{64}\b", "<redacted>", text)
    text = re.sub(r"(https?://)[^/\s]+@", r"\1<redacted>@", text)
    return text.encode()[:limit].decode(errors="ignore")


STEP_FAILURE_WITHHOLD = re.compile(r"(?i)(?:token|key|secret|password)[\"']?\s*[:=]|PASSWORD|SECRET|<redacted|"
                                   r"[A-Za-z0-9+/_=-]{40,}|\bbearer\s+\S")
STEP_FAILURE_CAP = 200


def live_step_gap(error):
    """M1-57 (run 9 F3, run 9b F3): the gap for a live step that failed for any reason but a named RowFailure or PollDeadline
    carries the first line of the error's message, stripped and capped, so an install-mode prepare refusal is diagnosable
    without opening the build-root ledger. A first line with a secret marker (colon or equals after token/key/secret/password,
    SECRET other than the row name BOOT-SECRETS, PASSWORD, a 40-character encoding-alphabet run, bearer value, or anything
    safe_stderr redacts) is withheld;
    an empty message keeps the bare text."""
    text = "Live step failed: " + type(error).__name__
    lines = str(error).strip().splitlines()
    if lines:
        first = lines[0].strip()
        if STEP_FAILURE_WITHHOLD.search(first.replace("BOOT-SECRETS", "")) or safe_stderr(first) != first:
            first = "(message withheld)"
        text += ": " + first[:STEP_FAILURE_CAP]
    return text + "; see build-root ledger"


# `just lab *args` is not @-prefixed, so just echoes its recipe body line to stderr before the tool runs (justfile `lab *args:`).
JUST_RECIPE_ECHO = ('bash Tools/lab/tart/lab.sh "$@"',)


def command_cause(stderr):
    """M1-57 fix pass 1 (VERIFY N2): the line of a failed command's stderr that names the cause: the last non-empty line once
    just's own recipe echo and its "error: recipe ... failed" trailer are set aside. That is the tool's refusal text for a
    `just lab` command and the exception line of a Python traceback. If that final diagnostic was redacted, return no cause
    (the bare error text), rather than naming an earlier progress line."""
    lines = [line.strip() for line in stderr.replace("\r", " ").split("\n")]
    lines = [line for line in lines if line and line not in JUST_RECIPE_ECHO
             and not line.lower().startswith("error: recipe")]
    return lines[-1] if lines and "<redacted" not in lines[-1] else ""


class PollDeadline(RuntimeError):
    """Named deadline with a separate bounded diagnostic record in build output."""


class RowFailure(RuntimeError):
    """Named, actionable row failure; the message carries no guest payload and is published in gaps."""

    def __init__(self, reason, detail):
        super().__init__(reason + ": " + detail)
        self.reason = reason


class ToggleMoved(Exception):
    """The press-time dump shows a toggle value other than the one the caller read before deciding to press (M1-10t): nothing
    was pressed. Raised by Session.click while Session.toggle_expected names the identifier."""


# At most this many presses of one toggle per Session, across every call (M1-10t, M1-10r VERIFY-B L3): a retry after a
# failure starts from the journal of the presses already made, never from zero.
TOGGLE_PRESS_LIMIT = 2


def public_key_digest(text):
    """12-hex SHA-256 prefix of the single key line in a fixture file; the key itself is never recorded."""
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if len(lines) != 1:
        raise ValueError("fixture public key format")
    return hashlib.sha256(lines[0].encode()).hexdigest()[:12]


def sidebar_rows(dump):
    """Profile row UUIDs in on-screen order, top to bottom; suffixed identifiers are not rows."""
    rows = {}
    for line in dump.splitlines():
        match = re.search(r"\bid=wgex\.main\.tunnel\.(" + UUID_PATTERN + r")\s*\|.*?\bpos=(-?\d+),(-?\d+)", line)
        if match:
            identity, position = match[1].upper(), (int(match[3]), int(match[2]))
            rows[identity] = min(rows.get(identity, position), position)
    return [identity for identity, _ in sorted(rows.items(), key=lambda item: item[1])]


def window_title(dump):
    """The dumped window's title; the main window titles itself with the selected profile name."""
    match = re.search(r"(?m)^AXWindow \| name=([^|\n]*?)\s*\|", dump)
    return match[1].strip() if match else None


# AppKit joins navigationTitle and navigationSubtitle with an en dash: "wgex-lab-dns – <status sentence>" (run 6, L16).
TITLE_STATUS_SEPARATOR = " \u2013 "


def title_form(title, name):
    """'exact' or 'statusSuffix' when the window title names the profile, otherwise None."""
    if title is None:
        return None
    if title == name:
        return "exact"
    prefix = name + TITLE_STATUS_SEPARATOR
    if title.startswith(prefix) and title[len(prefix):].strip():
        return "statusSuffix"
    return None


def keys_path(output):
    """The arrow-key helper's report: 'identifier' or 'window' (L17); anything else is unknown."""
    match = re.fullmatch(r"path=(identifier|window)\s*", output.decode(errors="replace"))
    return match[1] if match else "unknown"


def guest_client_check(path):
    """Guest shell test: a regular, executable, non-symlink file with the pinned iperf3 digest."""
    quoted = shlex.quote(path)
    return (f"test -f {quoted} && test ! -L {quoted} && test -x {quoted} && "
            f"test \"$(shasum -a 256 {quoted} | cut -d ' ' -f 1)\" = {IPERF3.PIN['sha256']}")


def clock_measurement(samples):
    sample = min(samples, key=lambda item: item["end"] - item["start"])
    offset = sample["timestamp"] - (sample["start"] + sample["end"]) / 2
    # Receiver times are shifted by offset below; only RTT/2 remains uncertain.
    uncertainty = (sample["end"] - sample["start"]) / 2
    if not all(math.isfinite(v) for v in (offset, uncertainty)) or not 0 <= uncertainty <= 2:
        raise ValueError("guest clock exceeds evaluator bound")
    return dict(offsetSeconds=offset, uncertaintySeconds=uncertainty, sampleCount=len(samples), source="minimum final-hop SSH RTT")


def inspect_capture_text(text, records, control_roles=None):
    """Inspect only marked packets in an offline en0 read; never persist payloads. control_roles (M1-10o fix pass): only
    unprotected windows of records with these roles count for tailSystemResolverObserved (the lead control); None: any."""
    packets = re.split(r"(?m)(?=^\d+\.\d+ (?:IP6?|IP6) )", text)
    dns_leaks = ipv6_leaks = 0
    tail_seen = False
    for packet in packets:
        match = re.match(r"(\d+\.\d+) (IP6?) .*? > (\S+):", packet)
        if not match:
            continue
        stamp, family, destination = float(match[1]), match[2], match[3]
        port = destination.rpartition(".")[2]
        for record in records:
            nonce = record["nonce"]
            def label(value):
                return bool(re.search(r"(?<![A-Za-z0-9-])" + re.escape(value) + r"(?![A-Za-z0-9-])", packet))
            if not (label(nonce) or label(nonce + "-system")):
                continue
            for window in record["windows"]:
                tolerance = record.get("clockToleranceSeconds", 0)
                if not window["start"] - tolerance <= stamp < window["end"] + tolerance:
                    continue
                denied = window["state"] in ("blocked", "protected")
                dns_leaks += int(denied and port == "53")
                ipv6_leaks += int(denied and family == "IP6")
                if (window["state"] == "unprotected" and label(nonce + "-system") and port == "53"
                        and (control_roles is None or record.get("role") in control_roles)):
                    tail_seen = True
    return dict(port53Inspected=True, ipv6Inspected=True, port53Leaks=dns_leaks, ipv6Leaks=ipv6_leaks,
                tailSystemResolverObserved=tail_seen)


def parse_observations(text):
    sections = {m[1]: m[2].strip() for m in re.finditer(r"__WGEX_([A-Z]+)__\n(.*?)(?=__WGEX_|\Z)", text, re.S)}
    raw = json.loads(sections.get("STATUS", "{}"))
    phases = ("idle", "preparing", "configuring", "active", "reasserting", "captiveWindow", "stopping", "failed", None)
    protections = ("protected", "blocked", "unprotected", "unknown", "captiveWindow", "unsupported", None)
    if raw.get("phase") not in phases or raw.get("protection") not in protections:
        raise ValueError("unknown status format")
    refs = re.findall(r"^\s*\d+\s+\S+\s+(\d+)\s+\d+ days", sections.get("REFERENCES", ""), re.M)
    log = re.fullmatch(r"events=(\d+); rawMessagesOmitted=1", sections.get("LOG", ""))
    result = dict(status={k: raw.get(k) for k in ("phase", "protection")}, referenceCount=len(refs), logEvents=int(log[1]) if log else None)
    for name in ["PFINFO", "REFERENCES", "RULES", "IFCONFIG", "ROUTES", "DNS"]:
        value = sections.get(name, "")
        if len(value.encode()) > 45000:
            raise ValueError("observation too large")
        value = re.sub(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}=|\b[0-9a-fA-F]{64}\b", "<redacted>", value)
        result[name.lower()] = value
    return result


class CommandRunner:
    now = staticmethod(time.time)
    monotonic = staticmethod(time.monotonic)
    sleep = staticmethod(time.sleep)

    def run(self, argv, data=None, timeout=100, env=None):
        return subprocess.run(argv, cwd=ROOT, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False, env=env)

    def start(self, argv, env=None):
        return subprocess.Popen(argv, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)


class Session:
    def __init__(self, row_name, controls, runner=None, probe_path=None, foreign_helper_path=None, no_install=False, iperf3_path=None):
        self.runner = runner or CommandRunner()
        self.controls = controls
        self.nonce = "lab-" + uuid.uuid4().hex
        self.stage = f"/Users/{GUEST_USER}/lab/verdict-" + self.nonce
        self.peer_stage = "/var/tmp/wgex-" + self.nonce
        build = STATE.build_root(ROOT).resolve()
        if build == ROOT or ROOT in build.parents:
            raise ValueError("build root must be outside repository")
        self.output = build / "lab-captures" / row_name / self.nonce
        self.output.mkdir(parents=True, mode=0o700)
        binaries = guest_binary_paths(build)
        self.probe_path = Path(probe_path) if probe_path else binaries["leakprobe"]
        self.foreign_helper = Path(foreign_helper_path) if foreign_helper_path else binaries["foreign-utun"]
        self.guest_binaries = dict(leakprobe=self.probe_path, **{"foreign-utun": self.foreign_helper})
        self.iperf3_path = Path(iperf3_path) if iperf3_path else IPERF3.asset_path()
        self.ledger, self.processes, self.cleanups, self.captures, self.fault_phases = [], [], [], {}, []
        self.receiver_started = False
        self.clock = dict(offsetSeconds=0, uncertaintySeconds=0)
        self.tcp_budget = 100
        self.window_number = 0
        self.prepared = self.row_finished = False
        self.last_status, self.deadlines = None, []
        # Guest run 8: per-row observations for verdict.row_checks, status polls recorded while sample_log is a list,
        # and the profile UUIDs select_profile resolved.
        self.row_observation, self.sample_log, self.profile_ids, self.boot_samples = {}, None, {}, []
        # M1-10m: the pending guest-load settle ("restore" or "reboot") the next GUI step runs first, and each settle's
        # result for the verdict's guestLoadAtGUIStart.
        self.gui_settle, self.guest_loads = None, []
        # M1-10o: the last press that acted (issuedAt and returnedAt on the guest clock, its path), stamped at the press
        # call after the element search, so GUI timing expectations never count the search; and the lockdownOffNeedsAdmin
        # gap of a row that needed lockdown off (the driver never turns it off), which skips the unprotected tail.
        self.last_press, self.lockdown_gap, self.lockdown_on = None, None, False
        self.observations_extra = []
        # M1-10t: (identifier, value read before the press) while toggle_until presses, and each toggle's presses so far.
        self.toggle_expected, self.toggle_journal = None, {}
        # M1-10t part 3 (VERIFY L-1): True once a `gui press` command has been sent for the current toggle press, so a reply that
        # raises afterwards is still counted as an attempt against TOGGLE_PRESS_LIMIT.
        self.press_sent = False
        # M1-10o fix pass: True once a lockdown row's lead control window (unprotectedLead) has been generated.
        self.lead_control = False
        # M1-10o fix pass 2 (F6): the utun capture coverage across M5.3-10's lead down and reconnect; None for other rows.
        self.utun_coverage = None
        # M1-10q: the remote path of the post-boot en0 capture (reboot_probe), for the unexplainedOutsideFlow read.
        self.post_boot_capture = None
        # M1-10u fix pass 1: the daemon's pid read right before the restart step (None: not recorded).
        self.pre_restart_daemon_pid = None
        # M1-10v: BOOT-SECRETS only: stop macOS reopening the app at the next login (prevent_relaunch) after the quit, before the reboot.
        self.prevent_login_relaunch = False
        self.no_install = no_install
        self.rosetta = False
        self.harness_scale = HARNESS.scale()
        self.snapshot = os.environ.get("WGEX_LAB_SNAPSHOT", "ready")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", self.snapshot):
            raise ValueError("invalid snapshot name")
        self.installation = dict(mode="snapshot-owner-asserted" if no_install else "build-and-install", snapshot=self.snapshot,
                                 buildCompleted=False, installCompleted=False, daemonRefreshed=False)
        self.provenance = dict(guestOS={}, sourceCommit=None, buildConfiguration=None,
                               buildInputs={}, artefacts={}, installed={})
        # M03-T03 (M5.3-07 only): the update bundle's path and receipt (build_update), then what measure_update found.
        self.update_build = self.update = None
        # M03-T07 phase B (DEC-034): the self-driven console, or None when the maintainer types at the guest console.
        self.console = ConsoleDriver.from_environment(self.nonce)

    @property
    def clock_tolerance(self):
        return self.clock["uncertaintySeconds"]

    def pause(self, seconds):
        self.runner.sleep(seconds)

    def command(self, argv, data=None, timeout=None, check=True, env=None, record_stdout=False):
        timeout = HARNESS.seconds("COMMAND") if timeout is None else timeout
        item = dict(argv=argv, start=self.runner.now())
        self.ledger.append(item)
        try:
            if env and "WGEX_LAB_SSH_DEADLINE" in env:
                item["sshDeadlineSeconds"] = int(env["WGEX_LAB_SSH_DEADLINE"])
            result = self.runner.run(argv, data=data, timeout=timeout, env=env)
        except subprocess.SubprocessError as error:
            item["error"] = "deadline"
            item["stderr"] = safe_stderr(getattr(error, "stderr", None))
            if record_stdout:
                item["stdout"] = safe_stderr(getattr(error, "stdout", None), 65536)
            raise RuntimeError("command deadline") from None
        item.update(exitCode=result.returncode, end=self.runner.now(), stderr=safe_stderr(result.stderr))
        if record_stdout:
            item.update(stdout=safe_stderr(result.stdout, 65536), stdoutTruncated=len(result.stdout) > 65536)
        if check and result.returncode:
            # M1-57: the tool's own error line names the cause (run 9: "engine: missing or stale XCFramework ...") and reaches
            # the gap; the ledger stays bounded, but cause selection must not use a truncated line or miss the final cause.
            # A None slice limit retains the full redacted copy without changing safe_stderr's other callers.
            cause = command_cause(safe_stderr(result.stderr, None))
            raise RuntimeError("command failed" + (": " + cause if cause else "") + "; inspect step ledger")
        return result.stdout

    def start(self, argv):
        self.ledger.append(dict(argv=argv, start=self.runner.now(), background=True))
        deadline = HARNESS.seconds("SSH_COMMAND")
        env = (dict(os.environ, WGEX_LAB_SSH_DEADLINE=str(deadline), WGEX_LAB_CONNECT_TIMEOUT=str(min(HARNESS.seconds("CONNECT_BUDGET"), deadline)))
               if argv[:3] == ["just", "lab", "ssh"] else None)
        process = self.runner.start(argv, env=env)
        self.processes.append(process)
        return process

    def lab(self, *args, ssh_deadline=None, **kw):
        if args[0] == "gui" and self.gui_settle:
            stage, self.gui_settle = self.gui_settle, None
            self.settle_guest(stage)
        if args[0] in ("ssh", "gui"):
            ssh_deadline = HARNESS.seconds("SSH_COMMAND") if ssh_deadline is None else ssh_deadline
            kw["env"] = dict(os.environ, WGEX_LAB_SSH_DEADLINE=str(ssh_deadline),
                             WGEX_LAB_CONNECT_TIMEOUT=str(min(HARNESS.seconds("CONNECT_BUDGET"), ssh_deadline)))
        return self.command(["just", "lab", *args], **kw)

    def settle_guest(self, stage):
        """The guest-load settle (M1-10m, guest run 8d: every row's own restore left the guest at load 19-52 when its GUI
        started), run by lab() before the first GUI step after prepare's restore or a reboot (stage). Reads the guest's
        1-minute load through the read-only guest-load action every GUEST_SETTLE_POLL_SECONDS until it is below
        HARNESS_GUEST_SETTLE_LOAD (unscaled), for at most GUEST_SETTLE seconds (scaled). Every reading goes to the ledger;
        at the bound the GUI starts anyway with a ledger warning, never a gap: load is context, not a verdict input. The
        last load read lands in the verdict's guestLoadAtGUIStart."""
        threshold, bound = HARNESS.threshold("GUEST_SETTLE_LOAD"), HARNESS.seconds("GUEST_SETTLE")
        start = self.runner.monotonic()
        deadline, readings, settled = start + bound, [], False
        while True:
            remaining = max(1, deadline - self.runner.monotonic())
            try:
                load = guest_load1(self.guest_action("guest-load", check=False, deadline=max(1, math.ceil(remaining)), timeout=remaining))
            except (RuntimeError, OSError):
                load = None
            readings.append(dict(at=self.runner.now(), load1=load))
            if load is not None and load < threshold:
                settled = True
                break
            if self.runner.monotonic() + GUEST_SETTLE_POLL_SECONDS >= deadline:
                break
            self.pause(GUEST_SETTLE_POLL_SECONDS)
        final = next((reading["load1"] for reading in reversed(readings) if reading["load1"] is not None), None)
        waited = round(self.runner.monotonic() - start, 3)
        entry = dict(guestSettle=stage, thresholdLoad1=threshold, boundSeconds=bound, readings=readings, settled=settled, waitedSeconds=waited)
        if not settled:
            entry["warning"] = (f"guest 1-minute load {'unreadable' if final is None else final} not below {threshold} after {waited} s "
                                f"({stage}); GUI steps start anyway")
        self.ledger.append(entry)
        self.guest_loads.append(dict(stage=stage, load1=final, settled=settled, thresholdLoad1=threshold, waitedSeconds=waited,
                                     readings=len(readings)))

    def walk_read(self, window, identifier=None, check=True):
        """One gui dump of a WGEX window (M1-10o): with an identifier the helper's targeted walk (gui dump APP WINDOW
        IDENTIFIER: the AXWindow line, the first described element carrying the identifier, the ax-walk line with
        target=found|missing), else the full dump. The dump's ledger entry gets the walk summary, the mode and the walk's
        duration in seconds (guest run 8e: complete walks of the connected main window took 142-161 s)."""
        args = ["gui", "dump", "WGEX", window] + ([identifier] if identifier else [])
        started = self.runner.monotonic()
        dump = self.lab(*args, check=check).decode(errors="replace")
        entry = next((item for item in reversed(self.ledger) if item.get("argv") == ["just", "lab", *args]), None)
        if entry is not None:
            entry.update(dumpMode="target" if identifier else "full", walk=dump_walk(dump), walkSeconds=round(self.runner.monotonic() - started, 3))
        return dump

    def read_dump(self, window, deadline=None, check=True, identifier=None, role="-", targeted=False):
        """gui.sh dump of one WGEX window (M1-10l, guest run 8d). A dump whose ax-walk line reports truncated=1 or errors is
        read again, up to DUMP_RETRIES times with DUMP_RETRY_SETTLE_SECONDS between reads, while the deadline (default
        GUI_SEARCH from now) allows; each retry is a ledger entry with the walk counts of the latest read. With an
        identifier (and role), a read carrying a line with that target ends the retries at once, complete or not (fix
        pass 1, F1), and is the read returned: carrying the target ranks first (M1-10l fix verify G1). The best read seen
        is returned (then dump_rank: truncated=0 first, then the most element lines, then the fewest errors; the later
        read on a tie), never simply the last, so a re-read worse than an earlier one never replaces it; the stop test
        is on that best read, never the latest (G1). A still-incomplete best reaches dump_summary as unreadable and the
        element parsers keep whatever lines it has. A dump without the line (an older helper, gui.sh's failure marker) is
        never retried. Only the first read raises; a re-read that fails or hits its command deadline ends the retries
        with the best read so far. targeted (M1-10o): every read is the helper's targeted walk for identifier, which stops
        at its first described match; callers that must see every match (ambiguity, child labels) keep the full dump."""
        deadline = self.runner.monotonic() + HARNESS.seconds("GUI_SEARCH") if deadline is None else deadline
        target = identifier if targeted else None

        def carries(read):
            return identifier is not None and dump_carries(read, identifier, role)

        def rank(read):
            return (carries(read),) + dump_rank(read)

        dump = self.walk_read(window, target, check=check)
        best = dump
        for retry in range(1, DUMP_RETRIES + 1):
            if not dump_incomplete(best) or carries(best) or self.runner.monotonic() + DUMP_RETRY_SETTLE_SECONDS >= deadline:
                break
            self.ledger.append(dict(dumpWindow=window, dumpRetry=retry, walk=dump_walk(dump)))
            self.pause(DUMP_RETRY_SETTLE_SECONDS)
            try:
                dump = self.walk_read(window, target, check=check)
            except RuntimeError:
                break
            if rank(dump) >= rank(best):
                best = dump
            if dump_rank(dump)[0] == 0:
                break
        return best

    def ssh(self, command, deadline=None, **kw):
        deadline = HARNESS.seconds("SSH_COMMAND") if deadline is None else deadline
        kw.setdefault("timeout", deadline + 10)
        return self.lab("ssh", "--", command, ssh_deadline=deadline, **kw)

    def peer(self, *args, **kw):
        return self.command([PEER, "shell", "wg-peer", "--", *args], **kw)

    def guest_action(self, action, *args, **kw):
        return self.ssh(shlex.join(["bash", self.stage + "/verdict-actions.sh", action, *args]), **kw)

    def gap_action(self, action, *args, **kw):
        return self.ssh(shlex.join(["bash", self.stage + "/gap-actions.sh", action, *args]), **kw)

    def console_login(self, logged_out_at):
        """Self-driven console: type the lab user's login 30 s after the logout (g-console.md), within the next 90 s."""
        console = getattr(self, "console", None)
        if console:
            not_before = logged_out_at + CONSOLE_LOGIN_SETTLE_SECONDS
            console.start("login", not_before, max(not_before, time.time()) + CONSOLE_LOGIN_TYPE_SECONDS)

    def console_approval(self, deadline):
        """Self-driven console: type the administrator approval once SecurityAgent shows its window (gap-actions
        agent-state), never before; returns True once the step has started."""
        console = getattr(self, "console", None)
        if not console:
            return False
        if self.gap_action("agent-state", check=False).strip() != b"agent=running windows=1":
            return False
        console.start("approve", time.time(), max(deadline, time.time() + CONSOLE_LOGIN_TYPE_SECONDS))
        return True

    def console_finish(self):
        console = getattr(self, "console", None)
        item = console.finish() if console else None
        if item:
            self.ledger.append(dict(consoleStep=dict(item)))
        return item

    def logout_row(self, profile):
        records = []
        identity = self.profile_ids[profile]
        for enabled in (False, True):
            # Through the app's Settings (M03-T07 phase B): the daemon refuses the guest CLI's boot-intent over SSH as
            # unauthorised (owner and console user: the SSH audit session is not the console's), and the CLI cannot enable it.
            if enabled:
                self.set_startup_boot(identity)
            else:
                self.set_startup_off(identity)
            item = dict(bootIntent=enabled, readBack=self.boot_intent(identity))
            self.row_observation.setdefault("logouts", []).append(item)
            if item["readBack"] is not enabled:
                raise RowFailure("bootIntentNotApplied", "the selected logout setting did not reach the guest profile")
            self.gap_action("logout")
            deadline = self.runner.monotonic() + HARNESS.seconds("CONSOLE_LOGOUT")
            while self.runner.monotonic() < deadline:
                if self.gap_action("console-user").strip() == b"logged-out":
                    item["loggedOut"] = True
                    logged_out_at = time.time()
                    g_signal("logged-out")
                    break
                self.pause(0.25)
            else:
                raise RowFailure("consoleLogoutMissing", "the guest console never logged out")
            self.await_status("protected" if enabled else "unprotected")
            observation = self.observe()
            item.update(whileLoggedOut=observation["status"]["protection"], referencesWhileLoggedOut=observation["referenceCount"])
            records.append(self.generate(item["whileLoggedOut"], role="loggedOut:" + ("on" if enabled else "off")))
            # No password is scripted. The ready guest or the maintainer supplies the existing lab user's console login.
            deadline = self.runner.monotonic() + HARNESS.seconds("CONSOLE_RELOGIN")
            g_signal("login-wait", HARNESS.seconds("CONSOLE_RELOGIN"))
            self.console_login(logged_out_at)
            try:
                while self.runner.monotonic() < deadline:
                    if self.gap_action("console-user").strip() == b"lab":
                        item["loggedIn"] = True
                        g_signal("logged-in")
                        break
                    self.pause(1)
                else:
                    raise RowFailure("consoleReloginMissing", "the lab user must relogin at the guest console; no password is scripted")
            finally:
                self.console_finish()
            item["statusAfterRelogin"] = self.status()
            # The off variant suspended the tunnel. Reconnect explicitly for the next variant, after recording relogin.
            if not enabled:
                self.lab("gui", "run", "open", "-a", "WGEX")
                self.connect(profile)
            self.await_status("protected", timeout=HARNESS.seconds("RELOGIN_PROTECTED"))
            records.append(self.generate("protected", role="relogin:" + ("on" if enabled else "off")))
        return records

    def login_item_state(self, identity):
        """LOGIN-SILENT: the profile's Connect at login choice and the Hide Dock icon preference, read from the app's own files."""
        text = self.gap_action("login-item-state", identity, check=False).decode(errors="replace")
        return VERDICT.LOGIN_SILENT.parse_login_item_state(text)

    def presentation(self):
        """LOGIN-SILENT: one presentation sample of the console session (windows, menu bar item, Dock item, app type); an
        unreadable reply is a sample with readable False, never an absent window."""
        budget = HARNESS.seconds("STATUS_POLL")
        try:
            text = self.gap_action("presentation", check=False, deadline=budget, timeout=budget + 10).decode(errors="replace")
        except (RuntimeError, OSError):
            text = ""
        sample = VERDICT.LOGIN_SILENT.parse_presentation(text)
        self.ledger.append(dict(presentation={key: sample.get(key) for key in ("readable", "process", "standardWindows", "otherWindows",
                                                                                "menuBarItem", "dockItem", "appType")}))
        return sample

    def presentation_series(self):
        self.pause(PRESENTATION_SETTLE_SECONDS)
        samples = []
        for index in range(PRESENTATION_SAMPLES):
            if index:
                self.pause(PRESENTATION_SPACING_SECONDS)
            samples.append(self.presentation())
        return samples

    def await_login_item(self, identity, key, wanted):
        current, deadline = None, self.runner.monotonic() + HARNESS.seconds("BOOT_INTENT_CONFIRM")
        while self.runner.monotonic() < deadline:
            current = self.login_item_state(identity)[key]
            if current is wanted:
                break
            self.pause(0.5)
        return current

    def set_startup_login(self, identity):
        """Settings, Service tab, Connection at startup: Connect at login (the app's own login item); the profile document must
        read autoConnectAtLogin true."""
        window = self.open_settings()
        self.select_settings_tab(window, "Service")
        self.select_startup_option(window, "login")
        current = self.await_login_item(identity, "autoConnectAtLogin", True)
        self.close_settings(window)
        self.ledger.append(dict(startupRequested="login", profileID=identity, autoConnectAtLoginReported=current))
        if current is not True:
            raise RowFailure("loginItemNotApplied", f"the profile document reports autoConnectAtLogin {current} after choosing Connect at login")

    def set_startup_off(self, identity):
        """Settings, Service tab, Connection at startup: Off (M5.3-09's start-before-login off round); the daemon registry must
        read startBeforeLoginOverride false."""
        window = self.open_settings()
        self.select_settings_tab(window, "Service")
        self.select_startup_option(window, "off")
        current, deadline = None, self.runner.monotonic() + HARNESS.seconds("BOOT_INTENT_CONFIRM")
        while self.runner.monotonic() < deadline:
            current = self.boot_intent(identity)
            if current is False:
                break
            self.pause(0.5)
        self.close_settings(window)
        self.ledger.append(dict(startupRequested="off", profileID=identity, bootIntentReported=current))
        if current is not False:
            raise RowFailure("bootIntentNotApplied", f"the daemon registry reports startBeforeLoginOverride {current} after choosing Off")

    def set_hide_dock(self, identity, wanted):
        """Settings, General tab: Hide Dock icon by compare-and-press until the app's preference reads `wanted`. The toggle's own
        value is read before every press and the press is pinned to it (toggle_expected); an unreadable toggle is never pressed
        blind, and at most two presses are made."""
        window = self.open_settings()
        self.select_settings_tab(window, "General")
        current, presses, toggle = self.login_item_state(identity)["hideDockIcon"], 0, None
        while current is not wanted and presses < 2:
            try:
                dump = self.read_dump(window, check=False, identifier=HIDE_DOCK_TOGGLE, targeted=True)
            except RuntimeError:
                dump = ""
            toggle = dump_toggle_value(dump, HIDE_DOCK_TOGGLE)
            self.ledger.append(dict(toggleIdentifier=HIDE_DOCK_TOGGLE, toggleValue=toggle, preferenceReported=current))
            if toggle is None or toggle is wanted:
                if toggle is wanted:
                    current = self.await_login_item(identity, "hideDockIcon", wanted)
                break
            self.toggle_expected, self.press_sent = (HIDE_DOCK_TOGGLE, toggle), False
            try:
                self.click_id(HIDE_DOCK_TOGGLE, window=window)
            except ToggleMoved:
                presses += 1
                continue
            finally:
                self.toggle_expected, self.press_sent = None, False
            presses += 1
            current = self.await_login_item(identity, "hideDockIcon", wanted)
        self.close_settings(window)
        self.ledger.append(dict(hideDockRequested=wanted, hideDockReported=current, togglePresses=presses))
        if current is not wanted:
            raise RowFailure("hideDockIconNotApplied", f"the app preference reports hideDockIcon {current} after {presses} press(es) of "
                             f"{HIDE_DOCK_TOGGLE} (toggle value {toggle}); an unreadable toggle is never pressed")

    def login_cycle(self, item):
        """Log the console out, wait for the lab user's console login (the maintainer at the guest console; no password is scripted) and for
        the login item to start the app with no driver launch."""
        self.gap_action("logout")
        deadline = self.runner.monotonic() + HARNESS.seconds("CONSOLE_LOGOUT")
        while self.gap_action("console-user").strip() != b"logged-out":
            if self.runner.monotonic() >= deadline:
                raise RowFailure("consoleLogoutMissing", "the guest console never logged out")
            self.pause(0.25)
        item["loggedOut"] = True
        logged_out_at = time.time()
        g_signal("logged-out")
        deadline = self.runner.monotonic() + HARNESS.seconds("CONSOLE_RELOGIN")
        g_signal("login-wait", HARNESS.seconds("CONSOLE_RELOGIN"))
        self.console_login(logged_out_at)
        try:
            while self.gap_action("console-user").strip() != b"lab":
                if self.runner.monotonic() >= deadline:
                    raise RowFailure("consoleReloginMissing", "the lab user must log in at the guest console; no password is scripted")
                self.pause(1)
        finally:
            self.console_finish()
        item["loggedIn"] = True
        g_signal("logged-in")
        deadline = self.runner.monotonic() + LOGIN_LAUNCH_SECONDS
        item["loginLaunchSeen"] = False
        while self.runner.monotonic() < deadline:
            if self.app_running():
                item["loginLaunchSeen"] = True
                break
            self.pause(1)

    def login_silent_row(self, profile):
        """LOGIN-SILENT (DEC-021). An ordinary launch first (Hide Dock icon off): one window and the Dock icon. Then Connect at
        login makes WGEX a login item, loginwindow's reopen-state relaunch is prevented (so only the login item can start the app),
        and for Hide Dock icon off and then on: quit, log out, the console login, presentation samples (no window, no Dock icon,
        the menu bar item), the menu's Open WGEX, samples again (the window, with the Dock icon only when Hide Dock icon is off).
        The tunnel is protected again before the protected window that closes the row."""
        identity = self.profile_ids[profile]
        row = self.row_observation.setdefault("loginSilent", dict(variants={}))
        self.set_hide_dock(identity, False)
        self.quit_app()
        self.lab("gui", "run", "open", "-a", "WGEX")
        row["ordinaryLaunch"] = dict(samples=self.presentation_series())
        self.set_startup_login(identity)
        row["loginItem"] = self.login_item_state(identity)
        for name, hide in VERDICT.LOGIN_SILENT.VARIANTS:
            self.set_hide_dock(identity, hide)
            item = row["variants"][name] = dict(loginItem=self.login_item_state(identity))
            self.quit_app()
            if "relaunchPrevention" not in self.row_observation:
                self.prevent_relaunch()
            self.login_cycle(item)
            if not item["loginLaunchSeen"]:
                raise RowFailure("loginLaunchMissing", f"no WGEX process within {LOGIN_LAUNCH_SECONDS} s of the console login ({name})")
            item["afterLogin"] = self.presentation_series()
            # The login's load settles before the menu opens, so the menu's window is not left open through the settle.
            self.settle_guest("login")
            item["menuOpened"] = self.gap_action("menu-open", check=False).strip() == b"menu=opened"
            if item["menuOpened"]:
                self.click_id(MENU_OPEN_WINDOW, window="1")
            item["fromMenu"] = self.presentation_series()
            item["statusAfterLogin"] = self.status()
        try:
            self.await_status("protected", timeout=HARNESS.seconds("RELOGIN_PROTECTED"))
            row["protectedWithoutAction"] = True
        except PollDeadline:
            row["protectedWithoutAction"] = False
            self.lab("gui", "run", "open", "-a", "WGEX")
            self.connect(profile)
            self.await_status("protected")
        self.pause(self.clock_tolerance * 2 + 0.1)
        return [self.generate("protected", role="afterLoginLaunch")]

    def update_action(self, action, *args, **kw):
        return self.ssh(shlex.join(["bash", self.stage + "/guest-update.sh", action, *args]), **kw)

    def corpus_action(self, action, *args, **kw):
        return self.ssh(shlex.join(["bash", self.stage + "/guest-corpus.sh", action, *args]), **kw)

    def build_update(self):
        """M5.3-07, before prepare: the update bundle (Tools/lab/update/build.sh, its own build root, so prepare's base build
        stays the checkout's ordinary Lab build). Its receipt is read back exactly like the base build's."""
        self.command(["bash", str(ROOT / "Tools/lab/update/build.sh")], timeout=UPDATE_BUILD_SECONDS)
        app = VERDICT.UPDATE.app_path(ROOT)
        receipt = json.loads(self.command([sys.executable, "-I", "-B", str(ROOT / "Tools/lab/check-verdicts.py"),
                                           "--inspect-build", str(app)]))
        self.update_build = dict(app=app, receipt={key: receipt[key] for key in
                                                   ("sourceCommit", "buildConfiguration", "buildInputs", "artefacts")})
        return self.update_build

    def measure_update(self):
        """End of M5.3-07, in place of the installed re-measure: the guest must run exactly the update bundle. The verdict's
        update carries that bundle's own receipt (sourceCommit, buildConfiguration, buildInputs, artefacts), the hashes
        found installed and the installed bundle version; check-verdicts validates them against the base build."""
        receipt = self.update_build["receipt"]
        measured = self.ssh(UPDATE_MEASURE).decode().splitlines()
        hashes = [line.removeprefix("CDHash=") for line in measured if line.startswith("CDHash=")]
        versions = [line.removeprefix("CFBundleVersion=") for line in measured if line.startswith("CFBundleVersion=")]
        if len(hashes) != 3 or any(not re.fullmatch(r"[0-9a-f]{40}", value) for value in hashes) or len(versions) != 1:
            raise ValueError("update installed code-directory hashes missing")
        installed = dict(zip(("app", "daemon", "cli"), hashes))
        self.update = dict(receipt, installed=installed, bundleVersion=versions[0])
        if installed != receipt["artefacts"]:
            raise RowFailure("updateNotInstalled", "the guest does not run the update bundle's binaries")

    def update_running(self):
        return json.loads(self.update_action("running", deadline=CORPUS_STEP_SECONDS))

    def press_finish_update(self, keep_probing=lambda: None):
        """Settings > Service shows Finish update once the new app sees an older daemon (MacDaemonBridge offerUpdate).
        keep_probing runs between the steps of opening Settings, selecting the tab and the offer wait, so the hand-off probes stay
        continuous through the slow console steps (M03-T17); returns the guest time of the press."""
        window = self.open_settings(keep_probing)
        self.select_settings_tab(window, "Service", keep_probing)
        keep_probing()
        deadline = self.runner.monotonic() + UPDATE_OFFER_SECONDS
        while not dump_carries(self.read_dump(window, identifier=FINISH_UPDATE, targeted=True, check=False), FINISH_UPDATE):
            if self.runner.monotonic() >= deadline:
                raise RowFailure("updateOfferMissing", "the new app never offered Finish update. On Lab builds the running daemon "
                                 "refuses the new app's code-directory hash and the new app refuses the running daemon's "
                                 "(catalogue dependency labUpdateIdentity)")
            self.pause(2)
            keep_probing()
        pressed = self.guest_now()
        # Identifier only (targeted walk), as every other identified press: the dumped title of this button did not match its
        # label live (M03-T07 phase B), while the identifier is unique on the Service tab.
        self.click(None, FINISH_UPDATE, window=window)
        return pressed

    def start_probe(self, state, role):
        """One hand-off marker generator in the background, with its own nonce and record file (M5.3-07)."""
        self.window_number += 1
        nonce = self.nonce + "-w" + str(self.window_number)
        path = self.stage + "/generator-" + str(self.window_number) + ".json"
        command = shlex.join([self.stage + "/leakprobe", "generate", "--config", self.stage + "/config.json", "--rounds",
                              str(UPDATE_PROBE_ROUNDS), "--state", state, "--nonce", nonce, "--record", path]) + " >/dev/null"
        return dict(process=self.start(["just", "lab", "ssh", "--", command]), path=path, role=role, nonce=nonce,
                    started=self.runner.monotonic())

    def probe_running(self, probe):
        """True once the generator of probe runs in the guest (its window start is taken at process start)."""
        if not re.fullmatch(r"[A-Za-z0-9-]{1,128}", probe["nonce"]):
            raise ValueError("unexpected generator nonce")
        # The nonce holds only letters, digits and hyphens, so it is literal in pgrep's extended regex as it stands.
        pattern = "leakprobe generate .*--nonce " + probe["nonce"] + "( |$)"
        return self.ssh("pgrep -f -- " + shlex.quote(pattern) + " >/dev/null && echo running || echo absent",
                        check=False).strip() == b"running"

    def wait_probe_running(self, probe):
        """Waits until probe's generator runs in the guest, so a start taken afterwards lies inside its window."""
        deadline = self.runner.monotonic() + UPDATE_PROBE_START_SECONDS
        while not self.probe_running(probe):
            if self.runner.monotonic() >= deadline:
                raise RowFailure("updateProbeNotStarted", "the first hand-off marker generator did not start in the guest")
            self.pause(0.5)

    def collect_daemon_log(self, since, kept):
        """Merges the guest daemon-log tail since the stamp into kept, keyed (stamp, line, occurrence). The tail holds 50
        lines, so the steady verifier lines after the hand-off would roll the new daemon's start line away before the row
        ends; the row reads it while the hand-off runs and again at the end (M03-T07 phase C2)."""
        seen = {}
        for stamp, line in json.loads(self.update_action("daemon-log-stamped", since)):
            seen[(stamp, line)] = seen.get((stamp, line), 0) + 1
            kept.setdefault((stamp, line, seen[(stamp, line)]), line)
        return [kept[key] for key in sorted(kept, key=lambda key: key[0])]

    def finish_probe(self, probe):
        """Waits for one hand-off generator and returns its record. The window keeps the generator's own start and end: the
        hand-off coverage is judged on the intervals that really carried markers."""
        try:
            if probe["process"].wait(timeout=UPDATE_PROBE_ROUNDS / 2 + HARNESS.seconds("GENERATOR_WAIT")):
                raise RuntimeError("guest generator failed")
        except subprocess.TimeoutExpired:
            raise RuntimeError("guest generator deadline") from None
        record = json.loads(self.ssh("cat " + shlex.quote(probe["path"])))
        record.update(clockToleranceSeconds=self.clock_tolerance, role=probe["role"])
        for window in record["windows"]:
            window["requiredFamilies"] = ["ipv4"]
            window.pop("receiversComplete", None)
        return record

    def stop_probes(self, probes):
        """A failed hand-off: the host side of every generator still running is stopped (only processes this row started)."""
        for probe in probes:
            process = probe["process"]
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=HARNESS.seconds("PROCESS_STOP"))
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=HARNESS.seconds("PROCESS_STOP"))

    def handoff_sample(self, observation):
        """One status and daemon-pid reading during the hand-off; True once a new daemon publishes protected."""
        try:
            protection = self.status(budget=HARNESS.seconds("STATUS_POLL"))["protection"]
        except (RuntimeError, ValueError):
            protection = "unavailable"
        found = re.fullmatch(rb"\s*([1-9][0-9]{0,9})\s*", self.ssh("pgrep -x WGEXDaemon || true", check=False))
        pid = int(found[1]) if found else None
        observation["samples"].append(dict(at=self.guest_now(), protection=protection, daemonPid=pid))
        return pid is not None and pid != observation["before"]["daemonPid"] and protection == "protected"

    def update_row(self, profile):
        """M5.3-07: install the update over the running bundle while connected and let the product hand off.

        Overlapping marker generators run without a gap from before the app quits until a new daemon is confirmed protected
        (start_probe, a new one every UPDATE_PROBE_STEP_SECONDS and between the steps). While the old daemon keeps the tunnel
        they are protected-state: the app quits (as an installer makes it), the bundle on disk becomes the update, the
        escrowed wrapping key is re-trusted for the new daemon (DEC-007) and the new app opens. From before the Settings
        window opens they are blocked-state, through the Finish update press and the swap, and deny any outside marker. The
        observation keeps their intervals, the start, the press and the recovery, so update.handoff_covered judges the whole
        interval. A last protected window proves in-tunnel delivery again. The administrator prompt is approved at the guest
        console; nothing is typed here."""
        base, receipt = self.provenance, self.update_build["receipt"]
        if receipt["sourceCommit"] != base.get("sourceCommit"):
            raise RowFailure("updateSourceDiffers", "the update bundle was built from another commit than the base build")
        observation = self.row_observation.setdefault("update", {})
        observation.update(baseVersion=VERDICT.UPDATE.receipt_version(base.get("buildInputs")),
                           updateVersion=VERDICT.UPDATE.receipt_version(receipt["buildInputs"]), samples=[],
                           expected=dict(baseDaemon=base.get("artefacts", {}).get("daemon"), updateDaemon=receipt["artefacts"].get("daemon")))
        for name, directory in (("guest-update.sh", ROOT / "Tools/lab/update"), ("wrapping-key.sh", ROOT / "Tools/lab/tart/guest")):
            self.guest_file((directory / name).read_bytes(), name)
        # The transfer is staging, not part of the update: it happens before any window.
        archive = self.output / "update.zip"
        self.command(["ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", str(self.update_build["app"]), str(archive)],
                     timeout=UPDATE_TRANSFER_SECONDS)
        self.ssh("umask 077; mkdir -p " + shlex.quote(self.stage + "/update"))
        self.cleanups.append(named("update cleanup", lambda: self.update_action("cleanup")))
        self.ssh("umask 077; cat > " + shlex.quote(self.stage + "/update/WGEX.zip"), data=archive.read_bytes(),
                 deadline=UPDATE_TRANSFER_SECONDS)
        self.update_action("unpack", deadline=UPDATE_TRANSFER_SECONDS)
        observation["before"] = self.update_running()
        since = self.update_action("stamp").decode().strip()

        probes, phase, daemon_lines = [], dict(state="protected", label="replace"), {}

        def keep_probing(force=False):
            if force or self.runner.monotonic() - probes[-1]["started"] >= UPDATE_PROBE_STEP_SECONDS:
                probes.append(self.start_probe(phase["state"], f"update:{phase['label']}-{len(probes)}"))

        try:
            keep_probing(force=True)
            self.wait_probe_running(probes[0])
            self.pause(1)
            observation["probedFrom"] = self.guest_now()
            self.quit_app()
            keep_probing()
            replaced = json.loads(self.update_action("replace", deadline=UPDATE_TRANSFER_SECONDS))
            observation.update(replaced=replaced.get("replaced") is True, protectionAtReplacement=replaced.get("protectionAtReplacement"))
            keep_probing()
            self.update_action("retrust")
            keep_probing()
            self.lab("gui", "run", "open", "-a", "WGEX")
            self.lab("gui", "activate", "WGEX")
            self.sample_phase("during:update:replace")
            # The tunnel may be swapped from here on: blocked-state generators, the first overlapping the last protected one.
            phase.update(state="blocked", label="handoff")
            keep_probing(force=True)
            self.pause(1)
            observation["pressedAt"] = self.press_finish_update(keep_probing)
            observation.update(offerShown=True, finishPressed=True)
            pressed, swapped = self.runner.monotonic(), None
            g_signal("approval-wait", UPDATE_APPROVAL_SECONDS)
            approval_deadline, approval_started = time.time() + UPDATE_APPROVAL_SECONDS, False
            while True:
                keep_probing()
                if not approval_started and swapped is None:
                    approval_started = self.console_approval(approval_deadline)
                recovered = self.handoff_sample(observation)
                started = any(s["daemonPid"] not in (None, observation["before"]["daemonPid"]) for s in observation["samples"])
                if started and swapped is None:
                    swapped = self.runner.monotonic()
                    g_signal("approval-seen")
                if swapped is not None:
                    observation["daemonLog"] = self.collect_daemon_log(since, daemon_lines)
                if recovered:
                    observation["recoveredAt"] = observation["samples"][-1]["at"]
                    break
                if swapped is None and self.runner.monotonic() - pressed > UPDATE_APPROVAL_SECONDS:
                    raise RowFailure("updateApprovalMissing", "the old daemon still runs after Finish update; the administrator prompt "
                                     "must be approved at the guest console (no password is scripted)")
                if swapped is not None and self.runner.monotonic() - swapped > UPDATE_RECOVERY_SECONDS:
                    raise RowFailure("updateNotProtected", "the new daemon did not publish protected after the hand-off")
                self.pause(1)
        except BaseException:
            self.console_finish()
            self.stop_probes(probes)
            raise
        self.console_finish()
        records = [self.finish_probe(probe) for probe in probes]
        observation["handoffWindows"] = [dict(state=window.get("state"), start=window.get("start"), end=window.get("end"))
                                         for record in records for window in record["windows"]]
        observation["clockToleranceSeconds"] = self.clock_tolerance
        records.append(self.generate("protected", role="update:after"))
        observation["after"] = self.update_running()
        observation["daemonLog"] = self.collect_daemon_log(since, daemon_lines)
        return records

    def uninstall_action(self, action, *args, **kw):
        return self.ssh(shlex.join(["bash", self.stage + "/guest-uninstall.sh", action, *args]), **kw)

    def uninstall_fields(self, action, *args):
        """One guest-uninstall.sh read as NAME=VALUE lines; a value that is JSON (status, reply, journal) is decoded."""
        fields = {}
        for line in self.uninstall_action(action, *args, record_stdout=True).decode(errors="replace").splitlines():
            name, separator, value = line.partition("=")
            if not separator or not re.fullmatch(r"[A-Za-z]{1,40}", name):
                continue
            if value[:1] == "{":
                try:
                    value = json.loads(value)
                except ValueError:
                    value = None
            elif re.fullmatch(r"-?[0-9]{1,6}", value):
                value = int(value)
            elif value in ("true", "false"):
                value = value == "true"
            if name == "file":
                fields.setdefault("files", []).append(value)
            else:
                fields[name] = value
        return fields

    def uninstall_refused(self, identity):
        """The console user's mutating requests after the uninstall: each as [exit code, error name]."""
        result = {}
        for line in self.uninstall_action("refuse", identity).decode(errors="replace").splitlines():
            match = re.fullmatch(r"(up|onDemand|down)=([0-9]{1,3}) ([A-Za-z]{1,40})", line.strip())
            if match:
                result[match[1]] = [int(match[2]), match[3]]
        return result

    def uninstall_state(self, identity):
        """What the row reads at each point: one observe (reduced), the pf anchor counts, the services and the profile store."""
        full = self.observe()
        self.observations_extra.append(full)
        return dict(observation=VERDICT.UNINSTALL.reduce_observation(full), pf=self.uninstall_fields("pf"),
                    services=self.uninstall_fields("services"), profiles=self.uninstall_fields("profiles", identity))

    def await_offer(self, identifier, seconds, window="1"):
        """True once the window carries the control (targeted walk), polled every 2 s for at most `seconds`."""
        deadline = self.runner.monotonic() + seconds
        while self.runner.monotonic() < deadline:
            try:
                if dump_carries(self.read_dump(window, identifier=identifier, targeted=True, check=False), identifier):
                    return True
            except RuntimeError:
                pass
            self.pause(2)
        return False

    def uninstall_cli(self, variant):
        """`wgex uninstall [--purge] --yes` in the console session; the administrator dialog is typed at the guest console
        (DEC-034) once SecurityAgent shows it. Returns the exit code, the reply's fixed fields and the console step."""
        started = self.uninstall_fields("cli-start", variant)
        seconds = HARNESS.seconds("UNINSTALL_CLI")
        deadline, approval_deadline, approval_started, result = self.runner.monotonic() + seconds, time.time() + seconds, False, {}
        g_signal("approval-wait", seconds)
        try:
            while self.runner.monotonic() < deadline:
                result = self.uninstall_fields("cli-result")
                if result.get("rc") != "running":
                    break
                if not approval_started:
                    approval_started = self.console_approval(approval_deadline)
                self.pause(1)
        finally:
            step = self.console_finish()
        self.uninstall_action("cleanup")
        approval = dict(result=step.get("result"), startedAt=step.get("startedAt")) if step else dict(result="notStarted")
        if result.get("rc") in (None, "running"):
            raise RowFailure("uninstallApprovalMissing", f"wgex uninstall did not finish within {HARNESS.seconds('UNINSTALL_CLI')} s "
                             f"(console approval {approval['result']})")
        return dict(rc=result.get("rc"), reply=result.get("reply"), approval=approval, startedAt=started.get("startedAt"))

    def uninstall_finish(self, identity):
        """Open the app: it offers to finish the CLI's uninstall; Finish removes the background service and the login item
        (DEC-037) and shows the final screen, whose Quit ends the app. The final screen's time is the unregister hang watch
        (M05-T11). A Quit that leaves the app running is recorded and the driver then stops the app itself."""
        self.lab("gui", "run", "open", "-a", "WGEX")
        self.lab("gui", "activate", "WGEX")
        finish = dict(offered=self.await_offer(UNINSTALL_CONFIRM, HARNESS.seconds("UNINSTALL_FINISH_OFFER")))
        if not finish["offered"]:
            raise RowFailure("uninstallFinishNotOffered", "the app did not offer to finish the uninstall (wgex.service.uninstallConfirm)")
        pressed = self.runner.monotonic()
        self.click_id(UNINSTALL_CONFIRM)
        bound = VERDICT.UNINSTALL.FINISH_BOUND_SECONDS
        finish["finalScreen"] = self.await_offer(UNINSTALL_QUIT, bound)
        finish["seconds"] = round(self.runner.monotonic() - pressed, 1)
        finish["services"] = self.uninstall_fields("services")
        finish["profiles"] = self.uninstall_fields("profiles", identity)
        quit_item = finish["quit"] = dict(pressed=False, exited=False)
        if finish["finalScreen"]:
            self.click_id(UNINSTALL_QUIT)
            quit_item["pressed"] = True
            deadline = self.runner.monotonic() + VERDICT.UNINSTALL.QUIT_BOUND_SECONDS
            while self.runner.monotonic() < deadline:
                if self.uninstall_fields("app-state").get("app") == "exited":
                    quit_item["exited"] = True
                    break
                self.pause(1)
        if not quit_item["exited"]:
            quit_item["driverStopped"] = self.uninstall_fields("stop-app").get("stopped")
        return finish

    def uninstall_reinstall(self, profile, identity):
        """A fresh secure install from the app: Settings > Service, Register Background Service, then the secure install action,
        whose administrator dialog is typed at the guest console; then Connect. A tunnel that does not start within the bound is
        recorded with the daemon's start-failure line, and the driver restarts the daemon once (recorded) so the row can go on."""
        install = {}
        window = self.open_settings()
        self.select_settings_tab(window, "Service")
        self.click_id(REGISTER_SERVICE, window=window)
        deadline = self.runner.monotonic() + HARNESS.seconds("UNINSTALL_REGISTER")
        while self.runner.monotonic() < deadline:
            install["services"] = self.uninstall_fields("services")
            if install["services"].get("launchdJob") == "present" and install["services"].get("daemonPid") != "none":
                break
            self.pause(2)
        if not self.await_offer(SECURE_INSTALL_ACTION, HARNESS.seconds("UNINSTALL_FINISH_OFFER"), window=window):
            raise RowFailure("secureInstallActionMissing", "Settings > Service shows no secure install action after the register")
        self.click_id(SECURE_INSTALL_ACTION, window=window)
        seconds = HARNESS.seconds("UNINSTALL_SECURE_INSTALL")
        deadline, approval_deadline, approval_started = self.runner.monotonic() + seconds, time.time() + seconds, False
        g_signal("approval-wait", seconds)
        try:
            while self.runner.monotonic() < deadline:
                if not approval_started:
                    approval_started = self.console_approval(approval_deadline)
                doctor = self.uninstall_fields("secure-install")
                install["secureInstall"] = doctor.get("secureInstall")
                if install["secureInstall"] == "verified":
                    break
                self.pause(2)
        finally:
            step = self.console_finish()
        install["approval"] = step.get("result") if step else "notStarted"
        self.close_settings(window)
        since = self.uninstall_action("stamp").decode().strip()
        self.connect(profile)
        tunnel = install["tunnel"] = dict(protected=False)
        try:
            self.await_status("protected", timeout=VERDICT.UNINSTALL.TUNNEL_BOUND_SECONDS)
            tunnel["protected"] = True
        except PollDeadline:
            tunnel["status"] = self.status()
            tunnel["startFailure"] = self.uninstall_action("start-failure", since).decode(errors="replace").strip().splitlines()
            self.guest_action("down")
            self.uninstall_action("restart-daemon")
            tunnel["driverRestartedDaemon"] = True
            self.guest_action("secure-install-status")
            self.connect(profile)
            self.await_status("protected", timeout=VERDICT.UNINSTALL.TUNNEL_BOUND_SECONDS)
            tunnel["protectedAfterDaemonRestart"] = True
        return install

    def uninstall_row(self, profile, baseline):
        """M03-T15 (UNINSTALL, DEC-037 item 4, DEC-040): for keep and then purge, with the tunnel up and the kill switch armed,
        `wgex uninstall` (the administrator approval typed at the guest console) must leave no WGEX pf rule, route or resolver
        and the launchd job until the app finishes it; then a fresh secure install from the app brings the daemon back and a
        tunnel starts. The baseline is the row's first observation, taken before any connect."""
        for name in ("guest-uninstall.sh",):
            self.guest_file((ROOT / "Tools/lab/uninstall" / name).read_bytes(), name)
        self.cleanups.append(named("uninstall cleanup", lambda: self.uninstall_action("cleanup")))
        self.select_profile(profile)
        identity = self.profile_ids[profile]
        row = self.row_observation["uninstall"] = dict(baseline=VERDICT.UNINSTALL.reduce_observation(baseline), variants={})
        records = []
        # The app's own login item, so the keep variant can show the app removing it (DEC-037).
        self.set_startup_login(identity)
        for variant in VERDICT.UNINSTALL.VARIANTS:
            item = row["variants"][variant] = {}
            # The keep variant's fresh install leaves the tunnel up, and the toolbar then offers Disconnect, not Connect.
            if self.status() != dict(phase="active", protection="protected"):
                self.connect(profile)
            self.await_status("protected", timeout=VERDICT.UNINSTALL.TUNNEL_BOUND_SECONDS)
            self.pause(self.clock_tolerance * 2 + 0.1)
            records.append(dict(self.generate("protected", role="beforeUninstall:" + variant), profileVariant=profile))
            item["before"] = self.uninstall_state(identity)
            if variant == "purge":
                # The generation while protected: the purge must keep it (the fence), never drop or lower it.
                item["before"]["stateRoot"] = self.uninstall_fields("state-root")
            self.quit_app()
            item["cli"] = self.uninstall_cli(variant)
            after = item["after"] = self.uninstall_state(identity)
            after["status"] = self.uninstall_fields("status")
            after["refused"] = self.uninstall_refused(identity)
            if variant == "purge":
                after["stateRoot"] = self.uninstall_fields("state-root")
            # The kill switch is off: the outside receivers must see every marker.
            self.pause(self.clock_tolerance * 2 + 0.1)
            records.append(dict(self.generate("unprotected", role="afterUninstall:" + variant), profileVariant=profile))
            item["finish"] = self.uninstall_finish(identity)
            item["freshInstall"] = self.uninstall_reinstall(profile, identity)
            self.pause(self.clock_tolerance * 2 + 0.1)
            records.append(dict(self.generate("protected", role="afterFreshInstall:" + variant), profileVariant=profile))
            self.observations_extra.append(self.observe())
        return records

    def rt17_row(self):
        """RT-17: the identity corpus inside one protected window, then the impostor, then the genuine CLI's down, which proves
        the lifecycle observer sees privileged work. A client whose identity is not what its name claims is never run. Each
        attempt carries the client's own report and the daemon's libxpc refusal count, so only the daemon's refusal passes
        (Tools/lab/corpus/corpus.py)."""
        client = STATE.build_root(ROOT) / "lab-tools" / CORPUS_CLIENT
        self.command(["bash", str(ROOT / "Tools/lab/corpus/build.sh"), str(client)], timeout=CORPUS_STEP_SECONDS)
        self.guest_file((ROOT / "Tools/lab/corpus/guest-corpus.sh").read_bytes(), "guest-corpus.sh")
        self.guest_file((ROOT / "Tools/lab/corpus/attempt.pl").read_bytes(), "corpus-attempt.pl")
        self.guest_file(client.read_bytes(), CORPUS_CLIENT)
        self.guest_file(client.with_name(CORPUS_CLIENT_X86).read_bytes(), CORPUS_CLIENT_X86)
        self.ssh("chmod 0700 " + shlex.quote(self.stage + "/" + CORPUS_CLIENT) + " " + shlex.quote(self.stage + "/" + CORPUS_CLIENT_X86))
        self.cleanups.append(named("corpus cleanup", lambda: self.corpus_action("cleanup")))
        observation = self.row_observation

        def attempts():
            manifest = json.loads(self.corpus_action("prepare", deadline=CORPUS_STEP_SECONDS))
            genuine, described = manifest["genuine"], {item.get("name"): item for item in manifest["clients"]}
            observation.update(genuine=genuine, clients=[])
            # The layout's positive control first: the genuine CLI from the corpus layout must be served and refused by no one.
            observation["layoutControl"] = json.loads(self.corpus_action("attempt", "genuine", deadline=CORPUS_STEP_SECONDS))
            for name in VERDICT.CORPUS.REQUIRED_CLIENTS:
                item = dict(described.get(name) or dict(name=name))
                if VERDICT.CORPUS.identity_valid(name, item, genuine):
                    item.update(json.loads(self.corpus_action("attempt", name, deadline=CORPUS_STEP_SECONDS)))
                else:
                    item["outcome"] = "corpusInvalid"
                observation["clients"].append(item)
            observation["impostor"] = json.loads(self.corpus_action("impostor", deadline=CORPUS_STEP_SECONDS))

        records = [self.generate("protected", attempts, role="identityCorpus")]
        observation["logControl"] = json.loads(self.corpus_action("control", deadline=CORPUS_STEP_SECONDS))
        return records

    def guest_file(self, data, name):
        self.ssh("umask 077; cat > " + shlex.quote(self.stage + "/" + name), data=data)

    def peer_file(self, data, name):
        self.peer("bash", "-c", "umask 077; cat > " + shlex.quote(self.peer_stage + "/" + name), data=data)

    def click(self, label, identifier=None, window="1", timeout=None):
        """Actuate one control (M1-10j). With an identifier: the element path, AXPress through System Events on the
        element matching identifier and dumped role, with the frame centre as the guest-side coordinate fallback (except a toggle
        the caller read, toggle_expected: M1-38, a frame-pinned press-only with no point, so nothing is ever clicked blind).
        Label-only targets keep the centre click. Either way the frame must lie inside the dumped window first; an
        identified element outside is scrolled into view once (AXScrollToVisible or its scroll bar) and handed to
        after_scroll (M1-10k), which never raises the generic ValueError. Returns the action path (None for coordinate
        clicks). M1-10o: an identifier without a label is searched with the helper's targeted walk (read_dump targeted);
        a prefix identifier (ending in ".") or a child label keeps the full dump. Every press that acts stamps last_press."""
        deadline = self.runner.monotonic() + (HARNESS.seconds("GUI_SEARCH") if timeout is None else timeout)
        calibrated = identifier is None and label is not None and label.casefold() in {key.casefold() for key in self.controls}
        targeted = identifier is not None and label is None and not identifier.endswith(".")
        dump = ""
        while self.runner.monotonic() < deadline:
            dump = self.read_dump(window, deadline=deadline, identifier=identifier, targeted=targeted)
            if "keyInUseElsewhere" in dump:
                raise ValueError("dedicated key required")
            try:
                if calibrated:
                    x, y = control_position(dump, label, self.controls)
                    issued = self.guest_now()
                    self.lab("gui", "click", str(x), str(y))
                    self.pressed(issued, "coordinate")
                    return
                frame, child = element_target(dump, identifier, label) if identifier else (control_frame(dump, label), False)
            except ValueError:
                self.pause(0.2)
                continue
            compared = bool(identifier) and self.toggle_compared(identifier)
            role = element_role(dump, identifier, None if child else frame, controls=compared) if identifier else None
            if identifier:
                self.expect_toggle(dump, identifier, None if child else frame, None if child else role)
            bounds, child_label = window_frame(dump), [label] if child else []
            record = dict(controlIdentifier=identifier, controlLabel=label, controlRole=role, elementFrame=list(frame),
                          windowFrame=list(bounds) if bounds else None)
            if not frame_inside(frame, bounds):
                if identifier:
                    output = self.lab("gui", "scroll", "WGEX", window, identifier, *child_label, check=False)
                    self.ledger.append(dict(record, scroll=action_path(output, "scroll", SCROLL_PATHS)))
                    return self.after_scroll(record, window, window_title(dump), child_label)
                self.ledger.append(dict(record, error="target outside the window"))
                raise RowFailure("guiTargetOffscreen:" + label, f"element frame {frame_text(frame)} outside window frame {frame_text(bounds)}")
            if not identifier:
                issued = self.guest_now()
                self.lab("gui", "click", str(frame[0] + frame[2] // 2), str(frame[1] + frame[3] // 2))
                self.pressed(issued, "coordinate")
                return None
            return self.press_inside(record, window, frame, bounds, role, child_label, match_frame=compared and not child,
                                     compared=compared and not child)
        entry = dict(controlIdentifier=identifier, controlLabel=label, error="missing or ambiguous accessible control")
        detail = ""
        if identifier:
            entry["lastDump"] = dump_summary(dump, identifier)
            # M07-T15: a targeted walk sees only its target, so one full read names the candidates the miss had to choose from.
            try:
                full = self.walk_read(window, check=False)
            except (RuntimeError, ValueError):
                full = ""
            exact, near = control_candidates(full, identifier)
            entry["candidates"] = dict(exact=exact, near=near, fullDumpLines=len(full.splitlines()))
            detail = f": searched id={identifier!r} label={label!r}; exact matches {exact}; {len(near)} candidates {near}"
        self.ledger.append(entry)
        raise ValueError("missing or ambiguous accessible control" + detail)

    def toggle_compared(self, identifier):
        """True while toggle_expected names this identifier: the caller read its value, so its press is compared and pinned."""
        return self.toggle_expected is not None and self.toggle_expected[0] == identifier

    def expect_toggle(self, dump, identifier, frame=None, role=None):
        """Compare before pressing (M1-10t, M1-10r VERIFY-B L2): while toggle_expected names this identifier, the dump the press
        is taken from must show the value the caller read; otherwise nothing is pressed and ToggleMoved is raised. The window
        between that dump and the helper's own walk stays; a guest-side compare was not added (no guest run in this ticket).
        frame and role (M1-36, LAB3-VERIFY G-1): the frame and role the press targets, which the press then passes to the helper;
        the value is read on the dump lines of that role at that frame only, and more than one such line is ToggleMoved. An
        earlier line with another frame or another role is never read. None (a child-label target): the first line carrying it."""
        if not self.toggle_compared(identifier):
            return
        expected, seen = self.toggle_expected[1], dump_toggle_value(dump, identifier, frame, role)
        if seen is not expected:
            self.ledger.append(dict(controlIdentifier=identifier, toggleExpected=expected, toggleSeen=seen,
                                    error="toggle value differs from the value read before the press; not pressed"))
            raise ToggleMoved(identifier)

    def press_inside(self, record, window, frame, bounds, role, child_label, match_frame=False, compared=False):
        """AXPress (or the guest-side click at the frame centre) on an element whose frame lies inside its window.
        match_frame: the helper also matches this frame, because the dump showed the identifier more than once (F3) or, M1-36,
        because the caller read this toggle's value (toggle_expected): a compared toggle is always pinned.
        compared (M1-38, M1-36 VERIFY H-2): the press is a pinned press-only, never `press` with a point: when the frame drifted
        between the dump and the helper's walk, the helper's coordinate fallback would click a blind point; press-only has no
        point, so a drifted frame is a retry (press_only) or the named gap guiActionFailed:<identifier>, nothing clicked."""
        identifier = record["controlIdentifier"]
        if compared:
            return self.press_only(dict(record, elementFrame=list(frame)), window, child_label, "inside its window", match_frame=frame,
                                   inside=True)
        x, y = frame[0] + frame[2] // 2, frame[1] + frame[3] // 2
        tail = [frame_argument(frame)] if match_frame else child_label
        issued = self.guest_now()
        self.press_sent = True
        output = self.lab("gui", "press", "WGEX", window, identifier, "press", str(x), str(y), role, *tail, check=False)
        path = action_path(output)
        # A popup press is sent ignoring application responses; element-timeout records an Apple Event timeout (F3).
        self.ledger.append(dict(record, actionPath=path, popupTimedOut=path == "element-timeout"))
        if path not in PRESSED_PATHS:
            raise RowFailure("guiActionFailed:" + identifier, f"neither AXPress nor the click at {x},{y} inside window frame "
                             f"{frame_text(bounds)} succeeded; see the step ledger")
        self.pressed(issued, path, output)
        return path

    def after_scroll(self, record, window, title, child_label):
        """The post-scroll lookup (M1-10k, guest run 8c): one bounded pass (re-reads within GUI_SEARCH_SHORT per window,
        never the search budget) that never raises the generic ValueError. The window is re-selected by its title's selector form ("<name>" or
        "<name> – <status>", L16), not trusted by index: the dumped index first, then every other WGEX window index
        (POST_SCROLL_WINDOWS), stopping at the first dump carrying the element (identifier plus role). Found inside its
        window: the ordinary element press. Found outside, or not found at all (a dump of another window, an empty dump,
        an incomplete tree): press-only AXPress on the element remembered from before the scroll, in the window whose
        title still names it (else the original index). Only a failed press-only is the named gap
        guiTargetOffscreen:<identifier>, with each post-scroll dump summarised in the ledger and the message.
        Fix pass 1: a dump that hits the command deadline is summarised as dump=deadline and the pass goes on (F2); an
        ambiguous dump (the identifier on several enabled lines of the remembered role) is not "not found": the line
        with the remembered frame is the element, else press-only matches that remembered frame in this window (F3).
        M1-10l: each window is read through read_dump, so a dump whose walk reports truncated=1 or errors is re-read
        (fix pass 1 F5: a re-read starts only within GUI_SEARCH_SHORT, 20 s at scale 4, of the window's first read, so
        one incomplete window costs that plus one walk; none once the dump carries the identifier and role) before it
        counts, and one still incomplete is summarised as unreadable.
        M1-10t part 4: the press-time compare reads the value on the line with the chosen frame (F-1). M1-36: for a toggle the
        caller read (toggle_expected) the compare reads only the lines of the press role at that frame, refuses a frame more than
        one such line carries, and the press (inside or press-only) always passes that frame to the helper, as press-only with no point
        (M1-38: a compared toggle is never clicked at a coordinate). A toggle the caller read
        (toggle_expected) that is not found, or ambiguous with the remembered frame absent, is no longer pressed press-only:
        refuse_uncompared raises the named gap guiTargetOffscreen:<identifier> with nothing pressed (M1-10t part 3, N-1).
        Child-label targets keep the plain lookup."""
        identifier, role, label = record["controlIdentifier"], record["controlRole"], record["controlLabel"]
        selector = title.split(TITLE_STATUS_SEPARATOR, 1)[0] if title else None
        title_window, seen = None, []
        for candidate in [window] + [index for index in POST_SCROLL_WINDOWS if index != window]:
            try:
                dump = self.read_dump(candidate, deadline=self.runner.monotonic() + HARNESS.seconds("GUI_SEARCH_SHORT"), check=False,
                                      identifier=identifier, role=role)
            except RuntimeError:
                seen.append(dict(window=candidate, dump="deadline", windowTitle=None, windowFrame=None, lines=0, matches=[]))
                continue
            if "keyInUseElsewhere" in dump:
                raise ValueError("dedicated key required")
            summary = dict(window=candidate, **dump_summary(dump, identifier))
            seen.append(summary)
            if title_window is None and selector is not None and title_form(window_title(dump), selector) is not None:
                title_window = candidate
            ambiguous = 0
            try:
                frame, child = element_target(dump, identifier, label)
            except ValueError:
                frames = [] if child_label else identifier_frames(dump, identifier, role)
                if not frames:
                    continue
                if len(frames) == 1:
                    frame, child = frames[0], False
                else:
                    ambiguous, remembered, bounds = len(frames), tuple(record["elementFrame"]), window_frame(dump)
                    if remembered not in frames:
                        self.refuse_uncompared(dict(record, postScrollWindow=candidate, postScrollDumps=seen, postScrollAmbiguous=ambiguous),
                                               "ambiguous after scrolling, remembered frame absent")
                        return self.press_only(dict(record, windowFrame=list(bounds) if bounds else None, postScrollWindow=candidate,
                                                    postScrollDumps=seen, postScrollAmbiguous=ambiguous),
                                               candidate, child_label, "ambiguous after scrolling; the remembered frame matched by the helper",
                                               match_frame=remembered)
                    frame, child = remembered, False
            pinned = self.toggle_compared(identifier) and not child
            if role != "-" and element_role(dump, identifier, None if child else frame, controls=pinned) != role:
                continue
            self.expect_toggle(dump, identifier, None if child else frame, None if child else role)
            bounds = window_frame(dump)
            found = dict(record, elementFrame=list(frame), windowFrame=list(bounds) if bounds else None, postScrollWindow=candidate,
                         postScrollDumps=seen)
            if ambiguous:
                found["postScrollAmbiguous"] = ambiguous
            if frame_inside(frame, bounds):
                return self.press_inside(found, candidate, frame, bounds, role, child_label, match_frame=bool(ambiguous) or pinned,
                                     compared=pinned)
            return self.press_only(found, candidate, child_label, "still outside its window", match_frame=frame if ambiguous or pinned else None)
        self.refuse_uncompared(dict(record, postScrollWindow=None, postScrollDumps=seen), "not found in any post-scroll dump")
        return self.press_only(dict(record, postScrollWindow=None, postScrollDumps=seen), title_window or window, child_label,
                               "not found in any post-scroll dump")

    def refuse_uncompared(self, record, why):
        """M1-10t part 3 (VERIFY N-1): while toggle_expected names this identifier a press-only by the remembered frame has no
        post-scroll dump to compare, so the value read before the scroll could be stale: Allow LAN read on and turned off by the
        scroll window's own events would be pressed back on, a loosening change. Nothing is pressed; the named gap says why.
        Targets nobody read (toggle_expected unset or another identifier) keep the press-only path."""
        identifier = record["controlIdentifier"]
        if self.toggle_expected is None or self.toggle_expected[0] != identifier:
            return
        dumps = "; ".join(dump_summary_text(item) for item in record["postScrollDumps"])
        self.ledger.append(dict(record, postScroll=why, error="toggle value cannot be compared after the scroll; not pressed"))
        raise RowFailure("guiTargetOffscreen:" + identifier, f"element frame {frame_text(record['elementFrame'])} outside window frame "
                         f"{frame_text(record['windowFrame'])} after scrolling ({why}; {dumps}); the toggle value read before the "
                         "scroll (" + str(self.toggle_expected[1]) + ") has no value to compare, so nothing was pressed")

    def press_only(self, record, window, child_label, why, match_frame=None, inside=False):
        """Press-only AXPress, never a coordinate (F1). Fix pass 1: up to PRESS_ONLY_ATTEMPTS helper calls within
        GUI_SEARCH_SHORT while the helper answers path=miss, path=error, path=none, nothing or ax-action=failed (for a press
        nobody compared; a compared press retries path=miss alone, see fix pass 1 below), each attempt in the ledger; only
        after the last is the result the named gap guiTargetOffscreen:<identifier>.
        match_frame: the helper also matches this frame (an ambiguous dump, F3; M1-36: always for a compared toggle, so a compared
        toggle is pinned whether it is off-screen or inside). inside (M1-38, VERIFY H-2): the element lies inside its window (a
        compared toggle's pinned press, from press_inside): the ledger entry is an ordinary actionPath=<path> press and the
        failure is guiActionFailed:<identifier>, not the off-screen gap. Fix pass 1 (VERIFY F-1, N-3): for every compared press
        (inside, or off-screen while toggle_expected names the identifier) only a path=miss is retried, since the other failed
        replies may have landed and a second press is no second look; the off-screen gap stays guiTargetOffscreen. A gap after
        nothing but misses restores press_sent: nothing acted, so it is no toggle press. M1-10m: a lookup miss (path=miss) and
        an AXPress error (path=error, pressOnlyErrorNumber) are both retried but recorded apart, per attempt and in
        pressOnlyOutcomes, and the gap message lists each attempt's outcome."""
        identifier = record["controlIdentifier"]
        tail = [frame_argument(match_frame)] if match_frame else child_label
        deadline = self.runner.monotonic() + HARNESS.seconds("GUI_SEARCH_SHORT")
        outcomes, sent_before, compared, only_misses = [], self.press_sent, inside or self.toggle_compared(identifier), True
        for attempt in range(1, PRESS_ONLY_ATTEMPTS + 1):
            issued = self.guest_now()
            self.press_sent = True
            output = self.lab("gui", "press", "WGEX", window, identifier, "press-only", record["controlRole"], *tail, check=False)
            path, number = press_reply(output), press_error(output)
            entry = dict(controlIdentifier=identifier, pressOnlyAttempt=attempt, pressOnly=path, pressOnlyWindow=window)
            if number is not None:
                entry["pressOnlyErrorNumber"] = number
            self.ledger.append(entry)
            if path in ("element", "element-timeout"):
                self.ledger.append(dict(record, actionPath=path if inside else "element-offscreen", pressOnly=path, pressOnlyWindow=window,
                                        postScroll=why, pressOnlyAttempts=attempt, popupTimedOut=path == "element-timeout"))
                self.pressed(issued, path, output)
                return path
            outcomes.append(press_outcome(path, number))
            only_misses = only_misses and path == "miss"
            # A compared toggle (inside, or off-screen while toggle_expected names it; M1-38 fix pass 1, VERIFY F-1): only path=miss,
            # which acted on nothing, is retried; an error, an older helper's path=none or a failed reply may have landed, and a
            # second AXPress would turn Allow LAN back on, so any of those is the gap at once. Presses nobody compared (lockdown, F3)
            # keep the M1-10m retry.
            if (attempt == PRESS_ONLY_ATTEMPTS or (compared and path != "miss")
                    or self.runner.monotonic() + PRESS_ONLY_SETTLE_SECONDS >= deadline):
                break
            self.pause(PRESS_ONLY_SETTLE_SECONDS)
        if only_misses:
            # M1-38 fix pass 1 (VERIFY N-3): every attempt acted on nothing, so the gap below is no press for the toggle journal.
            self.press_sent = sent_before
        if inside:
            self.ledger.append(dict(record, pressOnly=path, pressOnlyWindow=window, postScroll=why, pressOnlyAttempts=attempt,
                                    pressOnlyOutcomes=outcomes,
                                    error="pinned press-only failed; " + ("not clicked" if only_misses else "the press may have landed")))
            raise RowFailure("guiActionFailed:" + identifier, f"{attempt} failed press-only AXPress attempt{'s' if attempt != 1 else ''} "
                             f"({'; '.join(outcomes)}) on the pinned frame {frame_text(record['elementFrame'])} inside window frame "
                             f"{frame_text(record['windowFrame'])}; "
                             + ("nothing was clicked" if only_misses else "the press may have landed"))
        self.ledger.append(dict(record, pressOnly=path, pressOnlyWindow=window, postScroll=why, pressOnlyAttempts=attempt,
                                pressOnlyOutcomes=outcomes, error="target outside the window"))
        dumps = "; ".join(dump_summary_text(item) for item in record["postScrollDumps"])
        raise RowFailure("guiTargetOffscreen:" + identifier, f"element frame {frame_text(record['elementFrame'])} outside window frame "
                         f"{frame_text(record['windowFrame'])} after scrolling ({why}; {dumps}) and {attempt} failed press-only AXPress "
                         f"attempt{'s' if attempt != 1 else ''} ({'; '.join(outcomes)})")

    def pressed(self, issued, path, output=None):
        """Stamp the press that acted (M1-10o, guest run 8e: manualEndCloses counted a 116 s element search because its
        start was stamped before click_first): issuedAt is the guest-clock instant the press command was issued, after the
        driver's element search, returnedAt when it returned. M1-10o fix pass 2 (F1; run 8e's End press command took
        4.93 s, mostly the helper's own walk, so issuedAt still charged that walk to the daemon): pressedAt is the helper's
        own delivery stamp from output (pressedAtSource guest), read in the guest immediately before AXPress or the
        fallback click; without one (an older helper, a coordinate click, a failed clock read), or with one outside
        issuedAt..returnedAt widened by the clock uncertainty and PRESS_STAMP_SLACK_SECONDS (ledger pressedAtRejected),
        pressedAt is issuedAt (source issued), the bound that never makes the daemon look faster than it was."""
        returned = self.guest_now()
        stamp = press_stamp(output) if output is not None else None
        bound = self.clock_tolerance + PRESS_STAMP_SLACK_SECONDS
        if stamp is not None and not issued - bound <= stamp <= returned + bound:
            self.ledger.append(dict(pressedAtRejected=stamp, issuedAt=issued, returnedAt=returned))
            stamp = None
        self.last_press = dict(issuedAt=issued, returnedAt=returned, path=path, pressedAt=issued if stamp is None else stamp,
                               pressedAtSource="issued" if stamp is None else "guest")

    def click_id(self, identifier, window="1", timeout=None):
        return self.click(None, identifier, window=window, timeout=timeout)

    def click_first(self, choices, window="1"):
        """Press the first control found: each (label, identifier) gets a short search, the last the full search. A
        missing control or a named gap (RowFailure, e.g. guiTargetOffscreen) moves on to the next choice (F2)."""
        for index, (label, identifier) in enumerate(choices):
            try:
                self.click(label, identifier, window=window,
                           timeout=HARNESS.seconds("GUI_SEARCH" if index == len(choices) - 1 else "GUI_SEARCH_SHORT"))
                return
            except (ValueError, RowFailure):
                if index == len(choices) - 1:
                    raise

    def keystroke(self, text, command=False):
        modifier = " using command down" if command else ""
        self.lab("gui", "run", "osascript", "-e", f'tell application "System Events" to keystroke "{text}"{modifier}')

    def open_settings(self, keep_probing=lambda: None):
        """Settings opens with Command-comma; returns the index of the window whose dump shows Settings (M1-10m,
        settings_evidence): wgex.settings.surface, else a Settings tab title as the window title, else a General-tab
        identifier. The window and its evidence go to the ledger. keep_probing runs between the steps and polls (M03-T17)."""
        keep_probing()
        self.lab("gui", "run", "open", "-a", "WGEX")
        keep_probing()
        self.lab("gui", "activate", "WGEX")
        keep_probing()
        self.keystroke(",", command=True)
        keep_probing()
        deadline = self.runner.monotonic() + HARNESS.seconds("GUI_SETTINGS_OPEN")
        while self.runner.monotonic() < deadline:
            for window in ("1", "2"):
                dump = self.walk_read(window, check=False)
                keep_probing()
                evidence = settings_evidence(dump)
                if evidence:
                    self.ledger.append(dict(settingsWindow=window, settingsEvidence=evidence, windowTitle=window_title(dump)))
                    return window
            self.pause(0.5)
        self.ledger.append(dict(controlIdentifier=SETTINGS_SURFACE, error="settings window did not open"))
        raise RowFailure("settingsUnavailable", "the Settings window (wgex.settings.surface, a Settings tab title or a General-tab "
                         "identifier) did not open after Command-comma")

    def press_title(self, label, window="1", timeout=None, container_role="AXToolbar"):
        """Press a control by its title inside a container of container_role (M1-10m, guest run 8d: the Settings toolbar
        buttons carry no identifier). The helper's element path with identifier "-" (gui press APP WINDOW - press X Y
        ROLE LABEL): AXPress on the first such container's child so titled, with the title's frame centre as the
        guest-side coordinate fallback, passed only when that frame lies inside the dumped window. Outside it: the
        named gap guiTargetOffscreen:<label> and no press. Returns the action path."""
        deadline = self.runner.monotonic() + (HARNESS.seconds("GUI_SEARCH") if timeout is None else timeout)
        dump = ""
        while self.runner.monotonic() < deadline:
            dump = self.read_dump(window, deadline=deadline)
            try:
                frame = titled_control(dump, label, container_role)
            except ValueError:
                self.pause(0.2)
                continue
            bounds = window_frame(dump)
            record = dict(controlIdentifier=None, controlLabel=label, controlContainer=container_role, elementFrame=list(frame),
                          windowFrame=list(bounds) if bounds else None)
            if not frame_inside(frame, bounds):
                self.ledger.append(dict(record, error="target outside the window"))
                raise RowFailure("guiTargetOffscreen:" + label, f"element frame {frame_text(frame)} outside window frame {frame_text(bounds)}")
            x, y = frame[0] + frame[2] // 2, frame[1] + frame[3] // 2
            issued = self.guest_now()
            output = self.lab("gui", "press", "WGEX", window, "-", "press", str(x), str(y), container_role, label, check=False)
            path = action_path(output)
            self.ledger.append(dict(record, actionPath=path))
            if path not in PRESSED_PATHS:
                raise RowFailure("guiActionFailed:" + label, f"neither AXPress on {label!r} in the {container_role} nor the click at "
                                 f"{x},{y} inside window frame {frame_text(bounds)} succeeded; see the step ledger")
            self.pressed(issued, path, output)
            return path
        self.ledger.append(dict(controlLabel=label, controlContainer=container_role, error="missing or ambiguous accessible control",
                                windowTitle=window_title(dump)))
        raise ValueError("missing or ambiguous accessible control")

    def select_settings_tab(self, window, title, keep_probing=lambda: None):
        """One Settings tab (M1-10m): its wgex.settings.tab.<name> identifier for a build that exposes one, else its title
        in the toolbar through the element path (press_title), else the existing label click, only inside the window.
        Earlier choices get the short search, the last the full one; a missing control or a named gap moves on. M1-10m
        verify F1: a choice counts only when one re-dump of the window then shows the tab title as the window title (the
        AXWindow line leads the dump, so a truncated read still shows it); on another title the next choice runs, and
        after the last the named gap settingsTabNotSelected:<title> carries the observed title. keep_probing runs before and
        after every choice and its re-dump, so a slow selection (about 46 s live, M03-T17) opens no hand-off probe gap."""
        identifier = "wgex.settings.tab." + title.lower()
        choices = [lambda seconds: self.click(None, identifier, window=window, timeout=seconds),
                   lambda seconds: self.press_title(title, window=window, timeout=seconds),
                   lambda seconds: self.click(title, None, window=window, timeout=seconds)]
        observed = []
        for index, choice in enumerate(choices):
            keep_probing()
            try:
                path = choice(HARNESS.seconds("GUI_SEARCH" if index == len(choices) - 1 else "GUI_SEARCH_SHORT"))
            except (ValueError, RowFailure):
                keep_probing()
                if index == len(choices) - 1 and not observed:
                    raise
                continue
            keep_probing()
            try:
                dump = self.walk_read(window, check=False)
            except RuntimeError:
                dump = ""
            keep_probing()
            observed.append(window_title(dump))
            self.ledger.append(dict(settingsTab=title, settingsTabChoice=index, windowTitle=observed[-1]))
            if observed[-1] == title:
                return path
        raise RowFailure("settingsTabNotSelected:" + title, f"window {window} is titled {observed[-1]!r}, not {title!r}, after "
                         f"{len(observed)} tab press(es); see the step ledger")

    def close_settings(self, window):
        if window == "1":
            self.keystroke("w", command=True)

    def journal_lockdown(self):
        """The daemon's lockdown flag from its replayed journal; None when the guest cannot say."""
        raw = self.guest_action("lockdown-state", check=False).decode(errors="replace").strip()
        return {"lockdown=true": True, "lockdown=false": False}.get(raw)

    def toggle_value(self, identifier):
        """A main window toggle's AX value from a targeted dump (M1-10o fix pass 2, F3; M1-10r for Allow LAN): True for
        value=1, False for value=0, None when the dump has no such line, another value, or cannot be read."""
        try:
            dump = self.read_dump("1", check=False, identifier=identifier, targeted=True)
        except RuntimeError:
            return None
        return dump_toggle_value(dump, identifier)

    def lockdown_toggle(self):
        return self.toggle_value(LOCKDOWN_TOGGLE)

    def await_journal(self, read, wanted):
        """A daemon journal flag from read(), polled every 0.5 s for LOCKDOWN_CONFIRM until it reads wanted."""
        current, deadline = None, self.runner.monotonic() + HARNESS.seconds("LOCKDOWN_CONFIRM")
        while self.runner.monotonic() < deadline:
            current = read()
            if current is wanted:
                break
            self.pause(0.5)
        return current

    def await_lockdown(self, enabled):
        return self.await_journal(self.journal_lockdown, enabled)

    def set_lockdown(self, enabled):
        """Toggle wgex.protection.lockdown in the main window (the M1-04 guest check) until the daemon journal agrees.
        Rows call it only to turn lockdown on (M1-10o): turning it off raises the administrator prompt, see
        lockdown_off_needed. M1-10o fix pass 2 (F3): a press the journal has not confirmed within LOCKDOWN_CONFIRM
        may still have landed, and a second press would turn lockdown off (and raise the prompt while the journal still
        reads on). So before a second press, and before the first when the journal is unreadable, the toggle's own value
        is read through a targeted dump: already enabled, the journal is polled again for LOCKDOWN_CONFIRM and the toggle
        is never pressed again; unreadable, it is never pressed blind; only the opposite value allows the press. Still
        unconfirmed: the named gap lockdownNotApplied."""
        self.lab("gui", "run", "open", "-a", "WGEX")
        self.lab("gui", "activate", "WGEX")
        current = self.journal_lockdown()
        presses, toggle = 0, None
        while current is not enabled and presses < 2:
            if presses or current is None:
                toggle = self.lockdown_toggle()
                self.ledger.append(dict(lockdownToggleBeforePress=presses + 1, lockdownToggle=toggle, lockdownReported=current))
                if toggle is None or toggle is enabled:
                    if toggle is enabled:
                        current = self.await_lockdown(enabled)
                    break
            self.click_id(LOCKDOWN_TOGGLE)
            presses += 1
            current = self.await_lockdown(enabled)
        self.ledger.append(dict(lockdownRequested=enabled, lockdownReported=current, togglePresses=presses))
        if current is not enabled:
            raise RowFailure("lockdownNotApplied", f"the daemon journal reports lockdown {current} after {presses} press(es) of "
                             f"{LOCKDOWN_TOGGLE} (toggle value {toggle}); the toggle is never pressed again while it reads on or "
                             "cannot be read")
        self.lockdown_on = enabled
        return current

    def toggle_until(self, identifier, read, wanted):
        """Set a main window Protection toggle by compare-and-press until the daemon journal read `read` reports `wanted`.
        Used for Allow LAN (set_allow_lan_off); lockdown keeps its own loop in set_lockdown. M1-10r (M1-10q FIX1-VERIFY
        N1): a press the journal has not confirmed within LOCKDOWN_CONFIRM may still have landed, and a second press would
        flip the toggle back (for Allow LAN: on again, a loosening change that raises the administrator prompt).
        M1-10t (M1-10r VERIFY-B L2-L4): the toggle's own value is read before EVERY press, the first included, whatever
        the journal says; already `wanted`, the journal is polled again for LOCKDOWN_CONFIRM and the toggle is not
        pressed; unreadable, never pressed blind; only the opposite value allows a press, and that press is taken from a
        dump that must show the same value (expect_toggle; ToggleMoved: not pressed, read again, at most twice). Each
        press is journalled in toggle_journal and the ledger; TOGGLE_PRESS_LIMIT counts the whole Session, so a retry after
        a failure never presses more than the limit allows in total. A press with the toggle still reading the opposite
        value after the confirm wait is pressed again: the app's toggle follows the daemon-confirmed value, and SwiftUI's
        Toggle proposes the opposite of what it shows, so for Allow LAN (value on, wanted off) the re-press re-sends
        "off", a tightening change. Returns (journal value, presses this call, last toggle value read)."""
        self.lab("gui", "run", "open", "-a", "WGEX")
        self.lab("gui", "activate", "WGEX")
        current = read()
        journal = self.toggle_journal.setdefault(identifier, [])
        presses, toggle, moved = 0, None, 0
        while current is not wanted and len(journal) < TOGGLE_PRESS_LIMIT and moved < 2:
            toggle = self.toggle_value(identifier)
            self.ledger.append(dict(toggleIdentifier=identifier, toggleBeforePress=len(journal) + 1, toggleValue=toggle, journalReported=current))
            if toggle is None or toggle is wanted:
                if toggle is wanted:
                    current = self.await_journal(read, wanted)
                break
            self.toggle_expected, self.press_sent = (identifier, toggle), False
            try:
                self.click_id(identifier)
            except ToggleMoved:
                moved += 1
                continue
            except BaseException:
                # M1-10t part 3 (VERIFY L-1): the press command was sent but its reply raised (a helper failure, a deadline): the
                # press may have landed, so it counts against the cap; a failure before any press command is not an attempt.
                if self.press_sent:
                    journal.append(dict(press=len(journal) + 1, valueBefore=toggle))
                    self.ledger.append(dict(toggleIdentifier=identifier, togglePress=len(journal), toggleValueBefore=toggle, pressOutcome="raised"))
                raise
            finally:
                self.toggle_expected, self.press_sent = None, False
            journal.append(dict(press=len(journal) + 1, valueBefore=toggle))
            presses += 1
            self.ledger.append(dict(toggleIdentifier=identifier, togglePress=len(journal), toggleValueBefore=toggle))
            # The lockdown journal confirm deadline, reused for Allow LAN (M1-10q).
            current = self.await_journal(read, wanted)
        return current, presses, toggle

    def journal_allow_lan(self):
        """The daemon's Allow LAN flag (settings.allowLAN) from its replayed journal; None when the guest cannot say."""
        raw = self.guest_action("allow-lan-state", check=False).decode(errors="replace").strip()
        return {"allowLAN=true": True, "allowLAN=false": False}.get(raw)

    def set_allow_lan_off(self):
        """M1-10q: Allow LAN off with the main window Protection control wgex.protection.allowLocalNetwork, before
        REBOOT-LOCKDOWN's lockdown press, until the daemon journal reports settings.allowLAN false. setGlobalSettings
        allowLAN false is a tightening change: owner and console user, no administrator prompt (02-architecture.md:326).
        The row never turns it back on (that would need the prompt); the next restore discards it."""
        current, presses, toggle = self.toggle_until(ALLOW_LAN_TOGGLE, self.journal_allow_lan, False)
        self.ledger.append(dict(allowLANRequested=False, allowLANReported=current, togglePresses=presses))
        if current is not False:
            raise RowFailure("allowLANNotApplied", f"the daemon journal reports allowLAN {current} after {presses} press(es) of "
                             f"{ALLOW_LAN_TOGGLE} (toggle value {toggle}); the toggle is never pressed again while it reads off or "
                             "cannot be read")
        return current

    def lockdown_off_needed(self, step):
        """A row step that needs lockdown off (M1-10o, guest run 8e). Turning lockdown OFF in the app raises the macOS
        administrator password prompt (SecurityAgent "WGEX wants to make changes.", started at the press; turning it ON
        does not), the app disables its controls while it is pending, and the driver never types or answers it. So rows
        never turn lockdown off, at their end or mid-row: the next restore discards it. This reads the daemon journal
        only, never the GUI: lockdown already off, the step runs (True); otherwise lockdownOffNeedsAdmin is kept in
        lockdown_gap and the step is skipped (False). Never raised, so the row's measured part stands; run() publishes it as
        a gap only when no lead control stands in for the skipped tail (M1-10o fix pass)."""
        current = self.journal_lockdown()
        self.ledger.append(dict(lockdownOffNeeded=step, lockdownReported=current, togglePressed=False))
        if current is False:
            return True
        self.lockdown_gap = str(RowFailure("lockdownOffNeedsAdmin", f"{step} needs lockdown off and the daemon journal reports lockdown "
                                           f"{current}; turning it off raises the macOS administrator prompt (SecurityAgent \"WGEX wants "
                                           "to make changes.\", guest run 8e), which the driver never answers, so the toggle is not "
                                           "pressed and the step did not run"))
        return False

    def boot_intent(self, identity):
        raw = self.guest_action("boot-intent", identity, check=False).decode(errors="replace").strip()
        return {"bootIntent=true": True, "bootIntent=false": False}.get(raw)

    def select_startup_option(self, window, option):
        """The startup option by position inside BOOT_STARTUP_GROUP (M1-10r, guest run 8f: the radio buttons expose only
        the group's label). A full dump of the Settings window (re-read within GUI_SEARCH) must show the group with one
        AXRadioButton child per STARTUP_OPTIONS entry and the chosen one enabled; the chosen one is the option's index in
        x order. M1-10t (M1-10r VERIFY-B L1): the buttons must also lie in one row (one y, x strictly increasing) or one
        column (one x, y strictly increasing), else the gap is raised before any press (a wrapped or mirrored group has no
        Nth position). It is pressed by role and exact frame, always press-only (gui press WGEX WINDOW - press-only
        AXRadioButton frame=..., no point, never a click): run 8g (actionPath element, step 110) showed the element path
        is enough, so the coordinate fallback, which could click whatever sits at the old centre after a layout shift, is
        gone for this step. A press whose reply is not an element press (a lookup miss, an AXPress error, a helper failure,
        no reply) is the gap at once, naming the path, without waiting for BOOT_INTENT_CONFIRM (M1-10r VERIFY N1). A
        failing accessibility dump is retried within GUI_SEARCH and then named (VERIFY-B N8). Then the group is re-dumped
        (within BOOT_INTENT_CONFIRM, the daemon's round trip: the radio value follows the saved profile) until the chosen
        button reads value=1 and every other value=0. Gap lines are capped and filtered (gap_lines, VERIFY-B N6).
        Otherwise: the named gap startupOptionNotSelected with the group's dump lines. Returns the action path."""
        index, count = STARTUP_OPTIONS.index(option), len(STARTUP_OPTIONS)
        deadline = self.runner.monotonic() + HARNESS.seconds("GUI_SEARCH")
        dump, options, dump_failed = "", [], False
        while self.runner.monotonic() < deadline:
            try:
                dump = self.read_dump(window, deadline=deadline, identifier=BOOT_STARTUP_GROUP)
            except RuntimeError:
                dump, dump_failed = "", True
                self.pause(0.2)
                continue
            dump_failed = False
            options = radio_options(dump, BOOT_STARTUP_GROUP)
            if len(options) == count and options[index]["enabled"]:
                layout = radio_layout(options)
                if layout is not None:
                    break
                lines = gap_lines(group_lines(dump, BOOT_STARTUP_GROUP))
                self.ledger.append(dict(controlGroup=BOOT_STARTUP_GROUP, startupOption=option, startupGroupLines=lines,
                                        startupOptionFrames=[list(item["frame"]) for item in options], error="ambiguous radio layout"))
                raise RowFailure("startupOptionNotSelected", f"{BOOT_STARTUP_GROUP} in window {window} shows {count} radio buttons "
                                 f"that are neither in one row nor in one column, so no position means option {index + 1} ({option}); "
                                 f"nothing was pressed; group dump: {' / '.join(lines) or 'missing'}")
            self.pause(0.2)
        else:
            lines = gap_lines(group_lines(dump, BOOT_STARTUP_GROUP))
            self.ledger.append(dict(controlGroup=BOOT_STARTUP_GROUP, startupOption=option, startupGroupLines=lines,
                                    error="accessibility dump failed" if dump_failed else "option not resolved by position"))
            if dump_failed:
                raise RowFailure("startupOptionNotSelected", f"the accessibility dump of window {window} failed until the search "
                                 f"deadline, so option {index + 1} ({option}) of {BOOT_STARTUP_GROUP} was not looked for; nothing was pressed")
            raise RowFailure("startupOptionNotSelected", f"{BOOT_STARTUP_GROUP} in window {window} did not show {count} radio "
                             f"buttons with option {index + 1} ({option}) enabled; group dump: {' / '.join(lines) or 'missing'}")
        frame, bounds = options[index]["frame"], window_frame(dump)
        record = dict(controlIdentifier=None, controlGroup=BOOT_STARTUP_GROUP, controlRole="AXRadioButton", startupOption=option,
                      startupOptionIndex=index, startupLayout=layout, elementFrame=list(frame), windowFrame=list(bounds) if bounds else None)
        issued = self.guest_now()
        output = self.lab("gui", "press", "WGEX", window, "-", "press-only", "AXRadioButton", frame_argument(frame), check=False)
        path, number = press_reply(output), press_error(output)
        self.ledger.append(dict(record, actionPath=path, pressOnly=True))
        if path not in PRESSED_PATHS:
            raise RowFailure("startupOptionNotSelected", f"radio button {index + 1} of {count} ({option}) in {BOOT_STARTUP_GROUP} was "
                             f"not pressed: {press_outcome(path, number)} (path {path}); nothing else was pressed")
        self.pressed(issued, path, output)
        deadline = self.runner.monotonic() + HARNESS.seconds("BOOT_INTENT_CONFIRM")
        selected = False
        while True:
            try:
                dump = self.read_dump(window, deadline=deadline, check=False, identifier=BOOT_STARTUP_GROUP)
            except RuntimeError:
                dump = ""
            selected = option_selected(radio_options(dump, BOOT_STARTUP_GROUP), index, count)
            if selected or self.runner.monotonic() >= deadline:
                break
            self.pause(0.5)
        lines = gap_lines(group_lines(dump, BOOT_STARTUP_GROUP))
        self.ledger.append(dict(controlGroup=BOOT_STARTUP_GROUP, startupOption=option, startupOptionSelected=selected, startupGroupLines=lines))
        if not selected:
            raise RowFailure("startupOptionNotSelected", f"radio button {index + 1} of {count} ({option}) in {BOOT_STARTUP_GROUP} does not "
                             f"read value=1 with the others value=0 after the press (path {path}); group dump: "
                             f"{' / '.join(lines) or 'missing'}")
        return path

    def set_startup_boot(self, identity):
        """Settings, Service tab, Connection at startup: Connect at boot before login (M1-08); the daemon registry must agree.
        M1-10r: the label lookup stays first (a build whose options carry their own title or identifier), each with the
        short search; then the option by position inside its group (select_startup_option), which guest run 8f needs."""
        window = self.open_settings()
        self.select_settings_tab(window, "Service")
        choice = "position"
        for label, identifier in ((BOOT_STARTUP_LABEL, BOOT_STARTUP_GROUP), (BOOT_STARTUP_LABEL, None)):
            try:
                self.click(label, identifier, window=window, timeout=HARNESS.seconds("GUI_SEARCH_SHORT"))
            except (ValueError, RowFailure, RuntimeError):
                continue
            choice = "label"
            break
        else:
            self.select_startup_option(window, "boot")
        current, deadline = None, self.runner.monotonic() + HARNESS.seconds("BOOT_INTENT_CONFIRM")
        while self.runner.monotonic() < deadline:
            current = self.boot_intent(identity)
            if current is True:
                break
            self.pause(0.5)
        self.close_settings(window)
        self.ledger.append(dict(startupRequested="boot", startupChoice=choice, profileID=identity, bootIntentReported=current))
        if current is not True:
            raise RowFailure("bootIntentNotApplied", f"the daemon registry reports startBeforeLoginOverride {current} after choosing {BOOT_STARTUP_LABEL!r}")
        return current

    def set_captive_duration(self):
        """Best effort: the Protection tab's wgex.settings.captiveWindow popup to 1 minute; the read-back decides the deadline."""
        window = self.open_settings()
        value = popup = None
        try:
            self.select_settings_tab(window, "Protection")
            popup = self.click_id("wgex.settings.captiveWindow", window=window)
            self.keystroke("1 minute")
            self.lab("gui", "run", "osascript", "-e", 'tell application "System Events" to key code 36')
            self.pause(0.5)
            dump = self.read_dump(window)
            match = re.search(r"(?m)^AXPopUpButton \| name=[^|]*\| value=(\d+) minutes? \|.*\bid=wgex\.settings\.captiveWindow \|", dump)
            value = int(match[1]) * 60 if match else None
        except (ValueError, RuntimeError):
            value = None
        finally:
            self.close_settings(window)
        # popup: the helper's path for the popup press; element-timeout means its Apple Event timed out (F3), None unpressed.
        self.ledger.append(dict(captiveSecondsRequested=60, captiveSecondsReadBack=value, captivePopupPath=popup,
                                captivePopupTimedOut=None if popup is None else popup == "element-timeout"))
        return (value, True) if value else (CAPTIVE_SECONDS_DEFAULT, False)

    def app_running(self):
        return self.ssh("if pgrep -x WGEX >/dev/null; then printf running; else printf exited; fi").strip() == b"running"

    def captive_rules(self):
        """Captive TCP 80/443 pass counts from the anchor read-back; the rules themselves are not kept."""
        return VERDICT.captive_passes(self.guest_action("anchor-rules", check=False).decode(errors="replace"))

    def guest_now(self):
        return self.runner.now() + self.clock["offsetSeconds"]

    def open_captive(self, name):
        """Toolbar wgex.main.openCaptiveWindow, then the sheet's wgex.protection.confirmCaptiveWindow (M1-08b step 6)."""
        self.lab("gui", "activate", "WGEX")
        self.click_id("wgex.main.openCaptiveWindow")
        self.last_press = None
        self.click_id("wgex.protection.confirmCaptiveWindow")
        # M1-10o: the confirm press as delivered (fix pass 2, F1: the helper's guest stamp, else as issued, after the
        # driver's element search; pressed); the status poll below stamps openedAt.
        press = self.last_press or {}
        clicked = press.get("pressedAt")
        item = dict(name=name, openClickedAt=self.guest_now() if clicked is None else clicked,
                    openClickedAtSource=press.get("pressedAtSource", "return"), openedAt=None, protectionWhileOpen=None)
        self.row_observation.setdefault("scenarios", []).append(item)
        deadline = self.runner.monotonic() + CAPTIVE_OPEN_SECONDS
        while self.runner.monotonic() < deadline:
            status = self.status(budget=min(HARNESS.seconds("STATUS_POLL"), max(1, deadline - self.runner.monotonic())))
            item["protectionWhileOpen"] = status["protection"]
            if status["protection"] == "captiveWindow":
                item["openedAt"] = self.guest_now()
                break
            self.pause(0.5)
        item["passesWhileOpen"] = self.captive_rules()
        if item["openedAt"] is None:
            raise RowFailure("captiveNotOpened", f"{name}: status never reported captiveWindow within {CAPTIVE_OPEN_SECONDS} s of confirming")
        return item

    def await_captive_closed(self, item, timeout):
        """Poll status and the anchor every second until blocked with no captive pass; the last read-back is recorded.
        M1-10o fix pass 2 (F1, run 8e: closedAt taken after the anchor read was about 1 s late on a 2.9 s poll cycle):
        the anchor read after the status read confirms no captive pass; closedConfirmedAt is the instant after it.
        M1-10q fix pass 1 (M1-10o FIX2-VERIFY N1: the poll start read up to one status read, about 1 s, fast): closedAt
        is the guest instant the status read that observed blocked completed, the latest instant that read can reflect
        (closedAtSource statusReadCompleted; the daemon's measuredAt has whole-second resolution, too coarse here), and
        closedPollStartedAt the start of that poll."""
        deadline = self.runner.monotonic() + timeout
        while True:
            polled = self.guest_now()
            status = self.status(budget=min(HARNESS.seconds("STATUS_POLL"), max(1, deadline - self.runner.monotonic())))
            read = self.guest_now()
            passes = self.captive_rules()
            item.update(protectionAfterClose=status["protection"], phaseAfterClose=status["phase"], passesAfterClose=passes)
            if status["protection"] == "blocked" and not passes["port80"] and not passes["port443"]:
                item.update(closedAt=read, closedAtSource="statusReadCompleted", closedPollStartedAt=polled,
                            closedConfirmedAt=self.guest_now())
                return item
            if self.runner.monotonic() >= deadline:
                raise RowFailure("captiveNotClosed", f"{item['name']}: still {status['protection']} with {passes} after {timeout} s")
            self.pause(1)

    def captive_row(self, profile):
        """M5.3-10 by pf read-back: lockdown on, a failed intent (relay stopped), then expiry, manual End and app kill at
        10 s; afterwards the D8 typed refusal with no intent. Privileged 80/53 listeners are out of scope."""
        observation = self.row_observation
        records = []
        self.set_lockdown(True)
        observation["lockdownBeforeOpen"] = self.journal_lockdown()
        observation["durationSeconds"], observation["durationConfirmed"] = self.set_captive_duration()
        duration = observation["durationSeconds"]
        restore = named("relay start", lambda: self.lab("relay", "start"))
        self.cleanups.append(restore)
        self.lab("relay", "stop")
        observation["statusBeforeOpen"] = self.await_loss_blocked("captive")
        item = self.open_captive("expiry")
        self.await_captive_closed(item, duration + VERDICT.CAPTIVE_CLOSE_SLACK_SECONDS)
        records.append(self.generate("blocked", role="afterExpiry"))
        item = self.open_captive("manualEnd")
        # M1-10o (guest run 8e: a 116 s element search counted against the daemon): End is stamped at its delivery and the
        # close is measured from that instant. Fix pass 2 (F1: the 4.93 s press command, mostly the helper's own walk,
        # read 15.61 s): the helper's guest stamp (endClickedAtSource guest), else the instant the press was issued
        # (issued), after the driver's search; issuedAt and returnedAt bound the delivery.
        # M1-10q fix pass 1 (M1-10o FIX2-VERIFY N2: pressedAt is the guest's own clock, closedAt host time plus an offset
        # sampled at prepare, about 31 min earlier in run 8e): the guest clock is measured again right before End, and the
        # press bounds and the close are stamped with that offset, so secondsAfterEnd has both stamps on the guest clock;
        # the drift since prepare is recorded (endClockDriftSeconds). A failed measurement keeps the row's offset, said so.
        try:
            end_clock, source = self.measure_clock(), "remeasuredBeforeEnd"
        except (RuntimeError, ValueError, KeyError, TypeError):
            end_clock, source = self.clock, "rowClockMeasurementFailed"
        item.update(endClockSource=source, endClockOffsetSeconds=end_clock["offsetSeconds"],
                    endClockUncertaintySeconds=end_clock["uncertaintySeconds"],
                    endClockDriftSeconds=round(end_clock["offsetSeconds"] - self.clock["offsetSeconds"], 6))
        row_clock, self.clock = self.clock, end_clock
        try:
            self.last_press = None
            self.click_first([(None, "wgex.protection.endCaptiveWindow"), (None, "wgex.protection.endCaptiveBanner")])
            press = self.last_press or {}
            item.update(endClickedAt=press.get("pressedAt"), endClickedAtSource=press.get("pressedAtSource"),
                        endPressIssuedAt=press.get("issuedAt"), endPressReturnedAt=press.get("returnedAt"))
            self.await_captive_closed(item, VERDICT.CAPTIVE_END_SECONDS)
        finally:
            self.clock = row_clock
        records.append(self.generate("blocked", role="afterEnd"))
        item = self.open_captive("appKill")
        self.pause(max(0, item["openedAt"] + CAPTIVE_KILL_AFTER_SECONDS - self.guest_now()))
        # M1-10o: the guest action prints the guest-clock instant of its SIGKILL; an older script falls back to the return.
        killed = re.fullmatch(r"killedAt=(\d{9,11}\.\d{1,6})\s*", self.guest_action("kill-app-process").decode(errors="replace"))
        item.update(killedAt=float(killed[1]) if killed else self.guest_now(), killedAtSource="guest" if killed else "return")
        remaining = item["openedAt"] + duration + VERDICT.CAPTIVE_CLOSE_SLACK_SECONDS - self.guest_now()
        self.await_captive_closed(item, max(1, remaining))
        item["appAbsentAtClose"] = not self.app_running()
        records.append(self.generate("blocked", role="afterAppKill"))
        # D8 typed refusal: with lockdown on and no intent the daemon must refuse with a typed captive code, not UnknownError.
        self.lab("gui", "run", "open", "-a", "WGEX")
        self.lab("gui", "activate", "WGEX")
        # VERIFY N4: after a failed `down` the failed/blocked intent stays and its window opens, a FAIL misread as an
        # untyped refusal; so the failure is named here and the window is opened only from idle/blocked.
        try:
            self.guest_action("down")
        except RuntimeError:
            raise RowFailure("captiveRefusalDownFailed", "explicit down before the D8 typed-refusal step failed; see the step ledger") from None
        self.await_status("blocked", phase="idle")
        before = set(self.diagnostics_lines())
        self.click_id("wgex.main.openCaptiveWindow")
        self.click_id("wgex.protection.confirmCaptiveWindow")
        self.pause(5)
        fresh = [line for line in self.diagnostics_lines() if line not in before]
        observation["typedRefusal"] = dict(requestFailures=VERDICT.request_failures(fresh), statusAfter=self.status(),
                                           passesAfter=self.captive_rules())
        restore()
        self.cleanups.remove(restore)
        # M1-10o: lockdown stays on; run() asks lockdown_off_needed before the unprotected tail.
        return records

    def diagnostics_lines(self):
        try:
            tail = HARNESS.seconds("DIAGNOSTICS_TAIL")
            data = self.guest_action("diagnostics-tail", check=False, deadline=tail, timeout=tail)
        except (RuntimeError, OSError, ValueError):
            return []
        return safe_stderr(data, 65536).splitlines()

    def boot_observe(self):
        """Post-boot processes, launchd runs and the daemon's status lines since boot; None (and a ledger entry) if unreadable."""
        try:
            observe = HARNESS.seconds("BOOT_OBSERVE")
            # M1-10u fix pass 1: the host's time around the guest call, so the verdict can compare the guest's own sample time with
            # host time plus the clock offset (verdict.clock_drift); sample_boot_clock adds the offset measured beside the sample.
            started = self.runner.now()
            text = self.guest_action("boot-observe", deadline=observe, timeout=observe + 10).decode(errors="replace")
            value = VERDICT.parse_boot_observe(text)
            value.update(hostStartedAt=started, hostReturnedAt=self.runner.now())
        except (RuntimeError, ValueError) as error:
            self.ledger.append(dict(bootObserve="unavailable", error=type(error).__name__))
            return None
        self.ledger.append(dict(bootObserve="sampled", appRunning=value["appRunning"], daemonRuns=value["daemonRuns"],
                                timelineLines=len(value["timeline"])))
        return value

    def boot_summary(self, samples, first_status):
        """Merge the post-boot samples: app seen in any, earliest app start, daemon pid and start, last runs count, longest raw
        timeline (verdict.restart_timeline selects the post-restart daemon's lines from it, M1-10u).

        M1-10v fix pass 1 (VERIFY B H1, M1): an unreadable sample is dropped from the merge but never from the record: the planned
        count (bootObservePlanned), the last readable sample's time (lastBootSampleAt) and the guest's app-log-line count of every
        planned sample (appLogLinesSamples, None for an unreadable one) go to verdict.relaunch_prevented_check, which needs every
        planned sample, the last after protection was restored, and no app log line."""
        planned = list(samples)
        samples = [sample for sample in samples if sample]
        apps = [sample["appStartedAt"] for sample in samples if sample["appRunning"] and sample["appStartedAt"] is not None]
        apps_ps = [sample["appStartedAtPs"] for sample in samples if sample["appRunning"] and sample["appStartedAtPs"] is not None]
        started = next((sample["daemonStartedAt"] for sample in samples if sample["daemonStartedAt"] is not None), None)
        dropped = [sample["statusLinesDropped"] for sample in samples if sample["statusLinesDropped"] is not None]
        clocks = [dict(sampledAt=sample["sampledAt"], hostStartedAt=sample["hostStartedAt"], hostReturnedAt=sample["hostReturnedAt"],
                       offsetSeconds=sample["clockOffsetSeconds"], uncertaintySeconds=sample["clockUncertaintySeconds"])
                  for sample in samples if "clockOffsetSeconds" in sample]
        return dict(appRunningAfterBoot=any(sample["appRunning"] for sample in samples) if samples else None,
                    appStartedAt=min(apps) if apps else None, bootAt=samples[0]["bootAt"] if samples else None,
                    # Fix pass 1: ps lstart beside the etime estimate, the unparsed-start flag, the guest filter's dropped-line count
                    # (the largest reported), the pre-restart daemon's pid and the clock samples (verdict.clock_drift).
                    appStartedAtPs=min(apps_ps) if apps_ps else None,
                    daemonStartUnknown=started is None and any(sample["daemonStartUnknown"] for sample in samples),
                    statusLinesDropped=max(dropped) if dropped else None,
                    preRestartDaemonPid=self.pre_restart_daemon_pid, clockSamples=clocks,
                    daemonStartedAt=started,
                    # M1-10u: the post-restart daemon's pid (pgrep -o after the restart) and every sample's reading of it.
                    daemonPid=next((sample["daemonPid"] for sample in samples if sample["daemonPid"] is not None), None),
                    daemonPidSamples=[sample["daemonPid"] for sample in samples if sample["daemonPid"] is not None],
                    daemonRuns=samples[-1]["daemonRuns"] if samples else None,
                    timeline=max((sample["timeline"] for sample in samples), key=len, default=[]),
                    statusSamples=list(self.sample_log or []), firstStatus=first_status, bootObserveSamples=len(samples),
                    bootObservePlanned=len(planned), lastBootSampleAt=samples[-1]["sampledAt"] if samples else None,
                    appLogLinesSamples=[sample.get("appLogLines") if sample else None for sample in planned])

    def await_ssh(self, timeout, what):
        deadline = self.runner.monotonic() + timeout
        while self.runner.monotonic() < deadline:
            try:
                self.ssh("true", timeout=HARNESS.seconds("SSH_RETRY_ATTEMPT"))
                return
            except RuntimeError:
                self.pause(2)
        raise RuntimeError(what)

    def en0_loss(self, variant, seconds, phase=None):
        """Run 6 B1 as a row: en0 down for `seconds`, then up, observed inside the guest; a full-tunnel variant also
        probes the LAN receivers during the loss from a detached generator (the SSH session dies with en0). M03-T09: a row
        with more than one cycle of a variant names each `phase`, which keeps the cycles' records and receipts apart."""
        self.window_number += 1
        label = f"{variant}-{self.window_number}"
        item = dict(variant=variant, lossSeconds=seconds)
        if phase:
            item.update(phase=phase, role="linkLoss:" + variant + ":" + phase)
        full = not VERDICT.split_tunnel(VERDICT.PROFILE_ALLOWED_IPS[variant])
        if full:
            item["lossNonce"] = nonce = self.nonce + "-w" + str(self.window_number)
            item["generatorPath"] = path = self.stage + "/generator-en0-" + label + ".json"
            command = shlex.join(["nohup", self.stage + "/leakprobe", "generate", "--config", self.stage + "/config.json", "--rounds",
                                  str((seconds + 12) * 2), "--state", "blocked", "--nonce", nonce, "--record", path])
            self.ssh(command + " >/dev/null 2>&1 </dev/null &")
        triggered = self.runner.monotonic()
        trigger = HARNESS.seconds("EN0_LOSS_TRIGGER")
        self.guest_action("en0-loss", str(seconds), label, check=False, deadline=trigger, timeout=trigger + 10)
        self.pause(seconds + 5)
        self.await_ssh(HARNESS.seconds("SSH_RETURN_AFTER_EN0_LOSS"), "SSH did not return after the en0 loss")
        self.ledger.append(dict(en0Loss=variant, sshBackAfterSeconds=round(self.runner.monotonic() - triggered, 2)))
        self.pause(max(0, triggered + seconds + EN0_OBSERVER_EXTRA_SECONDS + 2 - self.runner.monotonic()))
        item.update(VERDICT.parse_en0(self.guest_action("en0-collect", label).decode(errors="replace")))
        self.ledger.append(dict(en0Collected=variant, down=item["down"], up=item["up"], samples=len(item["samples"])))
        record = None
        if full:
            deadline = self.runner.monotonic() + HARNESS.seconds("EN0_GENERATOR_RECORD")
            while record is None:
                raw = self.ssh("cat " + shlex.quote(path) + " 2>/dev/null || true")
                try:
                    candidate = json.loads(raw) if raw.strip() else None
                except ValueError:
                    candidate = None
                if candidate and candidate.get("windows"):
                    record = candidate
                elif self.runner.monotonic() >= deadline:
                    raise RuntimeError("en0 loss generator record missing")
                else:
                    self.pause(1)
            record.update(clockToleranceSeconds=self.clock_tolerance, role=item.get("role", "linkLoss:" + variant), profileVariant=variant)
            for window in record["windows"]:
                window["requiredFamilies"] = ["ipv4"]
                window.pop("receiversComplete", None)
        self.row_observation.setdefault("profiles", []).append(item)
        return record

    def power_wake(self, variant, seconds):
        """M1-47: an injected power event as a row. The guest signals its own Lab daemon (SIGUSR1 a sleep, SIGUSR2 a wake `seconds`
        later; the guest does not sleep, so SSH stays up) while status and the pf reference count are sampled inside the guest and a
        detached generator probes the LAN and tunnel receivers through the window (the profile is full4, a full tunnel)."""
        self.window_number += 1
        label = f"{variant}-{self.window_number}"
        item = dict(variant=variant, sleepSeconds=seconds, profile="full4")
        item["windowNonce"] = nonce = self.nonce + "-w" + str(self.window_number)
        item["generatorPath"] = path = self.stage + "/generator-power-" + label + ".json"
        command = shlex.join(["nohup", self.stage + "/leakprobe", "generate", "--config", self.stage + "/config.json", "--rounds",
                              str((seconds + 12) * 2), "--state", "blocked", "--nonce", nonce, "--record", path])
        self.ssh(command + " >/dev/null 2>&1 </dev/null &")
        triggered = self.runner.monotonic()
        self.guest_action("power-inject", str(seconds), label)
        self.pause(seconds + 5)
        self.pause(max(0, triggered + seconds + POWER_OBSERVER_EXTRA_SECONDS + 2 - self.runner.monotonic()))
        item.update(VERDICT.parse_power(self.guest_action("power-collect", label).decode(errors="replace")))
        self.ledger.append(dict(powerCollected=variant, sleepAt=item["sleepAt"], wakeAt=item["wakeAt"], injectedLines=len(item["injected"]),
                                samples=len(item["samples"])))
        record = None
        deadline = self.runner.monotonic() + HARNESS.seconds("EN0_GENERATOR_RECORD")
        while record is None:
            raw = self.ssh("cat " + shlex.quote(path) + " 2>/dev/null || true")
            try:
                candidate = json.loads(raw) if raw.strip() else None
            except ValueError:
                candidate = None
            if candidate and candidate.get("windows"):
                record = candidate
            elif self.runner.monotonic() >= deadline:
                raise RuntimeError("power wake generator record missing")
            else:
                self.pause(1)
        record.update(clockToleranceSeconds=self.clock_tolerance, role="powerWake:" + variant, profileVariant="full4")
        for window in record["windows"]:
            window["requiredFamilies"] = ["ipv4"]
            window.pop("receiversComplete", None)
        self.row_observation.setdefault("powerWakes", []).append(item)
        return record

    def od_read(self, identity):
        """One reduced daemon status read (guest od-status.pl): pid, start time, phase, protection and the on-demand fields. A read
        whose daemon identity changed or was unavailable around it comes back with a `discarded` reason and no pid."""
        return json.loads(self.gap_action("od-probe", identity, record_stdout=True))

    def od_probe(self, identity):
        """A status read that belongs to one daemon process; a discarded read is retried, then refused."""
        for attempt in range(3):
            sample = self.od_read(identity)
            if not sample.get("discarded"):
                return sample
            self.pause(1)
        raise RuntimeError(f"no status read kept its daemon identity: {sample['discarded']}")

    def od_policy(self, identity):
        """The profile's on-demand policy as the app stored it (compact JSON text, never the profile document)."""
        raw = self.gap_action("od-policy", identity, check=False).decode(errors="replace").strip()
        match = re.fullmatch(r"onDemand=(.{1,400})", raw)
        return match[1] if match else None

    def od_armed(self, identity):
        """True when the daemon reports this profile armed, False when not, None when it cannot say (a toggle_until read)."""
        try:
            status = self.od_probe(identity)
        except (RuntimeError, OSError, ValueError):
            return None
        if status.get("phase") is None:
            return None
        detail = status.get("onDemand")
        # A daemon with nothing armed reports no on-demand object at all.
        return False if detail is None else detail.get("armedIsProfile") is True if isinstance(detail, dict) else None

    def set_ethernet_rule(self, profile, identity):
        """Through the app: select the profile, Edit, tick Ethernet in the On-Demand section, Save; the saved policy is read back
        from the app's profile store by the caller. The editor is never driven twice: a missing control is the gap."""
        self.lab("gui", "run", "open", "-a", "WGEX")
        self.lab("gui", "activate", "WGEX")
        self.select_profile(profile)
        self.click_id("wgex.main.editProfile")
        self.click_id(ONDEMAND_ETHERNET)
        self.click_id(ONDEMAND_SAVE)
        self.ledger.append(dict(onDemandRuleEdit="ethernet", profileID=identity))

    def ondemand_row(self, profile, seconds):
        """M03-T09 (ONDEMAND-ETH, ADR-030): an Ethernet rule set through the app brings the tunnel up with no click after arming, after
        a daemon restart and after en0 returns; withdrawing it brings the tunnel down; Lockdown and the kill switch hold. en0 is
        cycled inside the guest only (en0_loss); the daemon restart is a SIGTERM to the Lab daemon in the guest."""
        records = []
        identity = self.profile_ids.get(profile)
        if identity is None:
            self.select_profile(profile)
            identity = self.profile_ids[profile]
        od = self.row_observation["onDemand"] = dict(profileID=identity, policyBefore=self.od_policy(identity))
        self.set_ethernet_rule(profile, identity)
        od["policyAfterEdit"] = self.od_policy(identity)
        if "ethernetOnly" not in (od["policyAfterEdit"] or ""):
            raise RowFailure("ethernetRuleNotSaved", f"the app's profile store reads the on-demand policy {od['policyAfterEdit']!r} after Save")
        # Arm: the one user action. Everything after it waits for the daemon on its own.
        toggle_id = f"{ONDEMAND_TOGGLE}.{identity}"
        _, presses, toggle = self.toggle_until(toggle_id, lambda: self.od_armed(identity), True)
        od.update(armPresses=presses, armToggleValue=toggle)
        self.await_status("protected", timeout=120)
        od["armed"] = self.od_probe(identity)
        self.pause(self.clock_tolerance * 2 + 0.1)
        records.append(dict(self.generate("protected", role="onDemandActivated"), profileVariant=profile))
        self.observations_extra.append(self.observe())
        # Daemon start: SIGTERM; the replacement daemon's own samples decide, with no GUI action in between.
        pressed = self.last_press
        restart = od["restart"] = dict(samples=[])
        for line in self.gap_action("od-restart").decode().splitlines():
            name, _, value = line.partition("=")
            if name == "prevpid" and re.fullmatch(r"[1-9][0-9]{0,9}", value):
                restart["prevPid"] = int(value)
            elif name == "prevstart" and re.fullmatch(VERDICT.ONDEMAND.START_PATTERN, value):
                restart["prevStarted"] = value
            elif name == "restartAt" and re.fullmatch(r"\d{9,11}\.\d+", value):
                restart["restartAt"] = float(value)
        deadline = self.runner.monotonic() + HARNESS.seconds("ONDEMAND_DAEMON_RESTART")
        while self.runner.monotonic() < deadline:
            try:
                sample = self.od_read(identity)
            except (RuntimeError, OSError, ValueError):
                sample = None
            if sample is not None and sample.get("discarded"):
                # The daemon changed or could not be identified around the read: it proves nothing about either daemon.
                restart.setdefault("discarded", []).append(dict(at=sample.get("at"), reason=sample["discarded"]))
            elif sample is not None:
                restart["samples"].append(sample)
                if VERDICT.ONDEMAND.counts_after_restart(restart, sample) and VERDICT.ONDEMAND.activated(sample):
                    break
            self.pause(1)
        restart["guiPress"] = self.last_press is not pressed
        self.await_status("protected", timeout=60)
        self.pause(self.clock_tolerance * 2 + 0.1)
        records.append(dict(self.generate("protected", role="afterDaemonStart"), profileVariant=profile))
        self.observations_extra.append(self.observe())
        # en0 returns: cycled inside the guest; the rule stays armed and nothing is clicked.
        pressed = self.last_press
        loss = self.en0_loss(profile, seconds, phase="armed")
        if loss:
            records.append(loss)
        self.await_status("protected", timeout=60)
        od["afterEn0"] = dict(status=self.od_probe(identity), guiPress=self.last_press is not pressed)
        self.pause(self.clock_tolerance * 2 + 0.1)
        records.append(dict(self.generate("protected", role="automaticRecovery:" + profile), profileVariant=profile))
        self.observations_extra.append(self.observe())
        # Removal under Lockdown (the driver never turns Lockdown off): disarm and deactivate through the app.
        self.set_lockdown(True)
        od["lockdownJournal"] = self.journal_lockdown()
        _, presses, toggle = self.toggle_until(toggle_id, lambda: self.od_armed(identity), False)
        self.await_status("blocked", timeout=60)
        od["removed"] = dict(presses=presses, toggleValue=toggle, status=self.od_probe(identity))
        self.pause(self.clock_tolerance * 2 + 0.1)
        records.append(dict(self.generate("blocked", role="ruleRemoved"), profileVariant=profile))
        self.observations_extra.append(self.observe())
        loss = self.en0_loss(profile, seconds, phase="removed")
        if loss:
            records.append(loss)
        self.pause(5)
        od["removedAfterEn0"] = dict(status=self.od_probe(identity))
        records.append(dict(self.generate("blocked", role="ruleRemovedAfterEn0"), profileVariant=profile))
        self.observations_extra.append(self.observe())
        return records

    def import_review(self):
        deadline = self.runner.monotonic() + HARNESS.seconds("GUI_IMPORT_REVIEW")
        while self.runner.monotonic() < deadline:
            dump = self.read_dump("1", deadline=deadline)
            if "keyInUseElsewhere" in dump:
                raise ValueError("dedicated key required")
            if "id=wgex.importReview.importLabel |" in dump:
                return dump
            self.pause(0.2)
        self.ledger.append(dict(controlIdentifier="wgex.importReview.surface", error="file review did not populate"))
        raise ValueError("file review did not populate")

    def select_profile(self, profile):
        """Select by keyboard: SwiftUI sidebar rows ignore clicks, AXPress and AXSelected (run 5, U12/L14).

        The title names the profile exactly or as "<name> – <status>" (L16). The helper focuses the
        `wgex.main.profiles` element when the AX tree carries it and otherwise the profile list found
        from the window (L17); the ledger records which path pressed the keys.
        """
        if not re.fullmatch(r"[a-z0-9-]+", profile):
            raise ValueError("invalid profile variant")
        name = "wgex-lab-" + profile
        deadline = self.runner.monotonic() + HARNESS.seconds("GUI_PROFILE_SELECT")
        identity = None
        while identity is None and self.runner.monotonic() < deadline:
            raw = self.guest_action("profile-id", name, check=False).decode().strip()
            if re.fullmatch(UUID_PATTERN, raw):
                identity = str(uuid.UUID(raw)).upper()
            else:
                self.pause(0.2)
        if identity is None:
            raise ValueError("profile name did not resolve to one valid stored UUID")
        # M03-T07 phase B: the title first, from a targeted walk (the AXWindow line plus the toolbar action). The connected main
        # window's full walk took 224 s and then over the 360 s SSH deadline under host load; after Import and Connect the
        # title already names the profile, so the full dump (for the sidebar rows) is read only when it does not.
        rows, title = [], window_title(self.walk_read("1", MAIN_ACTION, check=False))
        while not title_form(title, name) and self.runner.monotonic() < deadline:
            dump = self.read_dump("1", deadline=deadline)
            rows, title = sidebar_rows(dump), window_title(dump)
            if title_form(title, name) or identity in rows:
                break
            self.pause(0.2)
        keys, paths = [], []
        if not title_form(title, name):
            if identity not in rows:
                raise RowFailure("profileSelectionMismatch", f"no sidebar row for {name} ({identity}) in the accessibility dump")
            # Up once per row always reaches the first row; then Down to the target's on-screen index.
            self.lab("gui", "activate", "WGEX")
            for direction, count in [("up", len(rows)), ("down", rows.index(identity))]:
                if count:
                    output = self.lab("gui", "keys", "WGEX", "1", "wgex.main.profiles", direction, str(count), "fallback", check=False)
                    keys.append(direction + " " + str(count))
                    paths.append(keys_path(output))
            settle = self.runner.monotonic() + HARNESS.seconds("GUI_TITLE_SETTLE")
            while True:
                title = window_title(self.walk_read("1"))
                if title_form(title, name) or self.runner.monotonic() >= settle:
                    break
                self.pause(0.2)
        form = title_form(title, name)
        shown = name if form else title if title is None or re.fullmatch(r"[A-Za-z0-9 ._-]{0,64}", title) else "<other>"
        path = "none" if not paths else paths[0] if len(set(paths)) == 1 else "mixed"
        self.profile_ids[profile] = identity
        self.ledger.append(dict(profileName=name, profileID=identity, selectedTitle=shown, titleForm=form, arrowKeys=keys, selectionPath=path))
        if not form:
            raise RowFailure("profileSelectionMismatch", f"window title {shown!r} after arrow-key selection (path {path}); expected {name!r}")

    def connect(self, profile):
        self.select_profile(profile)
        # The toolbar action is wgex.main.action labelled Connect (M1-10j element path); the label search stays the fallback.
        self.click_first([("Connect", "wgex.main.action"), ("Connect", None)])

    def status(self, budget=None):
        options = dict(deadline=max(1, min(HARNESS.seconds("STATUS_POLL"), math.ceil(budget))), timeout=budget) if budget is not None else {}
        data = self.ssh(CLI + " status --json", record_stdout=True, **options)
        raw = json.loads(data)
        try:
            self.last_status = json.loads(safe_stderr(data, 65536))
        except ValueError:
            self.last_status = dict(redacted=True)
        if raw.get("phase") not in ("idle", "preparing", "configuring", "active", "reasserting", "captiveWindow", "stopping", "failed"):
            raise ValueError("invalid guest status")
        if self.sample_log is not None:
            self.sample_log.append([self.guest_now(), raw.get("phase"), raw.get("protection")])
        return {k: raw.get(k) for k in ("phase", "protection")}

    def await_status(self, protection, timeout=60, phase=None):
        deadline = self.runner.monotonic() + timeout
        while self.runner.monotonic() < deadline:
            try:
                status = self.status(budget=min(HARNESS.seconds("STATUS_POLL"), deadline - self.runner.monotonic()))
                if status["protection"] == protection and phase in (None, status["phase"]):
                    return
            except RuntimeError:
                pass
            self.pause(min(0.5, max(0, deadline - self.runner.monotonic())))
        self.poll_deadline("status protection=" + protection + (" phase=" + phase if phase else ""), timeout)

    def status_stream(self):
        """The daemon's recent status transitions from the guest diagnostics stream, oldest first (at most 20)."""
        try:
            tail = HARNESS.seconds("DIAGNOSTICS_TAIL")
            data = self.guest_action("diagnostics-tail", check=False, record_stdout=True, deadline=tail, timeout=tail)
        except (RuntimeError, OSError, ValueError):
            return []
        lines = [STATUS_STREAM_LINE.fullmatch(line.strip()) for line in safe_stderr(data, 65536).splitlines()]
        return [[match[1], match[2], match[3], match[4]] for match in lines if match][-20:]

    def await_loss_blocked(self, name):
        """Status sequence after a path loss: poll every 250 ms until reasserting/blocked or failed/blocked.

        The ledger keeps each polled transition as [phase, protection, seconds since the wait began] and the
        stream's transitions, so a phase that fell between polls is still on record.
        """
        started = self.runner.monotonic()
        deadline = started + LOSS_BLOCKED_SECONDS
        sequence = []
        while self.runner.monotonic() < deadline:
            try:
                status = self.status(budget=min(HARNESS.seconds("STATUS_POLL"), deadline - self.runner.monotonic()))
            except RuntimeError:
                status = None
            if status is not None:
                if not sequence or sequence[-1][:2] != [status["phase"], status["protection"]]:
                    sequence.append([status["phase"], status["protection"], round(self.runner.monotonic() - started, 2)])
                if status["protection"] == "blocked" and status["phase"] in LOSS_BLOCKED_PHASES:
                    self.ledger.append(dict(lossBlocked=name, met=True, statusSequence=sequence, statusStream=self.status_stream()))
                    self.fault_phases.append(dict(label="lossBlocked:" + name, timestamp=self.runner.now() + self.clock["offsetSeconds"], **status))
                    return status
            self.pause(min(STATUS_POLL_SECONDS, max(0, deadline - self.runner.monotonic())))
        self.ledger.append(dict(lossBlocked=name, met=False, statusSequence=sequence, statusStream=self.status_stream()))
        self.poll_deadline(f"loss blocked ({name}) phase={'|'.join(LOSS_BLOCKED_PHASES)} protection=blocked", LOSS_BLOCKED_SECONDS)

    def poll_deadline(self, name, timeout):
        tail = []
        try:
            tail = HARNESS.seconds("DIAGNOSTICS_TAIL")
            data = self.guest_action("diagnostics-tail", check=False, record_stdout=True, deadline=tail, timeout=tail)
            tail = safe_stderr(data, 65536).splitlines()[-50:]
        except (RuntimeError, OSError, ValueError):
            tail = ["stream tail unavailable"]
        path = self.output / ("deadline-" + str(len(self.deadlines) + 1) + ".json")
        report = dict(deadlineName=name, timeoutSeconds=timeout, lastStatus=self.last_status,
                      daemonLogTail=tail, ledgerTail=self.ledger[-20:])
        path.write_text(json.dumps(report, indent=2))
        self.deadlines.append(dict(name=name, path=str(path)))
        self.ledger.append(dict(error="pollDeadline", deadlineName=name, timeoutSeconds=timeout, diagnosticsPath=str(path)))
        raise PollDeadline(name + " deadline after " + str(timeout) + " s; diagnostics " + str(path))

    def await_guest(self):
        budget, attempt = HARNESS.seconds("READINESS"), HARNESS.seconds("READINESS_ATTEMPT")
        deadline, delay = self.runner.monotonic() + budget, 1
        while self.runner.monotonic() < deadline:
            remaining = deadline - self.runner.monotonic()
            try:
                self.ssh("true", deadline=max(1, min(attempt, int(remaining))), timeout=remaining)
                return
            except RuntimeError:
                self.pause(min(delay, max(0, deadline - self.runner.monotonic())))
                delay = min(delay * 2, 16)
        self.poll_deadline("post-restore IP and key-only SSH readiness", budget)

    def quit_app(self):
        step, wait, probe = HARNESS.seconds("QUIT_STEP"), HARNESS.seconds("QUIT_WAIT"), HARNESS.seconds("QUIT_PROBE")
        try:
            self.lab("gui", "activate", "WGEX", check=False, timeout=step, ssh_deadline=step)
        except RuntimeError:
            self.ledger.append(dict(quitAttempt="activate", error="deadline"))
        prefix = 'tell application "System Events" to tell process "WGEX" to '
        menu = 'menu item "Quit WGEX" of menu 1 of menu bar item "WGEX" of menu bar 1'
        def exists(element):
            deadline = self.runner.monotonic() + wait
            while self.runner.monotonic() < deadline:
                try:
                    remaining = min(probe, deadline - self.runner.monotonic())
                    if self.lab("gui", "run", "osascript", "-e", prefix + "exists " + element, check=False,
                                timeout=remaining, ssh_deadline=max(1, math.ceil(remaining))).strip() == b"true":
                        return True
                except RuntimeError:
                    return False
                self.pause(0.2)
            return False
        def exited():
            deadline = self.runner.monotonic() + wait
            while self.runner.monotonic() < deadline:
                try:
                    remaining = min(probe, deadline - self.runner.monotonic())
                    if self.ssh("if pgrep -x WGEX >/dev/null; then printf running; else printf exited; fi",
                                timeout=remaining, deadline=max(1, math.ceil(remaining))).strip() == b"exited":
                        return True
                except RuntimeError:
                    pass
                self.pause(0.2)
            return False
        actions = [("menu", lambda: self.lab("gui", "run", "osascript", "-e", prefix + "click " + menu, check=False, timeout=step, ssh_deadline=step)),
                   ("apple-event", lambda: self.lab("gui", "run", "osascript", "-e", 'tell application "WGEX" to quit', check=False, timeout=step, ssh_deadline=step)),
                   ("pkill", lambda: self.ssh("pkill -x WGEX", check=False, deadline=probe, timeout=probe))]
        for method, action in actions:
            if method == "menu" and not (exists("menu bar 1") and exists(menu)):
                continue
            try:
                action()
            except RuntimeError:
                self.ledger.append(dict(quitAttempt=method, error="deadline"))
            if exited():
                self.ledger.append(dict(quitPath=method, exited=True))
                return
            self.ledger.append(dict(quitAttempt=method, exited=False))
        raise RuntimeError("app quit deadline after menu, AppleEvent and pkill")

    def measure_clock(self):
        samples = [json.loads(self.lab("ssh", "--clock", self.stage + "/leakprobe")) for _ in range(5)]
        return clock_measurement(samples)

    def sample_clock(self):
        self.clock = self.measure_clock()

    def sample_boot_clock(self):
        """Measure the clock offset right after a boot sample and keep it with that sample (verdict.clock_drift)."""
        self.sample_clock()
        sample = self.boot_samples[-1] if self.boot_samples else None
        if sample:
            sample.update(clockOffsetSeconds=self.clock["offsetSeconds"], clockUncertaintySeconds=self.clock["uncertaintySeconds"])

    def daemon_pid(self):
        """The daemon's pid right now (the guest's daemon-pid action); None, with a ledger entry, when it cannot be read."""
        try:
            deadline = HARNESS.seconds("STATUS_POLL")
            text = self.guest_action("daemon-pid", check=False, deadline=deadline, timeout=deadline + 10).decode(errors="replace")
        except (RuntimeError, OSError):
            text = ""
        found = re.fullmatch(r"daemonpid=([1-9]\d{0,9})\s*", text)
        self.ledger.append(dict(preRestartDaemonPid="read" if found else "unavailable"))
        return int(found[1]) if found else None

    def prevent_relaunch(self):
        """M1-10v (1 Nov 2026): the guest's prevent-relaunch action, after the app is quit and before the reboot, so the boot
        verdict measures the daemon alone. The mechanism, its read-back and its undo (the snapshot restore) are recorded in the row
        observation (relaunchPrevention, judged after boot by verdict.relaunch_prevented_check). A reply that does not show every
        key applied is the named gap relaunchPreventionFailed and the row stops before the reboot."""
        deadline = HARNESS.seconds("STATUS_POLL")
        try:
            text = self.guest_action("prevent-relaunch", check=False, deadline=deadline, timeout=deadline + 10).decode(errors="replace")
        except (RuntimeError, OSError):
            text = ""
        value = VERDICT.parse_relaunch_prevention(text)
        value["undo"] = "snapshot restore"
        self.row_observation["relaunchPrevention"] = value
        self.ledger.append(dict(relaunchPrevention="applied" if value["applied"] else "failed", mechanism=value["mechanism"] or None))
        if not value["applied"]:
            raise RowFailure("relaunchPreventionFailed", "the guest did not confirm that macOS will not reopen WGEX.app at the next login "
                             f"(mechanism {value['mechanism'] or 'unreported'}); the boot would not measure the daemon alone")

    def measure_provenance(self):
        """Compare this checkout's verified build receipt with the restored/installed guest.

        Both modes use the same check. The guest commands only inspect signatures
        and sw_vers; the guarded lab SSH transport selects and verifies the guest.
        """
        app = STATE.build_root(ROOT) / "derived-data/Build/Products/Lab/WGEX.app"
        built = json.loads(self.command([sys.executable, "-I", "-B", str(ROOT / "Tools/lab/check-verdicts.py"),
                                         "--inspect-build", str(app)]))
        self.provenance.update({key: built[key] for key in ("sourceCommit", "buildConfiguration", "buildInputs", "artefacts")})
        script = ('set -eu; sw_vers -productVersion; sw_vers -buildVersion; '
                  'codesign --verify --deep --strict /Applications/WGEX.app; '
                  'for binary in /Applications/WGEX.app/Contents/MacOS/WGEX '
                  '/Applications/WGEX.app/Contents/MacOS/WGEXDaemon '
                  '/Applications/WGEX.app/Contents/Helpers/wgex; do '
                  'codesign --verify --strict "$binary"; '
                  'codesign -d --verbose=4 "$binary" 2>&1; done')
        measured = self.ssh(script).decode().splitlines()
        if len(measured) < 2:
            raise ValueError("guestOS missing")
        self.provenance["guestOS"] = dict(productVersion=measured[0], buildVersion=measured[1])
        hashes = [line.removeprefix("CDHash=") for line in measured[2:] if line.startswith("CDHash=")]
        if len(hashes) != 3 or any(not re.fullmatch(r"[0-9a-f]{40}", value) for value in hashes):
            raise ValueError("installed code-directory hashes missing")
        self.provenance["installed"] = dict(zip(("app", "daemon", "cli"), hashes))
        if self.provenance["installed"] != self.provenance["artefacts"]:
            raise RowFailure("installedArtefactsMismatch", "installed binaries differ from the current Lab build")

    def check_wrapping_key(self):
        """M01-T04: after an install the relaunched daemon must read the stored wrapping key with no prompt. Ad hoc Lab
        signing changes the daemon's cdhash on every build; guest/wrapping-key.sh re-trusts it from the guest escrow.
        Run 9b F1 was needsAttention(wrappingKeyUnavailable) with CSSMERR_CSP_OPERATION_AUTH_DENIED."""
        lines = self.guest_action("secure-install-status").decode(errors="replace").strip().splitlines()
        try:
            doctor = json.loads(lines[-1]) if lines else {}
        except ValueError:
            doctor = {}
        state = doctor.get("secureInstall") if isinstance(doctor, dict) else None
        state = state if isinstance(state, str) and SECURE_INSTALL_STATE.fullmatch(state) else "unreadable"
        self.installation.update(secureInstall=state, wrappingKeyReadable=state == "verified")
        if state != "verified":
            raise RowFailure("wrappingKeyUnreadable", f"reinstalled daemon reports secure install {state}; "
                             "the wrapping key is not readable without a prompt (see installation.wrappingKey)")

    def ensure_rosetta(self):
        """RT-17's unsigned client is its x86_64 slice, and the guest image ships without Rosetta. The install needs Apple's servers,
        so it runs here, after the restore and before any connect: inside the protected window nothing outside the tunnel is
        reachable. The command fails (and prepare with it) when x86_64 code still does not run."""
        probe = "/usr/bin/arch -x86_64 /usr/bin/true"
        self.ssh(f"{probe} 2>/dev/null || {{ sudo -n /usr/sbin/softwareupdate --install-rosetta --agree-to-license >/dev/null 2>&1; {probe}; }}",
                 deadline=CORPUS_STEP_SECONDS)

    def prepare(self, profile, connect=True):
        self.check_peer_key()
        self.lab("restore", self.snapshot, timeout=HARNESS.seconds("RESTORE"))
        self.await_guest()
        self.ssh("umask 077; mkdir -p " + shlex.quote(self.stage))
        if self.rosetta:
            self.ensure_rosetta()
        for name in ["guard.sh", "verdict-actions.sh", "profile-id.sh", "daemon-log-count.awk", "daemon-log-tail.pl", "journal-replay.pl",
                     "gap-actions.sh", "gap-status.pl", "pf-execs.pl", "od-status.pl"]:
            self.guest_file((ROOT / "Tools/lab/tart/guest" / name).read_bytes(), name)
        if getattr(self, "endpoint_name_action", None):
            for name in ("endpoint-name.sh", "asu.sh"):
                self.guest_file((ROOT / "Tools/lab/tart/guest" / name).read_bytes(), name)
        # M1-10m: the restore's load settles (settle_guest) before the first GUI step, the quit or `open -a WGEX` below.
        self.gui_settle = "restore"
        if not self.no_install:
            self.lab("build", timeout=1800)
            self.installation["buildCompleted"] = True
        if self.ssh("if pgrep -x WGEX >/dev/null; then printf running; else printf exited; fi").strip() == b"running":
            self.quit_app()
        if not self.no_install:
            installed = self.lab("install", timeout=900)
            self.installation["installCompleted"] = True
            self.installation["wrappingKey"] = wrapping_key_outcome(installed)
            self.guest_action("refresh-install")
            self.installation["daemonRefreshed"] = True
            self.check_wrapping_key()
        self.measure_provenance()
        self.lab("gui", "run", "open", "-a", "WGEX")
        self.lab("gui", "activate", "WGEX")
        self.cleanups.append(named("diagnostics-stop", lambda: self.guest_action("diagnostics-stop")))
        self.guest_action("diagnostics-start")
        for name in ["start-capture.sh", "stop-capture.sh"]:
            self.guest_file((ROOT / "Tools/lab/tart/capture" / name).read_bytes(), name)
        for name, path in self.guest_binaries.items():
            self.guest_file(path.read_bytes(), name)
        self.ssh("chmod 0700 " + shlex.join([self.stage + "/leakprobe", self.stage + "/foreign-utun"]))
        self.stage_iperf3()
        self.sample_clock()
        self.peer("bash", "-c", "set -eu; test \"$(uname -s)\" = Linux; case \"$(hostname)\" in wg-peer | lima-wg-peer) ;; *) exit 1 ;; esac; umask 077; mkdir " + shlex.quote(self.peer_stage))
        self.peer_file((ROOT / "Tools/leakprobe/receiver.py").read_bytes(), "receiver.py")
        for name in ["peer-fault.sh", "peer-state.sh"]:
            self.peer_file((ROOT / "Tools/lab/lima" / name).read_bytes(), name)
        self.peer("sudo", "-n", "bash", self.peer_stage + "/peer-fault.sh", "check")
        # Clean stale row-owned impairment before every row, including a previous interrupted run.
        self.peer("sudo", "-n", "bash", self.peer_stage + "/peer-fault.sh", "cleanup")
        self.lab("relay", "start")
        self.lab("relay", "mtu", "off")
        # Restore wipes home; profile setup is always repeated after it.
        self.guest_action("down")
        self.import_profile(profile, connect=connect)
        if connect:
            self.await_status("protected")
        self.prepared = True

    def check_peer_key(self):
        """A peer boot can restore wg-quick's own wg0.conf; refuse a non-fixture server key before any connect."""
        expected = public_key_digest((ROOT / "Tests/Fixtures/keys/server.pub").read_text())
        live = self.peer("bash", "-c", PEER_KEY_DIGEST_SCRIPT, check=False).decode(errors="replace").strip()
        if not re.fullmatch(r"[0-9a-f]{12}", live):
            self.ledger.append(dict(error="peerKeyMismatch", fixtureKeyHash=expected))
            raise RowFailure("peerKeyMismatch", "live wg0 public key unreadable on wg-peer; run just lab peer up, then retry")
        if live != expected:
            self.ledger.append(dict(error="peerKeyMismatch", liveKeyHash=live, fixtureKeyHash=expected))
            raise RowFailure("peerKeyMismatch", f"live wg0 public key {live} is not the fixture server key {expected}; "
                             "the peer booted with another wg0.conf: run just lab peer up, then retry")
        self.ledger.append(dict(peerKeyCheck="match", liveKeyHash=live, fixtureKeyHash=expected))

    def stage_iperf3(self):
        """Copy the verified host asset to ~/lab/bin/iperf3; a failure only affects rows that need it."""
        data = IPERF3.verified(self.iperf3_path)
        if data is None:
            self.ledger.append(dict(iperf3Staged=False, reason="host asset missing or not the pinned release; run just lab iperf3 fetch"))
            return
        temporary = GUEST_IPERF3 + ".next"
        try:
            self.ssh("umask 022; mkdir -p " + shlex.quote(GUEST_BIN))
            self.ssh("umask 077; cat > " + shlex.quote(temporary), data=data)
            # Verified again inside the guest before it replaces ~/lab/bin/iperf3.
            self.ssh(f"chmod 0755 {shlex.quote(temporary)} && {guest_client_check(temporary)} && "
                     f"mv -f {shlex.quote(temporary)} {shlex.quote(GUEST_IPERF3)} || {{ rm -f {shlex.quote(temporary)}; exit 1; }}")
            staged = True
        except RuntimeError:
            staged = False
        self.ledger.append(dict(iperf3Staged=staged, guestPath=GUEST_IPERF3, release=IPERF3.PIN["asset"] + " " + IPERF3.PIN["version"]))

    def import_profile(self, profile, connect=False):
        self.lab("profile", profile)
        if getattr(self, "endpoint_name_action", None):
            self.endpoint_name_step("fresh-profile")
        self.lab("gui", "run", "open", "-a", "WGEX")
        self.lab("gui", "activate", "WGEX")
        self.click_id("wgex.main.sidebarImport")
        path = f"/Users/{GUEST_USER}/lab/wgex-lab-" + profile + ".conf"
        self.lab("gui", "run", "open", "-a", "WGEX", path)
        self.pause(0.5)
        dump = self.import_review()
        if "id=wgex.importReview.duplicate |" in dump:
            self.click("Replace")
        self.click_id("wgex.importReview.importAndConnect" if connect else "wgex.importReview.importLabel")
        self.select_profile(profile)

    def endpoint_name_step(self, action, *args, **kwargs):
        return self.ssh(shlex.join(["bash", self.stage + "/endpoint-name.sh", action, *args]), **kwargs)

    def endpoint_name_row(self, action, profile):
        """Fresh name, no cache/last-good; guest-only fault, timed start and automatic rollback, never abort."""
        raw = self.endpoint_name_step(action, self.profile_ids[profile], deadline=25, timeout=30)
        evidence = json.loads(raw)
        checks = endpoint_name_checks(action, evidence)
        self.row_observation["endpointName"] = evidence
        return checks

    def start_receivers(self, configuration):
        # Lifetime is a cap only: cleanup() touches both stop files at the row's end.
        lifetime = str(HARNESS.seconds("RECEIVER_LIFETIME"))
        data = json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode()
        (self.output / "config.json").write_bytes(data)
        self.guest_file(data, "config.json")
        self.peer_file(data, "config.json")
        self.start([sys.executable, "-I", "-B", str(ROOT / "Tools/leakprobe/receiver.py"), "--config", str(self.output / "config.json"),
                    "--scope", "outside_tunnel", "--record", str(self.output / "host.json"), "--ready", str(self.output / "host.ready"),
                    "--stop", str(self.output / "host.stop"), "--seconds", lifetime])
        stage = shlex.quote(self.peer_stage)
        self.peer("bash", "-c", f"nohup sudo -n python3 -I -B {stage}/receiver.py --config {stage}/config.json --scope in_tunnel --record {stage}/peer.json --ready {stage}/peer.ready --stop {stage}/peer.stop --seconds {lifetime} >/dev/null 2>&1 </dev/null &")
        self.receiver_started = True
        deadline = self.runner.monotonic() + HARNESS.seconds("RECEIVER_READY")
        while self.runner.monotonic() < deadline:
            ready = self.peer("sudo", "-n", "cat", self.peer_stage + "/peer.ready", check=False)
            if (self.output / "host.ready").exists() and ready and json.loads(ready).get("ready") is True:
                return
            self.pause(0.2)
        raise RuntimeError("receiver readiness deadline")

    def observe(self):
        result = parse_observations(self.guest_action("observe", deadline=600, record_stdout=True).decode())
        index = len(list(self.output.glob("guest-*.json")))
        (self.output / f"guest-{index}.json").write_text(json.dumps(result, sort_keys=True))
        return result

    def start_capture(self, iface, label):
        raw = self.ssh(shlex.join(["bash", self.stage + "/start-capture.sh", iface, label])).decode()
        match = re.search(r"captureFile=(/[^\s]+\.pcap)", raw)
        if not match:
            raise ValueError("capture path missing")
        self.captures[match[1]] = iface
        if self.stop_captures not in self.cleanups:
            self.cleanups.append(self.stop_captures)

    def start_captures(self, observation, row_name):
        self.start_capture("en0", row_name.replace(".", "-"))
        for iface in tunnel_interfaces(observation["ifconfig"]):
            self.start_capture(iface, row_name.replace(".", "-"))

    def restart_tunnel_captures(self, row_name):
        """After M5.3-10's lead control (M1-10o fix pass 2, F6): the explicit down destroys the utun the capture started on
        and the reconnect brings up a new one, so the utun capture restarts on the interface now carrying 10.77.0.2
        (start-capture.sh replaces a record whose tcpdump has ended). utun pcaps are evidence only (the verdict inspects
        *-en0.pcap): a restart that fails or finds no such interface is recorded in utun_coverage (the verdict's
        utunCaptureCoverage) as the coverage gap, never a row gap."""
        coverage = dict(beforeLead=sorted({iface for iface in self.captures.values() if iface != "en0"}), afterReconnect=[], gap=None)
        try:
            for iface in tunnel_interfaces(self.ssh("/sbin/ifconfig", check=False).decode(errors="replace")):
                self.start_capture(iface, row_name.replace(".", "-") + "-reconnect")
                coverage["afterReconnect"].append(iface)
        except (RuntimeError, ValueError) as error:
            coverage["gap"] = (f"utun capture restart after the lead's reconnect failed ({type(error).__name__}); utun coverage after the "
                               "lead's down is limited to whatever the earlier capture still recorded")
        if not coverage["afterReconnect"] and coverage["gap"] is None:
            coverage["gap"] = "no interface carries 10.77.0.2 after the lead's reconnect; utun capture coverage ends at the lead's down"
        self.utun_coverage = coverage
        self.ledger.append(dict(utunCaptureRestart=coverage))

    def stop_captures(self):
        self.ssh(shlex.join(["bash", self.stage + "/stop-capture.sh"]))
        for index, (remote, iface) in enumerate(self.captures.items()):
            raw = self.ssh(shlex.join(["sudo", "-n", "cat", remote]))
            (self.output / f"capture-{index}-{iface}.pcap").write_bytes(raw)

    def sample_phase(self, label):
        try:
            status = self.status()
        except (RuntimeError, ValueError):
            status = dict(phase="unavailable", protection="unknown")
        self.fault_phases.append(dict(label=label, timestamp=self.runner.now() + self.clock["offsetSeconds"], **status))

    def generate(self, state, action=None, role="body", sample_status=True, lead=1, rounds=24):
        self.window_number += 1
        nonce = self.nonce + "-w" + str(self.window_number)
        command = shlex.join([self.stage + "/leakprobe", "generate", "--config", self.stage + "/config.json", "--rounds", str(rounds),
                              "--state", state, "--nonce", nonce, "--record", self.stage + "/generator.json"]) + " >/dev/null"
        process = self.start(["just", "lab", "ssh", "--", command])
        if action:
            self.pause(lead)
            action()
        if sample_status:
            self.sample_phase("during:" + role)
        query_path = self.stage + "/system-" + str(self.window_number) + ".json"
        query = shlex.join(["perl", "-e", 'alarm shift; exec @ARGV or die "exec failed\\n"', "8", self.stage + "/leakprobe",
                            "system-resolve", "--nonce", nonce, "--record", query_path]) + " >/dev/null"
        self.ssh(query, check=False, timeout=HARNESS.seconds("SYSTEM_RESOLVE"))
        attempt = json.loads(self.ssh("cat " + shlex.quote(query_path)))
        try:
            if process.wait(timeout=HARNESS.seconds("GENERATOR_WAIT")):
                raise RuntimeError("guest generator failed")
        except subprocess.TimeoutExpired:
            raise RuntimeError("guest generator deadline") from None
        record = json.loads(self.ssh("cat " + shlex.quote(self.stage + "/generator.json")))
        record.update(clockToleranceSeconds=self.clock_tolerance, role=role, systemResolverProbe=attempt)
        for window in record["windows"]:
            window["requiredFamilies"] = ["ipv4"]
            # The generator's own end, before the driver extends the window to now: the detection window's coverage check uses it.
            window["generatorEnd"] = window["end"]
            window["end"] = max(window["end"], self.runner.now() + self.clock["offsetSeconds"])
            window.pop("receiversComplete", None)
        return record

    def reboot_probe(self):
        self.quit_app()
        if self.prevent_login_relaunch:
            self.prevent_relaunch()
        # M1-10u fix pass 1: the daemon that is about to be restarted, recorded before the reboot step.
        self.pre_restart_daemon_pid = self.daemon_pid()
        self.guest_action("reboot", check=False)
        self.pause(2)
        self.await_ssh(HARNESS.seconds("SSH_RETURN_AFTER_REBOOT"), "SSH did not return after reboot")
        ssh_return_host = self.runner.now()
        # M1-10m: the boot's load settles before the first GUI step after it, never inside the never-open window.
        self.gui_settle = "reboot"
        self.guest_action("diagnostics-start")
        # Whether the app is running after boot (C8): sampled now and again once the boot phase ends.
        self.boot_samples = [self.boot_observe()]
        self.sample_boot_clock()
        self.sample_log = []
        ssh_return = ssh_return_host + self.clock["offsetSeconds"]
        self.start_capture("en0", "post-boot-never-open")
        # M1-10q: the post-boot en0 capture runs from here (it cannot be armed across the reboot); boot to here is uncaptured.
        capture_at = self.runner.now() + self.clock["offsetSeconds"]
        self.post_boot_capture = list(self.captures)[-1]
        record = self.generate("blocked", role="neverOpen", sample_status=False)
        first_status = self.status()
        first_status_at = self.runner.now() + self.clock["offsetSeconds"]
        # M1-10q fix pass 1 (VERIFY N2): the generator's first window start (guest clock), probedFrom; a window ending at
        # or before it held no probe (never_open_window measured false).
        starts = [window["start"] for window in record.get("windows", []) if VERDICT.finite_number(window.get("start"))]
        # The driver's first poll; run() moves the window's end to the daemon's first blocked status line where the row
        # asks for it (never_open_window) once the boot timeline is read.
        record["neverOpenWindow"] = dict(start=ssh_return, end=first_status_at, firstStatus=first_status, postBootCaptureAt=capture_at,
                                         probedFrom=min(starts) if starts else None)
        return record

    def post_boot_flows(self, rules, first_enforcing_at=None):
        """M1-10q unexplainedOutsideFlow: headers of the post-boot en0 capture (no payload), outside flows only, matched
        against the after-boot pf rules; a failed read is recorded as not inspected, never a gap. Fix pass 1 (VERIFY N3):
        each flow is tagged beforeFirstEnforcing against the daemon's first enforcing status line."""
        remotes = list(self.captures)
        path = None
        if self.post_boot_capture in remotes:
            # stop_captures names the copies capture-<index>-<iface>.pcap in self.captures order.
            path = self.output / f"capture-{remotes.index(self.post_boot_capture)}-en0.pcap"
        if path is None or not path.exists():
            return dict(inspected=False, reason="no post-boot en0 capture was collected")
        try:
            text = self.command(["tcpdump", "-nn", "-tt", "-r", str(path), OUTSIDE_FLOW_FILTER],
                                timeout=HARNESS.seconds("PCAP_READ")).decode(errors="replace")
        except (RuntimeError, OSError) as error:
            self.ledger.append(dict(outsideFlowInspection="failed", error=type(error).__name__))
            return dict(inspected=False, reason="tcpdump read failed; see build-root ledger")
        return VERDICT.unexplained_outside_flow(text, rules, first_enforcing_at)

    def iperf(self):
        present = self.ssh(f"if {guest_client_check(GUEST_IPERF3)}; then printf present; else printf missing; fi", check=False)
        if present.strip() != b"present":
            raise RowFailure("iperf3Missing", f"{GUEST_IPERF3} is absent or not the pinned {IPERF3.PIN['asset']} "
                             f"{IPERF3.PIN['version']}; run just lab iperf3 fetch on the host, then rerun (prepare stages it after restore)")
        self.peer("bash", "-c", "nohup iperf3 -s -1 -B 10.77.0.1 -p 5201 >/dev/null 2>&1 </dev/null &")
        deadline = self.runner.monotonic() + HARNESS.seconds("IPERF3_READY")
        while self.runner.monotonic() < deadline:
            # Inspect listening state; a connect readiness probe would consume -1.
            ready = self.peer("bash", "-c", "ss -H -ltn 'sport = :5201'", check=False)
            if ready.strip():
                break
            self.pause(0.2)
        else:
            raise RuntimeError("iperf3 server readiness deadline")
        result = json.loads(self.ssh(shlex.join([GUEST_IPERF3, "-c", "10.77.0.1", "-p", "5201", "-t", "10", "-J"]), timeout=HARNESS.seconds("IPERF3_CLIENT")))
        bits = result["end"]["sum_received"]["bits_per_second"]
        if not isinstance(bits, (int, float)) or not 0 < bits < 1e15:
            raise ValueError("invalid throughput measurement")
        return dict(name="iperf3NumberRecorded", met=True, megabitsPerSecond=bits / 1e6,
                    engineFollowUp=bits < 100e6, performanceGateAccepted=False, baseline="not measured; measurement row only")

    def collect(self):
        """Evidence collection, before any cleanup step (M1-10o, guest run 8e: the row's end voided offlineEn0Capture): the
        guest captures are stopped and copied, then the receivers stop and the peer's record is copied. Returns the gaps:
        missing evidence stays a gap; a fixture cleanup failure (cleanup) is a ledger warning."""
        errors = []
        if self.stop_captures in self.cleanups:
            self.cleanups.remove(self.stop_captures)
            try:
                self.stop_captures()
            except (RuntimeError, OSError, ValueError) as error:
                self.ledger.append(dict(collection="captures", error=type(error).__name__))
                errors.append("en0 capture collection failed; see build-root ledger")
        if self.receiver_started:
            try:
                self.pause(self.clock_tolerance + 0.1)
                (self.output / "host.stop").touch()
                self.peer("sudo", "-n", "touch", self.peer_stage + "/peer.stop")
                for process in self.processes:
                    process.wait(timeout=HARNESS.seconds("PROCESS_STOP"))
                deadline = self.runner.monotonic() + HARNESS.seconds("RECEIVER_RECORD")
                while self.runner.monotonic() < deadline:
                    raw = self.peer("sudo", "-n", "cat", self.peer_stage + "/peer.json", check=False)
                    if raw:
                        (self.output / "peer.json").write_bytes(raw)
                        break
                    self.pause(0.2)
                else:
                    raise RuntimeError("receiver record missing")
            except (RuntimeError, OSError, subprocess.SubprocessError):
                errors.append("receiver collection incomplete")
        return errors

    def read_captures(self):
        """The copied en0 captures as tcpdump text (IPv6 or port 53 only) for inspect_capture_text, read right after
        collect and before cleanup (M1-10o); None, with a ledger entry, when tcpdump fails or hits its deadline."""
        text = []
        try:
            for path in sorted(self.output.glob("*-en0.pcap")):
                text.append(self.command(["tcpdump", "-nn", "-tt", "-A", "-r", str(path), "ip6 or port 53"],
                                         timeout=HARNESS.seconds("PCAP_READ")).decode(errors="replace"))
        except (RuntimeError, OSError) as error:
            self.ledger.append(dict(captureInspection="failed", error=type(error).__name__))
            return None
        return text

    def cleanup(self):
        """Row fixture cleanup after collect (M1-10o): each operation that fails is a ledger warning, never a row gap;
        the step ledger is written last. Returns the warnings, each led by the operation's name (fix pass 2, F5), which
        run() publishes as the verdict's cleanupWarnings."""
        warnings = []
        for operation in reversed(self.cleanups):
            try:
                operation()
            except (RuntimeError, OSError, ValueError) as error:
                name = getattr(operation, "cleanupName", None) or getattr(operation, "__name__", "operation")
                warnings.append(f"{name}: row fixture cleanup failed ({type(error).__name__}); the next restore discards guest state")
                self.ledger.append(dict(cleanupWarning=warnings[-1], operation=name))
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=HARNESS.seconds("PROCESS_STOP"))
        (self.output / "steps.json").write_text(json.dumps(self.ledger, indent=2))
        return warnings


def endpoint_name_checks(action, evidence):
    """Fail closed on missing observations; timings include the rollback status read, on the guest's clock."""
    before, after = evidence.get("before", {}), evidence.get("after", {})
    rollback = after.get("cutover", {})
    checks = [dict(name="freshNameWithoutCachedAnswer", met=evidence.get("freshName") is True
                   and evidence.get("noLastGood") is True),
              dict(name="resolverUnreachableInGuest", met=evidence.get("faultPackets", 0) > 0),
              dict(name="namedFailure", met=evidence.get("exitCode") == 8
                   and evidence.get("error") == "underlayResolverNoAnswer"),
              dict(name="automaticRollbackWithin15Seconds", met=isinstance(evidence.get("elapsedSeconds"), (int, float))
                   and 0 <= evidence["elapsedSeconds"] <= 15 and rollback == dict(state="rolledBack", reason="startFailed")),
              dict(name="priorProtectionRestoredWithoutAbort", met=before.get("protection") == "unprotected"
                   and after.get("protection") == before["protection"] and after.get("phase") == "idle"
                   and after.get("policyEnforcing") is False and after.get("activeProfileID") is None
                   and after.get("operationInFlight") is False and after.get("cutoverRollbackFailures") == [])]
    if action == "endpoint-name-lookup":
        checks.append(dict(name="vpsDNSOnlyUnderConnectingPolicy", met=evidence.get("lookupHost") == "cdn.example.net"
                           and evidence.get("addresses") == ["203.0.113.75"]
                           and evidence.get("connectingBeforeLookup") is True and evidence.get("connectingAfterLookup") is True))
    return checks


def remeasure_exempt(row_name, row):
    """M03-T03 (REV-M01-T03): only M5.3-07, the update row, skips the end-of-row installed re-measure."""
    return row_name == UPDATE_ROW and row.get("action") == "update"


def finish_provenance(session, row_name, row):
    """Re-read at completion: neither a long row nor an update may silently change the installed artefacts or the
    source/build inputs it claims. M5.3-07 installs a different bundle on purpose, so it alone records and checks the
    update bundle's own hashes and receipt instead (measure_update; check-verdicts validates them)."""
    if remeasure_exempt(row_name, row):
        session.measure_update()
        return
    initial_provenance = session.provenance.copy()
    session.measure_provenance()
    if session.provenance != initial_provenance:
        raise RowFailure("provenanceChanged", "build or guest provenance changed during the row")


def run(row_name, row, table, verdict, controls, runner=None, probe_path=None, foreign_helper_path=None, no_install=False, iperf3_path=None,
        host_load_start=None, host_load=None):
    session = Session(row_name, controls, runner, probe_path, foreign_helper_path, no_install, iperf3_path)
    # Capture metadata (M1-10i): host load at capture start and end, beside the captures; evidence only.
    sample_load = host_load or HARNESS.host_load
    load_start = host_load_start or sample_load()
    (session.output / "host-load.json").write_text(json.dumps(HARNESS.load_record(load_start, None), indent=2, sort_keys=True))
    records, observations, checks, gaps = [], [], [], []
    restore_fault = kind = post_boot_rules = None
    try:
        action = row["action"]
        profile = row.get("profile", "default")
        session.tcp_budget = 1500 if action == "latency" else 100
        kind = row.get("checks")
        connect = row.get("connect", action != "blackhole")
        if action == "update":
            session.build_update()
        session.rosetta = action == "rt17"
        if action in ("endpoint-name-fail", "endpoint-name-lookup"):
            session.endpoint_name_action = action
        session.prepare(profile, connect=connect)
        config = dict(format="marker", intervalMilliseconds=500, targets=[
            dict(address="192.168.64.1", scope="outside_tunnel", dnsPort=5354, httpPort=8088, udpPort=8088, allowedLAN=False),
            dict(address="10.77.0.1", scope="in_tunnel", dnsPort=53, httpPort=8088, udpPort=8088, allowedLAN=False)])
        if action == "latency":
            config["tcpTimeoutMilliseconds"] = session.tcp_budget
        session.start_receivers(config)
        session.pause(session.clock_tolerance + 0.1)
        before = session.observe()
        observations.append(before)
        if action != "iperf":
            session.start_captures(before, row_name)
        if kind in LEAD_CONTROL_KINDS:
            # M1-10o fix pass: the positive control leads. Lockdown is turned on below and never off (turning it off raises
            # the administrator prompt), so one unprotected window with receipts required runs first, in the same receivers
            # and en0 capture. M5.3-10 starts connected: down for the window, then connect again, because its captive
            # steps need the tunnel intent; REBOOT-LOCKDOWN is already idle and unprotected.
            session.pause(session.clock_tolerance * 2 + 0.1)
            session.guest_action("down")
            session.await_status("unprotected")
            records.append(session.generate("unprotected", role="unprotectedLead"))
            observations.append(session.observe())
            session.lead_control = True
            if connect:
                session.connect(profile)
                session.await_status("protected")
                session.restart_tunnel_captures(row_name)
        inject = None
        if action in ("kill-app", "kill-no-app", "term"):
            def crash():
                if action == "kill-no-app":
                    session.quit_app()
                session.guest_action(action)
            inject = crash
        elif action == "app-quit":
            inject = session.quit_app
        elif action in ("second-anchor", "resolver", "foreign-up"):
            session.guest_action(action)
            cleanup = {"second-anchor": "remove-second-anchor", "resolver": "remove-resolver", "foreign-up": "foreign-down"}[action]
            session.cleanups.append(named(cleanup, lambda: session.guest_action(cleanup)))
        elif action == "interface-cycle":
            iface = re.search(r"^(utun\d+):[^\n]*\n(?:(?!^\S).)*?inet 10\.77\.0\.2", before["ifconfig"], re.M | re.S)
            if not iface:
                raise ValueError("lab interface identity missing")
            identity_before = json.loads(session.ssh(shlex.join([session.stage + "/leakprobe", "interface-index", "--name", iface[1]])))
            inject = lambda: session.guest_action(action, iface[1])
            checks.append(dict(name="interfaceIdentityBefore", met=identity_before["index"] > 0, interface=iface[1], **identity_before))
        elif action in ("loss", "latency"):
            restore_fault = named("peer-fault cleanup", lambda: session.peer("sudo", "-n", "bash", session.peer_stage + "/peer-fault.sh", "cleanup"))
            session.cleanups.append(restore_fault)
            session.peer("sudo", "-n", "bash", session.peer_stage + "/peer-fault.sh", action)
        elif action == "mtu":
            session.lab("relay", "mtu", "on")
            session.pause(1.1)  # Allow the relay's bounded control poll before the window.
            restore_fault = named("relay mtu off", lambda: session.lab("relay", "mtu", "off"))
        elif action in ("relay-stop", "blackhole"):
            restore_fault = named("relay start", lambda: session.lab("relay", "start"))
            if action == "blackhole":
                # Registered before the fault, so a wait deadline still restarts the relay (run 6, M5.1-08).
                session.cleanups.append(restore_fault)
                session.lab("relay", "stop")
                session.connect(profile)
                session.await_loss_blocked("blackhole")
            else:
                inject = lambda: session.lab("relay", "stop")
        elif action == "wrong-key":
            session.guest_action("down")
            session.import_profile("wrong-key", connect=True)
            session.await_loss_blocked("wrong-key")
        elif action == "iperf":
            checks.append(session.iperf())
        if restore_fault and restore_fault not in session.cleanups:
            session.cleanups.append(restore_fault)
        if action == "dns-edit":
            restore_dns = named("restore administrator DNS", lambda: session.gap_action("dns-restore"))
            session.cleanups.append(restore_dns)
            session.row_observation.update(json.loads(session.gap_action("dns-edit")))
            records.append(session.generate("protected", role="adminDNSEdit"))
            session.guest_action("down")
            session.await_status("unprotected")
            session.row_observation.update(json.loads(session.gap_action("dns-check")))
            session.row_observation.update(json.loads(session.gap_action("dns-restore")))
            session.cleanups.remove(restore_dns)
            observations.append(session.observe())
        elif action in ("token", "pf-disable", "rt22"):
            if action == "rt22":
                restore_fault = named("relay start", lambda: session.lab("relay", "start"))
                session.cleanups.append(restore_fault)
                session.lab("relay", "stop")
            def inject_fault():
                session.row_observation.update(VERDICT.GAP_ROWS.parse_fault(session.gap_action("fault", action, deadline=HARNESS.seconds("FAULT_SAMPLING")).decode()))
            # DEC-028: a row with a detectionWindow leads the injection by 3 s so the pre window holds probes, then judges the
            # window from injection to the first sample with enforcement restored as its own bounded state.
            detection = row.get("detectionWindow")
            # The generator (500 ms rounds) covers the lead, the 7 s bound, 5 s after restoration and 5 s for the SSH start-up.
            rounds = 2 * (3 + VERDICT.GAP_ROWS.DETECTION_BOUND_SECONDS + VERDICT.GAP_ROWS.POST_OBSERVATION_SECONDS + 5) if detection else 24
            record = session.generate(row["state"], inject_fault, role="fault:" + action, lead=3 if detection else 1, rounds=rounds)
            if detection:
                record["windows"] = VERDICT.GAP_ROWS.split_detection_window(record["windows"], session.row_observation, detection["state"],
                                                                         record["clockToleranceSeconds"])
            records.append(record)
            observations.append(session.observe())
        elif action == "logout":
            records.extend(session.logout_row(profile))
            observations.append(session.observe())
        elif action == "update":
            records.extend(session.update_row(profile))
            observations.append(session.observe())
        elif action == "rt17":
            records.extend(session.rt17_row())
            observations.append(session.observe())
        elif action == "reboot":
            if kind == "reboot-lockdown":
                # M1-10q: the strict case. Allow LAN off first (tightening, no prompt), so the underlay subnet must stay dark
                # under lockdown after boot; both flags are read back from the journal right before the reboot.
                session.set_allow_lan_off()
                session.set_lockdown(True)
                session.await_status("blocked")
                session.row_observation.update(lockdownBeforeReboot=session.journal_lockdown(), statusBeforeReboot=session.status(),
                                               allowLANBeforeReboot=session.journal_allow_lan())
            elif kind == "boot-secrets":
                session.prevent_login_relaunch = True
                identity = session.profile_ids[profile]
                session.set_startup_boot(identity)
                # Stays connected: an explicit down deletes the daemon's bundle even with boot intent set
                # (TunnelController+Lifecycle.swift stopStep deleteSecrets), so a disconnect here would defeat the row.
                session.row_observation["bootIntentBeforeReboot"] = session.boot_intent(identity)
            else:
                # M03-T07: REBOOT-INTENT records the cutover state and the intended profile before the reboot; an armed trial (or
                # any state but none or confirmed) stops the row before the reboot: a reboot while armed rolls back by design.
                session.status()
                intent_before = verdict.intent_snapshot(session.last_status)
                session.row_observation["intentBeforeReboot"] = intent_before
                cutover_check = verdict.cutover_before_reboot_check(intent_before)
                checks.append(cutover_check)
                if not cutover_check["met"]:
                    raise RowFailure("cutoverStateBeforeReboot", cutover_check["gap"])
            record = session.reboot_probe()
            records.append(record)
            if kind == "boot-secrets":
                session.await_status("protected", timeout=120)
                records.append(session.generate("protected", role="bootSecretsRecovery"))
            elif kind is None:
                # M03-T07: the persisted intent must come back on its own after the reboot (no driver action); a deadline is
                # recorded and leaves the check unmet, never a pass.
                try:
                    session.await_status("protected", timeout=INTENT_RESTORE_WAIT_SECONDS, phase="active")
                except PollDeadline:
                    pass
                session.status()
                intent_after = verdict.intent_snapshot(session.last_status)
                session.row_observation["intentAfterBoot"] = intent_after
                restored = verdict.intent_restored_check(session.row_observation["intentBeforeReboot"], intent_after)
                checks.append(restored)
                if not restored["met"]:
                    gaps.append(restored["gap"])
            session.boot_samples.append(session.boot_observe())
            # Fix pass 1: the offset sampled again at the end of the boot phase, kept with this sample.
            session.sample_boot_clock()
            boot = session.boot_summary(session.boot_samples, record["neverOpenWindow"]["firstStatus"])
            window = record["neverOpenWindow"]
            window.update(verdict.never_open_window(window["start"], window["end"], verdict.restart_timeline(boot)["lines"], strict=kind == "reboot-lockdown",
                                                    probed_from=window.get("probedFrom")))
            boot["neverOpenWindow"] = window
            session.sample_log = None
            after_boot = session.observe()
            observations.append(after_boot)
            post_boot_rules = after_boot.get("rules")
            boot["referenceCount"] = after_boot["referenceCount"]
            session.row_observation["boot"] = boot
            if kind is None:
                checks.append(dict(name="oneReferenceAfterBoot", met=after_boot["referenceCount"] == 1))
                # M1-10u: REBOOT-INTENT has no row checks; its post-restart timeline must still be consistent, and (fix pass 1)
                # launchd must have started the daemon once.
                for item in verdict.reboot_intent_checks(boot):
                    checks.append(item)
                    if not item["met"]:
                        gaps.append(item.get("gap") or f"{item['name']}: launchd runs = {item['daemonRuns'] if item.get('daemonRuns') is not None else 'unreadable'}")
        elif action == "en0-loss":
            for index, variant in enumerate(row["profiles"]):
                if index:
                    session.guest_action("down")
                    session.await_status("unprotected")
                    session.import_profile(variant, connect=True)
                    session.await_status("protected")
                session.pause(session.clock_tolerance * 2 + 0.1)
                records.append(dict(session.generate("protected", role="protected:" + variant), profileVariant=variant))
                observations.append(session.observe())
                loss = session.en0_loss(variant, row.get("lossSeconds", 20))
                if loss:
                    records.append(loss)
                # No user action: the daemon must be protected again on its own after the link returns.
                session.await_status("protected", timeout=60)
                session.pause(session.clock_tolerance * 2 + 0.1)
                records.append(dict(session.generate("protected", role="automaticRecovery:" + variant), profileVariant=variant))
                observations.append(session.observe())
        elif action in ("power-wake", "rt21"):
            if action == "rt21":
                session.row_observation["rulesBefore"] = before["rules"]
                stop_watch = named("stop pf execution observer", lambda: session.gap_action("rt21-stop"))
                session.cleanups.append(stop_watch)
                session.gap_action("rt21-start")
            for variant in row["variants"]:
                session.pause(session.clock_tolerance * 2 + 0.1)
                records.append(dict(session.generate("protected", role="protected:" + variant["name"]), profileVariant=profile))
                observations.append(session.observe())
                records.append(session.power_wake(variant["name"], variant["sleepSeconds"]))
                # No user action: the daemon must be protected again on its own after the wake.
                session.await_status("protected", timeout=POWER_RECOVERY_WAIT_SECONDS)
                session.pause(session.clock_tolerance * 2 + 0.1)
                records.append(dict(session.generate("protected", role="automaticRecovery:" + variant["name"]), profileVariant=profile))
                observations.append(session.observe())
            if action == "rt21":
                session.row_observation["pfExecs"] = [json.loads(line) for line in session.gap_action("rt21-stop").splitlines()]
                session.cleanups.remove(stop_watch)
                session.row_observation["rulesAfter"] = observations[-1]["rules"]
        elif action == "ondemand-eth":
            records.extend(session.ondemand_row(profile, row.get("lossSeconds", 20)))
            observations.extend(session.observations_extra)
        elif action == "uninstall":
            records.extend(session.uninstall_row(profile, before))
            observations.extend(session.observations_extra)
        elif action == "captive":
            records.extend(session.captive_row(profile))
            observations.append(session.observe())
        elif action in ("endpoint-name-fail", "endpoint-name-lookup"):
            checks.extend(session.endpoint_name_row(action, profile))
            observations.append(session.observe())
        elif action == "login-silent":
            records.extend(session.login_silent_row(profile))
            observations.append(session.observe())
        else:
            for scenario in row.get("exercise", [row["state"]]):
                state = "blocked" if scenario in ("connecting", "error") else scenario
                session.pause(session.clock_tolerance * 2 + 0.1)
                if scenario == "connecting":
                    session.guest_action("down")
                    session.lab("relay", "stop")
                    if restore_fault is None:
                        restore_fault = named("relay start", lambda: session.lab("relay", "start"))
                        session.cleanups.append(restore_fault)
                    session.connect(profile)
                    session.await_loss_blocked("connecting")
                elif scenario == "error":
                    session.await_loss_blocked("error")
                elif state == "unprotected":
                    if restore_fault:
                        restore_fault()
                        session.cleanups.remove(restore_fault)
                        restore_fault = None
                        session.await_status("protected", timeout=120)
                        session.pause(session.clock_tolerance * 2 + 0.1)
                        records.append(session.generate("protected", role="automaticRecovery"))
                    session.guest_action("down")
                    session.await_status("unprotected")
                record = session.generate(state, inject, role=scenario)
                inject = None
                observation = session.observe()
                if action == "dns":
                    record["dns"] = observation["dns"]
                records.append(record)
                observations.append(observation)
        if restore_fault:
            restore_fault()
            session.cleanups.remove(restore_fault)
            # No user action: the daemon must recover on its own after fault removal.
            session.await_status("protected", timeout=120)
            session.pause(session.clock_tolerance * 2 + 0.1)
            records.append(session.generate("protected", role="automaticRecovery"))
            observations.append(session.observe())
        if action == "second-anchor":
            after_rules = observations[-1]["rules"]
            first = re.search(r'wgex-canary".*?Evaluations:\s*(\d+)', before["rules"], re.S)
            last = re.search(r'wgex-canary".*?Evaluations:\s*(\d+)', after_rules, re.S)
            checks.append(dict(name="canaryIncremented", met=bool(first and last and int(last[1]) > int(first[1]))))
        if action == "resolver":
            session.guest_action("check-resolver")
            checks.append(dict(name="customResolverVisibleInScutil", met="m1-10.wgex.test" in session.observe()["dns"]))
        if action == "foreign-up":
            session.guest_action("check-foreign")
            checks.append(dict(name="foreignScopedRoutesSurvive", met=True))
        if action == "interface-cycle":
            current = re.search(r"^(utun\d+):[^\n]*\n(?:(?!^\S).)*?inet 10\.77\.0\.2", observations[-1]["ifconfig"], re.M | re.S)
            if not current:
                raise ValueError("lab interface missing after recovery")
            identity_after = json.loads(session.ssh(shlex.join([session.stage + "/leakprobe", "interface-index", "--name", current[1]])))
            checks.append(dict(name="interfaceIdentityAfter", met=identity_after["index"] > 0,
                               interface=current[1], recreated=current[1] != iface[1] or identity_after != identity_before, **identity_after))
        if action in ("kill-app", "kill-no-app", "term"):
            checks.append(dict(name="oneReferenceAfterRestart", met=observations[-1]["referenceCount"] == 1))
        # Positive guest-to-host control is mandatory for every measured row. Under lockdown the trailing one needs lockdown
        # off, which the driver never does (M1-10o): it is skipped, and the row's lead control stands in for it; a row
        # without one keeps the gap lockdownOffNeedsAdmin and its tail control stays unmet.
        if session.lockdown_on and not session.lockdown_off_needed("the unprotected tail"):
            if not session.lead_control:
                gaps.append(session.lockdown_gap)
        else:
            session.pause(session.clock_tolerance * 2 + 0.1)
            session.guest_action("down")
            session.await_status("unprotected")
            records.append(session.generate("unprotected", role="unprotectedTail"))
            observations.append(session.observe())
        finish_provenance(session, row_name, row)
        session.row_finished = True
    except (RuntimeError, OSError, ValueError, KeyError, TypeError) as error:
        gaps.append(str(error) if isinstance(error, (PollDeadline, RowFailure)) else live_step_gap(error))
    finally:
        # M1-10o: evidence first (captures and receiver records, then the capture inspection), only then the fixture
        # cleanup, whose failures are ledger warnings: a cleanup step can no longer void offlineEn0Capture.
        gaps.extend(session.collect())
        capture_text = session.read_captures()
        cleanup_warnings = session.cleanup()
    receivers, named_receivers = [], []
    for name in ["host", "peer"]:
        path = session.output / (name + ".json")
        if path.exists():
            value = json.loads(path.read_bytes())
            for item in value["observations"]:
                item["timestamp"] += session.clock["offsetSeconds"]
            for item in value.get("receiverCoverage", []):
                item["start"] += session.clock["offsetSeconds"]
                item["end"] += session.clock["offsetSeconds"]
            at = value.get("healthPollGapAt")
            if (isinstance(at, (int, float)) and not isinstance(at, bool) and 0 <= at < 4_000_000_000
                    and verdict.finite_number(at)):
                value["healthPollGapAt"] += session.clock["offsetSeconds"]
            receivers.append(value)
            named_receivers.append((name, value))
    # M1-57 fix pass 1 (VERIFY N1): the health lines are diagnostics; they stay out of `gaps` while rowCompleted is decided (a
    # completed row with an unhealthy receiver is still a completed row for verdict-run's report destination) and join the
    # verdict's gaps at the return, where `met` already counts them.
    health_gaps = verdict.receiver_health_gaps(named_receivers)
    states = []
    families = set()
    scope = verdict.tunnel_scope(profile)
    for index, record in enumerate(records):
        record["action"] = action
        record["tunnelScope"] = verdict.tunnel_scope(record.get("profileVariant", profile))
        (session.output / f"generator-{index}.json").write_bytes(verdict.canonical(record))
        result = verdict.evaluate(record, table, receivers)
        states.extend(dict(window, role=record["role"]) for window in result["states"])
        families.update(result["familiesCovered"])
        if "neverOpenWindow" in record:
            window = record["neverOpenWindow"]
            # M1-10q: only this row's own probes (nonce lab-<row>-w<n>, any window, -system included) count, never a
            # receiver self-control or a stray marker; the row's nonce is recorded beside the window.
            window["nonce"] = session.nonce
            own = [o for receiver in receivers for o in receiver["observations"] if o.get("kind") == "received"
                   and str(o.get("nonce", "")).startswith(session.nonce + "-w")]
            receipts = [o for o in own if window["start"] <= o["timestamp"] < window["end"]]
            # A row that never connects has no tunnel, so a receipt at the in-tunnel peer is outside too.
            outside = [o for o in receipts if not connect or o.get("scope") != "in_tunnel"]
            if kind is None:
                checks.append(dict(name="zeroReceiptsBeforeFirstStatus", scope="outside_tunnel", met=not outside,
                                   receiptCount=len(outside), inTunnelReceiptCount=len(receipts) - len(outside), **window))
            else:
                boot = session.row_observation.setdefault("boot", {})
                boot["outsideReceiptsBeforeFirstStatus"] = len(outside)
                if kind == "reboot-lockdown":
                    # The strict case after boot: [SSH return, driver's first poll) holds the whole post-boot probe window.
                    after = [o for o in own if window["start"] <= o["timestamp"] < window.get("driverFirstPollAt", window["end"])]
                    off = [o for o in after if not verdict.in_underlay_subnet(o.get("address"))]
                    boot.update(lanReceiptsAfterBoot=len(after) - len(off), offSubnetReceiptsAfterBoot=len(off),
                                offSubnetAddresses=sorted({str(o.get("address")) for o in off}))
    tolerance = session.clock_tolerance
    for item in session.row_observation.get("profiles", []):
        loss = next((record for record in records if record.get("role") == item.get("role", "linkLoss:" + item["variant"])), None)
        if loss is None or not all(verdict.finite_number(item.get(key)) for key in ("down", "up")):
            continue
        received = [o for receiver in receivers for o in receiver["observations"] if o.get("kind") == "received"
                    and o.get("scope") != "in_tunnel" and o.get("nonce") == item["lossNonce"]
                    and item["down"] - tolerance <= o["timestamp"] <= item["up"] + tolerance]
        item["lossOutsideReceipts"] = len(received)
        item["lossProbeAttempts"] = sum(verdict.probe_attempt(o) and o.get("scope") == "outside_tunnel"
                                        and verdict.finite_number(o.get("timestamp")) and item["down"] <= o["timestamp"] <= item["up"]
                                        for o in loss["observations"])
    # M1-47: outside receipts and probe attempts inside each injected-event window, from the sleep to the first protected sample
    # after the wake (verdict.power_window), counted from the row's own nonce for that variant.
    for item in session.row_observation.get("powerWakes", []):
        window = next((record for record in records if record.get("role") == "powerWake:" + item["variant"]), None)
        span = verdict.power_window(item)
        if window is None or span is None:
            continue
        start, end = span
        received = [o for receiver in receivers for o in receiver["observations"] if o.get("kind") == "received"
                    and o.get("scope") != "in_tunnel" and o.get("nonce") == item["windowNonce"]
                    and start - tolerance <= o["timestamp"] <= end + tolerance]
        item["windowOutsideReceipts"] = len(received)
        item["windowProbeAttempts"] = sum(verdict.probe_attempt(o) and o.get("scope") == "outside_tunnel"
                                          and verdict.finite_number(o.get("timestamp")) and start <= o["timestamp"] <= end + tolerance
                                          for o in window["observations"])
    if kind:
        try:
            for check in verdict.row_checks(kind, session.row_observation):
                checks.append(check)
                if not check["met"] and check.get("gap"):
                    gaps.append(check["gap"])
        except (KeyError, TypeError, ValueError):
            gaps.append(f"Row checks ({kind}) incomplete: observation missing; see row-observation.json under buildRoot")
    # M1-10q: REBOOT-LOCKDOWN keeps lockdown on for its whole post-boot capture; outside flows no pass rule explains are a
    # named observation (unexplainedOutsideFlow), never a check or a gap.
    outside_flow = None
    if kind == "reboot-lockdown":
        first_enforcing = verdict.early_boot_capture(session.row_observation.get("boot") or {})["firstEnforcingStatusAt"]
        outside_flow = session.post_boot_flows(post_boot_rules, first_enforcing)
    (session.output / "row-observation.json").write_text(json.dumps(session.row_observation, indent=2, sort_keys=True))
    boot_observation = verdict.boot_report(session.row_observation["boot"]) if session.row_observation.get("boot", {}).get("firstStatus") else None
    if capture_text is None:
        gaps.append("en0 capture inspection failed; see build-root ledger")
        capture_text = []
    # M1-10o fix pass: the lead control stands in for the trailing one only when that was skipped for lockdownOffNeedsAdmin;
    # then both tailControl and offlineEn0Capture's tailSystemResolverObserved come from the lead window alone.
    position = "lead" if session.lead_control and session.lockdown_gap else "trail"
    control_role = "unprotectedLead" if position == "lead" else "unprotectedTail"
    if action == "iperf":
        capture = dict(skipped="IPERF3 throughput measurement", port53Inspected=False, ipv6Inspected=False)
        checks.append(dict(name="offlineEn0Capture", met=True, **capture))
    else:
        capture = inspect_capture_text("\n".join(capture_text), records, control_roles=(control_role,) if position == "lead" else None)
        checks.append(dict(name="offlineEn0Capture", met=bool(capture_text) and not capture["port53Leaks"] and not capture["ipv6Leaks"] and capture["tailSystemResolverObserved"], **capture))
    if position == "lead":
        lead = [window for window in states if window.get("role") == control_role]
        tail = bool(lead) and all(window.get("expectationMet") is True for window in lead)
    else:
        tail = bool(states) and states[-1].get("role") == "unprotectedTail" and states[-1].get("expectationMet") is True
    (session.output / "steps.json").write_text(json.dumps(session.ledger, indent=2))
    # M1-10o fix pass 2 (F4, run 8e: M5.3-10 took 3273 s of its 3600 s alarm, 1796 s of it in 29 dumps): the row's total
    # GUI time, every completed `just lab gui` command in the ledger, so the next run measures the walk budget.
    gui_seconds = round(sum(item["end"] - item["start"] for item in session.ledger
                            if item.get("argv", [])[:3] == ["just", "lab", "gui"] and "end" in item), 3)
    host_load_record = HARNESS.load_record(load_start, sample_load())
    (session.output / "host-load.json").write_text(json.dumps(host_load_record, indent=2, sort_keys=True))
    hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in session.output.glob("*.json")}
    met = bool(states) and tail and not gaps and not health_gaps and all(window.get("expectationMet") for window in states) and all(check["met"] for check in checks)
    return dict(states=states, observations=observations, checks=checks, gaps=gaps + health_gaps, familiesCovered=sorted(families) if met else [],
                prepareCompleted=session.prepared, rowCompleted=session.row_finished and bool(states) and not gaps, installation=session.installation,
                **session.provenance, **(dict(update=session.update) if session.update else {}),
                bootObservation=boot_observation, **(dict(unexplainedOutsideFlow=outside_flow) if outside_flow else {}),
                tailControl=dict(required=True, met=tail, receiptsRequired=True, receiverHealthProves="receiver binding/self-control only; guest path is proven by tail receipts",
                                 **(dict(trailSkipped="lockdownOffNeedsAdmin") if session.lockdown_gap else {})),
                tailControlPosition=position,
                clockMeasurement=session.clock, phasesDuringFault=session.fault_phases, captureChecks=capture,
                buildRoot=str(session.output), recordHashes=hashes, tunnelScope=scope, expectationsMet=met, deadlineDiagnostics=session.deadlines,
                hostLoad=host_load_record, guestLoadAtGUIStart=session.guest_loads, guiSeconds=gui_seconds,
                cleanupWarnings=cleanup_warnings, utunCaptureCoverage=session.utun_coverage,
                **(dict(consoleInput=dict(route="Tart --vnc-experimental, console.py (DEC-034)", steps=session.console.log))
                   if getattr(session, "console", None) else {}),
                transport="injected recorded runner" if runner else "guarded Tart SSH and dedicated Lima peer")
