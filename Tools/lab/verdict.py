#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Receiver-based leak verdicts. Invoke with python3 -I; no network or subprocesses."""

import argparse
import calendar
import hashlib
import importlib.util
import ipaddress
import json
import math
import re
from pathlib import Path
import sys
import time


# Lab profile variants and their AllowedIPs, as Tools/lab/lima/peer-provision.sh writes them (a test keeps them equal).
PROFILE_ALLOWED_IPS = {
    "default": ["10.77.0.0/24"],
    "full4": ["0.0.0.0/1", "128.0.0.0/1"],
    "full4-name": ["0.0.0.0/1", "128.0.0.0/1"],
    "dual": ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"],
    "dns": ["10.77.0.0/24"],
    "lockdown": ["0.0.0.0/1", "128.0.0.0/1"],
    "wrong-key": ["0.0.0.0/1", "128.0.0.0/1"],
}
# Lab topology: the vmnet underlay host and router (receiver host, SSH escape-hatch source) and the relay endpoint
# (profile Endpoint and relay listener 192.168.64.1:51820); a test reads both from the lab scripts. The relay
# endpoint is exempt only because it is the same address; nothing else can ever be named exempt.
UNDERLAY_HOST = "192.168.64.1"
RELAY_ENDPOINT = "192.168.64.1"
# A relay endpoint on any other address would be a separate host on the LAN and is never exempt.
UNDERLAY_DESTINATIONS = [UNDERLAY_HOST]
FULL_TUNNEL_HALVES = (("0.0.0.0/1", "128.0.0.0/1"), ("::/1", "8000::/1"))


def split_tunnel(allowed_ips):
    """True when AllowedIPs cover neither 0/1+128/1 nor ::/1+8000::/1: the profile routes only some destinations."""
    networks = [ipaddress.ip_network(value, strict=False) for value in allowed_ips]
    def covered(half):
        half = ipaddress.ip_network(half)
        return any(network.version == half.version and half.subnet_of(network) for network in networks)
    return not any(all(covered(half) for half in pair) for pair in FULL_TUNNEL_HALVES)


def tunnel_scope(variant):
    """What a profile variant routes; a split profile reaches the underlay host and relay over en0 by design."""
    allowed = list(PROFILE_ALLOWED_IPS[variant])
    return dict(variant=variant, allowedIPs=allowed,
                underlayDestinations=list(UNDERLAY_DESTINATIONS) if split_tunnel(allowed) else [])


def validate_tunnel_scope(scope):
    if not isinstance(scope, dict) or not isinstance(scope.get("allowedIPs"), list) or not isinstance(scope.get("underlayDestinations"), list):
        raise ValueError("tunnel scope")
    networks = [ipaddress.ip_network(value, strict=False) for value in scope["allowedIPs"]]
    for value in scope["underlayDestinations"]:
        if value not in UNDERLAY_DESTINATIONS:
            # Only the lab's own underlay host/router can be exempt; another LAN address (the peer) never.
            raise ValueError("tunnel scope underlay destination")
        address = ipaddress.ip_address(value)
        # An exempt destination is outside the tunnel by construction; a routed address can never be exempt.
        if not address.is_private or any(address in network for network in networks):
            raise ValueError("tunnel scope underlay destination")


def underlay_expected(observation, record, state):
    """Split profiles only, protected windows only: receipts at the underlay host/relay are expected, except system DNS."""
    scope = record.get("tunnelScope")
    if state != "protected" or not scope or not split_tunnel(scope["allowedIPs"]):
        return False
    return (observation.get("scope") == "outside_tunnel" and observation.get("address") in scope["underlayDestinations"]
            and observation.get("nonce") != record["nonce"] + "-system")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def finite_number(value):
    return isinstance(value, (float, int)) and not isinstance(value, bool) and math.isfinite(value)


def validate_record(record):
    if record.get("schemaVersion") != 1 or not isinstance(record.get("nonce"), str):
        raise ValueError("record schema or nonce")
    config = record.get("configuration", {})
    if sha256(canonical(config)) != record.get("configurationSHA256"):
        raise ValueError("configuration hash mismatch")
    if config.get("intervalMilliseconds") != 500 or not config.get("targets"):
        raise ValueError("configuration interval or targets")
    for target in config["targets"]:
        ipaddress.ip_address(target["address"])
        if "resolver" in target:
            ipaddress.ip_address(target["resolver"])
        if target["scope"] not in ("in_tunnel", "outside_tunnel", "gateway"):
            raise ValueError("target scope")
        for key in ("dnsPort", "httpPort", "udpPort"):
            if not isinstance(target[key], int) or isinstance(target[key], bool) or not 1 <= target[key] <= 65535:
                raise ValueError("target port")
    if not isinstance(record.get("observations"), list) or not isinstance(record.get("windows"), list):
        raise ValueError("observations and windows must be arrays")
    if "tunnelScope" in record:
        validate_tunnel_scope(record["tunnelScope"])
    return record


def target_matches(observation, configuration):
    """Only configured receivers/ports can prove successful delivery."""
    proto = observation.get("proto")
    port_key = {"dns": "dnsPort", "http": "httpPort", "tcp": "httpPort", "udp": "udpPort"}.get(proto)
    if port_key is None:
        return False
    try:
        family = "ipv6" if ipaddress.ip_address(observation.get("address")).version == 6 else "ipv4"
    except ValueError:
        return False
    if observation.get("family") != family:
        return False
    for target in configuration["targets"]:
        address = target.get("resolver", target["address"]) if proto == "dns" else target["address"]
        if (observation.get("address") == address and observation.get("port") == target[port_key]
                and observation.get("scope") == target["scope"]):
            return True
    return False


def lan_exception(observation, window, configuration):
    if not window.get("allowLAN") or observation.get("proto") == "dns":
        return False
    return any(target.get("allowedLAN") is True and target["scope"] == "outside_tunnel"
               and target["address"] == observation.get("address")
               and observation.get("port") == target[{"http": "httpPort", "tcp": "httpPort", "udp": "udpPort"}.get(observation.get("proto"), "udpPort")]
               for target in configuration["targets"])


def captive_exception(observation, configuration):
    if observation.get("proto") in ("http", "tcp") and observation.get("port") in (80, 443):
        return target_matches(observation, configuration)
    if observation.get("proto") == "dns" and observation.get("port") == 53:
        return target_matches(observation, configuration)
    return False


def probe_attempt(item):
    if item.get("kind") == "sent":
        return True
    # A blocked TCP connect cannot send a payload. Darwin network errors prove
    # an attempted connect; local descriptor/configuration failures do not.
    return item.get("kind") == "failure" and bool(re.fullmatch(r"socket\((?:36|51|60|61|64|65)\)", item.get("detail", "")))


def receipt_nonce_matches(item, record):
    """System DNS has a separate, exact nonce label; prefixes never match."""
    return item.get("nonce") == record["nonce"] or (item.get("proto") == "dns" and item.get("nonce") == record["nonce"] + "-system")


def receiver_coverage(window, record):
    """Compute coverage from bound, control-tested receiver lifetimes, never a sender boolean.

    One healthy receiver must cover the entire half-open window for each configured
    binding. A gap, failed control exchange or different config is unknown.
    """
    missing = []
    ports = {"dns": "dnsPort", "http": "httpPort", "tcp": "httpPort", "udp": "udpPort"}
    for target in record["configuration"]["targets"]:
        family = "ipv6" if ":" in target["address"] else "ipv4"
        if family not in window.get("requiredFamilies", ["ipv4", "ipv6"]):
            continue
        for proto, key in ports.items():
            address = target.get("resolver", target["address"]) if proto == "dns" else target["address"]
            binding = dict(scope=target["scope"], proto=proto, address=address, port=target[key])
            if not any(all(item.get(k) == v for k, v in binding.items())
                       and item.get("configurationSHA256") == record["configurationSHA256"]
                       and item.get("healthy") is True
                       and finite_number(item.get("start")) and finite_number(item.get("end"))
                       and item["start"] <= window["start"] - record.get("clockToleranceSeconds", 0)
                       and item["end"] >= window["end"] + record.get("clockToleranceSeconds", 0)
                       for item in record.get("receiverCoverage", [])):
                missing.append(f"receiver:{address}:{target[key]}:{proto}")
    return {"complete": not missing, "missing": missing}


def receiver_health_gaps(receivers):
    """M1-57 (run 9b F2): one gap line per unhealthy receiver, naming why (healthCause, written by Tools/leakprobe/receiver.py:
    pollGap with the largest gap and its time, startControl, endControl). Text only: the 1.5 s rule, the healthy flag and the
    coverage decision are untouched, so an unhealthy record stays unhealthy. A record without the field (older) says so.
    Diagnostic bounds only: seconds 0..86400 (one day), epoch time 0 <= at < 4000000000 (through 2096). Omit malformed
    numbers or unconvertible times, keeping the unhealthy cause; these bounds never determine receiver health or coverage.
    receivers: (name, record) pairs."""
    gaps = []
    for name, record in receivers:
        if all(item.get("healthy") is True for item in record.get("receiverCoverage", [])):
            continue
        cause = record.get("healthCause")
        if cause == "pollGap":
            seconds, at = record.get("healthPollGapSeconds"), record.get("healthPollGapAt")
            # Check bounds before finite_number: math.isfinite can overflow on a malformed, arbitrarily large integer.
            valid_seconds = isinstance(seconds, (int, float)) and 0 <= seconds <= 86_400 and finite_number(seconds)
            detail = "receiver poll gap" + (f" of {seconds:.1f} s" if valid_seconds else "") + " over the 1.5 s limit"
            if isinstance(at, (int, float)) and 0 <= at < 4_000_000_000 and finite_number(at):
                try:
                    stamp = time.strftime("%H:%M:%S", time.gmtime(at))
                except (OverflowError, OSError, ValueError):
                    pass
                else:
                    detail += " at " + stamp + " GMT"
        elif cause == "startControl":
            detail = "the start control exchange failed"
        elif cause == "endControl":
            detail = "the end control exchange failed"
        else:
            detail = "cause not recorded (no healthCause in the record)"
        gaps.append(f"{name} receiver unhealthy: {detail}; its coverage cannot count")
    return gaps


def evaluate_detection_window(window, record, observations, expectation, result):
    """DEC-028: the bounded window in which a third party has released WGEX's pf protection and the daemon has not yet said
    so. Outside receipts are recorded, never failed; the window fails when it is longer than its bound or when its split
    carries a `shortfall` (insufficient observation or coverage). No send requirement: the window is short by design."""
    tolerance = record.get("clockToleranceSeconds", 0)
    if not finite_number(tolerance) or not 0 <= tolerance <= 2:
        raise ValueError("clock uncertainty")
    received = [item for item in observations if item.get("kind") == "received" and receipt_nonce_matches(item, record)
                and finite_number(item.get("timestamp")) and item.get("scope") != "in_tunnel"
                and window["start"] - tolerance <= item["timestamp"] < window["end"] + tolerance]
    length = window["end"] - window["start"]
    result.update(verdict="unknown", boundSeconds=expectation["maxSeconds"], lengthSeconds=round(length, 3),
                  recordedOutsideObservationCount=len(received), recordedOutsideObservations=received[:100])
    result["expectationMet"] = True
    if length > expectation["maxSeconds"]:
        result["missing"].append(f"detection window {round(length, 3)} s is longer than {expectation['maxSeconds']} s")
        result["expectationMet"] = False
    # The window's own measurement is not enough when the observation around it is: see split_detection_window.
    if window.get("shortfall"):
        result["missing"].append(str(window["shortfall"]))
        result["expectationMet"] = False
    return result


def evaluate_window(window, record, observations, table):
    state = window.get("state", "unknown")
    result = {"state": state, "start": window.get("start"), "end": window.get("end"),
              "verdict": "unknown", "offendingObservations": [], "missing": []}
    if (not finite_number(window.get("start")) or not finite_number(window.get("end"))
            or window["start"] >= window["end"]):
        result["missing"].append("valid time window")
        return result
    expectation = table["states"].get(state)
    if window.get("phase"):
        result["phase"] = window["phase"]
    if expectation and expectation.get("maxSeconds") is not None:
        return evaluate_detection_window(window, record, observations, expectation, result)
    if not expectation or expectation["claim"] == "unknown":
        result["missing"].append("known state expectation")
        return result
    families = window.get("requiredFamilies", ["ipv4", "ipv6"])
    if not families or any(family not in ("ipv4", "ipv6") for family in families):
        result["missing"].append("valid required families")
        return result
    matching = [item for item in observations if item.get("nonce") == record["nonce"]
                and finite_number(item.get("timestamp")) and window["start"] <= item["timestamp"] < window["end"]]
    tolerance = record.get("clockToleranceSeconds", 0)
    if not finite_number(tolerance) or not 0 <= tolerance <= 2:
        raise ValueError("clock uncertainty")
    received = [item for item in observations if item.get("kind") == "received" and receipt_nonce_matches(item, record)
                and finite_number(item.get("timestamp"))
                and window["start"] - tolerance <= item["timestamp"] < window["end"] + tolerance]
    configuration = record["configuration"]
    outside = [item for item in received if item.get("scope") != "in_tunnel"]
    scope = record.get("tunnelScope")
    if state == "protected" and scope and split_tunnel(scope["allowedIPs"]):
        expected_count = sum(underlay_expected(item, record, state) for item in outside)
        result["splitTunnel"] = dict(underlayDestinations=scope["underlayDestinations"], expectedUnderlayObservationCount=expected_count)
        outside = [item for item in outside if not underlay_expected(item, record, state)]
    offending = []
    if expectation["denyOutside"]:
        offending = [item for item in outside if state == "protected" or not lan_exception(item, window, configuration)]
    elif state == "captiveWindow":
        offending = [item for item in outside if not captive_exception(item, configuration)
                     and not lan_exception(item, window, configuration)]
    result["offendingObservations"] = offending
    if offending:
        result["verdict"] = "unprotected"
        result["expectationMet"] = False
        return result
    coverage = receiver_coverage(window, record)
    result["coverage"] = coverage
    if not coverage["complete"]:
        result["missing"].extend(coverage["missing"])
    if record.get("action") == "dns" and state == "protected":
        result["nameserverConfigured"] = bool(re.search(r"(?m)^\s*nameserver\[0\]\s*:\s*10\.77\.0\.1\s*$", record.get("dns", "")))
        result["systemResolverReceiptCount"] = sum(
            item.get("nonce") == record["nonce"] + "-system" and item.get("proto") == "dns"
            and item.get("scope") == "in_tunnel" and item.get("address") == "10.77.0.1"
            and item.get("port") == 53 and target_matches(item, configuration) for item in received)
        if not result["nameserverConfigured"]:
            result["missing"].append("scutil:nameserver[0]:10.77.0.1")
        if not result["systemResolverReceiptCount"]:
            result["missing"].append("received:in_tunnel:dns:system")
    protocols = table["protocols"]
    # Every required family must have LAN probes; protected also needs tunnel probes.
    # A send to one target never substitutes for probes to a different receiver.
    scopes = ["outside_tunnel", "in_tunnel"] if state == "protected" else ["outside_tunnel"]
    for family in families:
        for scope in scopes:
            targets = [target for target in configuration["targets"] if target["scope"] == scope
                       and ("ipv6" if ":" in target["address"] else "ipv4") == family]
            if not targets:
                result["missing"].append(f"target:{scope}:{family}")
            for target in targets:
                for proto in protocols:
                    port_key = {"dns": "dnsPort", "http": "httpPort", "tcp": "httpPort", "udp": "udpPort"}[proto]
                    address = target.get("resolver", target["address"]) if proto == "dns" else target["address"]
                    if not any(probe_attempt(item) and item.get("family") == family and item.get("proto") == proto and item.get("scope") == scope
                               and item.get("address") == address and item.get("port") == target[port_key] for item in matching):
                        result["missing"].append(f"sent:{address}:{target[port_key]}:{proto}")
        required_scope = expectation["require"]
        required_protocols = ["dns", "http"] if required_scope == "captive" else protocols
        if required_scope:
            for proto in required_protocols:
                if not any(item.get("family") == family and item.get("proto") == proto
                           and (item.get("scope") in ("outside_tunnel", "gateway") if required_scope == "captive"
                                else item.get("scope") == required_scope)
                           and target_matches(item, configuration)
                           and (required_scope != "captive" or captive_exception(item, configuration)) for item in received):
                    result["missing"].append(f"received:{required_scope}:{family}:{proto}")
    if not result["missing"]:
        result["verdict"] = expectation["claim"]
        result["expectationMet"] = True
    return result


def evaluate(record, table, receiver_records=()):
    validate_record(record)
    if table.get("schemaVersion") != 1 or set(table.get("protocols", [])) != {"dns", "http", "udp", "tcp"}:
        raise ValueError("expectations schema or protocols")
    record = dict(record)
    record["receiverCoverage"] = []
    observations = [item for item in record["observations"] if item.get("kind") != "received"]
    for receiver in receiver_records:
        validate_record(receiver)
        if receiver["configurationSHA256"] != record["configurationSHA256"]:
            raise ValueError("receiver configuration mismatch")
        observations.extend(receiver["observations"])
        record["receiverCoverage"].extend(receiver.get("receiverCoverage", []))
    results = [evaluate_window(window, record, observations, table) for window in record["windows"]]
    families = sorted(set.intersection(*(set(item.get("requiredFamilies", [])) for item in record["windows"]))) if results and all(item.get("expectationMet") for item in results) else []
    return {"schemaVersion": 1, "nonce": record["nonce"], "states": results, "familiesCovered": families,
            "expectationsMet": bool(results) and all(item.get("expectationMet") is True for item in results)}


# Guest run 8 row checks (M1-10h). Pure: the live driver builds an observation dict from guest output and the dry run
# reads the same dict from Tools/lab/tests/fixtures/rows/<ROW>.json, so both evaluate identical expectations.
STATUS_LINE = re.compile(r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?) status: phase=([a-z]{1,32}) "
                         r"protection=(protected|blocked|unprotected|unknown) reason=([A-Za-z]{1,40})(?: pid=(\d{1,10}))?")
REQUEST_FAILURE = re.compile(r"request failed, type: ([A-Za-z]{1,40}) case: ([A-Za-z]{1,40}) code: (-?\d{1,11})")
# TunnelController+Captive.swift and DaemonFailure.swift: typed captive admission, DNS, routes and pf failures.
CAPTIVE_CODES = range(754, 758)
EN0_RECOVERY_SECONDS = 10
# M1-47 (POWER-WAKE, injected power events): traffic (protected) within 3 s after the wake; the daemon's injected-event log lines lie
# within 5 s of the injector's own instants. Short sleeps hold for [1, 5) s (above 5 s forces a handshake); long holds allow 5%
# slack. Samples in the window have no gap over 5 s; without logged recovery, the first 3 s after wake need gaps at most 1 s.
# A reasserting status line with reason wake counts as the forced handshake for 30 s after the wake line.
POWER_WAKE_SECONDS = 3
POWER_LOG_SLACK_SECONDS = 5
POWER_HOLD_SLACK_FRACTION = 0.05
POWER_SAMPLE_GAP_SECONDS = 5
POWER_RECOVERY_SAMPLE_GAP_SECONDS = 1
POWER_FORCED_LOG_SECONDS = 30
POWER_VARIANTS = {"short": 3, "long": 130}
POWER_LOG_LINE = re.compile(r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?) lab power inject (sleep|wake)(?: pid=(\d{1,10}))?")
CAPTIVE_CLOSE_SLACK_SECONDS = 30
CAPTIVE_END_SECONDS = 15
# M1-10h fix pass 1 (VERIFY F1): only the boot timeline covers boot to SSH return, so without it that interval is unknown.
BOOT_TIMELINE_GAP = "boot timeline unavailable (log show returned no status lines)"
# M1-10q: the Tart vmnet underlay subnet (host and router 192.168.64.1; the daemon's Allow LAN pass is "from <lan> to
# <lan>" on it). REBOOT-LOCKDOWN reports receipts inside it (the LAN case) apart from receipts anywhere else (off-subnet).
UNDERLAY_SUBNET = "192.168.64.0/24"
# ADR-009 documents the early-boot gap; the row records it in bootObservation.earlyBootCapture, never as a pass.
EARLY_BOOT_GAP = ("ADR-009 documented early-boot gap: from kernel boot until the daemon's first enforcing status line pf does "
                  "not hold the policy yet, and no capture covers that interval (the guest en0 capture cannot survive the "
                  "reboot and starts after SSH returns; a host live capture is outside the lab policy), so whatever the guest "
                  "sent then is uncaptured")
NEVER_OPEN_EMPTY = ("empty: the daemon's first blocked status line precedes SSH return, so no post-boot probe can land before "
                    "it; boot to enforcement is the uncaptured early-boot gap (bootObservation.earlyBootCapture)")
# M1-10q fix pass 1 (VERIFY N2): the neverOpen generator starts some seconds after SSH return (run 8e: 21.9 s), so a
# window that ends at or before its first probe (probedFrom) is not empty but still holds no probe.
NEVER_OPEN_UNPROBED = ("unprobed: the window ends at or before the neverOpen generator's first window start (probedFrom), so "
                       "no post-boot probe could land in it")
# M1-10q fix pass 1 (VERIFY N1): why a never-open check measured nothing; the verdict summary line and README say so.
NOT_MEASURED_EMPTY = "not measured (empty window)"
NOT_MEASURED_UNPROBED = "not measured (window ends before the first probe)"
OFF_SUBNET_LIMITATION = ("the lab's only outside receiver is the underlay host 192.168.64.1 (the LAN case); the peer 10.77.0.1 "
                         "is off-subnet but reachable only through a tunnel, which this row never has, so a receipt there is "
                         "outside by construction; off-subnet traffic to any other destination is seen on the wire only "
                         "(unexplainedOutsideFlow)")
# Link-scope and broadcast destinations the lockdown policy may pass with Allow LAN on; never an outside flow.
LINK_SCOPE = [ipaddress.ip_network(value) for value in ("169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32", "fe80::/10", "ff00::/8")]
CAPTURE_HEADER = re.compile(r"(?m)^(\d+\.\d+) (IP6?) (\S+) > (\S+): (.*)$")
OUTSIDE_FLOW_LIMIT = 16


def elapsed_seconds(value):
    """ps etime ([[DD-]HH:]MM:SS) as seconds; None for anything else."""
    match = re.fullmatch(r"(?:(\d{1,3})-)?(?:(\d{1,2}):)?(\d{1,2}):(\d{2})", value or "")
    if not match:
        return None
    days, hours, minutes, seconds = (int(part or 0) for part in match.groups())
    return ((days * 24 + hours) * 60 + minutes) * 60 + seconds


def guest_epoch(stamp, offset):
    """A guest-local log time 'YYYY-MM-DD HH:MM:SS[.fff]' in the guest's UTC offset (+HHMM) as epoch seconds."""
    match = re.fullmatch(r"([+-])(\d\d)(\d\d)", offset or "")
    if not match:
        raise ValueError("guest UTC offset")
    whole, _, fraction = stamp.partition(".")
    seconds = calendar.timegm(time.strptime(whole, "%Y-%m-%d %H:%M:%S"))
    shift = (int(match[2]) * 3600 + int(match[3]) * 60) * (1 if match[1] == "+" else -1)
    return seconds - shift + (float("0." + fraction) if fraction else 0.0)


def status_timeline(lines, offset):
    """Daemon status transitions from sanitised log lines, as [epoch, phase, protection, pid, logIndex], oldest stamp first.

    pid is the logging daemon's pid as the guest script wrote it (M1-10u), None when the line carries none; logIndex is the
    line's position in the log as read (M1-10u fix pass 1): sorting by stamp loses the order the daemon logged in, which is
    the only evidence of a guest clock step after the daemon started (restart_timeline, clockStepped)."""
    timeline = []
    for line in lines:
        match = STATUS_LINE.search(line)
        if match:
            timeline.append([guest_epoch(match[1], offset), match[2], match[3], int(match[5]) if match[5] else None, len(timeline)])
    return sorted(timeline, key=lambda item: item[0])


def parse_boot_observe(text):
    """verdict-actions.sh boot-observe: fixed key=value lines, then sanitised daemon status lines since boot.

    App and daemon start times come from ps etime (1 s resolution) and are recorded as the earliest possible start,
    so an app that may have started before the daemon's first protected status never counts as later.
    """
    head, _, timeline = text.partition("__TIMELINE__\n")
    fields = dict(re.findall(r"(?m)^(now|tz|boot|app|applstart|daemon|daemonstart|daemonpid|runs|appLogLines)=(\S*)$", head))
    if not re.fullmatch(r"\d{9,11}(?:\.\d+)?", fields.get("now", "")) or not re.fullmatch(r"\d{9,11}", fields.get("boot", "")):
        raise ValueError("boot observation format")
    now = float(fields["now"])
    def started(name):
        seconds = elapsed_seconds(fields.get(name))
        return None if seconds is None else now - seconds - 1
    runs = fields.get("runs", "")
    daemon_pid = fields.get("daemonpid", "")
    # M1-10u fix pass 1: ps lstart as an epoch where the guest could parse it (the app's start, beside the etime estimate);
    # daemonstart=unknown is a daemon that ran but whose etime did not parse; statuslinesdropped is the guest filter's count
    # of status lines past its cap (None from an older script).
    app_ps, dropped = fields.get("applstart", ""), re.search(r"(?m)^statuslinesdropped=(\d{1,9})$", timeline)
    # M1-10v fix pass 1 (VERIFY B M1): the count of unified-log lines from the app's own process since the post-restart daemon's
    # start (a count only, never line content); "unknown" (no daemon start, log read failed) and a missing line (an older script)
    # are None, which relaunch_prevented_check never reads as zero.
    app_log = fields.get("appLogLines", "")
    return dict(sampledAt=now, bootAt=int(fields["boot"]), appStartedAt=started("app"), daemonStartedAt=started("daemon"),
                appStartedAtPs=float(app_ps) if re.fullmatch(r"\d{9,11}", app_ps) else None,
                daemonPid=int(daemon_pid) if re.fullmatch(r"[1-9]\d{0,9}", daemon_pid) else None,
                daemonStartUnknown=fields.get("daemonstart") == "unknown",
                statusLinesDropped=int(dropped[1]) if dropped else None,
                appRunning=fields.get("app") not in (None, "", "none"), daemonRuns=int(runs) if runs.isdigit() else None,
                appLogLines=int(app_log) if re.fullmatch(r"\d{1,9}", app_log) else None,
                timeline=status_timeline(timeline.splitlines(), fields.get("tz")))


RELAUNCH_MECHANISM = "loginwindow-reopen-state"


def parse_relaunch_prevention(text):
    """verdict-actions.sh prevent-relaunch: fixed key=value lines (M1-10v). applied is true only when the guest names the mechanism
    this verdict knows, the console user is the SSH user (usermatch=yes), both loginwindow keys read back as written, the saved
    relaunch list holds no entry and the app was not running; anything else (a missing line, an unconfirmed key, another mechanism
    name, a refused user match) is not applied. Fix pass 1: a key printed twice is refused (duplicateKeys names it, applied false),
    never resolved by taking the last or the first value; relaunchlistbefore and relaunchlistwgex are the saved list's state before
    the delete (a count and yes|no, nothing else), recorded so the first live run shows whether the snapshot's list held WGEX."""
    keys = ("mechanism", "usermatch", "savesstate", "relaunchapps", "relaunchlist", "relaunchlistbefore", "relaunchlistwgex", "app")
    found = re.findall(r"(?m)^(" + "|".join(keys) + r")=(\S*)$", text or "")
    duplicates = sorted({key for key in (key for key, _ in found) if [name for name, _ in found].count(key) > 1})
    fields = {}
    for key, value in found:
        fields.setdefault(key, value)
    flags = {"false": False, "true": True}
    saves, relaunch = flags.get(fields.get("savesstate")), flags.get(fields.get("relaunchapps"))
    def number(key):
        return int(fields[key]) if re.fullmatch(r"\d{1,6}", fields.get(key, "")) else None
    count, before = number("relaunchlist"), number("relaunchlistbefore")
    user = {"yes": True, "no": False}.get(fields.get("usermatch"))
    listed = {"yes": True, "no": False}.get(fields.get("relaunchlistwgex"))
    mechanism = RELAUNCH_MECHANISM if fields.get("mechanism") == RELAUNCH_MECHANISM else ""
    return dict(mechanism=mechanism, userMatch=user, savesLogoutState=saves, relaunchesApps=relaunch, savedRelaunchEntries=count,
                savedRelaunchEntriesBefore=before, savedListHeldWGEX=listed, duplicateKeys=duplicates,
                applied=bool(mechanism) and user is True and saves is False and relaunch is False and count == 0 and fields.get("app") == "none"
                and not duplicates)


def parse_en0(text):
    """verdict-actions.sh en0-collect: link down/up epochs and the guest-side samples taken every 0.25 s."""
    times = dict((kind, float(value)) for kind, value in re.findall(r"(?m)^(down|up) (\d{9,11}\.\d+)$", text))
    samples = []
    for match in re.finditer(r"(?m)^(\d{9,11}\.\d+) refs=(\d{1,3}) (.*)$", text):
        try:
            status = json.loads(match[3])
            phase, protection = status.get("phase"), status.get("protection")
        except ValueError:
            phase, protection = "unavailable", "unknown"
        samples.append([float(match[1]), phase if isinstance(phase, str) else "unavailable",
                        protection if isinstance(protection, str) else "unknown", int(match[2])])
    return dict(down=times.get("down"), up=times.get("up"), samples=samples)


def parse_power(text):
    """verdict-actions.sh power-collect (M1-47): the UTC offset and the injector's own sleep and wake instants, then the daemon's
    injected-event log lines (`lab power inject sleep|wake`), its status lines, then the guest-side samples every 0.25 s.

    Only whole lines of the fixed vocabulary are kept; a line with any other text, or any line when the offset is missing or
    unreadable, is dropped, so a check that needs it fails closed instead of reading a guess."""
    head, _, rest = text.partition("__LOG__\n")
    log, _, rest = rest.partition("__STATUS__\n")
    status, _, samples = rest.partition("__SAMPLES__\n")
    times = dict((kind, float(value)) for kind, value in re.findall(r"(?m)^(sleep|wake) (\d{9,11}\.\d+)$", head))
    offset = re.search(r"(?m)^tz=([+-]\d{4})$", head)
    injected, daemon_status = [], []
    try:
        for line in log.splitlines():
            match = POWER_LOG_LINE.fullmatch(line.strip())
            if match and offset:
                injected.append([guest_epoch(match[1], offset[1]), match[2], int(match[3]) if match[3] else None])
        for line in status.splitlines():
            match = STATUS_LINE.fullmatch(line.strip())
            if match and offset:
                daemon_status.append([guest_epoch(match[1], offset[1]), match[2], match[3], match[4], int(match[5]) if match[5] else None])
    except ValueError:
        injected, daemon_status = [], []
    dropped = re.search(r"(?m)^statuslinesdropped=(\d{1,9})$", status)
    return dict(sleepAt=times.get("sleep"), wakeAt=times.get("wake"), injected=injected, daemonStatus=daemon_status,
                statusLinesDropped=int(dropped[1]) if dropped else None,
                samples=parse_en0(samples)["samples"])


def captive_passes(rules):
    """Captive TCP 80/443 pass rules in a `pfctl -a com.apple/wgex -sr` read-back (numeric or service-name ports)."""
    counts = {"port80": 0, "port443": 0}
    for line in rules.splitlines():
        if not line.startswith("pass") or "proto tcp" not in line:
            continue
        if re.search(r"\bport (?:= )?(?:80|http|www)\b", line):
            counts["port80"] += 1
        if re.search(r"\bport (?:= )?(?:443|https)\b", line):
            counts["port443"] += 1
    return counts


def request_failures(lines):
    """Typed request failures from the sanitised daemon stream: [type, case, code]."""
    return [[match[1], match[2], int(match[3])] for line in lines if (match := REQUEST_FAILURE.search(line))]


def _check(name, met, **detail):
    return dict(name=name, met=bool(met), **detail)


def _status_is(status, phase, protection):
    return isinstance(status, dict) and status.get("phase") == phase and status.get("protection") == protection


RESTART_FILTER = ("status lines of the post-restart daemon only: its pid, and never earlier than that daemon's start (ps etime); "
                  "kern.boottime does not window the timeline")
# M1-10u fix pass 1: the guest's own clock against the host's. A guest sample may sit this far outside [host call start, host call
# return] + the measured offset beyond the offset's own uncertainty; clock_measurement bounds that uncertainty at 2 s.
CLOCK_DRIFT_SLACK_SECONDS = 0.5
CLOCK_UNCERTAINTY_BOUND_SECONDS = 2.0
CLOCK_NOT_MEASURED = "clock drift not measured"
ATTEMPT_STEPS = ("preparing", "configuring")


def _pid(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def _line_pid(item):
    return _pid(item[3]) if len(item) > 3 else None


def _log_index(item):
    return item[4] if len(item) > 4 and isinstance(item[4], int) and not isinstance(item[4], bool) else None


def clock_drift(boot):
    """(observation, diagnostics): the guest clock against host time plus the measured offset, at each boot-observe sample.

    The driver records the host time before and after each sample's guest call and the offset measured beside it
    (boot["clockSamples"]). The guest's sampledAt must lie within [call start, call return] + offset, give or take the
    offset's uncertainty plus CLOCK_DRIFT_SLACK_SECONDS; the offset must not change between samples either. A stored capture
    without these stamps says "clock drift not measured" and is never a silent pass on it."""
    fields = ("sampledAt", "hostStartedAt", "hostReturnedAt", "offsetSeconds", "uncertaintySeconds")
    raw = [item for item in boot.get("clockSamples") or [] if isinstance(item, dict)]
    samples = [item for item in raw if all(finite_number(item.get(name)) for name in fields)]
    if not samples:
        return dict(measured=False, note=CLOCK_NOT_MEASURED), []
    diagnostics, drifts = [], []
    for item in samples:
        low, high = item["hostStartedAt"] + item["offsetSeconds"], item["hostReturnedAt"] + item["offsetSeconds"]
        drift = max(low - item["sampledAt"], item["sampledAt"] - high, 0.0)
        drifts.append(round(drift, 3))
        limit = item["uncertaintySeconds"] + CLOCK_DRIFT_SLACK_SECONDS
        if drift > limit:
            diagnostics.append(["clockDrift", f"the guest's sample time {item['sampledAt']} is {round(drift, 3)} s outside host time plus the measured "
                                f"offset ({round(low, 3)} to {round(high, 3)}), more than its uncertainty plus {CLOCK_DRIFT_SLACK_SECONDS} s ({round(limit, 3)} s): "
                                "the guest clock stepped or the offset is wrong"])
    offsets = [item["offsetSeconds"] for item in samples]
    spread = max(offsets) - min(offsets)
    allowed = 2 * max(item["uncertaintySeconds"] for item in samples) + CLOCK_DRIFT_SLACK_SECONDS
    if len(samples) > 1 and spread > allowed:
        diagnostics.append(["clockDrift", f"the guest clock offset changed by {round(spread, 3)} s between the boot samples (allowed {round(allowed, 3)} s): "
                            "the guest clock stepped during the boot phase"])
    observation = dict(measured=True, samples=len(samples), maxDriftSeconds=max(drifts), offsetSpreadSeconds=round(spread, 3))
    if len(samples) < len(raw):
        observation["note"] = f"{len(raw) - len(samples)} sample(s) carry no usable host stamps"
    return observation, diagnostics


def restart_timeline(boot):
    """M1-10u (run 8g BOOT-SECRETS false PASS): the status lines a verdict may count after a daemon restart (reboot or kill).

    The guest's status read starts before kern.boottime and returns the previous daemon's shutdown lines whenever the guest
    dates boot before them (run 8g: pid 282's last "active/protected" line sat 16.6 s before the new daemon started), so a
    timeline is never windowed by boot time. A line counts only when it comes from the post-restart daemon: its pid
    (boot["daemonPid"], the oldest live WGEXDaemon after the restart) where the line carries one, and its time is at or
    after that daemon's start (boot["daemonStartedAt"], earliest possible start from ps etime). Everything else is excluded
    and counted. Lines without a pid count by time alone only where no pid is on record (stored captures).

    Returns lines (the counted ones, oldest first), excluded (every other line), pids (every pid seen), observations and
    diagnostics, each [name, detail], that fail the row. M1-10u: postRestartDaemonUnidentified (lines read, neither start nor
    pid read), noPostRestartStatusLine (lines read, none from the post-restart daemon; an empty log read stays the existing
    unknown, BOOT_TIMELINE_GAP), pidSetContradictsRestart (another pid logs at or after the post-restart daemon's start, the
    post-restart pid never logs a status line, or the daemon pid changed between boot samples),
    postRestartLineBeforeDaemonStart (the post-restart pid logs earlier than its own start: a stepped guest clock, an etime
    error or a reused pid; the pid cannot tell these apart, so the row fails closed) and firstProtectedBeforeDaemonStart.
    Fix pass 1 (VERIFY A L2, L3, B M1-M3, L1a): clockStepped (one pid's lines are not monotonic in log order versus their
    stamps), clockDrift (the guest's sample time against host time plus offset, clock_drift), activeBeforeAttemptSteps (a
    preparing or configuring line directly after an active/protected one of the same pid that the log order does not confirm
    (M1-10v: an explicit restart from active is legitimate when logged in that order); the check that still works on stored
    captures, which lost the log order), postRestartLineUnattributed (the daemon pid
    is known and a line carries none; there is no opt-out, M1-10v), postRestartDaemonReplaced (an excluded pid other than the recorded pre-restart daemon,
    boot["preRestartDaemonPid"], with a line dated at or after that daemon's last line (M1-10v); with that pid not recorded, more than one excluded pid), postRestartDaemonStartUnknown (a daemon
    ran but its start time did not parse, so no line can be judged by time) and statusLinesDropped (the guest filter dropped
    status lines past its cap).
    """
    raw = [list(item) for item in boot.get("timeline") or [] if isinstance(item, (list, tuple)) and len(item) >= 3 and finite_number(item[0])]
    start = boot.get("daemonStartedAt") if finite_number(boot.get("daemonStartedAt")) else None
    pid = _pid(boot.get("daemonPid"))
    before = _pid(boot.get("preRestartDaemonPid"))
    start_unknown = start is None and (pid is not None or boot.get("daemonStartUnknown") is True)
    identified = start is not None or pid is not None
    lines, excluded = [], []
    for item in raw:
        line_pid = _line_pid(item)
        foreign = pid is not None and line_pid is not None and line_pid != pid
        early = start is not None and item[0] < start
        (excluded if foreign or early or not identified else lines).append(item)
    unattributed = [item for item in raw if pid is not None and _line_pid(item) is None]
    tagged = [(item, _line_pid(item)) for item in raw if _line_pid(item)]
    pids = sorted({line_pid for _, line_pid in tagged})
    diagnostics = []
    # An empty log read is the existing unknown (BOOT_TIMELINE_GAP, timelineAvailable false, which fails
    # neverUnprotectedAfterBoot); lines that were read but cannot be attributed to the post-restart daemon are a failure.
    if raw and not identified and not start_unknown:
        diagnostics.append(["postRestartDaemonUnidentified", "neither the post-restart daemon's start time nor its pid was read, so no line can be attributed to it"])
    if start_unknown:
        diagnostics.append(["postRestartDaemonStartUnknown", "a daemon is running but its start time (ps etime) did not parse"
                            + (f" (pid {pid})" if pid is not None else "") + ", so no status line can be judged by time"])
    if raw and not lines:
        diagnostics.append(["noPostRestartStatusLine", f"no status line from the post-restart daemon on record ({len(raw)} line(s) read, all excluded)"])
    after = {line_pid for item, line_pid in tagged if start is None or item[0] >= start}
    others = [] if start_unknown else sorted(after - {pid}) if pid is not None else (sorted(after) if len(after) > 1 else [])
    if others:
        diagnostics.append(["pidSetContradictsRestart", f"pid(s) {others} log at or after the start of the post-restart daemon"
                            + (f" (pid {pid})" if pid is not None else "") + ": more than one daemon since the restart"])
    if pid is not None and tagged and pid not in pids:
        diagnostics.append(["pidSetContradictsRestart", f"the post-restart daemon (pid {pid}) logged no status line; the timeline carries pid(s) {pids}"])
    sampled = sorted({_pid(value) for value in boot.get("daemonPidSamples") or [] if _pid(value)})
    if len(sampled) > 1:
        diagnostics.append(["pidSetContradictsRestart", f"the daemon pid changed between boot samples {sampled}: the daemon restarted again"])
    if unattributed:
        diagnostics.append(["postRestartLineUnattributed", f"{len(unattributed)} of {len(raw)} status line(s) carry no pid although the post-restart "
                            f"daemon's pid ({pid}) is on record ({sum(item in lines for item in unattributed)} of them counted): every line must be attributable to a daemon"])
    excluded_pids = sorted({_line_pid(item) for item in excluded if _line_pid(item)})
    # M1-10v (FIX1-VERIFY N-1): with the pre-restart pid recorded, another excluded pid is a replacement only when one of its lines is
    # dated at or after the last line of that pid (install mode kickstarts the daemon, so the snapshot daemon's lines precede the
    # installed one's and both precede the restart). The recorded pid logging nothing leaves no baseline: every other excluded pid
    # counts. With the pid unrecorded, two excluded daemons cannot be told apart (the snapshot daemon then the installed one looks
    # exactly like the pre-restart daemon then a replacement), so more than one excluded pid still fails closed.
    # Fix pass 1 (VERIFY B L3, L4): a line dated exactly at the recorded pid's last stamp is not "before" it, so it counts (>=, fail
    # closed; the stamps carry milliseconds, so a genuine snapshot daemon never ties). The relaxation leans on noRestartLoop and on
    # a readable launchd runs count: the run 8g early-boot clock dates a post-restart daemon's first lines 9-10 s before the
    # pre-reboot daemon's last line, which this rule no longer names, so a second launchd start (runs 2) or an unread runs count
    # (daemonRuns None) is what still fails the row (noRestartLoop is met only with daemonRuns == 1).
    last_line = {}
    for item in raw:
        if _line_pid(item):
            last_line[_line_pid(item)] = max(last_line.get(_line_pid(item), item[0]), item[0])
    if not identified:
        replaced = []
    elif before is not None:
        replaced = [value for value in excluded_pids if value not in (before, pid) and (before not in last_line or last_line[value] >= last_line[before])]
    else:
        replaced = excluded_pids if len(excluded_pids) > 1 else []
    if replaced:
        diagnostics.append(["postRestartDaemonReplaced", f"status lines from pid(s) {replaced} were excluded as pre-restart, but "
                            + (f"the recorded pre-restart daemon was pid {before} and they are dated at or after its last line" if before is not None
                               else "the pre-restart daemon pid was not recorded and more than one pid was excluded")
                            + ": a daemon other than the post-restart one ran after the restart (crash loop or relaunch)"])
    mine = [item for item, line_pid in tagged if line_pid == pid] if pid is not None else []
    early_mine = [item[0] for item in mine if start is not None and item[0] < start]
    if early_mine:
        diagnostics.append(["postRestartLineBeforeDaemonStart", f"{len(early_mine)} line(s) of pid {pid} are dated before that daemon's start ({start}), "
                            f"earliest {min(early_mine)}: stepped guest clock, start-time error or reused pid"])
    protected = [item[0] for item in mine if item[2] == "protected"] + [item[0] for item in boot.get("statusSamples") or []
                                                                         if len(item) > 2 and item[2] == "protected" and finite_number(item[0])]
    early_protected = [value for value in protected if start is not None and value < start]
    if early_protected:
        diagnostics.append(["firstProtectedBeforeDaemonStart", f"first protected status {min(early_protected)} is earlier than the post-restart "
                            f"daemon's start {start}: impossible for one daemon"])
    # A step of the guest clock after the daemon started shows as the daemon's own lines going backwards in the order it logged
    # them (the pid-less group too, where it is evaluated); the log order is lost in stored captures (logOrderRecorded false).
    groups = {}
    for item in raw:
        if _log_index(item) is not None:
            groups.setdefault(_line_pid(item), []).append(item)
    stepped = []
    for key in ([pid, None] if pid is not None else list(groups)):
        ordered = sorted(groups.get(key, []), key=_log_index)
        stepped += [(key, earlier[0] - later[0], later[0]) for earlier, later in zip(ordered, ordered[1:]) if later[0] < earlier[0]]
    if stepped:
        key, size, stamp = max(stepped, key=lambda value: value[1])
        diagnostics.append(["clockStepped", f"{len(stepped)} status line(s) of {'pid ' + str(key) if key else 'the pid-less lines'} are dated earlier than the line logged "
                            f"before them (largest step back {round(size, 3)} s, at {stamp}): the guest clock stepped after the daemon started"])
    # M1-10v (FIX1-VERIFY N-5): an explicit start while active goes straight from active/protected to the next attempt's preparing
    # (Lifecycle.swift:38-39, :106), so that order is legitimate. It is flagged only when the log order contradicts the stamps (the
    # attempt line was logged before the active line the stamps place first: a stepped clock) or is absent (a stored capture cannot
    # tell the two apart, so it still fails closed).
    last, flagged = {}, []
    for item in lines:
        key = _line_pid(item)
        if item[1] in ATTEMPT_STEPS and last.get(key) is not None and last[key][1] == "active" and last[key][2] == "protected":
            earlier, later = _log_index(last[key]), _log_index(item)
            if earlier is None or later is None or later < earlier:
                flagged.append((item[1], item[0], last[key][0]))
        last[key] = item
    if flagged:
        name, stamp, protected_at = flagged[0]
        diagnostics.append(["activeBeforeAttemptSteps", f"an active/protected status ({protected_at}) is directly followed by {name} ({stamp}) of the same daemon: "
                            "an impossible order within one attempt, so a stamp is wrong (stepped guest clock)"])
    drift, drift_diagnostics = clock_drift(boot)
    diagnostics += drift_diagnostics
    dropped = boot.get("statusLinesDropped")
    if isinstance(dropped, int) and not isinstance(dropped, bool) and dropped > 0:
        diagnostics.append(["statusLinesDropped", f"the guest filter dropped {dropped} status line(s) past its cap: the post-restart timeline is incomplete"])
    observations = dict(excludedPreRestartStatusLines=len(excluded), excludedPids=excluded_pids, samePidLinesBeforeStart=len(early_mine),
                        postRestartDaemonPid=pid, preRestartDaemonPid=before, postRestartDaemonStartedAt=start, countedStatusLines=len(lines),
                        unattributedStatusLines=len(unattributed), logOrderRecorded=bool(groups), clockDrift=drift,
                        statusLinesDropped=dropped if isinstance(dropped, int) and not isinstance(dropped, bool) else None, filter=RESTART_FILTER)
    return dict(lines=lines, excluded=excluded, pids=pids, diagnostics=diagnostics, observations=observations)


def boot_timeline_available(boot):
    """The post-restart daemon's status lines since boot are on record and start no later than the first driver poll (VERIFY F1)."""
    timeline, polls = restart_timeline(boot)["lines"], boot.get("statusSamples") or []
    return bool(timeline) and (not polls or min(item[0] for item in timeline) <= min(item[0] for item in polls))


def poll_clock_margin(boot):
    """The largest clock uncertainty on record for driver polls plus the drift slack; the bound clock_measurement allows when none
    was recorded (stored captures). Driver polls are stamped host time + offset, so they only count as protected before the app
    started when they precede it by this much (VERIFY B N1: fix 1(b) detects steps, it does not bound the offset error)."""
    uncertainties = [item["uncertaintySeconds"] for item in boot.get("clockSamples") or [] if isinstance(item, dict) and finite_number(item.get("uncertaintySeconds"))]
    return (max(uncertainties) if uncertainties else CLOCK_UNCERTAINTY_BOUND_SECONDS) + CLOCK_DRIFT_SLACK_SECONDS


def boot_report(boot):
    """REBOOT-INTENT, REBOOT-LOCKDOWN and BOOT-SECRETS: was the app running after boot, and when was protection restored.

    Only the post-restart daemon's status lines count (restart_timeline, M1-10u), plus the driver's own polls, which count as
    protected before the app only by poll_clock_margin; the first protected status is never the previous daemon's.
    protectedBeforeAppSeen is timing only (M1-10u fix pass 1, VERIFY B M4): true when that protected status precedes the earliest
    possible app start (or no app process was seen), false when an app process may have been seen first, None when no protected
    status is on record, the app sample is unreadable or the post-restart timeline is inconsistent (postRestartTimelineConsistent
    false, diagnostics named); without the boot timeline an earlier protected status cannot be excluded, so false becomes None.
    A false value carries protectedOnlyAfterAppSeen with both times and the delta. daemonDrivenReconnect is causal and is None
    ("not measured") unless the capture carries appMutatingRequestBeforeFirstProtected (no driver records it yet).
    """
    view = restart_timeline(boot)
    polls = [item[0] for item in boot.get("statusSamples") or [] if len(item) > 2 and item[2] == "protected" and finite_number(item[0])]
    lines = [item[0] for item in view["lines"] if item[2] == "protected"]
    margin = poll_clock_margin(boot)
    first = min(lines + polls, default=None)
    decisive = min(lines + [value + margin for value in polls], default=None)
    app = boot.get("appStartedAt")
    running = boot.get("appRunningAfterBoot")
    timeline = boot_timeline_available(boot)
    # None (no readable post-boot process sample) is unknown, never "no app".
    before = None if decisive is None or running is None else (running is False or (app is not None and decisive < app))
    consistent = not view["diagnostics"]
    signal = boot.get("appMutatingRequestBeforeFirstProtected")
    caused = isinstance(signal, bool) and consistent and first is not None
    report = dict(appRunningAfterBoot=running, appStartedAt=app, daemonStartedAt=boot.get("daemonStartedAt"),
                  firstProtectedAt=first, protectedBeforeAppSeen=(before if timeline or before else None) if consistent else None,
                  daemonDrivenReconnect=(not signal) if caused else None,
                  daemonDrivenReconnectBasis=("the capture records whether the app sent a mutating request before the first protected status" if caused
                                              else "not measured: no capture field records whether the app sent a mutating request (M1-24 E6), so timing alone does not show who restored protection"),
                  timelineAvailable=timeline, postRestartTimelineConsistent=consistent, noRestartLoop=boot.get("daemonRuns") == 1,
                  postRestartTimeline=dict(view["observations"], diagnostics=[name for name, _ in view["diagnostics"]]),
                  timelineSource="post-restart daemon status lines since boot (/usr/bin/log show) plus driver status polls",
                  earlyBootCapture=early_boot_capture(boot))
    if decisive is not None and running and app is not None and decisive >= app and consistent:
        value = dict(firstProtectedAt=first, appStartedAt=app, appStartedAtSource="earliest possible start (ps etime, minus 1 s)",
                     deltaSeconds=round(decisive - app, 3))
        ps = boot.get("appStartedAtPs")
        if finite_number(ps):
            value.update(appStartedAtPsLstart=ps, deltaSecondsVsPsLstart=round(decisive - ps, 3))
        if decisive != first:
            value["pollClockMarginSeconds"] = margin
        report["protectedOnlyAfterAppSeen"] = value
    if not timeline:
        report["gap"] = BOOT_TIMELINE_GAP
    return report


def early_boot_capture(boot):
    """M1-10q: the interval no capture covers, stated in the verdict: kernel boot (kern.boottime) to the post-restart daemon's
    first enforcing (blocked or protected) status line, and to the post-boot en0 capture start. Never a pass criterion."""
    enforcing = [item[0] for item in restart_timeline(boot)["lines"] if item[2] in ("blocked", "protected")]
    start, first = boot.get("bootAt"), min(enforcing) if enforcing else None
    capture = (boot.get("neverOpenWindow") or {}).get("postBootCaptureAt")
    def seconds(end):
        return round(end - start, 3) if finite_number(start) and finite_number(end) else None
    return dict(captured=False, bootAt=start, firstEnforcingStatusAt=first, postBootCaptureAt=capture,
                unenforcedSeconds=seconds(first), uncapturedSeconds=seconds(capture), gap=EARLY_BOOT_GAP)


def never_open_window(start, driver_poll_at, timeline, strict, probed_from=None):
    """M1-10q: the never-open window [SSH return, end). strict (REBOOT-LOCKDOWN) ends it at the daemon's first blocked status
    line from the boot timeline; otherwise, or without such a line, at the driver's first poll as before. Both instants and
    the daemon's first status line of any kind are recorded; an end before the start is an empty window, said so.
    The timeline is the post-restart daemon's (restart_timeline, M1-10u), never the raw log since boot.
    Fix pass 1 (VERIFY N1, N2): probed_from, the generator's first window start, is recorded as probedFrom, and the window
    carries measured (never_open_measured): false when it is empty or ends at or before probedFrom."""
    first_status = min((item[0] for item in timeline or []), default=None)
    first_blocked = min((item[0] for item in timeline or [] if item[2] == "blocked"), default=None)
    end, source = (first_blocked, "daemonFirstBlockedStatus") if strict and first_blocked is not None else (driver_poll_at, "driverFirstPoll")
    window = dict(start=start, end=end, endSource=source, sshReturnAt=start, driverFirstPollAt=driver_poll_at,
                  daemonFirstStatusAt=first_status, daemonFirstBlockedAt=first_blocked, windowSeconds=round(max(0.0, end - start), 3))
    window["probedFrom"] = probed_from
    # M1-10u: measured, not assumed: samples inside the window whose protection was unknown or whose phase had failed
    # (run 8g: failed/unknown for 1.5 s while the daemon retried). Never counted as protected, never a failure by themselves.
    inside = [item for item in timeline or [] if start <= item[0] < end]
    window.update(unknownProtectionSamples=sum(item[2] == "unknown" for item in inside), failedPhaseSamples=sum(item[1] == "failed" for item in inside))
    if end <= start:
        window["note"] = NEVER_OPEN_EMPTY
    elif finite_number(probed_from) and end <= probed_from:
        window["note"] = NEVER_OPEN_UNPROBED
    measured, reason = never_open_measured(window)
    window.update(measured=measured, **({"notMeasured": reason} if reason else {}))
    return window


def never_open_measured(window):
    """(measured, reason) for a never-open window, from its own bounds, never from a stored flag: an end at or before the
    start (empty, VERIFY N1) or at or before probedFrom (no probe could land, VERIFY N2) measured nothing."""
    start, end, probed = window.get("start"), window.get("end"), window.get("probedFrom")
    if not (finite_number(start) and finite_number(end)) or end <= start:
        return False, NOT_MEASURED_EMPTY
    if finite_number(probed) and end <= probed:
        return False, NOT_MEASURED_UNPROBED
    return True, None


def checks_not_measured(checks):
    """M1-10q fix pass 1 (VERIFY N1): the checks that measured nothing (measured false). Their met stays true only beside
    that flag; they are neither a pass nor a fail, so the row's PASS rests on its measured checks alone, and the verdict
    summary line and README name them with the reason."""
    return [dict(name=check.get("name"), reason=check.get("notMeasured") or "not measured") for check in checks or []
            if isinstance(check, dict) and check.get("measured") is False]


def check_counts(checks):
    """Measured checks met and failed, and the unmeasured ones, which are never counted as met (VERIFY N1)."""
    checks = [check for check in checks or [] if isinstance(check, dict)]
    return dict(met=sum(check.get("met") is True and check.get("measured") is not False for check in checks),
                failed=sum(check.get("met") is not True for check in checks),
                notMeasured=sum(check.get("met") is True and check.get("measured") is False for check in checks))


def in_underlay_subnet(address):
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(UNDERLAY_SUBNET)
    except ValueError:
        return False


def outside_flows(text):
    """Header-only tcpdump lines (-nn -tt, no payload) as flows to destinations outside the underlay subnet and outside
    link-local, multicast and broadcast; nothing else of the line is kept."""
    flows = []
    for stamp, family, source, destination, rest in CAPTURE_HEADER.findall(text):
        # tcpdump -nn writes address.port, or the bare address for ICMP and fragments.
        address, port = destination, None
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            address, _, port = destination.rpartition(".")
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                continue
            port = port if port.isdigit() else None
        if in_underlay_subnet(address) or any(ip.version == net.version and ip in net for net in LINK_SCOPE):
            continue
        flags = re.search(r"Flags \[([^\]]{1,8})\]", rest)
        proto = "tcp" if flags else "icmp" if "ICMP" in rest else "udp" if port else "other"
        flows.append(dict(timestamp=float(stamp), family="ipv6" if family == "IP6" else "ipv4", source=source.rpartition(".")[0] or source,
                          destination=address, port=int(port) if port else None, proto=proto, tcpFlags=flags[1] if flags else None))
    return flows


def pass_rule_for(flow, rules):
    """The first outbound-capable pf pass rule that could match the flow (to any, a table, or a network holding the
    destination, with a compatible proto and port), or None. Conservative: an unparsable target counts as a match."""
    for line in (rules or "").splitlines():
        line = line.strip()
        if not line.startswith("pass") or re.match(r"pass\s+in\b", line):
            continue
        interface = re.search(r"\bon (\S+)", line)
        if interface and interface[1] != "en0":
            continue
        proto = re.search(r"\bproto (\S+)", line)
        if proto and proto[1] != flow["proto"]:
            continue
        family = re.search(r"\b(inet6?)\b", line)
        if family and (family[1] == "inet6") != (flow["family"] == "ipv6"):
            continue
        target = re.search(r"\bto (!?\S+)(?: port (?:= )?(\d+))?", line)
        if not target:
            return line
        if target[2] and flow["port"] is not None and int(target[2]) != flow["port"]:
            continue
        value = target[1]
        try:
            if value != "any" and not value.startswith("!") and ipaddress.ip_address(flow["destination"]) not in ipaddress.ip_network(value, strict=False):
                continue
        except ValueError:
            pass
        return line
    return None


def unexplained_outside_flow(text, rules, first_enforcing_at=None):
    """M1-10q named observation, not a pass criterion: outside flows on en0 in the post-boot capture, taken with lockdown
    on, that no pass rule of the after-boot ruleset could match (run 8e: one TCP ACK to 17.188.182.132:443). Fix pass 1
    (VERIFY N3): each flow carries beforeFirstEnforcing, true when its timestamp precedes the daemon's first enforcing
    status line (earlyBootCapture.firstEnforcingStatusAt, guest clock like the capture), when pf was not enforcing yet
    rather than passing it; None when that instant is unknown."""
    flows = outside_flows(text)
    for flow in flows:
        flow["beforeFirstEnforcing"] = flow["timestamp"] < first_enforcing_at if finite_number(first_enforcing_at) else None
    unexplained = [flow for flow in flows if pass_rule_for(flow, rules) is None]
    return dict(inspected=True, observed=bool(unexplained), outsideFlowCount=len(flows), unexplainedCount=len(unexplained),
                unexplainedBeforeFirstEnforcingCount=sum(flow["beforeFirstEnforcing"] is True for flow in unexplained),
                firstEnforcingStatusAt=first_enforcing_at, flows=unexplained[:OUTSIDE_FLOW_LIMIT],
                source="post-boot en0 capture headers, lockdown on; after-boot pf rules",
                note="named observation for the next run; not a pass criterion")


def timeline_consistency_check(boot):
    """M1-10u: the post-restart timeline is consistent (restart_timeline names no diagnostic); each failure is named with
    its detail and carries a gap, so it is never a pass. The excluded pre-restart lines are an observation, not a failure."""
    view = restart_timeline(boot)
    detail = dict(view["observations"], diagnostics=[dict(name=name, detail=text) for name, text in view["diagnostics"]])
    if view["diagnostics"]:
        detail["gap"] = "postRestartTimelineInconsistent: " + "; ".join(f"{name}: {text}" for name, text in view["diagnostics"])
    return _check("postRestartTimelineConsistent", not view["diagnostics"], **detail)


def _boot_common(boot):
    view = restart_timeline(boot)
    samples = view["lines"] + (boot.get("statusSamples") or [])
    # Boot to SSH return is covered only by the timeline; driver polls alone never make that interval a pass (VERIFY F1).
    timeline = boot_timeline_available(boot)
    # README: neverUnprotectedAfterBoot fails on any sample whose protection is `unprotected`. A sample whose protection is
    # `unknown` (idle/unknown at daemon start, failed/unknown while it retries) is neither protected nor unprotected: it is
    # never counted as protected and is measured here as an observation (M1-10u, run 8g: 1.5 s of failed/unknown).
    unprotected = dict(statusCount=len(samples), unprotectedCount=sum(item[2] == "unprotected" for item in samples),
                       unknownProtectionCount=sum(item[2] == "unknown" for item in samples),
                       failedPhaseCount=sum(item[1] == "failed" for item in samples),
                       timelineLines=len(view["lines"]), excludedPreRestartStatusLines=len(view["excluded"]))
    if not timeline:
        unprotected["gap"] = BOOT_TIMELINE_GAP
    # M1-10q fix pass 1 (VERIFY N1, N2): a window that measured nothing says so on the check (measured false, notMeasured);
    # met stays true only beside that flag, and the row never counts it as a pass (checks_not_measured, check_counts).
    window = boot.get("neverOpenWindow")
    measured = {}
    if isinstance(window, dict):
        value, reason = never_open_measured(window)
        measured = dict(measured=value, **({"notMeasured": reason} if reason else {}), window=window)
    return [
        timeline_consistency_check(boot),
        _check("oneReferenceAfterBoot", boot.get("referenceCount") == 1, referenceCount=boot.get("referenceCount")),
        _check("zeroReceiptsBeforeFirstStatus", boot.get("outsideReceiptsBeforeFirstStatus") == 0,
               receiptCount=boot.get("outsideReceiptsBeforeFirstStatus"), **measured),
        _check("neverUnprotectedAfterBoot", timeline and all(item[2] != "unprotected" for item in samples), **unprotected),
        _check("noRestartLoop", boot.get("daemonRuns") == 1, daemonRuns=boot.get("daemonRuns")),
    ]


def reboot_lockdown_checks(observation):
    """M1-10q: the strict case. Allow LAN is off before the reboot, so the underlay subnet (192.168.64.1) must stay dark
    after boot; receipts there (the LAN case) and anywhere else (off-subnet) are counted apart over the post-boot probe
    window [SSH return, driver's first poll), by the row's own nonce."""
    boot = observation["boot"]
    after = dict(subnet=UNDERLAY_SUBNET, window=[(boot.get("neverOpenWindow") or {}).get(key) for key in ("sshReturnAt", "driverFirstPollAt")])
    return [_check("lockdownReachedDaemon", observation.get("lockdownBeforeReboot") is True
                   and _status_is(observation.get("statusBeforeReboot"), "idle", "blocked"),
                   lockdown=observation.get("lockdownBeforeReboot"), status=observation.get("statusBeforeReboot")),
            _check("allowLANOffReachedDaemon", observation.get("allowLANBeforeReboot") is False, allowLAN=observation.get("allowLANBeforeReboot")),
            _check("idleBlockedAfterBoot", _status_is(boot.get("firstStatus"), "idle", "blocked"), firstStatus=boot.get("firstStatus")),
            *_boot_common(boot),
            _check("zeroLANReceiptsAfterBoot", boot.get("lanReceiptsAfterBoot") == 0, receiptCount=boot.get("lanReceiptsAfterBoot"), **after),
            _check("zeroOffSubnetReceiptsAfterBoot", boot.get("offSubnetReceiptsAfterBoot") == 0,
                   receiptCount=boot.get("offSubnetReceiptsAfterBoot"), addresses=boot.get("offSubnetAddresses"),
                   limitation=OFF_SUBNET_LIMITATION, **after)]


def reboot_intent_checks(boot):
    """REBOOT-INTENT has no row checks of its own; after a reboot its post-restart timeline must be consistent and launchd must have
    started the daemon once (M1-10u fix pass 1: the runs check REBOOT-LOCKDOWN and BOOT-SECRETS already had)."""
    return [timeline_consistency_check(boot), _check("noRestartLoop", boot.get("daemonRuns") == 1, daemonRuns=boot.get("daemonRuns"))]


# M03-T07: REBOOT-INTENT runs with no cutover trial ("none") or a confirmed one, never an armed one. A reboot while armed rolls back by
# design (TunnelController+Cutover.swift) and is accepted only through the M03-T08 rehearsal's reboot-while-armed scenario.
REBOOT_INTENT_CUTOVER_STATES = ("none", "confirmed")


def intent_snapshot(status):
    """The fields of one `wgex status --json` reply that REBOOT-INTENT records around the reboot: phase, protection, the intended
    profile and the cutover state ("unreadable" when the reply carries no cutover object with a string state)."""
    status = status if isinstance(status, dict) else {}
    cutover = status.get("cutover")
    state = cutover.get("state") if isinstance(cutover, dict) else None
    profile = status.get("activeProfileID")
    return dict(phase=status.get("phase"), protection=status.get("protection"),
                activeProfileID=profile if isinstance(profile, str) and profile else None,
                cutoverState=state if isinstance(state, str) and state else "unreadable",
                cutoverReason=cutover.get("reason") if isinstance(cutover, dict) and isinstance(cutover.get("reason"), str) else None)


def cutover_before_reboot_check(before):
    """Met only for a readable cutover state of none or confirmed before the reboot; armed, rolledBack or unreadable is not met."""
    before = before if isinstance(before, dict) else {}
    state = before.get("cutoverState", "unreadable")
    detail = dict(cutoverState=state, cutoverReason=before.get("cutoverReason"))
    met = state in REBOOT_INTENT_CUTOVER_STATES
    if not met:
        detail["gap"] = ("cutoverArmedBeforeReboot: a reboot while armed rolls back by design and is judged only by the M03-T08 rehearsal"
                         if state == "armed" else f"cutoverStateBeforeReboot {state}: REBOOT-INTENT needs no cutover trial or a confirmed one")
    return _check("cutoverStateBeforeReboot", met, **detail)


def intent_restored_check(before, after):
    """M03-T07: REBOOT-INTENT passes only when the persisted intent is restored after the reboot: the intended profile recorded
    before the reboot is the active one after it, active and protected. A missing pre-reboot profile is a gap, never a pass."""
    before = before if isinstance(before, dict) else {}
    after = after if isinstance(after, dict) else {}
    wanted = before.get("activeProfileID")
    met = (isinstance(wanted, str) and after.get("activeProfileID") == wanted and after.get("phase") == "active"
           and after.get("protection") == "protected")
    detail = dict(intendedProfileBeforeReboot=wanted, statusAfterBoot={key: after.get(key) for key in ("phase", "protection", "activeProfileID")})
    if not met:
        detail["gap"] = ("intentNotRestored: no intended profile before the reboot" if not isinstance(wanted, str) else
                         "intentNotRestored: the intended profile is not active and protected after the reboot")
    return _check("intentRestoredAfterBoot", met, **detail)


def _count(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def relaunch_prevention_applied(recorded):
    """The recorded loginwindow reopen-state prevention, re-derived from its facts (M1-10v; LOGIN-SILENT reuses it, M03-T07)."""
    recorded = recorded if isinstance(recorded, dict) else {}
    return (recorded.get("applied") is True and (recorded.get("mechanism") or None) == RELAUNCH_MECHANISM and recorded.get("userMatch") is True
            and recorded.get("savesLogoutState") is False and recorded.get("relaunchesApps") is False
            and _count(recorded.get("savedRelaunchEntries")) == 0 and not recorded.get("duplicateKeys"))


def relaunch_prevented_check(observation, boot, first_protected=None):
    """M1-10v (1 Nov 2026): BOOT-SECRETS prevents the app's login relaunch, so no app process may appear during the measurement
    window. Fix pass 1 (VERIFY B H1, M1, L2): the window is enforced, not described. The check is met only when
    - the recorded prevention is re-derived here, not trusted: `applied` must be recorded true AND the facts must say so (the
      mechanism is RELAUNCH_MECHANISM, the console user matched, both loginwindow keys read back false, the saved relaunch list held
      no entry, no key was printed twice), so an offline capture cannot assert `applied` over contradicting facts;
    - every planned boot sample was read (bootObservePlanned, at least two: at SSH return and after protection was restored) and
      the last one was taken at or after the first protected status, so the window reaches past the point the app would be judged
      against; a lost sample is a named gap, never a pass on one;
    - no app process was seen (appRunningAfterBoot false, appStartedAt absent) and the guest counted no unified-log line from the
      app's own process since the post-restart daemon's start (appLogLinesSamples, a count only), which closes the gap between the
      two point samples (assumed: an app that starts and exits between them still logs, not yet shown on a guest), one count per required
      sample; every required count must be readable, and an unreadable or missing one is a gap, never zero.
    An app that appears anyway is relaunchNotPrevented ("an app process appeared despite the recorded prevention; what started it
    was not measured": a login item, another profile's autoConnectAtLogin or a mechanism that did not take effect are all possible)."""
    prevention = observation.get("relaunchPrevention")
    recorded = prevention if isinstance(prevention, dict) else {}
    mechanism = recorded.get("mechanism") or None
    applied = relaunch_prevention_applied(recorded)
    running, app = boot.get("appRunningAfterBoot"), boot.get("appStartedAt")
    first = first_protected if first_protected is not None else boot_report(boot)["firstProtectedAt"]
    samples, planned = _count(boot.get("bootObserveSamples")), _count(boot.get("bootObservePlanned"))
    required = max(2, planned or 0)
    last = boot.get("lastBootSampleAt")
    counts = boot.get("appLogLinesSamples")
    counts = counts if isinstance(counts, list) else []
    logged = [value for value in map(_count, counts) if value]
    end_count = _count(counts[-1]) if counts else None
    covered = samples is not None and samples >= required
    # M1-10t (M1-10v FIX1-VERIFY L-B): one app log count per required sample, so an offline capture cannot drop the first sample's.
    counted = len(counts) >= required
    # M1-10t part 3 (VERIFY L-3): every count up to `required` must be readable, not only the end count; None, a string, a negative
    # number, a bool or a float in a non-final sample is a gap, never zero.
    unreadable = [index for index, value in enumerate(counts[:required]) if _count(value) is None]
    reaches = finite_number(last) and finite_number(first) and last >= first
    met = (applied and running is False and app is None and not logged and end_count is not None and covered and counted and not unreadable and reaches)
    detail = dict(mechanism=mechanism, relaunchPrevention=recorded or None, appRunningAfterBoot=running, appStartedAt=app,
                  bootObserveSamples=samples, bootObserveRequired=required, lastBootSampleAt=last, firstProtectedAt=first,
                  appLogLinesSamples=counts or None)
    if not met:
        if not applied:
            detail["gap"] = ("relaunchPreventionNotApplied: no applied login-relaunch prevention is recorded before the reboot, so an app-free boot "
                             "would not show the daemon alone and an app process would not be attributable to the relaunch")
        elif running is None:
            detail["gap"] = "relaunchNotPrevented not excluded: no readable post-boot process sample, so the absence of an app process is not shown"
        elif running or app is not None:
            detail["gap"] = (f"relaunchNotPrevented: an app process appeared despite the recorded prevention {mechanism} (seen after boot: running {running}, "
                             f"earliest possible start {app}); what started it was not measured, so the daemon alone was not measured")
        elif logged:
            detail["gap"] = (f"relaunchNotPrevented: app log activity during the window: {max(logged)} unified-log line(s) from the app's own process since the "
                             f"post-restart daemon's start although no app process was running at a sample; an app process appeared despite the recorded "
                             f"prevention {mechanism}; what started it was not measured")
        elif not covered:
            detail["gap"] = (f"no-app window not covered: {samples or 0} of {required} boot samples readable, so an app that started in the unread part "
                             "of the window would not be seen; relaunchNotPrevented not excluded")
        elif not counted:
            detail["gap"] = (f"no-app window not covered: {len(counts)} app log count(s) recorded for {required} required boot samples, so the "
                             "app's log activity at the missing sample is not shown; relaunchNotPrevented not excluded")
        elif unreadable:
            detail["gap"] = (f"no-app window not covered: the guest's count of app log lines since the post-restart daemon's start was not read at boot "
                             f"sample(s) {', '.join(str(index + 1) for index in unreadable)} of {required} (a count is a whole number, never a guess), "
                             "so the app's log activity there is not shown, never zero; relaunchNotPrevented not excluded")
        elif not reaches:
            detail["gap"] = (f"no-app window not covered: the last boot sample ({last}) is not at or after the first protected status ({first}) "
                             "or one of the two times is missing; relaunchNotPrevented not excluded")
        else:
            detail["gap"] = ("no-app window not covered: the guest's count of app log lines since the post-restart daemon's start was not read at the end "
                             "sample; relaunchNotPrevented not excluded")
    return _check("relaunchPrevented", met, **detail)


def boot_secrets_checks(observation):
    boot = observation["boot"]
    report = boot_report(boot)
    checks = [_check("bootIntentReachedDaemon", observation.get("bootIntentBeforeReboot") is True,
                     bootIntent=observation.get("bootIntentBeforeReboot")),
              relaunch_prevented_check(observation, boot, report["firstProtectedAt"]),
              _check("protectedAfterBoot", report["firstProtectedAt"] is not None, firstProtectedAt=report["firstProtectedAt"]),
              *_boot_common(boot)]
    # Timing only (README rule: protection restored before any app process is seen, with the relaunch prevented). Who restored it is not measured.
    held = report["protectedBeforeAppSeen"] is True
    detail = dict(appRunningAfterBoot=report["appRunningAfterBoot"], appStartedAt=report["appStartedAt"],
                  firstProtectedAt=report["firstProtectedAt"], daemonStartedAt=report["daemonStartedAt"])
    if not held:
        seen = report.get("protectedOnlyAfterAppSeen")
        if not report["postRestartTimelineConsistent"]:
            detail["gap"] = ("timelineInconsistent: the post-restart status timeline failed "
                             + ", ".join(report["postRestartTimeline"]["diagnostics"]) + ", so daemon-held boot secrets are not proven")
        elif report["appRunningAfterBoot"] is None:
            detail["gap"] = "protectedOnlyAfterAppSeen not excluded: no readable post-boot process sample, so daemon-held boot secrets are not proven"
        elif seen:
            # README rule: a PASS needs the post-restart daemon's first protected status before the app process's earliest start.
            detail.update(protectedOnlyAfterAppSeen=seen)
            lstart = (f" (ps lstart {seen['appStartedAtPsLstart']}, {seen['deltaSecondsVsPsLstart']} s)" if "appStartedAtPsLstart" in seen else "")
            detail["gap"] = (f"protectedOnlyAfterAppSeen: the post-restart daemon reached protected at {seen['firstProtectedAt']}, "
                             f"{seen['deltaSeconds']} s after the app process's earliest possible start at {seen['appStartedAt']}{lstart}; "
                             "protection was restored only after an app process was seen; causation not measured")
        elif report["appRunningAfterBoot"]:
            detail["gap"] = ("protectedOnlyAfterAppSeen: the app process was running after boot and protection was not shown restored before "
                             "its earliest possible start, so daemon-held boot secrets are not proven; causation not measured")
        else:
            detail["gap"] = "daemon-held boot secrets did not restore protection while no app process was seen"
    checks.append(_check("daemonSecretsBeforeApp", held, **detail))
    return checks


def en0_loss_checks(observation):
    checks = []
    for item in observation["profiles"]:
        variant, down, up = item.get("variant"), item.get("down"), item.get("up")
        samples = item.get("samples", [])
        cycled = finite_number(down) and finite_number(up) and 0 < up - down <= 60
        checks.append(_check("linkCycled:" + variant, cycled and up - down >= item.get("lossSeconds", 20) - 1,
                             lossSeconds=(up - down) if cycled else None))
        # M1-04: protected -> failed/blocked -> reasserting -> active/protected. The daemon must notice the loss (VERIFY F2).
        loss = [s for s in samples if cycled and down <= s[0] <= up]
        noticed = [s for s in loss if s[2] == "blocked" or s[1] in ("failed", "reasserting")]
        checks.append(_check("lossDetected:" + variant, bool(noticed), samplesWhileLinkDown=len(loss), lossSamples=len(noticed)))
        # Recovery is the first protected sample after the last non-protected one, never a stale protected status.
        lost = lambda s: s[2] != "protected" or s[1] in ("failed", "reasserting")
        last = max((s[0] for s in samples if cycled and s[0] >= down and lost(s)), default=None)
        recovered = sorted(s[0] for s in samples if last is not None and s[0] > last and s[0] >= up and not lost(s))
        recovery = recovered[0] - up if recovered else None
        checks.append(_check("protectedWithin10sOfLinkUp:" + variant, recovery is not None and recovery <= EN0_RECOVERY_SECONDS,
                             secondsAfterLinkUp=recovery))
        end = recovered[0] if recovered else (up + EN0_RECOVERY_SECONDS if cycled else None)
        during = [sample for sample in samples if cycled and down <= sample[0] <= end]
        lost = [sample for sample in during if sample[0] <= up]
        checks.append(_check("neverUnprotectedDuringLoss:" + variant, bool(lost) and all(s[2] != "unprotected" for s in during),
                             sampleCount=len(during), samplesWhileLinkDown=len(lost),
                             unprotectedCount=sum(s[2] == "unprotected" for s in during)))
        references = sorted({sample[3] for sample in samples})
        checks.append(_check("onePfReferenceThroughout:" + variant, bool(samples) and references == [1], referenceCounts=references))
        if not split_tunnel(PROFILE_ALLOWED_IPS[variant]):
            checks.append(_check("zeroLanReceiptsDuringLoss:" + variant, item.get("lossOutsideReceipts") == 0
                                 and (item.get("lossProbeAttempts") or 0) > 0,
                                 receiptCount=item.get("lossOutsideReceipts"), probeAttempts=item.get("lossProbeAttempts")))
    return checks


def _power_lost(sample):
    return sample[2] != "protected" or sample[1] in ("failed", "reasserting")


def power_instants(item):
    """(sleep, wake) of one injected-event variant: the daemon's own log lines when it logged exactly one of each, in order, near the
    injector's instants (seen true), else the injector's instants (seen false). None when the injector's instants are unusable."""
    slept, woke = item.get("sleepAt"), item.get("wakeAt")
    if not (finite_number(slept) and finite_number(woke)) or woke <= slept:
        return None
    near = [line for line in item.get("injected") or [] if slept - POWER_LOG_SLACK_SECONDS <= line[0] <= woke + POWER_LOG_SLACK_SECONDS]
    sleeps = [line[0] for line in near if line[1] == "sleep"]
    wakes = [line[0] for line in near if line[1] == "wake"]
    seen = len(sleeps) == 1 and len(wakes) == 1 and sleeps[0] < wakes[0]
    return dict(sleep=sleeps[0] if seen else slept, wake=wakes[0] if seen else woke, seen=seen)


def _power_recovery(samples, wake):
    """First protected entry after the last lost entry at or after wake; samples and daemon status share their first 3 fields."""
    after = [sample for sample in samples if sample[0] >= wake]
    last_lost = max((sample[0] for sample in after if _power_lost(sample)), default=None)
    again = [sample[0] for sample in after if (last_lost is None or sample[0] > last_lost) and not _power_lost(sample)]
    return min(again) if again else None


def power_protected_again(samples, wake, daemon_status=None, status_lines_dropped=None):
    """Recovery needs the guest timeline and, when present after wake, the daemon timeline. The later recovery must be
    corroborated by a non-lost guest sample with a pf reference at or after it. A truncated status log proves no recovery."""
    if (status_lines_dropped or 0) > 0:
        return None
    timelines = [samples]
    if any(entry[0] >= wake for entry in daemon_status or []):
        timelines.append(daemon_status)
    recoveries = [_power_recovery(entries, wake) for entries in timelines]
    if any(at is None for at in recoveries):
        return None
    recovery = max(recoveries)
    return recovery if any(sample[0] >= recovery and not _power_lost(sample) and sample[3] > 0 for sample in samples) else None


def power_window(item):
    """Sleep through recovery established by samples and daemon status, or wake + 3 s when recovery is not established."""
    instants = power_instants(item)
    if instants is None:
        return None
    protected = power_protected_again(item.get("samples") or [], instants["wake"], item.get("daemonStatus"), item.get("statusLinesDropped"))
    return instants["sleep"], protected if protected is not None else instants["wake"] + POWER_WAKE_SECONDS


def _power_gap(times, start, end):
    points = [start, *sorted(times), end]
    return max(later - earlier for earlier, later in zip(points, points[1:]))


def power_wake_checks(observation):
    """POWER-WAKE (M1-47): the injected sleep and wake on full4, a short (3 s) and a long (130 s) variant. Injected events exercise the
    daemon's sleep/wake handling only; the guest and its WireGuard timers do not sleep."""
    items = observation.get("powerWakes") or []
    names = sorted(str(item.get("variant")) for item in items)
    asked = all(POWER_VARIANTS.get(item.get("variant")) == item.get("sleepSeconds") for item in items)
    checks = [_check("variantsObserved", names == sorted(POWER_VARIANTS) and asked, variants=names, expected=POWER_VARIANTS)]
    for item in items:
        variant_start = len(checks)
        variant = item.get("variant")
        samples = item.get("samples") or []
        instants = power_instants(item)
        window = power_window(item)
        sleep, wake = (instants["sleep"], instants["wake"]) if instants else (None, None)
        held = wake - sleep if instants and instants["seen"] else None
        seconds = item.get("sleepSeconds")
        hold_ok = held is not None and finite_number(seconds) and (
            1 <= held < 5 if variant == "short" else abs(held - seconds) <= seconds * POWER_HOLD_SLACK_FRACTION)
        checks.append(_check("injectedEventsSeen:" + str(variant), bool(instants) and instants["seen"] and finite_number(seconds)
                             and hold_ok,
                             injectedLines=len(item.get("injected") or []), heldSeconds=held, sleepSeconds=seconds))
        start, end = window if window else (None, None)
        during = [sample for sample in samples if window and start <= sample[0] <= end]
        unprotected = sum(sample[2] not in ("protected", "blocked") for sample in during)
        gap = _power_gap([sample[0] for sample in during], start, end) if window else None
        checks.append(_check("neverUnprotected:" + str(variant), bool(during) and unprotected == 0 and gap <= POWER_SAMPLE_GAP_SECONDS,
                             sampleCount=len(during), unprotectedCount=unprotected, maxGapSeconds=gap))
        daemon_status = item.get("daemonStatus") or []
        protected = power_protected_again(samples, wake, daemon_status, item.get("statusLinesDropped")) if instants else None
        recovery = protected - wake if protected is not None else None
        coverage_gap = _power_gap([sample[0] for sample in samples if wake <= sample[0] <= wake + POWER_WAKE_SECONDS],
                                  wake, wake + POWER_WAKE_SECONDS) if instants else None
        recovery_shown = protected is not None and (_power_recovery(daemon_status, wake) is not None
                                                    or coverage_gap <= POWER_RECOVERY_SAMPLE_GAP_SECONDS)
        reasserted = bool(instants) and any(sample[2] in ("protected", "blocked")
                                            and (sample[1] == "reasserting" or sample[2] == "blocked") for sample in samples
                                            if wake <= sample[0] <= end)
        checks.append(_check("protectedWithin3sOfWake:" + str(variant), recovery is not None and recovery <= POWER_WAKE_SECONDS and recovery_shown,
                             secondsAfterWake=recovery, reassertingAfterWake=reasserted, recoverySampleMaxGapSeconds=coverage_gap))
        references = sorted({sample[3] for sample in samples})
        checks.append(_check("onePfReferenceThroughout:" + str(variant), bool(samples) and references == [1], referenceCounts=references))
        checks.append(_check("zeroLanReceiptsDuringWindow:" + str(variant), item.get("windowOutsideReceipts") == 0
                             and (item.get("windowProbeAttempts") or 0) > 0,
                             receiptCount=item.get("windowOutsideReceipts"), probeAttempts=item.get("windowProbeAttempts")))
        if variant == "long":
            # The samples (0.25 s) can miss a sub-second reassert, so the daemon's own reasserting status line (reason wake, logged
            # after the wake line) counts as well; seenIn says which one showed it.
            in_samples = reasserted
            in_log = bool(instants) and any(line[1] == "reasserting" and line[3] == "wake"
                                            and wake <= line[0] <= wake + POWER_FORCED_LOG_SECONDS for line in item.get("daemonStatus") or [])
            checks.append(_check("forcedHandshakeObserved:long", in_samples or in_log,
                                 seenIn="samples" if in_samples else "daemonLog" if in_log else None))
        if (item.get("statusLinesDropped") or 0) > 0:
            # The recovery window and log fallback both need a complete status timeline. Receipt counts use that same window.
            dependent = {"neverUnprotected", "protectedWithin3sOfWake", "zeroLanReceiptsDuringWindow", "forcedHandshakeObserved"}
            for check in checks[variant_start:]:
                if check["name"].split(":")[0] in dependent:
                    check.update(met=False, reason="status lines dropped")
    return checks


def captive_checks(observation):
    duration = observation.get("durationSeconds")
    scenarios = {item.get("name"): item for item in observation.get("scenarios", [])}
    def opened(item):
        passes = item.get("passesWhileOpen") or {}
        return item.get("protectionWhileOpen") == "captiveWindow" and passes.get("port80", 0) > 0 and passes.get("port443", 0) > 0
    def closed(item):
        passes = item.get("passesAfterClose") or {}
        return (item.get("protectionAfterClose") == "blocked" and passes.get("port80") == 0 and passes.get("port443") == 0)
    def expired(item):
        age = item["closedAt"] - item["openedAt"] if finite_number(item.get("closedAt")) and finite_number(item.get("openedAt")) else None
        return age, finite_number(duration) and age is not None and duration - 5 <= age <= duration + CAPTIVE_CLOSE_SLACK_SECONDS
    checks = [_check("lockdownReachedDaemon", observation.get("lockdownBeforeOpen") is True, lockdown=observation.get("lockdownBeforeOpen"))]
    before = observation.get("statusBeforeOpen") or {}
    expiry = scenarios.get("expiry", {})
    checks.append(_check("d8FailedIntentOpens", before.get("protection") == "blocked" and before.get("phase") in ("reasserting", "failed")
                         and bool(expiry) and opened(expiry), statusBeforeOpen=before))
    for name in ("expiry", "manualEnd", "appKill"):
        item = scenarios.get(name, {})
        checks.append(_check("captivePassesWhileOpen:" + name, bool(item) and opened(item), passes=item.get("passesWhileOpen"),
                             protection=item.get("protectionWhileOpen")))
    age, in_time = expired(expiry) if expiry else (None, False)
    checks.append(_check("expiryCloses", bool(expiry) and in_time and closed(expiry), secondsOpen=age, durationSeconds=duration,
                         passesAfterClose=expiry.get("passesAfterClose"), protectionAfterClose=expiry.get("protectionAfterClose")))
    end = scenarios.get("manualEnd", {})
    took = end["closedAt"] - end["endClickedAt"] if finite_number(end.get("closedAt")) and finite_number(end.get("endClickedAt")) else None
    checks.append(_check("manualEndCloses", bool(end) and took is not None and 0 <= took <= CAPTIVE_END_SECONDS and closed(end),
                         secondsAfterEnd=took, endClickedAtSource=end.get("endClickedAtSource"), closedAtSource=end.get("closedAtSource"),
                         endClockDriftSeconds=end.get("endClockDriftSeconds"), passesAfterClose=end.get("passesAfterClose"),
                         protectionAfterClose=end.get("protectionAfterClose")))
    kill = scenarios.get("appKill", {})
    killed = kill["killedAt"] - kill["openedAt"] if finite_number(kill.get("killedAt")) and finite_number(kill.get("openedAt")) else None
    age, in_time = expired(kill) if kill else (None, False)
    checks.append(_check("appKillCannotExtend", bool(kill) and killed is not None and 9 <= killed <= 15 and kill.get("appAbsentAtClose") is True
                         and in_time and closed(kill), secondsToKill=killed, secondsOpen=age, appAbsentAtClose=kill.get("appAbsentAtClose"),
                         passesAfterClose=kill.get("passesAfterClose"), protectionAfterClose=kill.get("protectionAfterClose")))
    refusal = observation.get("typedRefusal") or {}
    failures = refusal.get("requestFailures") or []
    typed = [item for item in failures if item[0] != "UnknownError" and item[2] in CAPTIVE_CODES]
    untyped = [item for item in failures if item[0] == "UnknownError"]
    passes = refusal.get("passesAfter") or {}
    checks.append(_check("d8TypedRefusal", bool(typed) and not untyped and _status_is(refusal.get("statusAfter"), "idle", "blocked")
                         and passes.get("port80") == 0 and passes.get("port443") == 0,
                         typedFailures=typed, unknownErrors=len(untyped), statusAfter=refusal.get("statusAfter")))
    return checks


_gap_spec = importlib.util.spec_from_file_location("lab_gap_rows", Path(__file__).with_name("gap-rows.py"))
GAP_ROWS = importlib.util.module_from_spec(_gap_spec)
_gap_spec.loader.exec_module(GAP_ROWS)
ROW_CHECKS = {"reboot-lockdown": reboot_lockdown_checks, "boot-secrets": boot_secrets_checks,
              "en0-loss": en0_loss_checks, "power-wake": power_wake_checks, "captive": captive_checks, **GAP_ROWS.CHECKS}
ROW_CHECKS["rt21"] = lambda observation: GAP_ROWS.rt21_checks(observation) + power_wake_checks(observation)


def _lab_module(name, relative):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parent / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


# M03-T03: the update bundle row (M5.3-07) and the XPC identity corpus row (RT-17).
UPDATE = _lab_module("lab_update", "update/update.py")
CORPUS = _lab_module("lab_corpus", "corpus/corpus.py")
ROW_CHECKS.update({"update": UPDATE.update_checks, "rt17": CORPUS.rt17_checks})
# M03-T09: the on-demand Ethernet row; the armed en0 cycle is judged by EN0-LOSS's own checks.
ONDEMAND = _lab_module("lab_ondemand", "ondemand/ondemand.py")
ROW_CHECKS["ondemand-eth"] = lambda observation: ONDEMAND.ondemand_checks(observation, en0_loss_checks)
# M03-T15: the uninstall row (DEC-037 item 4, DEC-040).
UNINSTALL = _lab_module("lab_uninstall", "uninstall/uninstall.py")
ROW_CHECKS["uninstall"] = UNINSTALL.uninstall_checks
# M03-T07: the silent login launch row (DEC-021).
LOGIN_SILENT = _lab_module("lab_login_silent", "login/login_silent.py")
ROW_CHECKS["login-silent"] = lambda observation: LOGIN_SILENT.login_silent_checks(observation, relaunch_prevention_applied)


def row_checks(kind, observation):
    """Named row expectations for one observation; every check has name and met, and a failed one may carry a gap."""
    if kind not in ROW_CHECKS:
        raise ValueError("unknown row check kind")
    return ROW_CHECKS[kind](observation)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("record", type=Path)
    parser.add_argument("--expectations", type=Path, default=Path(__file__).with_name("leak-expectations.json"))
    parser.add_argument("--receiver", type=Path, action="append", default=[])
    arguments = parser.parse_args(argv)
    hashes = {}
    try:
        inputs = [("record", arguments.record), ("expectations", arguments.expectations)]
        inputs.extend((f"receiver:{index}", path) for index, path in enumerate(arguments.receiver))
        decoded = {}
        for name, path in inputs:
            data = path.read_bytes()
            hashes[name] = sha256(data)
            decoded[name] = json.loads(data)
        result = evaluate(decoded["record"], decoded["expectations"],
                          [decoded[f"receiver:{index}"] for index in range(len(arguments.receiver))])
        result["inputHashes"] = hashes
        sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
        return 0 if result["expectationsMet"] else 1
    except (OSError, ValueError, KeyError, TypeError) as error:
        sys.stdout.write(json.dumps({"schemaVersion": 1, "verdict": "unknown", "familiesCovered": [], "error": str(error), "inputHashes": hashes}, sort_keys=True) + "\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
