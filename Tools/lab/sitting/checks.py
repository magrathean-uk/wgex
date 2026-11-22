#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Checks run at the cutover sitting (DEC-026).

Usage: python3 -I checks.py [--cli PATH] SUBCOMMAND [ARGS]

Every subcommand ends with one verdict line, `<name>: PASS - <why>` or `<name>: FAIL - <why>`, and exits 0 on PASS,
1 on FAIL and 2 on a usage error. Every external command goes through `Runner`, which prints `[exit N] <command>` for
each one and keeps the exit code, so no failed command can read as success. There are no shell pipelines: each
command runs on its own and its output is parsed here. Privileged commands use `sudo -n`, so the maintainer authenticates once with
`sudo -v` in the same terminal beforehand (a cached ticket is fine) and the helper never asks for or sees a password.
The helper changes nothing on the network; it reads status, routes, resolvers and packets, and the only changes it
makes are the ones the step names (E1 worktree and builds, E2 install and daemon restart, WGEX's own on-demand and
cutover requests, the rollback's daemon bootout, and stopping the captures it spawned, by their recorded PIDs).

Standard library only; run with `python3 -I`. Tests: Tools/lab/tests/test_sitting_checks.py feeds a fake runner.
"""
import argparse
import base64
import datetime
import hashlib
import ipaddress
import json
import os
import plistlib
import re
import secrets
import subprocess
import shutil
import sys
import time

CANDIDATE_TAG = "M04-rc9"  # the one place the helper names the candidate tag; check-sitting.py reads it
CLI = "/Applications/WGEX.app/Contents/Helpers/wgex"
# Plain-text echo services, asked in order (M04-T12, DEC-079): ifconfig.co answers a data-centre address with a
# Cloudflare challenge page, and the full tunnel's DNS does not resolve api.ipify.org or icanhazip.com, so none of
# those is used.
PROBE_URLS = ("https://ifconfig.me/ip", "https://ident.me", "https://ip.me")
HTTP_MARK = "wgex-http-status="
RIGHT = "com.magrathean.WGEXApp.manage-protection"
DAEMON_SERVICE = "system/com.magrathean.WGEXApp.daemon"
APP_IDENTIFIER = "com.magrathean.WGEXApp"
WWDR_MARKER = "certificate 1[field.1.2.840.113635.100.6.2.1] /* exists */"
CAPTURE_SECONDS = 20
CAPTURE_FILTER = "port 53 or port 853"
LOOKUPS = 5
# sudo re-raises the signal that ended its command, so a capture ended by perl's alarm shows as SIGALRM: -14 from
# Python, 142 from a shell.
ALARM_EXITS = (-14, 142)
UUID = re.compile(r"^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$")
KEY_SIGNALS = ("CSSMERR_CSP_OPERATION_AUTH_DENIED", "Wrapping key is unavailable", "secretsUnavailable")

PHASES = {"idle", "preparing", "configuring", "active", "reasserting", "captiveWindow", "stopping", "failed"}
PROTECTIONS = {"protected", "blocked", "unprotected", "unknown", "unsupported", "captiveWindow"}
NOTES = {"ipv6Unavailable", "dnsUnverified", "verificationFailed", "canaryFailed"}
CUTOVER_STATES = {"none", "armed", "confirmed", "rolledBack"}
ROLLBACK_REASONS = {"timeout", "aborted", "daemonRestart", "startFailed"}
JOURNAL_POLICIES = {"disconnected", "connecting", "connected", "disconnecting", "error", "lockdown", "captiveWindow"}
NETWORKS = {"none", "ethernet", "wifi"}
SSID_STATES = {"notRequired", "known", "settling", "unavailable"}
SSID_REASONS = {"noReporter", "notAuthorised", "timedOut", "unreadable"}
DECISIONS = {"connect": None, "disconnect": None,
             "hold": {"noNetwork", "ssidUnavailable", "anotherTunnelActive"},
             "paused": {"ownerNotConsoleUser", "recovering", "cutoverArmed"}}


class Result:
    def __init__(self, argv, rc, out="", err=""):
        self.argv, self.rc, self.out, self.err = list(argv), rc, out, err

    @property
    def ok(self):
        return self.rc == 0


class Runner:
    """The one place commands run. Each finished command is recorded with its exit code and printed as `[exit N]`."""

    def __init__(self, echo=None):
        self.log = []
        self.echo = echo if echo is not None else sys.stdout

    def record(self, result):
        self.log.append(result)
        print("  [exit %s] %s" % (result.rc, " ".join(result.argv)), file=self.echo)
        return result

    def run(self, argv, cwd=None, env=None, timeout=None, data=None, interactive=False):
        try:
            if interactive:
                proc = subprocess.run(argv, cwd=cwd, env=env, timeout=timeout, check=False)
                out, err = "", ""
            else:
                proc = subprocess.run(argv, cwd=cwd, env=env, timeout=timeout, input=data, capture_output=True,
                                      check=False)
                out = proc.stdout.decode("utf-8", "replace")
                err = proc.stderr.decode("utf-8", "replace")
            rc = proc.returncode
        except FileNotFoundError:
            rc, out, err = 127, "", "%s: not found" % argv[0]
        except subprocess.TimeoutExpired:
            rc, out, err = 124, "", "%s: timed out" % argv[0]
        return self.record(Result(argv, rc, out, err))

    def spawn(self, argv, out_path, err_path):
        return Spawned(self, argv, out_path, err_path)

    def monotonic(self):
        return time.monotonic()

    def sleep(self, seconds):
        time.sleep(seconds)

    def clock(self):
        return datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S")


class Spawned:
    """A capture this helper started. `pid` is its own child (sudo), unreaped until it has exited, so the pid cannot have
    been reused while the helper still signals it."""

    def __init__(self, runner, argv, out_path, err_path):
        self.runner, self.argv, self.done, self.rc = runner, list(argv), False, None
        with open(out_path, "wb") as out, open(err_path, "wb") as err:
            try:
                self.proc = subprocess.Popen(argv, stdout=out, stderr=err, stdin=subprocess.DEVNULL)
                self.pid = self.proc.pid
            except FileNotFoundError:
                self.proc, self.pid = None, None
                err.write(("%s: not found\n" % argv[0]).encode())

    def poll(self):
        """The exit code once the process has ended (recorded once as `[exit N]`), or None while it runs."""
        if self.done:
            return self.rc
        rc = 127 if self.proc is None else self.proc.poll()
        if rc is None:
            return None
        self.done, self.rc = True, rc
        self.runner.record(Result(self.argv, rc))
        return rc

    def wait(self, timeout):
        """The exit code, or None when the process is still running at the timeout."""
        if not self.done and self.proc is not None:
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                return None
        return self.poll()


class Check:
    """Collects detail lines and problems for one subcommand and prints its single verdict line."""

    def __init__(self, name, out):
        self.name, self.out, self.problems = name, out, []

    def say(self, text):
        print(text, file=self.out)

    def fail(self, why):
        self.problems.append(why)
        self.say("%s-FAIL: %s" % (self.name.upper(), why))
        return False

    def verdict(self, why_ok):
        if self.problems:
            self.say("%s: FAIL - %s" % (self.name, self.problems[0]))
            return 1
        self.say("%s: PASS - %s" % (self.name, why_ok))
        return 0


def command_failed(check, result, what):
    """Fails the check when a command did not exit 0; returns True when it failed."""
    if result.rc != 0:
        detail = (result.err or result.out).strip().splitlines()
        check.fail("%s exited %s%s" % (what, result.rc, (": " + detail[-1][:160]) if detail else ""))
        return True
    return False


# ---- WGEX status --------------------------------------------------------------------------------------------------

def is_uuid_or_null(value):
    return value is None or (isinstance(value, str) and bool(UUID.match(value)))


def is_number_or_null(value):
    return value is None or (isinstance(value, (int, float)) and not isinstance(value, bool))


def is_text_or_null(value):
    return value is None or isinstance(value, str)


def is_one_of(value, values):
    """Enum membership guarded by type, so a list or object never raises and never matches."""
    return isinstance(value, str) and value in values


def on_demand_problems(value):
    if value is None:
        return []
    if not isinstance(value, dict):
        return ["onDemand is not an object or null"]
    problems = []
    for field in ("armedProfileID", "activated", "network", "ssid", "decision", "evaluatedAtContinuous"):
        if field not in value:
            problems.append("onDemand has no %s" % field)
    if problems:
        return problems
    if not is_uuid_or_null(value["armedProfileID"]):
        problems.append("onDemand.armedProfileID is not a UUID or null")
    if not isinstance(value["activated"], bool):
        problems.append("onDemand.activated is not a boolean")
    if not is_one_of(value["network"], NETWORKS):
        problems.append("onDemand.network is not one of %s" % sorted(NETWORKS))
    ssid = value["ssid"]
    if not isinstance(ssid, dict) or not is_one_of(ssid.get("state"), SSID_STATES):
        problems.append("onDemand.ssid.state is invalid")
    elif ssid["state"] == "unavailable" and not is_one_of(ssid.get("reason"), SSID_REASONS):
        problems.append("onDemand.ssid.reason is invalid")
    decision = value["decision"]
    if decision is not None:
        if not isinstance(decision, dict) or not is_one_of(decision.get("state"), DECISIONS):
            problems.append("onDemand.decision.state is invalid")
        elif DECISIONS[decision["state"]] is not None and not is_one_of(decision.get("reason"),
                                                                         DECISIONS[decision["state"]]):
            problems.append("onDemand.decision.reason is invalid")
    if not is_number_or_null(value["evaluatedAtContinuous"]):
        problems.append("onDemand.evaluatedAtContinuous is not a number or null")
    return problems


# One status publication (WGEXCLICore.swift publicationFields and telemetryFields); `startup` holds the run's first
# publication in the same fields, or null (statusFields, DEC-018).
PUBLICATION_FIELDS = ("phase", "protection", "protectionNote", "sequence", "activeProfileID", "measuredAt",
                      "measuredAtContinuous", "operationInFlight", "policyEnforcing", "cutover",
                      "cutoverRollbackFailures", "verifiedAt", "verifiedAtContinuous", "onDemand", "journalPolicy")


def publication_problems(doc, where=""):
    """Type and value checks for one publication; `where` prefixes field names (`startup.`)."""
    if not isinstance(doc, dict):
        return ["%s is not a JSON object" % (where.rstrip(".") or "the reply")]
    missing = [where + field for field in PUBLICATION_FIELDS if field not in doc]
    if missing:
        return ["the reply has no %s" % ", ".join(missing)]
    problems = []
    if not is_one_of(doc["phase"], PHASES):
        problems.append("phase is not a known phase")
    if not is_one_of(doc["protection"], PROTECTIONS):
        problems.append("protection is not a known protection state")
    if doc["protectionNote"] is not None and not is_one_of(doc["protectionNote"], NOTES):
        problems.append("protectionNote is invalid")
    if not isinstance(doc["sequence"], int) or isinstance(doc["sequence"], bool) or doc["sequence"] < 0:
        problems.append("sequence is not a non-negative integer")
    if not is_uuid_or_null(doc["activeProfileID"]):
        problems.append("activeProfileID is not a UUID or null")
    for field in ("operationInFlight", "policyEnforcing"):
        if not isinstance(doc[field], bool):
            problems.append("%s is not a boolean" % field)
    for field in ("measuredAt", "verifiedAt"):
        if not is_text_or_null(doc[field]):
            problems.append("%s is not text or null" % field)
    for field in ("measuredAtContinuous", "verifiedAtContinuous"):
        if not is_number_or_null(doc[field]):
            problems.append("%s is not a number or null" % field)
    cutover = doc["cutover"]
    if not isinstance(cutover, dict) or not is_one_of(cutover.get("state"), CUTOVER_STATES):
        problems.append("cutover.state is invalid")
    elif cutover["state"] == "armed" and not isinstance(cutover.get("deadline"), str):
        problems.append("cutover.deadline is missing for an armed trial")
    elif cutover["state"] == "rolledBack" and not is_one_of(cutover.get("reason"), ROLLBACK_REASONS):
        problems.append("cutover.reason is not a rollback reason")
    failures = doc["cutoverRollbackFailures"]
    if not isinstance(failures, list) or not all(isinstance(item, str) for item in failures):
        problems.append("cutoverRollbackFailures is not a list of names")
    if doc["journalPolicy"] is not None and not is_one_of(doc["journalPolicy"], JOURNAL_POLICIES):
        problems.append("journalPolicy is invalid")
    if "recoveryFailureReason" in doc and not isinstance(doc["recoveryFailureReason"], str):
        problems.append("recoveryFailureReason is not text")
    problems.extend(on_demand_problems(doc["onDemand"]))
    return [where + problem if problem[0].islower() and not problem.startswith("the ") else problem
            for problem in problems]


def status_problems(doc):
    """Type and value checks for `wgex status --json`: the current publication plus `startup` (null or one more)."""
    if not isinstance(doc, dict):
        return ["the reply is not a JSON object"]
    if "error" in doc:
        return ["the reply is an error: %s" % render(doc["error"])]
    if "startup" not in doc:
        return ["the reply has no startup"]
    problems = publication_problems(doc)
    if doc["startup"] is not None:
        problems.extend(publication_problems(doc["startup"], "startup."))
    return problems


def cli_json(runner, cli, args, timeout=None):
    """Runs `wgex ARGS --json`: (document, problem). A non-zero exit, error JSON or invalid JSON is a problem. A
    `timeout` bounds the command (exit 124 when it expires)."""
    result = runner.run([cli] + list(args) + ["--json"], timeout=timeout)
    try:
        doc = json.loads(result.out)
    except ValueError:
        doc = None
    if result.rc != 0:
        name = doc.get("error") if isinstance(doc, dict) else None
        return doc, "wgex %s exited %s%s" % (args[0], result.rc, (" (%s)" % name) if name else "")
    if doc is None:
        return None, "wgex %s did not print JSON" % args[0]
    if not isinstance(doc, dict):
        return None, "wgex %s did not print a JSON object" % args[0]
    if "error" in doc:
        return doc, "wgex %s replied with error %s" % (args[0], doc["error"])
    return doc, None


def read_status(runner, cli, timeout=None):
    doc, problem = cli_json(runner, cli, ["status"], timeout=timeout)
    if problem:
        return None, problem
    problems = status_problems(doc)
    if problems:
        return None, "invalid status: " + "; ".join(problems)
    return doc, None


def lookup(doc, key):
    value = doc
    for part in key.split("."):
        if value is None:
            return None
        if not isinstance(value, dict) or part not in value:
            raise KeyError(key)
        value = value[part]
    return value


def render(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value)


def armed_profile(doc):
    """The armed profile ID, or None when nothing is armed (onDemand null or armedProfileID null)."""
    return None if doc["onDemand"] is None else doc["onDemand"]["armedProfileID"]


# ---- network reads ------------------------------------------------------------------------------------------------

TUNNEL_PREFIXES = ("utun", "ipsec", "bridge", "lo", "gif", "stf", "awdl", "llw", "anpi", "ap")


def default_routes(text):
    """(gateway, flags, netif) of each `default` line of `netstat -rn -f inet`; flag `I` marks an interface-scoped
    route."""
    routes = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[0] == "default":
            routes.append((fields[1], fields[2], fields[3]))
    return routes


def physical_from_netstat(text):
    """First default route through an IPv4 gateway on a non-tunnel interface, preferring an unscoped one (no `I`)."""
    fallback = None
    for gateway, flags, netif in default_routes(text):
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", gateway) or netif.startswith(TUNNEL_PREFIXES):
            continue
        if "I" not in flags:
            return netif
        fallback = fallback or netif
    return fallback


def tunnel_defaults(text, scoped=None):
    """Distinct utun interfaces holding a default route, in table order: all of them, or only the interface-scoped
    (`scoped=True`) or unscoped (`scoped=False`) ones."""
    names = []
    for _, flags, netif in default_routes(text):
        if netif.startswith("utun") and (scoped is None or ("I" in flags) == scoped) and netif not in names:
            names.append(netif)
    return names


def read_netstat(runner, check):
    result = runner.run(["/usr/sbin/netstat", "-rn", "-f", "inet"])
    if command_failed(check, result, "netstat"):
        return None
    return result.out


def read_physical(runner, check, text=None):
    text = read_netstat(runner, check) if text is None else text
    if text is None:
        return None
    name = physical_from_netstat(text)
    if not name:
        check.fail("no default route through a physical interface")
    return name


def read_route_interface(runner, check, target="9.9.9.9"):
    result = runner.run(["/sbin/route", "-n", "get", "-inet", target])
    if command_failed(check, result, "route get"):
        return None
    match = re.search(r"^\s*interface:\s*(\S+)\s*$", result.out, re.M)
    if not match:
        check.fail("route get printed no interface")
        return None
    return match.group(1)


def read_tunnel(runner, check, phys, scoped):
    """The tunnel that carries traffic, from evidence the Mac gives, never a hard-coded name. Two layouts:
    unscoped (WGEX: 0/1 and 128/1 on the utun, so `route get 9.9.9.9` names the utun) and, only with `scoped`,
    interface-scoped (the official app's NetworkExtension tunnel on macOS 27: `default link#N UCSIg utunN` while the
    unscoped default stays on the physical interface, so `route get` names `phys`). The scoped layout is accepted only
    when exactly one utun holds a scoped default, no utun holds an unscoped one, and resolver #1 is on that utun.
    Whether traffic really uses it is then proved by the caller's S1 (VPS4) and S3 (DNS on the utun, none on `phys`)."""
    route = read_route_interface(runner, check)
    if route is None:
        return None
    if route.startswith("utun"):
        check.say("tunnel layout: unscoped (9.9.9.9 routes through %s)" % route)
        return route
    if not scoped:
        check.fail("9.9.9.9 routes through %s, not a utun: no tunnel carries it in the unscoped layout this check "
                   "supports" % route)
        return None
    if route != phys:
        check.fail("9.9.9.9 routes through %s, neither a utun nor the physical interface %s" % (route, phys))
        return None
    text = read_netstat(runner, check)
    if text is None:
        return None
    candidates = tunnel_defaults(text, scoped=True)
    if len(candidates) != 1 or tunnel_defaults(text, scoped=False):
        check.fail("9.9.9.9 routes through %s and %d utun(s) hold a scoped default (%s): no single tunnel carries "
                   "the traffic" % (route, len(candidates), ", ".join(candidates) or "none"))
        return None
    utun = candidates[0]
    result = runner.run(["/usr/sbin/scutil", "--dns"])
    if command_failed(check, result, "scutil --dns"):
        return None
    on = resolver_interface(result.out)
    if on != utun:
        check.fail("resolver #1 is on %s, not on %s, the utun with the scoped default" % (on, utun))
        return None
    check.say("tunnel layout: scoped (9.9.9.9 routes through %s; scoped default and resolver #1 on %s)" % (route, utun))
    return utun


def resolver_interface(text):
    """The interface named by resolver #1's `if_index : N (name)` line in `scutil --dns`, or None."""
    block = False
    for line in text.splitlines():
        if re.match(r"^resolver #1\s*$", line):
            block = True
            continue
        if line.startswith("resolver #"):
            block = False
        match = re.match(r"^\s*if_index\s*:\s*\d+\s*\((\S+)\)\s*$", line)
        if block and match:
            return match.group(1)
    return None


def first_resolver(text):
    block = False
    for line in text.splitlines():
        if re.match(r"^resolver #1\s*$", line):
            block = True
            continue
        if line.startswith("resolver #"):
            block = False
        match = re.match(r"^\s*nameserver\[0\]\s*:\s*(\S+)\s*$", line)
        if block and match:
            return match.group(1)
    return None


class Probe:
    """One address probe: `address` is the first successful reply that parsed as exactly one address of the asked
    family, or None, which means "could not measure" (never a pass, never a leak). `attempts` keeps every service
    asked, with its exit code, HTTP status (None when curl printed none) and body. `ipv6_reply` is reachability
    evidence even after a failed transfer, kept apart from the accepted measurement."""

    def __init__(self, family):
        self.family, self.address, self.attempts = family, None, []

    @property
    def rc(self):
        """The exit code of the reply that gave the address, else of the last service asked (None if none was)."""
        asked = [attempt for attempt in self.attempts if not attempt.get("skipped")]
        return asked[-1]["rc"] if asked else None

    @property
    def replied(self):
        """True when any service answered at all (curl exit 0): a reply over IPv6 means IPv6 reached out."""
        return any(attempt["rc"] == 0 for attempt in self.attempts)

    @property
    def ipv6_reply(self):
        """The first IPv6 body received, whatever curl's exit or HTTP status; never an accepted measurement."""
        for attempt in self.attempts:
            address = parse_address(6, attempt["body"])
            if address is not None:
                return address
        return None

    def reasons(self):
        parts = []
        for attempt in self.attempts:
            if attempt.get("skipped"):
                parts.append("%s not asked: no time left" % attempt["url"])
                continue
            part = "%s exit %s" % (attempt["url"], attempt["rc"])
            if attempt["status"] is not None:
                part += " HTTP %s" % attempt["status"]
            part += " body %r" % attempt["body"][:40]
            if attempt["rc"] != 0 and attempt["err"].strip():
                part += " error %r" % attempt["err"].strip()[:60]
            parts.append(part)
        return "; ".join(parts) or "no service asked"

    def unmeasured(self):
        return "could not measure the IPv%d address (%s)" % (self.family, self.reasons())


def parse_address(family, body):
    """The one address of `family` in a plain-text reply, or None: HTML, several lines or other text is no address."""
    text = body.strip()
    if not text or not re.match(r"^[0-9A-Fa-f:.]+$", text):
        return None
    try:
        return str(ipaddress.IPv4Address(text) if family == 4 else ipaddress.IPv6Address(text))
    except ValueError:
        return None


def split_status(out):
    """curl's output split into (body, HTTP status): the status is the last line curl's --write-out added, if any."""
    match = re.search(r"\n?%s(\d{3})\n?$" % re.escape(HTTP_MARK), out)
    if not match:
        return out, None
    return out[:match.start()], match.group(1)


def probe(runner, family, max_time, timeout=None):
    """Ask PROBE_URLS in order with `curl -<family>` until one reply is exactly one address of that family.

    Each request has its own --max-time of at most `max_time` (as one curl had before) and, when the caller gives a
    `timeout`, a subprocess timeout too (exit 124). The whole probe stays within `max_time` and `timeout`: a later
    service is asked only with the time left, at least one whole second, else it is recorded as not asked."""
    result = Probe(family)
    start = runner.monotonic()
    budget = max_time if timeout is None else min(max_time, timeout)
    for url in PROBE_URLS:
        remaining = budget - (runner.monotonic() - start)
        if remaining < 1:
            result.attempts.append({"url": url, "skipped": True, "rc": None, "status": None, "body": "", "err": ""})
            continue
        run = runner.run(["/usr/bin/curl", "-%d" % family, "-sS", "--max-time", str(min(max_time, int(remaining))),
                          "--write-out", "\\n%s%%{http_code}\\n" % HTTP_MARK, url],
                         timeout=None if timeout is None else timeout - (runner.monotonic() - start))
        body, status = split_status(run.out)
        result.attempts.append({"url": url, "rc": run.rc, "status": status, "body": body, "err": run.err})
        address = parse_address(family, body) if run.rc == 0 and status in (None, "200") else None
        if address is not None:
            result.address = address
            break
    return result


def ipv4(text):
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        raise argparse.ArgumentTypeError("not an IPv4 address: %r" % text)


def ipv6_or_none(text):
    if text == "none":
        return text
    try:
        return str(ipaddress.IPv6Address(text))
    except ValueError:
        raise argparse.ArgumentTypeError("not an IPv6 address or none: %r" % text)


def uuid_text(text):
    if not UUID.match(text):
        raise argparse.ArgumentTypeError("not a profile UUID: %r" % text)
    return text.upper()


def window_text(text):
    """The CLI's own window syntax: N s or N m, 60 seconds to 60 minutes (WGEXCLICore.swift cutoverSeconds)."""
    match = re.match(r"^([1-9]\d{0,5})([sm])$", text)
    if not match or not 60 <= int(match.group(1)) * (60 if match.group(2) == "m" else 1) <= 3600:
        raise argparse.ArgumentTypeError("not a window of 60s to 60m: %r" % text)
    return text


def interface_name(text):
    if not re.match(r"^en\d+$", text):
        raise argparse.ArgumentTypeError("not an enN interface: %r" % text)
    return text


# ---- S1, S2 -------------------------------------------------------------------------------------------------------

def s1_into(runner, check, vps4):
    result = probe(runner, 4, 10)
    printed = result.address or ""
    check.say("S1 printed %r, exit=%s" % (printed, result.rc))
    if result.address is None:
        return check.fail("S1 %s" % result.unmeasured())
    if result.address != vps4:
        return check.fail("S1 printed %s, not VPS4 %s: a leak" % (result.address, vps4))
    return True


def s2_into(runner, check, vps6):
    """IPv6 must not reach out (VPS6=none) or must leave through the VPS: an IPv6 address from any service other than
    VPS6 is a leak; with VPS6=none any exit-0 reply or IPv6 body (even after a failed transfer) fails."""
    result = probe(runner, 6, 10)
    printed = result.address or ""
    check.say("S2 printed %r, exit=%s" % (printed, result.rc))
    if vps6 == "none":
        reached = result.ipv6_reply
        if reached is not None:
            return check.fail("S2 received %s although IPv6 must be blocked outside the tunnel: a leak (%s)"
                              % (reached, result.reasons()))
        if result.replied:
            return check.fail("S2 exited 0 with no address although IPv6 must fail (%s)" % result.reasons())
        return True
    if result.address is None:
        return check.fail("S2 %s" % result.unmeasured())
    if result.address != str(ipaddress.IPv6Address(vps6)):
        return check.fail("S2 printed %s, not VPS6 %s: a leak" % (result.address, vps6))
    return True


# ---- S3 DNS capture -----------------------------------------------------------------------------------------------

BANNER_NOISE = re.compile(r"^(tcpdump: verbose output suppressed, use -v\[v\]\.\.\. for full protocol decode"
                          r"|listening on [A-Za-z0-9]+, link-type .*|tcpdump: WARNING: .*)$")


def capture_started(text, interface):
    return re.search(r"^listening on %s, link-type " % re.escape(interface), text, re.M) is not None


def capture_noise(text):
    return [line for line in text.splitlines() if line.strip() and not BANNER_NOISE.match(line)]


def read_file(path):
    """(text, None), or (None, why) when the file cannot be read: a read error is never taken as empty output."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read(), None
    except OSError as error:
        return None, str(error)


def capture_argv(interface):
    return ["/usr/bin/sudo", "-n", "/usr/bin/perl", "-e", "alarm %d; exec @ARGV" % CAPTURE_SECONDS,
            "/usr/sbin/tcpdump", "-n", "-l", "-i", interface, CAPTURE_FILTER]


STOP_GRACE = 5


def stop_capture(runner, check, name, proc):
    """Stops one capture this check spawned, by the pid it recorded: SIGTERM through `sudo -n /bin/kill` (sudo relays it
    to perl and tcpdump), then SIGKILL when it is still running after STOP_GRACE seconds. Prints the final exit."""
    for signal in ("-TERM", "-KILL"):
        if proc.poll() is not None:
            break
        runner.run(["/usr/bin/sudo", "-n", "/bin/kill", signal, str(proc.pid)], timeout=STOP_GRACE)
        proc.wait(STOP_GRACE)
    rc = proc.poll()
    check.say("capture stopped: %s pid %s, final exit %s" % (name, proc.pid, render(rc)))
    if rc is None:
        check.fail("the %s capture (pid %s) is still running after SIGTERM and SIGKILL" % (name, proc.pid))
    return rc


def dns_capture_into(runner, check, phys, utun, dnsip, workdir):
    """S3: both captures start, both still run when the five lookups end, both end at their alarm, no message other than
    banners, every capture file readable."""
    if not phys or not utun or phys == utun or not utun.startswith("utun"):
        return check.fail("physical %r and tunnel %r must be set, different, and the tunnel a utun" % (phys, utun))
    sudo = runner.run(["/usr/bin/sudo", "-n", "/usr/bin/true"])
    if sudo.rc != 0:
        return check.fail("sudo has no cached ticket: run `sudo -v` in this terminal first")
    os.makedirs(workdir, exist_ok=True)
    paths = {name: (os.path.join(workdir, name + ".txt"), os.path.join(workdir, name + ".err"))
             for name in ("physical", "tunnel")}
    origin = runner.monotonic()
    elapsed = lambda: runner.monotonic() - origin
    procs = {"physical": runner.spawn(capture_argv(phys), *paths["physical"]),
             "tunnel": runner.spawn(capture_argv(utun), *paths["tunnel"])}
    check.say("capture pids: physical=%s tunnel=%s files=%s" % (procs["physical"].pid, procs["tunnel"].pid, workdir))
    interfaces = {"physical": phys, "tunnel": utun}
    started, unreadable = {}, {}
    while True:
        for name in procs:
            if name in started:
                continue
            text, error = read_file(paths[name][1])
            if error:
                unreadable[name] = error
            elif capture_started(text, interfaces[name]):
                started[name] = elapsed()
        remaining = 5 - elapsed()
        if len(started) == len(procs) or remaining <= 0:
            break
        runner.sleep(min(0.25, remaining))
    for name in procs:
        if name not in started:
            why = (": cannot read %s: %s" % (paths[name][1], unreadable[name])) if name in unreadable else ""
            check.fail("the %s capture on %s did not start within five seconds%s" % (name, interfaces[name], why))
    names, window = [], None
    if len(started) == len(procs):
        first = elapsed()
        for _ in range(LOOKUPS):
            name = "wgex-s3-%s.example.net" % secrets.token_hex(4)
            names.append(name)
            result = runner.run(["/usr/bin/dig", "+time=2", "+tries=1", "A", name], timeout=15)
            if result.rc != 0 or "->>HEADER<<-" not in result.out:
                check.fail("dig %s exited %s without an answer header" % (name, result.rc))
        window = (first, elapsed())
        for name, proc in procs.items():
            # Both observation windows must cover every lookup: started before the first, still running after the last.
            if proc.poll() is not None:
                check.fail("the %s capture ended before the lookups finished (+%.1fs)" % (name, window[1]))
        deadline = CAPTURE_SECONDS + 10
        while not all(proc.poll() is not None for proc in procs.values()) and elapsed() < deadline:
            runner.sleep(min(0.25, deadline - elapsed()))
    for name, proc in procs.items():
        rc = proc.poll()
        if rc is None:
            if window is not None:
                check.fail("the %s capture (pid %s) was still running after its bound" % (name, proc.pid))
            rc = stop_capture(runner, check, name, proc)
        elif window is not None and rc not in ALARM_EXITS:
            check.fail("the %s capture exited %s, not at its %d-second alarm" % (name, rc, CAPTURE_SECONDS))
        check.say("capture exit: %s=%s" % (name, render(rc)))
        if name in started and window is not None:
            check.say("window: %s +%.1fs to after +%.1fs; lookups +%.1fs to +%.1fs" % (
                name, started[name], window[1], window[0], window[1]))
        text, error = read_file(paths[name][1])
        if error:
            check.fail("cannot read the %s capture's messages %s: %s" % (name, paths[name][1], error))
        elif capture_noise(text):
            check.fail("the %s capture printed: %s" % (name, capture_noise(text)[0][:160]))
    if window is None:
        return False
    physical_text, error = read_file(paths["physical"][0])
    if error:
        check.fail("cannot read the physical capture %s: %s" % (paths["physical"][0], error))
    tunnel_text, error = read_file(paths["tunnel"][0])
    if error:
        check.fail("cannot read the tunnel capture %s: %s" % (paths["tunnel"][0], error))
    if physical_text is not None:
        physical_lines = [line for line in physical_text.splitlines() if line.strip()]
        check.say("physical lines: %d" % len(physical_lines))
        if physical_lines:
            check.fail("%d DNS packet line(s) on the physical interface: a leak" % len(physical_lines))
    if tunnel_text is not None:
        seen = {name for name in names
                if re.search(r" > %s\.53: .* A\? %s\. " % (re.escape(dnsip), re.escape(name)), tunnel_text)}
        check.say("utun queries: %d of %d" % (len(seen), LOOKUPS))
        if len(seen) != LOOKUPS:
            check.fail("only %d of %d lookups reached %s on %s" % (len(seen), LOOKUPS, dnsip, utun))
    scutil = runner.run(["/usr/sbin/scutil", "--dns"])
    if not command_failed(check, scutil, "scutil --dns"):
        resolver = first_resolver(scutil.out)
        check.say("resolver #1: %s" % resolver)
        if resolver != dnsip:
            check.fail("resolver #1 is %s, not %s" % (resolver, dnsip))
    return not check.problems


def default_workdir(tag):
    base = os.environ.get("TMPDIR") or "/tmp"
    return os.path.join(base, "wgex-sitting-%s-%s" % (tag, secrets.token_hex(3)))


# ---- subcommands --------------------------------------------------------------------------------------------------

def cmd_ready(args, runner, out):
    """Loads the helper and, given the terminal's variables, checks their shape (a placeholder fails as usage)."""
    check = Check("ready", out)
    check.say("python %s; cli %s" % (sys.version.split()[0], args.cli))
    for name in ("vps4", "vps6", "phys", "dns", "profile", "eth"):
        value = getattr(args, name)
        if value is not None:
            check.say("%s=%s ok" % (name, value))
    return check.verdict("checks.py loaded")


def parse_expect(texts):
    expect = {}
    for text in texts:
        key, sep, values = text.partition("=")
        if not sep or not key:
            raise SystemExit("--expect takes KEY=VALUE[|VALUE...], got %r" % text)
        expect[key] = values.split("|")
    return expect


def cmd_status(args, runner, out):
    check = Check("status", out)
    expect = parse_expect(args.expect)
    doc, problem = read_status(runner, args.cli)
    if problem:
        check.fail(problem)
        return check.verdict("")
    for key in list(args.keys) + [key for key in expect if key not in args.keys]:
        try:
            text = render(lookup(doc, key))
        except KeyError:
            check.fail("the reply has no %s" % key)
            continue
        check.say("%s=%s" % (key, text))
        if key in expect and text not in expect[key]:
            check.fail("%s=%s, expected %s" % (key, text, " or ".join(expect[key])))
    return check.verdict("valid status" + (", every expected value matched" if expect else ""))


def cmd_doctor(args, runner, out):
    check = Check("doctor", out)
    doc, problem = cli_json(runner, args.cli, ["doctor"])
    if problem:
        check.fail(problem)
    else:
        check.say("daemonReachable=%s secureInstall=%s" % (render(doc.get("daemonReachable")), doc.get("secureInstall")))
        if doc.get("daemonReachable") is not True:
            check.fail("the daemon is not reachable")
        if doc.get("secureInstall") != "verified":
            check.fail("secureInstall is %s, not verified" % doc.get("secureInstall"))
    return check.verdict("daemon reachable and secure install verified")


def cmd_physif(args, runner, out):
    check = Check("physif", out)
    name = read_physical(runner, check)
    if name:
        check.say("physical=%s" % name)
        if args.expect and name != args.expect:
            check.fail("the physical interface is %s, not %s" % (name, args.expect))
    return check.verdict("physical interface %s" % name)


def hardware_ports(text):
    ports, port = {}, None
    for line in text.splitlines():
        if line.startswith("Hardware Port: "):
            port = line[len("Hardware Port: "):].strip()
        elif line.startswith("Device: ") and port is not None:
            ports[line[len("Device: "):].strip()] = port
            port = None
    return ports


def cmd_ethernet(args, runner, out):
    """Lists the hardware ports, or checks that the adapter the maintainer named is wired (not Wi-Fi or a bridge) with an active link."""
    check = Check("ethernet", out)
    result = runner.run(["/usr/sbin/networksetup", "-listallhardwareports"])
    if command_failed(check, result, "networksetup"):
        return check.verdict("")
    ports = hardware_ports(result.out)
    if args.device is None:
        for device, port in sorted(ports.items()):
            check.say("%s: %s" % (device, port))
        return check.verdict("%d hardware ports listed" % len(ports))
    port = ports.get(args.device)
    check.say("%s is %r" % (args.device, port))
    if port is None:
        check.fail("%s is not a hardware port" % args.device)
    elif port == "Wi-Fi" or port.startswith(("Thunderbolt Bridge", "Bluetooth")):
        check.fail("%s is %s, not a wired Ethernet adapter" % (args.device, port))
    else:
        link = runner.run(["/sbin/ifconfig", args.device])
        if not command_failed(check, link, "ifconfig"):
            status = re.search(r"^\s*status:\s*(\S+)", link.out, re.M)
            check.say("status: %s" % (status.group(1) if status else None))
            if not status or status.group(1) != "active":
                check.fail("%s has no active link: connect the cable" % args.device)
    return check.verdict("%s is a wired adapter with an active link" % args.device)


def cmd_direct(args, runner, out):
    """S6 exclude cycle: with the tunnel down by rule, IPv4 leaves directly, so the address is not VPS4."""
    check = Check("direct", out)
    result = probe(runner, 4, 10)
    address = result.address
    check.say("printed %r, exit=%s" % (address or "", result.rc))
    if address is None:
        check.fail("no direct IPv4 address: %s" % result.unmeasured())
    elif address == args.vps4:
        check.fail("the address is VPS4: the tunnel still carries traffic")
    return check.verdict("direct address %s, not VPS4" % address)


def cmd_s1(args, runner, out):
    check = Check("s1", out)
    s1_into(runner, check, args.vps4)
    return check.verdict("IPv4 leaves through the VPS (%s)" % args.vps4)


def cmd_s2(args, runner, out):
    check = Check("s2", out)
    s2_into(runner, check, args.vps6)
    return check.verdict("IPv6 blocked outside the tunnel" if args.vps6 == "none" else "IPv6 through the VPS")


def cmd_s3(args, runner, out):
    """WGEX's tunnel, unscoped layout only (read_tunnel): a scoped tunnel default, which WGEX never installs, fails."""
    check = Check("s3", out)
    utun = read_tunnel(runner, check, args.phys, scoped=False)
    check.say("physical=%s tunnel=%s" % (args.phys, utun))
    if not check.problems:
        dns_capture_into(runner, check, args.phys, utun, args.dns, args.workdir or default_workdir("s3"))
    return check.verdict("no DNS on the physical interface, %d lookups to %s on the tunnel" % (LOOKUPS, args.dns))


def cmd_baseline(args, runner, out):
    """Rollback baseline: S1 and S3 against the official tunnel, in either layout (read_tunnel)."""
    check = Check("baseline", out)
    phys = read_physical(runner, check)
    utun = read_tunnel(runner, check, phys, scoped=True) if phys else None
    check.say("physical=%s tunnel=%s" % (phys, utun))
    if not check.problems:
        s1_into(runner, check, args.vps4)
        dns_capture_into(runner, check, phys, utun, args.dns, args.workdir or default_workdir("baseline"))
    return check.verdict("the official tunnel carries IPv4 and DNS")


def cmd_s123(args, runner, out):
    """WGEX's tunnel, unscoped layout only, as s3."""
    check = Check("s123", out)
    phys = read_physical(runner, check)
    utun = read_tunnel(runner, check, phys, scoped=False)
    check.say("physical=%s tunnel=%s" % (phys, utun))
    if args.phys and phys != args.phys:
        check.fail("the physical interface is %s, not %s" % (phys, args.phys))
    if not check.problems:
        s1_into(runner, check, args.vps4)
        s2_into(runner, check, args.vps6)
        dns_capture_into(runner, check, phys, utun, args.dns, args.workdir or default_workdir("s123"))
    doc, problem = read_status(runner, args.cli)
    if problem:
        check.fail(problem)
    else:
        check.say("protection=%s" % doc["protection"])
        if doc["protection"] != "protected":
            check.fail("protection is %s, not protected" % doc["protection"])
    return check.verdict("S1, S2 and S3 hold on %s" % phys)


def cmd_leakwatch(args, runner, out):
    """IPv4 watch bounded by elapsed time; a foreign address fails at once, and VPS4 must be back before the end."""
    check = Check("leakwatch", out)
    start = runner.monotonic()
    states = []
    while True:
        remaining = args.window - (runner.monotonic() - start)
        if remaining < 1:
            break
        result = probe(runner, 4, max(1, min(3, int(remaining))), timeout=remaining)
        offset = runner.monotonic() - start
        printed = result.address
        if printed is not None and printed != args.vps4:
            state = "leak"
        elif printed == args.vps4 and offset <= args.window:
            state = "ok"
        else:
            state = "down"  # "could not measure" is an outage sample, never a leak
        states.append((offset, state))
        late = " (after the window)" if offset > args.window else ""
        shown = printed if printed else "FAIL exit=%s %s" % (result.rc, result.unmeasured())
        check.say("%s +%3ds %s%s" % (runner.clock(), int(offset), shown, late))
        if state == "leak":
            check.fail("%s printed at +%ds: a leak" % (printed, int(offset)))
            break
        remaining = args.window - (runner.monotonic() - start)
        if remaining > 0:
            runner.sleep(min(args.interval, remaining, 2))
    elapsed = runner.monotonic() - start
    down = [offset for offset, state in states if state == "down"]
    if not states:
        check.fail("no probe ran")
    elif not check.problems and states[-1][1] != "ok":
        check.fail("VPS4 did not return within %d seconds" % args.window)
    if check.problems:
        return check.verdict("")
    if down:
        recovered = next(offset for offset, state in states if state == "ok" and offset > down[-1])
        why = "outage from +%ds, VPS4 back at +%ds, within %d seconds" % (int(down[0]), int(recovered), args.window)
    else:
        why = "no outage seen; VPS4 throughout %d seconds" % int(elapsed)
    return check.verdict("recovered: " + why)


def cmd_phasewatch(args, runner, out):
    """S6: the phase reaches `active` within the window (include), or stays `idle` for all of it (exclude)."""
    check = Check("phasewatch", out)
    start = runner.monotonic()
    reached = False
    samples = 0
    while runner.monotonic() - start < args.window:
        doc, problem = read_status(runner, args.cli, timeout=args.window - (runner.monotonic() - start))
        offset = int(runner.monotonic() - start)
        if problem:
            check.fail("at +%ds: %s" % (offset, problem))
            break
        if runner.monotonic() - start > args.window:
            if args.hold:
                # A hold proves the phase for the whole window; a reply past the deadline leaves its end unproven.
                check.fail("status answered at +%ds, after the %d-second window (phase=%s)" % (
                    offset, args.window, doc["phase"]))
                break
            check.say("%s +%3ds phase=%s (after the window, not counted)" % (runner.clock(), offset, doc["phase"]))
            break
        samples += 1
        check.say("%s +%3ds phase=%s" % (runner.clock(), offset, doc["phase"]))
        if args.until and doc["phase"] == args.until:
            reached = True
            break
        if args.hold and doc["phase"] != args.hold:
            check.fail("phase=%s at +%ds; it must stay %s" % (doc["phase"], offset, args.hold))
            break
        remaining = args.window - (runner.monotonic() - start)
        if remaining > 0:
            runner.sleep(min(2, remaining))
    if not check.problems:
        if args.until and not reached:
            check.fail("phase never reached %s within %d seconds" % (args.until, args.window))
        if samples == 0:
            check.fail("no status sample")
    if args.until:
        return check.verdict("phase reached %s with no click" % args.until)
    return check.verdict("phase stayed %s for %d seconds (%d samples)" % (args.hold, args.window, samples))


def cmd_arm(args, runner, out):
    check = Check("arm", out)
    doc, problem = cli_json(runner, args.cli, ["on-demand", args.profile, "on"])
    if problem:
        check.fail(problem)
    elif doc.get("result") != "armed":
        check.fail("on-demand on replied %s, not armed" % render(doc.get("result")))
    return check.verdict("on-demand armed for %s" % args.profile)


def cmd_disarm(args, runner, out):
    """The disarm exits 0, then a valid status shows no armed selection; prints armed-empty or NOT-DISARMED."""
    check = Check("disarm", out)
    doc, problem = cli_json(runner, args.cli, ["on-demand", args.profile, "off"])
    if problem:
        check.fail(problem)
    elif doc.get("result") != "disarmed":
        check.fail("on-demand off replied %s, not disarmed" % render(doc.get("result")))
    status, problem = read_status(runner, args.cli)
    if problem:
        check.fail(problem)
    else:
        armed = armed_profile(status)
        check.say("onDemand.armedProfileID=%s" % render(armed))
        if armed is not None:
            check.fail("on-demand is still armed for %s" % armed)
    check.say("armed-empty" if not check.problems else "NOT-DISARMED")
    return check.verdict("disarmed and no armed selection")


def cmd_abort(args, runner, out):
    """`wgex cutover abort`; success when the trial is rolled back with a completed reason, or no trial exists."""
    check = Check("abort", out)
    result_doc, problem = cli_json(runner, args.cli, ["cutover", "abort"])
    if problem:
        check.fail(problem)
    status, problem = read_status(runner, args.cli)
    if problem:
        check.fail(problem)
    else:
        cutover = status["cutover"]
        check.say("cutover.state=%s cutover.reason=%s activeProfileID=%s phase=%s protection=%s failures=%s" % (
            cutover["state"], render(cutover.get("reason")), render(status["activeProfileID"]), status["phase"],
            status["protection"], render(status["cutoverRollbackFailures"])))
        if cutover["state"] not in ("none", "rolledBack"):
            check.fail("cutover.state is %s after abort" % cutover["state"])
        if status["activeProfileID"] is not None:
            check.fail("a profile is still active")
        if status["operationInFlight"]:
            check.fail("an operation is still in flight")
    why = "no trial exists"
    if not check.problems and status["cutover"]["state"] == "rolledBack":
        why = "trial rolled back (%s)" % status["cutover"]["reason"]
    return check.verdict(why)


# Lines log(1) prints before the header: the predicate it applies, and the note on skipped levels.
LOG_PREAMBLE = re.compile(r"^(Filtering the log data using .*|Skipping info and debug messages, pass --info and/or "
                          r"--debug to include\.)$")


def trial_reply(check, runner, cli, args, want):
    """`wgex cutover ... --json`: exit 0, a valid status object with no `error`, and cutover.state WANT."""
    doc, problem = cli_json(runner, cli, args)
    if problem:
        check.fail(problem)
        return None
    problems = status_problems(doc)
    if problems:
        check.fail("invalid status: " + "; ".join(problems))
        return None
    cutover = doc["cutover"]
    check.say("cutover.state=%s deadline=%s reason=%s activeProfileID=%s phase=%s protection=%s" % (
        cutover["state"], render(cutover.get("deadline")), render(cutover.get("reason")),
        render(doc["activeProfileID"]), doc["phase"], doc["protection"]))
    if cutover["state"] != want:
        check.fail("cutover.state is %s, not %s" % (cutover["state"], want))
    return doc


def cmd_cutover_start(args, runner, out):
    """C2: `wgex cutover start PROFILE --confirm-within WINDOW --json`; exit 0 and an armed trial for PROFILE."""
    check = Check("cutover-start", out)
    doc = trial_reply(check, runner, args.cli, ["cutover", "start", args.profile, "--confirm-within", args.within],
                      "armed")
    if doc is not None and (doc["activeProfileID"] or "").upper() != args.profile:
        check.fail("the active profile is %s, not %s" % (render(doc["activeProfileID"]), args.profile))
    return check.verdict("trial armed for %s" % args.profile)


def cmd_cutover_confirm(args, runner, out):
    """C3: `wgex cutover confirm --json`; exit 0 and a confirmed trial. Exit 8 means the trial already rolled back."""
    check = Check("cutover-confirm", out)
    trial_reply(check, runner, args.cli, ["cutover", "confirm"], "confirmed")
    return check.verdict("trial confirmed")


BOOTOUT_ABSENT = 113  # launchctl print: "Could not find service"
BOOTOUT_WAIT = 20
BOOTOUT_POLL = 1


def cmd_bootout(args, runner, out):
    """Rollback without a verified disarm: boot out the WGEX daemon, unconditionally, then prove it is not loaded."""
    check = Check("bootout", out)
    runner.run(["/usr/bin/sudo", "-n", "/bin/launchctl", "bootout", DAEMON_SERVICE], timeout=60)
    deadline = runner.monotonic() + BOOTOUT_WAIT
    printed = None
    while True:
        remaining = deadline - runner.monotonic()
        if printed is not None and remaining <= 0:
            break
        # The whole wait ends within BOOTOUT_WAIT: each print and each sleep is capped to what is left.
        printed = runner.run(["/usr/bin/sudo", "-n", "/bin/launchctl", "print", DAEMON_SERVICE],
                             timeout=min(30, remaining))
        # launchctl print can still list the job (exit 0) just after a successful bootout (DEC-031): poll for absence.
        if printed.rc != 0:
            break
        left = deadline - runner.monotonic()
        if left <= 0:
            break
        runner.sleep(min(BOOTOUT_POLL, left))
    if printed.rc == 0:
        detail = (printed.out or printed.err).strip().splitlines()
        check.fail("%s is still loaded after %ds%s" % (DAEMON_SERVICE, BOOTOUT_WAIT,
                                                        (": " + detail[-1][:160]) if detail else ""))
    elif printed.rc != BOOTOUT_ABSENT:
        detail = (printed.err or printed.out).strip().splitlines()
        check.fail("launchctl print exited %s%s" % (printed.rc, (": " + detail[-1][:160]) if detail else ""))
    else:
        check.say("not-loaded")
    return check.verdict("%s is not loaded" % DAEMON_SERVICE)


def cmd_keylog(args, runner, out):
    check = Check("keylog", out)
    if not re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$", args.since):
        check.fail("--since must be YYYY-MM-DD HH:MM:SS, got %r" % args.since)
        return check.verdict("")
    result = runner.run(["/usr/bin/log", "show", "--start", args.since, "--style", "compact",
                         "--predicate", 'process == "WGEXDaemon"'])
    if not command_failed(check, result, "log show"):
        lines = result.out.splitlines()
        while lines and LOG_PREAMBLE.match(lines[0]):
            lines = lines[1:]
        if not lines or not lines[0].startswith("Timestamp") or "Process[PID:TID]" not in lines[0]:
            check.fail("log show printed no compact header: %s" % (result.err.strip() or "empty output")[:160])
        else:
            for signal in KEY_SIGNALS:
                count = sum(1 for line in lines[1:] if signal in line)
                check.say("%s: %d" % (signal, count))
                if count:
                    check.fail("%d line(s) name %s since %s" % (count, signal, args.since))
    return check.verdict("no key-denial line since %s" % args.since)


def parse_right(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        raw = value.encode()
        try:
            return json.loads(raw)
        except ValueError:
            return plistlib.loads(raw)
    raise ValueError("rightDefinition is neither an object nor text")


# DEC-027: the policy keys compared with AUTH-REAL's record, the same keys M03-T11 compares with the M01-T02 fixture.
# `shared` and `timeout` may be absent, and then must be absent on both sides. Every other key (`comment`, `version`,
# authd's `created`, `modified`, `identifier` and `requirement`, which differ because AUTH-REAL's right came from the
# Lab-signed daemon) is printed for information only.
RIGHT_POLICY_KEYS = ("class", "rule", "shared", "timeout")
ABSENT = object()


def cmd_e3(args, runner, out):
    check = Check("e3", out)
    try:
        with open(args.recorded, encoding="utf-8") as handle:
            recorded = parse_right(json.load(handle)["rightDefinition"])
    except (OSError, ValueError, KeyError, TypeError, plistlib.InvalidFileException) as error:
        check.fail("cannot read rightDefinition from %s: %s" % (args.recorded, error))
        return check.verdict("")
    result = runner.run(["/usr/bin/security", "authorizationdb", "read", args.right])
    if not command_failed(check, result, "security authorizationdb read"):
        try:
            live = plistlib.loads(result.out.encode())
        except (ValueError, plistlib.InvalidFileException):
            live = None
        if not isinstance(live, dict) or not isinstance(recorded, dict):
            check.fail("the right is not a dictionary")
        else:
            differences = [key for key in RIGHT_POLICY_KEYS if live.get(key, ABSENT) != recorded.get(key, ABSENT)]
            if live.get("class", ABSENT) is ABSENT or live.get("rule", ABSENT) is ABSENT:
                differences = differences or ["class or rule absent"]
            for key in sorted((set(live) | set(recorded)) - set(RIGHT_POLICY_KEYS)):
                check.say("info %s: this Mac %s; AUTH-REAL %s" % (
                    key, render(live.get(key)) if key in live else "absent",
                    render(recorded.get(key)) if key in recorded else "absent"))
            check.say("equal" if not differences else "DIFFERENT: %s" % ", ".join(differences))
            if differences:
                check.fail("the right differs from AUTH-REAL in %s" % ", ".join(differences))
    return check.verdict("class, rule, shared and timeout equal AUTH-REAL's rightDefinition")


def cmd_profile(args, runner, out):
    """E4 item 1: exactly one profile named NAME, its UUID valid, its public key the one added on the VPS."""
    check = Check("profile", out)
    matches = []
    try:
        entries = sorted(os.listdir(args.dir))
    except OSError as error:
        check.fail("cannot list %s: %s" % (args.dir, error))
        return check.verdict("")
    for entry in entries:
        if not entry.endswith(".json"):
            continue
        try:
            with open(os.path.join(args.dir, entry), encoding="utf-8") as handle:
                profile = json.load(handle)["profile"]
        except (OSError, ValueError, KeyError, TypeError):
            continue
        if isinstance(profile, dict) and profile.get("name") == args.name:
            matches.append((entry[:-len(".json")], profile))
    check.say("matches=%d" % len(matches))
    if len(matches) != 1:
        check.fail("%d profiles are named %r" % (len(matches), args.name))
        return check.verdict("")
    uuid, profile = matches[0]
    if not UUID.match(uuid) or str(profile.get("id", "")).upper() != uuid.upper():
        check.fail("the file name %r is not the profile's UUID" % uuid)
    key = (profile.get("interface") or {}).get("publicKey") if isinstance(profile.get("interface"), dict) else None
    if key != args.pubkey:
        check.fail("the saved public key is not the key added on the VPS")
    if not check.problems:
        check.say("PROFILE=%s" % uuid.upper())
    return check.verdict("one %r profile, public key matches" % args.name)


def wireguard_services(text):
    return [line for line in text.splitlines() if "com.wireguard.macos" in line]


def official_app_quit(runner, check):
    """`pgrep -x WireGuard` exits 1: the official app is not running. Exit 0 (it runs) or any other exit fails."""
    running = runner.run(["/usr/bin/pgrep", "-x", "WireGuard"])
    if running.rc == 0:
        check.fail("WireGuard is still running (pid %s)" % " ".join(running.out.split()))
    elif running.rc != 1:
        check.fail("pgrep exited %s" % running.rc)


def cmd_c1(args, runner, out):
    """No tunnel in either layout: route get names PHYS and no utun holds a default route, scoped or unscoped."""
    check = Check("c1", out)
    result = runner.run(["/usr/sbin/scutil", "--nc", "list"])
    if not command_failed(check, result, "scutil --nc list"):
        services = wireguard_services(result.out)
        check.say("official configurations: %d" % len(services))
        if not services:
            check.fail("no official WireGuard configuration is listed")
        for line in services:
            if "(Disconnected)" not in line:
                check.fail("still not disconnected: %s" % " ".join(line.split())[:160])
    official_app_quit(runner, check)
    # An unscoped utun default would win `route get`; a scoped one leaves `route get` on PHYS while it carries traffic.
    route = read_route_interface(runner, check)
    check.say("route=%s" % route)
    if route and route != args.phys:
        check.fail("9.9.9.9 routes through %s, not %s" % (route, args.phys))
    text = read_netstat(runner, check)
    if text is not None:
        utuns = tunnel_defaults(text)
        check.say("tunnel defaults: %s" % (", ".join(utuns) or "none"))
        if utuns:
            check.fail("a tunnel still holds a default route: %s" % ", ".join(utuns))
    return check.verdict("official tunnel off, configurations kept, route on %s" % args.phys)


def cmd_s8(args, runner, out):
    check = Check("s8", out)
    result = runner.run(["/usr/sbin/scutil", "--nc", "list"])
    if not command_failed(check, result, "scutil --nc list"):
        services = wireguard_services(result.out)
        check.say("official configurations: %d" % len(services))
        if not services:
            check.fail("the official configurations are gone")
        for line in services:
            if "(Disconnected)" not in line:
                check.fail("an official configuration is not disconnected")
    # M04 Definition of Done (S8): the official app stays quit after C1, so WGEX alone carries the tunnel.
    official_app_quit(runner, check)
    status, problem = read_status(runner, args.cli)
    if problem:
        check.fail(problem)
    else:
        check.say("activeProfileID=%s cutover.state=%s" % (render(status["activeProfileID"]), status["cutover"]["state"]))
        if (status["activeProfileID"] or "").upper() != args.profile:
            check.fail("the active profile is not %s" % args.profile)
        if status["cutover"]["state"] != "confirmed":
            check.fail("cutover.state is %s, not confirmed" % status["cutover"]["state"])
    s1_into(runner, check, args.vps4)
    return check.verdict("WGEX carries the daily tunnel; official app quit, its configurations kept")


def cmd_airdrop(args, runner, out):
    """S7: `mark` records the names in Downloads; `check` lists the names that appeared since. Names, not times, because
    a received photo can keep its original modification date."""
    check = Check("airdrop", out)
    try:
        names = sorted(entry.name for entry in os.scandir(args.downloads) if entry.is_file())
        if args.action == "mark":
            with open(args.mark, "w", encoding="utf-8") as handle:
                json.dump(names, handle)
        else:
            with open(args.mark, encoding="utf-8") as handle:
                before = set(json.load(handle))
    except (OSError, ValueError) as error:
        check.fail("cannot read or write %s or %s: %s" % (args.downloads, args.mark, error))
        return check.verdict("")
    if args.action == "mark":
        check.say("mark=%s (%d files in %s)" % (args.mark, len(names), args.downloads))
        return check.verdict("mark written; send the photo now")
    received = [name for name in names if name not in before]
    for name in received:
        check.say("received: %s" % name)
    if not received:
        check.fail("no new file in %s" % args.downloads)
    return check.verdict("%d file(s) received" % len(received))


def cmd_addresses(args, runner, out):
    """Prerequisites: the exit addresses seen through the official tunnel, to write down as VPS4 and VPS6."""
    check = Check("addresses", out)
    v4 = probe(runner, 4, 10)
    if v4.address is None:
        check.fail("no IPv4 address: %s" % v4.unmeasured())
    else:
        check.say("VPS4=%s" % v4.address)
    v6 = probe(runner, 6, 10)
    check.say("IPv6 seen: %s (exit %s)" % (v6.address or "none", v6.rc))
    if v6.address is None:
        check.say("IPv6: %s" % v6.unmeasured())
    return check.verdict("IPv4 exit address read")


PROTOCOL_FILE = "Packages/WGEXBackendMac/Sources/WGEXDaemonProtocol/Messages/Envelope.swift"


def cmd_protocol(args, runner, out):
    """E2 step 4: the candidate's one shared protocol constant is 8 (ADR-030), read from the candidate worktree."""
    check = Check("protocol", out)
    try:
        with open(os.path.join(args.worktree, PROTOCOL_FILE), encoding="utf-8") as handle:
            count = sum(1 for line in handle if re.search(r"\bcurrentProtocolVersion = 8\b", line))
    except OSError as error:
        check.fail("cannot read %s: %s" % (PROTOCOL_FILE, error))
        return check.verdict("")
    check.say("%s: %d" % (PROTOCOL_FILE, count))
    if count != 1:
        check.fail("currentProtocolVersion = 8 appears %d times, not once" % count)
    return check.verdict("protocol 8 on both sides")


# ---- E1 and E2 ----------------------------------------------------------------------------------------------------

def select_identity(runner, check, team):
    """The one Apple Development leaf in the maintainer's team (Config/Local.xcconfig): (sha1, name). Prints the name only; the hash stays in memory."""
    listing = runner.run(["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"])
    if command_failed(check, listing, "security find-identity"):
        return None
    found = set()
    for digest, name in re.findall(r'(?m)^\s*\d+\)\s+([0-9A-Fa-f]{40})\s+"([^"]+)"\s*$', listing.out):
        if not name.startswith("Apple Development:"):
            continue
        certs = runner.run(["/usr/bin/security", "find-certificate", "-a", "-p", "-c", name])
        if command_failed(check, certs, "security find-certificate"):
            return None
        for pem in re.findall(r"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----", certs.out, re.S):
            der = base64.b64decode(re.sub(r"\s+", "", pem))
            if hashlib.sha1(der).hexdigest().upper() != digest.upper():
                continue
            subject = runner.run(["/usr/bin/openssl", "x509", "-inform", "DER", "-noout", "-subject", "-nameopt",
                                  "RFC2253"], data=der)
            if command_failed(check, subject, "openssl x509"):
                return None
            text = subject.out.strip()
            text = text[len("subject="):].strip() if text.startswith("subject=") else text
            if re.search(r"(?:^|,)OU=" + re.escape(team) + r"(?:,|$)", text):
                found.add((digest.upper(), name))
    if len(found) != 1:
        check.fail("expected exactly one Apple Development leaf in team %s, found %d" % (team, len(found)))
        return None
    return next(iter(found))


LOCAL_CONFIG = "Config/Local.xcconfig"


def copy_local_config(repo, rc_path):
    """The git-ignored local config is not in the candidate worktree; copy the maintainer's, privately."""
    target = os.path.join(rc_path, LOCAL_CONFIG)
    source = os.path.join(repo, LOCAL_CONFIG)
    if os.path.exists(target) or not os.path.isfile(source):
        return
    os.makedirs(os.path.dirname(target), exist_ok=True)
    shutil.copyfile(source, target)
    os.chmod(target, 0o600)


def local_setting(rc_path, name, check):
    """The one value of `name` in the candidate's Config/Local.xcconfig, which the build script also reads."""
    path = os.path.join(rc_path, LOCAL_CONFIG)
    try:
        with open(path, encoding="utf-8") as handle:
            found = re.findall(r"(?m)^[ \t]*" + name + r"[ \t]*=[ \t]*(.*?)[ \t]*$", handle.read())
    except (OSError, UnicodeDecodeError) as error:
        check.fail("cannot read %s: %s" % (path, error))
        return None
    if len(found) != 1:
        check.fail("%s defines %d %s values, not one" % (LOCAL_CONFIG, len(found), name))
        return None
    return found[0]


def codesign_fields(text):
    lines = text.splitlines()
    authorities = [line[len("Authority="):] for line in lines if line.startswith("Authority=")]
    get = lambda key: next((line[len(key) + 1:] for line in lines if line.startswith(key + "=")), None)
    return {"Identifier": get("Identifier"), "TeamIdentifier": get("TeamIdentifier"), "CDHash": get("CDHash"),
            "Authority": authorities}


def cmd_e1(args, runner, out):
    check = Check("e1", out)
    rc_path = args.worktree
    if os.environ.get("CLEAN_DEV_MODE") != "external":
        check.fail("CLEAN_DEV_MODE is %r, not external" % os.environ.get("CLEAN_DEV_MODE"))
        return check.verdict("")
    tag = runner.run(["/usr/bin/git", "-C", args.repo, "rev-parse", CANDIDATE_TAG + "^{commit}"])
    if tag.rc != 0:
        check.fail("tag %s not found; the lead tags it" % CANDIDATE_TAG)
        return check.verdict("")
    if not os.path.exists(rc_path):
        added = runner.run(["/usr/bin/git", "-C", args.repo, "worktree", "add", "--detach", rc_path, CANDIDATE_TAG])
        if command_failed(check, added, "git worktree add"):
            return check.verdict("")
    head = runner.run(["/usr/bin/git", "-C", rc_path, "rev-parse", "HEAD"])
    if command_failed(check, head, "git rev-parse HEAD"):
        return check.verdict("")
    if head.out.strip() != tag.out.strip():
        check.fail("the worktree %s is not at %s" % (rc_path, CANDIDATE_TAG))
        return check.verdict("")
    check.say("candidate-ok %s" % head.out.strip())
    if command_failed(check, runner.run(["just", "engine"], cwd=rc_path, interactive=True), "just engine"):
        return check.verdict("")
    copy_local_config(args.repo, rc_path)
    team = local_setting(rc_path, "WGEX_TEAM", check)
    if team is None:
        return check.verdict("")
    identity = select_identity(runner, check, team)
    if identity is None:
        return check.verdict("")
    digest, name = identity
    check.say("identity: %s" % name)
    pinned = local_setting(rc_path, "WGEX_OWN_MAC_LEAF", check)
    if pinned is None:
        return check.verdict("")
    check.say("pinned: %s" % pinned)
    if name != pinned:
        check.fail("this Mac's leaf is %s; %s accepts only %s" % (name, LOCAL_CONFIG, pinned))
        return check.verdict("")
    home = os.path.expanduser("~/.wgex-own-mac")
    for path in (home, os.path.join(home, "tmp")):
        os.makedirs(path, mode=0o700, exist_ok=True)
        os.chmod(path, 0o700)
    output = os.path.join(home, "out")
    env = dict(os.environ, WGEX_OWN_MAC_OUTPUT_ROOT=output, TMPDIR=os.path.join(home, "tmp"),
               WGEX_OWN_MAC_BUILD_NUMBER=datetime.datetime.now(datetime.timezone.utc).strftime("%y%m%d%H%M"),
               WGEX_OWN_MAC_IDENTITY_SHA1=digest)
    for attempt in args.attempts:
        built = runner.run(["just", "build-own-mac", attempt], cwd=rc_path, env=env, interactive=True)
        if built.rc == 77:
            check.fail("build %s needs the maintainer at the keychain prompt (exit 77): allow it, then rerun with new attempt "
                       "names" % attempt)
            return check.verdict("")
        if command_failed(check, built, "just build-own-mac %s" % attempt):
            return check.verdict("")
    first, second = args.attempts
    compared = runner.run(["just", "build-own-mac", "compare", first, second], cwd=rc_path, env=env)
    check.say(compared.out.strip())
    if command_failed(check, compared, "build-own-mac compare"):
        return check.verdict("")
    if "designated requirements match and all CDHashes changed" not in compared.out:
        check.fail("compare did not report matching requirements and changed CDHashes")
        return check.verdict("")
    try:
        with open(os.path.join(output, first, "app.dr"), encoding="utf-8") as handle:
            marker = handle.read().count(WWDR_MARKER)
    except OSError as error:
        marker = 0
        check.fail("cannot read %s/app.dr: %s" % (first, error))
    check.say("WWDR marker count: %d" % marker)
    if marker != 1:
        check.fail("the designated requirement carries the WWDR marker %d times, not once" % marker)
    app = os.path.join(output, first, "derived-data/Build/Products/Release/WGEX.app")
    signed = runner.run(["/usr/bin/codesign", "-dv", "--verbose=4", app])
    if not command_failed(check, signed, "codesign -dv"):
        fields = codesign_fields(signed.err + signed.out)
        check.say("Identifier=%s TeamIdentifier=%s Authority=%s" % (
            fields["Identifier"], fields["TeamIdentifier"], (fields["Authority"] or [None])[0]))
        if fields["Identifier"] != APP_IDENTIFIER:
            check.fail("Identifier is %s" % fields["Identifier"])
        if not fields["Authority"] or fields["Authority"][0] != name:
            check.fail("the leaf authority is not %s" % name)
        if fields["TeamIdentifier"] != team:
            check.fail("TeamIdentifier is %s" % fields["TeamIdentifier"])
    check.say("APP_A=%s" % app)
    return check.verdict("builds %s and %s signed by %s, team %s" % (first, second, name, team))


def cmd_install(args, runner, out):
    check = Check("install", out)
    target = "/Applications/WGEX.app"
    if os.path.lexists(target):
        check.say("TARGET-EXISTS")
        check.fail("%s exists: uninstall it in WGEX (Settings, Service, Uninstall WGEX...), move it to the Trash in "
                   "Finder, then run this again" % target)
        return check.verdict("")
    # macOS 27 refused to spawn a registered daemon replaced by a build with another cdhash (EXP-M03-M27HO), so build A
    # goes only where no WGEX daemon is loaded: an older WGEX is uninstalled first, not replaced in place.
    loaded = runner.run(["/usr/bin/sudo", "-n", "/bin/launchctl", "print", DAEMON_SERVICE], timeout=30)
    if loaded.rc == 0:
        check.fail("%s is still loaded: an older WGEX is registered; uninstall it first" % DAEMON_SERVICE)
        return check.verdict("")
    if loaded.rc != BOOTOUT_ABSENT:
        detail = (loaded.err or loaded.out).strip().splitlines()
        check.fail("launchctl print exited %s%s" % (loaded.rc, (": " + detail[-1][:160]) if detail else ""))
        return check.verdict("")
    check.say("no-daemon")
    source = runner.run(["/usr/bin/codesign", "-dv", "--verbose=4", args.app])
    if command_failed(check, source, "codesign -dv build A"):
        return check.verdict("")
    if command_failed(check, runner.run(["/usr/bin/sudo", "-n", "/usr/bin/ditto", args.app, target]), "sudo ditto"):
        return check.verdict("")
    if command_failed(check, runner.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", target]),
                      "codesign --verify"):
        return check.verdict("")
    installed = runner.run(["/usr/bin/codesign", "-dv", "--verbose=4", target])
    if not command_failed(check, installed, "codesign -dv installed"):
        want = codesign_fields(source.err + source.out)["CDHash"]
        have = codesign_fields(installed.err + installed.out)["CDHash"]
        if not want or want != have:
            check.fail("the installed CDHash is not build A's")
    return check.verdict("build A installed and verified")


RESTART_WINDOW = 30


def cmd_restart(args, runner, out):
    """E2 step 3: restart the daemon on the installed build, then doctor verified and phase idle."""
    check = Check("restart", out)
    kick = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    check.say("KICK=%s" % kick)
    kicked = runner.run(["/usr/bin/sudo", "-n", "/bin/launchctl", "kickstart", "-k", DAEMON_SERVICE])
    if command_failed(check, kicked, "sudo launchctl kickstart"):
        return check.verdict("")
    start = runner.monotonic()
    problem = "no doctor read"
    while True:
        remaining = RESTART_WINDOW - (runner.monotonic() - start)
        if remaining <= 0:
            doc, problem = None, "the daemon did not answer doctor within %d seconds (last: %s)" % (
                RESTART_WINDOW, problem)
            break
        runner.sleep(min(2, remaining))
        remaining = RESTART_WINDOW - (runner.monotonic() - start)
        if remaining <= 0:
            continue
        doc, problem = cli_json(runner, args.cli, ["doctor"], timeout=remaining)
        if runner.monotonic() - start > RESTART_WINDOW:
            doc, problem = None, "doctor answered after %d seconds" % RESTART_WINDOW
            break
        if not problem:
            break
    if problem:
        check.fail(problem)
    elif doc.get("daemonReachable") is not True or doc.get("secureInstall") != "verified":
        check.fail("doctor: daemonReachable=%s secureInstall=%s" % (render(doc.get("daemonReachable")),
                                                                    doc.get("secureInstall")))
    status, problem = read_status(runner, args.cli)
    if problem:
        check.fail(problem)
    elif status["phase"] != "idle":
        check.fail("phase is %s, not idle" % status["phase"])
    return check.verdict("daemon restarted at %s, secure install verified, protocol accepted" % kick)


# ---- entry --------------------------------------------------------------------------------------------------------

def parser():
    top = argparse.ArgumentParser(prog="checks.py", description=__doc__.splitlines()[0])
    top.add_argument("--cli", default=CLI)
    sub = top.add_subparsers(dest="command", required=True)
    p = sub.add_parser("ready")
    p.add_argument("--vps4", type=ipv4)
    p.add_argument("--vps6", type=ipv6_or_none)
    p.add_argument("--phys", type=interface_name)
    p.add_argument("--dns", type=ipv4)
    p.add_argument("--profile", type=uuid_text)
    p.add_argument("--eth", type=interface_name)
    p = sub.add_parser("status")
    p.add_argument("keys", nargs="*")
    p.add_argument("--expect", action="append", default=[])
    sub.add_parser("doctor")
    p = sub.add_parser("physif")
    p.add_argument("--expect", type=interface_name)
    p = sub.add_parser("ethernet")
    p.add_argument("--device", type=interface_name)
    sub.add_parser("direct").add_argument("--vps4", type=ipv4, required=True)
    p = sub.add_parser("s1")
    p.add_argument("--vps4", type=ipv4, required=True)
    p = sub.add_parser("s2")
    p.add_argument("--vps6", type=ipv6_or_none, required=True)
    p = sub.add_parser("s3")
    p.add_argument("--phys", type=interface_name, required=True)
    p.add_argument("--dns", type=ipv4, required=True)
    p.add_argument("--workdir")
    p = sub.add_parser("baseline")
    p.add_argument("--vps4", type=ipv4, required=True)
    p.add_argument("--dns", type=ipv4, required=True)
    p.add_argument("--workdir")
    p = sub.add_parser("s123")
    p.add_argument("--vps4", type=ipv4, required=True)
    p.add_argument("--vps6", type=ipv6_or_none, required=True)
    p.add_argument("--dns", type=ipv4, required=True)
    p.add_argument("--phys", type=interface_name)
    p.add_argument("--workdir")
    p = sub.add_parser("leakwatch")
    p.add_argument("--vps4", type=ipv4, required=True)
    p.add_argument("--window", type=int, default=120)
    p.add_argument("--interval", type=float, default=2)
    p = sub.add_parser("phasewatch")
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--until", choices=sorted(PHASES))
    mode.add_argument("--hold", choices=sorted(PHASES))
    p.add_argument("--window", type=int, default=60)
    for name in ("arm", "disarm"):
        sub.add_parser(name).add_argument("--profile", type=uuid_text, required=True)
    sub.add_parser("abort")
    p = sub.add_parser("cutover-start")
    p.add_argument("--profile", type=uuid_text, required=True)
    p.add_argument("--confirm-within", dest="within", type=window_text, required=True)
    sub.add_parser("cutover-confirm")
    sub.add_parser("bootout")
    sub.add_parser("keylog").add_argument("--since", required=True)
    p = sub.add_parser("e3")
    p.add_argument("--recorded", required=True)
    p.add_argument("--right", default=RIGHT)
    p = sub.add_parser("profile")
    p.add_argument("--name", default="WGEX dedicated")
    p.add_argument("--pubkey", required=True)
    p.add_argument("--dir", default=os.path.expanduser("~/Library/Application Support/WGEX/profiles"))
    sub.add_parser("c1").add_argument("--phys", type=interface_name, required=True)
    p = sub.add_parser("s8")
    p.add_argument("--profile", type=uuid_text, required=True)
    p.add_argument("--vps4", type=ipv4, required=True)
    p = sub.add_parser("airdrop")
    p.add_argument("action", choices=("mark", "check"))
    p.add_argument("--mark", default=os.path.join(os.environ.get("TMPDIR") or "/tmp", "wgex-s7.mark"))
    p.add_argument("--downloads", default=os.path.expanduser("~/Downloads"))
    p = sub.add_parser("e1")
    p.add_argument("--repo", default=os.path.expanduser("~/src/wgex"))
    p.add_argument("--worktree", default=os.path.join(os.environ.get("WGEX_WORKTREE_ROOT") or os.path.expanduser("~/wgex-worktrees"), CANDIDATE_TAG))
    p.add_argument("--attempts", nargs=2, default=["A", "B"], metavar=("FIRST", "SECOND"))
    sub.add_parser("addresses")
    sub.add_parser("protocol").add_argument("--worktree", default=os.path.join(os.environ.get("WGEX_WORKTREE_ROOT") or os.path.expanduser("~/wgex-worktrees"), CANDIDATE_TAG))
    p = sub.add_parser("install")
    p.add_argument("--app", required=True)
    sub.add_parser("restart")
    return top


COMMANDS = {
    "ready": cmd_ready, "status": cmd_status, "doctor": cmd_doctor, "physif": cmd_physif, "ethernet": cmd_ethernet, "direct": cmd_direct,
    "s1": cmd_s1, "s2": cmd_s2, "s3": cmd_s3, "baseline": cmd_baseline, "s123": cmd_s123,
    "leakwatch": cmd_leakwatch, "phasewatch": cmd_phasewatch, "arm": cmd_arm, "disarm": cmd_disarm,
    "abort": cmd_abort, "cutover-start": cmd_cutover_start, "cutover-confirm": cmd_cutover_confirm,
    "bootout": cmd_bootout, "keylog": cmd_keylog, "e3": cmd_e3, "profile": cmd_profile, "c1": cmd_c1, "s8": cmd_s8,
    "airdrop": cmd_airdrop, "addresses": cmd_addresses, "protocol": cmd_protocol, "e1": cmd_e1, "install": cmd_install, "restart": cmd_restart,
}


def main(argv, runner=None, out=None):
    out = out if out is not None else sys.stdout
    try:
        args = parser().parse_args(argv)
    except SystemExit as error:
        return 2 if error.code else 0
    runner = runner if runner is not None else Runner(out)
    try:
        return COMMANDS[args.command](args, runner, out)
    except SystemExit as error:
        print("%s: FAIL - %s" % (args.command, error), file=out)
        return 2
    except Exception as error:  # a defect or an unforeseen reply still ends in one FAIL verdict, never a traceback
        print("%s: FAIL - internal error %s: %s" % (args.command, type(error).__name__, error), file=out)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
