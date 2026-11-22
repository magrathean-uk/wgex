# SPDX-License-Identifier: MIT
"""RT-17 identity corpus: the clients the row must see refused and the row's checks. Pure functions; no VM or network.

Every client sends privileged work (the genuine CLI's `down`, or the corpus client's hello followed by stopCurrent), and
each one can be refused only by the daemon: the CLI variants run from a bundle layout whose daemon copy is the running
daemon (so their own Lab requirement on the daemon holds), and the corpus client sets no requirement at all. A client
passes only on the daemon's own refusal: the client ran and reported the dropped connection in its fixed form, the
daemon's libxpc logged at least one code-signing refusal while the client logged none, the daemon state (pid, phase,
protection, journal intent, owner pf token, reference count) is unchanged and the daemon logged no lifecycle line. A
launch, loader, guard, parsing or local validation failure leaves no such report, so it fails the row. The genuine CLI
run from the same layout is the layout's positive control, and the genuine CLI's own `down` afterwards is the positive
control that the lifecycle observer sees privileged work.
"""
import re

# Identifiers of a Lab build (BuildIdentifiers: base com.magrathean.WGEXApp.dev).
LAB_APP = "com.magrathean.WGEXApp.dev"
LAB_CLI = "com.magrathean.WGEXApp.dev.cli"
GENUINE_IDENTIFIERS = (LAB_APP, LAB_CLI)
PROTOCOL_VERSION = 7  # Envelope.currentProtocolVersion
CDHASH = re.compile(r"[a-f0-9]{40}")
DIGEST = re.compile(r"[a-f0-9]{12}")
# Order is the attempt order; the names are the guest action's variant names and the check suffixes.
REQUIRED_CLIENTS = ("unsigned", "ad-hoc", "wrong-team", "wrong-identifier", "get-task-allow", "old-protocol", "older-build")
# Re-signed copies of the genuine CLI, run from the corpus layout; the others are the corpus client in these modes.
LAYOUT_CLIENTS = ("ad-hoc", "wrong-team", "wrong-identifier", "get-task-allow")
CLIENT_MODES = {"unsigned": "current", "old-protocol": "old-protocol", "older-build": "older-build"}
# The CLI's fixed rendering of a dropped daemon connection (DaemonFailureCatalog: .disconnected, daemonUnavailable, exit 1).
CLI_REFUSED = ({"error": "daemonUnavailable"}, 1)
# NSXPCConnectionInterrupted and NSXPCConnectionInvalid: the remote side dropped the connection.
DROPPED = (4097, 4099)


def check(name, met):
    return dict(name=name, met=bool(met))


def _dict(value):
    return value if isinstance(value, dict) else {}


def snapshot_valid(value):
    value = _dict(value)
    pid = value.get("daemonPid")
    return (type(pid) is int and pid > 0 and value.get("protection") == "protected" and value.get("phase") == "active"
            and isinstance(value.get("intentDigest"), str) and DIGEST.fullmatch(value["intentDigest"]) is not None
            and isinstance(value.get("ownerTokenHash"), str) and DIGEST.fullmatch(value["ownerTokenHash"]) is not None
            and value.get("referenceCount") == 1)


def unchanged(item):
    """Both snapshots readable and protected, and equal: no privileged work changed the daemon."""
    before, after = _dict(item.get("before")), _dict(item.get("after"))
    return snapshot_valid(before) and snapshot_valid(after) and before == after


def distinct(item, genuine):
    value = item.get("cdhash")
    return isinstance(value, str) and CDHASH.fullmatch(value) is not None and value not in (genuine.get("app"), genuine.get("cli"))


def identity_valid(name, item, genuine):
    """The client really is the identity its name claims, so a wrongly built corpus cannot pass by accident."""
    identifier = item.get("identifier")
    if name == "unsigned":
        return item.get("signature") == "unsigned" and item.get("cdhash") is None
    if not distinct(item, genuine):
        return False
    if name == "ad-hoc":
        return item.get("signature") == "adhoc" and identifier == LAB_CLI and item.get("getTaskAllow") is False
    if name == "wrong-team":
        team = item.get("teamOU")
        return (item.get("signature") == "certificate" and identifier == LAB_CLI and isinstance(team, str)
                and re.fullmatch(r"[A-Z0-9]{10}", team) is not None and team != genuine.get("teamOU"))
    if name == "wrong-identifier":
        return item.get("signature") == "adhoc" and isinstance(identifier, str) and identifier not in GENUINE_IDENTIFIERS
    if name == "get-task-allow":
        return item.get("signature") == "adhoc" and identifier == LAB_CLI and item.get("getTaskAllow") is True
    if name == "old-protocol":
        version = item.get("protocolVersion")
        return item.get("signature") == "adhoc" and identifier == LAB_CLI and type(version) is int and 0 < version < PROTOCOL_VERSION
    if name == "older-build":
        build, daemon = item.get("clientBuild"), genuine.get("daemonBuild")
        return (item.get("signature") == "adhoc" and identifier == LAB_CLI and type(build) is int and type(daemon) is int
                and 0 <= build < daemon)
    return False


def layout_valid(genuine):
    """The layout's daemon copy is the running daemon, so a CLI variant's own requirement on the daemon is met."""
    daemon = genuine.get("daemon")
    return isinstance(daemon, str) and CDHASH.fullmatch(daemon) is not None and genuine.get("layoutDaemon") == daemon


def client_reported_refusal(name, item):
    """The client ran and reported the dropped connection in its own fixed form; any other exit or report is a failure."""
    report, code = item.get("report"), item.get("exitCode")
    if not isinstance(report, dict) or type(code) is not int:
        return False
    if name in LAYOUT_CLIENTS:
        return (report, code) == CLI_REFUSED
    return (code == 0 and name in CLIENT_MODES and report.get("mode") == CLIENT_MODES[name] and report.get("outcome") == "refused"
            and report.get("errorCode") in DROPPED and report.get("impostor") is False)


def daemon_refused(item):
    """The daemon's libxpc logged a code-signing refusal during the attempt, and the client logged none of its own."""
    refusals, own = item.get("daemonRefusals"), item.get("clientRefusals")
    return type(refusals) is int and refusals >= 1 and type(own) is int and own == 0


def refused(name, item, genuine):
    return (identity_valid(name, item, genuine) and (name not in LAYOUT_CLIENTS or layout_valid(genuine))
            and client_reported_refusal(name, item) and daemon_refused(item) and unchanged(item) and item.get("lifecycleLines") == 0)


def layout_served(control, genuine):
    """The genuine CLI from the corpus layout is served by the daemon and refused by no one: the layout itself works."""
    report = control.get("report") if isinstance(control.get("report"), dict) else {}
    return (layout_valid(genuine) and control.get("exitCode") == 0 and report.get("phase") == "active"
            and report.get("protection") == "protected" and control.get("daemonRefusals") == 0 and control.get("clientRefusals") == 0
            and unchanged(control) and control.get("lifecycleLines") == 0)


def rt17_checks(observation):
    genuine = _dict(observation.get("genuine"))
    clients = observation.get("clients") if isinstance(observation.get("clients"), list) else []
    checks = [check("layoutServed", layout_served(_dict(observation.get("layoutControl")), genuine))]
    for name in REQUIRED_CLIENTS:
        matches = [item for item in clients if isinstance(item, dict) and item.get("name") == name]
        checks.append(check("refused:" + name, refused(name, matches[0] if len(matches) == 1 else {}, genuine)))
    impostor = _dict(observation.get("impostor"))
    before, after = impostor.get("connectionsBeforePrivileged"), impostor.get("connectionsAfterPrivileged")
    # The unprivileged control must reach the impostor (it was registered); the privileged lookup must not.
    checks.append(check("impostorNeverReached", impostor.get("registered") is True and impostor.get("controlReached") is True
                        and type(before) is int and before >= 1 and after == before
                        and impostor.get("privilegedServedByDaemon") is True and unchanged(impostor)
                        and impostor.get("lifecycleLines") == 0))
    control = _dict(observation.get("logControl"))
    lines = control.get("genuineDownLifecycleLines")
    checks.append(check("daemonLogObserved", type(lines) is int and lines >= 1 and control.get("protectionAfter") == "unprotected"))
    return checks
