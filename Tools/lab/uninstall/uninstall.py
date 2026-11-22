# SPDX-License-Identifier: MIT
"""UNINSTALL (M03-T15, DEC-037 item 4, DEC-040): the checks of the uninstall row. Pure functions; no VM or network.

The observation is what the driver collected (verdict-live.Session.uninstall_row): the pre-tunnel baseline (inet routes and the
resolver set, reduced here from the guest's netstat and scutil text), then for each variant (keep: `wgex uninstall --yes`, purge:
`wgex uninstall --purge --yes`) the state while protected, the CLI's exit code and reply with the console approval, what the
uninstall left (status, pf anchor and references, routes, resolvers, launchd job, BTM items, refused requests, the app's profile
store and, after a purge, the daemon state root), the app's finish (the offer, the press, the final screen, the Quit) and the
fresh secure install from the app with the tunnel started after it.

Routes are compared without link-layer entries (flag L: ARP and broadcast lines, whose expiry and presence change on their own);
resolvers are compared on their servers, domains, search domains, options and interface, without reach flags or order numbers,
in both the default and the scoped section (scoped entries carry a "scoped:" prefix), so a tunnel resolver left only in the
scoped section is a difference too.

A guest read that failed is "unknown" (services, pf counts, the state root's files) or "unreadable" (the journal); every check
compares against the confirmed value it needs, so a failed read never passes as an absence or a zero.
"""
import re

VARIANTS = ("keep", "purge")
# The tunnel's own addresses in the lab profile (Tools/lab/peer.sh full4): the in-tunnel peer as resolver, the guest's address.
TUNNEL_RESOLVER = "10.77.0.1"
TUNNEL_ADDRESS = "10.77.0.2"
# The CLI's uninstall failure code and name (WGEXCLICore uninstallFailure, exit 19), the reply to a request the fence refuses.
REFUSED = (19, "uninstallFailed")
# What a purge may leave under the daemon's state root (DEC-040): the journal, reduced to the marker and its generation fence.
# TunnelController+Uninstall's purge writes a fresh DaemonJournalDocument that keeps only the generation and the uninstall
# record: the exact type of each field the guest's reduction (guest-uninstall.sh state-root) reports, then its fixed values.
PURGE_FILES = {"journal.json", "journal.log"}
PURGE_REQUIRED = {"schemaVersion": "integer", "generation": "integer", "journalSequence": "integer", "settings": "object:4",
                  "pfPolicy": "object:1"}
PURGE_EMPTY = {"entries": "array:0", "resources": "array:0", "pendingSecretDeletions": "array:0", "lastGoodAddresses": "object:0"}
PURGE_VALUES = {"schemaVersion.value": 2, "settings.default": "true", "pfPolicy.disconnected": "true", "uninstall.completed": "true",
                "uninstall.purgeState": "true"}
UNINSTALL_KIND = re.compile(r"object:[1-9][0-9]?")
# The final screen must appear within this many seconds of the Finish press (the M05-T11 unregister hang watch item).
FINISH_BOUND_SECONDS = 90
QUIT_BOUND_SECONDS = 10
TUNNEL_BOUND_SECONDS = 90


def check(name, met, **evidence):
    return dict(name=name, met=bool(met), **evidence)


def routes(text):
    """The IPv4 routing table (netstat -rn, Internet section) as sorted "destination gateway flags netif" lines, without
    link-layer (L) entries."""
    lines, inside = [], False
    for line in (text or "").splitlines():
        if line.startswith("Internet:"):
            inside = True
            continue
        if line.startswith("Internet6:"):
            break
        fields = line.split()
        if not inside or len(fields) < 4 or fields[0] == "Destination" or "L" in fields[2]:
            continue
        lines.append(" ".join(fields[:4]))
    return sorted(set(lines))


def resolvers(text):
    """The resolver sets of scutil --dns as sorted canonical strings: the default section as is, the scoped section with a
    "scoped:" prefix."""
    default, _, scoped = (text or "").partition("DNS configuration (for scoped queries)")
    return sorted(_resolver_section(default) + ["scoped:" + entry for entry in _resolver_section(scoped)])


def _resolver_section(text):
    result = []
    for block in re.split(r"\n(?=resolver #\d+)", "\n" + text):
        block = block.lstrip("\n")
        if not block.startswith("resolver #"):
            continue
        fields = []
        for line in block.splitlines()[1:]:
            name, _, value = line.partition(":")
            name, value = name.strip(), value.strip()
            if re.fullmatch(r"(nameserver|search domain)\[\d+\]", name):
                fields.append(name.split("[")[0] + "=" + value)
            elif name in ("domain", "options"):
                fields.append(name + "=" + value)
            elif name == "if_index":
                fields.append("if=" + value.split("(")[-1].rstrip(")"))
        result.append(";".join(sorted(fields)))
    return result


def tunnel_interfaces(ifconfig):
    """utun interfaces carrying the lab tunnel address."""
    return sorted(set(re.findall(r"^(utun\d+):[^\n]*\n(?:(?!^\S).)*?inet " + re.escape(TUNNEL_ADDRESS) + r"\b", ifconfig or "", re.M | re.S)))


def reduce_observation(observation):
    """The parts of one verdict-actions observe the row judges, reduced."""
    observation = observation if isinstance(observation, dict) else {}
    return dict(status=observation.get("status"), referenceCount=observation.get("referenceCount"),
                ruleLines=len([line for line in (observation.get("rules") or "").splitlines() if re.match(r"\s*(?:@\d+\s+)?(?:pass|block|match)\b", line)]),
                routes=routes(observation.get("routes")), resolvers=resolvers(observation.get("dns")),
                tunnelInterfaces=tunnel_interfaces(observation.get("ifconfig")))


def count(value):
    """A measured count, or None for a failed read ("unknown") or anything else that is not a whole number."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def enabled(disposition):
    return isinstance(disposition, str) and disposition.startswith("[enabled")


def removed(disposition):
    return disposition == "absent" or (isinstance(disposition, str) and disposition.startswith("[disabled"))


def status_uninstalled(status, line, purge):
    """M05-T14's output: `wgex status --json` carries `uninstall` {completed: true, purgeState, pendingStep: null} at the top
    level, and the text form's uninstall line says completed, with "(purge)" after a purge."""
    uninstall = (status if isinstance(status, dict) else {}).get("uninstall")
    expected = "uninstall: completed" + (" (purge)" if purge else "") + "; the service is uninstalled;"
    return (isinstance(uninstall, dict) and uninstall.get("completed") is True and uninstall.get("purgeState") is purge
            and uninstall.get("pendingStep") is None and isinstance(line, str) and line.startswith(expected))


def variant_checks(name, item, baseline):
    item = item if isinstance(item, dict) else {}
    before, after = item.get("before") or {}, item.get("after") or {}
    cli, finish, install = item.get("cli") or {}, item.get("finish") or {}, item.get("freshInstall") or {}
    before_obs, after_obs = before.get("observation") or {}, after.get("observation") or {}
    pf_before, pf_after = before.get("pf") or {}, after.get("pf") or {}
    added = sorted(set(before_obs.get("routes") or []) - set(baseline.get("routes") or []))
    left = sorted(set(added) & set(after_obs.get("routes") or []))
    utun_routes = [line for line in after_obs.get("routes") or [] if re.search(r" utun\d+$", line)]
    refused = after.get("refused") or {}
    status = after.get("status") or {}
    approval = cli.get("approval") or {}
    checks = [
        check(name + ":protectedBefore", (before_obs.get("status") or {}) == dict(phase="active", protection="protected")
              and (count(pf_before.get("anchorRules")) or 0) > 0 and count(pf_before.get("references")) == 1 and bool(before_obs.get("tunnelInterfaces")),
              status=before_obs.get("status"), anchorRules=pf_before.get("anchorRules"), references=pf_before.get("references"),
              tunnelInterfaces=before_obs.get("tunnelInterfaces")),
        check(name + ":cliUninstalled", cli.get("rc") == 0 and (cli.get("reply") or {}).get("result") == "uninstalled"
              and (cli.get("reply") or {}).get("purge") is (name == "purge") and approval.get("result") == "typed",
              rc=cli.get("rc"), reply=cli.get("reply"), approval=approval.get("result")),
        check(name + ":tunnelStopped", (after_obs.get("status") or {}) == dict(phase="idle", protection="unprotected")
              and not after_obs.get("tunnelInterfaces") and not utun_routes,
              status=after_obs.get("status"), tunnelInterfaces=after_obs.get("tunnelInterfaces"), utunRoutes=utun_routes),
        check(name + ":noWgexPfRule", pf_after.get("anchorListed") in (True, False)
              and all(count(pf_after.get(key)) == 0 for key in ("anchorRules", "anchorTables", "anchorNested", "references"))
              and count(after_obs.get("ruleLines")) == 0 and count(after_obs.get("referenceCount")) == 0,
              anchorListed=pf_after.get("anchorListed"), anchorRules=pf_after.get("anchorRules"), anchorTables=pf_after.get("anchorTables"),
              anchorNested=pf_after.get("anchorNested"), references=pf_after.get("references")),
        check(name + ":noWgexRoute", bool(added) and not left and not utun_routes
              and sorted(after_obs.get("routes") or []) == sorted(baseline.get("routes") or []),
              addedWhileProtected=added, leftAfterUninstall=left,
              differsFromBaseline=sorted(set(after_obs.get("routes") or []) ^ set(baseline.get("routes") or []))),
        check(name + ":dnsAsBeforeTunnel", bool(baseline.get("resolvers")) and after_obs.get("resolvers") == baseline.get("resolvers")
              and not any("nameserver=" + TUNNEL_RESOLVER in entry for entry in after_obs.get("resolvers") or []),
              tunnelResolverWhileProtected=any("nameserver=" + TUNNEL_RESOLVER in entry for entry in before_obs.get("resolvers") or []),
              differsFromBaseline=sorted(set(after_obs.get("resolvers") or []) ^ set(baseline.get("resolvers") or []))),
        check(name + ":statusReportsUninstalled", status.get("rc") == 0
              and status_uninstalled(status.get("status"), status.get("uninstallLine"), name == "purge"),
              rc=status.get("rc"), status=status.get("status"), uninstallLine=status.get("uninstallLine")),
        check(name + ":mutatingRequestsRefused", all(tuple(refused.get(request) or ()) == REFUSED for request in ("up", "onDemand")),
              up=refused.get("up"), onDemand=refused.get("onDemand"), down=refused.get("down")),
        check(name + ":appFinishOffered", finish.get("offered") is True, offered=finish.get("offered")),
        check(name + ":serviceRemovedByApp", (finish.get("services") or {}).get("launchdJob") == "absent"
              and (finish.get("services") or {}).get("daemonPid") == "none" and removed((finish.get("services") or {}).get("btmDaemon")),
              services=finish.get("services")),
        check(name + ":finishDidNotHang", finish.get("finalScreen") is True and isinstance(finish.get("seconds"), (int, float))
              and finish["seconds"] <= FINISH_BOUND_SECONDS, finalScreen=finish.get("finalScreen"), seconds=finish.get("seconds")),
        check(name + ":finalQuitEndsApp", (finish.get("quit") or {}).get("exited") is True
              and "driverStopped" not in (finish.get("quit") or {}), quit=finish.get("quit")),
        check(name + ":appProfilesKept", (after.get("profiles") or {}).get("profilePresent") is True
              and (finish.get("profiles") or {}).get("profilePresent") is True,
              afterCli=after.get("profiles"), afterFinish=finish.get("profiles")),
        check(name + ":freshInstallRestoresDaemon", (install.get("services") or {}).get("launchdJob") == "present"
              and (count((install.get("services") or {}).get("daemonPid")) or 0) > 0 and install.get("secureInstall") == "verified",
              services=install.get("services"), secureInstall=install.get("secureInstall")),
        check(name + ":tunnelStartsAfterFreshInstall", (install.get("tunnel") or {}).get("protected") is True
              and not (install.get("tunnel") or {}).get("driverRestartedDaemon"), tunnel=install.get("tunnel")),
    ]
    if name == "keep":
        services = finish.get("services") or {}
        checks.append(check("keep:loginItemRemovedByApp", enabled((before.get("services") or {}).get("btmApp")) and removed(services.get("btmApp")),
                            before=(before.get("services") or {}).get("btmApp"), after=services.get("btmApp")))
    else:
        root = after.get("stateRoot") or {}
        journal = root.get("journal") if isinstance(root.get("journal"), dict) else {}
        files = root.get("files") if isinstance(root.get("files"), list) else None
        generation = count(journal.get("generation.value"))
        protected = count(((before.get("stateRoot") or {}).get("journal") or {}).get("generation.value")
                          if isinstance((before.get("stateRoot") or {}).get("journal"), dict) else None)
        checks.append(check("purge:stateRootMarkerOnly", root.get("root") == "present" and files is not None and set(files) <= PURGE_FILES
                            and "journal.json" in files and journal_marker_only(journal)
                            and generation is not None and protected is not None and generation >= protected >= 1,
                            files=files, journal=journal or None, generationWhileProtected=protected))
    return checks


def journal_marker_only(journal):
    """The purged journal's reduction: exactly the fields a fresh document with the marker carries, each of its exact type,
    the containers that must be empty empty, and the fixed values (schema 2, default settings, disconnected policy, the
    completed purge marker)."""
    if not isinstance(journal, dict):
        return False
    kinds = {key: value for key, value in journal.items() if "." not in key}
    allowed = set(PURGE_REQUIRED) | set(PURGE_EMPTY) | {"uninstall"}
    return (set(kinds) <= allowed and all(kinds.get(key) == kind for key, kind in PURGE_REQUIRED.items())
            and all(kinds.get(key, kind) == kind for key, kind in PURGE_EMPTY.items())
            and isinstance(kinds.get("uninstall"), str) and bool(UNINSTALL_KIND.fullmatch(kinds["uninstall"]))
            and set(journal) - set(kinds) == set(PURGE_VALUES) | {"generation.value"}
            and all(journal.get(key) == value and type(journal.get(key)) is type(value) for key, value in PURGE_VALUES.items()))


def uninstall_checks(observation):
    row = observation["uninstall"]
    baseline = row.get("baseline") or {}
    variants = row.get("variants") or {}
    checks = []
    for name in VARIANTS:
        checks += variant_checks(name, variants.get(name), baseline)
    return checks
