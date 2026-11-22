# SPDX-License-Identifier: MIT
"""ONDEMAND-ETH: the checks of the on-demand Ethernet row (ADR-030). Pure functions; no VM or network.

The observation is what the driver collected (verdict-live.Session.ondemand_row): the saved policy before and after the app
edit, one reduced status read per phase (guest od-status.pl: pid, phase, protection and the on-demand fields, never an SSID),
the replacement daemon's samples after a SIGTERM (and the reads discarded because the daemon changed around them), whether any GUI press happened while the row waited for the tunnel on its
own, and the two en0 cycles (one with the rule armed, one with it withdrawn under Lockdown) in the shape of EN0-LOSS.

Daemon start is judged on the replacement daemon's own samples only: a sample counts when its pid and start time are known, were
identical before and after the status read, and differ from the pid and start time recorded before the restart (the run 8g false
PASS came from counting the previous daemon's lines; a restart during the read could label the old daemon's status with the new pid). en0 is cycled
inside the guest only; the en0 recovery expectations are EN0-LOSS's own (verdict.en0_loss_checks), applied to the armed cycle.
"""
import math
import re

# A process start time as `ps -o lstart` prints it (od-status.pl validates the same shape).
START_PATTERN = r"[A-Za-z]{3} [A-Za-z]{3} [ 0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4}"
LOSS_BOUND_SECONDS = 60
# EN0-LOSS's own recovery bound: after en0 returns the daemon is back to its steady state within this many seconds.
SETTLE_SECONDS = 10


def check(name, met, **evidence):
    return dict(name=name, met=bool(met), **evidence)


def finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def activated(status):
    """The tunnel is up because an armed Ethernet rule brought it: one daemon status read, whole."""
    status = status if isinstance(status, dict) else {}
    od = status.get("onDemand") if isinstance(status.get("onDemand"), dict) else {}
    return (status.get("phase") == "active" and status.get("protection") == "protected" and od.get("armedIsProfile") is True
            and od.get("activated") is True and od.get("network") == "ethernet" and od.get("decision") == "connect"
            and od.get("evaluated") is True)


def withdrawn(status, protection):
    """Not armed, nothing brought up, no tunnel, and the blocking state the row expects (Lockdown: blocked)."""
    status = status if isinstance(status, dict) else {}
    od = status.get("onDemand") if isinstance(status.get("onDemand"), dict) else {}
    return (status.get("phase") == "idle" and status.get("protection") == protection and od.get("armed") is False
            and od.get("activated") is False)


def counts_after_restart(restart, sample):
    """A sample is post-start evidence only when it is the replacement daemon's: a known pid and start time (taken before and after
    the status read, od-probe) that differ from the daemon the restart signalled, and no discard marker."""
    if not isinstance(sample, dict) or sample.get("discarded"):
        return False
    previous, previous_start, started = restart.get("prevPid"), restart.get("prevStarted"), sample.get("started")
    return (type(sample.get("pid")) is int and sample["pid"] > 0 and sample["pid"] != previous
            and isinstance(started, str) and re.fullmatch(START_PATTERN, started) is not None
            and isinstance(previous_start, str) and re.fullmatch(START_PATTERN, previous_start) is not None
            and started != previous_start)


def post_start(restart):
    """The replacement daemon's samples."""
    return [s for s in restart.get("samples") or [] if counts_after_restart(restart, s)]


def en0_item(observation, phase):
    items = [item for item in observation.get("profiles") or [] if isinstance(item, dict) and item.get("phase") == phase]
    return items[0] if len(items) == 1 else None


def withdrawn_cycle_checks(item, status_after, loss_seconds):
    """With the rule withdrawn under Lockdown an en0 loss and return must leave the tunnel down and blocked: no tunnel phase, never
    protected or unprotected, and blocked again within SETTLE_SECONDS of en0 returning. While the link is down the daemon may
    report protection `unknown` (it cannot verify a network that is not there; guest run, one reference held throughout), so a
    sample from en0 down to SETTLE_SECONDS after it is up may read unknown; none outside that span may."""
    if item is None:
        gap = "the withdrawn-rule en0 cycle was not observed"
        return [check(name, False, gap=gap) for name in ("withdrawnLinkCycled", "withdrawnRuleStaysDown", "withdrawnOnePfReference")]
    samples = item.get("samples") or []
    down, up = item.get("down"), item.get("up")
    cycled = finite(down) and finite(up) and 0 < up - down <= LOSS_BOUND_SECONDS and up - down >= loss_seconds - 1
    after_up = [s for s in samples if cycled and s[0] > up + SETTLE_SECONDS]

    def held(sample):
        inside = down <= sample[0] <= up + SETTLE_SECONDS
        return sample[1] == "idle" and (sample[2] == "blocked" or (inside and sample[2] == "unknown"))
    steady = cycled and bool(samples) and all(held(s) for s in samples)
    return [check("withdrawnLinkCycled", cycled, lossSeconds=(up - down) if cycled else None),
            check("withdrawnRuleStaysDown", steady and bool(after_up) and withdrawn(status_after, "blocked"),
                  samples=len(samples), samplesAfterSettle=len(after_up),
                  notIdleBlocked=sum(not (s[1] == "idle" and s[2] == "blocked") for s in samples),
                  unknownWhileLinkDown=sum(s[2] == "unknown" and cycled and down <= s[0] <= up + SETTLE_SECONDS for s in samples)),
            check("withdrawnOnePfReference", bool(samples) and sorted({s[3] for s in samples}) == [1],
                  referenceCounts=sorted({s[3] for s in samples}))]


def ondemand_checks(observation, en0_loss_checks, loss_seconds=20):
    od = observation["onDemand"]
    restart = od.get("restart") or {}
    after = post_start(restart)
    before, saved = od.get("policyBefore"), od.get("policyAfterEdit")
    # Both reads are needed: an unreadable policy before the edit does not show that the app changed it.
    checks = [check("ruleSavedThroughApp", isinstance(before, str) and bool(before) and "ethernetOnly" not in before
                    and isinstance(saved, str) and "ethernetOnly" in saved,
                    policyBefore=od.get("policyBefore"), policyAfterEdit=od.get("policyAfterEdit")),
              check("activatedAfterArm", od.get("armPresses") == 1 and activated(od.get("armed")), armPresses=od.get("armPresses"),
                    status=od.get("armed"))]
    first_up = next((s for s in after if activated(s)), None)
    checks += [check("daemonReplaced", type(restart.get("prevPid")) is int and restart["prevPid"] > 0 and bool(after)
                     and len({s["pid"] for s in after}) == 1, previousPid=restart.get("prevPid"), postStartSamples=len(after),
                     postStartPids=sorted({s["pid"] for s in after}),
                     discardedReads=[d.get("reason") for d in restart.get("discarded") or [] if isinstance(d, dict)]),
               check("protectedAfterDaemonStart", first_up is not None, firstActivatedAt=first_up["at"] if first_up else None,
                     secondsAfterRestart=(first_up["at"] - restart["restartAt"]) if first_up and finite(restart.get("restartAt")) else None),
               check("postStartNeverUnprotected", bool(after) and all(s.get("protection") != "unprotected" for s in after),
                     unprotected=sum(s.get("protection") == "unprotected" for s in after)),
               check("noGuiActionAfterDaemonStart", restart.get("guiPress") is False, guiPress=restart.get("guiPress"))]
    armed_item = en0_item(observation, "armed")
    if armed_item is None:
        checks.append(check("armedLinkCycleObserved", False, gap="the armed en0 cycle was not observed"))
    else:
        checks += [dict(item, name="armed:" + item["name"]) for item in en0_loss_checks(dict(profiles=[armed_item]))]
    after_en0 = od.get("afterEn0") or {}
    checks += [check("armedAndActivatedAfterEn0Return", activated(after_en0.get("status")), status=after_en0.get("status")),
               check("noGuiActionAfterEn0Return", after_en0.get("guiPress") is False, guiPress=after_en0.get("guiPress"))]
    removed = od.get("removed") or {}
    checks += [check("lockdownOn", od.get("lockdownJournal") is True, lockdownJournal=od.get("lockdownJournal")),
               check("removalBringsTunnelDown", removed.get("presses") == 1 and withdrawn(removed.get("status"), "blocked"),
                     presses=removed.get("presses"), status=removed.get("status"))]
    checks += withdrawn_cycle_checks(en0_item(observation, "removed"), (od.get("removedAfterEn0") or {}).get("status"), loss_seconds)
    return checks
