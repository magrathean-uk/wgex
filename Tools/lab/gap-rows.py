# SPDX-License-Identifier: MIT
"""Kept-gap observations and checks. Pure functions also used by fixture replay."""
from datetime import datetime
import json
import math
import re

# DEC-028 (amended): one 5 s canary poll plus up to 2 s for the check itself; Tools/lab/rows.json detectionWindow carries the same bound.
DETECTION_BOUND_SECONDS = 7
# Leak-free observation required after enforcement is restored; the generator window covers injection + bound + this.
POST_OBSERVATION_SECONDS = 5


def check(name, met, **evidence):
    return dict(name=name, met=bool(met), **evidence)


def utc_stamp(sample):
    try:
        stamp = sample["measuredAt"]
        measured = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        return stamp.endswith("Z") and measured.utcoffset().total_seconds() == 0
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def telemetry(sample):
    sequence = sample.get("sequence")
    return (utc_stamp(sample) and type(sequence) is int and 0 < sequence < 2**64
            and sample.get("journalPolicy") in ("disconnected", "connecting", "connected", "disconnecting", "error", "lockdown", "captiveWindow")
            and sample.get("ownerPFTokenPresent") is True and sample.get("ownerInReferences") is True
            and re.fullmatch(r"[a-f0-9]{12}", sample.get("ownerPFTokenHash") or "") is not None)


def rules_digest(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{12}", value) is not None


def restored(sample, baseline, kind="pf-disable"):
    """Enforcement is restored when pf is enabled, exactly one WGEX reference is held and the daemon reports protected or
    blocked. For the third-party faults (token, pf-disable) the anchor's rules must also be loaded as they were before the
    injection: the sample's digest of `pfctl -a com.apple/wgex -sr` equals the baseline's. A reference without those rules
    is not enforcement."""
    if not (telemetry(sample) and sample.get("pfEnabled") is True and sample.get("referenceCount") == 1
            and sample.get("protection") in ("blocked", "protected")):
        return False
    if kind not in ("token", "pf-disable"):
        return True
    return rules_digest(sample.get("rulesDigest")) and sample["rulesDigest"] == baseline.get("rulesDigest")


def fault_checks(kind, observation):
    baseline = observation.get("baseline", {})
    samples = observation.get("samples", [])
    injected = observation.get("injectedAt")
    valid_time = type(injected) in (int, float) and math.isfinite(injected)
    after = [s for s in samples if valid_time and type(s.get("at")) in (int, float) and s["at"] >= injected]
    ordered = bool(after) and len(after) == len(samples) and all(a["at"] <= b["at"] for a, b in zip(after, after[1:]))
    recovery = [s for s in after if restored(s, baseline, kind)]
    # A new observation must be newer than the pre-injection measurement. Repeated status is not recovery evidence.
    baseline_stamp = baseline.get("measuredAt") or ""
    baseline_sequence = baseline.get("sequence")
    recovery = [s for s in recovery if s["measuredAt"] > baseline_stamp]
    baseline_rules = kind not in ("token", "pf-disable") or rules_digest(baseline.get("rulesDigest"))
    checks = [check("ownerTelemetry", telemetry(baseline) and baseline.get("referenceCount") == 1 and baseline_rules),
              check("enforcementRestored", ordered and bool(recovery) and restored(after[-1], baseline, kind))]
    if kind in ("pf-disable", "token"):
        unknown = [s for s in after if s.get("protection") == "unknown" and 0 <= s["at"] - injected <= DETECTION_BOUND_SECONDS
                   and type(s.get("sequence")) is int and type(baseline_sequence) is int and s["sequence"] > baseline_sequence
                   and isinstance(s.get("measuredAt"), str) and s["measuredAt"] > baseline_stamp]
        checks.append(check("unknownWithin7s", bool(unknown) and bool(recovery) and unknown[0]["at"] <= recovery[-1]["at"]))
        # The digest evidence travels in the verdict: the baseline's and that of every sample counted as restored (at is the
        # offset from the injection). The row passes only when each equals the baseline; check-verdicts re-reads the same fields.
        digests = [dict(offsetSeconds=round(s["at"] - injected, 3), sequence=s["sequence"], rulesDigest=s["rulesDigest"]) for s in recovery]
        checks.append(check("rulesDigestRestored", rules_digest(baseline.get("rulesDigest")) and bool(digests)
                            and all(d["rulesDigest"] == baseline["rulesDigest"] for d in digests),
                            baselineRulesDigest=baseline.get("rulesDigest"), recoveryRulesDigests=digests))
        if kind == "token":
            checks.append(check("replacementOwnerToken", bool(recovery) and recovery[-1]["ownerPFTokenHash"] != baseline.get("ownerPFTokenHash")))
    else:
        restarted = [s for s in after if s.get("pid", 0) > 0 and s["pid"] != baseline.get("pid")]
        first = restarted[0] if restarted else {}
        # DEC-018: the restarted run's first publication is the `startup` record the daemon keeps for the run, read beside
        # each live sample instead of racing for the first one. Sequence 1 is required, and the record must be newer than
        # the baseline and the same in every restarted sample: a missing or changed record is incomplete evidence, never
        # inferred ordering.
        record = first.get("startup")
        checks.append(check("errorPolicyFirst", telemetry(first) and isinstance(record, dict) and utc_stamp(record)
                            and type(record.get("sequence")) is int and record["sequence"] == 1
                            and record.get("journalPolicy") == "error" and record.get("protection") == "blocked"
                            and record["measuredAt"] > (baseline.get("measuredAt") or "")
                            and all(s.get("startup") == record for s in restarted)))
        checks.append(check("oneDaemonAfterRestart", bool(restarted) and len({s["pid"] for s in restarted}) == 1))
    return checks


def newer_than_baseline(sample, baseline):
    return (type(sample.get("sequence")) is int and type(baseline.get("sequence")) is int and sample["sequence"] > baseline["sequence"]
            and isinstance(sample.get("measuredAt"), str) and sample["measuredAt"] > (baseline.get("measuredAt") or ""))


def detection_end(observation):
    """DEC-028: the time of the first sample after the injection in which enforcement is restored (see `restored`: pf on, one
    WGEX reference, the anchor's rules equal to the pre-injection digest, protected or blocked). The daemon's own `unknown`
    report comes inside the window, not at its end: the reassert follows it (live runs: 0.2 to 0.6 s later), and leaks until
    then belong to the same bounded detection window. Only samples newer than the baseline count, as in fault_checks. None
    when no sample qualifies."""
    baseline = observation.get("baseline", {})
    injected = observation.get("injectedAt")
    if type(injected) not in (int, float) or not math.isfinite(injected):
        return None
    for sample in observation.get("samples", []):
        at = sample.get("at")
        if type(at) not in (int, float) or not math.isfinite(at) or at < injected or not newer_than_baseline(sample, baseline):
            continue
        if restored(sample, baseline):
            return at
    return None


def split_detection_window(windows, observation, detection_state, tolerance):
    """DEC-028: split each generator window around the detection window [injectedAt, first restored sample) into pre,
    detection and post windows. The detection window carries `detection_state` and its real length, never clipped to the
    generator window: a daemon that restores late (or never) yields a window longer than the bound, which the evaluator fails.
    The generator's own end is `generatorEnd` (the driver may extend `end` past it). The detection window also carries a
    `shortfall`, which fails the row, when the observation cannot support the verdict: no restored sample before the generator
    stopped (insufficient observation), a restored sample only after it stopped (insufficient observation), or less than
    POST_OBSERVATION_SECONDS of generator coverage after the restored sample (insufficient coverage). The pre and post windows are
    pulled in by the clock tolerance, because the evaluator widens every window by it: receipts are then judged against the
    true boundaries, none in two windows and none in neither."""
    injected = observation.get("injectedAt")
    if type(injected) not in (int, float) or not math.isfinite(injected):
        return list(windows)
    end = detection_end(observation)
    result = []
    for window in windows:
        generated = min(window["end"], window.get("generatorEnd", window["end"]))
        shortfall = None
        # The window passed in is the generator's run for this injection: an injection before it started or after it stopped
        # was not observed at all (no window, no post-recovery traffic), whatever the recovery time.
        if injected < window["start"]:
            shortfall = "insufficient observation: the injection came before the generator started"
        elif injected >= generated:
            shortfall = "insufficient observation: the injection came after the generator stopped"
        elif end is None:
            shortfall = "insufficient observation: no sample with enforcement restored before the generator stopped"
        elif end > generated:
            shortfall = "insufficient observation: enforcement was restored after the generator stopped"
        elif generated - end < POST_OBSERVATION_SECONDS:
            shortfall = (f"insufficient coverage: {round(generated - end, 3)} s of observation after enforcement was restored, "
                         f"{POST_OBSERVATION_SECONDS} s required")
        detection_stop = generated if end is None else end
        pieces = [("pre", window["start"], min(window["end"], injected - tolerance), window.get("state")),
                  ("detection", max(window["start"], injected), detection_stop, detection_state),
                  ("post", max(window["start"], (generated if end is None else end) + tolerance), generated, window.get("state"))]
        for phase, start, stop, state in pieces:
            keep_empty = phase == "detection" and shortfall
            if start < stop or keep_empty:
                piece = {**window, "phase": phase, "start": start, "end": max(start, stop), "state": state}
                if keep_empty:
                    piece["shortfall"] = shortfall
                result.append(piece)
    return result


def dns_checks(observation):
    return [check("adminDNSEdited", observation.get("edited") is True),
            check("adminDNSPreservedOnDisconnect", observation.get("preserved") is True),
            check("priorDNSRestored", observation.get("restored") is True)]


def logout_checks(observation):
    variants = observation.get("logouts", [])
    checks = []
    for enabled in (False, True):
        matches = [v for v in variants if v.get("bootIntent") is enabled]
        item = matches[0] if len(matches) == 1 else {}
        suffix = ":on" if enabled else ":off"
        checks.extend([check("consoleLogoutRelogin" + suffix, item.get("loggedOut") is True and item.get("loggedIn") is True),
                       check("selectedBootIntent" + suffix, item.get("readBack") is enabled),
                       check("logoutPolicy" + suffix, item.get("whileLoggedOut") == ("protected" if enabled else "unprotected")
                             and item.get("referencesWhileLoggedOut") == (1 if enabled else 0))])
    return checks


def rule_order(text):
    rules = [re.sub(r"^@\d+\s+", "", line.strip()) for line in text.splitlines()]
    rules = [line for line in rules if re.match(r"(?:pass|block|set)\b", line)]
    dns = [i for i, line in enumerate(rules) if line.startswith("block ") and "quick" in line
           and re.search(r"port\s+(?:=\s*)?(?:53|domain|853)\b", line)]
    lan = [i for i, line in enumerate(rules) if line.startswith("pass ") and " on en0 " in line
           and re.search(r"(?:192\.168\.64\.0/24|169\.254\.0\.0/16|224\.0\.0\.0/24|fe80::/10|ff02::/16)", line)]
    dns_pairs = {(proto, port) for i in dns for proto in ("tcp", "udp") if re.search(r"\bproto " + proto + r"\b", rules[i])
                 for port in ("53", "853") if re.search(r"port\s+(?:=\s*)?" + (r"(?:53|domain)" if port == "53" else port) + r"\b", rules[i])}
    return (dns_pairs == {("tcp", "53"), ("tcp", "853"), ("udp", "53"), ("udp", "853")}
            and bool(lan) and max(dns) < min(lan) and not any(line.startswith("set ") for line in rules)
            and bool(rules) and re.fullmatch(r"block(?: drop)? quick (?:all|from any to any)", rules[-1]) is not None)


def rt21_checks(observation):
    events = observation.get("pfExecs", [])
    kills = [event for event in events if isinstance(event, dict) and "arguments" in event]
    controls = [event for event in events if isinstance(event, dict) and "daemonPfctlExecs" in event]
    def scoped(event):
        args = event.get("arguments", [])
        return len(args) == 4 and args[0] == "-i" and args[1] == "en0" and args[2:] == ["-F", "states"]
    # The daemon kills states only on blocking entry (M1-05), so a steady wake may run none: the check is that every state kill
    # the observer saw is scoped to en0, and that it saw daemon pfctl children at all (its positive control), never a silence.
    observed = controls[0]["daemonPfctlExecs"] if len(controls) == 1 else None
    kills_scoped = (len(kills) + len(controls) == len(events) and type(observed) is int and observed >= len(kills) and observed >= 1
                    and all(scoped(event) for event in kills))
    return [check("pfRuleOrderBeforeWake", rule_order(observation.get("rulesBefore", ""))),
            check("pfRuleOrderAfterWake", rule_order(observation.get("rulesAfter", ""))),
            check("interfaceScopedStateKills", kills_scoped)]


CHECKS = {"dns-edit": dns_checks, "logout": logout_checks, "rt21": rt21_checks,
          **{kind: (lambda observation, kind=kind: fault_checks(kind, observation)) for kind in ("token", "pf-disable", "rt22")}}


def parse_fault(text):
    if len(text.encode()) >= 45000:
        raise ValueError("fault observation too large")
    result = dict(samples=[])
    for line in text.splitlines():
        name, _, value = line.partition(" ")
        if name == "baseline":
            result["baseline"] = json.loads(value)
        elif name == "sample":
            result["samples"].append(json.loads(value))
        elif name == "injectedAt":
            result["injectedAt"] = float(value)
        else:
            raise ValueError("invalid fault observation")
    return result
