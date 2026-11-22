#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One row, one report. Fixture replay never imports or invokes the live transport."""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "Tools/lab"
# Rows whose catalogue entry names a driver run only through that script (M03-T11).
DRIVERS = {"auth-real": "auth-real.py"}
# The secret shapes Tools/lint/secret-shapes.py refuses in the tree (a test keeps them identical). Written reports
# carry SHA-256 digests as 12-hex prefixes, as the peer key check does; full records stay under buildRoot.
HEX = re.compile(r"(?<![0-9A-Za-z_])[0-9a-fA-F]{64}(?![0-9A-Za-z_])")
B64 = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/]{43}=?(?![A-Za-z0-9+/=_-])")
DIGEST_PREFIX_HEX = 12
# Row check kinds whose positive control leads (M1-10o fix pass 2, F2): verdict-live.LEAD_CONTROL_KINDS, mirrored here
# because replay never imports the live transport; a test keeps the two identical.
LEAD_CONTROL_KINDS = ("captive", "reboot-lockdown", "ondemand-eth")
EXCEPTION = dict(kind="labEscapeHatch", source="192.168.64.1", proto="tcp", port=22,
                 direction="host to guest SSH and replies", excludedFromLeakClaims=True)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


V = load_module("wgex_verdict", LAB / "verdict.py")
STATE = load_module("verdict_lab_state", LAB / "state.py")
HARNESS = load_module("verdict_lab_harness", LAB / "harness.py")
PROVENANCE = load_module("verdict_provenance", LAB / "check-verdicts.py")
# Shared product-path contract; never duplicate it in the producer.
PRODUCT_PATHS = PROVENANCE.PRODUCT_PATHS


def read(path, hashes, label):
    data = path.read_bytes()
    hashes[label] = hashlib.sha256(data).hexdigest()
    return json.loads(data)


def report_root(dry_run, requested, completed=False):
    build = STATE.build_root(ROOT)
    directory = requested or (build / "lab-verdict-replay" if dry_run else ROOT / "Tests/Reports/M1/M1-10" if completed else build / "lab-verdict-failures")
    directory = Path(directory).resolve()
    if dry_run and (directory == ROOT or ROOT in directory.parents):
        raise ValueError("fixture reports must stay outside the source tree")
    if not dry_run and not completed and (directory == ROOT or ROOT in directory.parents):
        directory = (build / "lab-verdict-failures").resolve()
        if directory == ROOT or ROOT in directory.parents:
            raise ValueError("failed preparations must stay outside the source tree")
    return directory


def escape_tail(match):
    """Length of a JSON escape's letters that open a match (n in \\n, u00e9 in \\u00e9); 0 when no escape precedes it."""
    text, start, slashes = match.string, match.start(), 0
    while start - slashes > 0 and text[start - slashes - 1] == "\\":
        slashes += 1
    if slashes % 2 == 0:
        return 0
    return 5 if text[start] == "u" else 1


def public_text(text):
    """Text exactly as written to disk with 64-hex digests cut to 12-hex prefixes and 43-character base64 runs redacted.

    It runs on serialised bytes, so a JSON escape letter that lengthens a run is seen as lint sees it; the
    escape's own letters are kept, so the JSON stays valid. A remaining shape refuses the write.
    """
    text = HEX.sub(lambda match: match[0][:DIGEST_PREFIX_HEX], text)
    text = B64.sub(lambda match: match[0][:escape_tail(match)] + "<redacted>", text)
    if HEX.search(text) or B64.search(text):
        raise ValueError("report text still carries a secret shape")
    return text


def public_payload(result):
    payload = public_text(json.dumps(result, indent=2, sort_keys=True))
    json.loads(payload)
    return payload.encode() + b"\n"


def set_path(value, path, replacement):
    for key in path[:-1]:
        value = value[key]
    value[path[-1]] = replacement


def replay_row_checks(row, hashes):
    """Guest run 8 rows (M1-10h): the row's named expectations on a recorded observation, plus one failing fixture per
    expectation that each must reject and passing variants that must still pass. Reboot rows also report the boot
    observation (appRunningAfterBoot, protectedBeforeAppSeen, timelineAvailable; daemonDrivenReconnect is null, not measured); REBOOT-INTENT has no row checks, so its
    failing fixtures name a boot observation field that each must turn false."""
    kind = row.get("checks")
    name = kind or ("reboot-intent" if row["action"] == "reboot" else None)
    if name is None:
        return {}
    fixture = read(LAB / "tests/fixtures/rows" / (name + ".json"), hashes, "fixture:rows:" + name)
    result = {}
    if "boot" in fixture["pass"]:
        result["bootObservation"] = V.boot_report(fixture["pass"]["boot"])
    def mutated(edits):
        observation = copy.deepcopy(fixture["pass"])
        for path, replacement in edits:
            set_path(observation, path, replacement)
        return observation
    if not kind:
        failing = [dict(expectation=case["expectation"], rejected=V.boot_report(mutated(case["set"])["boot"]).get(case["expectation"]) is False)
                   for case in fixture["failing"]]
        if failing:
            result.update(failingFixtures=failing, rowChecksMet=all(case["rejected"] for case in failing))
        return result
    def evaluated(edits):
        return {check["name"]: check for check in V.row_checks(kind, mutated(edits))}
    checks = V.row_checks(kind, fixture["pass"])
    passing = [dict(name=case["name"], met=all(check["met"] for check in evaluated(case["set"]).values()))
               for case in fixture.get("passing", [])]
    failing = [dict(expectation=case["expectation"], rejected=evaluated(case["set"]).get(case["expectation"], {}).get("met") is False)
               for case in fixture["failing"]]
    uncovered = sorted({check["name"] for check in checks} - {case["expectation"] for case in failing})
    result.update(checks=checks, passingFixtures=passing, failingFixtures=failing, failingFixturesUncovered=uncovered,
                  rowChecksMet=all(check["met"] for check in checks) and all(case["met"] for case in passing)
                  and all(case["rejected"] for case in failing) and not uncovered)
    return result


def replay(row, table, hashes):
    """Recorded markers exercise receiver provenance, mandatory tail and evaluator. A lockdown row (LEAD_CONTROL_KINDS)
    replays as the live driver runs it (M1-10o fix pass 2, F2): the unprotected fixture first as unprotectedLead, no
    trailing tail (lockdownOffNeedsAdmin), tailControl from the lead windows and tailControlPosition lead."""
    results, observations = [], []
    lead = row.get("checks") in LEAD_CONTROL_KINDS
    control = "unprotectedLead" if lead else "unprotectedTail"
    exercise = list(row.get("exercise", [row["state"]]))
    scenarios = [control] + exercise if lead else exercise + [control]
    for scenario in scenarios:
        state = "blocked" if scenario in ("connecting", "error") else "unprotected" if scenario == control else scenario
        fixture = "dns-protected" if row["action"] == "dns" and state == "protected" else state
        record = read(LAB / "tests/fixtures" / (fixture + ".json"), hashes, "fixture:" + fixture)
        record["action"] = row["action"]
        record["tunnelScope"] = V.tunnel_scope(row.get("profile", "default"))
        windows = V.evaluate(record, table, record.pop("receiverRecords"))["states"]
        if fixture == "dns-protected":
            observations.append(dict(source="recorded DNS-TUNNEL scutil observation", dns=record.get("dns", "")))
        for window in windows:
            window["scenario"] = scenario
        results.extend(windows)
    if not observations:
        observations.append(read(LAB / "tests/fixtures/guest.json", hashes, "fixture:guest"))
    for name in ["enable", "references-with-token", "info", "rules", "rules-verbose", "anchor-wgex"]:
        path = ROOT / "Tests/Fixtures/pfctl/macos26" / (name + ".txt")
        label = "references-table" if name == "references-with-token" else name
        hashes["pfTranscriptDigest:" + label] = hashlib.sha256(path.read_bytes()).hexdigest()
    if lead:
        windows = [item for item in results if item["scenario"] == control]
        tail = bool(windows) and all(item.get("expectationMet") is True for item in windows)
    else:
        tail = results[-1].get("expectationMet") is True
    rows = replay_row_checks(row, hashes)
    met = bool(results) and all(item.get("expectationMet") for item in results) and rows.pop("rowChecksMet", True)
    return dict(states=results, observations=observations, checks=rows.pop("checks", []), familiesCovered=["ipv4"] if tail else [],
                tailControl=dict(required=True, met=tail, receiptsRequired=True,
                                 receiverHealthProves="receiver binding and self-control only; guest delivery requires tail receipts",
                                 **(dict(trailSkipped="lockdownOffNeedsAdmin") if lead else {})),
                tailControlPosition="lead" if lead else "trail",
                clockMeasurement=dict(offsetSeconds=0, uncertaintySeconds=0, source="recorded fixture"),
                expectationsMet=met, **rows,
                transport="recorded markers; live orchestration is separately tested with an injected command runner")


def next_attempt(directory):
    """One past the highest kept attempt, so a retry never overwrites an earlier failure verdict."""
    numbers = [int(match[1]) for path in directory.glob("verdict-*.json") if (match := re.fullmatch(r"verdict-([1-9][0-9]{0,5})\.json", path.name))]
    return max(numbers, default=0) + 1


def write_report(directory, result, row, keep_attempts=False):
    directory.mkdir(parents=True, exist_ok=True)
    attempt = None
    if keep_attempts:
        attempt = result["attempt"] = next_attempt(directory)
    result = copy.deepcopy(dict(result, digestPrefixHex=DIGEST_PREFIX_HEX))
    # Reports are bounded summaries; receiver/probe records and captures stay in build output.
    payload = public_payload(result)
    if len(payload) > 50000:
        result["observations"] = [dict(note="Full observations retained under buildRoot")]
        for window in result.get("states", []):
            window["offendingObservationCount"] = len(window.get("offendingObservations", []))
            window["offendingObservations"] = window.get("offendingObservations", [])[:4]
        payload = public_payload(result)
    if len(payload) > 50000:
        raise ValueError("bounded report exceeded 50 KB")
    written = directory / "verdict.json"
    if attempt is not None:
        # Exclusive create: verdict-<n>.json is immutable; verdict.json is a copy of the latest attempt.
        written = directory / f"verdict-{attempt}.json"
        with written.open("xb") as handle:
            handle.write(payload)
    (directory / "verdict.json").write_bytes(payload)
    lines = [f"# {result['row']} - {row['title']}", "", f"Date: {result['date']}.", "",
             f"Mode: {'fixture replay' if result['dryRun'] else 'live guest orchestration'}.",
             f"Expectations met: {str(result['expectationsMet']).lower()}; live acceptance: {str(result['liveAcceptance']).lower()}.", "",
             *([f"Attempt: {attempt} (verdict-{attempt}.json; earlier attempts are kept beside it).", ""] if attempt is not None else []),
             "Exception in every claim: host 192.168.64.1 TCP/22 guest SSH and replies (Lab escape hatch).", "",
             "Steps:", ""]
    lines.extend(f"{n}. {step}" for n, step in enumerate(row["steps"], 1))
    lines.extend(["", "Expected:", ""] + ["- " + item for item in row["expected"]])
    if result.get("gaps"):
        lines.extend(["", "Not verified:", ""] + ["- " + item for item in result["gaps"]])
    if result.get("checksNotMeasured"):
        # M1-10q fix pass 1 (VERIFY N1): a check that measured nothing is named, never read as a pass.
        lines.extend(["", "Not measured (neither a pass nor a fail; the row's PASS rests on its measured checks):", ""]
                     + [f"- {item['name']}: {item['reason']}" for item in result["checksNotMeasured"]])
    lines.extend(["", "Orchestrator:", "", "```sh", f"just lab verdict {result['row']}", "```", "",
                  "Raw probe/receiver records and guest captures belong under build_root()/lab-captures, never here.", ""])
    (directory / "README.md").write_text(public_text("\n".join(lines)))
    return written


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("row", nargs="?")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--report-root", type=Path)
    parser.add_argument("--controls", type=Path, help="optional calibrated label -> [x,y] map; no secrets")
    parser.add_argument("--no-install", action="store_true", help="reuse snapshot only if its installed binaries match this checkout's verified Lab build")
    args = parser.parse_args(argv)
    hashes = {}
    catalogue = read(LAB / "rows.json", hashes, "catalogue")["rows"]
    if args.list:
        sys.stdout.write("\n".join(f"{name}: {row['title']}" for name, row in catalogue.items()) + "\n")
        return 0
    if args.row not in catalogue:
        parser.error("row must be in --list")
    row = catalogue[args.row]
    if row.get("driver"):
        # M03-T11: a row with its own driver (AUTH-REAL) runs only through it, live, with --report-root; the shared pipeline
        # would judge it on leak windows it does not have.
        driver = DRIVERS.get(row["driver"])
        if driver is None or args.dry_run or args.no_install or args.controls or args.report_root is None:
            parser.error(f"{args.row} runs through its own driver: --report-root DIR only")
        os.execv(sys.executable, [sys.executable, "-I", "-B", str(LAB / driver), "--report-root", str(args.report_root)])
    # Host load at start and end (M1-10i): recorded in hostLoad and warned about in one line; never a verdict input.
    load_start = HARNESS.host_load()
    warned = HARNESS.warning(load_start, "start")
    if warned:
        sys.stderr.write(warned + "\n")
    table = read(LAB / "leak-expectations.json", hashes, "expectations")
    result = dict(schemaVersion=1, row=args.row, date=datetime.now(timezone.utc).isoformat(), dryRun=args.dry_run,
                  guestOS={}, sourceCommit=None, buildConfiguration=None, buildInputs={}, artefacts={}, installed={},
                  prepareCompleted=False, rowCompleted=False,
                  liveAcceptance=False, exceptions=[EXCEPTION], inputHashes=hashes, gaps=[], expectationsMet=False, familiesCovered=[],
                  dependencies=row.get("dependencies", {}), profileVariant=row.get("profile", "default"),
                  tailControl=dict(required=True, met=False, receiverHealthProves="binding only; guest delivery requires tail receipts"))
    if row.get("gap"):
        result["gaps"].append(row["gap"])
    if not args.dry_run:
        result["gaps"].extend(row.get("dependencies", {}).values())
    try:
        if args.dry_run:
            result.update(replay(row, table, hashes))
            result["replayExpectationsMet"] = result["expectationsMet"]
        elif not result["gaps"]:
            live = load_module("wgex_live", LAB / "verdict-live.py")
            controls = read(args.controls, hashes, "controls") if args.controls else {}
            result.update(live.run(args.row, row, table, V, controls, no_install=args.no_install, host_load_start=load_start))
            # Do not let a live transport (including injected runners) assert a
            # pass without the same provenance the acceptance reader requires.
            guest = result.get("guestOS")
            major = str(guest.get("productVersion", "")).split(".")[0] if isinstance(guest, dict) else ""
            failures = PROVENANCE.provenance_errors(result, major)
            if failures:
                result["gaps"].extend("Provenance: " + failure for failure in failures)
        if result["gaps"]:
            result["expectationsMet"] = False
        result["liveAcceptance"] = not args.dry_run and result["expectationsMet"] and not result["gaps"]
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        # Tool output can include UI contents; never expose raw stderr or exception text.
        result["gaps"].append("Pipeline failed closed: " + type(error).__name__ + "; inspect non-secret step ledger in build output")
        result["expectationsMet"] = False
    # M1-10q fix pass 1 (VERIFY N1): checks that measured nothing are listed and never counted as met.
    result["checksNotMeasured"] = V.checks_not_measured(result.get("checks"))
    result["checkCounts"] = V.check_counts(result.get("checks"))
    if not isinstance(result.get("hostLoad"), dict):
        result["hostLoad"] = HARNESS.load_record(load_start, HARNESS.host_load())
    if not warned and HARNESS.warning(result["hostLoad"].get("end") or {}, "end"):
        sys.stderr.write(HARNESS.warning(result["hostLoad"]["end"], "end") + "\n")
    try:
        completed = result.get("rowCompleted") is True and bool(result.get("states"))
        destination = report_root(args.dry_run, args.report_root, completed=completed)
        result["reportDisposition"] = "fixture replay" if args.dry_run else "completed row" if completed else "incomplete run; build root only"
        # Every failed live attempt keeps its verdict; only replays and fully accepted rows keep one.
        written = write_report(destination / args.row, result, row, keep_attempts=not args.dry_run and not result["liveAcceptance"])
    except (OSError, ValueError, TypeError):
        sys.stderr.write("verdict: unable to write permitted report output\n")
        return 2
    unmeasured = "".join(f"; {item['name']} {item['reason']}" for item in result["checksNotMeasured"])
    sys.stdout.write(f"{args.row}: {'PASS (fixture replay only)' if args.dry_run and result['expectationsMet'] else 'PASS' if result['liveAcceptance'] else 'UNKNOWN/FAIL'}{unmeasured}; {written}\n")
    return 0 if result["expectationsMet"] else 1


if __name__ == "__main__":
    sys.exit(main())
