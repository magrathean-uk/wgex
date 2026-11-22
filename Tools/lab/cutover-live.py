#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""M03-T08: the live guest cutover rehearsal, one guest and one verdict.

Started by `cutover-rehearsal.sh --report-root DIR GUEST` (the guest name arrives as WGEX_LAB_VM). It prepares the guest
exactly as a verdict row does (verdict-live.Session.prepare: snapshot restore, Lab build and install, provenance, app,
relay, peer and the full4-name profile imported idle), runs the four scenarios through `cutover-rehearsal.sh --scenario` and
the ten RUNBOOK supplements, and writes DIR/cutover-rehearsal/verdict.json with a row's provenance fields and the fourteen
booleans of check-verdicts.REHEARSAL_CHECKS. check-verdicts.py --rehearsal cutover-rehearsal is the only judge.
Reboot steps are judged only by the daemon that answers after the boot session changed.
"""
import argparse
import copy
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "Tools/lab"
ROW = "cutover-rehearsal"
PROFILE = "full4-name"
SCRIPT = LAB / "cutover-rehearsal.sh"
SCENARIOS = ("expiryRollback", "confirmThenRebootRestoresIntent", "abort", "rebootWhileArmedRollback")
SUPPLEMENTS = ("receiverLeakVerdict", "unrelatedRoutesAndReferencesPreserved", "dedicatedPeerHandshake", "appAbsentAndPresent",
               "failedStopRetry", "restartDuringRollback", "confirmedRestartRestoresIntent",
               "rebootWindowUnprotectedRecoveryNotBlocked", "manualRecoveryDevDaemon", "oldGuestClientAvailable")
REPORT_LIMIT = 50000
# Seconds for one scenario step: a reboot step includes the scheduled shutdown (75 s), the scaled SSH readiness bound and
# the 180 s rollback poll; the others are bounded by the 180 s poll and the 60 s remember deadline.
STEP_SECONDS = dict(reboot=3000, other=900)
POST_BOOT_SAMPLES = 10
HANDSHAKE_SLACK_SECONDS = 5
# The one rollback step the failed-stop fixture blocks (the daemon's unlink of the trial's bundle).
BLOCKED_STEP = ("deleteSecrets",)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


RUN = load_module("cutover_verdict_run", LAB / "verdict-run.py")
V, HARNESS, PROVENANCE, STATE = RUN.V, RUN.HARNESS, RUN.PROVENANCE, RUN.STATE
if SCENARIOS + SUPPLEMENTS != PROVENANCE.REHEARSAL_CHECKS:
    raise SystemExit("cutover-live: keys differ from check-verdicts.REHEARSAL_CHECKS")


class StepFailure(Exception):
    """A check's own failure, with a short public reason."""


def status_summary(status):
    """The public status fields a check is judged on; nothing else leaves the guest record."""
    cutover = status.get("cutover") if isinstance(status.get("cutover"), dict) else {}
    return dict(phase=status.get("phase"), protection=status.get("protection"), policyEnforcing=status.get("policyEnforcing"),
                activeProfileID=status.get("activeProfileID"), cutoverState=cutover.get("state"), cutoverReason=cutover.get("reason"),
                rollbackFailures=status.get("cutoverRollbackFailures"), recoveryFailureReason=status.get("recoveryFailureReason"),
                operationInFlight=status.get("operationInFlight"))


def rolled_back_unprotected(summary, reason, recovered=()):
    """The rolled-back end state: the reason, unprotected, idle, no policy, no profile, no blocked recovery. The trial record
    keeps the names of failed attempts after a retry completes them (guest run M03-T08), so a recovered rollback may list
    exactly the steps it was made to fail (recovered); any other name, or one on a clean rollback, fails."""
    failures = summary["rollbackFailures"]
    return (summary["cutoverState"] == "rolledBack" and summary["cutoverReason"] == reason and summary["protection"] == "unprotected"
            and summary["phase"] == "idle" and summary["policyEnforcing"] is False and summary["activeProfileID"] is None
            and isinstance(failures, list) and set(failures) <= set(recovered) and summary["recoveryFailureReason"] is None)


def restored_intent(summary, profile):
    return (summary["cutoverState"] == "confirmed" and summary["activeProfileID"] == profile and summary["phase"] == "active"
            and summary["protection"] == "protected")


def bounded(result):
    """The verdict payload under 50 KB: windows keep their verdict and at most four offending observations."""
    payload = RUN.public_payload(result)
    if len(payload) > REPORT_LIMIT:
        result = copy.deepcopy(result)
        for window in result.get("leakWindows", []):
            window["offendingObservationCount"] = len(window.get("offendingObservations", []))
            window["offendingObservations"] = window.get("offendingObservations", [])[:4]
        payload = RUN.public_payload(result)
    if len(payload) > REPORT_LIMIT:
        raise ValueError("bounded report exceeded 50 KB")
    return payload


# DEC-030: what oldGuestClientAvailable establishes in the guest; the README row names it whatever the run's summary says,
# and claims the proof only when the check was met (a failed or unreached check states what it is meant to establish).
def old_client_note(met):
    claim = "proves" if met else "is meant to establish that"
    return (f"foreign-utun stand-in for the old client (DEC-030): {claim} another client's utun, address and routes "
            "survive cutover and rollback; the official app's reconnection is checked at the maintainer's sitting")


def orchestrator_target(guest):
    """The README's commands: a macos27 guest's rehearsal lives under Tests/Reports/v2/macos27 (M03-T10); every other
    guest keeps the macOS 26 commands."""
    if isinstance(guest, str) and guest.startswith("macos27-"):
        return "27", "macos27-wgex", "Tests/Reports/v2/macos27"
    return "26", "macos26-wgex", "Tests/Reports/v2"


def readme(result):
    lines = [f"# {ROW} - M1-12 guest cutover rehearsal", "", f"Date: {result['date']}.", "",
             f"Guest: {result.get('guest')} (macOS {result.get('guestOS', {}).get('productVersion', 'unknown')}); "
             f"profile {result.get('profileVariant', 'full4')}.",
             f"Live acceptance: {str(result['liveAcceptance']).lower()}.", "",
             "Exception in every claim: host 192.168.64.1 TCP/22 guest SSH and replies (Lab escape hatch).", "",
             "| Check | Met | Evidence |", "|---|---|---|"]
    for key in PROVENANCE.REHEARSAL_CHECKS:
        item = result["checks"].get(key, {})
        evidence = item.get('summary', 'not reached')
        met = result.get(key) is True
        if key == "oldGuestClientAvailable":
            evidence = f"{evidence}; {old_client_note(met)}"
        lines.append(f"| {key} | {str(met).lower()} | {evidence} |")
    if result.get("gaps"):
        lines.extend(["", "Not verified:", ""] + ["- " + gap for gap in result["gaps"]])
    major, guest, root = orchestrator_target(result.get("guest"))
    lines.extend(["", "Orchestrator:", "", "```sh", f"bash Tools/lab/cutover-rehearsal.sh --report-root {root} {guest}",
                  f"python3 -I Tools/lab/check-verdicts.py --root {root} --guest-os {major} --since M02 --rehearsal cutover-rehearsal",
                  "```", "", "Receiver records, captures and the step ledger stay under build_root()/lab-captures, never here.", ""])
    return RUN.public_text("\n".join(lines))


def write_report(directory, result):
    """verdict.json plus README.md; a run that is not accepted is also kept as verdict-<n>.json (exclusive create)."""
    directory.mkdir(parents=True, exist_ok=True)
    payload = bounded(result)
    if not result["liveAcceptance"]:
        attempt = RUN.next_attempt(directory)
        result["attempt"] = attempt
        payload = bounded(result)
        with (directory / f"verdict-{attempt}.json").open("xb") as handle:
            handle.write(payload)
    (directory / "verdict.json").write_bytes(payload)
    (directory / "README.md").write_text(readme(result))
    return directory / "verdict.json"


class Rehearsal:
    def __init__(self, session, guest):
        self.session, self.guest = session, guest
        self.checks = {key: dict(met=False, summary="not reached") for key in PROVENANCE.REHEARSAL_CHECKS}
        self.unrelated = []  # one entry per unrelated-fixture check after a rollback
        self.leak_records, self.profile, self.gaps = [], None, []
        self.unrelated_up = self.foreign_up = False

    # Transport.
    def scenario(self, step, check=True):
        kind = "reboot" if "reboot" in step else "other"
        argv = ["bash", str(SCRIPT), "--scenario", step, self.profile]
        env = dict(os.environ, WGEX_LAB_VM=self.guest)
        output = self.session.command(argv, timeout=STEP_SECONDS[kind], check=False, env=env)
        code = self.session.ledger[-1].get("exitCode")
        if check and code != 0:
            raise StepFailure(f"scenario step {step} exited {code}")
        return code, output

    def sup(self, action, *args, check=True):
        command = shlex.join(["bash", self.session.stage + "/cutover-supplements.sh", action, *args])
        # The drill's step lines go to the ledger (they carry no token); the other actions print one state line.
        return self.session.ssh(command, check=check, record_stdout=action == "manual-drill").decode(errors="replace").strip()

    def status(self):
        return status_summary(json.loads(self.session.ssh(LIVE.CLI + " status --json", check=False) or b"{}"))

    def stage_helpers(self):
        for name in ("guard.sh", "journal-replay.pl", "cutover-supplements.sh", "verdict-actions.sh"):
            self.session.guest_file((LAB / "tart/guest" / name).read_bytes(), name)

    def ensure_app(self):
        if self.sup("app-state") != "app=running":
            self.session.lab("gui", "run", "open", "-a", "WGEX")
            deadline = time.monotonic() + 60
            while self.sup("app-state") != "app=running":
                if time.monotonic() > deadline:
                    raise StepFailure("WGEX did not start in the console session")
                time.sleep(1)
            time.sleep(3)

    def boot_session(self):
        value = self.sup("boot-session")
        if not re.fullmatch(LIVE.UUID_PATTERN, value):
            raise StepFailure("boot session unreadable")
        return value

    def after_reboot(self, before):
        """The boot session must have changed; helpers are staged again; the app is reopened if macOS did not."""
        after = self.boot_session()
        if after == before:
            raise StepFailure("the guest did not reboot (boot session unchanged)")
        self.session.ssh("umask 077; mkdir -p " + shlex.quote(self.session.stage))
        self.stage_helpers()

    def await_summary(self, predicate, seconds, what):
        deadline, last = time.monotonic() + seconds, None
        while time.monotonic() < deadline:
            try:
                last = self.status()
                if predicate(last):
                    return last
            except (RuntimeError, ValueError):
                pass
            time.sleep(1)
        raise StepFailure(f"{what} not reached within {seconds} s (last {last})")

    def recover(self):
        """Best effort after a failed check: clear the bundle flag and abort, so the next check starts from no trial."""
        for operation in (lambda: self.sup("secrets-unlock", self.profile, check=False),
                          lambda: self.scenario("abort-attempt", check=False)):
            try:
                operation()
            except (RuntimeError, OSError, ValueError):
                pass

    def run_check(self, key, body):
        try:
            evidence = body()
            self.checks[key] = dict(met=True, **evidence)
        except (StepFailure, RuntimeError, OSError, ValueError, KeyError, TypeError) as error:
            reason = str(error) if isinstance(error, StepFailure) else type(error).__name__ + " in a guest step; see the step ledger"
            self.checks[key] = dict(met=False, summary="failed: " + reason[:300])
            self.gaps.append(f"{key}: {reason[:300]}")
            self.recover()

    def unrelated_check(self, after):
        if not self.unrelated_up:
            return
        line = self.sup("unrelated-check", check=False)
        foreign = self.foreign_alive()
        self.unrelated.append(dict(after=after, fixtures=line, foreignClientRoutes=foreign,
                                   met=line == "unrelated route=present reference=present" and foreign))

    def foreign_alive(self):
        command = shlex.join(["bash", self.session.stage + "/verdict-actions.sh", "check-foreign"])
        self.session.ssh(command, check=False)
        return self.session.ledger[-1].get("exitCode") == 0

    # The checks, in the order the guest runs them.
    def prepare(self):
        self.session.prepare(PROFILE, connect=False)
        self.profile = self.session.profile_ids[PROFILE]
        self.stage_helpers()
        summary = self.status()
        if summary["phase"] != "idle" or summary["protection"] != "unprotected" or summary["activeProfileID"] is not None:
            raise StepFailure(f"the guest is not idle before the rehearsal ({summary})")
        lockdown = self.session.guest_action("lockdown-state").decode().strip()
        boot = self.session.guest_action("boot-intent", self.profile).decode().strip()
        if lockdown != "lockdown=false" or boot != "bootIntent=false":
            raise StepFailure(f"preconditions: {lockdown}, {boot}")
        # The old guest client (a second utun owner with its own address and scoped /1 routes, the foreign-utun fixture)
        # and the unrelated route and pf reference stay in place through every rollback that keeps the boot.
        self.session.guest_action("foreign-up")
        self.foreign_up = True
        self.session.cleanups.append(LIVE.named("foreign-down", lambda: self.session.guest_action("foreign-down")))
        self.sup("unrelated-up")
        self.unrelated_up = True
        self.session.cleanups.append(LIVE.named("unrelated-down", lambda: self.sup("unrelated-down")))

    def expiry(self):
        self.scenario("expiry")
        summary = self.status()
        if not rolled_back_unprotected(summary, "timeout"):
            raise StepFailure(f"after expiry: {summary}")
        self.unrelated_check("expiry")
        return dict(summary="60 s window expired; rolledBack(timeout), every effect removed, unprotected and idle", status=summary)

    def armed_abort_with_leak_window(self):
        """One armed trial carries the receiver leak window and the handshake check; abort then reverts it, and an
        unprotected window after the rollback is the positive control."""
        session = self.session
        config = dict(format="marker", intervalMilliseconds=500, targets=[
            dict(address="192.168.64.1", scope="outside_tunnel", dnsPort=5354, httpPort=8088, udpPort=8088, allowedLAN=False),
            dict(address="10.77.0.1", scope="in_tunnel", dnsPort=53, httpPort=8088, udpPort=8088, allowedLAN=False)])
        session.start_receivers(config)
        session.pause(session.clock_tolerance + 0.1)
        started = time.time()
        self.scenario("start")
        session.await_status("protected", timeout=60)
        session.pause(session.clock_tolerance * 2 + 0.1)
        self.leak_records.append(session.generate("protected", role="armedTrial"))
        self.run_check("dedicatedPeerHandshake", lambda: self.handshake(time.time() - started))
        self.run_check("abort", self.abort_armed)
        session.pause(session.clock_tolerance * 2 + 0.1)
        self.leak_records.append(session.generate("unprotected", role="unprotectedTail"))
        self.run_check("receiverLeakVerdict", self.leak_verdict)

    def handshake(self, since_start):
        raw = self.session.peer("bash", "-c", "set -eu; now=$(date +%s); sudo -n wg show wg0 latest-handshakes | awk -v now=\"$now\" "
                                "'{ n++; if ($2 > 0) age = now - $2 } END { if (n != 1 || age == \"\") exit 1; print age }'")
        age = int(raw.decode().strip())
        if not 0 <= age <= since_start + HANDSHAKE_SLACK_SECONDS:
            raise StepFailure(f"latest handshake {age} s old, the trial started {since_start:.0f} s ago")
        return dict(summary=f"wg-peer's one peer handshook {age} s ago, after the trial started {since_start:.0f} s earlier",
                    handshakeAgeSeconds=age, trialAgeSeconds=round(since_start, 1))

    def abort_armed(self):
        before = self.status()
        if before["cutoverState"] != "armed" or before["protection"] != "protected":
            raise StepFailure(f"not armed and protected before abort ({before})")
        self.scenario("abort")
        summary = self.status()
        if not rolled_back_unprotected(summary, "aborted"):
            raise StepFailure(f"after abort: {summary}")
        self.unrelated_check("abort")
        return dict(summary="armed and protected, then abort; rolledBack(aborted), every effect removed", status=summary)

    def leak_verdict(self):
        errors = self.session.collect()
        self.session.receiver_started = False
        receivers, named = [], []
        for name in ("host", "peer"):
            path = self.session.output / (name + ".json")
            if not path.exists():
                continue
            value = json.loads(path.read_bytes())
            for item in value["observations"]:
                item["timestamp"] += self.session.clock["offsetSeconds"]
            for item in value.get("receiverCoverage", []):
                item["start"] += self.session.clock["offsetSeconds"]
                item["end"] += self.session.clock["offsetSeconds"]
            receivers.append(value)
            named.append((name, value))
        health = V.receiver_health_gaps(named)
        windows = []
        for record in self.leak_records:
            record["action"], record["tunnelScope"] = "cutover", V.tunnel_scope(PROFILE)
            (self.session.output / f"generator-{record['role']}.json").write_bytes(V.canonical(record))
            windows.extend(dict(window, role=record["role"]) for window in V.evaluate(record, TABLE, receivers)["states"])
        self.leak_windows = windows
        roles = {window["role"] for window in windows}
        met = (not errors and not health and roles == {"armedTrial", "unprotectedTail"}
               and all(window.get("expectationMet") is True for window in windows))
        if not met:
            raise StepFailure("leak windows " + ", ".join(f"{w['role']}={w.get('expectationMet')}" for w in windows)
                              + ("; " + "; ".join(errors + health) if errors or health else ""))
        return dict(summary="armed trial: in-tunnel receipts only; after rollback: the outside receivers see the guest (control)",
                    windows=[dict(role=w["role"], state=w.get("state"), expectationMet=w.get("expectationMet")) for w in windows])

    def app_absent_and_present(self):
        session = self.session
        session.quit_app()
        if self.sup("app-state") != "app=absent":
            raise StepFailure("the app did not quit")
        code, _ = self.scenario("start", check=False)
        absent = self.status()
        bundle = self.sup("bundle-state", self.profile)
        if code == 0 or absent["cutoverState"] == "armed" or absent["activeProfileID"] is not None or bundle != "bundle=absent":
            raise StepFailure(f"with the app absent the start was not refused cleanly (exit {code}, {absent}, {bundle})")
        self.ensure_app()
        self.scenario("start")
        armed = self.status()
        if armed["cutoverState"] != "armed" or armed["protection"] != "protected":
            raise StepFailure(f"with the app present the trial did not arm ({armed})")
        session.quit_app()
        self.scenario("abort")
        summary = self.status()
        if not rolled_back_unprotected(summary, "aborted"):
            raise StepFailure(f"abort with the app absent: {summary}")
        self.unrelated_check("abort with the app absent")
        self.ensure_app()
        return dict(summary=f"app absent: start refused (exit {code}), nothing armed, no bundle; app present: armed and protected; "
                            "app quit while armed: abort reverted every effect", refusedExit=code, absentStatus=absent)

    def failed_stop_retry(self):
        self.scenario("start")
        self.sup("secrets-lock", self.profile)
        code, _ = self.scenario("abort-attempt", check=False)
        failed = self.status()
        journal = self.sup("journal-cutover")
        failures = failed["rollbackFailures"] or []
        if code == 0 or journal != "rollbackPending=true reason=aborted" or not set(BLOCKED_STEP) <= set(failures):
            raise StepFailure(f"the blocked rollback did not stay pending (exit {code}, {journal}, {failed})")
        self.sup("secrets-unlock", self.profile)
        # The retry keeps the trial's remembered resources: once releaseToken ran, the journal has no token, and the
        # unrelated reference would be the sole pfctl References row a fresh remember falls back to.
        retry, _ = self.scenario("abort-attempt", check=False)
        if retry != 0:
            raise StepFailure(f"retried abort exited {retry}")
        self.scenario("assert-aborted")
        summary = self.status()
        if not rolled_back_unprotected(summary, "aborted", BLOCKED_STEP) or self.sup("journal-cutover") != "rollbackPending=false reason=aborted":
            raise StepFailure(f"retried abort: {summary}")
        self.unrelated_check("retried abort")
        return dict(summary=f"bundle delete blocked: abort exit {code}, rollbackPending, failures {sorted(set(failures))}; "
                            "retried abort completed every step", firstExit=code, pendingStatus=failed)

    def restart_during_rollback(self):
        self.scenario("start")
        self.sup("secrets-lock", self.profile)
        code, _ = self.scenario("abort-attempt", check=False)
        journal = self.sup("journal-cutover")
        if code == 0 or journal != "rollbackPending=true reason=aborted":
            raise StepFailure(f"no pending rollback to restart into (exit {code}, {journal})")
        self.sup("secrets-unlock", self.profile)
        self.sup("restart-daemon")
        self.scenario("settle-aborted")
        summary = self.await_summary(lambda s: rolled_back_unprotected(s, "aborted", BLOCKED_STEP), 60, "rolled back after the restart")
        if self.sup("journal-cutover") != "rollbackPending=false reason=aborted":
            raise StepFailure("journal still pending after the restart")
        self.unrelated_check("daemon restart during a pending rollback")
        return dict(summary="rollback left pending, daemon restarted (kickstart -k); the new daemon finished it at startup "
                            "without another abort", status=summary)

    def confirmed_restart(self):
        self.scenario("start")
        self.scenario("confirm")
        self.sup("restart-daemon")
        summary = self.await_summary(lambda s: restored_intent(s, self.profile), 120, "confirmed intent after the restart")
        self.scenario("abort")
        after = self.status()
        if not rolled_back_unprotected(after, "aborted"):
            raise StepFailure(f"abort of the confirmed trial: {after}")
        self.unrelated_check("abort of a confirmed trial")
        return dict(summary="confirmed trial: after a daemon restart the profile is active and protected again; abort then "
                            "reverted it", status=summary)

    def unrelated_preserved(self):
        if not self.unrelated or not all(item["met"] for item in self.unrelated):
            raise StepFailure("unrelated fixtures lost: " + "; ".join(f"{i['after']}: {i['fixtures']}, foreign {i['foreignClientRoutes']}"
                                                                    for i in self.unrelated if not i["met"]))
        self.sup("unrelated-down")
        self.unrelated_up = False
        self.session.guest_action("foreign-down")
        self.foreign_up = False
        return dict(summary=f"scoped host route, own pf reference and the old client's utun routes intact after "
                            f"{len(self.unrelated)} rollbacks; then removed by their owner", after=[i["after"] for i in self.unrelated])

    def confirm_then_reboot(self):
        self.ensure_app()
        self.scenario("start")
        self.scenario("confirm")
        before = self.boot_session()
        self.scenario("reboot-confirmed")
        self.after_reboot(before)
        summary = self.await_summary(lambda s: restored_intent(s, self.profile), 180, "confirmed intent after the reboot")
        self.ensure_app()
        self.scenario("abort")
        after = self.status()
        if not rolled_back_unprotected(after, "aborted"):
            raise StepFailure(f"abort after the reboot: {after}")
        return dict(summary="confirmed, rebooted: the post-boot daemon restored the profile active and protected; abort then "
                            "reverted it", status=summary)

    def armed_reboot(self):
        self.ensure_app()
        self.scenario("start")
        before = self.boot_session()
        code, _ = self.scenario("armed-reboot", check=False)
        self.after_reboot(before)
        samples = []
        for _ in range(POST_BOOT_SAMPLES):
            samples.append(self.status())
            time.sleep(1)
        final = samples[-1]
        blocked = [s for s in samples if s["protection"] in ("blocked", "unknown") or s["phase"] in ("failed", "reasserting")
                   or s["policyEnforcing"] is True or s["recoveryFailureReason"] is not None]
        self.checks["rebootWindowUnprotectedRecoveryNotBlocked"] = (
            dict(met=True, summary=f"post-boot daemon, {len(samples)} samples at 1 s: never blocked or enforcing, "
                                   "unprotected and idle, no recovery failure", samples=len(samples))
            if not blocked and all(s["protection"] == "unprotected" for s in samples)
            else dict(met=False, summary=f"post-boot samples not all unprotected and unblocked: {blocked[:2] or samples[:2]}"))
        if code != 0 or not rolled_back_unprotected(final, "daemonRestart"):
            raise StepFailure(f"armed reboot (scenario exit {code}): {final}")
        return dict(summary="armed, rebooted: the post-boot daemon rolled back with reason daemonRestart; unprotected and idle, "
                            "recovery not blocked", status=final)

    def manual_recovery(self):
        self.ensure_app()
        self.scenario("start")
        output = self.sup("manual-drill", self.profile, f"/Users/{LIVE.GUEST_USER}/lab/cutover")
        before = self.boot_session()
        self.session.guest_action("reboot", check=False)
        time.sleep(30)
        self.session.await_guest()
        self.after_reboot(before)
        self.scenario("settle-daemonRestart")
        summary = self.status()
        if not rolled_back_unprotected(summary, "daemonRestart"):
            raise StepFailure(f"after the drill and reboot: {summary}")
        steps = [line for line in output.splitlines() if line]
        return dict(summary="bootout of the .dev.daemon job (print 113), anchor flush, exact token release, canary and DNS key "
                            "removed; after the reboot the daemon completed the durable cleanup (rolledBack(daemonRestart))",
                    drill=steps[-8:], status=summary)

    def old_client(self):
        self.session.guest_action("foreign-up")
        self.foreign_up = True
        alive = self.foreign_alive()
        status = self.status()
        self.session.guest_action("foreign-down")
        self.foreign_up = False
        if not alive or status["phase"] != "idle":
            raise StepFailure(f"old client fixture not usable after the rehearsal (routes {alive}, {status})")
        return dict(summary="after the last rollback the foreign-utun stand-in's utun came up with its address and scoped "
                            "routes and went down again; WGEX stayed idle")

    def run(self):
        self.prepare()
        self.run_check("expiryRollback", self.expiry)
        self.ensure_app()
        try:
            self.armed_abort_with_leak_window()
        except (StepFailure, RuntimeError, OSError, ValueError, KeyError, TypeError) as error:
            self.gaps.append("leak window: " + (str(error) if isinstance(error, StepFailure) else type(error).__name__))
            self.recover()
        self.ensure_app()
        self.run_check("appAbsentAndPresent", self.app_absent_and_present)
        self.ensure_app()
        self.run_check("failedStopRetry", self.failed_stop_retry)
        self.ensure_app()
        self.run_check("restartDuringRollback", self.restart_during_rollback)
        self.ensure_app()
        self.run_check("confirmedRestartRestoresIntent", self.confirmed_restart)
        self.run_check("unrelatedRoutesAndReferencesPreserved", self.unrelated_preserved)
        self.run_check("confirmThenRebootRestoresIntent", self.confirm_then_reboot)
        self.run_check("rebootWhileArmedRollback", self.armed_reboot)
        self.run_check("manualRecoveryDevDaemon", self.manual_recovery)
        self.run_check("oldGuestClientAvailable", self.old_client)


LIVE = None
TABLE = None


def main(argv=None):
    global LIVE, TABLE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-root", type=Path, required=True)
    args = parser.parse_args(argv)
    guest = os.environ.get("WGEX_LAB_VM", "")
    if not re.fullmatch(r"macos(26|27)-wgex(-[A-Za-z0-9_-]+)?", guest):
        parser.error("WGEX_LAB_VM must name the guest")
    hashes = {}
    TABLE = RUN.read(LAB / "leak-expectations.json", hashes, "expectations")
    LIVE = load_module("cutover_live_transport", LAB / "verdict-live.py")
    load_start = HARNESS.host_load()
    session = LIVE.Session(ROW, {})
    rehearsal = Rehearsal(session, guest)
    result = dict(schemaVersion=1, row=ROW, date=datetime.now(timezone.utc).isoformat(), dryRun=False, guest=guest,
                  profileVariant=PROFILE, exceptions=[RUN.EXCEPTION], inputHashes=hashes)
    completed = False
    try:
        rehearsal.run()
        initial = copy.deepcopy(session.provenance)
        session.measure_provenance()
        if session.provenance != initial:
            rehearsal.gaps.append("provenanceChanged: build or guest provenance changed during the rehearsal")
        completed = True
    except (StepFailure, RuntimeError, OSError, ValueError, KeyError, TypeError) as error:
        rehearsal.gaps.append("rehearsal stopped: " + (str(error) if isinstance(error, StepFailure) else type(error).__name__
                                                         + "; see the step ledger under buildRoot"))
    finally:
        if rehearsal.profile and not completed:
            rehearsal.recover()
        session.collect()
        warnings = session.cleanup()
    result.update(session.provenance, installation=session.installation, profileID=rehearsal.profile, cleanupWarnings=warnings,
                  checks=rehearsal.checks, leakWindows=getattr(rehearsal, "leak_windows", []), unrelatedChecks=rehearsal.unrelated,
                  clockMeasurement=session.clock, buildRoot=str(session.output), rehearsalCompleted=completed,
                  hostLoad=HARNESS.load_record(load_start, HARNESS.host_load()),
                  transport="guarded Tart SSH, console-session CLI (asu.sh) and dedicated Lima peer")
    for key in PROVENANCE.REHEARSAL_CHECKS:
        result[key] = rehearsal.checks[key].get("met") is True
    major = str(result.get("guestOS", {}).get("productVersion", "")).split(".")[0]
    rehearsal.gaps.extend("Provenance: " + failure for failure in PROVENANCE.provenance_errors(result, major))
    result["gaps"] = rehearsal.gaps
    result["liveAcceptance"] = completed and not rehearsal.gaps and all(result[key] for key in PROVENANCE.REHEARSAL_CHECKS)
    (session.output / "steps.json").write_text(json.dumps(session.ledger, indent=2))
    destination = args.report_root.resolve() if completed else (STATE.build_root(ROOT) / "lab-verdict-failures").resolve()
    try:
        written = write_report(destination / ROW, result)
    except (OSError, ValueError, TypeError):
        sys.stderr.write("cutover rehearsal: unable to write permitted report output\n")
        return 2
    met = sum(result[key] for key in PROVENANCE.REHEARSAL_CHECKS)
    sys.stdout.write(f"{ROW}: {'PASS' if result['liveAcceptance'] else 'FAIL'} ({met}/14 checks met); {written}\n")
    return 0 if result["liveAcceptance"] else 1


if __name__ == "__main__":
    sys.exit(main())
