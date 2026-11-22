# SPDX-License-Identifier: MIT
"""ONDEMAND-ETH (M03-T09): the catalogue entry, the guest actions, the status reducer, the row's checks on their recorded
observation and the real driver on recorded replies. Never a VM; en0 is never touched on the host."""
import copy
import json
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

import test_live_replay as replay
import test_run8_rows as run8

ROOT, LIVE, V = replay.ROOT, replay.LIVE, replay.V
GUEST = ROOT / "Tools/lab/tart/guest"
ROWS = json.loads((ROOT / "Tools/lab/rows.json").read_text())["rows"]
FIXTURE = json.loads((ROOT / "Tools/lab/tests/fixtures/rows/ondemand-eth.json").read_text())
OD = V.ONDEMAND


def observation():
    return copy.deepcopy(FIXTURE["pass"])


def checks(value):
    return {item["name"]: item for item in V.row_checks("ondemand-eth", value)}


def failed(value):
    return sorted(name for name, item in checks(value).items() if not item["met"])


class CatalogueTests(unittest.TestCase):
    def test_the_row_is_live_in_the_catalogue_scope_and_mirror(self):
        row = ROWS["ONDEMAND-ETH"]
        self.assertNotIn("gap", row)
        self.assertEqual((row["action"], row["checks"], row["profile"], row["connect"]), ("ondemand-eth", "ondemand-eth", "full4", False))
        self.assertIn(row["checks"], V.ROW_CHECKS)
        self.assertIn("ondemand-eth", LIVE.LEAD_CONTROL_KINDS)
        self.assertIn("ONDEMAND-ETH", (ROOT / "Tools/lab/scope-v2.txt").read_text().split())

    def test_every_criterion_has_an_expectation_and_every_check_has_a_failing_fixture(self):
        expected = " ".join(ROWS["ONDEMAND-ETH"]["expected"])
        for words in ("Ethernet rule saved through the app", "Arming from idle", "daemon restart", "After en0 returns", "Removing the rule",
                      "does not bring the tunnel back", "Lockdown and the kill switch"):
            self.assertIn(words, expected)
        names = {item["name"] for item in V.row_checks("ondemand-eth", observation())}
        self.assertEqual(names, {case["expectation"] for case in FIXTURE["failing"]})
        self.assertTrue(all(item["met"] for item in V.row_checks("ondemand-eth", observation())))

    def test_the_guest_actions_exist_and_never_touch_en0_or_the_ssid(self):
        script = (GUEST / "gap-actions.sh").read_text()
        for action in ("od-policy", "od-probe", "od-restart"):
            self.assertRegex(script, rf"(?m)^  {action}\)")
        block = script[script.index("  od-policy)"):script.index("  *) exit 2")]
        self.assertNotIn("ifconfig", block)
        self.assertNotRegex(block, r"(?i)airport|wdutil|system_profiler|CWWiFi")
        # en0 is cycled by the existing guarded en0-loss action only, from the guest.
        driver = (ROOT / "Tools/lab/verdict-live.py").read_text()
        body = driver[driver.index("    def ondemand_row"):driver.index("    def import_review")]
        self.assertEqual(re.findall(r"self\.en0_loss\(", body), ["self.en0_loss(", "self.en0_loss("])
        self.assertNotIn("ifconfig", body)
        self.assertIn('"od-status.pl"', driver)


class StatusReducerTests(unittest.TestCase):
    ID = "00000000-0000-4000-8000-000000000109"

    STARTED = "Tue Nov 10 07:00:00 2026"

    def reduce(self, status, pid="512", identity=None, started=STARTED, discard=""):
        result = subprocess.run(["perl", str(GUEST / "od-status.pl"), "1794291790.123", pid, started, identity or self.ID, discard],
                                input=json.dumps(status), capture_output=True, text=True, check=True)
        return json.loads(result.stdout)

    def status(self, **fields):
        value = dict(armedProfileID=self.ID.lower(), activated=True, network="ethernet", evaluatedAtContinuous=12.5,
                     ssid=dict(state="notRequired"), decision=dict(state="connect"))
        value.update(fields)
        return dict(phase="active", protection="protected", ownerPFToken="123456", onDemand=value, activeProfileID=self.ID)

    def test_an_armed_activated_status_reduces_to_public_fields_only(self):
        out = self.reduce(self.status())
        self.assertEqual((out["pid"], out["started"]), (512, self.STARTED))
        self.assertEqual(out["onDemand"], dict(armed=True, armedIsProfile=True, activated=True, network="ethernet", decision="connect",
                                               reason=None, evaluated=True))
        self.assertTrue(OD.activated(out))
        self.assertNotIn("ownerPFToken", json.dumps(out))
        self.assertNotIn("ssid", json.dumps(out))

    def test_another_profile_a_hold_and_no_object_are_not_activation(self):
        other = self.reduce(self.status(armedProfileID="11111111-2222-3333-4444-555555555555"))
        self.assertEqual((other["onDemand"]["armed"], other["onDemand"]["armedIsProfile"]), (True, False))
        self.assertFalse(OD.activated(other))
        hold = self.reduce(self.status(decision=dict(state="hold", reason="noNetwork"), network="none", evaluatedAtContinuous=None, activated=False))
        self.assertEqual((hold["onDemand"]["decision"], hold["onDemand"]["reason"], hold["onDemand"]["evaluated"]), ("hold", "noNetwork", False))
        self.assertFalse(OD.activated(hold))
        none = self.reduce(dict(phase="idle", protection="blocked", onDemand=None))
        self.assertIsNone(none["onDemand"])
        self.assertTrue(OD.withdrawn(dict(none, onDemand=dict(armed=False, activated=False)), "blocked"))

    def test_an_unreadable_status_and_odd_words_reduce_to_nothing(self):
        out = self.reduce(dict(phase="rm -rf", protection="whatever", onDemand=dict(armedProfileID="not-a-uuid", network="wifi; x")))
        self.assertEqual((out["phase"], out["protection"]), (None, None))
        self.assertEqual((out["onDemand"]["armed"], out["onDemand"]["network"]), (False, None))
        empty = subprocess.run(["perl", str(GUEST / "od-status.pl"), "1.0", "512", self.STARTED, self.ID, ""], input="not json",
                               capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(empty.stdout)["onDemand"], None)

    def test_a_read_without_a_daemon_identity_or_with_a_discard_reason_carries_no_pid_and_says_why(self):
        for kwargs, reason in (dict(discard="daemonChanged"), "daemonChanged"), (dict(pid="0"), "identityUnavailable"), \
                (dict(started=""), "identityUnavailable"), (dict(started="not a time"), "identityUnavailable"), \
                (dict(pid="12; id"), "identityUnavailable"), (dict(discard="bad reason!"), "identityUnavailable"):
            out = self.reduce(self.status(), **kwargs)
            self.assertEqual((out["pid"], out["started"], out["phase"], out["onDemand"], out["discarded"]), (0, None, None, None, reason), kwargs)
            self.assertFalse(OD.activated(out))
        self.assertNotIn("discarded", self.reduce(self.status()))


class ProbeIdentityTests(unittest.TestCase):
    """The od-probe and od-restart blocks of gap-actions.sh, run for real against stubbed pgrep, ps and wgex CLI: the guest guard is
    not sourced (host-safe), everything else is the shipped text."""
    ID = StatusReducerTests.ID
    OLD, NEW = "Mon Nov 9 10:00:00 2026", "Tue Nov 10 07:00:00 2026"

    @classmethod
    def block(cls, script, start, end):
        return script[script.index(start):script.index(end, script.index(start))]

    def probe(self, pgrep_lines, ps_lines, action="od-probe", status=None):
        script = (GUEST / "gap-actions.sh").read_text()
        ident = self.block(script, "od_identity() {", "sample() {")
        case = self.block(script, f"  {action})", "  *) exit 2")
        case = case[:case.index("    ;;")].split("\n", 1)[1]
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "pgrep.txt").write_text("".join(line + "\n" for line in pgrep_lines))
            (tmp / "ps.txt").write_text("".join(line + "\n" for line in ps_lines))
            (tmp / "cli").write_text(f"#!/bin/sh\ncat <<'EOF'\n{json.dumps(status or dict(phase='active', protection='protected'))}\nEOF\n")
            (tmp / "pgrep").write_text("#!/bin/sh\nf=" + str(tmp / "pgrep.txt") + "\nl=$(head -n1 \"$f\")\nsed -i '' 1d \"$f\"\n[ -n \"$l\" ] && echo \"$l\"\nexit 0\n")
            (tmp / "ps").write_text("#!/bin/sh\nf=" + str(tmp / "ps.txt") + "\nl=$(head -n1 \"$f\")\nsed -i '' 1d \"$f\"\n[ -n \"$l\" ] && echo \"  $l\"\nexit 0\n")
            (tmp / "kill").write_text("#!/bin/sh\necho \"$@\" >> " + str(tmp / "kills.txt") + "\n")
            (tmp / "sudo").write_text("#!/bin/sh\nshift\nexec \"$@\"\n")
            for name in ("cli", "pgrep", "ps", "kill", "sudo"):
                (tmp / name).chmod(0o755)
            harness = (f'set -euo pipefail\nstage={shlex.quote(str(GUEST))}\ncli={tmp}/cli\nnow() {{ echo 1794291790.123; }}\n'
                       f'{ident}\nset -- {action} {self.ID}\n{case}\n')
            result = subprocess.run(["bash", "-c", harness], capture_output=True, text=True, timeout=30,
                                    env=dict(PATH=f"{tmp}:/usr/bin:/bin:/usr/sbin:/sbin", HOME=str(tmp)))
            kills = (tmp / "kills.txt").read_text() if (tmp / "kills.txt").exists() else ""
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout, kills

    def test_a_stable_daemon_keeps_its_pid_and_start_time(self):
        out, _ = self.probe(["512", "512"], [self.NEW, self.NEW])
        sample = json.loads(out)
        self.assertEqual((sample["pid"], sample["started"], sample["phase"]), (512, self.NEW, "active"))
        self.assertNotIn("discarded", sample)

    def test_a_daemon_replaced_during_the_status_read_is_discarded_not_labelled_with_the_replacement_pid(self):
        # The old daemon answers the read; its replacement is what pgrep sees afterwards (and the reverse).
        for pgrep, ps in ((["336", "512"], [self.OLD, self.NEW]), (["512", "336"], [self.NEW, self.OLD])):
            out, _ = self.probe(pgrep, ps)
            sample = json.loads(out)
            self.assertEqual((sample["pid"], sample["discarded"], sample["phase"], sample["onDemand"]), (0, "daemonChanged", None, None))

    def test_the_same_pid_with_another_start_time_is_a_different_process(self):
        sample = json.loads(self.probe(["512", "512"], [self.OLD, self.NEW])[0])
        self.assertEqual((sample["pid"], sample["discarded"]), (0, "daemonChanged"))

    def test_an_identity_that_is_unavailable_before_or_after_the_read_is_discarded(self):
        for pgrep, ps in ((["", "512"], [self.NEW]), (["512", ""], [self.NEW]), (["512", "512"], ["", self.NEW]), (["512", "512"], [self.NEW, ""])):
            sample = json.loads(self.probe(pgrep, ps)[0])
            self.assertEqual((sample["pid"], sample["discarded"]), (0, "identityUnavailable"), (pgrep, ps))

    def test_the_restart_signals_the_identified_daemon_and_reports_its_start_time(self):
        out, kills = self.probe(["336"], [self.OLD], action="od-restart")
        self.assertEqual(out.split("\n")[:2], ["prevpid=336", f"prevstart={self.OLD}"])
        self.assertIn("-TERM 336", kills)
        # No identity, no signal.
        script = (GUEST / "gap-actions.sh").read_text()
        self.assertIn('ident="$(od_identity)" || exit 1', script)


class CheckTests(unittest.TestCase):
    def test_a_good_observation_passes_every_check(self):
        self.assertEqual(failed(observation()), [])

    def test_the_daemon_start_is_judged_on_the_replacement_daemons_samples_only(self):
        value = observation()
        restart = value["onDemand"]["restart"]
        old = [item for item in restart["samples"] if item["pid"] == restart["prevPid"]]
        self.assertTrue(old and OD.activated(old[0]), "the previous daemon looks activated: it must not count")
        restart["samples"] = old
        self.assertIn("daemonReplaced", failed(value))
        self.assertIn("protectedAfterDaemonStart", failed(value))
        # A post-start daemon that never evaluates is not activation either.
        value = observation()
        for item in value["onDemand"]["restart"]["samples"]:
            if item["pid"] != restart["prevPid"] and item["onDemand"]:
                item["onDemand"]["evaluated"] = False
        self.assertEqual(failed(value), ["protectedAfterDaemonStart"])
        # Two replacement pids (a restart loop) are not one daemon.
        value = observation()
        value["onDemand"]["restart"]["samples"].append(dict(value["onDemand"]["restart"]["samples"][-1], pid=777))
        self.assertIn("daemonReplaced", failed(value))

    def test_a_status_read_labelled_with_the_replacement_pid_but_the_old_start_time_is_not_post_start_evidence(self):
        value = observation()
        restart = value["onDemand"]["restart"]
        restart["samples"] = [dict(item, pid=512, started=restart["prevStarted"]) if item["pid"] == restart["prevPid"] else item
                              for item in restart["samples"]][:1] + [dict(restart["samples"][-1], started=restart["prevStarted"])]
        self.assertIn("daemonReplaced", failed(value))
        self.assertIn("protectedAfterDaemonStart", failed(value))

    def test_a_post_start_sample_without_a_known_start_time_or_with_a_discard_marker_does_not_count(self):
        for change in (dict(started=None), dict(started="not a time"), dict(discarded="daemonChanged"), dict(pid=0)):
            value = observation()
            restart = value["onDemand"]["restart"]
            restart["samples"] = [dict(item, **change) if item["pid"] != restart["prevPid"] else item for item in restart["samples"]]
            self.assertIn("daemonReplaced", failed(value), change)
            self.assertIn("protectedAfterDaemonStart", failed(value), change)
        # Without the pre-restart start time nothing can be told apart from the old daemon.
        value = observation()
        del value["onDemand"]["restart"]["prevStarted"]
        self.assertIn("daemonReplaced", failed(value))

    def test_a_gui_action_while_waiting_for_the_tunnel_fails_the_row(self):
        for place in (("restart", "guiPress"), ("afterEn0", "guiPress")):
            value = observation()
            value["onDemand"][place[0]][place[1]] = True
            self.assertEqual(len(failed(value)), 1, place)
        value = observation()
        value["onDemand"]["restart"]["guiPress"] = None
        self.assertIn("noGuiActionAfterDaemonStart", failed(value), "an unknown press state is not a pass")

    def test_arming_needs_exactly_one_press_and_an_activated_status(self):
        for edit in (lambda o: o["onDemand"].update(armPresses=0), lambda o: o["onDemand"].update(armPresses=2),
                     lambda o: o["onDemand"]["armed"]["onDemand"].update(activated=False),
                     lambda o: o["onDemand"]["armed"]["onDemand"].update(network="wifi"),
                     lambda o: o["onDemand"]["armed"].update(protection="blocked"),
                     lambda o: o["onDemand"].update(armed=None)):
            value = observation()
            edit(value)
            self.assertEqual(failed(value), ["activatedAfterArm"])

    def test_the_rule_must_change_from_off_to_ethernet_only(self):
        for before, after in (('{"interfaces":{"_0":{"ethernetOnly":{}}}}', '{"interfaces":{"_0":{"ethernetOnly":{}}}}'),
                              ('{"off":{}}', '{"off":{}}'), ('{"off":{}}', None), (None, '{"interfaces":{"_0":{"ethernetOnly":{}}}}')):
            value = observation()
            value["onDemand"].update(policyBefore=before, policyAfterEdit=after)
            self.assertEqual(failed(value), ["ruleSavedThroughApp"], (before, after))

    def test_removal_must_take_the_tunnel_down_under_lockdown_with_one_press(self):
        for edit in (lambda o: o["onDemand"]["removed"].update(presses=2), lambda o: o["onDemand"]["removed"]["status"].update(phase="active"),
                     lambda o: o["onDemand"]["removed"]["status"].update(protection="unprotected"),
                     lambda o: o["onDemand"]["removed"]["status"]["onDemand"].update(armed=True),
                     lambda o: o["onDemand"]["removed"]["status"]["onDemand"].update(activated=True)):
            value = observation()
            edit(value)
            self.assertEqual(failed(value), ["removalBringsTunnelDown"])
        value = observation()
        value["onDemand"]["lockdownJournal"] = None
        self.assertEqual(failed(value), ["lockdownOn"])

    def test_the_armed_cycle_is_judged_by_the_en0_loss_expectations_and_the_withdrawn_cycle_by_its_own(self):
        value = observation()
        value["profiles"][0]["samples"] = [[s[0], "active", "protected", 1] for s in value["profiles"][0]["samples"]]
        self.assertEqual(failed(value), ["armed:lossDetected:full4", "armed:protectedWithin10sOfLinkUp:full4"])
        value = observation()
        value["profiles"][1]["samples"][3][2] = "unprotected"
        self.assertEqual(failed(value), ["withdrawnRuleStaysDown"])
        value = observation()
        value["onDemand"]["removedAfterEn0"]["status"]["onDemand"]["armed"] = True
        self.assertEqual(failed(value), ["withdrawnRuleStaysDown"])
        value = observation()
        del value["profiles"][1]
        self.assertEqual(sorted(failed(value)), ["withdrawnLinkCycled", "withdrawnOnePfReference", "withdrawnRuleStaysDown"])
        value = observation()
        del value["profiles"][0]
        self.assertIn("armedLinkCycleObserved", failed(value))


FULL4 = "00000000-0000-4000-8000-000000000001"
TOGGLE = "wgex.main.onDemandToggle." + FULL4
# Controls only this row presses; the coordinates are recorded-runner data. (role, name, id, x, y)
OD_CONTROLS = {
    "wgex.main.editProfile": ("AXButton", "Edit Profile", 500, 300),
    "wgex.editor.onDemandEthernet": ("AXCheckBox", "Ethernet", 520, 300),
    "wgex.editor.save": ("AXButton", "Save", 540, 300),
    TOGGLE: ("AXCheckBox", "On-demand", 560, 300),
}
OD_POSITIONS = {(x + 10, y + 10): identifier for identifier, (_, _, x, y) in OD_CONTROLS.items()}


class OnDemandRunner(run8.Run8Runner):
    """Run8Runner plus the Mac editor, the On-Demand toggle, the daemon's on-demand status and a SIGTERM restart."""

    def __init__(self):
        super().__init__()
        self.rule, self.ethernet_ticked, self.armed = False, False, False
        self.save_works, self.arm_works, self.disarm_works = True, True, True
        self.restart_comes_back, self.reconnect_after_removal = True, False
        self.pid, self.new_pid, self.restart_probes, self.restarted = 336, 512, None, False
        self.removed_cycles = 0
        self.replaced_during_read, self.mislabelled = False, False
        self.starts = {336: "Mon Nov 9 10:00:00 2026", 512: "Tue Nov 10 07:00:00 2026"}

    def arm_state(self):
        return self.armed and self.connected

    def dump(self):
        lines = super().dump()
        for identifier, (role, name, x, y) in OD_CONTROLS.items():
            value = ("1" if self.ethernet_ticked else "0") if identifier == "wgex.editor.onDemandEthernet" else \
                    ("1" if self.armed else "0") if identifier == TOGGLE else ""
            lines.append(f"{role} | name={name} | value={value} | desc= | id={identifier} | pos={x},{y} size=20x20 en=true")
        return lines

    def probe(self):
        """What guest/od-status.pl prints for the daemon that answers now."""
        sample = self.read()
        sample.setdefault("started", self.starts.get(sample["pid"]))
        return sample

    def discarded(self, reason):
        return dict(at=self.clock, pid=0, started=None, phase=None, protection=None, onDemand=None, discarded=reason)

    def read(self):
        pid, up = self.pid, self.arm_state()
        if self.restart_probes is not None:
            self.restart_probes += 1
            if self.restart_probes == 1:
                return self.discarded("identityUnavailable")
            if self.restart_probes == 2 and self.replaced_during_read:
                # The old daemon answered, the replacement was there afterwards: the guest keeps nothing.
                self.pid = self.new_pid
                return self.discarded("daemonChanged")
            if self.restart_probes == 2 and self.mislabelled:
                # What the unbracketed probe used to print: the old daemon's activated status under the replacement's pid.
                return dict(at=self.clock, pid=self.new_pid, started=self.starts[self.pid], phase="active", protection="protected",
                            onDemand=dict(armed=True, armedIsProfile=True, activated=True, network="ethernet", decision="connect",
                                          reason=None, evaluated=True))
            pid = self.pid = self.new_pid
            if self.restart_probes <= (3 if self.replaced_during_read or self.mislabelled else 2) or not self.restart_comes_back:
                return dict(at=self.clock, pid=pid, phase="idle", protection="blocked",
                            onDemand=dict(armed=self.armed, armedIsProfile=self.armed, activated=False, network="ethernet", decision=None,
                                          reason=None, evaluated=False))
            self.restarted, self.restart_probes = True, None
            self.connected = True
        detail = dict(armed=self.armed, armedIsProfile=self.armed, activated=up, network="ethernet", decision="connect" if up else None,
                      reason=None, evaluated=self.armed)
        if up:
            return dict(at=self.clock, pid=pid, phase="active", protection="protected", onDemand=detail)
        if not self.armed and not self.rule_known:
            return dict(at=self.clock, pid=pid, phase="idle", protection="unprotected", onDemand=None)
        return dict(at=self.clock, pid=pid, phase="idle", protection="blocked" if self.lockdown else "unprotected", onDemand=detail)

    rule_known = False

    def en0_text(self, label):
        if self.lockdown and not self.connected:
            self.removed_cycles += 1
            trigger = self.en0[label]
            down, up = trigger + 2, trigger + 22
            lines, t = [f"down {down:.3f}", f"up {up:.3f}", "__SAMPLES__"], down - 2
            while t < up + 40:
                back = self.reconnect_after_removal and t >= up + 3
                state = ("active", "protected") if back else ("idle", "blocked")
                lines.append(f'{t:.3f} refs=1 {{"phase":"{state[0]}","protection":"{state[1]}","sequence":4}}')
                t += 0.25
            return ("\n".join(lines) + "\n").encode()
        return super().en0_text(label)

    def status(self):
        if self.restart_probes is not None and not self.restart_comes_back and self.armed:
            self.status_calls += 1
            return dict(phase="idle", protection="blocked")
        return super().status()

    def run(self, argv, data=None, timeout=100, env=None):
        args = argv[2:] if argv[:1] == ["just"] else []
        if args[:2] in (["gui", "click"], ["gui", "press"]):
            target = OD_POSITIONS.get(replay.press_point(args))
            if target == "wgex.editor.onDemandEthernet":
                self.ethernet_ticked = not self.ethernet_ticked
            elif target == "wgex.editor.save" and self.save_works:
                self.rule = self.ethernet_ticked
                self.rule_known = True
            elif target == TOGGLE:
                if not self.armed and self.arm_works and self.rule:
                    self.armed, self.connected, self.blocked, self.status_calls = True, True, False, 0
                elif self.armed and self.disarm_works:
                    self.armed, self.connected = False, False
        if args[:2] == ["ssh", "--"]:
            words = shlex.split(args[2])
            if len(words) > 2 and words[1].endswith("gap-actions.sh") and words[2].startswith("od-"):
                action = words[2]
                if action == "od-policy":
                    policy = '{"interfaces":{"_0":{"ethernetOnly":{}}}}' if self.rule else '{"off":{}}'
                    return self.handled(argv, env, f"onDemand={policy}\n".encode())
                if action == "od-probe":
                    return self.handled(argv, env, json.dumps(self.probe()).encode())
                if action == "od-restart":
                    self.restart_probes = 0
                    return self.handled(argv, env, f"prevpid={self.pid}\nprevstart={self.starts[self.pid]}\nrestartAt={self.clock:.3f}\n".encode())
        return super().run(argv, data, timeout, env)


def run_od(runner=None, accepted=True):
    return run8.run_row("ONDEMAND-ETH", runner or OnDemandRunner(), accepted=accepted)


def index_of(lines, needle, start=0):
    return next(i for i, line in enumerate(lines) if i >= start and needle in line)


class DriverTests(unittest.TestCase):
    def test_the_row_runs_end_to_end_in_the_documented_order_with_one_press_per_step(self):
        runner, result = run_od()
        lines = run8.commands(runner)
        edit = next(i for i, line in enumerate(lines) if replay.actuates(line, 510, 310))
        ticked = next(i for i, line in enumerate(lines) if replay.actuates(line, 530, 310))
        save = next(i for i, line in enumerate(lines) if replay.actuates(line, 550, 310))
        toggles = [i for i, line in enumerate(lines) if replay.actuates(line, 570, 310)]
        lockdown = [i for i, line in enumerate(lines) if replay.actuates(line, 310, 310)]
        restart = index_of(lines, "gap-actions.sh od-restart")
        cycles = [i for i, line in enumerate(lines) if "verdict-actions.sh en0-loss" in line]
        unprotected_lead = next(i for i, line in enumerate(lines) if " generate " in line and "--state unprotected" in line)
        self.assertLess(unprotected_lead, edit, "the unprotected lead control runs before Lockdown and the editor")
        self.assertLess(edit, ticked)
        self.assertLess(ticked, save)
        self.assertLess(save, toggles[0])
        self.assertEqual(len(toggles), 2, "one press to arm, one to disarm")
        self.assertLess(toggles[0], restart)
        self.assertLess(restart, cycles[0])
        self.assertLess(cycles[0], lockdown[0])
        self.assertEqual(len(lockdown), 1, "Lockdown on only, never off")
        self.assertLess(lockdown[0], toggles[1])
        self.assertLess(toggles[1], cycles[1])
        self.assertEqual(len(cycles), 2)
        self.assertEqual(result["tailControlPosition"], "lead", "Lockdown stays on, so the lead control stands in for the tail")
        self.assertEqual(result["gaps"], [])
        self.assertTrue(result["rowCompleted"])
        self.assertTrue(all(item["met"] for item in result["checks"]), [item["name"] for item in result["checks"] if not item["met"]])

    def test_nothing_is_clicked_while_the_row_waits_for_the_tunnel_on_its_own(self):
        runner, _ = run_od()
        lines = run8.commands(runner)
        restart = index_of(lines, "gap-actions.sh od-restart")
        cycle = index_of(lines, "verdict-actions.sh en0-loss", restart)
        lockdown = next(i for i, line in enumerate(lines) if replay.actuates(line, 310, 310))
        self.assertEqual([line for line in lines[restart:lockdown] if re.search(r"just lab gui (?:click|press)", line)], [],
                         "no GUI press from the daemon restart through the en0 return")
        self.assertGreater(cycle, restart)

    def test_en0_is_only_cycled_by_the_guarded_guest_action_never_by_the_host(self):
        runner, _ = run_od()
        for line in run8.commands(runner):
            self.assertNotRegex(line, r"ifconfig|networksetup|route |pfctl|launchctl")
        self.assertEqual(sum("verdict-actions.sh en0-loss" in line for line in run8.commands(runner)), 2)

    def test_a_rule_the_app_does_not_save_is_a_named_gap_and_nothing_is_armed(self):
        runner = OnDemandRunner()
        runner.save_works = False
        _, result = run_od(runner, accepted=False)
        self.assertTrue(any(gap.startswith("ethernetRuleNotSaved:") for gap in result["gaps"]), result["gaps"])
        self.assertFalse(any(replay.actuates(line, 570, 310) for line in run8.commands(runner)), "no arm press without a saved rule")
        self.assertFalse(any("od-restart" in line for line in run8.commands(runner)))

    def test_a_toggle_that_never_arms_stops_the_row_before_the_daemon_restart(self):
        runner = OnDemandRunner()
        runner.arm_works = False
        _, result = run_od(runner, accepted=False)
        self.assertTrue(any("status protection=protected" in gap for gap in result["gaps"]), result["gaps"])
        self.assertFalse(any("od-restart" in line for line in run8.commands(runner)))
        self.assertLessEqual(sum(replay.actuates(line, 570, 310) for line in run8.commands(runner)), 2, "the press limit holds")

    def test_a_daemon_replaced_during_a_status_read_has_that_read_discarded_and_recorded(self):
        runner = OnDemandRunner()
        runner.replaced_during_read = True
        _, result = run_od(runner)
        self.assertTrue(all(item["met"] for item in result["checks"]), [item["name"] for item in result["checks"] if not item["met"]])
        replaced = run8.check(result, "daemonReplaced")
        self.assertEqual(replaced["discardedReads"], ["identityUnavailable", "daemonChanged"])
        self.assertEqual(replaced["postStartPids"], [512])
        # Two reads were discarded, so the replacement daemon's counted reads start later than in the undisturbed run.
        _, plain = run_od()
        self.assertEqual(run8.check(plain, "daemonReplaced")["discardedReads"], ["identityUnavailable"])
        self.assertGreater(run8.check(result, "protectedAfterDaemonStart")["secondsAfterRestart"],
                           run8.check(plain, "protectedAfterDaemonStart")["secondsAfterRestart"])

    def test_a_status_the_old_daemon_answered_under_the_new_pid_does_not_count_as_post_start_evidence(self):
        runner = OnDemandRunner()
        runner.mislabelled = True
        _, result = run_od(runner)
        restart_check = run8.check(result, "protectedAfterDaemonStart")
        _, plain = run_od()
        # The mislabelled read is an activated status at once; had it counted, activation would be the first read after the restart.
        self.assertGreater(restart_check["secondsAfterRestart"], run8.check(plain, "protectedAfterDaemonStart")["secondsAfterRestart"])
        self.assertEqual(run8.check(result, "daemonReplaced")["postStartPids"], [512])

    def test_a_daemon_that_does_not_bring_the_tunnel_back_after_its_restart_fails_the_row(self):
        runner = OnDemandRunner()
        runner.restart_comes_back = False
        _, result = run_od(runner, accepted=False)
        self.assertFalse(result["rowCompleted"])
        self.assertTrue(result["gaps"], "an unrecovered daemon start is a gap, never a pass")
        self.assertFalse(any("verdict-actions.sh en0-loss" in line for line in run8.commands(runner)), "no en0 cycle after a failed start")

    def test_a_disarm_that_leaves_the_tunnel_up_fails_the_row(self):
        runner = OnDemandRunner()
        runner.disarm_works = False
        _, result = run_od(runner, accepted=False)
        self.assertFalse(result["rowCompleted"])
        self.assertFalse(runner.removed_cycles, "the withdrawn cycle is never run while the tunnel is still up")

    def test_a_tunnel_that_returns_after_the_rule_is_withdrawn_fails_the_row(self):
        runner = OnDemandRunner()
        runner.reconnect_after_removal = True
        _, result = run_od(runner, accepted=False)
        names = {item["name"]: item["met"] for item in result["checks"]}
        self.assertFalse(names["withdrawnRuleStaysDown"])
        self.assertTrue(names["removalBringsTunnelDown"])
        self.assertTrue(runner.removed_cycles)
