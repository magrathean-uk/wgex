# SPDX-License-Identifier: MIT
"""M1-47 POWER-WAKE: the injected power event row through the real driver with recorded replies, its fixture replay, the observation
parser and the guest-script shapes. The guest signals its own Lab daemon (SIGUSR1 sleep, SIGUSR2 wake); nothing here runs a VM, SSH
or a guest command, and no test sends a signal."""
import copy
import json
import re
import shlex
import subprocess
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import test_live_replay as replay
import test_run8_rows as run8

ROOT, LIVE, V = replay.ROOT, replay.LIVE, replay.V
GUEST = ROOT / "Tools/lab/tart/guest"
ROWS = json.loads((ROOT / "Tools/lab/rows.json").read_text())["rows"]
FIXTURE = json.loads((ROOT / "Tools/lab/tests/fixtures/rows/power-wake.json").read_text())
SCRIPT = (GUEST / "verdict-actions.sh").read_text()


def stamp(epoch):
    """A guest log time as `log show --style compact` prints it, in a +0000 guest."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(epoch)) + f".{int(epoch * 1000) % 1000:03d}"


class PowerRunner(run8.Run8Runner):
    """Run8Runner plus the guest's power-inject and power-collect replies. Switches: power_forced (the long variant's forced
    handshake reaches the status), power_forced_in_samples (the 0.25 s samples catch it; the daemon's own status line always does),
    power_recovery (seconds from the wake line to protected again), power_never_protected, power_log_missing (sleep or wake),
    power_unprotected (one unprotected sample mid-sleep), power_extra_ref (a second pf reference at one sample)."""

    def __init__(self):
        super().__init__()
        self.power = {}
        self.power_forced, self.power_forced_in_samples, self.power_recovery = True, True, 1.0
        self.power_never_protected, self.power_log_missing = False, None
        self.power_unprotected, self.power_extra_ref = False, False

    def run(self, argv, data=None, timeout=100, env=None):
        args = argv[2:] if argv[:1] == ["just"] else []
        if args[:2] == ["ssh", "--"]:
            words = shlex.split(args[2])
            action = words[2] if len(words) > 2 and words[1].endswith("verdict-actions.sh") else None
            if action == "power-inject":
                self.power[words[4]] = (self.clock, int(words[3]))
                return self.handled(argv, env)
            if action == "power-collect":
                return self.handled(argv, env, self.power_text(words[3]))
        return super().run(argv, data, timeout, env)

    def power_text(self, label):
        trigger, seconds = self.power[label]
        sleep_at = trigger + 2
        wake_at = sleep_at + seconds + 0.012
        sleep_log, wake_log = sleep_at + 0.021, wake_at + 0.022
        forced = self.power_forced and seconds > 5
        lines = ["tz=+0000", f"sleep {sleep_at:.3f}", f"wake {wake_at:.3f}", "__LOG__"]
        if self.power_log_missing != "sleep":
            lines.append(f"{stamp(sleep_log)} lab power inject sleep pid=282")
        if self.power_log_missing != "wake":
            lines.append(f"{stamp(wake_log)} lab power inject wake pid=282")
        lines.append("__STATUS__")
        if forced:
            lines += [f"{stamp(wake_log + 0.04)} status: phase=reasserting protection=blocked reason=wake pid=282",
                      f"{stamp(wake_log + self.power_recovery)} status: phase=active protection=protected reason=none pid=282"]
        lines.append("__SAMPLES__")
        t, marked = sleep_at - 2, False
        while t < trigger + seconds + 45:
            phase, protection, refs = "active", "protected", 1
            if t >= wake_log + 0.3 and self.power_never_protected:
                phase, protection = "failed", "blocked"
            elif forced and self.power_forced_in_samples and wake_log + 0.3 <= t < wake_log + self.power_recovery:
                phase, protection = "reasserting", "blocked"
            if self.power_unprotected and abs(t - (sleep_at + seconds / 2)) < 0.13:
                protection = "unprotected"
            if self.power_extra_ref and not marked and t >= sleep_at + 1:
                refs, marked = 2, True
            lines.append(f'{t:.3f} refs={refs} {{"phase":"{phase}","protection":"{protection}","sequence":4}}')
            t += 0.25
        return ("\n".join(lines) + "\n").encode()


def run_row(runner=None, accepted=True):
    return replay.LiveReplayTests().run_recorded("POWER-WAKE", runner or PowerRunner(), accepted=accepted)


def check(result, name):
    return next(item for item in result["checks"] if item["name"] == name)


def guest_commands(runner):
    """The commands the row ran in the guest for the injected events: the detached generators, the power actions and the record reads."""
    # The recorded runner also records the detached generator's own start (the command without `nohup`); the guest runs it once.
    return [argv[-1] for argv in runner.commands
            if argv[:4] == ["just", "lab", "ssh", "--"] and ("verdict-actions.sh power-" in argv[-1] or "generator-power" in argv[-1])
            and not (" generate " in argv[-1] and not argv[-1].startswith("nohup "))]


class PowerWakeRowTests(unittest.TestCase):
    def test_both_variants_inject_and_pass_with_exactly_these_guest_commands(self):
        runner, result = run_row()
        stage = r"\S+"
        expected = [
            rf"nohup {stage}/leakprobe generate --config {stage}/config\.json --rounds 30 --state blocked --nonce \S+-w\d+ "
            rf"--record {stage}/generator-power-short-\d+\.json >/dev/null 2>&1 </dev/null &$",
            rf"bash {stage}/verdict-actions\.sh power-inject 3 short-\d+$",
            rf"bash {stage}/verdict-actions\.sh power-collect short-\d+$",
            rf"cat {stage}/generator-power-short-\d+\.json 2>/dev/null \|\| true$",
            rf"nohup {stage}/leakprobe generate --config {stage}/config\.json --rounds 284 --state blocked --nonce \S+-w\d+ "
            rf"--record {stage}/generator-power-long-\d+\.json >/dev/null 2>&1 </dev/null &$",
            rf"bash {stage}/verdict-actions\.sh power-inject 130 long-\d+$",
            rf"bash {stage}/verdict-actions\.sh power-collect long-\d+$",
            rf"cat {stage}/generator-power-long-\d+\.json 2>/dev/null \|\| true$",
        ]
        commands = guest_commands(runner)
        self.assertEqual(len(commands), len(expected), commands)
        for command, pattern in zip(commands, expected):
            self.assertRegex(command, pattern)
        names = {item["name"] for item in result["checks"]}
        for variant in ("short", "long"):
            for expectation in ("injectedEventsSeen", "neverUnprotected", "protectedWithin3sOfWake", "onePfReferenceThroughout",
                                "zeroLanReceiptsDuringWindow"):
                self.assertIn(f"{expectation}:{variant}", names)
        self.assertIn("forcedHandshakeObserved:long", names)
        self.assertNotIn("forcedHandshakeObserved:short", names)
        self.assertIn("variantsObserved", names)
        self.assertGreater(check(result, "zeroLanReceiptsDuringWindow:long")["probeAttempts"], 0)
        roles = [window["role"] for window in result["states"]]
        for role in ("protected:short", "powerWake:short", "automaticRecovery:short", "protected:long", "powerWake:long", "automaticRecovery:long"):
            self.assertIn(role, roles)

    def test_a_power_event_is_injected_after_a_protected_window_and_recovery_is_awaited_without_user_action(self):
        runner, _ = run_row()
        lines = run8.commands(runner)
        order = [next(i for i, c in enumerate(lines) if f"verdict-actions.sh power-inject {seconds} " in c) for seconds in (3, 130)]
        self.assertLess(order[0], order[1])
        for index in order:
            before = [i for i, c in enumerate(lines[:index]) if " generate " in c and "--state protected" in c]
            self.assertTrue(before, "a protected marker window comes first")
            after = [i for i, c in enumerate(lines[index:], index) if " generate " in c and "--state protected" in c]
            self.assertTrue(after, "a protected marker window follows (automatic recovery)")
        self.assertFalse([c for c in lines[order[0]:] if re.match(r"just lab gui (press|click|keys)\b", c)],
                         "no GUI step after the first injection: the daemon recovers without user action")

    def test_never_protected_after_the_wake_fails(self):
        runner = PowerRunner()
        runner.power_never_protected = True
        _, result = run_row(runner, accepted=False)
        for variant in ("short", "long"):
            self.assertFalse(check(result, f"protectedWithin3sOfWake:{variant}")["met"], variant)

    def test_protected_late_fails_and_inside_the_limit_passes(self):
        runner = PowerRunner()
        runner.power_recovery = 6.0
        _, result = run_row(runner, accepted=False)
        self.assertFalse(check(result, "protectedWithin3sOfWake:long")["met"])
        self.assertTrue(check(result, "protectedWithin3sOfWake:short")["met"])
        runner = PowerRunner()
        runner.power_recovery = 2.8
        _, result = run_row(runner)
        self.assertTrue(check(result, "protectedWithin3sOfWake:long")["met"])

    def test_a_missing_injected_line_fails_the_injected_events_check(self):
        for missing in ("sleep", "wake"):
            runner = PowerRunner()
            runner.power_log_missing = missing
            _, result = run_row(runner, accepted=False)
            for variant in ("short", "long"):
                self.assertFalse(check(result, f"injectedEventsSeen:{variant}")["met"], (missing, variant))

    def test_an_unprotected_sample_during_the_sleep_fails(self):
        runner = PowerRunner()
        runner.power_unprotected = True
        _, result = run_row(runner, accepted=False)
        for variant in ("short", "long"):
            self.assertFalse(check(result, f"neverUnprotected:{variant}")["met"], variant)

    def test_a_second_pf_reference_fails(self):
        runner = PowerRunner()
        runner.power_extra_ref = True
        _, result = run_row(runner, accepted=False)
        for variant in ("short", "long"):
            self.assertFalse(check(result, f"onePfReferenceThroughout:{variant}")["met"], variant)

    def test_a_lan_receipt_in_the_window_fails(self):
        runner = PowerRunner()
        runner.loss_leak = True
        _, result = run_row(runner, accepted=False)
        for variant in ("short", "long"):
            self.assertGreater(check(result, f"zeroLanReceiptsDuringWindow:{variant}")["receiptCount"], 0, variant)
            self.assertFalse(check(result, f"zeroLanReceiptsDuringWindow:{variant}")["met"], variant)

    def test_the_forced_handshake_is_found_in_the_daemon_log_when_the_samples_miss_it_and_fails_when_nothing_shows_it(self):
        runner = PowerRunner()
        runner.power_forced_in_samples = False
        _, result = run_row(runner)
        forced = check(result, "forcedHandshakeObserved:long")
        self.assertTrue(forced["met"])
        self.assertEqual(forced["seenIn"], "daemonLog")
        runner = PowerRunner()
        runner.power_forced = False
        _, result = run_row(runner, accepted=False)
        self.assertFalse(check(result, "forcedHandshakeObserved:long")["met"])
        runner = PowerRunner()
        _, result = run_row(runner)
        self.assertEqual(check(result, "forcedHandshakeObserved:long")["seenIn"], "samples")

    def test_the_observation_with_both_windows_is_written_for_the_report(self):
        _, result = run_row()
        self.assertIn("row-observation.json", result["recordHashes"])
        observed = json.loads((Path(result["buildRoot"]) / "row-observation.json").read_text())["powerWakes"]
        self.assertEqual([item["variant"] for item in observed], ["short", "long"])
        for item in observed:
            self.assertEqual(item["windowOutsideReceipts"], 0)
            self.assertGreater(item["windowProbeAttempts"], 0)
            self.assertEqual(len(item["injected"]), 2)


class PowerWakeRegressionTests(unittest.TestCase):
    """Verifier probes P1-P3, P8-P10, P12-P13, with independent copies of the passing observation."""

    def observation(self):
        return copy.deepcopy(FIXTURE["pass"])

    def test_P13_daemon_recovery_bounds_the_timing_and_window_after_a_sampler_stall(self):
        observation = self.observation()
        item = observation["powerWakes"][1]
        wake = V.power_instants(item)["wake"]
        item["daemonStatus"] = [[wake + 0.3, "reasserting", "blocked", "wake", 282],
                                [wake + 4.5, "active", "protected", "none", 282]]
        item["samples"] = [s for s in item["samples"] if s[0] < wake] + [
            [wake + 0.1, "active", "protected", 1], [wake + 4.7, "active", "protected", 1]]
        result = dict(checks=V.power_wake_checks(observation))
        self.assertFalse(check(result, "protectedWithin3sOfWake:long")["met"])
        self.assertAlmostEqual(check(result, "protectedWithin3sOfWake:long")["secondsAfterWake"], 4.5)
        self.assertEqual(V.power_window(item), (V.power_instants(item)["sleep"], wake + 4.5))

    def test_P12_one_sample_after_wake_cannot_prove_recovery_without_a_daemon_status(self):
        observation = self.observation()
        item = observation["powerWakes"][0]
        wake = V.power_instants(item)["wake"]
        item["samples"] = [s for s in item["samples"] if s[0] < wake] + [[wake + 0.1, "active", "protected", 1]]
        result = dict(checks=V.power_wake_checks(observation))
        self.assertFalse(check(result, "protectedWithin3sOfWake:short")["met"])

    def test_daemon_status_must_recover_after_its_last_lost_line(self):
        observation = self.observation()
        item = observation["powerWakes"][1]
        wake = V.power_instants(item)["wake"]
        item["daemonStatus"] = [[wake + 0.1, "active", "protected", "none", 282],
                                [wake + 0.3, "reasserting", "blocked", "wake", 282]]
        self.assertFalse(check(dict(checks=V.power_wake_checks(observation)), "protectedWithin3sOfWake:long")["met"])
        self.assertEqual(V.power_window(item)[1], wake + V.POWER_WAKE_SECONDS)

    def test_P12_daemon_recovery_cannot_prove_timing_when_sampling_ends_before_recovery(self):
        observation = self.observation()
        item = observation["powerWakes"][1]
        wake = V.power_instants(item)["wake"]
        item["daemonStatus"] = [[wake + 0.3, "reasserting", "blocked", "wake", 282],
                                [wake + 0.9, "active", "protected", "none", 282]]
        item["samples"] = [s for s in item["samples"] if s[0] < wake] + [[wake + 0.1, "active", "protected", 1]]
        result = dict(checks=V.power_wake_checks(observation))
        self.assertFalse(check(result, "protectedWithin3sOfWake:long")["met"])
        self.assertIsNone(check(result, "protectedWithin3sOfWake:long")["secondsAfterWake"])
        self.assertEqual(V.power_window(item)[1], wake + V.POWER_WAKE_SECONDS)

    def test_P10_no_guest_sample_after_wake_means_no_recovery_even_with_a_daemon_log(self):
        observation = self.observation()
        item = observation["powerWakes"][1]
        wake = V.power_instants(item)["wake"]
        item["samples"] = [s for s in item["samples"] if s[0] < wake]
        self.assertIsNone(V.power_protected_again(item["samples"], wake, item["daemonStatus"]))
        self.assertEqual(V.power_window(item)[1], wake + V.POWER_WAKE_SECONDS)
        checks = V.power_wake_checks(observation)
        self.assertEqual([c["name"] for c in checks if not c["met"]], ["protectedWithin3sOfWake:long"])

    def test_recovery_requires_a_non_lost_guest_sample_with_the_pf_reference_at_or_after_both_timelines(self):
        wake = 103.0
        daemon = [[wake + 0.3, "reasserting", "blocked", "wake", 282],
                  [wake + 0.9, "active", "protected", "none", 282]]
        stale = [[wake + 0.1, "active", "protected", 1]]
        for phase, protection, refs in [("active", "protected", 0), ("reasserting", "protected", 1),
                                         ("active", "unknown", 1)]:
            with self.subTest(phase=phase, protection=protection, refs=refs):
                self.assertIsNone(V.power_protected_again(stale + [[wake + 1, phase, protection, refs]], wake, daemon))
        self.assertEqual(V.power_protected_again(stale + [[wake + 0.9, "active", "protected", 1]], wake, daemon), wake + 0.9)
        self.assertEqual(V.power_protected_again(stale + [[wake + 1.2, "active", "protected", 1]], wake, daemon), wake + 0.9)
        self.assertIsNone(V.power_protected_again([[wake, "active", "protected", 0]], wake))

    def test_status_lines_dropped_fails_every_daemon_status_dependent_check_with_a_reason(self):
        dependent = {"neverUnprotected:long", "protectedWithin3sOfWake:long",
                     "zeroLanReceiptsDuringWindow:long", "forcedHandshakeObserved:long"}
        for dropped in (0, 5):
            with self.subTest(dropped=dropped):
                observation = self.observation()
                item = observation["powerWakes"][1]
                item["statusLinesDropped"] = dropped
                checks = V.power_wake_checks(observation)
                self.assertEqual({c["name"] for c in checks if not c["met"]}, dependent if dropped else set())
                for result in checks:
                    if dropped and result["name"] in dependent:
                        self.assertEqual(result.get("reason"), "status lines dropped")
                if dropped:
                    self.assertEqual(V.power_window(item)[1], V.power_instants(item)["wake"] + V.POWER_WAKE_SECONDS)

    def test_status_lines_dropped_reaches_the_checks_through_the_driver(self):
        for dropped in (0, 5):
            with self.subTest(dropped=dropped):
                runner = PowerRunner()
                original = runner.power_text
                runner.power_text = lambda label: original(label).replace(b"__SAMPLES__", f"statuslinesdropped={dropped}\n__SAMPLES__".encode())
                _, result = run_row(runner, accepted=dropped == 0)
                for variant in ("short", "long"):
                    for name in ("neverUnprotected", "protectedWithin3sOfWake", "zeroLanReceiptsDuringWindow"):
                        value = check(result, name + ":" + variant)
                        self.assertEqual(value["met"], dropped == 0)
                        if dropped:
                            self.assertEqual(value.get("reason"), "status lines dropped")

    def test_P1_P2_P3_any_protection_outside_protected_or_blocked_fails_the_sleep_window(self):
        for probe, variant, protection in [("P1", 1, "unknown"), ("P1", 1, "unavailable"),
                                            ("P2", 1, "captiveWindow"), ("P3", 0, "unsupported")]:
            with self.subTest(probe=probe, protection=protection):
                observation = self.observation()
                item = observation["powerWakes"][variant]
                sleep, wake = V.power_instants(item)["sleep"], V.power_instants(item)["wake"]
                for sample in item["samples"]:
                    if sleep <= sample[0] < wake and (probe != "P3" or sample[0] == item["sleepAt"] + 1):
                        sample[1:3] = ["unavailable" if probe == "P1" else "active", protection]
                result = dict(checks=V.power_wake_checks(observation))
                self.assertFalse(check(result, "neverUnprotected:" + item["variant"])["met"])

    def test_P8_P9_short_sleep_must_be_at_least_1_s_and_below_the_5_s_force_threshold(self):
        for probe, held in [("P8", 0.05), ("P9", 5.9)]:
            with self.subTest(probe=probe):
                observation = self.observation()
                item = observation["powerWakes"][0]
                item["injected"][1][0] = item["injected"][0][0] + held
                result = dict(checks=V.power_wake_checks(observation))
                self.assertFalse(check(result, "injectedEventsSeen:short")["met"])

    def test_short_hold_boundaries_and_relative_long_slack(self):
        for variant, held, accepted in [(0, 1, True), (0, 4.99, True), (0, 0.99, False), (0, 5, False),
                                         (1, 124, True), (1, 136, True), (1, 110, False), (1, 150, False)]:
            with self.subTest(variant=variant, held=held):
                observation = self.observation()
                item = observation["powerWakes"][variant]
                item["wakeAt"] = item["sleepAt"] + held
                item["injected"][1][0] = item["injected"][0][0] + held
                result = dict(checks=V.power_wake_checks(observation))
                self.assertEqual(check(result, "injectedEventsSeen:" + item["variant"])["met"], accepted)

    def test_H1_daemon_fallback_requires_reason_wake(self):
        runner = PowerRunner()
        runner.power_forced_in_samples = False
        original = runner.power_text
        runner.power_text = lambda label: original(label).replace(b"reason=wake", b"reason=underlay")
        _, result = run_row(runner, accepted=False)
        self.assertFalse(check(result, "forcedHandshakeObserved:long")["met"])

    def test_H9_probe_attempts_outside_either_end_of_the_window_do_not_count(self):
        for edge in ("before", "after"):
            with self.subTest(edge=edge):
                class OutsideWindowRunner(PowerRunner):
                    def run(self, argv, data=None, timeout=100, env=None):
                        if argv[:4] == ["just", "lab", "ssh", "--"] and "cat " in argv[-1] and "generator-power-" in argv[-1]:
                            path = shlex.split(argv[-1])[1]
                            record = self.files[path]
                            label = Path(path).stem.removeprefix("generator-power-")
                            item = V.parse_power(self.power_text(label).decode())
                            start, end = V.power_window(item)
                            # Keep the generator window valid; put every sent probe before sleep or after recovery.
                            for sample in record["observations"]:
                                sample["timestamp"] = start - 0.5 if edge == "before" else end + 2
                        return super().run(argv, data, timeout, env)
                _, result = run_row(OutsideWindowRunner(), accepted=False)
                for variant in ("short", "long"):
                    counted = check(result, "zeroLanReceiptsDuringWindow:" + variant)
                    self.assertEqual(counted["probeAttempts"], 0)
                    self.assertFalse(counted["met"])


class PowerWakeParserTests(unittest.TestCase):
    # A guest at UTC-05:00: its log stamps are the epoch minus five hours rendered as UTC.
    LOCAL = lambda epoch: stamp(epoch - 5 * 3600)
    TEXT = ("tz=-0500\nsleep 1793301000.000\nwake 1793301130.012\n__LOG__\n"
            f"{LOCAL(1793301000.021)} lab power inject sleep pid=282\n{LOCAL(1793301130.034)} lab power inject wake pid=282\n"
            f"__STATUS__\n{LOCAL(1793301130.056)} status: phase=reasserting protection=blocked reason=wake pid=282\n"
            "__SAMPLES__\n1793301000.100 refs=1 {\"phase\":\"active\",\"protection\":\"protected\"}\n1793301000.350 refs=1 not json\n")

    def test_the_collect_text_parses_into_times_lines_status_and_samples(self):
        value = V.parse_power(self.TEXT)
        self.assertEqual((value["sleepAt"], value["wakeAt"]), (1793301000.0, 1793301130.012))
        self.assertEqual([[line[1], line[2]] for line in value["injected"]], [["sleep", 282], ["wake", 282]])
        self.assertAlmostEqual(value["injected"][0][0], 1793301000.021, places=3, msg="the guest's UTC offset is applied")
        self.assertAlmostEqual(value["injected"][1][0], 1793301130.034, places=3)
        self.assertEqual(value["daemonStatus"][0][1:4], ["reasserting", "blocked", "wake"])
        self.assertEqual(value["samples"], [[1793301000.1, "active", "protected", 1], [1793301000.35, "unavailable", "unknown", 1]])

    def test_an_unreadable_or_missing_offset_drops_the_log_lines_so_the_check_fails_closed(self):
        value = V.parse_power(self.TEXT.replace("tz=-0500\n", ""))
        self.assertEqual(value["injected"], [])
        self.assertEqual(value["daemonStatus"], [])

    def test_status_lines_dropped_is_parsed_from_the_status_section(self):
        self.assertIsNone(V.parse_power(self.TEXT).get("statusLinesDropped"))
        for dropped in (0, 5):
            with self.subTest(dropped=dropped):
                value = V.parse_power(self.TEXT.replace("__SAMPLES__", f"statuslinesdropped={dropped}\n__SAMPLES__"))
                self.assertEqual(value.get("statusLinesDropped"), dropped)

    def test_only_the_fixed_log_vocabulary_is_kept(self):
        text = self.TEXT.replace("lab power inject sleep pid=282", "lab power inject sleep pid=282 key=SECRET").replace("reason=wake", "reason=wake extra")
        value = V.parse_power(text)
        self.assertEqual([line[1] for line in value["injected"]], ["wake"], "a line with any other text is not an injected-event line")


class PowerWakeWindowTests(unittest.TestCase):
    """The helpers the checks and the driver share (verdict.power_instants, power_protected_again, power_window)."""

    def item(self, injected, slept=100.0, woke=103.0):
        return dict(variant="short", sleepSeconds=3, sleepAt=slept, wakeAt=woke, injected=injected, samples=[])

    def test_the_daemons_lines_set_the_instants_only_when_one_of_each_is_in_order_near_the_injector(self):
        ok = V.power_instants(self.item([[100.02, "sleep", 7], [103.03, "wake", 7]]))
        self.assertEqual((ok["sleep"], ok["wake"], ok["seen"]), (100.02, 103.03, True))
        reversed_lines = V.power_instants(self.item([[103.03, "sleep", 7], [100.02, "wake", 7]]))
        self.assertFalse(reversed_lines["seen"], "a wake line stamped before the sleep line is not an injected sleep and wake")
        self.assertEqual((reversed_lines["sleep"], reversed_lines["wake"]), (100.0, 103.0), "the injector's own instants stand in")
        for lines in ([], [[100.02, "sleep", 7]], [[103.03, "wake", 7]], [[100.02, "sleep", 7], [100.5, "sleep", 7], [103.03, "wake", 7]],
                      [[100.02, "sleep", 7], [103.03, "wake", 7], [103.5, "wake", 7]], [[10.0, "sleep", 7], [13.0, "wake", 7]]):
            self.assertFalse(V.power_instants(self.item(lines))["seen"], lines)
        self.assertIsNone(V.power_instants(self.item([], slept=103.0, woke=100.0)))
        self.assertIsNone(V.power_instants(self.item([], slept=None)))

    def test_a_stale_protected_sample_right_after_the_wake_never_counts_as_recovery(self):
        samples = [[103.0, "active", "protected", 1], [103.25, "active", "protected", 1], [103.5, "reasserting", "blocked", 1],
                   [104.0, "reasserting", "blocked", 1], [104.5, "active", "protected", 1], [104.75, "active", "protected", 1]]
        self.assertEqual(V.power_protected_again(samples, 103.0), 104.5)
        self.assertEqual(V.power_protected_again(samples[:2], 103.0), 103.0, "nothing was lost: the first protected sample")
        self.assertIsNone(V.power_protected_again(samples[:4], 103.0), "lost to the end: never protected again")
        item = dict(self.item([[100.02, "sleep", 7], [103.03, "wake", 7]]), samples=samples)
        self.assertEqual(V.power_window(item), (100.02, 104.5))
        self.assertEqual(V.power_window(dict(item, samples=samples[:4])), (100.02, 106.03), "wake + 3 s when never protected again")


class PowerWakeFixtureTests(unittest.TestCase):
    RUNNER = replay.module("power_runner", "verdict-run.py")

    def test_the_fixture_replays_and_every_check_has_a_failing_case(self):
        result = self.RUNNER.replay(ROWS["POWER-WAKE"], replay.TABLE, {})
        self.assertTrue(result["expectationsMet"], result.get("failingFixtures"))
        self.assertEqual(result["failingFixturesUncovered"], [])
        self.assertTrue(all(case["rejected"] for case in result["failingFixtures"]))
        self.assertTrue(all(case["met"] for case in result["passingFixtures"]))
        self.assertGreaterEqual(len(result["failingFixtures"]), 25)
        self.assertEqual({check["name"] for check in result["checks"]} - {case["expectation"] for case in result["failingFixtures"]}, set())

    def test_the_passing_observation_is_the_two_variants_of_the_row(self):
        names = [item["variant"] for item in FIXTURE["pass"]["powerWakes"]]
        self.assertEqual(names, [variant["name"] for variant in ROWS["POWER-WAKE"]["variants"]])
        self.assertEqual([item["sleepSeconds"] for item in FIXTURE["pass"]["powerWakes"]],
                         [variant["sleepSeconds"] for variant in ROWS["POWER-WAKE"]["variants"]])

    def test_failing_fixtures_fail_the_named_check_and_preserve_existing_additional_failures(self):
        additional = {
            "a duplicate variant name": {"forcedHandshakeObserved:long"},
            "the long variant asked for 3 s": {"injectedEventsSeen:long"},
            "the daemon held the sleep 60 s, not 130 s": {"protectedWithin3sOfWake:long"},
            "no sample at all: nothing proves it": {"protectedWithin3sOfWake:short", "onePfReferenceThroughout:short"},
            "N2: status lines dropped; every daemon-status-dependent check fails closed": {
                "neverUnprotected:long", "zeroLanReceiptsDuringWindow:long", "forcedHandshakeObserved:long"},
        }
        for case in FIXTURE["failing"]:
            with self.subTest(note=case.get("note"), expectation=case["expectation"]):
                observation = copy.deepcopy(FIXTURE["pass"])
                for path, replacement in case["set"]:
                    self.RUNNER.set_path(observation, path, replacement)
                self.assertEqual({c["name"] for c in V.power_wake_checks(observation) if not c["met"]},
                                 {case["expectation"]} | additional.get(case.get("note"), set()))
                if case.get("note", "").startswith(("P10-long:", "P12-long:")):
                    item = observation["powerWakes"][1]
                    wake = V.power_instants(item)["wake"]
                    self.assertIsNone(V.power_protected_again(item["samples"], wake, item["daemonStatus"]))
                    self.assertEqual(V.power_window(item)[1], wake + V.POWER_WAKE_SECONDS)

    def test_a_failing_case_that_does_nothing_is_not_rejected(self):
        read = self.RUNNER.read
        def harmless(path, hashes, label):
            value = read(path, hashes, label)
            if label == "fixture:rows:power-wake":
                value["failing"][0]["set"] = [[["powerWakes", 0, "profile"], "full4"]]
            return value
        with patch.object(self.RUNNER, "read", side_effect=harmless):
            self.assertFalse(self.RUNNER.replay(ROWS["POWER-WAKE"], replay.TABLE, {})["expectationsMet"])


class PowerWakeCatalogueTests(unittest.TestCase):
    def test_the_row_is_live_injected_and_states_its_limits(self):
        row = ROWS["POWER-WAKE"]
        self.assertNotIn("gap", row)
        self.assertEqual((row["action"], row["checks"], row["profile"]), ("power-wake", "power-wake", "full4"))
        self.assertIn(row["checks"], V.ROW_CHECKS)
        self.assertEqual([(item["name"], item["sleepSeconds"]) for item in row["variants"]], [("short", 3), ("long", 130)])
        self.assertEqual({item["name"]: item["sleepSeconds"] for item in row["variants"]}, V.POWER_VARIANTS)
        text = json.dumps([row["title"], row["steps"]])
        self.assertIn("injected power event", text)
        self.assertNotIn("pmset", text)
        limits = " ".join(row["limitations"])
        for phrase in ("sleep/wake handling only", "do not sleep", "RT-18", "real hardware"):
            self.assertIn(phrase, limits)

    def test_rt_21_has_no_gap_and_the_other_gate_row_6_rows_keep_theirs(self):
        self.assertNotIn("gap", ROWS["RT-21"])
        for name in ("M5.2-01", "M5.2-03"):
            self.assertIn("gap", ROWS[name], name)


class PowerWakeGuestScriptTests(unittest.TestCase):
    @staticmethod
    def block(start, end):
        return SCRIPT[SCRIPT.index(f"  {start})"):SCRIPT.index(f"  {end})")]

    def test_every_power_action_is_a_case_of_the_guest_script(self):
        for action in ("power-inject", "power-cycle", "power-observe", "power-collect"):
            self.assertRegex(SCRIPT, rf"(?m)^  {action}\)")

    def test_inject_validates_arguments_and_refuses_no_daemon_or_more_than_one(self):
        block = self.block("power-inject", "power-cycle")
        self.assertIn('seconds="${2:?sleep seconds required}"', block)
        self.assertIn('label="${3:?label required}"', block)
        patterns = re.findall(r'\[\[ "\$(?:seconds|label)" =~ (\S+) \]\]', block)
        self.assertEqual(len(patterns), 2, block)
        self.assertIn("((seconds <= 200))", block)
        for text, ok in (("3", True), ("130", True), ("200", True), ("0", False), ("03", False), ("", False), ("3x", False), ("-3", False),
                         ("1e2", False), ("3 ", False), ("1000", False)):
            self.assertEqual(self.matches(patterns[0], text), ok, ("seconds", text))
        for text, ok in (("short-1", True), ("long-12", True), ("a" * 32, True), ("a" * 33, False), ("", False), ("Short", False),
                         ("a/b", False), ("../x", False), ("a b", False), ("a;b", False)):
            self.assertEqual(self.matches(patterns[1], text), ok, ("label", text))
        self.assertIn("pgrep -o -x WGEXDaemon", block)
        self.assertRegex(block, r'pgrep -x WGEXDaemon[^\n]*wc -l')
        self.assertRegex(block, r'\[\[ "\$count" == 1 \]\]')
        self.assertIn("grep -aqF 'lab power inject sleep' \"$daemon\"", block, "SIGUSR1 ends a process without the handler: only a build that carries the injection is signalled")
        self.assertIn("/Applications/WGEX.app/Contents/MacOS/WGEXDaemon", block)
        self.assertNotIn('"$daemon" --doctor', block, "the daemon binary is read, never executed, by the guest action")
        self.assertIn('mkdir -m 0700 "$out"', block)
        self.assertIn('nohup bash "$0" power-observe "$out" "$((seconds + 45))"', block)
        self.assertIn('sudo -n nohup bash "$0" power-cycle "$out" "$seconds" "$pid"', block)
        self.assertLess(block.index("pgrep -o -x WGEXDaemon"), block.index("mkdir -m 0700"), "nothing is created before the daemon is identified")

    def test_cycle_runs_as_root_signals_only_the_checked_daemon_and_rechecks_before_each_signal(self):
        block = self.block("power-cycle", "power-observe")
        self.assertIn("((EUID == 0)) || exit 1", block)
        self.assertEqual(block.count("kill -s"), 1, "one signalling statement, behind the check")
        self.assertIn('kill -s "$1" "$pid"', block)
        self.assertLess(block.index("signal_daemon USR1 sleep"), block.index('sleep "$seconds"'))
        self.assertLess(block.index('sleep "$seconds"'), block.index("signal_daemon USR2 wake"))
        self.assertEqual(len(re.findall(r"signal_daemon [A-Z0-9]+ ", block)), 2, "exactly the two injections")
        self.assertEqual(len(re.findall(r"pgrep -x WGEXDaemon", block)), 1, "one shared check function, called before each signal")
        self.assertNotIn("kill -9", block)
        self.assertNotIn("kill -KILL", block)

    def test_observe_delegates_to_the_same_sampler_as_en0_and_counts_references(self):
        block = self.block("power-observe", "power-collect")
        self.assertIn("en0-observe", block)
        observe = self.block("en0-observe", "en0-collect")
        self.assertIn("{n++} END {print n + 0}", observe, "reference rows are counted, never printed")

    def test_collect_prints_only_the_fixed_vocabulary_of_the_daemon_log(self):
        block = self.block("power-collect", "*")
        self.assertIn("__LOG__", block)
        self.assertIn("__STATUS__", block)
        self.assertIn("__SAMPLES__", block)
        self.assertIn("lab power inject (sleep|wake)", block)
        self.assertIn("/usr/bin/log show --style compact", block)
        self.assertIn("'process == \"WGEXDaemon\"'", block)
        self.assertRegex(block, r"\[\[ \"\$label\" =~ \^\[a-z0-9-\]\{1,32\}\$ \]\] \|\| exit 1")

    def test_the_collect_filters_pass_only_whole_lines_of_the_daemon_in_the_fixed_vocabulary(self):
        block = self.block("power-collect", "*")
        programs = re.findall(r"perl -ne '([^\n]*)' <<<\"\$lines\"", block)
        self.assertEqual(len(programs), 2)
        log = "\n".join([
            "2026-11-02 10:05:11.123 Df  WGEXDaemon[282:4a1] [com.magrathean.WGEXApp.lab:daemon] lab power inject sleep",
            "2026-11-02 10:05:11.125 Df  WGEXDaemon[282:4a1] [com.magrathean.WGEXApp.lab:daemon] lab power inject sleep key=SECRET",
            "2026-11-02 10:07:21.321 Df  WGEXDaemon[282:4a1] [com.magrathean.WGEXApp.lab:daemon] lab power inject wake",
            "2026-11-02 10:07:21.360 Df  WGEXDaemon[282:4a1] [com.magrathean.WGEXApp.lab:daemon] status: phase=reasserting protection=blocked reason=wake",
            "2026-11-02 10:07:21.370 Df  other[11:1] [x:y] lab power inject wake",
            "2026-11-02 10:07:21.380 Df  other[11:1] [x:y] status: phase=active protection=protected reason=none",
            "2026-11-02 10:07:22.000 Df  WGEXDaemon[282:4a1] [com.magrathean.WGEXApp.lab:daemon] status: phase=active protection=protected reason=none",
        ]) + "\n"
        run = lambda program: subprocess.run(["perl", "-ne", program], input=log, capture_output=True, text=True, timeout=20, check=True).stdout.splitlines()
        self.assertEqual(run(programs[0]), ["2026-11-02 10:05:11.123 lab power inject sleep pid=282", "2026-11-02 10:07:21.321 lab power inject wake pid=282"])
        self.assertEqual([line for line in run(programs[1]) if "status: " in line], ["2026-11-02 10:07:21.360 status: phase=reasserting protection=blocked reason=wake pid=282",
                                            "2026-11-02 10:07:22.000 status: phase=active protection=protected reason=none pid=282"])

    def test_H7_status_filter_caps_at_200_and_reports_the_number_dropped(self):
        block = self.block("power-collect", "*")
        programs = re.findall(r"perl -ne '([^\n]*)' <<<\"\$lines\"", block)
        self.assertEqual(len(programs), 2)
        line = ("2026-11-02 10:07:22.000 Df  WGEXDaemon[282:4a1] [com.magrathean.WGEXApp.lab:daemon] "
                "status: phase=active protection=protected reason=none\n")
        for count in (0, 200, 207):
            with self.subTest(count=count):
                result = subprocess.run(["perl", "-ne", programs[1]], input=line * count,
                                        capture_output=True, text=True, timeout=20, check=True).stdout.splitlines()
                self.assertEqual(sum("status: " in line for line in result), min(count, 200))
                self.assertIn(f"statuslinesdropped={max(0, count - 200)}", result)

    @staticmethod
    def matches(pattern, text):
        return subprocess.run(["bash", "-c", f'[[ "$1" =~ {pattern} ]]', "fixture", text], check=False, timeout=20).returncode == 0


if __name__ == "__main__":
    unittest.main()
