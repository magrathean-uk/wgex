# SPDX-License-Identifier: MIT
"""M1-10q: REBOOT-LOCKDOWN tests the strict case (Allow LAN off before the reboot), with the never-open window ended at the
daemon's first blocked status line, receipts filtered by the row's own nonce and counted apart for the LAN and off-subnet
cases, the early-boot capture gap stated and the unexplainedOutsideFlow observation; real driver with recorded replies
and the pure verdict helpers. Never a VM."""
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_live_replay as replay
import test_run8_rows as run8
from test_run8e_driver import steps

LIVE, V = replay.LIVE, replay.V
# Guest run 8e capture-1-en0 (M1-10p-ANALYSIS.txt section 4): the one outside packet, headers only.
ACK = "1793294300.350000 IP 192.168.64.98.51550 > 17.188.182.132.443: Flags [.], ack 1, win 2048, length 0\n"
# The run 8e live ruleset (daemon-loaded, lockdown, no profile), the lines the analysis quotes.
RULES_8E = "\n".join([
    "pass quick on en0 inet from 192.168.64.0/24 to 192.168.64.0/24 no state",
    "pass quick on en0 inet from any to 169.254.0.0/16 no state",
    "pass quick on en0 inet from any to 224.0.0.0/24 no state",
    "pass quick on en0 inet from any to 255.255.255.255 no state",
    "block drop quick all"])


class StrictRunner(run8.Run8Runner):
    """Run8Runner whose receivers also hold chosen receipts after the reboot, at host-clock offsets from the reboot
    command: (offset, address, scope, nonce), where a nonce starting with -w is this row's own (session prefix added);
    and whose header-only post-boot capture read returns `wire`."""

    def __init__(self, receipts=(), wire=""):
        super().__init__()
        self.extra, self.wire = list(receipts), wire

    def receiver(self, scope):
        value = super().receiver(scope)
        if self.rebooted_at is not None:
            prefix = self.generator["nonce"].rsplit("-w", 1)[0]
            for offset, address, where, nonce in self.extra:
                if where == scope:
                    value["observations"].append(dict(kind="received", scope=where, family="ipv4", proto="udp", address=address,
                                                      port=8088, timestamp=self.rebooted_at + offset,
                                                      nonce=prefix + nonce if nonce.startswith("-w") else nonce))
        return value

    def run(self, argv, data=None, timeout=100, env=None):
        if argv[:1] == ["tcpdump"] and LIVE.OUTSIDE_FLOW_FILTER in argv:
            self.commands.append(list(argv))
            return self.reply(argv, self.wire.encode())
        return super().run(argv, data, timeout, env)


def window(result):
    return run8.check(result, "zeroReceiptsBeforeFirstStatus")["window"]


class AllowLANOffTests(unittest.TestCase):
    def test_allow_lan_goes_off_after_the_lead_control_and_before_the_lockdown_press_and_is_read_back_before_the_reboot(self):
        runner, result = run8.run_row("REBOOT-LOCKDOWN")
        lines = run8.commands(runner)
        lead = next(i for i, c in enumerate(lines) if " generate " in c and "--state unprotected" in c)
        allow = [i for i, c in enumerate(lines) if replay.actuates(c, 400, 310)]
        lockdown = next(i for i, c in enumerate(lines) if replay.actuates(c, 310, 310))
        boot = next(i for i, c in enumerate(lines) if c.endswith("verdict-actions.sh reboot"))
        self.assertEqual(len(allow), 1, "one Allow LAN press, never back on")
        self.assertLess(lead, allow[0])
        self.assertLess(allow[0], lockdown)
        reads = [i for i, c in enumerate(lines) if c.endswith("verdict-actions.sh allow-lan-state")]
        self.assertTrue(any(lockdown < i < boot for i in reads), "read back from the journal after the lockdown press, before the reboot")
        self.assertFalse(runner.allow_lan)
        check = run8.check(result, "allowLANOffReachedDaemon")
        self.assertEqual((check["met"], check["allowLAN"]), (True, False))

    def test_an_allow_lan_toggle_that_never_reaches_the_journal_fails_before_the_lockdown_press(self):
        runner = run8.Run8Runner()
        runner.allow_lan_works = False
        _, result = run8.run_row("REBOOT-LOCKDOWN", runner, accepted=False)
        self.assertTrue(any(gap.startswith("allowLANNotApplied:") for gap in result["gaps"]), result["gaps"])
        lines = run8.commands(runner)
        # M1-10t: the dump shows the toggle still on after the first press, which never reached the daemon (read before each
        # press, the first included); the second press is the last the Session allows (TOGGLE_PRESS_LIMIT).
        self.assertEqual(len([c for c in lines if replay.actuates(c, 400, 310)]), 2, "each press follows a toggle read of on")
        reads = [(item["toggleBeforePress"], item["toggleValue"]) for item in steps(result) if "toggleValue" in item]
        self.assertEqual(reads, [(1, True), (2, True)])
        self.assertFalse(any(replay.actuates(c, 310, 310) for c in lines), "no lockdown press")
        self.assertFalse(any(c.endswith("verdict-actions.sh reboot") for c in lines))

    def test_the_guest_action_reads_settings_allow_lan_from_the_replayed_journal_only(self):
        script = (run8.GUEST / "verdict-actions.sh").read_text()
        block = script[script.index("  allow-lan-state)"):script.index("  boot-intent)")]
        for needle in ["umask 077", "trap 'rm -f \"$replayed\"' EXIT", "plutil -extract settings.allowLAN raw",
                       "printf 'allowLAN=%s\\n'", '[[ "$value" == true || "$value" == false ]] || exit 1']:
            self.assertIn(needle, block)


class NeverOpenWindowTests(unittest.TestCase):
    def test_the_window_ends_at_the_daemons_first_blocked_line_and_records_both_instants(self):
        _, result = run8.run_row("REBOOT-LOCKDOWN")
        value = window(result)
        self.assertEqual(value["endSource"], "daemonFirstBlockedStatus")
        self.assertEqual(value["end"], value["daemonFirstBlockedAt"])
        self.assertLess(value["daemonFirstStatusAt"], value["daemonFirstBlockedAt"], "idle/unknown precedes idle/blocked")
        self.assertLess(value["daemonFirstBlockedAt"], value["driverFirstPollAt"])
        self.assertEqual(value["start"], value["sshReturnAt"])
        self.assertTrue(value["nonce"].startswith("lab-"))
        self.assertGreater(value["postBootCaptureAt"], value["sshReturnAt"])

    def test_reboot_intent_keeps_the_driver_poll_end_and_records_the_daemon_instants(self):
        _, result = replay.LiveReplayTests().run_recorded("REBOOT-INTENT", accepted=False) # M1-10u fix pass 1: REBOOT-INTENT needs launchd runs == 1; this runner has no boot-observe, so the row is not accepted
        check = run8.check(result, "zeroReceiptsBeforeFirstStatus")
        self.assertEqual(check["endSource"], "driverFirstPoll")
        self.assertEqual(check["end"], check["driverFirstPollAt"])
        self.assertIn("daemonFirstBlockedAt", check)

    def test_own_nonce_receipts_before_the_first_blocked_line_fail_and_foreign_ones_do_not(self):
        _, result = run8.run_row("REBOOT-LOCKDOWN", StrictRunner([(4.0, "192.168.64.1", "outside_tunnel", "receiver"),
                                                                 (4.0, "192.168.64.1", "outside_tunnel", "lab-other-w1")]))
        self.assertEqual(run8.check(result, "zeroReceiptsBeforeFirstStatus")["receiptCount"], 0)
        _, result = run8.run_row("REBOOT-LOCKDOWN", StrictRunner([(4.0, "192.168.64.1", "outside_tunnel", "-w9")]), accepted=False)
        check = run8.check(result, "zeroReceiptsBeforeFirstStatus")
        self.assertLessEqual(check["window"]["start"], check["window"]["end"])
        self.assertEqual((check["met"], check["receiptCount"]), (False, 1))

    def test_an_end_before_the_start_is_an_empty_window_said_so(self):
        value = V.never_open_window(110.0, 140.0, [[100.0, "idle", "unknown"], [102.5, "idle", "blocked"]], strict=True)
        self.assertEqual((value["end"], value["windowSeconds"], value["note"]), (102.5, 0.0, V.NEVER_OPEN_EMPTY))
        value = V.never_open_window(110.0, 140.0, [[100.0, "idle", "unknown"]], strict=True)
        self.assertEqual((value["endSource"], value["end"], value["daemonFirstBlockedAt"]), ("driverFirstPoll", 140.0, None))
        self.assertNotIn("note", value)
        value = V.never_open_window(110.0, 140.0, [[115.0, "idle", "blocked"]], strict=False)
        self.assertEqual((value["endSource"], value["end"], value["daemonFirstBlockedAt"]), ("driverFirstPoll", 140.0, 115.0))
        value = V.never_open_window(110.0, 140.0, [[115.0, "idle", "blocked"]], strict=True)
        self.assertEqual((value["end"], value["windowSeconds"]), (115.0, 5.0))


class LANAndOffSubnetTests(unittest.TestCase):
    def test_a_post_boot_lan_receipt_fails_the_lan_check_alone(self):
        _, result = run8.run_row("REBOOT-LOCKDOWN", StrictRunner([(12.0, "192.168.64.1", "outside_tunnel", "-w2")]), accepted=False)
        value = window(result)
        self.assertGreaterEqual(value["daemonFirstBlockedAt"], value["start"])
        lan = run8.check(result, "zeroLANReceiptsAfterBoot")
        self.assertEqual((lan["met"], lan["receiptCount"], lan["subnet"]), (False, 1, "192.168.64.0/24"))
        self.assertTrue(run8.check(result, "zeroOffSubnetReceiptsAfterBoot")["met"])
        self.assertTrue(run8.check(result, "zeroReceiptsBeforeFirstStatus")["met"], "after the first blocked line")

    def test_a_receipt_at_the_peer_without_a_tunnel_is_off_subnet(self):
        _, result = run8.run_row("REBOOT-LOCKDOWN", StrictRunner([(12.0, "10.77.0.1", "in_tunnel", "-w2")]), accepted=False)
        off = run8.check(result, "zeroOffSubnetReceiptsAfterBoot")
        self.assertEqual((off["met"], off["receiptCount"], off["addresses"]), (False, 1, ["10.77.0.1"]))
        self.assertEqual(off["limitation"], V.OFF_SUBNET_LIMITATION)
        self.assertTrue(run8.check(result, "zeroLANReceiptsAfterBoot")["met"])

    def test_receipts_after_the_driver_poll_are_outside_the_post_boot_window(self):
        _, result = run8.run_row("REBOOT-LOCKDOWN", StrictRunner([(400.0, "192.168.64.1", "outside_tunnel", "-w2")]))
        self.assertEqual(run8.check(result, "zeroLANReceiptsAfterBoot")["receiptCount"], 0)

    def test_the_subnet_test(self):
        self.assertTrue(V.in_underlay_subnet(V.UNDERLAY_HOST))
        self.assertFalse(V.in_underlay_subnet("10.77.0.1"))
        self.assertFalse(V.in_underlay_subnet(None))


class EarlyBootTests(unittest.TestCase):
    def test_the_verdict_states_the_early_boot_interval_uncaptured(self):
        _, result = run8.run_row("REBOOT-LOCKDOWN")
        early = result["bootObservation"]["earlyBootCapture"]
        self.assertFalse(early["captured"])
        self.assertEqual(early["gap"], V.EARLY_BOOT_GAP)
        self.assertIn("ADR-009", early["gap"])
        self.assertGreater(early["unenforcedSeconds"], 0)
        window = run8.check(result, "zeroReceiptsBeforeFirstStatus")["window"]
        self.assertEqual(early["postBootCaptureAt"], window["postBootCaptureAt"])
        self.assertGreater(early["postBootCaptureAt"], window["sshReturnAt"], "the capture starts after SSH returns")
        self.assertGreater(early["uncapturedSeconds"], 0)
        self.assertEqual(result["gaps"], [], "stated, never a row gap")

    def test_without_boot_time_the_seconds_are_unknown(self):
        early = V.early_boot_capture(dict(timeline=[[5.0, "idle", "blocked"]]))
        self.assertEqual((early["captured"], early["unenforcedSeconds"], early["uncapturedSeconds"]), (False, None, None))


class UnexplainedOutsideFlowTests(unittest.TestCase):
    def test_the_run_8e_ack_is_named_and_does_not_decide_the_row(self):
        runner, result = run8.run_row("REBOOT-LOCKDOWN", StrictRunner(wire=ACK))
        flow = result["unexplainedOutsideFlow"]
        self.assertEqual((flow["inspected"], flow["observed"], flow["unexplainedCount"]), (True, True, 1))
        self.assertEqual({key: flow["flows"][0][key] for key in ("destination", "port", "proto", "tcpFlags")},
                         dict(destination="17.188.182.132", port=443, proto="tcp", tcpFlags="."))
        self.assertNotIn("unexplainedOutsideFlow", [c["name"] for c in result["checks"]])
        read = next(argv for argv in runner.commands if argv[:1] == ["tcpdump"] and LIVE.OUTSIDE_FLOW_FILTER in argv)
        self.assertNotIn("-A", read, "headers only, never a payload")
        starts = [c for c in run8.commands(runner) if c.startswith("just lab ssh -- bash ") and "/start-capture.sh " in c]
        post = next(i for i, c in enumerate(starts) if c.endswith(" en0 post-boot-never-open"))
        self.assertEqual(read[read.index("-r") + 1].rpartition("/")[2], f"capture-{post}-en0.pcap", "the post-boot copy")

    def test_a_clean_post_boot_capture_is_inspected_and_unobserved(self):
        _, result = run8.run_row("REBOOT-LOCKDOWN", StrictRunner(wire="1793294300.1 IP 192.168.64.98.5000 > 192.168.64.1.8088: UDP, length 40\n"))
        flow = result["unexplainedOutsideFlow"]
        self.assertEqual((flow["inspected"], flow["observed"], flow["outsideFlowCount"]), (True, False, 0))

    def test_other_rows_carry_no_outside_flow_observation(self):
        for row, runner in (("M5.3-10", run8.Run8Runner()), ("BOOT-SECRETS", None)):
            with self.subTest(row=row):
                if runner is None:
                    runner = run8.Run8Runner()
                    runner.boot_secret_mode = True
                _, result = run8.run_row(row, runner)
                self.assertNotIn("unexplainedOutsideFlow", result)

    def test_outside_flows_keep_only_destinations_beyond_the_subnet_and_link_scope(self):
        text = "".join([ACK,
                        "1.0 IP 192.168.64.98.5000 > 192.168.64.1.8088: UDP, length 40\n",
                        "2.0 IP 192.168.64.98.68 > 255.255.255.255.67: BOOTP/DHCP, Request\n",
                        "3.0 IP 192.168.64.98.5353 > 224.0.0.251.5353: 0 PTR (QM)? local. (40)\n",
                        "4.0 IP6 fe80::1.546 > ff02::1:2.547: dhcp6 solicit\n",
                        "5.0 IP6 2001:db8::5.5000 > 2001:db8::9.53: 1+ A? leak. (30)\n",
                        "6.0 IP 192.168.64.98 > 8.8.8.8: ICMP echo request, id 1, seq 0, length 64\n"])
        flows = V.outside_flows(text)
        self.assertEqual([(f["destination"], f["port"], f["proto"]) for f in flows],
                         [("17.188.182.132", 443, "tcp"), ("2001:db8::9", 53, "udp"), ("8.8.8.8", None, "icmp")])
        self.assertTrue(all(set(f) == {"timestamp", "family", "source", "destination", "port", "proto", "tcpFlags"} for f in flows))

    def test_a_flow_is_explained_only_by_an_outbound_pass_rule_that_could_match_it(self):
        flow = V.outside_flows(ACK)[0]
        self.assertIsNone(V.pass_rule_for(flow, RULES_8E))
        self.assertEqual(V.unexplained_outside_flow(ACK, RULES_8E)["unexplainedCount"], 1)
        for rule in ["pass out quick on en0 inet proto tcp from any to any port = 443 flags S/SA keep state",
                     "pass out quick on en0 inet from any to 17.188.0.0/16 no state",
                     "pass out quick on en0 inet from any to <captive_hosts> no state"]:
            with self.subTest(rule=rule):
                self.assertEqual(V.pass_rule_for(flow, rule), rule)
        for rule in ["pass in quick on en0 inet proto tcp from any to any port = 443",
                     "pass out quick on lo0 all",
                     "pass out quick on en0 inet proto udp from any to any port = 443",
                     "pass out quick on en0 inet proto tcp from any to any port = 80",
                     "pass out quick on en0 inet6 from any to any"]:
            with self.subTest(rule=rule):
                self.assertIsNone(V.pass_rule_for(flow, rule))


class FixtureTests(unittest.TestCase):
    def test_the_dry_run_fixture_has_a_failing_case_for_every_new_expectation(self):
        fixture = json.loads((replay.ROOT / "Tools/lab/tests/fixtures/rows/reboot-lockdown.json").read_text())
        expectations = {case["expectation"] for case in fixture["failing"]}
        self.assertLessEqual({"allowLANOffReachedDaemon", "zeroLANReceiptsAfterBoot", "zeroOffSubnetReceiptsAfterBoot"}, expectations)
        self.assertEqual(fixture["pass"]["boot"]["neverOpenWindow"]["note"], V.NEVER_OPEN_EMPTY)
        checks = {c["name"]: c for c in V.row_checks("reboot-lockdown", fixture["pass"])}
        self.assertTrue(all(c["met"] for c in checks.values()), checks)
        self.assertEqual(checks["zeroReceiptsBeforeFirstStatus"]["window"]["endSource"], "daemonFirstBlockedStatus")

    def test_the_catalogue_states_the_strict_case(self):
        row = run8.ROWS["REBOOT-LOCKDOWN"]
        self.assertTrue(any("wgex.protection.allowLocalNetwork" in step for step in row["steps"]))
        self.assertTrue(any("off-subnet" in item for item in row["expected"]))
        self.assertTrue(any("early-boot" in item for item in row["expected"]))
        self.assertTrue(any("unexplainedOutsideFlow" in item for item in row["expected"]))


# M1-10q fix pass 1 (VERIFY N1-N3). Run 8e's reboot timing on the guest clock, seconds after an arbitrary base: the daemon's
# first blocked status line 225.4, SSH return 227.25, the neverOpen generator's first window start 249.16.
BASE = 1793373000.0
RUN8E_BLOCKED, RUN8E_SSH, RUN8E_PROBE = BASE + 225.4, BASE + 227.25, BASE + 249.16


class LateProbeRunner(StrictRunner):
    """StrictRunner whose post-boot neverOpen generator starts `late` seconds after its usual start, as in run 8e (the
    generator runs only after diagnostics-start, boot_observe, sample_clock and start_capture)."""

    def __init__(self, late, **kwargs):
        super().__init__(**kwargs)
        self.late, self.shifted = late, False

    def start(self, argv, env=None):
        process = super().start(argv, env)
        if "--state blocked" in argv[-1] and self.rebooted_at is not None and not self.shifted:
            self.shifted = True
            # The whole generator run moves: its window and its probes' receipts.
            for item in self.generator["windows"]:
                item["start"] += self.late
                item["end"] += self.late
            for source in [self.generator, *self.generator["receiverRecords"]]:
                for observation in source["observations"]:
                    observation["timestamp"] += self.late
        return process


def run_dry(row):
    runner = replay.module("strict_dry_run_" + row.replace("-", "_"), "verdict-run.py")
    stdout = io.StringIO()
    with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
        with patch("sys.stdout", stdout):
            code = runner.main([row, "--dry-run", "--report-root", directory])
        report = json.loads((Path(directory) / row / "verdict.json").read_text())
        readme = (Path(directory) / row / "README.md").read_text()
    return code, report, readme, stdout.getvalue()


class NotMeasuredTests(unittest.TestCase):
    """N1 and N2: a never-open window that cannot hold a probe says so (measured false), and the row never counts it."""

    def test_run_8e_timing_is_an_empty_window_not_measured(self):
        timeline = [[BASE + 224.0, "idle", "unknown"], [RUN8E_BLOCKED, "idle", "blocked"]]
        value = V.never_open_window(RUN8E_SSH, BASE + 270.0, timeline, strict=True, probed_from=RUN8E_PROBE)
        self.assertEqual((value["end"], value["windowSeconds"], value["probedFrom"]), (RUN8E_BLOCKED, 0.0, RUN8E_PROBE))
        self.assertEqual((value["measured"], value["notMeasured"], value["note"]), (False, V.NOT_MEASURED_EMPTY, V.NEVER_OPEN_EMPTY))
        self.assertEqual(V.NOT_MEASURED_EMPTY, "not measured (empty window)")

    def test_a_window_ending_before_the_first_probe_is_not_measured(self):
        """N2: the daemon's first blocked line 0-22 s after SSH return: a non-empty window no probe can land in."""
        for blocked, measured in ((BASE + 240.0, False), (RUN8E_PROBE, False), (BASE + 255.0, True)):
            with self.subTest(blocked=blocked - BASE):
                value = V.never_open_window(RUN8E_SSH, BASE + 270.0, [[blocked, "idle", "blocked"]], strict=True, probed_from=RUN8E_PROBE)
                self.assertGreater(value["windowSeconds"], 0)
                self.assertEqual(value["measured"], measured)
                if measured:
                    self.assertNotIn("notMeasured", value)
                    self.assertNotIn("note", value)
                else:
                    self.assertEqual((value["notMeasured"], value["note"]), (V.NOT_MEASURED_UNPROBED, V.NEVER_OPEN_UNPROBED))
        value = V.never_open_window(RUN8E_SSH, BASE + 270.0, [], strict=False)
        self.assertEqual((value["probedFrom"], value["measured"]), (None, True), "no probe start on record: the bounds alone")

    def test_the_check_carries_the_flag_and_the_row_never_counts_it_as_met(self):
        fixture = json.loads((replay.ROOT / "Tools/lab/tests/fixtures/rows/reboot-lockdown.json").read_text())
        window = fixture["pass"]["boot"]["neverOpenWindow"]
        self.assertEqual((window["measured"], window["notMeasured"], window["probedFrom"] > window["start"]), (False, V.NOT_MEASURED_EMPTY, True))
        checks = V.row_checks("reboot-lockdown", fixture["pass"])
        check = next(c for c in checks if c["name"] == "zeroReceiptsBeforeFirstStatus")
        self.assertEqual((check["met"], check["measured"], check["notMeasured"]), (True, False, "not measured (empty window)"))
        self.assertEqual(V.checks_not_measured(checks), [dict(name="zeroReceiptsBeforeFirstStatus", reason="not measured (empty window)")])
        self.assertEqual(V.check_counts(checks), dict(met=len(checks) - 1, failed=0, notMeasured=1))
        # The flag comes from the window's bounds, never from a stored measured=true.
        tampered = json.loads(json.dumps(fixture["pass"]))
        tampered["boot"]["neverOpenWindow"].update(measured=True)
        tampered["boot"]["neverOpenWindow"].pop("notMeasured")
        self.assertFalse(next(c for c in V.row_checks("reboot-lockdown", tampered) if c["name"] == "zeroReceiptsBeforeFirstStatus")["measured"])
        # An unmeasured check that is not met is a fail, never hidden.
        leaked = json.loads(json.dumps(fixture["pass"]))
        leaked["boot"]["outsideReceiptsBeforeFirstStatus"] = 3
        self.assertEqual(V.check_counts(V.row_checks("reboot-lockdown", leaked))["failed"], 1)

    def test_the_dry_run_summary_line_and_readme_say_not_measured(self):
        code, report, readme, line = run_dry("REBOOT-LOCKDOWN")
        self.assertEqual(code, 0)
        self.assertTrue(report["expectationsMet"])
        check = next(c for c in report["checks"] if c["name"] == "zeroReceiptsBeforeFirstStatus")
        self.assertEqual((check["met"], check["measured"]), (True, False))
        self.assertEqual(report["checksNotMeasured"], [dict(name="zeroReceiptsBeforeFirstStatus", reason="not measured (empty window)")])
        self.assertEqual(report["checkCounts"]["notMeasured"], 1)
        self.assertIn("REBOOT-LOCKDOWN: PASS (fixture replay only); zeroReceiptsBeforeFirstStatus not measured (empty window); ", line)
        self.assertIn("- zeroReceiptsBeforeFirstStatus: not measured (empty window)", readme)
        code, report, readme, line = run_dry("M5.3-10")
        self.assertEqual((code, report["checksNotMeasured"]), (0, []))
        self.assertNotIn("not measured", line + readme)

    def test_the_live_window_records_the_generators_first_start_as_probed_from(self):
        runner, result = run8.run_row("REBOOT-LOCKDOWN")
        value = window(result)
        build = Path(result["buildRoot"])
        generators = [json.loads(path.read_text()) for path in sorted(build.glob("generator-*.json"))]
        never_open = next(g for g in generators if g.get("role") == "neverOpen")
        self.assertEqual(value["probedFrom"], min(w["start"] for w in never_open["windows"]))
        self.assertTrue(value["measured"])
        self.assertTrue(run8.check(result, "zeroReceiptsBeforeFirstStatus")["measured"])

    def test_a_late_generator_leaves_the_live_window_unmeasured_without_failing_the_row(self):
        _, result = run8.run_row("REBOOT-LOCKDOWN", LateProbeRunner(late=5.0))
        value = window(result)
        self.assertGreater(value["windowSeconds"], 0)
        self.assertLessEqual(value["end"], value["probedFrom"])
        check = run8.check(result, "zeroReceiptsBeforeFirstStatus")
        self.assertEqual((check["met"], check["measured"], check["notMeasured"]), (True, False, V.NOT_MEASURED_UNPROBED))
        self.assertTrue(result["expectationsMet"], "neither a pass nor a fail: the measured checks decide")


class OutsideFlowTimingTests(unittest.TestCase):
    """N3: each outside flow is tagged beforeFirstEnforcing against the daemon's first enforcing status line."""

    BEFORE = "1793294016.000000 IP 192.168.64.98 > 8.8.8.8: ICMP echo request, id 1, seq 0, length 64\n"

    def test_a_flow_before_and_one_after_the_first_enforcing_line(self):
        value = V.unexplained_outside_flow(self.BEFORE + ACK, RULES_8E, first_enforcing_at=1793294018.4)
        tags = {flow["destination"]: flow["beforeFirstEnforcing"] for flow in value["flows"]}
        self.assertEqual(tags, {"8.8.8.8": True, "17.188.182.132": False})
        self.assertEqual((value["unexplainedCount"], value["unexplainedBeforeFirstEnforcingCount"]), (2, 1))
        self.assertEqual(value["firstEnforcingStatusAt"], 1793294018.4)
        unknown = V.unexplained_outside_flow(ACK, RULES_8E)
        self.assertIsNone(unknown["flows"][0]["beforeFirstEnforcing"], "no enforcing line on record: unknown, never false")

    def test_the_live_observation_uses_the_boot_timelines_first_enforcing_line(self):
        _, result = run8.run_row("REBOOT-LOCKDOWN", StrictRunner(wire=self.BEFORE + ACK))
        flow = result["unexplainedOutsideFlow"]
        first = result["bootObservation"]["earlyBootCapture"]["firstEnforcingStatusAt"]
        self.assertEqual(flow["firstEnforcingStatusAt"], first)
        self.assertLess(1793294016.0, first)
        self.assertEqual({f["destination"]: f["beforeFirstEnforcing"] for f in flow["flows"]}, {"8.8.8.8": True, "17.188.182.132": False})
        self.assertNotIn("unexplainedOutsideFlow", [c["name"] for c in result["checks"]])


if __name__ == "__main__":
    unittest.main()
