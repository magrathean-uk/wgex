# SPDX-License-Identifier: MIT
"""Second guest-run regressions; public profile documents and injected commands only."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_live_replay as replay
import test_peer_setup as peer
from test_prepare_failures import catalogue_with_dependency

ROOT, LIVE = replay.ROOT, replay.LIVE
GUEST = ROOT / "Tools/lab/tart/guest"


class SecondLiveTests(unittest.TestCase):
    def test_selection_uses_uuid_when_sidebar_contains_only_status(self):
        runner = replay.RecordedRunner()
        runner.auto_select = False
        runner, _ = replay.LiveReplayTests().run_recorded("IPERF3", runner)
        commands = [" ".join(c) for c in runner.commands]
        resolve = next(i for i, c in enumerate(commands) if "profile-id wgex-lab-default" in c)
        select = next(i for i, c in enumerate(commands) if i > resolve and "gui keys WGEX 1 wgex.main.profiles up" in c)
        self.assertLess(resolve, select)
        self.assertFalse(any("gui click 110 110" in c for c in commands), "row clicks never select (L14)")
        dump = 'AXGroup | name=Inactive | desc= | id=wgex.main.tunnel.00000000-0000-4000-8000-000000000001-extra | pos=1,2 size=20x20 en=true\n'
        with self.assertRaises(ValueError):
            LIVE.control_position(dump, None, {}, "wgex.main.tunnel.00000000-0000-4000-8000-000000000001")
        self.assertEqual(LIVE.sidebar_rows(dump), [], "a suffixed identifier is not a profile row")

    def test_profile_reader_emits_only_the_unique_matching_uuid(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            root = Path(directory)
            identity = "deadbeef-0000-4000-8000-000000000001"
            profile = dict(schemaVersion=2, profile=dict(name="wgex-lab-default", id=identity, unused="must stay in guest"))
            (root / (identity + ".json")).write_text(json.dumps(profile))
            def read():
                return subprocess.run(["bash", "-c", 'source "$1"; profile_id "$2" "$3"', "fixture",
                                       str(GUEST / "profile-id.sh"), directory, "wgex-lab-default"], capture_output=True, check=False)
            result = read()
            self.assertEqual(result.returncode, 0, "public fixture lookup failed")
            self.assertEqual(result.stdout, (identity.upper() + "\n").encode())
            other = "00000000-0000-4000-8000-000000000002"
            profile["profile"]["id"] = other
            (root / (other + ".json")).write_text(json.dumps(profile))
            self.assertNotEqual(read().returncode, 0, "duplicate names must refuse selection")
            (root / (identity + ".json")).unlink()
            profile["profile"]["id"] = "not-a-uuid"
            (root / (other + ".json")).write_text(json.dumps(profile))
            self.assertNotEqual(read().returncode, 0, "invalid identities must refuse selection")

    def test_duplicate_controls_are_in_the_dump_catalogue(self):
        source = (GUEST / "ax-dump.applescript").read_text()
        for role in ["AXRadioGroup", "AXGroup", "AXRadioButton"]:
            self.assertIn('"' + role + '"', source)
        runner = replay.RecordedRunner()
        runner.fixture["controls"].extend([["Duplicate", "wgex.importReview.duplicate", 60, 10], ["Replace", "", 70, 10]])
        runner, _ = replay.LiveReplayTests().run_recorded("IPERF3", runner)
        clicks = replay.actuations(runner.commands)
        self.assertLess(clicks.index(["80", "20"]), clicks.index(["35", "20"]))

    def test_full_tunnel_catalogue_is_explicit_and_fixture_dependency_blocks_dispatch(self):
        row = replay.ROWS["M5.1-01"]
        self.assertEqual(row["profile"], "full4")
        self.assertEqual(row["dependencies"], {})
        self.assertEqual(replay.ROWS["M5.1-02"]["profile"], "dual")
        for name, row in replay.ROWS.items():
            if row.get("profile") in ("full4", "lockdown"):
                # The import choice and D5 are guest-verified; neither remains a dependency.
                self.assertNotIn("importIPv6PolicyChoice", row.get("dependencies", {}), name)
                self.assertNotIn("daemonD5DNSVerification", row.get("dependencies", {}), name)
        runner = replay.module("dependency_report", "verdict-run.py")
        with catalogue_with_dependency(runner, "M5.1-01"), \
                patch.object(runner, "load_module", side_effect=AssertionError("live dependency bypass")), \
                patch.object(runner, "write_report") as writer:
            self.assertEqual(runner.main(["M5.1-01"]), 1)
        result = writer.call_args.args[1]
        self.assertEqual(result["gaps"], ["Fixture prerequisite remains unmet"])
        self.assertEqual(result["dependencies"], {"fixturePrerequisite": "Fixture prerequisite remains unmet"})
        self.assertFalse(result["liveAcceptance"])
        self.assertNotIn(ROOT, writer.call_args.args[0].parents)

    def test_diagnostics_stream_spans_actions_and_restarts_after_boot(self):
        runner, _ = replay.LiveReplayTests().run_recorded("REBOOT-INTENT", accepted=False) # M1-10u fix pass 1: REBOOT-INTENT needs launchd runs == 1; this runner has no boot-observe, so the row is not accepted
        commands = [" ".join(c) for c in runner.commands]
        starts = [i for i, c in enumerate(commands) if c.endswith("verdict-actions.sh diagnostics-start")]
        boot = next(i for i, c in enumerate(commands) if c.endswith("verdict-actions.sh reboot"))
        self.assertEqual(len(starts), 2)
        self.assertLess(starts[0], boot)
        self.assertGreater(starts[1], boot)
        self.assertTrue(any(c.endswith("verdict-actions.sh diagnostics-stop") for c in commands))
        source = (GUEST / "verdict-actions.sh").read_text()
        self.assertIn("/usr/bin/log stream", source)
        # Live observations come from the stream armed before the action. The only `log show` reads are in boot-observe, before any
        # stream can exist (M1-10h): the daemon's status lines since boot (a missing timeline is unknown, never a pass) and, since
        # M1-10v fix pass 1, a count of the app's own log lines (printed as a count only; unknown, never zero, when unread).
        # M1-47: the one other read is power-collect's, after an injected power event: the stream's 50-line tail does not carry the
        # injected-event lines (its filter is a fixed vocabulary), so the two lines and the daemon's status lines come from a bounded
        # `log show` that starts 30 s before the injected sleep and prints only fixed-vocabulary lines (the harness tests run its filters).
        boot_observe = source[source.index("  boot-observe)"):source.index("  anchor-rules)")]
        power_collect = source[source.index("  power-collect)"):source.index("  *)\n    printf 'unknown guest verdict action")]
        self.assertEqual(source.count("/usr/bin/log show"), 3)
        self.assertEqual(boot_observe.count("/usr/bin/log show"), 2)
        self.assertEqual(power_collect.count("/usr/bin/log show"), 1)
        # H6: pin both the epoch-derived start and its use by the one POWER-WAKE log reader.
        self.assertIn('''slept="$(awk '$1 == "sleep" {print int($2); exit}' "$out/times")"''', power_collect)
        self.assertIn('''start="$(date -r "$((slept - 30))" '+%Y-%m-%d %H:%M:%S')"''', power_collect)
        log_show = next(line for line in power_collect.splitlines() if "/usr/bin/log show" in line)
        self.assertIn('--start "$start"', log_show)
        self.assertEqual(power_collect.count("""--predicate 'process == "WGEXDaemon"'"""), 1)
        self.assertEqual(boot_observe.count("""--predicate 'process == "WGEX"'"""), 1)
        self.assertEqual(boot_observe.count("""--predicate 'process == "WGEXDaemon"'"""), 1)
        counter = subprocess.run(["awk", "-f", str(GUEST / "daemon-log-count.awk"), "-v", "output=/dev/stdout"],
                                 input=b"Filtering the log data\naction event\n", capture_output=True, check=True)
        self.assertIn(b"events=1; rawMessagesOmitted=1", counter.stdout)
        self.assertNotIn(b"action event", counter.stdout)

    def test_a_missing_or_late_boot_timeline_is_unknown_never_a_pass(self):
        """M1-10h VERIFY F1: the claim above. Driver polls start at SSH return; only the timeline covers boot to SSH return."""
        fixtures = ROOT / "Tools/lab/tests/fixtures/rows"
        for name in ["reboot-lockdown", "boot-secrets", "reboot-intent"]:
            observation = json.loads((fixtures / (name + ".json")).read_text())["pass"]
            first_poll = observation["boot"]["statusSamples"][0][0]
            for timeline in [[], [[first_poll + 1, "idle", "blocked"]]]:
                with self.subTest(row=name, timeline=timeline):
                    observation["boot"]["timeline"] = timeline
                    report = replay.V.boot_report(observation["boot"])
                    self.assertFalse(report["timelineAvailable"])
                    self.assertEqual(report["gap"], replay.V.BOOT_TIMELINE_GAP)
                    self.assertIsNot(report["daemonDrivenReconnect"], False)
                    if name == "reboot-intent":
                        continue
                    check = next(c for c in replay.V.row_checks(name, observation) if c["name"] == "neverUnprotectedAfterBoot")
                    self.assertFalse(check["met"])
                    self.assertEqual(check["gap"], "boot timeline unavailable (log show returned no status lines)")

    def test_partial_diagnostics_start_is_cleaned_up(self):
        class FailedStreamRunner(replay.RecordedRunner):
            def run(self, argv, **kwargs):
                result = super().run(argv, **kwargs)
                if argv[:4] == ["just", "lab", "ssh", "--"] and argv[-1].endswith("verdict-actions.sh diagnostics-start"):
                    return self.reply(argv, code=1, stderr=b"stream readiness failed\n")
                return result
        runner, result = replay.LiveReplayTests().run_recorded("IPERF3", FailedStreamRunner(), accepted=False)
        self.assertFalse(result["prepareCompleted"])
        self.assertTrue(any(c[-1].endswith("verdict-actions.sh diagnostics-stop") for c in runner.commands))

    def test_guest_markers_are_quoted_for_zsh(self):
        for path in (ROOT / "Tools/lab").rglob("*.sh"):
            self.assertIsNone(re.search(r"\b(?:echo|printf)\s+(?:===|__WGEX_)", path.read_text()), str(path))
        result = subprocess.run(["zsh", "-f", "-c", "printf '%s\\n' '===STATUS' '__WGEX_STATUS__'"], capture_output=True, check=True)
        self.assertEqual(result.stdout, b"===STATUS\n__WGEX_STATUS__\n")


class ProfileVariantTests(unittest.TestCase):
    setUp = peer.PeerSetupTests.setUp
    run_script = peer.PeerSetupTests.run_script
    commands = peer.PeerSetupTests.commands

    def test_profile_variants_need_no_peer_hand_edits(self):
        for name in ["client1.key", "client2.key"]:
            (self.state / name).write_text("fixture input omitted\n")
        for variant, address, routes in [
            ("default", b"Address = 10.77.0.2/24\n", b"AllowedIPs = 10.77.0.0/24\n"),
            ("dns", b"Address = 10.77.0.2/24\n", b"AllowedIPs = 10.77.0.0/24\n"),
            ("full4", b"Address = 10.77.0.2/24\n", b"AllowedIPs = 0.0.0.0/1, 128.0.0.0/1\n"),
            ("full4-name", b"Address = 10.77.0.2/24\n", b"AllowedIPs = 0.0.0.0/1, 128.0.0.0/1\n"),
            ("dual", b"Address = 10.77.0.2/24, fd77::2/64\n", b"AllowedIPs = 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1\n")]:
            result = self.run_script("peer-provision.sh", "profile", variant)
            self.assertEqual(result.returncode, 0, variant)
            self.assertTrue(address in result.stdout and routes in result.stdout, variant + " profile format mismatch")
            if variant == "full4-name":
                self.assertIn(b"Endpoint = 192-168-64-1.sslip.io:51820\n", result.stdout)
        result = self.run_script("peer-provision.sh", "up", "https://deb.debian.org/debian", "--variant", "dual", "--adopt")
        self.assertEqual(result.returncode, 0, "fake dual peer setup failed")
        self.assertIn("ip -6 address replace fd77::1/64 dev wg0", self.commands())

