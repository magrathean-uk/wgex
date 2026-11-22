# SPDX-License-Identifier: MIT
"""Fifth guest-run regressions (L10-L15); fake peer tools, recorded commands and public fixtures only."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import Mock, patch

import test_live_replay as replay
import test_peer_setup as peer
from test_prepare_failures import catalogue_with_dependency

ROOT, LIVE = replay.ROOT, replay.LIVE
GUEST = ROOT / "Tools/lab/tart/guest"
IPERF3 = replay.module("fifth_iperf3", "iperf3-asset.py")
VARIANTS = ["default", "full4", "full4-name", "dual", "dns", "lockdown", "wrong-key"]
D5 = "daemonD5DNSVerification"
STAMP = b"2026-10-28 01:00:00.000 WGEXDaemon: "


def commands(runner):
    return [" ".join(c) for c in runner.commands]


class PeerBootConfigurationTests(unittest.TestCase):
    """L10: peer up persists what wg-quick@wg0 loads at boot, so a peer reboot keeps the fixture keys."""
    setUp = peer.PeerSetupTests.setUp
    run_script = peer.PeerSetupTests.run_script
    commands = peer.PeerSetupTests.commands

    def boot(self):
        return self.root / "wireguard/wg0.conf"

    def test_peer_up_persists_the_runtime_configuration_for_wg_quick(self):
        for variant, address, allowed in [("default", "10.77.0.1/24", "10.77.0.2/32"),
                                          ("dual", "10.77.0.1/24, fd77::1/64", "10.77.0.2/32, fd77::2/128")]:
            result = self.run_script("peer-provision.sh", "up", "https://deb.debian.org/debian", "--adopt", "--variant", variant)
            self.assertEqual(result.returncode, 0, variant)
            boot, runtime = self.boot().read_text(), (self.state / "wg0.conf").read_text()
            self.assertTrue(boot.startswith("[Interface]\nAddress = " + address + "\n"), variant)
            # Same key, port and peer as the runtime syncconf file; wg-quick only adds the address.
            self.assertEqual(boot.split("\n", 2)[2], runtime.split("\n", 1)[1], variant)
            self.assertIn("ListenPort = 51820\n", boot)
            self.assertIn("AllowedIPs = " + allowed + "\n", boot)
            self.assertEqual(stat.S_IMODE(self.boot().stat().st_mode), 0o600, variant)
            self.assertEqual([p.name for p in self.boot().parent.iterdir()], ["wg0.conf"], "no temporary file may remain")
        self.assertIn("wg syncconf wg0", self.commands())

    def test_original_boot_configuration_is_kept_once_before_replacement(self):
        self.boot().write_text("original owner configuration placeholder\n")
        self.boot().chmod(0o600)
        for _ in range(2):
            self.assertEqual(self.run_script("peer-provision.sh", "up", "https://deb.debian.org/debian", "--adopt").returncode, 0)
        backup = self.state / "wg0.conf.pre-wgex-lab"
        self.assertEqual(backup.read_text(), "original owner configuration placeholder\n")
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
        self.assertIn("Address = 10.77.0.1/24\n", self.boot().read_text())

    def test_refused_or_unsafe_setup_never_touches_wg0_or_the_boot_file(self):
        self.boot().write_text("original owner configuration placeholder\n")
        refused = self.run_script("peer-provision.sh", "up", "https://deb.debian.org/debian")
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(self.boot().read_text(), "original owner configuration placeholder\n")
        self.boot().unlink()
        self.boot().parent.rmdir()
        missing = self.run_script("peer-provision.sh", "up", "https://deb.debian.org/debian", "--adopt")
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn(b"wg-quick", missing.stderr)
        self.assertNotIn("syncconf", self.commands(), "the boot directory is checked before wg0 changes")

    def test_dry_run_plan_names_the_boot_configuration(self):
        result = subprocess.run(["bash", str(ROOT / "Tools/lab/peer.sh"), "--dry-run", "up"], capture_output=True, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"wg-quick@wg0", result.stdout)

    def test_boot_mktemp_failure_reports_after_runtime_rekey_and_keeps_original(self):
        self.boot().write_text("original owner configuration placeholder\n")
        fake = self.root / "bin/mktemp"
        fake.write_text("#!/bin/bash\nexit 1\n")
        fake.chmod(0o700)
        result = self.run_script("peer-provision.sh", "up", "https://deb.debian.org/debian", "--adopt")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("wg syncconf wg0", self.commands())
        self.assertIn(b"peer: wg-quick boot configuration temporary file creation failed", result.stderr)
        self.assertEqual(self.boot().read_text(), "original owner configuration placeholder\n")


class PeerKeyCheckTests(unittest.TestCase):
    """L10: prepare compares the live wg0 key digest with the fixture server key before the first connect."""

    def test_peer_digest_script_matches_the_host_digest_without_printing_the_key(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            tools = Path(directory)
            (tools / "sudo").write_text('#!/bin/bash\n[[ "$1" == -n ]] && shift\nexec "$@"\n')
            (tools / "wg").write_text('#!/bin/bash\n[[ "$*" == "show wg0 public-key" ]] || exit 9\ncat "$WGEX_TEST_PUBLIC"\n')
            for name in ["sudo", "wg"]:
                (tools / name).chmod(0o700)
            public = tools / "public"
            public.write_text(replay.SERVER_PUBLIC + "\n")
            env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"], WGEX_TEST_PUBLIC=str(public))
            result = subprocess.run(["bash", "-c", LIVE.PEER_KEY_DIGEST_SCRIPT], env=env, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, "fake peer digest failed")
        self.assertRegex(result.stdout.decode(), r"^[0-9a-f]{12}\n?$")
        self.assertEqual(result.stdout.decode().strip(), replay.FIXTURE_KEY_HASH)
        self.assertTrue(replay.SERVER_PUBLIC.encode() not in result.stdout + result.stderr, "the key must stay on the peer")
        self.assertEqual(LIVE.public_key_digest((ROOT / "Tests/Fixtures/keys/server.pub").read_text()), replay.FIXTURE_KEY_HASH)

    def test_reverted_peer_fails_by_name_before_restore_build_or_connect(self):
        runner = replay.RecordedRunner()
        runner.peer_key_hash = hashlib.sha256(b"pre-fixture peer configuration").hexdigest()[:12]
        runner, result = replay.LiveReplayTests().run_recorded("IPERF3", runner, accepted=False)
        self.assertFalse(result["prepareCompleted"])
        self.assertTrue(any(gap.startswith("peerKeyMismatch:") and "just lab peer up" in gap for gap in result["gaps"]), result["gaps"])
        listing = commands(runner)
        check = next(i for i, c in enumerate(listing) if "wg show wg0 public-key" in c)
        self.assertFalse(any("lab restore" in c or "lab build" in c or "lab install" in c for c in listing))
        self.assertFalse(any("lab profile" in c or "gui click" in c or "gui press" in c for c in listing[check:]), "no import or connect after a mismatch")
        steps = (Path(result["buildRoot"]) / "steps.json").read_text()
        self.assertIn("peerKeyMismatch", steps)
        self.assertTrue(replay.SERVER_PUBLIC not in steps, "only digests are recorded")

    def test_matching_key_is_recorded_as_digests_and_an_unreadable_key_fails(self):
        matched, result = replay.LiveReplayTests().run_recorded("IPERF3")
        listing = commands(matched)
        check = next(i for i, c in enumerate(listing) if "wg show wg0 public-key" in c)
        self.assertLess(check, next(i for i, c in enumerate(listing) if "lab restore ready" in c))
        ledger = json.loads((Path(result["buildRoot"]) / "steps.json").read_text())
        self.assertIn(dict(peerKeyCheck="match", liveKeyHash=replay.FIXTURE_KEY_HASH, fixtureKeyHash=replay.FIXTURE_KEY_HASH), ledger)
        runner = replay.RecordedRunner()
        runner.peer_key_hash, runner.peer_key_code = "", 1
        _, result = replay.LiveReplayTests().run_recorded("IPERF3", runner, accepted=False)
        self.assertTrue(any(gap.startswith("peerKeyMismatch:") for gap in result["gaps"]), result["gaps"])


class ProfileDNSTests(unittest.TestCase):
    """L11: every generated variant carries the tunnel resolver."""
    setUp = peer.PeerSetupTests.setUp
    run_script = peer.PeerSetupTests.run_script

    def test_every_profile_variant_carries_the_tunnel_resolver(self):
        for name in ["client1.key", "client2.key"]:
            (self.state / name).write_text("fixture input omitted\n")
        for variant in VARIANTS:
            result = self.run_script("peer-provision.sh", "profile", variant)
            self.assertEqual(result.returncode, 0, variant)
            self.assertEqual(result.stdout.count(b"DNS = 10.77.0.1\n"), 1, variant)
            self.assertIn(b"DNS = 10.77.0.1\n", result.stdout.split(b"[Peer]")[0], variant + ": DNS belongs to [Interface]")
        accepted = re.search(r'case "\$variant" in ([^)]*)\)', (ROOT / "Tools/lab/profile.sh").read_text())[1]
        self.assertEqual([value.strip() for value in accepted.split("|")], VARIANTS, "the dns variant name keeps working")


class CatalogueDependencyTests(unittest.TestCase):
    """M1-10c: verified D5 is cleared; other dependencies still block live dispatch."""

    def test_every_row_clears_daemon_d5_and_stale_dependencies(self):
        for name, row in replay.ROWS.items():
            dependencies = row.get("dependencies", {})
            self.assertNotIn(D5, dependencies, name)
            self.assertNotIn("importIPv6PolicyChoice", dependencies, name)
            self.assertNotIn("tunnelDNSConnectingPF", dependencies, name)

    def test_fixture_dependency_refuses_live_dispatch_and_still_replays(self):
        runner = replay.module("fifth_dependency", "verdict-run.py")
        for name in ["IPERF3", "DNS-TUNNEL", "M5.1-01"]:
            with catalogue_with_dependency(runner, name), \
                    patch.object(runner, "load_module", side_effect=AssertionError("live transport loaded")), \
                    patch.object(runner, "write_report") as writer:
                self.assertEqual(runner.main([name]), 1)
                self.assertEqual(writer.call_args.args[1]["gaps"], ["Fixture prerequisite remains unmet"], name)
                self.assertFalse(writer.call_args.args[1]["liveAcceptance"])
                self.assertEqual(runner.main([name, "--dry-run"]), 0)
                self.assertTrue(writer.call_args.args[1]["expectationsMet"], name)
                self.assertFalse(writer.call_args.args[1]["liveAcceptance"])


class Iperf3AssetTests(unittest.TestCase):
    """L12: a pinned static client, fetched host-side and verified before it is stored or staged."""

    def test_release_is_pinned_and_stored_outside_the_repository(self):
        self.assertEqual(IPERF3.PIN["url"], "https://github.com/userdocs/iperf3-static/releases/download/3.22/iperf3-arm64-osx-15")
        self.assertRegex(IPERF3.PIN["sha256"], r"^[0-9a-f]{64}$")
        path = IPERF3.asset_path()
        self.assertEqual(path, Path.home() / ".wgex-lab/tools/iperf3-static/3.22/iperf3")
        self.assertNotIn(ROOT, path.parents)

    def test_pin_is_loaded_only_from_toolchain_lock(self):
        with (ROOT / "Toolchain.lock").open("rb") as handle:
            pin = tomllib.load(handle)["iperf3"]
        self.assertEqual(set(pin), {"version", "asset", "url", "sha256"})
        self.assertEqual(IPERF3.PIN, pin)
        self.assertEqual(pin["version"], "3.22")
        self.assertEqual(pin["asset"], "iperf3-arm64-osx-15")
        for path in [ROOT / "Tools/lab/iperf3-asset.py", *Path(__file__).parent.glob("test_*.py")]:
            self.assertNotIn(pin["sha256"], path.read_text(), str(path))

    def test_fetch_verifies_before_publishing_and_is_idempotent(self):
        payload, calls = b"fixture static client, never executed", []

        def opener(url, timeout):
            calls.append((url, timeout))
            return io.BytesIO(payload)
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            target = Path(directory) / "helpers/iperf3"
            with patch.dict(IPERF3.PIN, sha256=hashlib.sha256(b"another build").hexdigest()):
                with self.assertRaises(ValueError):
                    IPERF3.fetch(target, opener=opener)
            self.assertEqual(list(target.parent.iterdir()), [], "a mismatched download is never stored")
            with patch.dict(IPERF3.PIN, sha256=hashlib.sha256(payload).hexdigest()):
                self.assertEqual(IPERF3.fetch(target, opener=opener), target)
                self.assertEqual(IPERF3.verified(target), payload)
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
                IPERF3.fetch(target, opener=opener)
                self.assertEqual([p.name for p in target.parent.iterdir()], ["iperf3"])
            self.assertEqual(len(calls), 2, "a verified asset is never downloaded again")
            self.assertEqual(calls[0][0], IPERF3.PIN["url"])
            self.assertIsNone(IPERF3.verified(target), "anything but the pinned digest is refused")

    def test_asset_size_and_symlink_guards_fail_closed(self):
        payload = b"fixture static client, never executed"
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory, \
                patch.dict(IPERF3.PIN, sha256=hashlib.sha256(payload).hexdigest()):
            target = Path(directory) / "iperf3"
            target.write_bytes(payload)
            link = target.with_name("link")
            link.symlink_to(target)
            self.assertIsNone(IPERF3.verified(link))
            with patch.object(IPERF3, "MAX_BYTES", len(payload) - 1):
                self.assertIsNone(IPERF3.verified(target))
                with self.assertRaises(ValueError):
                    IPERF3.fetch(target, opener=lambda *args, **kwargs: io.BytesIO(payload))
            self.assertEqual(target.read_bytes(), payload, "a refused download preserves the stored copy")
            with patch.object(IPERF3.os, "open", wraps=os.open) as opened:
                self.assertEqual(IPERF3.verified(target), payload)
            self.assertTrue(opened.call_args.args[1] & os.O_NOFOLLOW)
            for unsafe in (link, target):
                if unsafe == target:
                    target.with_name("iperf3.next").symlink_to(link)
                    target.write_bytes(b"corrupt fixture")
                with patch.object(IPERF3.urllib.request, "urlopen", side_effect=AssertionError("network before path guard")):
                    with self.assertRaises(ValueError):
                        IPERF3.fetch(unsafe)

    def test_dry_run_and_path_are_offline(self):
        with patch.object(IPERF3.urllib.request, "urlopen", side_effect=AssertionError("network in dry run")), \
                patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(IPERF3.main(["fetch", "--dry-run"]), 0)
        self.assertIn(IPERF3.PIN["url"], output.getvalue())
        self.assertIn(IPERF3.PIN["sha256"], output.getvalue())
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            with patch.object(IPERF3, "asset_path", return_value=Path(directory) / "iperf3"), \
                    patch("sys.stderr", new_callable=io.StringIO):
                self.assertEqual(IPERF3.main(["path"]), 1)


class Iperf3RowTests(unittest.TestCase):
    """L12: prepare stages the verified client in ~/lab/bin and IPERF3 runs it by absolute path."""

    def test_prepare_stages_the_verified_client_and_the_row_uses_its_absolute_path(self):
        runner, result = replay.LiveReplayTests().run_recorded("IPERF3")
        self.assertEqual(LIVE.GUEST_IPERF3, "/Users/" + LIVE.GUEST_USER + "/lab/bin/iperf3")
        self.assertEqual(runner.guest_files[LIVE.GUEST_IPERF3], replay.FIXTURE_IPERF3)
        listing = commands(runner)
        restore = next(i for i, c in enumerate(listing) if "lab restore ready" in c)
        stage = next(i for i, c in enumerate(listing) if "cat > " + LIVE.GUEST_IPERF3 + ".next" in c)
        self.assertLess(restore, stage)
        client = [c for c in listing if "-c 10.77.0.1" in c]
        self.assertEqual(client, ["just lab ssh -- " + LIVE.GUEST_IPERF3 + " -c 10.77.0.1 -p 5201 -t 10 -J"])
        self.assertTrue(next(check for check in result["checks"] if check["name"] == "iperf3NumberRecorded")["met"])

    def test_missing_or_corrupt_client_fails_the_row_by_name_before_the_peer_server(self):
        for case in ["never fetched", "corrupt guest copy"]:
            runner = replay.RecordedRunner()
            runner.corrupt_guest_copy = case == "corrupt guest copy"
            runner, result = replay.LiveReplayTests().run_recorded("IPERF3", runner, accepted=False, iperf3=case != "never fetched")
            self.assertTrue(result["prepareCompleted"], case)
            self.assertTrue(any(gap.startswith("iperf3Missing:") for gap in result["gaps"]), (case, result["gaps"]))
            self.assertFalse(any("iperf3 -s" in c for c in commands(runner)), case + ": the one-shot server is never started")
            self.assertNotIn(LIVE.GUEST_IPERF3, runner.guest_files, case)


class VerdictAttemptTests(unittest.TestCase):
    """L13: failed attempts keep verdict-<n>.json; verdict.json is the latest."""

    def test_failed_attempts_keep_every_verdict_and_the_last_as_verdict_json(self):
        runner = replay.module("fifth_attempts", "verdict-run.py")
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            row = Path(directory) / "IPERF3"
            for attempt in (1, 2, 3):
                with catalogue_with_dependency(runner, "IPERF3"), \
                        patch.object(runner, "load_module", side_effect=AssertionError("live transport loaded")), \
                        patch("sys.stdout", new_callable=io.StringIO) as output:
                    self.assertEqual(runner.main(["IPERF3", "--report-root", directory]), 1)
                self.assertIn(f"verdict-{attempt}.json", output.getvalue())
                self.assertEqual(sorted(p.name for p in row.glob("verdict-*.json")), [f"verdict-{n}.json" for n in range(1, attempt + 1)])
                latest = (row / "verdict.json").read_bytes()
                self.assertEqual(latest, (row / f"verdict-{attempt}.json").read_bytes())
                self.assertEqual(json.loads(latest)["attempt"], attempt)
            self.assertEqual(json.loads((row / "verdict-1.json").read_text())["attempt"], 1)
            self.assertIn("Attempt: 3", (row / "README.md").read_text())

    def test_replays_keep_a_single_verdict(self):
        runner = replay.module("fifth_replay_attempts", "verdict-run.py")
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            for _ in range(2):
                with patch("sys.stdout", new_callable=io.StringIO):
                    self.assertEqual(runner.main(["M5.1-01", "--dry-run", "--report-root", directory]), 0)
            row = Path(directory) / "M5.1-01"
            self.assertEqual(sorted(p.name for p in row.iterdir()), ["README.md", "verdict.json"])
            self.assertNotIn("attempt", json.loads((row / "verdict.json").read_text()))

    def test_completed_failed_expectations_keep_every_attempt_but_accepted_rows_do_not(self):
        runner = replay.module("fifth_completed_attempts", "verdict-run.py")
        live = Mock()
        live.run.return_value = dict(states=[dict(verdict="unprotected")], rowCompleted=True,
                                     prepareCompleted=True, expectationsMet=False, **replay.PROVENANCE, guestOS=dict(productVersion="26.1", buildVersion="25B12"), installed=replay.PROVENANCE["artefacts"])
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory, \
                patch.object(runner, "load_module", return_value=live), \
                patch.object(runner.PROVENANCE, "ancestor", return_value=True), \
                patch("sys.stdout", new_callable=io.StringIO):
            row = Path(directory) / "IPERF3"
            for attempt in (1, 2):
                self.assertEqual(runner.main(["IPERF3", "--report-root", directory]), 1)
                kept = json.loads((row / f"verdict-{attempt}.json").read_text())
                self.assertTrue(kept["rowCompleted"])
                self.assertFalse(kept["expectationsMet"])
                self.assertEqual((row / "verdict.json").read_bytes(), (row / f"verdict-{attempt}.json").read_bytes())
            first = (row / "verdict-1.json").read_bytes()
            live.run.return_value["expectationsMet"] = True
            self.assertEqual(runner.main(["IPERF3", "--report-root", directory]), 0)
            self.assertTrue(json.loads((row / "verdict.json").read_text())["liveAcceptance"])
            self.assertNotIn("attempt", json.loads((row / "verdict.json").read_text()))
            self.assertEqual(sorted(p.name for p in row.glob("verdict-*.json")), ["verdict-1.json", "verdict-2.json"])
            self.assertEqual((row / "verdict-1.json").read_bytes(), first)


class DeadlineLogTailTests(unittest.TestCase):
    """L13: omitted events collapse, so a deadline capture keeps the L7 status, verifier and pf lines."""

    def tail(self, source):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            result = subprocess.run(["perl", str(GUEST / "daemon-log-tail.pl"), directory], input=source, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, "stream fixture sanitizer failed")
            return (Path(directory) / "daemon-log-tail").read_bytes(), (Path(directory) / "daemon-log-count").read_bytes()

    def test_deadline_capture_keeps_l7_lines_behind_omitted_noise(self):
        state = [b"status: phase=reasserting protection=blocked reason=handshakeTimeout", b"verifier: anchorMissing", b"pf: token acquired"]
        source = b"Filtering the log data\n" + b"".join(STAMP + line + b"\n" for line in state)
        source += b"".join(STAMP + b"handshake bookkeeping payload " + str(n).encode() + b"\n" for n in range(200))
        tail, count = self.tail(source)
        self.assertEqual([line.split(" ", 2)[2] for line in tail.decode().splitlines()],
                         [line.decode() for line in state] + ["<200 events omitted; non-diagnostic content>"])
        self.assertNotIn(b"bookkeeping", tail)
        self.assertEqual(count, b"events=203; rawMessagesOmitted=1\n")
        runner = replay.RecordedRunner()
        runner.connected = runner.blocked = True
        runner.diagnostics_tail = tail
        session = LIVE.Session("fixture", {}, runner=runner)
        with self.assertRaises(LIVE.PollDeadline):
            session.await_status("protected", timeout=1)
        report = json.loads(Path(session.deadlines[-1]["path"]).read_text())
        captured = [line.split(" ", 2)[2] for line in report["daemonLogTail"]]
        for line in state:
            self.assertIn(line.decode(), captured)

    def test_single_and_interleaved_omissions_keep_order_and_the_fifty_line_bound(self):
        source = b"".join(STAMP + line + b"\n" for line in [
            b"noise a", b"status: phase=active protection=unknown reason=dnsUnverified", b"noise b", b"noise c", b"verifier: ok"])
        tail, _ = self.tail(source)
        self.assertEqual([line.split(" ", 2)[2] for line in tail.decode().splitlines()], [
            "<event omitted; non-diagnostic content>", "status: phase=active protection=unknown reason=dnsUnverified",
            "<2 events omitted; non-diagnostic content>", "verifier: ok"])
        source = b"".join(STAMP + b"pf: token acquired\n" + STAMP + b"noise\n" for _ in range(40))
        tail, _ = self.tail(source)
        lines = tail.decode().splitlines()
        self.assertEqual(len(lines), 50)
        self.assertEqual(lines[-1].split(" ", 2)[2], "<event omitted; non-diagnostic content>")


class KeyboardSelectionTests(unittest.TestCase):
    """L14: SwiftUI sidebar rows ignore clicks; select with arrow keys and verify the window title."""

    def test_rows_are_selected_with_arrow_keys_from_the_top_and_verified_by_title(self):
        runner = replay.RecordedRunner()
        runner.auto_select = False
        runner, result = replay.LiveReplayTests().run_recorded("DNS-TUNNEL", runner)
        listing = commands(runner)
        keys = [c.split("gui keys ", 1)[1] for c in listing if "gui keys " in c]
        # M1-10d L17: the pipeline always allows the helper's window fallback.
        self.assertIn("WGEX 1 wgex.main.profiles up 4 fallback", keys)
        self.assertIn("WGEX 1 wgex.main.profiles down 1 fallback", keys)
        self.assertLess(keys.index("WGEX 1 wgex.main.profiles up 4 fallback"), keys.index("WGEX 1 wgex.main.profiles down 1 fallback"))
        self.assertFalse(any(re.search(r"gui click (110|140|170|200) 110$", c) for c in listing))
        ledger = json.loads((Path(result["buildRoot"]) / "steps.json").read_text())
        self.assertTrue(any(entry.get("selectedTitle") == "wgex-lab-dns" for entry in ledger))

    def test_an_already_selected_profile_needs_no_keys(self):
        runner, _ = replay.LiveReplayTests().run_recorded("M5.1-04")
        self.assertFalse(any("gui keys" in c for c in commands(runner)))

    def test_selection_that_leaves_another_title_fails_loudly_before_connect(self):
        runner = replay.RecordedRunner()
        runner.auto_select, runner.keys_work = False, False
        runner, result = replay.LiveReplayTests().run_recorded("M5.1-08", runner, accepted=False)
        self.assertTrue(any(gap.startswith("profileSelectionMismatch:") and "wgex-lab-full4" in gap for gap in result["gaps"]), result["gaps"])
        self.assertFalse(any(replay.actuates(c, 40, 20) for c in commands(runner)), "never connect an unverified selection")

    def test_dump_parsers_and_static_key_helper(self):
        dump = ("AXWindow | name=wgex-lab-dns | value= | desc= | id= | pos=0,0 size=800x600 en=\n"
                "AXStaticText | name=Inactive | desc= | id=wgex.main.tunnel.00000000-0000-4000-8000-000000000002 | pos=10,60 size=20x20 en=true\n"
                "AXStaticText | name=Active | desc= | id=wgex.main.tunnel.00000000-0000-4000-8000-000000000001 | pos=10,30 size=20x20 en=true\n")
        self.assertEqual(LIVE.window_title(dump), "wgex-lab-dns")
        self.assertIsNone(LIVE.window_title(dump.split("\n", 1)[1]))
        self.assertEqual(LIVE.sidebar_rows(dump), ["00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002"])
        self.assertIn('"AXWindow | name="', (GUEST / "ax-dump.applescript").read_text())
        helper = (GUEST / "arrow-keys.applescript").read_text()
        for needle in ["key code", "AXFocused", "item 3 of argv"]:
            self.assertIn(needle, helper)
        self.assertNotIn("do shell script", helper)
        self.assertIn("arrow-keys.applescript", (ROOT / "Tools/lab/tart/gui.sh").read_text())


if __name__ == "__main__":
    unittest.main()
