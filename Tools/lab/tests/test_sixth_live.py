# SPDX-License-Identifier: MIT
"""Sixth guest-run regressions (M1-10d L16-L20); recorded commands and public fixtures only, never a VM."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

import test_live_replay as replay

ROOT, LIVE = replay.ROOT, replay.LIVE
GUEST = ROOT / "Tools/lab/tart/guest"
README = ROOT / "Tools/lab/tart/README.md"
DIAGNOSTICS = ROOT / "Packages/WGEXBackendMac/Sources/WGEXDaemonCore/Controller/DaemonDiagnostics+Operational.swift"
EN_DASH = "–"
# A compact unified-log line as `/usr/bin/log stream --style compact` writes it in the guest.
PREFIX = b"2026-10-29 03:09:30.404 Df WGEXDaemon[321:1a2b] [com.magrathean.WGEXApp.lab:daemon] "


def commands(runner):
    return [" ".join(c) for c in runner.commands]


def selections(result):
    ledger = json.loads((Path(result["buildRoot"]) / "steps.json").read_text())
    return [entry for entry in ledger if "selectionPath" in entry]


class TitleStatusSuffixTests(unittest.TestCase):
    """L16: AppKit titles the main window "<profile> – <status sentence>"; the exact title still selects."""

    def test_exact_and_status_suffix_select_and_other_titles_do_not(self):
        name = "wgex-lab-dns"
        self.assertEqual(LIVE.title_form(name, name), "exact")
        for status in ["Traffic can leave outside the tunnel", "The connection failed. The kill switch is blocking traffic"]:
            self.assertEqual(LIVE.title_form(f"{name} {EN_DASH} {status}", name), "statusSuffix")
        for title in [None, "", "WGEX", f"WGEX {EN_DASH} No tunnels", "wgex-lab-dns-extra", f"wgex-lab-dnsx {EN_DASH} Connected",
                      f"wgex-lab-dns {EN_DASH} ", f"wgex-lab-dns{EN_DASH}Connected", "wgex-lab-dns - Connected",
                      f"wgex-lab-full4 {EN_DASH} wgex-lab-dns", f"x wgex-lab-dns {EN_DASH} Connected"]:
            self.assertIsNone(LIVE.title_form(title, name), title)
        self.assertEqual(LIVE.TITLE_STATUS_SEPARATOR, f" {EN_DASH} ")

    def test_status_suffix_title_selects_after_arrow_keys(self):
        runner = replay.RecordedRunner()
        runner.auto_select, runner.title_status = False, "Traffic can leave outside the tunnel"
        runner, result = replay.LiveReplayTests().run_recorded("DNS-TUNNEL", runner)
        self.assertTrue(any("gui keys WGEX 1 wgex.main.profiles" in c for c in commands(runner)))
        entry = selections(result)[-1]
        self.assertEqual((entry["selectedTitle"], entry["titleForm"]), ("wgex-lab-dns", "statusSuffix"))
        self.assertNotIn("Traffic", json.dumps(selections(result)), "the status sentence is not copied into the ledger")

    def test_already_selected_profile_with_status_suffix_needs_no_keys(self):
        runner = replay.RecordedRunner()
        runner.title_status = "Connected, last handshake 1 min ago"
        runner, result = replay.LiveReplayTests().run_recorded("M5.1-04", runner)
        self.assertFalse(any("gui keys" in c for c in commands(runner)))
        self.assertTrue(all(entry["selectionPath"] == "none" for entry in selections(result)))

    def test_another_profiles_status_title_fails_before_connect(self):
        runner = replay.RecordedRunner()
        runner.auto_select, runner.keys_work, runner.title_status = False, False, "Inactive"
        runner, result = replay.LiveReplayTests().run_recorded("M5.1-08", runner, accepted=False)
        self.assertTrue(any(gap.startswith("profileSelectionMismatch:") and "wgex-lab-full4" in gap for gap in result["gaps"]), result["gaps"])
        self.assertFalse(any(replay.actuates(c, 40, 20) for c in commands(runner)), "never connect an unverified selection")


class WindowKeyboardPathTests(unittest.TestCase):
    """L17: without a wgex.main.profiles element the helper takes the profile list found from the window."""

    def test_missing_profiles_identifier_selects_through_the_window_path(self):
        runner = replay.RecordedRunner()
        runner.auto_select, runner.profiles_identifier = False, False
        runner, result = replay.LiveReplayTests().run_recorded("DNS-TUNNEL", runner)
        keys = [c.split("gui keys ", 1)[1] for c in commands(runner) if "gui keys " in c]
        self.assertEqual(keys, ["WGEX 1 wgex.main.profiles up 4 fallback", "WGEX 1 wgex.main.profiles down 1 fallback"])
        entry = selections(result)[-1]
        self.assertEqual((entry["selectionPath"], entry["selectedTitle"], entry["arrowKeys"]), ("window", "wgex-lab-dns", ["up 4", "down 1"]))

    def test_identifier_path_is_reported_when_the_element_exists(self):
        runner = replay.RecordedRunner()
        runner.auto_select = False
        runner, result = replay.LiveReplayTests().run_recorded("DNS-TUNNEL", runner)
        self.assertEqual(selections(result)[-1]["selectionPath"], "identifier")

    def test_a_failed_window_path_names_the_path_and_never_connects(self):
        runner = replay.RecordedRunner()
        runner.auto_select, runner.keys_work, runner.profiles_identifier = False, False, False
        runner, result = replay.LiveReplayTests().run_recorded("M5.1-08", runner, accepted=False)
        gap = next(gap for gap in result["gaps"] if gap.startswith("profileSelectionMismatch:"))
        self.assertIn("(path window)", gap)
        self.assertFalse(any(replay.actuates(c, 40, 20) for c in commands(runner)))

    def test_helper_report_parser_accepts_only_the_two_fixed_paths(self):
        self.assertEqual(LIVE.keys_path(b"path=identifier\n"), "identifier")
        self.assertEqual(LIVE.keys_path(b"path=window\n"), "window")
        for output in [b"", b"path=other\n", b"path=window\nextra\n", b"window", b"\xff"]:
            self.assertEqual(LIVE.keys_path(output), "unknown")

    def test_helper_falls_back_only_on_request_and_reports_the_path(self):
        helper = (GUEST / "arrow-keys.applescript").read_text()
        for needle in ['item 6 of argv is "fallback"', 'error "identifier not found" number 3', '"AXParent"',
                       'starts with "wgex.main.tunnel."', 'set pathName to "window"', 'return "path=" & pathName']:
            self.assertIn(needle, helper)
        self.assertLess(helper.index('if not allowFallback then error "identifier not found" number 3'), helper.index('set pathName to "window"'))
        self.assertNotIn("do shell script", helper)
        gui = (ROOT / "Tools/lab/tart/gui.sh").read_text()
        self.assertIn("^path=(identifier|window)$", gui, "only the fixed path report leaves the guest helper")


class SnapshotAndManualPathDocumentationTests(unittest.TestCase):
    """L18: ready snapshots follow completed onboarding; the manual app path is the documented fallback."""

    def test_readme_states_the_ready_snapshot_prerequisite_and_the_authorizationdb_position(self):
        text = " ".join(README.read_text().split())
        for needle in ["A `ready` snapshot", "only after the app's first-run onboarding has completed",
                       "seven presses of `wgex.onboarding.continue`", '"Open WGEX"', "wgex.main.sidebarImport",
                       "authorizationdb pre-allow is therefore not needed", "it is not accepted any more",
                       "`adminRightRequired`", "Do not write authorizationdb rows in the guest."]:
            self.assertIn(needle, text)
        snapshot = (ROOT / "Tools/lab/tart/snapshot.sh").read_text()
        self.assertIn("ready snapshot only after onboarding has completed (7 x Continue, then Open WGEX)", snapshot)

    def test_readme_documents_the_manual_app_path(self):
        text = README.read_text()
        for needle in ['just lab gui run open -a WGEX "/Users/$guest_user/lab/wgex-lab-dns.conf"', "wgex.importReview.importAndConnect",
                       '("Import and connect")', "wgex.main.action desc=Disconnect", "Disconnect or Reconnect at the dumped centre",
                       "Helpers/wgex down"]:
            self.assertIn(needle, text)


class GuestLogCommandTests(unittest.TestCase):
    """L19: the guest login shell is zsh, where `log` is a builtin; guest log commands use /usr/bin/log."""

    # A command, not prose: followed by an option or closing a code span.
    BARE = re.compile(r"(?<![/\w.-])log (?:show|stream|collect)(?= +-|`)")

    def test_lab_scripts_and_docs_never_run_a_bare_log_command(self):
        sources = [README] + [path for path in sorted((ROOT / "Tools/lab").rglob("*"))
                              if path.suffix in {".sh", ".py", ".pl", ".awk", ".applescript", ".md"}
                              and "tests" not in path.relative_to(ROOT / "Tools/lab").parts and "__pycache__" not in path.parts]
        offenders = [f"{path.relative_to(ROOT)}:{number}" for path in sources
                     for number, line in enumerate(path.read_text(errors="replace").splitlines(), 1) if self.BARE.search(line)]
        self.assertEqual(offenders, [])
        self.assertIn("/usr/bin/log stream --level debug", (GUEST / "verdict-actions.sh").read_text())
        readme = README.read_text()
        self.assertIn("`/usr/bin/log stream`", readme)
        self.assertIn("/usr/bin/log show --last 5m", readme)

    def test_the_bare_command_pattern_matches_commands_only(self):
        for line in ["prefer `log stream` during", "log show --last 5m", "ssh -- log stream --level debug"]:
            self.assertTrue(self.BARE.search(line), line)
        for line in ["`/usr/bin/log stream`", "/usr/bin/log show --last 5m", "daemon log stream failed to start", "log show often misses"]:
            self.assertFalse(self.BARE.search(line), line)


class OwnershipAllowlistTests(unittest.TestCase):
    """L20: the guest log tail keeps the Lab-only ownership verdicts by bounded, end-anchored shapes."""

    ACCEPTED = [
        "ownership: canary adopted", "ownership: canary replaced", "ownership: foreign route", "ownership: tunnel descriptor missing",
        "ownership: tunnel identity drift", "ownership: route interface drift", "ownership: engine interface missing",
        "ownership: interface utun4 index 12->12 check descriptor", "ownership: interface utun9 index 9->10 check index",
        "ownership: interface utun9 index 9->9 check address", "ownership: interface en0 index 4->4 check link address",
        "ownership: interface en0 index 6->absent",
    ]
    REJECTED = [
        "ownership: free text a peer could have chosen", "ownership: canary adopted key=AAAA", "ownership: canary adopted ",
        "ownership: interface utun4 index 12->12 change 1s", "ownership: interface utun4 index 12->12",
        "ownership: interface utun4 index 12->12 check absent", "ownership: interface UTUN4 index 12->12 check index",
        "ownership: interface utun4 index 123456->1 check index", "ownership: interface utun1234 index 1->1 check index",
        "ownership: interface utun4 index 12->12 check descriptor 10.77.0.2", "ownership:canary adopted",
    ]

    def tail(self, lines):
        source = b"Filtering the log data\n" + b"".join(PREFIX + line.encode() + b"\n" for line in lines)
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            result = subprocess.run(["perl", str(GUEST / "daemon-log-tail.pl"), directory], input=source, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, "stream fixture sanitizer failed")
            return [line.split(" ", 2)[2] for line in (Path(directory) / "daemon-log-tail").read_text().splitlines()]

    def test_each_accepted_shape_is_kept_verbatim(self):
        for line in self.ACCEPTED:
            self.assertEqual(self.tail([line]), [line], line)

    def test_free_text_and_unbounded_shapes_are_omitted(self):
        for line in self.REJECTED:
            self.assertEqual(self.tail([line]), ["<event omitted; non-diagnostic content>"], line)
        tail = self.tail(self.REJECTED + ["ownership: canary adopted"])
        self.assertEqual(tail, [f"<{len(self.REJECTED)} events omitted; non-diagnostic content>", "ownership: canary adopted"])

    def test_every_label_the_lab_daemon_emits_is_kept(self):
        source = DIAGNOSTICS.read_text()
        events = re.findall(r'\.\w+: "([a-z ]+)"', source[source.index("ownershipLabels"):source.index("public static func interface")])
        checks = re.findall(r'\.\w+: "([a-z ]+)"', source[source.index("breachLabels"):source.index("private static func emit")])
        self.assertGreaterEqual(len(events), 16)
        self.assertEqual(sorted(checks), ["absent", "address", "descriptor", "index", "link address"])
        lines = [f"ownership: {event}" for event in events] + ["ownership: unknown"]
        lines += [f"ownership: interface utun4 index 7->7 check {check}" for check in checks if check != "absent"]
        self.assertEqual(self.tail(lines), lines)


if __name__ == "__main__":
    unittest.main()
