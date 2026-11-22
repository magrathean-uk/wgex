# SPDX-License-Identifier: MIT
"""M03-T03: the update bundle row (M5.3-07) and the XPC identity corpus row (RT-17).

Builders run as dry runs or compile only, guest scripts stop at their host guard, drivers run on stubbed sessions. No VM,
Xcode build, XPC connection, signing identity or keychain is used.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[3]
LAB = ROOT / "Tools/lab"


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


V = module("m03t03_verdict", LAB / "verdict.py")
RUN = module("m03t03_run", LAB / "verdict-run.py")
LIVE = module("m03t03_live", LAB / "verdict-live.py")
C = module("m03t03_checks", LAB / "check-verdicts.py")
UPDATE = module("m03t03_update", LAB / "update/update.py")
CATALOGUE = json.loads((LAB / "rows.json").read_text())["rows"]
TABLE = json.loads((LAB / "leak-expectations.json").read_text())
ROWS = {"M5.3-07": "update", "RT-17": "rt17"}
BASE = dict(app="b" * 40, daemon="c" * 40, cli="d" * 40)
NEW = dict(app="a" * 40, daemon="e" * 40, cli="f" * 40)


def fixture(kind):
    return json.loads((LAB / "tests/fixtures/rows" / (kind + ".json")).read_text())


def inputs(version="1", override=""):
    return dict(configuration="Lab", compilationConditions=C.CONDITIONS, bundleVersionOverride=override,
                targets={target: dict(CONFIGURATION="Lab", CODE_SIGN_IDENTITY="lab", EXPANDED_CODE_SIGN_IDENTITY="-",
                                      CURRENT_PROJECT_VERSION=version, SWIFT_ACTIVE_COMPILATION_CONDITIONS="DEBUG WGEX_LAB_BUILD")
                         for target in C.BUILD_TARGETS})


def update_block():
    return dict(sourceCommit="5" * 40, buildConfiguration="Lab", buildInputs=inputs("2", "2"), artefacts=dict(NEW),
                installed=dict(NEW), bundleVersion="2")


def record(row="M5.3-07", update=True):
    value = dict(row=row, guestOS=dict(productVersion="26.1", buildVersion="25B12"), sourceCommit="5" * 40,
                 buildConfiguration="Lab", buildInputs=inputs(), artefacts=dict(BASE), installed=dict(BASE),
                 expectationsMet=True, liveAcceptance=True, rowCompleted=True)
    if update:
        value["update"] = update_block()
    return value


def update_errors(value, **kw):
    with patch.object(C, "ancestor", return_value=True):
        return [error for error in C.provenance_errors(value, "26", **kw) if error.startswith(("update", "product-unchanged"))]


class CatalogueTests(unittest.TestCase):
    def test_both_rows_drop_the_gap_and_replay_with_every_expectation_covered_by_a_rejecting_fixture(self):
        for name, kind in ROWS.items():
            row = CATALOGUE[name]
            with self.subTest(row=name), patch.object(RUN, "load_module", side_effect=AssertionError("live import")):
                self.assertNotIn("gap", row)
                self.assertEqual((row["action"], row["checks"], row["profile"], row["state"]), (kind, kind, "full4", "protected"))
                result = RUN.replay(row, TABLE, {})
                self.assertTrue(result["expectationsMet"], result)
                self.assertFalse(result["failingFixturesUncovered"])
                self.assertTrue(result["failingFixtures"])
                self.assertTrue(all(case["rejected"] for case in result["failingFixtures"]))
                self.assertLess((LAB / "tests/fixtures/rows" / (kind + ".json")).stat().st_size, 50000)
                self.assertFalse(all(check["met"] for check in V.row_checks(kind, {})))

    def test_neither_row_holds_a_product_dependency(self):
        update = CATALOGUE["M5.3-07"]
        self.assertEqual(update["dependencies"], {})  # M03-T12 delivered the Lab-only update identity (DEC-013)
        limits = " ".join(update["limitations"])
        for phrase in ("DEC-007", "updateApprovalMissing", "never enters a password", "this row only"):
            self.assertIn(phrase, limits)
        self.assertEqual(CATALOGUE["RT-17"]["dependencies"], {})
        self.assertIn("host keychain", " ".join(CATALOGUE["RT-17"]["limitations"]))

    def test_catalogue_copy_is_byte_identical_and_the_catalogue_check_passes(self):
        result = subprocess.run([os.sys.executable, "-I", "-B", str(LAB / "check-verdicts.py"), "--catalogue-only", "M5.3-07", "RT-17"],
                                capture_output=True, timeout=60, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_live_dispatch_of_the_update_row_reaches_the_live_driver(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory, \
                patch.object(RUN, "load_module") as loader, \
                patch.object(RUN.HARNESS, "host_load", return_value={}), patch.object(RUN.HARNESS, "warning", return_value=None):
            loader.return_value.run.return_value = dict(expectationsMet=False)
            code = RUN.main(["M5.3-07", "--report-root", directory])
            value = json.loads((Path(directory) / "M5.3-07/verdict.json").read_text())
        loader.assert_called_once()
        self.assertEqual(loader.return_value.run.call_args.args[:2], ("M5.3-07", CATALOGUE["M5.3-07"]))
        self.assertEqual(code, 1)
        self.assertFalse(value["liveAcceptance"])
        self.assertEqual(value["dependencies"], {})
        self.assertFalse(any("prepareForUpdate" in gap for gap in value["gaps"]))


class UpdateBuilderTests(unittest.TestCase):
    def test_version_is_above_the_base_and_the_bundle_has_its_own_build_root(self):
        base = UPDATE.base_version(ROOT)
        self.assertEqual(UPDATE.next_version(ROOT), base + 1)
        self.assertEqual(UPDATE.next_version(ROOT, str(base + 4)), base + 4)
        for requested in (str(base), "0", "-1", "abc"):
            with self.assertRaises(ValueError):
                UPDATE.next_version(ROOT, requested)
        app = UPDATE.app_path(ROOT, dict(WGEX_BUILD_ROOT="/builds"))
        self.assertEqual(app, Path("/builds") / ROOT.name / "lab-update" / ROOT.name / "derived-data/Build/Products/Lab/WGEX.app")
        self.assertEqual(UPDATE.receipt_version(inputs("3")), 3)
        self.assertIsNone(UPDATE.receipt_version(dict(targets=dict(a=dict(CURRENT_PROJECT_VERSION="1"), b=dict(CURRENT_PROJECT_VERSION="2")))))

    def test_dry_run_routes_a_higher_version_through_the_lab_build_script(self):
        base = UPDATE.base_version(ROOT)
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            env = {key: value for key, value in os.environ.items() if not key.startswith("WGEX_")}
            env["WGEX_BUILD_ROOT"] = directory
            result = subprocess.run(["bash", str(LAB / "update/build.sh"), "--dry-run"], env=env, capture_output=True, timeout=120, check=False)
            text = result.stdout.decode() + result.stderr.decode()
            self.assertEqual(result.returncode, 0, text)
            expected = Path(directory) / ROOT.name / "lab-update" / ROOT.name / "derived-data"
            self.assertIn("-derivedDataPath " + str(expected), text)
            self.assertIn("CURRENT_PROJECT_VERSION=" + str(base + 1), text)
            self.assertIn("-configuration Lab", text)
            self.assertTrue(result.stdout.decode().strip().endswith(f"WGEX.app version={base + 1}"))
            self.assertFalse(expected.exists(), "a dry run builds nothing")
            env["WGEX_LAB_UPDATE_VERSION"] = str(base)
            refused = subprocess.run(["bash", str(LAB / "update/build.sh"), "--dry-run"], env=env, capture_output=True, timeout=60, check=False)
            self.assertNotEqual(refused.returncode, 0)
            self.assertNotIn(b"xcodebuild", refused.stderr)


class CorpusClientTests(unittest.TestCase):
    def test_client_compiles_warning_free_and_refuses_outside_a_lab_vm_before_any_xpc(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            client = Path(directory) / "client"
            built = subprocess.run(["bash", str(LAB / "corpus/build.sh"), str(client)], capture_output=True, timeout=120, check=False)
            self.assertEqual(built.returncode, 0, built.stderr)
            archs = subprocess.run(["lipo", "-archs", str(client)], capture_output=True, timeout=30, check=True).stdout.split()
            self.assertEqual(sorted(archs), [b"arm64", b"x86_64"], "the guest strips the x86_64 slice as the unsigned client")
            thin = subprocess.run(["lipo", "-archs", str(client) + "-x86_64"], capture_output=True, timeout=30, check=True).stdout.split()
            self.assertEqual(thin, [b"x86_64"], "the host cuts the unsigned slice: the guest has no developer tools, so no lipo")
            # A service name no WGEX build uses: even a broken guard could not reach a WGEX daemon.
            for mode in ("current", "old-protocol", "older-build", "probe-user"):
                result = subprocess.run([str(client), mode, "com.example.wgex-lab-test.none"], capture_output=True, timeout=10, check=False)
                self.assertEqual(result.returncode, 2, mode)
                self.assertIn(b"lab VM required", result.stderr)
                self.assertEqual(result.stdout, b"")


class CorpusGuestToolsTests(unittest.TestCase):
    def test_guest_corpus_script_uses_no_developer_tool(self):
        text = (LAB / "corpus/guest-corpus.sh").read_text()
        for tool in ("lipo", "xcrun", "clang", "otool", "strip "):
            self.assertNotRegex(text, r"(?m)^[^#\n]*\b" + tool.strip() + r"\b ", tool)
        self.assertIn("wgex-corpus-client-x86_64", text)


class CorpusGuestRosettaTests(unittest.TestCase):
    def test_the_driver_installs_rosetta_after_the_restore_and_before_any_connect(self):
        text = (LAB / "verdict-live.py").read_text()
        prepare = text[text.index("    def prepare(self, profile, connect=True):"):text.index("    def check_peer_key")]
        self.assertLess(prepare.index("self.await_guest()"), prepare.index("self.ensure_rosetta()"))
        self.assertLess(prepare.index("self.ensure_rosetta()"), prepare.index("self.import_profile("))
        self.assertIn('session.rosetta = action == "rt17"', text)
        self.assertNotIn("softwareupdate", (LAB / "corpus/guest-corpus.sh").read_text(), "the protected window cuts the guest off")

    def test_the_lifecycle_counter_ignores_a_status_line_that_repeats_the_connected_state_only(self):
        text = (LAB / "corpus/guest-corpus.sh").read_text()
        start = text.index("lifecycle_since() {")
        program = re.search(r"perl -e '(.*?)' \"\$1\"", text[start:], re.S).group(1)
        stamp = "2026-11-09 01:02:03.000"
        lines = [
            f"{stamp} Df WGEXDaemon[301:1] [x:daemon] status: phase=active protection=protected reason=none",
            f"{stamp} Df WGEXDaemon[301:1] [x:daemon] status: phase=idle protection=unprotected reason=none",
            f"{stamp} Df WGEXDaemon[301:1] [x:daemon] status: phase=active protection=unknown reason=none",
            f"{stamp} Df WGEXDaemon[301:1] [x:daemon] pf: token released",
            f"{stamp} Df WGEXDaemon[301:1] [x:daemon] recovery: anchor kept",
            f"{stamp} Df WGEXDaemon[301:1] [x:daemon] Daemon listening; recovering",
            "2026-11-09 01:02:02.999 Df WGEXDaemon[301:1] [x:daemon] pf: token released",
        ]
        count = lambda body: subprocess.run(["perl", "-e", program, "2026-11-09 01:02:03.000"], input=body.encode(), capture_output=True, check=True).stdout
        self.assertEqual(count(lines[0] + "\n"), b"0", "the connected state repeated")
        self.assertEqual(count("\n".join(lines) + "\n"), b"5", "idle, unknown, pf, recovery and recovery start; the earlier line is skipped")


class GuardTests(unittest.TestCase):
    def test_guest_scripts_refuse_on_the_host_before_any_command(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            root = Path(directory)
            stage, tools, log = root / "stage", root / "bin", root / "calls"
            stage.mkdir()
            tools.mkdir()
            for script in (LAB / "update/guest-update.sh", LAB / "corpus/guest-corpus.sh", LAB / "tart/guest/guard.sh"):
                (stage / script.name).write_bytes(script.read_bytes())
            for name, reply in (("sw_vers", "27.0"), ("sysctl", "0")):
                (tools / name).write_text('#!/bin/sh\nprintf "%s\\n" "' + reply + '"\n')
                (tools / name).chmod(0o700)
            for name in ("codesign", "security", "openssl", "launchctl", "sudo", "pfctl", "ditto", "plutil", "wgex", "pgrep"):
                (tools / name).write_text('#!/bin/sh\nprintf called >> "$CALLS"\nexit 97\n')
                (tools / name).chmod(0o700)
            cases = [("guest-update.sh", action) for action in ("unpack", "replace", "retrust", "running", "stamp", "daemon-log x", "daemon-log-stamped x", "cleanup")]
            cases += [("guest-corpus.sh", action) for action in ("prepare", "attempt genuine", "attempt ad-hoc", "impostor", "control", "cleanup")]
            for script, action in cases:
                with self.subTest(script=script, action=action):
                    result = subprocess.run(["bash", str(stage / script), *action.split()],
                                            env=dict(os.environ, PATH=str(tools) + ":/usr/bin:/bin", CALLS=str(log)),
                                            capture_output=True, timeout=10, check=False)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(b"VM required", result.stderr)
                    self.assertFalse(log.exists(), "a guest command ran before the host guard")

    def test_corpus_identities_stay_in_the_guest_stage(self):
        text = (LAB / "corpus/guest-corpus.sh").read_text()
        self.assertIn('keychain="$corpus/wrong-team.keychain-db"', text)
        self.assertIn("security list-keychains -d user -s ${saved[@]+", text, "the guest's own search list is put back")
        self.assertIn("security delete-keychain", text)
        self.assertNotIn("login.keychain", text)
        self.assertNotIn("/Library/Keychains/System.keychain", text)


SNAPSHOT = dict(daemonPid=301, phase="active", protection="protected", intentDigest="0123456789ab", ownerTokenHash="111111111111",
                referenceCount=1)
XPC_LINES = [
    'Filtering the log data using "eventMessage CONTAINS \\"code signing requirement\\""',
    "Timestamp               Ty Process[PID:TID]",
    "2026-11-09 01:02:03.456 E  WGEXDaemon[301:1a2b] [com.apple.xpc:connection] [0x7f8a] Dropping check-in message due to code "
    "signing requirement: <private>",
    "2026-11-09 01:02:03.461 E  WGEXDaemon[301:1a2b] [com.apple.xpc:connection] [0x7f8a] Received message forbidden due to code "
    "signing requirement: <private>",
    "2026-11-09 01:02:03.470 Df wgex[5555:9c1] [com.apple.Foundation:xpc] Connection to 'com.magrathean.WGEXApp.dev.daemon' "
    "failed peer code signing requirement",
    "2026-11-09 01:02:03.480 Df WGEXDaemon[301:1a2b] [com.apple.xpc:connection] [0x7f8a] Code-signing requirement (<private>) set on connection",
    "2026-11-09 01:02:03.490 E  WGEXDaemon[301:1a2b] [com.magrathean.WGEXApp.dev:lab-code-identity] Lab XPC client refused: its code "
    "matches neither the installed app nor the installed CLI",
    "2026-11-09 01:02:03.495 E  wgex[5555:9c1] [com.magrathean.WGEXApp.dev:lab-code-identity] Lab XPC refused: executable is outside "
    "the expected bundle layout",
    "WGEXDaemon[301:1a2b] Dropping check-in message due to code signing requirement (no timestamp: not a stream line)",
]


def attempt(*args, data=b""):
    return subprocess.run(["perl", str(LAB / "corpus/attempt.pl"), *args], input=data, capture_output=True, timeout=30, check=False)


class CorpusEvidenceTests(unittest.TestCase):
    """REV-M03-T03 round 1 item 1: only the daemon's own refusal passes RT-17."""

    def observation(self):
        return copy.deepcopy(fixture("rt17")["pass"])

    def checks(self, value):
        return {check["name"]: check["met"] for check in V.CORPUS.rt17_checks(value)}

    def test_the_recorded_pass_carries_the_daemons_refusal_for_every_client(self):
        value = self.observation()
        self.assertTrue(all(self.checks(value).values()), self.checks(value))
        self.assertTrue(all(item["daemonRefusals"] >= 1 and item["clientRefusals"] == 0 for item in value["clients"]))

    def test_an_unrelated_client_failure_can_never_pass_as_a_refusal(self):
        # 127 command not found, 126 not executable, 134 loader abort, 137 kernel kill, 142 the attempt's alarm, 2 the lab
        # guard or the CLI's usage, 64 the corpus client's usage, 255 a failed exec. Each fails even with the daemon's
        # refusal line, unchanged state and no lifecycle line in the same interval.
        for index, item in enumerate(self.observation()["clients"]):
            for code in (127, 126, 134, 137, 142, 2, 64, 255):
                for report in (None, {}, item["report"]):
                    with self.subTest(client=item["name"], code=code, report=report):
                        value = self.observation()
                        value["clients"][index].update(exitCode=code, report=report)
                        self.assertFalse(self.checks(value)["refused:" + item["name"]])
                        self.assertTrue(self.checks(value)["layoutServed"])

    def test_a_client_refusal_of_its_own_or_a_foreign_layout_daemon_cannot_pass(self):
        value = self.observation()
        for item in value["clients"]:
            item["clientRefusals"] = 1
        self.assertFalse(any(met for name, met in self.checks(value).items() if name.startswith("refused:")))
        value = self.observation()
        value["genuine"]["layoutDaemon"] = "9" * 40
        checks = self.checks(value)
        self.assertFalse(checks["layoutServed"])
        for name in V.CORPUS.LAYOUT_CLIENTS:
            self.assertFalse(checks["refused:" + name], name)
        for name in V.CORPUS.CLIENT_MODES:
            self.assertTrue(checks["refused:" + name], "the corpus client sets no requirement on the daemon")

    def test_the_attempt_helper_counts_only_libxpc_refusal_lines_by_pid(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            out, ready = Path(directory) / "refusals", Path(directory) / "ready"
            result = attempt("watch", str(out), str(ready), data="\n".join(XPC_LINES).encode() + b"\n")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(out.read_text(), "301 3\n5555 1\n", "the Lab admission line counts for the daemon, the client's own layout line does not")
            self.assertTrue(ready.exists())
            self.assertEqual(sorted(path.name for path in Path(directory).iterdir()), ["ready", "refusals"], "no log line is kept")

    def test_the_attempt_helper_keeps_fixed_report_fields_and_none_for_a_silent_client(self):
        state = json.dumps(SNAPSHOT)
        silent = json.loads(attempt("report", "ad-hoc", "127", "", state, state, "0", "301 2", "5555").stdout)
        self.assertEqual((silent["exitCode"], silent["report"], silent["daemonRefusals"], silent["clientRefusals"]), (127, None, 2, 0))
        refused = json.loads(attempt("report", "ad-hoc", "1", json.dumps(dict(error="daemonUnavailable", detail="free text")),
                                     state, state, "0", "301 1\n5555 0", "5555").stdout)
        self.assertEqual(refused["report"], dict(error="daemonUnavailable"))
        corpus = json.loads(attempt("report", "unsigned", "0", json.dumps(dict(mode="current", outcome="refused", errorCode=4099, impostor=False)),
                                    state, state, "0", "301 1", "77").stdout)
        self.assertEqual(corpus["report"], dict(mode="current", outcome="refused", errorCode=4099, impostor=False))
        for name, item, met in (("ad-hoc", silent, False), ("ad-hoc", refused, True), ("unsigned", corpus, True)):
            with self.subTest(name=name, met=met):
                value = self.observation()
                index = [client["name"] for client in value["clients"]].index(name)
                value["clients"][index].update(item)
                self.assertEqual(self.checks(value)["refused:" + name], met)
        self.assertNotEqual(attempt("report", "ad-hoc", "1", "", state, state, "0", "", "0").returncode, 0)
        self.assertNotEqual(attempt("bogus").returncode, 0)


class CheckVerdictsUpdateTests(unittest.TestCase):
    def test_a_valid_update_block_passes_and_the_row_constants_agree(self):
        self.assertEqual(update_errors(record()), [])
        self.assertEqual(C.UPDATE_ROW, LIVE.UPDATE_ROW)
        self.assertEqual(C.UPDATE_ROW, "M5.3-07")

    def test_each_update_defect_is_rejected(self):
        def edited(path, value):
            item = record()
            target = item["update"]
            for key in path[:-1]:
                target = target[key]
            if value is KeyError:
                del target[path[-1]]
            else:
                target[path[-1]] = value
            return item

        cases = [
            ((["buildConfiguration"], "Release"), "buildConfiguration"),
            ((["sourceCommit"], "6" * 40), "sourceCommit"),
            ((["installed", "daemon"], "9" * 40), "installed differs"),
            ((["artefacts", "daemon"], "short"), "artefacts missing"),
            ((["artefacts", "cli"], BASE["cli"]), "differ from the base"),
            ((["bundleVersion"], "1"), "installed bundle version"),
            ((["buildInputs", "bundleVersionOverride"], ""), "override above"),
            ((["buildInputs", "targets", "WGEXMac", "SWIFT_ACTIVE_COMPILATION_CONDITIONS"], "DEBUG WGEX_LAB_BUILD EXTRA"), "beyond the bundle version"),
            ((["buildInputs", "targets", "WGEXDaemon", "CODE_SIGN_IDENTITY"], "own-mac"), "beyond the bundle version"),
            ((["buildInputs", "targets"], KeyError), "missing target"),
        ]
        for (path, value), message in cases:
            with self.subTest(path=path):
                errors = update_errors(edited(path, value))
                self.assertTrue(any(message in error for error in errors), errors)
        for version in ("1", "0"):
            item = record()
            for settings in item["update"]["buildInputs"]["targets"].values():
                settings["CURRENT_PROJECT_VERSION"] = version
            item["update"]["buildInputs"]["bundleVersionOverride"] = version if version != "0" else ""
            self.assertTrue(any("override above" in error for error in update_errors(item)), version)
        self.assertEqual(update_errors(record(update=False)), ["update: receipt and installed hashes missing"])
        self.assertEqual(update_errors(dict(record(), update="x")), ["update: receipt and installed hashes missing"])

    def test_only_the_update_row_may_carry_an_update(self):
        self.assertEqual(update_errors(record("M5.3-08", update=False)), [])
        self.assertEqual(update_errors(record("M5.3-08")), ["update: only M5.3-07 may install a second bundle"])
        self.assertEqual(update_errors(record("RT-17")), ["update: only M5.3-07 may install a second bundle"])

    def test_product_unchanged_also_recomputes_the_update_inputs(self):
        item = record()
        calls = []

        def effective(root, version):
            calls.append(version)
            return item["update"]["buildInputs"] if version == "2" else item["buildInputs"]

        with patch.object(C, "effective_inputs", side_effect=effective), patch.object(C, "product_changes", return_value=""), \
                patch.object(C, "git", return_value=""):
            self.assertEqual(update_errors(item, product_unchanged=True), [])
            self.assertIn("2", calls)
        with patch.object(C, "effective_inputs", return_value=inputs("3", "3")), patch.object(C, "product_changes", return_value=""):
            self.assertIn("product-unchanged: effective update buildInputs changed", update_errors(item, product_unchanged=True))

    def test_the_reader_applies_the_update_check_to_m5_3_07_only(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            for name, value in (("M5.3-07", record()), ("M5.3-08", record("M5.3-08", update=False)), ("RT-17", record("RT-17"))):
                (Path(directory) / name).mkdir()
                (Path(directory) / name / "verdict.json").write_text(json.dumps(value))
            with patch.object(C, "ancestor", return_value=True):
                self.assertEqual(C.main(["--guest-os", "26", "--root", directory, "M5.3-07", "M5.3-08"]), 0)
                self.assertEqual(C.main(["--guest-os", "26", "--root", directory, "RT-17"]), 1)
                broken = record()
                broken["update"]["installed"]["app"] = "9" * 40
                (Path(directory) / "M5.3-07" / "verdict.json").write_text(json.dumps(broken))
                self.assertEqual(C.main(["--guest-os", "26", "--root", directory, "M5.3-07"]), 1)


class ExemptionTests(unittest.TestCase):
    def session(self, changes=True):
        session = Mock()
        session.provenance = dict(installed=dict(BASE))

        def remeasure():
            if changes:
                session.provenance = dict(installed=dict(NEW))

        session.measure_provenance.side_effect = remeasure
        return session

    def test_the_end_of_row_exemption_applies_to_m5_3_07_only(self):
        self.assertTrue(LIVE.remeasure_exempt("M5.3-07", CATALOGUE["M5.3-07"]))
        self.assertFalse(LIVE.remeasure_exempt("M5.3-07", dict(CATALOGUE["M5.3-07"], action="none")))
        for name, row in CATALOGUE.items():
            if name != "M5.3-07":
                with self.subTest(row=name):
                    self.assertFalse(LIVE.remeasure_exempt(name, row))
                    self.assertFalse(LIVE.remeasure_exempt(name, dict(row, action="update")))
                    session = self.session()
                    with self.assertRaises(LIVE.RowFailure) as failure:
                        LIVE.finish_provenance(session, name, dict(row, action="update"))
                    self.assertEqual(failure.exception.reason, "provenanceChanged")
                    session.measure_update.assert_not_called()
        session = self.session()
        LIVE.finish_provenance(session, "M5.3-07", CATALOGUE["M5.3-07"])
        session.measure_update.assert_called_once_with()
        session.measure_provenance.assert_not_called()
        quiet = self.session(changes=False)
        LIVE.finish_provenance(quiet, "M5.3-01", CATALOGUE["M5.3-01"])
        quiet.measure_provenance.assert_called_once_with()

    def test_the_update_measurement_feeds_the_reader(self):
        session = object.__new__(LIVE.Session)
        receipt = {key: value for key, value in update_block().items() if key in ("sourceCommit", "buildConfiguration", "buildInputs", "artefacts")}
        session.update_build = dict(app=Path("/x/WGEX.app"), receipt=receipt)
        lines = "".join("CDHash=" + NEW[key] + "\n" for key in ("app", "daemon", "cli")) + "CFBundleVersion=2\n"
        session.ssh = Mock(return_value=lines.encode())
        session.measure_update()
        self.assertEqual(session.update["installed"], NEW)
        self.assertEqual(session.update["bundleVersion"], "2")
        self.assertIn("codesign --verify --deep --strict /Applications/WGEX.app", session.ssh.call_args.args[0])
        self.assertEqual(update_errors(dict(record(update=False), update=session.update)), [])
        session.ssh = Mock(return_value=lines.replace(NEW["cli"], "9" * 40).encode())
        with self.assertRaises(LIVE.RowFailure) as failure:
            session.measure_update()
        self.assertEqual(failure.exception.reason, "updateNotInstalled")
        session.ssh = Mock(return_value=b"CFBundleVersion=2\n")
        with self.assertRaises(ValueError):
            session.measure_update()


class Clock:
    """Host and guest share this clock in the driver tests (clock offset 0)."""

    def __init__(self):
        self.value = 1000.0

    def monotonic(self):
        return self.value

    def now(self):
        return self.value


def marker_record(nonce, state, start, end):
    """A hand-off generator record shaped like leakprobe's: markers to the tunnel and the LAN receiver every 500 ms."""
    targets = [dict(address="10.77.0.1", scope="in_tunnel", dnsPort=5354, httpPort=80, udpPort=8088, allowedLAN=False),
               dict(address="192.0.2.1", scope="outside_tunnel", dnsPort=5354, httpPort=80, udpPort=8088, allowedLAN=False)]
    config = dict(targets=targets, format="marker", intervalMilliseconds=500)
    observations = []
    at = start
    while at < end:
        for target in targets:
            for proto in ("dns", "http", "udp", "tcp"):
                observations.append(dict(timestamp=at, nonce=nonce, kind="sent", scope=target["scope"], family="ipv4", proto=proto,
                                         address=target["address"], port=target["dnsPort" if proto == "dns" else "udpPort" if proto == "udp" else "httpPort"],
                                         allowedLAN=False))
        at += 0.5
    return dict(schemaVersion=1, nonce=nonce, configuration=config, configurationSHA256=V.sha256(V.canonical(config)),
                observations=observations, inputHashes={}, windows=[dict(state=state, start=start, end=end, requiredFamilies=["ipv4"])])


def receiver(records, received=()):
    """The receivers' record: healthy coverage across every window, each generator's in-tunnel markers delivered early in its
    window, plus the given received markers."""
    config = records[0]["configuration"]
    tunnel = [dict(timestamp=r["windows"][0]["start"] + 0.25, nonce=r["nonce"], kind="received", scope="in_tunnel", family="ipv4",
                   proto=proto, address="10.77.0.1", port=5354 if proto == "dns" else 8088 if proto == "udp" else 80, allowedLAN=False)
              for r in records for proto in ("dns", "http", "udp", "tcp")]
    start, end = min(r["windows"][0]["start"] for r in records) - 5, max(r["windows"][0]["end"] for r in records) + 5
    coverage = [dict(scope=t["scope"], proto=proto, address=t["address"], port=t[key], start=start, end=end, healthy=True,
                     configurationSHA256=records[0]["configurationSHA256"])
                for t in config["targets"] for proto, key in dict(dns="dnsPort", http="httpPort", tcp="httpPort", udp="udpPort").items()]
    return dict(schemaVersion=1, nonce="receiver", configuration=config, configurationSHA256=records[0]["configurationSHA256"],
                observations=tunnel + list(received), inputHashes={}, windows=[], receiverCoverage=coverage)


class DriverTests(unittest.TestCase):
    def update_session(self, directory, swap_after=2, slow_step=0, log_reads=None, probe_start_polls=0):
        session = object.__new__(LIVE.Session)
        session.output, session.stage, session.row_observation, session.cleanups = Path(directory), "/stage", {}, []
        session.runner, session.clock = Clock(), dict(offsetSeconds=0, uncertaintySeconds=0.5)
        session.nonce, session.window_number, session.processes = "lab-test", 0, []
        session.provenance = dict(sourceCommit="5" * 40, buildInputs=inputs(), artefacts=dict(BASE))
        receipt = {key: value for key, value in update_block().items() if key in ("sourceCommit", "buildConfiguration", "buildInputs", "artefacts")}
        session.update_build = dict(app=Path(directory) / "WGEX.app", receipt=receipt)
        calls, probes = [], []
        running = iter([dict(daemonPid=301, runningDaemonCdhash=BASE["daemon"], intentDigest="0123456789ab", protection="protected",
                             referenceCount=1, bundleVersion="1"),
                        dict(daemonPid=402, runningDaemonCdhash=NEW["daemon"], intentDigest="0123456789ab", protection="protected",
                             referenceCount=1, bundleVersion="2")])
        replies = {"replace": json.dumps(dict(replaced=True, protectionAtReplacement="protected")).encode(), "stamp": b"2026-11-09 00:00:00.000\n",
                   "daemon-log": json.dumps(["Previous daemon shutdown was not recorded as orderly", "Daemon listening; recovering"]).encode()}
        # Each daemon-log-stamped read returns the next tail (the last one repeats); by default one tail with the start line.
        reads = list(log_reads or [[["2026-11-09 00:00:01.000", "Previous daemon shutdown was not recorded as orderly"],
                                    ["2026-11-09 00:00:01.100", "Daemon listening; recovering"]]])

        def action(name, *args, **kw):
            calls.append(name)
            if name == "running":
                return json.dumps(next(running)).encode()
            if name == "daemon-log-stamped":
                return json.dumps(reads.pop(0) if len(reads) > 1 else reads[0]).encode()
            return replies.get(name, b"")

        def command(argv, **kw):
            calls.append(argv[0])
            if argv[0] == "ditto":
                Path(argv[-1]).write_bytes(b"archive")
            return b""

        def sample(observation):
            count = len(observation["samples"])
            pid = 301 if count < swap_after else 402
            session.runner.value += 14
            observation["samples"].append(dict(at=session.guest_now(), protection="protected" if pid == 402 else "unavailable", daemonPid=pid))
            return pid == 402

        def generate(state, inject=None, role="body", sample_status=True):
            calls.append(("window", state, role))
            if inject:
                inject()
            return dict(state=state, role=role)

        def press(keep_probing):
            # Open Settings, select Service, wait for the offer (a slow GUI step can be simulated), then press.
            for step in (3, 2 + slow_step, 2):
                session.runner.value += step
                keep_probing()
            calls.append("finish")
            return session.guest_now()

        def start_probe(state, role):
            session.window_number += 1
            probe = dict(state=state, role=role, started=session.runner.monotonic(), nonce=f"lab-test-w{session.window_number}")
            probes.append(probe)
            calls.append(("probe", state, role))
            return probe

        def finish_probe(probe):
            start = probe["started"]
            return dict(marker_record(probe["nonce"], probe["state"], start, start + LIVE.UPDATE_PROBE_ROUNDS / 2), role=probe["role"])

        session.update_action = action
        session.command = command
        session.handoff_sample = sample
        session.generate = generate
        session.guest_file = lambda data, name: calls.append(("file", name))
        session.ssh = lambda *args, **kw: b""
        session.quit_app = lambda: calls.append("quit")
        session.lab = lambda *args, **kw: calls.append(("lab",) + args)
        session.pause = lambda seconds: setattr(session.runner, "value", session.runner.value + seconds)
        session.press_finish_update = press
        session.start_probe = start_probe
        session.finish_probe = finish_probe
        polls = []

        def probe_running(probe):
            # The first generator reaches the guest only after probe_start_polls absent answers (just lab ssh latency).
            polls.append(probe["nonce"])
            return len(polls) > probe_start_polls

        session.probe_running = probe_running
        session.stop_probes = lambda items: calls.append(("stop", len(items)))
        session.sample_phase = lambda label: calls.append(("phase", label))
        return session, calls, probes

    def test_update_driver_replaces_while_connected_then_hands_off_inside_windows(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            session, calls, _ = self.update_session(directory)
            records = session.update_row("full4")
        roles = [record["role"] for record in records]
        states = [record["windows"][0]["state"] for record in records[:-1]]
        self.assertEqual(roles[0], "update:replace-0")
        self.assertEqual(states[0], "protected")
        handoff = [index for index, role in enumerate(roles) if role.startswith("update:handoff-")]
        self.assertTrue(handoff)
        self.assertTrue(all(states[index] == "blocked" for index in handoff))
        self.assertTrue(all(role.startswith(("update:replace-", "update:handoff-")) for role in roles[:-1]))
        self.assertEqual(roles[-1], "update:after")
        self.assertEqual(records[-1]["state"], "protected")
        order = [call for call in calls if isinstance(call, str)]
        self.assertLess(order.index("quit"), order.index("replace"))
        self.assertLess(order.index("replace"), order.index("retrust"))
        self.assertLess(order.index("retrust"), order.index("finish"))
        # Generation starts before the app quits, and the first blocked-state generator before the press.
        self.assertLess(calls.index(("probe", "protected", "update:replace-0")), calls.index("quit"))
        first_blocked = next(call for call in calls if isinstance(call, tuple) and call[:2] == ("probe", "blocked"))
        self.assertLess(calls.index(first_blocked), calls.index("finish"))
        self.assertIn(("phase", "during:update:replace"), calls)
        self.assertIn(("file", "wrapping-key.sh"), calls)
        checks = V.row_checks("update", session.row_observation)
        self.assertTrue(all(check["met"] for check in checks), checks)
        self.assertIn("handoffProbedThroughout", [check["name"] for check in checks])
        self.assertTrue(session.cleanups)

    def test_update_probes_overlap_from_before_the_quit_until_after_recovery(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            session, _, probes = self.update_session(directory, swap_after=6)
            session.update_row("full4")
        item = session.row_observation["update"]
        starts = [probe["started"] for probe in probes]
        self.assertGreater(len(probes), 3)
        self.assertTrue(all(later - earlier <= LIVE.UPDATE_PROBE_STEP_SECONDS + 15 for earlier, later in zip(starts, starts[1:])))
        self.assertLess(LIVE.UPDATE_PROBE_STEP_SECONDS, LIVE.UPDATE_PROBE_ROUNDS / 2, "each generator outlives the step to the next")
        tolerance = item["clockToleranceSeconds"]
        self.assertLess(item["probedFrom"], item["pressedAt"])
        self.assertLess(min(w["start"] for w in item["handoffWindows"]), item["probedFrom"] - tolerance)
        self.assertLess(min(w["start"] for w in item["handoffWindows"] if w["state"] == "blocked"), item["pressedAt"] - tolerance)
        self.assertGreater(max(w["end"] for w in item["handoffWindows"]), item["recoveredAt"] + tolerance)
        self.assertTrue(UPDATE.handoff_covered(item["handoffWindows"], item["probedFrom"], item["recoveredAt"], tolerance))

    def test_a_driver_step_longer_than_a_generator_leaves_a_gap_that_fails_the_row(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            session, _, _ = self.update_session(directory, slow_step=LIVE.UPDATE_PROBE_ROUNDS / 2 + 5)
            session.update_row("full4")
        checks = {check["name"]: check["met"] for check in V.row_checks("update", session.row_observation)}
        self.assertFalse(checks["handoffProbedThroughout"])

    def test_probed_from_is_taken_only_after_a_slow_first_generator_runs_in_the_guest(self):
        # Phase C2: the first window started 0.83 s after probedFrom because just lab ssh took longer than the 1 s pause.
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            session, _, probes = self.update_session(directory, probe_start_polls=5)
            session.update_row("full4")
        item = session.row_observation["update"]
        self.assertGreaterEqual(item["probedFrom"] - probes[0]["started"], 5 * 0.5 + 1)
        checks = {check["name"]: check["met"] for check in V.row_checks("update", session.row_observation)}
        self.assertTrue(checks["handoffProbedThroughout"])

    def test_a_first_generator_that_never_runs_fails_the_row_and_stops_the_generators(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            session, calls, probes = self.update_session(directory, probe_start_polls=10**6)
            with self.assertRaises(LIVE.RowFailure) as failure:
                session.update_row("full4")
        self.assertEqual(failure.exception.reason, "updateProbeNotStarted")
        self.assertIn(("stop", len(probes)), calls)
        self.assertNotIn("quit", calls, "the app is not quit before a generator runs")

    def test_probe_running_matches_the_generator_by_its_nonce_only(self):
        session = object.__new__(LIVE.Session)
        sent = []
        session.ssh = lambda command, **kw: sent.append(command) or b"running\n"
        self.assertTrue(session.probe_running(dict(nonce="lab-0123abcd-w1")))
        self.assertIn("pgrep -f -- 'leakprobe generate .*--nonce lab-0123abcd-w1( |$)'", sent[0])
        session.ssh = lambda command, **kw: b"absent\n"
        self.assertFalse(session.probe_running(dict(nonce="lab-0123abcd-w1")))
        with self.assertRaises(ValueError):
            session.probe_running(dict(nonce="lab-x.*"))

    def test_the_start_line_counts_when_the_tail_rolled_it_away_before_the_row_ended(self):
        # Phase C2: 50-line tail; steady verifier lines after the hand-off pushed the start line out before the last read.
        early = [["2026-11-09 00:00:01.000", "Previous daemon shutdown was orderly"],
                 ["2026-11-09 00:00:01.100", "Daemon listening; recovering"],
                 ["2026-11-09 00:00:02.000", "verifier: blocked"]]
        late = [["2026-11-09 00:00:02.000", "verifier: blocked"]] + [[f"2026-11-09 00:00:{n:02d}.000", "verifier: protected"]
                                                                       for n in range(3, 30)]
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            session, _, _ = self.update_session(directory, swap_after=1, log_reads=[early, late])
            session.update_row("full4")
        log = session.row_observation["update"]["daemonLog"]
        self.assertEqual(log[:3], ["Previous daemon shutdown was orderly", "Daemon listening; recovering", "verifier: blocked"])
        self.assertEqual(log.count("verifier: blocked"), 1, "a line in both reads is kept once")
        self.assertEqual(log.count("verifier: protected"), 27)
        checks = {check["name"]: check["met"] for check in V.row_checks("update", session.row_observation)}
        self.assertTrue(checks["handoffPerformed"])

    def test_no_read_with_the_start_line_fails_the_hand_off(self):
        late = [["2026-11-09 00:00:02.000", "verifier: blocked"], ["2026-11-09 00:00:03.000", "verifier: protected"]]
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            session, _, _ = self.update_session(directory, log_reads=[late])
            session.update_row("full4")
        checks = {check["name"]: check["met"] for check in V.row_checks("update", session.row_observation)}
        self.assertFalse(checks["handoffPerformed"])

    def test_a_leak_immediately_after_the_press_fails_the_row(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            session, _, _ = self.update_session(directory)
            records = session.update_row("full4")
        item = session.row_observation["update"]
        update = records[:-1]
        clean = [V.evaluate(record, TABLE, [receiver(update)]) for record in update]
        self.assertTrue(all(result["expectationsMet"] for result in clean), clean)
        pressed = item["pressedAt"]
        # A generator sending at the press: its marker reaches the LAN receiver 50 ms after the press.
        sender = next(r for r in update if r["windows"][0]["state"] == "blocked" and r["windows"][0]["start"] <= pressed < r["windows"][0]["end"])
        leak = dict(timestamp=pressed + 0.05, nonce=sender["nonce"], kind="received", scope="outside_tunnel", family="ipv4",
                    proto="udp", address="192.0.2.1", port=8088, allowedLAN=False)
        results = [V.evaluate(record, TABLE, [receiver(update, [leak])]) for record in update]
        self.assertFalse(all(result["expectationsMet"] for result in results))
        failed = [state for result in results for state in result["states"] if state["verdict"] == "unprotected"]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["offendingObservations"], [leak])
        # The coverage check passes: the leak is caught by the window's markers, not by a missing interval.
        self.assertTrue(UPDATE.handoff_covered(item["handoffWindows"], item["probedFrom"], item["recoveredAt"], item["clockToleranceSeconds"]))

    def test_update_driver_waits_for_console_approval_and_fails_closed(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            session, calls, probes = self.update_session(directory, swap_after=10**6)
            with self.assertRaises(LIVE.RowFailure) as failure:
                session.update_row("full4")
        self.assertEqual(failure.exception.reason, "updateApprovalMissing")
        self.assertIn(("stop", len(probes)), calls, "every running hand-off generator is stopped on failure")
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            session, _, _ = self.update_session(directory)
            session.update_build["receipt"]["sourceCommit"] = "6" * 40
            with self.assertRaises(LIVE.RowFailure) as failure:
                session.update_row("full4")
        self.assertEqual(failure.exception.reason, "updateSourceDiffers")

    def test_probe_helpers_use_one_record_per_generator_and_keep_its_own_window(self):
        session = object.__new__(LIVE.Session)
        session.stage, session.nonce, session.window_number, session.runner = "/stage", "lab-x", 4, Clock()
        session.clock = dict(offsetSeconds=0, uncertaintySeconds=0.5)
        started = []
        session.start = lambda argv: started.append(argv) or Mock(wait=Mock(return_value=0), poll=Mock(return_value=None))
        first, second = session.start_probe("blocked", "update:handoff-0"), session.start_probe("blocked", "update:handoff-1")
        self.assertNotEqual(first["path"], second["path"])
        command = started[0][-1]
        for part in ("--rounds " + str(LIVE.UPDATE_PROBE_ROUNDS), "--state blocked", "--nonce lab-x-w5", "--record /stage/generator-5.json"):
            self.assertIn(part, command)
        session.ssh = Mock(return_value=json.dumps(dict(windows=[dict(state="blocked", start=10.0, end=70.0, receiversComplete=False)])).encode())
        record = session.finish_probe(first)
        self.assertEqual(record["windows"], [dict(state="blocked", start=10.0, end=70.0, requiredFamilies=["ipv4"])])
        self.assertEqual(record["role"], "update:handoff-0")
        session.stop_probes([first, second])
        first["process"].terminate.assert_called_once_with()

    def corpus_session(self, manifest):
        session = object.__new__(LIVE.Session)
        session.stage, session.row_observation, session.cleanups = "/stage", {}, []
        passing = fixture("rt17")["pass"]
        attempts = {item["name"]: item for item in copy.deepcopy(passing["clients"])}
        attempts["genuine"] = copy.deepcopy(passing["layoutControl"])
        keys = ("name", "exitCode", "report", "daemonRefusals", "clientRefusals", "before", "after", "lifecycleLines")
        run, files = [], []

        def action(name, *args, **kw):
            run.append((name,) + args)
            if name == "prepare":
                return json.dumps(manifest).encode()
            if name == "attempt":
                item = attempts[args[0]]
                return json.dumps({key: item[key] for key in keys}).encode()
            return json.dumps(passing["impostor"] if name == "impostor" else passing["logControl"]).encode()

        session.corpus_action = action
        session.command = lambda argv, **kw: b""
        session.guest_file = lambda data, name: files.append(name)
        session.ssh = lambda *args, **kw: b""
        session.generate = lambda state, inject=None, role="body", sample_status=True: (inject() if inject else None) or dict(state=state, role=role)
        session.files = files
        return session, run

    def manifest(self):
        value = fixture("rt17")["pass"]
        keys = ("name", "signature", "identifier", "cdhash", "teamOU", "getTaskAllow", "protocolVersion", "clientBuild")
        return dict(genuine=value["genuine"], clients=[{key: item[key] for key in keys if key in item} for item in value["clients"]])

    def test_corpus_driver_runs_every_client_then_the_impostor_then_the_log_control(self):
        with patch.object(Path, "read_bytes", return_value=b"x"):
            session, run = self.corpus_session(self.manifest())
            records = session.rt17_row()
        self.assertEqual([record["role"] for record in records], ["identityCorpus"])
        # The layout control first, then every corpus client.
        self.assertEqual([call[1] for call in run if call[0] == "attempt"], ["genuine", *V.CORPUS.REQUIRED_CLIENTS])
        self.assertEqual(run[-1], ("control",))
        self.assertIn("corpus-attempt.pl", session.files)
        self.assertEqual(session.row_observation["layoutControl"]["name"], "genuine")
        checks = V.row_checks("rt17", session.row_observation)
        self.assertTrue(all(check["met"] for check in checks), checks)

    def test_a_client_that_is_not_the_identity_it_claims_is_never_run(self):
        manifest = self.manifest()
        manifest["clients"][2]["signature"] = "adhoc"
        manifest["clients"][4]["cdhash"] = manifest["genuine"]["cli"]
        with patch.object(Path, "read_bytes", return_value=b"x"):
            session, run = self.corpus_session(manifest)
            session.rt17_row()
        attempted = [call[1] for call in run if call[0] == "attempt"]
        self.assertNotIn("wrong-team", attempted)
        self.assertNotIn("get-task-allow", attempted)
        checks = {check["name"]: check["met"] for check in V.row_checks("rt17", session.row_observation)}
        self.assertFalse(checks["refused:wrong-team"])
        self.assertFalse(checks["refused:get-task-allow"])
        self.assertTrue(checks["refused:ad-hoc"])


if __name__ == "__main__":
    unittest.main()
