# SPDX-License-Identifier: MIT
"""Provenance boundaries with an in-memory history and evidence store.

No git mutations, Xcode, signatures, guest commands or temporary files are used.
The existing RecordedRunner integration covers these seams in the whole driver.
"""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[3]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "Tools/lab" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


C = module("acceptance_provenance", "check-verdicts.py")
LIVE = module("live_provenance", "verdict-live.py")
RUN = module("run_provenance", "verdict-run.py")
A, B, SOURCE, HEAD, OFF = (letter * 40 for letter in "abcdf")


def inputs():
    return dict(configuration="Lab", compilationConditions=C.CONDITIONS, bundleVersionOverride="",
                targets={target: dict(CONFIGURATION="Lab", CODE_SIGN_IDENTITY="lab", EXPANDED_CODE_SIGN_IDENTITY="-",
                    CURRENT_PROJECT_VERSION="1", SWIFT_ACTIVE_COMPILATION_CONDITIONS="DEBUG WGEX_LAB_BUILD") for target in C.BUILD_TARGETS})


def record(row="M5.1-01", major="26"):
    hashes = dict(app="1" * 40, daemon="2" * 40, cli="3" * 40)
    return dict(row=row, guestOS=dict(productVersion=major + ".1", buildVersion="25B12"),
                sourceCommit=SOURCE, buildConfiguration="Lab", buildInputs=inputs(), artefacts=hashes,
                installed=hashes.copy(), expectationsMet=True, liveAcceptance=True, rowCompleted=True,
                installation=dict(installCompleted=True))


class ReaderTests(unittest.TestCase):
    def setUp(self):
        self.value = record()
        self.files = {}
        self.diff, self.untracked, self.history = "", "", A + "\tM01-T01\n" + B + "\tM01-T02"
        self.current_inputs = inputs()
        self.git_calls = []

    def git(self, *args, root=None):
        self.git_calls.append(args)
        if args[0] == "merge-base":
            order = [A, B, SOURCE, HEAD]
            left, right = ({"HEAD": HEAD, "main": HEAD}.get(value, value) for value in args[1:])
            if OFF in (left, right):
                return A
            if left not in order or right not in order:
                raise ValueError("missing ref")
            return min((left, right), key=order.index)
        if args[0] == "rev-parse":
            if args[-1] == "M02^{commit}":
                return A
            if args[-1] == "future^{commit}":
                return HEAD
            raise ValueError("missing ref")
        if args[0] == "log":
            return self.history
        if args[0] == "diff":
            return self.diff
        if args[0] == "ls-files":
            return self.untracked
        raise AssertionError(args)

    def read(self, path, *args, **kwargs):
        if str(path) in self.files:
            result = self.files[str(path)]
            if isinstance(result, Exception):
                raise result
            return result
        if path.name == "verdict.json":
            return json.dumps(self.value)
        if path.name == "rows.json":
            return json.dumps(dict(rows={"M5.1-01": {}, "GAP": {"gap": "pending"}}))
        raise FileNotFoundError(path)

    def check(self, args=(), expected=0, mentions=None):
        output = io.StringIO()
        with patch.object(C, "git", side_effect=self.git), patch.object(C, "effective_inputs", return_value=self.current_inputs) as effective_inputs, \
                patch.object(Path, "read_text", lambda path, *a, **kw: self.read(path, *a, **kw)), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = C.main(list(args))
        self.input_calls = effective_inputs.call_args_list
        self.assertEqual(code, expected, output.getvalue())
        if mentions:
            for text in mentions:
                self.assertIn(text, output.getvalue())
        return output.getvalue()

    def row(self, *args, expected=0, mentions=None):
        return self.check(["--guest-os", "26", *args, "M5.1-01"], expected, mentions)

    def test_pass_all_flags_and_scope_union(self):
        self.files["scope.txt"] = "# rows\nM5.1-01\nM5.1-01 # duplicate\n"
        self.row("--root", "records", "--since", "M02", "--after-task", "M01-T01", "--after-task", "M01-T02",
                 "--install", "--product-unchanged", "--scope", "scope.txt")
        for call in self.git_calls:
            if call[0] == "diff":
                self.assertEqual(call[call.index("--") + 1:], C.PRODUCT_PATHS)

    def test_each_required_field_missing_and_not_boolean_true(self):
        original = record()
        for key in original:
            if key == "installation":
                continue
            with self.subTest(key=key):
                self.value = copy.deepcopy(original)
                del self.value[key]
                self.row(expected=1, mentions=["M5.1-01", key.split("Commit")[0]])
        for key in ("expectationsMet", "liveAcceptance", "rowCompleted"):
            for value in (False, 1, "true", None):
                self.value = dict(original, **{key: value})
                self.row(expected=1, mentions=[key])

    def test_wrong_row_os_and_non_lab(self):
        for key, value, message in (("row", "M5.1-04", "row differs"), ("buildConfiguration", "Release", "buildConfiguration"),
                                    ("guestOS", {"productVersion": "27.0", "buildVersion": "26A1"}, "--guest-os")):
            self.value = dict(record(), **{key: value})
            self.row(expected=1, mentions=[message])
        self.value = record()
        self.check(["--guest-os", "27", "M5.1-01"], 1, ["M5.1-01", "guestOS"])

    def test_missing_invalid_and_malformed_files(self):
        for data in (FileNotFoundError(), "{", "null", "[]"):
            self.files["records/M5.1-01/verdict.json"] = data
            self.row("--root", "records", expected=1, mentions=["M5.1-01", "verdict.json"])
        self.files["scope.txt"] = FileNotFoundError()
        self.row("--scope", "scope.txt", expected=1, mentions=["scope"])

    def test_empty_rows_guest_required_and_invalid_identifier(self):
        self.check(["--guest-os", "26"], 1, ["empty row set"])
        self.files["empty"] = "# empty\n"
        self.check(["--guest-os", "26", "--scope", "empty"], 1, ["empty row set"])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            C.main(["M5.1-01"])
        self.assertEqual(error.exception.code, 2)
        self.check(["--guest-os", "26", "../escape"], 1, ["invalid row identifier"])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            C.main(["--guest-os", "26", "--rehearsal", "cutover-rehearsal", "M5.1-01"])

    def test_install_flag(self):
        for installation in ({}, None, {"installCompleted": False}, {"installCompleted": 1}):
            self.value["installation"] = installation
            self.row()  # Installation is additional, selected only by --install.
            self.row("--install", expected=1, mentions=["installation.installCompleted"])

    def test_hash_missing_malformed_and_mismatched(self):
        for side in ("artefacts", "installed"):
            for binary in C.BINARIES:
                for replacement in (None, "short", "9" * 40):
                    self.value = record()
                    if replacement is None:
                        del self.value[side][binary]
                    else:
                        self.value[side][binary] = replacement
                    self.row(expected=1, mentions=[side if replacement != "9" * 40 else "installed differs"])

    def test_source_bounds_main_head_since_and_trailers(self):
        for source, message in ((OFF, "ancestor of HEAD"), (HEAD, "off main")):
            self.value = dict(record(), sourceCommit=source)
            if source == HEAD:
                base_git = self.git
                with patch.object(self, "git", side_effect=lambda *args, **kw: SOURCE if args == ("merge-base", HEAD, "main") else base_git(*args, **kw)):
                    self.row(expected=1, mentions=[message])
            else:
                self.row(expected=1, mentions=[message])
        self.value = record()
        self.row("--since", "future", expected=1, mentions=["precedes --since"])
        self.row("--since", "absent", expected=1, mentions=["verification failed"])
        self.row("--after-task", "M01-T03", expected=1, mentions=["missing Plan-Task: M01-T03"])
        self.history = HEAD + "\tM01-T03"
        self.row("--after-task", "M01-T03", expected=1, mentions=["precedes --after-task"])
        self.history = A + "\tM01-T030"
        self.row("--after-task", "M01-T03", expected=1, mentions=["missing Plan-Task"])

    def test_product_paths_and_effective_inputs(self):
        for path in ("Apps/WGEXMac/file.swift", "justfile", "Tools/lab/tart/build.sh", "Config/Scripts/lib.sh"):
            self.diff = path
            self.row()
            self.row("--product-unchanged", expected=1, mentions=["product paths changed"])
        self.diff, self.untracked = "", "Packages/new.swift"
        self.row("--product-unchanged", expected=1, mentions=["product paths changed"])
        self.untracked = ""
        for key, value in (("CODE_SIGN_IDENTITY", "other"), ("CURRENT_PROJECT_VERSION", "2"),
                           ("SWIFT_ACTIVE_COMPILATION_CONDITIONS", "DEBUG WGEX_LAB_BUILD EXTRA")):
            self.current_inputs = inputs()
            self.current_inputs["targets"]["WGEXMac"][key] = value
            self.row("--product-unchanged", expected=1, mentions=["effective buildInputs changed"])

    def test_product_unchanged_uses_recorded_bundle_override(self):
        self.value["buildInputs"]["bundleVersionOverride"] = "12"
        self.current_inputs = copy.deepcopy(self.value["buildInputs"])
        with patch.dict(os.environ, WGEX_LAB_BUNDLE_VERSION="99"):
            self.row("--product-unchanged")
        self.assertEqual(self.input_calls[-1].args, (C.ROOT, "12"))

    def test_catalogue_only_does_not_read_verdicts_or_require_guest(self):
        self.value = None
        self.check(["--catalogue-only", "M5.1-01"])
        self.check(["--catalogue-only", "GAP"], 1, ["GAP", "gap"])
        self.check(["--catalogue-only", "unknown"], 1, ["unknown", "missing"])
        self.check(["--catalogue-only"], 1, ["empty row set"])

    def test_exact_m03_m04_rehearsal_commands_and_each_check_false_or_missing(self):
        # The three distinct rehearsal-only invocations from the M03/M04 plans.
        commands = [
            "--root Tests/Reports/v2 --guest-os 26 --since M02 --rehearsal cutover-rehearsal",
            "--root Tests/Reports/v2/macos27 --guest-os 27 --since M02 --rehearsal cutover-rehearsal",
            "--root Tests/Reports/v2 --guest-os 26 --since M02 --product-unchanged --rehearsal cutover-rehearsal",
            "--root Tests/Reports/v2/macos27 --guest-os 27 --since M02 --product-unchanged --rehearsal cutover-rehearsal",
        ]
        self.assertEqual(len(C.REHEARSAL_CHECKS), 14)
        for command in commands:
            major = command.split("--guest-os ")[1].split()[0]
            good = dict(record("cutover-rehearsal", major), **dict.fromkeys(C.REHEARSAL_CHECKS, True))
            for key in ("expectationsMet", "liveAcceptance", "rowCompleted"):
                del good[key]  # Rehearsals have their own acceptance booleans.
            self.value = copy.deepcopy(good)
            self.check(command.split())
            for key in C.REHEARSAL_CHECKS:
                for missing in (False, True):
                    self.value = copy.deepcopy(good)
                    if missing:
                        del self.value[key]
                    else:
                        self.value[key] = False
                    self.check(command.split(), 1, ["cutover-rehearsal", key])
            self.value = dict(good, buildConfiguration="Release")
            self.check(command.split(), 1, ["buildConfiguration"])

    def test_scope_matches_plan_mac26_rows(self):
        ids = [line for line in (ROOT / "Tools/lab/scope-v2.txt").read_text().splitlines() if line and not line.startswith("#")]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(ids), 37)
        self.assertIn("ONDEMAND-ETH", ids)
        self.assertIn("UNINSTALL", ids)  # M03-T15 (DEC-037 item 4)
        self.assertIn("LOGIN-SILENT", ids)  # M03-T07 (DEC-021)
        self.assertNotIn("AUTH-REAL", ids)


class ProducerTests(unittest.TestCase):
    def session(self, no_install=False, mismatch=False):
        session = object.__new__(LIVE.Session)
        session.no_install = no_install
        session.provenance = {}
        built = {key: value for key, value in record().items() if key in ("sourceCommit", "buildConfiguration", "buildInputs", "artefacts")}
        session.command = Mock(return_value=json.dumps(built).encode())
        hashes = list(built["artefacts"].values())
        if mismatch:
            hashes[2] = "4" * 40
        session.ssh = Mock(return_value=("26.1\n25B12\n" + "\n".join("CDHash=" + value for value in hashes)).encode())
        return session

    def test_installed_measurement_both_install_modes(self):
        for no_install in (False, True):
            session = self.session(no_install)
            session.measure_provenance()
            self.assertEqual(session.provenance["installed"], session.provenance["artefacts"])
            self.assertEqual(session.provenance["guestOS"], record()["guestOS"])
            self.assertIn("--inspect-build", session.command.call_args.args[0])
            self.assertIn("codesign --verify --deep --strict", session.ssh.call_args.args[0])
            with self.assertRaises(LIVE.RowFailure):
                self.session(no_install, mismatch=True).measure_provenance()
            session.ssh.return_value = b"26.1\n25B12\n"
            with self.assertRaises(ValueError):
                session.measure_provenance()

    def test_source_commit_uses_merge_base_and_refuses_committed_dirty_untracked_changes(self):
        for changed in ("", "Apps/committed.swift", "Daemon/dirty.swift", "justfile", "Tools/lab/tart/build.sh"):
            with patch.object(C, "git", return_value=SOURCE) as git, patch.object(C, "product_changes", return_value=changed):
                if changed:
                    with self.assertRaisesRegex(ValueError, "product paths"):
                        C.source_commit()
                else:
                    self.assertEqual(C.source_commit(), SOURCE)
                git.assert_called_once_with("merge-base", "HEAD", "main", root=C.ROOT)

    def test_receipt_rejects_source_input_or_binary_drift(self):
        built = {key: value for key, value in record().items() if key in ("sourceCommit", "buildConfiguration", "buildInputs", "artefacts")}
        current = {key: value for key, value in built.items() if key != "artefacts"}
        for key in (None, "sourceCommit", "buildInputs", "artefacts"):
            receipt = copy.deepcopy(built)
            if key:
                receipt[key] = "changed"
            with patch.object(Path, "read_text", return_value=json.dumps(receipt)), \
                    patch.object(C, "build_provenance", return_value=current), patch.object(C, "binary_hashes", return_value=built["artefacts"]):
                if key:
                    with self.assertRaises(ValueError):
                        C.inspect_build(Path("WGEX.app"))
                else:
                    self.assertEqual(C.inspect_build(Path("WGEX.app")), built)

    def test_effective_inputs_capture_flags_signing_and_override(self):
        settings = inputs()["targets"]["WGEXMac"]
        settings.update(CODE_SIGN_IDENTITY="-", OTHER_SWIFT_FLAGS="-D EXTRA", EXPANDED_CODE_SIGN_IDENTITY="4" * 40,
                        MARKETING_VERSION="0.1.0", BUILD_DIR="/build", OTHER_LDFLAGS="/build/engine.a")
        settings["WGEX_UNRELATED_SECRET"] = "omitted"
        payload = json.dumps([dict(target=target, buildSettings=settings) for target in C.BUILD_TARGETS])
        with patch.object(C, "command", return_value=payload) as command, patch.dict(os.environ, WGEX_LAB_BUNDLE_VERSION="12"):
            value = C.effective_inputs()
        self.assertEqual(value["bundleVersionOverride"], "12")
        self.assertEqual(value["targets"]["WGEXMac"]["OTHER_SWIFT_FLAGS"], "-D EXTRA")
        self.assertEqual(value["targets"]["WGEXMac"]["OTHER_LDFLAGS"], "<build>/engine.a")
        self.assertIn("CURRENT_PROJECT_VERSION=12", command.call_args.args[0])
        self.assertEqual(value["targets"]["WGEXMac"]["EXPANDED_CODE_SIGN_IDENTITY"], "4" * 40)
        self.assertNotIn("WGEX_UNRELATED_SECRET", value["targets"]["WGEXMac"])

    def test_effective_inputs_are_portable_between_hosts_and_worktrees(self):
        def capture(home, root, derived):
            settings = inputs()["targets"]["WGEXMac"]
            settings.update(CODE_SIGN_IDENTITY="-", HOME=home, SRCROOT=root, PROJECT_DIR=root,
                            BUILD_DIR=derived + "/Build/Products", OBJROOT=derived + "/Build/Intermediates.noindex",
                            DEVELOPER_DIR=home + "/Xcode.app/Contents/Developer",
                            SDKROOT=home + "/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk",
                            OTHER_LDFLAGS=f'-L"{derived}/Build/Products/Lab" -L"{derived}/Build/Intermediates.noindex/cache"',
                            OTHER_SWIFT_FLAGS=f'-I"{root}/Packages" -I"{home}/Library/include" -I"{derived}/SDKStatCaches.noindex"')
            payload = json.dumps([dict(target=target, buildSettings=settings) for target in C.BUILD_TARGETS])
            with patch.object(C, "command", return_value=payload), patch.dict(os.environ, WGEX_LAB_BUNDLE_VERSION=""):
                return C.effective_inputs(Path(root))
        first = capture("/Users/one", "/Users/one/work/first", "/Users/one/Library/Developer/Xcode/DerivedData/first-abc")
        second = capture("/Users/two", "/Volumes/External/work/second", "/build/custom-derived-data")
        self.assertEqual(first, second)
        flags = first["targets"]["WGEXMac"]
        self.assertEqual(flags["OTHER_LDFLAGS"], '-L"<build>/Lab" -L"<intermediates>/cache"')
        self.assertEqual(flags["OTHER_SWIFT_FLAGS"], '-I"<source>/Packages" -I"<home>/Library/include" -I"<derived-data>/SDKStatCaches.noindex"')
        changed = capture("/Users/two", "/Volumes/External/work/second", "/build/custom-derived-data")
        changed["targets"]["WGEXMac"]["OTHER_SWIFT_FLAGS"] += " -D EXTRA"
        self.assertNotEqual(first, changed)

    def test_inspect_build_uses_receipt_override_without_callers_environment(self):
        for override in ("", "12"):
            built = {key: value for key, value in record().items() if key in ("sourceCommit", "buildConfiguration", "buildInputs", "artefacts")}
            built["buildInputs"]["bundleVersionOverride"] = override
            settings = copy.deepcopy(built["buildInputs"]["targets"]["WGEXMac"])
            settings["CODE_SIGN_IDENTITY"] = "-"
            settings["CURRENT_PROJECT_VERSION"] = override or "1"
            for target in C.BUILD_TARGETS:
                built["buildInputs"]["targets"][target]["CURRENT_PROJECT_VERSION"] = override or "1"
            payload = json.dumps([dict(target=target, buildSettings=settings) for target in C.BUILD_TARGETS])
            for ambient in (None, "99", "invalid"):
                with self.subTest(override=override, ambient=ambient), patch.dict(os.environ):
                    os.environ.pop("WGEX_LAB_BUNDLE_VERSION", None)
                    if ambient is not None:
                        os.environ["WGEX_LAB_BUNDLE_VERSION"] = ambient
                    with patch.object(Path, "read_text", return_value=json.dumps(built)), \
                            patch.object(C, "source_commit", return_value=SOURCE), \
                            patch.object(C, "command", return_value=payload) as command, \
                            patch.object(C, "binary_hashes", return_value=built["artefacts"]):
                        self.assertEqual(C.inspect_build(Path("WGEX.app")), built)
                    args = command.call_args.args[0]
                    self.assertEqual([arg for arg in args if arg.startswith("CURRENT_PROJECT_VERSION=")],
                                     ["CURRENT_PROJECT_VERSION=" + override] if override else [])

    def test_signing_identity_records_class_and_sha1_without_common_name_or_team(self):
        for own_mac in ("0", "1"):
            settings = inputs()["targets"]["WGEXMac"]
            settings.update(CODE_SIGN_IDENTITY="Apple Development: Example Person (TEAM)",
                            EXPANDED_CODE_SIGN_IDENTITY_NAME="Apple Development: Example Person (TEAM)",
                            EXPANDED_CODE_SIGN_IDENTITY="A" * 40, DEVELOPMENT_TEAM="TEAM", WGEX_TEAM="TEAM",
                            WGEX_OWN_MAC_BUILD=own_mac)
            payload = json.dumps([dict(target=target, buildSettings=settings) for target in C.BUILD_TARGETS])
            with patch.object(C, "command", return_value=payload):
                value = C.effective_inputs(bundle_version="")
            captured = value["targets"]["WGEXMac"]
            self.assertEqual(captured["CODE_SIGN_IDENTITY"], "own-mac" if own_mac == "1" else "lab")
            self.assertEqual(captured["EXPANDED_CODE_SIGN_IDENTITY"], "a" * 40)
            self.assertNotIn("Example Person", json.dumps(value))
            self.assertNotIn("TEAM", json.dumps(value))
            for fingerprint in ("", "invalid", None):
                settings["EXPANDED_CODE_SIGN_IDENTITY"] = fingerprint
                payload = json.dumps([dict(target=target, buildSettings=settings) for target in C.BUILD_TARGETS])
                with patch.object(C, "command", return_value=payload), self.assertRaisesRegex(ValueError, "SHA-1"):
                    C.effective_inputs(bundle_version="")

    def test_build_receipt_compares_before_and_after_build(self):
        current = {key: value for key, value in record().items() if key in ("sourceCommit", "buildConfiguration", "buildInputs")}
        with patch.object(C, "build_provenance", return_value=copy.deepcopy(current)), \
                patch.object(Path, "mkdir"), patch.object(Path, "write_text") as write:
            C.record_build(Path("WGEX.app"), "prepare")
        self.assertEqual(json.loads(write.call_args.args[0]), current)
        for changed in (False, True):
            previous = dict(current, sourceCommit=OFF) if changed else current
            with patch.object(C, "build_provenance", return_value=copy.deepcopy(current)), \
                    patch.object(Path, "read_text", return_value=json.dumps(previous)), \
                    patch.object(Path, "mkdir"), patch.object(Path, "write_text") as write, \
                    patch.object(C, "binary_hashes", return_value=record()["artefacts"]):
                if changed:
                    with self.assertRaisesRegex(ValueError, "changed during build"):
                        C.record_build(Path("WGEX.app"), "finish")
                    write.assert_not_called()
                else:
                    C.record_build(Path("WGEX.app"), "finish")
                    self.assertEqual(json.loads(write.call_args.args[0])["artefacts"], record()["artefacts"])

    def test_missing_effective_target_flags_signing_and_version_refused(self):
        for key in ("WGEXDaemon", "CODE_SIGN_IDENTITY", "EXPANDED_CODE_SIGN_IDENTITY", "CURRENT_PROJECT_VERSION", "SWIFT_ACTIVE_COMPILATION_CONDITIONS"):
            value = inputs()
            if key == "WGEXDaemon":
                del value["targets"][key]
            else:
                del value["targets"]["WGEXMac"][key]
            with self.assertRaises(ValueError):
                C.validate_inputs(value)

    def test_runner_refuses_passing_transport_without_provenance(self):
        transport = Mock()
        transport.run.return_value = dict(expectationsMet=True, rowCompleted=True, states=[{}])
        with patch.object(RUN, "load_module", return_value=transport), patch.object(RUN, "write_report") as writer, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(RUN.main(["IPERF3", "--no-install"]), 1)
        result = writer.call_args.args[1]
        self.assertFalse(result["liveAcceptance"])
        self.assertTrue(any("Provenance" in gap for gap in result["gaps"]))


if __name__ == "__main__":
    unittest.main()
