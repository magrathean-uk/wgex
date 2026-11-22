# SPDX-License-Identifier: MIT
"""Minimum-toolchain regressions; subprocesses are bounded and mutations stay in TMPDIR."""
import copy
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

COMMAND_TIMEOUT = 180

ROOT = Path(os.environ.get("WGEX_TOOLCHAIN_TEST_ROOT", Path(__file__).resolve().parents[2]))


class ToolchainTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="wgex-toolchain-", dir=os.environ["TMPDIR"])
        self.addCleanup(self.temporary.cleanup)
        self.tree = Path(self.temporary.name) / "tree"
        for name in ("Toolchain.lock", "Tools/doctor/doctor.sh", "Engine/scripts/lib.sh",
                     "Engine/scripts/build-xcframework.sh", "Engine/scripts/build-test-support.sh",
                     "Engine/scripts/source-digest.py", "Config/Scripts/lib.sh"):
            target = self.tree / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, target)
        self.lock = tomllib.loads((self.tree / "Toolchain.lock").read_text())
        self.bin = Path(self.temporary.name) / "bin"
        self.bin.mkdir()
        self.versions = {"xcode": self.lock["xcode"]["version"], "swift": self.lock["swift"]["version"],
                         "go": self.lock["go"]["version"], "xcodegen": self.lock["xcodegen"]["version"],
                         **self.lock["homebrew"]}
        mock = self.bin / "mock"
        mock.write_text(f'#!{sys.executable}\n' + '''import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
versions = json.loads(os.environ["TEST_VERSIONS"])
version = versions.get(name, "")
if name == "python3" and "--version" not in sys.argv:
    os.execv(sys.executable, [sys.executable, *sys.argv[1:]])
if name == "go" and sys.argv[1:3] == ["version", "-m"]:
    tool = pathlib.Path(sys.argv[3]).name
    module, version = json.loads(os.environ["TEST_GO_TOOLS"])[tool].split("@")
    print("path", module)
    print("mod fixture", version)
elif name == "go" and sys.argv[1] == "env":
    print("local\\n-mod=vendor\\noff")
elif name == "go": print("go version", version, "darwin/arm64")
elif name == "xcodebuild": print("Xcode " + versions["xcode"] + "\\nBuild version " + os.environ.get("TEST_XCODE_BUILD", "99Z999"))
elif name == "swift": print("Apple Swift version", version, "(swiftlang-99.0.1 clang-99.0.1)")
elif name == "xcodegen": print("Version:", version)
elif name == "xcode-select": print(os.environ["TEST_TREE"])
elif name == "xcrun":
    if "--show-sdk-path" in sys.argv: print(os.environ["TEST_TREE"])
    elif "--show-sdk-version" in sys.argv: print("99.0")
    elif sys.argv[1:4] == ["simctl", "list", "runtimes"]:
        if "-j" in sys.argv: print('{"runtimes": []}')
        else: print("iOS 27.0 (test) - com.apple.test\\ntvOS 27.0 (test) - com.apple.test")
    else: print('{"devices": {}}')
elif name == "ioreg": print('"IOPlatformUUID" = "fixture"')
elif name == "security": pass
else: print(name, version)
''')
        mock.chmod(0o755)
        for name in (*self.versions, "xcodebuild", "xcode-select", "xcrun", "ioreg", "security", *self.lock["go_tools"]):
            (self.bin / name).symlink_to(mock)
        self.env = os.environ | {"PATH": f"{self.bin}:/usr/bin:/bin", "TEST_TREE": str(self.tree),
                                 "TEST_GO_TOOLS": json.dumps(self.lock["go_tools"]), "WGEX_OFFLINE": "1",
                                 "WGEX_DOCTOR_SIMCTL_RETRY_SECONDS": "0", "WGEX_BUILD_KEY": "fixture"}
        vendor = self.tree / "Engine/go/vendor"
        vendor.mkdir(parents=True)
        (vendor / "modules.txt").write_text("# golang.zx2c4.com/wireguard v0.0.0\n")
        (vendor.parent / "go.mod").write_text("module fixture\ngo 1.27\ntoolchain go1.27.3\n")

    def run_command(self, command, versions=None):
        try:
            return subprocess.run(command, cwd=self.tree,
                                  env=self.env | {"TEST_VERSIONS": json.dumps(versions or self.versions)},
                                  capture_output=True, text=True, timeout=COMMAND_TIMEOUT)
        except subprocess.TimeoutExpired:
            self.fail(f"toolchain step {' '.join(map(str, command))} exceeded {COMMAND_TIMEOUT}s; "
                      f"1-minute load average {os.getloadavg()[0]:.2f}")

    def test_timeout_names_the_step_bound_and_load(self):
        with patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired("fixture", COMMAND_TIMEOUT)):
            with self.assertRaisesRegex(AssertionError, r"toolchain step bash Tools/doctor/doctor.sh exceeded 180s; 1-minute load average [0-9.]+"):
                self.doctor()

    def doctor(self, versions=None):
        return self.run_command(["bash", "Tools/doctor/doctor.sh"], versions)

    def test_doctor_equal_and_newer_versions_print_found_versions(self):
        for versions in (self.versions, {name: ("go99.0.10" if name == "go" else "99.0.10") for name in self.versions}):
            with self.subTest(go=versions["go"]):
                result = self.doctor(versions)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for name, version in versions.items():
                    self.assertRegex(result.stdout, rf"(?m)^OK +{name}( version)? +{version.replace('.', '[. ]')}\b")
                self.assertIn("99Z999", result.stdout)
                self.assertIn("swiftlang-99.0.1", result.stdout)

    def test_doctor_older_and_missing_fail(self):
        older = {name: ("go0.1.0" if name == "go" else "0.0.1") for name in self.versions}
        for versions in (older, {name: "" for name in self.versions}):
            result = self.doctor(versions)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            for name in self.versions:
                self.assertRegex(result.stdout, rf"(?m)^FAIL +{name}( version)? +")
        (self.bin / "swiftformat").unlink()
        result = self.doctor()
        self.assertRegex(result.stdout, r"(?m)^FAIL +swiftformat +missing")
        self.assertNotEqual(result.returncode, 0)

    # (found, floor, accepted): lexical and numeric order disagree on the first, third and last rows; the trailing-component
    # rows (found shorter than the floor, 3.15 against 3.15.1) separate a real comparison from one that stops at the shorter.
    VERSION_TABLE = (("3.15.10", "3.15.2", True), ("3.15.2", "3.15.10", False), ("3.15.2", "3.15.1", True),
                     ("3.15.1", "3.15.2", False), ("3.15", "3.15.1", False), ("3.15", "3.15.0", True),
                     ("3.15.1", "3.15", True), ("3.15.2.0", "3.15.2", True), ("3.15.0.1", "3.15", True),
                     ("3.16", "3.15.2", True), ("3.9.99", "3.15.2", False), ("go1.27.10", "go1.27.3", True),
                     ("go1.27.3", "go1.27.10", False), ("go1.28", "go1.27.3", True), ("27.10", "27.2", True),
                     ("27.2", "27.10", False), ("invalid", "3.15.2", False), ("", "3.15.2", False))

    def test_numeric_component_comparison_in_doctor_and_engine(self):
        # Exercise both shipped helpers directly, without probing any host tool.
        doctor = (self.tree / "Tools/doctor/doctor.sh").read_text().split("# Xcode and Swift")[0]
        doctor = doctor.replace('ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"', f'ROOT="{self.tree}"')
        path = self.tree / "compare.sh"
        path.write_text(doctor + '\nversion_at_least "$TEST_FOUND" "$TEST_FLOOR"\n')
        engine = 'source Engine/scripts/lib.sh; version_at_least "$TEST_FOUND" "$TEST_FLOOR"'
        for found, floor, accepted in self.VERSION_TABLE:
            self.env |= {"TEST_FOUND": found, "TEST_FLOOR": floor}
            for name, command in (("doctor", ["bash", str(path)]), ("engine", ["bash", "-c", engine])):
                with self.subTest(helper=name, found=found, floor=floor):
                    result = self.run_command(command)
                    self.assertEqual(result.returncode, 0 if accepted else 1, result.stdout + result.stderr)

    def test_engine_accepts_newer_and_rejects_older_or_missing(self):
        command = ["bash", "-c", 'source Engine/scripts/lib.sh; assert_toolchain macosx']
        for versions, expected in ((self.versions, 0), (self.versions | {"go": "go1.28.10", "xcode": "28.0"}, 0),
                                   (self.versions | {"go": "go1.26.9"}, 1), (self.versions | {"xcode": "27.1"}, 1),
                                   (self.versions | {"go": ""}, 1), (self.versions | {"xcode": ""}, 1)):
            with self.subTest(versions=versions):
                result = self.run_command(command, versions)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        # Lexical order puts go1.27.10 below go1.27.3 and 27.10 below 27.2; both are newer.
        for versions in (self.versions | {"go": "go1.27.10"}, self.versions | {"xcode": "27.10"}):
            with self.subTest(versions=versions):
                result = self.run_command(command, versions)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # The go.mod toolchain is a separate minimum, never an equality with the lock floor.
        path = self.tree / "Toolchain.lock"
        path.write_text(path.read_text().replace('version = "go1.27.3"', 'version = "go1.28.0"'))
        self.assertEqual(self.run_command(command, self.versions | {"go": "go1.28.10"}).returncode, 0)
        path.write_text(path.read_text().replace('version = "go1.28.0"', 'version = "go1.27.3"'))
        gomod = self.tree / "Engine/go/go.mod"
        gomod.write_text("module fixture\ngo 1.27\ntoolchain go1.27.4\n")
        for found, expected in (("go1.27.3", 1), ("go1.27.4", 0), ("go1.27.10", 0)):
            with self.subTest(gomod_floor="go1.27.4", found=found):
                result = self.run_command(command, self.versions | {"go": found})
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                if expected:
                    self.assertIn("go.mod toolchain minimum is 'go1.27.4'", result.stderr)

    def engine_fixture(self):
        """A tree whose real build-xcframework.sh runs with the toolchain preflight and the compile stubbed."""
        library = self.tree / "Engine/scripts/lib.sh"
        # create_xcframework writes the slice archives and Info.plist that source-digest.py --verify reads.
        assemble = (self.tree / "assemble.py")
        assemble.write_text("""import pathlib, plistlib, shutil, sys
target, libraries = pathlib.Path(sys.argv[1]), []
for archive in (pathlib.Path(a) for a in sys.argv[2:] if a.endswith("libwgex.a")):
    name = archive.parent.name
    (target / name).mkdir(parents=True)
    shutil.copy(archive, target / name / "libwgex.a")
    platform = name.split("-")[0]
    entry = {"LibraryIdentifier": name, "LibraryPath": "libwgex.a", "SupportedPlatform": platform,
             "SupportedArchitectures": ["arm64"]}
    if name.endswith("-simulator"):
        entry["SupportedPlatformVariant"] = "simulator"
    libraries.append(entry)
(target / "Info.plist").write_bytes(plistlib.dumps({"AvailableLibraries": libraries}))
""")
        library.write_text(library.read_text() + f'''
assert_toolchain() {{ export GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off; }}
configure_caches() {{ :; }}
build_root() {{ printf '%s/build' "$ROOT"; }}
dependency_cache() {{ printf '%s/cache' "$ROOT"; }}
build_slice() {{ mkdir -p "$2"; printf '%s' "$SCRIPT_SHA" >"$2/libwgex.a"; echo built >>"$ROOT/builds.log"; }}
create_xcframework() {{ local out="$1"; shift; mkdir -p "$out"; {sys.executable} -I "{assemble}" "$out" "$@"; }}
''')
        verify = self.tree / "Engine/scripts/verify-slices.sh"
        verify.write_text("#!/bin/bash\nexit 0\n")
        verify.chmod(0o755)
        for name, content in (("bridge/wgex.h", "fixture"), ("bridge/module.modulemap", "fixture"),
                              ("testsupport/wgex_test.h", "fixture"), ("testsupport/module.modulemap", "fixture"),
                              ("engine/engine.go", 'const WireGuardCommit = "abcd"\n')):
            path = self.tree / "Engine/go" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        self.run_command(["git", "init", "-q", "--template="]).check_returncode()

    def engine_build(self, versions, *flags):
        return self.run_command(["bash", "Engine/scripts/build-xcframework.sh", *flags], versions)

    def support_build(self, versions, *flags):
        return self.run_command(["bash", "Engine/scripts/build-test-support.sh", *flags], versions)

    def support_provenance(self):
        return json.loads((self.tree / "Packages/WGEXEngine/Binary/provenance-test.json").read_text())

    def drop_toolchain_key(self, name):
        """Rewrites a provenance file as the pre-M1-46 builds wrote it: no toolchain_sha256."""
        path = self.tree / "Packages/WGEXEngine/Binary" / name
        data = json.loads(path.read_text())
        self.assertIn("toolchain_sha256", data)
        del data["toolchain_sha256"]
        path.write_text(json.dumps(data))

    def verify_archive(self, *flags):
        return self.run_command([sys.executable, "-I", "Engine/scripts/source-digest.py", "--verify",
                                 "Packages/WGEXEngine/Binary", *flags])

    def engine_builds(self):
        log = self.tree / "builds.log"
        return len(log.read_text().split()) if log.exists() else 0

    def engine_provenance(self):
        return json.loads((self.tree / "Packages/WGEXEngine/Binary/provenance.json").read_text())

    def test_engine_logs_and_provenance_use_found_versions(self):
        self.engine_fixture()
        versions = self.versions | {"go": "go1.28.10", "xcode": "28.0"}
        result = self.engine_build(versions, "--force")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        provenance = self.engine_provenance()
        self.assertEqual(provenance["go"], "go1.28.10")
        self.assertEqual(provenance["xcode"], "28.0 (99Z999)")
        self.assertIn("go go1.28.10, Xcode 28.0 (99Z999)", result.stdout)

    def test_engine_cache_key_includes_the_compiling_toolchain(self):
        # M1-46 F1: a toolchain change rebuilds once; the same toolchain, or a floor edit, reuses the archive.
        self.engine_fixture()
        base = self.versions | {"go": "go1.28.10", "xcode": "28.0"}
        self.assertEqual(self.engine_build(base).returncode, 0)
        self.assertEqual(self.engine_builds(), 5)
        result = self.engine_build(base)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.engine_builds(), 5, "same toolchain must reuse the archive")
        self.assertIn("using existing", result.stdout)
        # A floor edit in Toolchain.lock is eligibility policy, not a rebuild trigger.
        path = self.tree / "Toolchain.lock"
        path.write_text(path.read_text().replace('version = "go1.27.3"', 'version = "go1.27.9"')
                        .replace('version = "27.2"', 'version = "27.3"'))
        self.assertEqual(self.engine_build(base).returncode, 0)
        self.assertEqual(self.engine_builds(), 5, "a floor edit must not rebuild")
        for label, changed, built in (("go version", base | {"go": "go1.28.11"}, 10),
                                      ("xcode version", base | {"go": "go1.28.11", "xcode": "28.1"}, 15)):
            with self.subTest(change=label):
                result = self.engine_build(changed)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.engine_builds(), built, f"a {label} change must rebuild once")
                self.assertNotIn("using existing", result.stdout)
                self.assertEqual(self.engine_provenance()["go"], changed["go"])
                self.assertEqual(self.engine_build(changed).returncode, 0)
                self.assertEqual(self.engine_builds(), built, f"the {label} rebuild must be a one-off")
        # The Xcode build alone (same version string) is part of the key.
        self.env["TEST_XCODE_BUILD"] = "99Z998"
        changed = base | {"go": "go1.28.11", "xcode": "28.1"}
        self.assertEqual(self.engine_build(changed).returncode, 0)
        self.assertEqual(self.engine_builds(), 20, "an Xcode build change must rebuild")
        self.assertEqual(self.engine_provenance()["xcode"], "28.1 (99Z998)")

    def test_engine_rebuilds_once_from_a_provenance_without_a_toolchain_key(self):
        # M1-46 N1: an archive built before the toolchain joined the key has no toolchain_sha256. It must rebuild once
        # (no traceback, never silently reuse), and the lib.sh:37 form of verify (no --toolchain) still accepts it.
        self.engine_fixture()
        versions = self.versions | {"go": "go1.28.10", "xcode": "28.0"}
        self.assertEqual(self.engine_build(versions).returncode, 0)
        self.assertEqual(self.engine_builds(), 5)
        self.drop_toolchain_key("provenance.json")
        self.assertEqual(self.verify_archive().returncode, 0, "verify without --toolchain must not need the key")
        keyed = self.verify_archive("--toolchain", "go version go1.28.10 darwin/arm64", "28.0", "99Z999")
        self.assertEqual(keyed.returncode, 1)
        self.assertIn("missing or stale XCFramework", keyed.stderr)
        self.assertNotIn("Traceback", keyed.stderr)
        result = self.engine_build(versions)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stdout + result.stderr)
        self.assertEqual(self.engine_builds(), 10, "an archive without toolchain_sha256 must rebuild once")
        self.assertRegex(self.engine_provenance()["toolchain_sha256"], r"[0-9a-f]{64}")
        self.assertEqual(self.engine_build(versions).returncode, 0)
        self.assertEqual(self.engine_builds(), 10, "the rebuild must be a one-off")

    def test_test_support_cache_key_includes_the_compiling_toolchain(self):
        # M1-54 N3: the test-support archive is keyed like the production one; its provenance records the toolchain.
        self.engine_fixture()
        base = self.versions | {"go": "go1.28.10", "xcode": "28.0"}
        result = self.support_build(base)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.engine_builds(), 1)
        provenance = self.support_provenance()
        self.assertRegex(provenance["toolchain_sha256"], r"[0-9a-f]{64}")
        self.assertEqual(provenance["go"], "go1.28.10")
        self.assertEqual(provenance["xcode"], "28.0 (99Z999)")
        self.assertEqual(self.verify_archive("--test-support").returncode, 0, "the lib.sh:37 form must still verify")
        result = self.support_build(base)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.engine_builds(), 1, "same toolchain must reuse the test-support archive")
        self.assertIn("using existing", result.stdout)
        path = self.tree / "Toolchain.lock"
        path.write_text(path.read_text().replace('version = "go1.27.3"', 'version = "go1.27.9"')
                        .replace('version = "27.2"', 'version = "27.3"'))
        self.assertEqual(self.support_build(base).returncode, 0)
        self.assertEqual(self.engine_builds(), 1, "a floor edit must not rebuild the test-support archive")
        built = 1
        for label, changed in (("go version", base | {"go": "go1.28.11"}),
                               ("xcode version", base | {"go": "go1.28.11", "xcode": "28.1"})):
            with self.subTest(change=label):
                built += 1
                result = self.support_build(changed)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.engine_builds(), built, f"a {label} change must rebuild the test-support archive once")
                self.assertNotIn("using existing", result.stdout)
                self.assertEqual(self.support_provenance()["go"], changed["go"])
                self.assertEqual(self.support_build(changed).returncode, 0)
                self.assertEqual(self.engine_builds(), built, f"the {label} rebuild must be a one-off")
        self.env["TEST_XCODE_BUILD"] = "99Z998"
        self.assertEqual(self.support_build(changed).returncode, 0)
        self.assertEqual(self.engine_builds(), 4, "an Xcode build change must rebuild the test-support archive")
        self.assertEqual(self.support_provenance()["xcode"], "28.1 (99Z998)")
        # M1-46 N1 for this path: a provenance-test.json from before the key must rebuild once, with no traceback.
        self.drop_toolchain_key("provenance-test.json")
        self.assertEqual(self.verify_archive("--test-support").returncode, 0)
        result = self.support_build(changed)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stdout + result.stderr)
        self.assertEqual(self.engine_builds(), 5, "a provenance-test.json without toolchain_sha256 must rebuild once")
        self.assertRegex(self.support_provenance()["toolchain_sha256"], r"[0-9a-f]{64}")
        self.assertEqual(self.support_build(changed).returncode, 0)
        self.assertEqual(self.engine_builds(), 5, "the rebuild must be a one-off")

    def test_engine_cache_key_reads_the_whole_go_version_output(self):
        # Same go1.28.10 token, different found output (the platform): the key is the output, not the third word.
        self.engine_fixture()
        versions = self.versions | {"go": "go1.28.10"}
        self.assertEqual(self.engine_build(versions).returncode, 0)
        mock = self.bin / "mock"
        mock.write_text(mock.read_text().replace("darwin/arm64", "darwin/amd64"))
        self.assertEqual(self.engine_build(versions).returncode, 0)
        self.assertEqual(self.engine_builds(), 10)

    def test_engine_reuse_prints_the_provenance_tools(self):
        self.engine_fixture()
        versions = self.versions | {"go": "go1.28.10", "xcode": "28.0"}
        self.assertEqual(self.engine_build(versions).returncode, 0)
        provenance = self.tree / "Packages/WGEXEngine/Binary/provenance.json"
        provenance.write_text(provenance.read_text().replace('"go1.28.10"', '"go1.28.10-recorded"'))
        result = self.engine_build(versions)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        reuse = [line for line in result.stdout.splitlines() if "using existing" in line]
        self.assertEqual(len(reuse), 1, result.stdout)
        self.assertIn("go1.28.10-recorded, Xcode 28.0 (99Z999)", reuse[0])

    def test_floor_edits_do_not_invalidate_engine_sources(self):
        self.run_command(["git", "init", "-q", "--template="]).check_returncode()
        command = [sys.executable, "-I", "Engine/scripts/source-digest.py"]
        original = self.run_command(command)
        self.assertEqual(original.returncode, 0, original.stderr)
        path = self.tree / "Toolchain.lock"
        path.write_text(path.read_text().replace('version = "go1.27.3"', 'version = "go1.28.0"')
                       .replace('version = "27.2"', 'version = "28.0"'))
        self.assertEqual(self.run_command(command).stdout, original.stdout)
        source = self.tree / "Engine/go/new.go"
        source.write_text("package fixture\n")
        self.assertNotEqual(self.run_command(command).stdout, original.stdout)

    SHA256 = re.compile(r"[0-9a-f]{64}")
    MODULE = re.compile(r"[a-z0-9][a-z0-9.\-]*(/[A-Za-z0-9._\-]+)+@v\d+\.\d+\.\d+(-[0-9A-Za-z.\-]+)?(\+incompatible)?")

    @classmethod
    def integrity_problems(cls, lock):
        """M1-46 F2: structure only (module@vX.Y.Z, https URL, 64-hex sha256), never a value or a fixed commit."""
        problems = []
        for tool, module in lock.get("go_tools", {}).items():
            if not (isinstance(module, str) and cls.MODULE.fullmatch(module)):
                problems.append(f"go_tools.{tool} is not module@vX.Y.Z")
        if not lock.get("go_tools"):
            problems.append("go_tools is empty")
        for section, name in (("sparkle", "archive"), ("iperf3", "asset")):
            record = lock.get(section, {})
            url, sha256, file = record.get("url"), record.get("sha256"), record.get(name)
            if not (isinstance(url, str) and re.fullmatch(r"https://[^\s/]+/\S+", url)):
                problems.append(f"{section}.url is not an https URL")
            if not (isinstance(sha256, str) and cls.SHA256.fullmatch(sha256)):
                problems.append(f"{section}.sha256 is not 64 lower-case hex digits")
            if not (isinstance(file, str) and file and isinstance(url, str) and url.endswith("/" + file)):
                problems.append(f"{section}.{name} is not the last component of its url")
            if not (isinstance(record.get("version"), str) and record["version"]):
                problems.append(f"{section}.version is missing")
        return problems

    def test_module_and_artefact_integrity_records_have_the_expected_shape(self):
        # These are offline module resolutions and immutable artefacts. A reviewed bump changes the values and must
        # stay green; no commit is needed, so a clone without any particular history passes too.
        self.assertEqual(self.integrity_problems(self.lock), [])

    def test_integrity_shape_check_rejects_malformed_records(self):
        good = self.lock
        self.assertEqual(self.integrity_problems(good), [])
        bumped = copy.deepcopy(good)
        bumped["sparkle"].update(version="9.9.9", archive="Sparkle-9.9.9.tar.xz", sha256="0" * 64,
                                 url="https://example.invalid/Sparkle-9.9.9.tar.xz")
        bumped["go_tools"]["staticcheck"] = "honnef.co/go/tools/cmd/staticcheck@v9.9.9"
        self.assertEqual(self.integrity_problems(bumped), [], "a reviewed bump must stay valid")
        bumped["go_tools"]["staticcheck"] = "github.com/foo/bar@v2.0.0+incompatible"
        self.assertEqual(self.integrity_problems(bumped), [], "a legal +incompatible version must stay valid")
        for label, mutate in (
                ("short sha256", lambda lock: lock["sparkle"].update(sha256="a" * 63)),
                ("upper-case sha256", lambda lock: lock["iperf3"].update(sha256="A" * 64)),
                ("plain http url", lambda lock: lock["iperf3"].update(url="http://example.invalid/" + lock["iperf3"]["asset"])),
                ("url that is not the asset", lambda lock: lock["sparkle"].update(archive="other.tar.xz")),
                ("module without a version", lambda lock: lock["go_tools"].update(staticcheck="honnef.co/go/tools/cmd/staticcheck")),
                ("module with another build suffix", lambda lock: lock["go_tools"].update(staticcheck="honnef.co/go/tools/cmd/staticcheck@v1.0.0+other")),
                ("module with a branch", lambda lock: lock["go_tools"].update(staticcheck="honnef.co/go/tools/cmd/staticcheck@main")),
                ("missing section", lambda lock: lock.pop("sparkle")),
                ("empty go_tools", lambda lock: lock.update(go_tools={}))):
            with self.subTest(label):
                broken = copy.deepcopy(good)
                mutate(broken)
                self.assertNotEqual(self.integrity_problems(broken), [])

    def test_lock_explains_offline_modules_and_artefact_integrity(self):
        comment = (ROOT / "Toolchain.lock").read_text()
        for phrase in ("exact module versions", "module cache", "artefact integrity"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, comment)

    def test_go_tool_modules_still_require_exact_versions(self):
        modules = self.lock["go_tools"] | {"staticcheck": "honnef.co/go/tools/cmd/staticcheck@v99.0.0"}
        self.env["TEST_GO_TOOLS"] = json.dumps(modules)
        result = self.doctor()
        self.assertNotEqual(result.returncode, 0)
        self.assertRegex(result.stdout, r"(?m)^FAIL +staticcheck +found .*@v99[.]0[.]0, expected ")

    def test_docs_and_lock_describe_minimum_versions(self):
        for name in ("README.md", "CONTRIBUTING.md", "Toolchain.lock"):
            with self.subTest(file=name):
                self.assertIn("minimum versions", (ROOT / name).read_text().lower(), name)
        for section in ("xcode", "swift"):
            self.assertNotIn("build", self.lock[section])


if __name__ == "__main__":
    unittest.main()
