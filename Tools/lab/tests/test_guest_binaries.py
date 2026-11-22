# SPDX-License-Identifier: MIT
"""Read Mach-O load commands; staged guest executables are never launched here."""
import importlib.util
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[3]


class GuestBinaryTests(unittest.TestCase):
    def test_every_staged_guest_binary_supports_macos_26(self):
        spec = importlib.util.spec_from_file_location("binary_live", ROOT / "Tools/lab/verdict-live.py")
        live = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(live)
        binaries = live.guest_binary_paths(live.STATE.build_root(ROOT))
        self.assertEqual(set(binaries), {"leakprobe", "foreign-utun"})
        for name, binary in binaries.items():
            with self.subTest(binary=name):
                self.assertTrue(binary.is_file(), "just test tools must build guest binaries before this check")
                result = subprocess.run(["xcrun", "otool", "-l", str(binary)], capture_output=True, check=False)
                self.assertEqual(result.returncode, 0)
                commands = re.findall(r"cmd LC_BUILD_VERSION\n(.*?)(?=Load command|\Z)", result.stdout.decode(), re.S)
                self.assertTrue(commands, "each Mach-O architecture requires LC_BUILD_VERSION")
                for command in commands:
                    self.assertRegex(command, r"platform (?:1|MACOS)\b")
                    match = re.search(r"\bminos (\d+(?:\.\d+){0,2})", command)
                    self.assertIsNotNone(match)
                    version = tuple(map(int, match[1].split(".")))
                    self.assertLessEqual((version + (0, 0))[:3], (26, 0, 0), "guest is macOS 26")
