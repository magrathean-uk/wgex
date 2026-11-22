# SPDX-License-Identifier: MIT
"""Run Linux provisioning logic with scratch state and mandatory fake commands."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class PeerSetupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"])
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        self.state.mkdir()
        # Stands in for /etc/wireguard, where wg-quick@wg0 reads wg0.conf at boot.
        (self.root / "wireguard").mkdir()
        (self.root / "bin").mkdir()
        (self.root / "fixture-only").touch()
        (self.root / "wg-present").touch()
        # Non-key placeholders; the fake wg never parses cryptographic input.
        for name in ["server.key", "client1.pub"]:
            (self.state / name).write_text("fixture input omitted\n")
        fake = self.root / "bin/fake"
        fake.write_text('''#!/bin/bash
set -eu
root="${WGEX_LAB_PEER_TEST_ROOT:?}"
name="${0##*/}"
printf '%s %s\\n' "$name" "$*" >>"$root/commands"
case "$name $*" in
  'ip link show wg0') test -f "$root/wg-present" ;;
  'ip link show eth0') test ! -f "$root/missing-uplink" ;;
  'ip link add wg0 type wireguard') touch "$root/wg-present" ;;
  'wg show wg0') test ! -f "$root/not-wireguard" ;;
  'wg syncconf wg0 '*) test -f "$root/state/owned" ;;
  'tc qdisc show dev '*) if [[ -f "$root/qdisc" ]]; then cat "$root/qdisc"; fi ;;
  'tc qdisc del dev '*) : >"$root/qdisc" ;;
esac
''')
        fake.chmod(0o700)
        for name in ["ip", "wg", "tc", "iperf3", "python3"]:
            (self.root / "bin" / name).symlink_to("fake")
        self.env = dict(os.environ, WGEX_LAB_PEER_TEST_ROOT=str(self.root), PATH=str(self.root / "bin") + os.pathsep + os.environ["PATH"])

    def run_script(self, name, *args):
        return subprocess.run(["bash", str(ROOT / "Tools/lab/lima" / name), "--dry-run", *args], env=self.env,
                              capture_output=True, check=False)

    def commands(self):
        path = self.root / "commands"
        return path.read_text() if path.exists() else ""

    def test_adoption_is_explicit_and_repeated_up_is_idempotent(self):
        refused = self.run_script("peer-provision.sh", "up", "https://deb.debian.org/debian")
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn(b"--adopt", refused.stderr)
        self.assertNotIn("syncconf", self.commands())
        for flags in [("--adopt",), ()]:
            result = self.run_script("peer-provision.sh", "up", "https://deb.debian.org/debian", *flags)
            self.assertEqual(result.returncode, 0, "fake peer setup failed")
            self.assertTrue((self.state / "owned").is_file())
        self.assertNotIn("ip link add", self.commands())

    def test_adoption_refuses_non_wireguard_interface(self):
        (self.root / "not-wireguard").touch()
        result = self.run_script("peer-provision.sh", "up", "https://deb.debian.org/debian", "--adopt")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.state / "owned").exists())
        self.assertNotIn("syncconf", self.commands())

    def test_missing_fault_cleanup_succeeds_without_touching_network_commands(self):
        for _ in range(2):
            self.assertEqual(self.run_script("peer-fault.sh", "cleanup").returncode, 0)
        self.assertEqual(self.commands(), "")
        check = self.run_script("peer-fault.sh", "check")
        self.assertNotEqual(check.returncode, 0)
        self.assertIn(b"peer up", check.stderr)

    def test_stale_fault_is_idempotent_and_foreign_qdisc_is_retained(self):
        (self.state / "owned").touch()
        (self.state / "netem-owned").write_text("eth0\n")
        (self.root / "qdisc").write_text("qdisc fq_codel 0: root refcnt 2\n")
        self.assertEqual(self.run_script("peer-fault.sh", "cleanup").returncode, 0)
        self.assertFalse((self.state / "netem-owned").exists())
        self.assertNotIn("qdisc del", self.commands())
        self.assertEqual(self.run_script("peer-fault.sh", "cleanup").returncode, 0)

    def test_owned_netem_is_removed_once(self):
        (self.state / "owned").touch()
        (self.state / "netem-owned").write_text("eth0\n")
        (self.root / "qdisc").write_text("qdisc netem 8001: root refcnt 2 limit 1000 loss 20%\n")
        for _ in range(2):
            self.assertEqual(self.run_script("peer-fault.sh", "cleanup").returncode, 0)
        self.assertEqual(self.commands().count("tc qdisc del dev eth0 root"), 1)

    def test_cleanup_of_a_disappeared_interface_is_idempotent(self):
        (self.state / "owned").touch()
        (self.state / "netem-owned").write_text("eth0\n")
        (self.root / "missing-uplink").touch()
        for _ in range(2):
            self.assertEqual(self.run_script("peer-fault.sh", "cleanup").returncode, 0)
        self.assertFalse((self.state / "netem-owned").exists())
        self.assertNotIn("tc ", self.commands())

    def test_fixture_seam_refuses_live_invocation(self):
        result = subprocess.run(["bash", str(ROOT / "Tools/lab/lima/peer-fault.sh"), "cleanup"], env=self.env, capture_output=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.commands(), "")
