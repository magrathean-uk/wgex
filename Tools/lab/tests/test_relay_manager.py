# SPDX-License-Identifier: MIT
"""Relay lifecycle uses fake process inventory; never reads/signals a host relay."""
import os
from pathlib import Path
import tempfile
import unittest

import test_live_replay as replay


class RelayInventory:
    def __init__(self, script, control):
        self.processes = {123: f'python3 -I -B {script} 192.168.64.1:51820 192.168.64.12:51820 --control {control}'}
        self.killed, self.started, self.clock = [], [], 0

    def candidates(self):
        return list(self.processes)

    def command(self, pid):
        return self.processes.get(pid, "")

    def listeners(self):
        return sorted(self.processes)

    def alive(self, pid):
        return pid in self.processes

    def terminate(self, pid):
        self.killed.append(pid)
        del self.processes[pid]

    def start(self, argv, log):
        self.started.append(argv)
        self.processes[456] = " ".join(argv)
        return 456

    def sleep(self, seconds):
        self.clock += seconds

    def monotonic(self):
        return self.clock


class RelayManagerTests(unittest.TestCase):
    def test_adopts_own_stable_relay_without_pid_file(self):
        manager = replay.module("manager", "relay-manager.py")
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            state = Path(directory)
            runner = RelayInventory(replay.ROOT / "Tools/lab/tart/host/udp-relay.py", state / "control.json")
            instance = manager.RelayManager(replay.ROOT, state, runner)
            instance.start()
            self.assertEqual((state / "relay.pid").read_text().strip(), "123")
            self.assertFalse(runner.started or runner.killed)

    def test_own_legacy_build_root_relay_is_restarted_and_can_be_stopped(self):
        manager = replay.module("legacy_manager", "relay-manager.py")
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            state = Path(directory)
            runner = RelayInventory(replay.ROOT / "Tools/lab/tart/host/udp-relay.py", "/fixture/old-build-root/control.json")
            instance = manager.RelayManager(replay.ROOT, state, runner)
            instance.start()
            self.assertEqual(runner.killed, [123])
            self.assertEqual(len(runner.started), 1)
            self.assertIn(str(state / "control.json"), runner.started[0])
            instance.stop()
            self.assertEqual(runner.killed, [123,456])

    def test_other_listener_is_retained_and_identified(self):
        manager = replay.module("foreign_manager", "relay-manager.py")
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            runner = RelayInventory(Path("/unrelated/udp-relay.py"), "/unrelated/control.json")
            instance = manager.RelayManager(replay.ROOT, Path(directory), runner)
            with self.assertRaisesRegex(RuntimeError, "123"):
                instance.start()
            self.assertFalse(runner.killed or runner.started)

    def test_macos_python_process_name_and_pid_identity_recheck(self):
        manager = replay.module("pid_manager", "relay-manager.py")
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            state = Path(directory)
            runner = RelayInventory(replay.ROOT / "Tools/lab/tart/host/udp-relay.py", state / "control.json")
            runner.processes[123] = runner.processes[123].replace("python3", "Python", 1)
            instance = manager.RelayManager(replay.ROOT, state, runner)
            self.assertIn(123, instance.owned())
            runner.processes[123] = "unrelated process"
            with self.assertRaisesRegex(RuntimeError, "identity changed"):
                instance.stop_pid(123)
            self.assertFalse(runner.killed)
