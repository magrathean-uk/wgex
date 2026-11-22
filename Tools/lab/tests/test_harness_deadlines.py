# SPDX-License-Identifier: MIT
"""M1-10i: harness deadlines come from harness-deadlines.sh and scale with WGEX_LAB_HARNESS_SCALE; host load is
recorded in verdict.json and the capture metadata and never changes a verdict. One test per changed deadline; each
runs at scale 2 and at the default, and computes the expected value from the base, not through HARNESS.seconds."""
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import test_gui_element as element
import test_live_replay as replay
import test_startup_position as startup
from test_relay_manager import RelayInventory
from test_third_live import QuitRunner

LIVE, ROOT = replay.LIVE, replay.ROOT
H = LIVE.HARNESS
SCALES = ("2", None)
SCALE_ONLY_NAMES = {"SSH_CONNECT_TIMEOUT", "SSH_ALIVE_COUNT", "CONNECT_PROBE", "WAIT_STOPPED", "WAIT_READY", "PEER_SHELL"}
RELAY_NAMES = {"RELAY_INVENTORY", "RELAY_STOP", "RELAY_BIND_SETTLE"}
OVERLOADED = dict(sampledAt="2026-10-30T02:39:00+00:00", available=True, load1=56.57, load5=60.85, load15=64.27, cores=12)
QUIET = dict(sampledAt="2026-10-30T02:45:00+00:00", available=True, load1=3.1, load5=4.0, load15=5.2, cores=12)


def expected(name, scale):
    factor = int(scale) if scale else H.BASES["HARNESS_SCALE_DEFAULT"]
    return max(H.BASES["HARNESS_" + name] * factor, H.BASES.get("HARNESS_" + name + "_MIN", 0))


def scaled(scale):
    environ = {key: value for key, value in os.environ.items() if key != H.SCALE_VARIABLE}
    if scale:
        environ[H.SCALE_VARIABLE] = scale
    return patch.dict(os.environ, environ, clear=True)


class Timed(replay.RecordedRunner):
    """Records each command's subprocess timeout, environment and simulated start time."""

    def __init__(self):
        super().__init__()
        self.calls = []

    def run(self, argv, data=None, timeout=100, env=None):
        self.calls.append(dict(argv=list(argv), timeout=timeout, env=env, at=self.clock))
        return super().run(argv, data=data, timeout=timeout, env=env)


class TimedQuit(QuitRunner):
    def __init__(self):
        super().__init__("never")
        self.calls = []

    def run(self, argv, **kwargs):
        self.calls.append(dict(argv=list(argv), timeout=kwargs.get("timeout"), env=kwargs.get("env"), at=self.clock))
        return super().run(argv, **kwargs)


def session(runner=None):
    runner = runner or Timed()
    return runner, LIVE.Session("fixture", {}, runner=runner)


class Process:
    def __init__(self):
        self.timeouts = []

    def wait(self, timeout=None):
        self.timeouts.append(timeout)
        return 0

    def poll(self):
        return 0


class SourceTests(unittest.TestCase):
    def test_one_source_names_every_harness_deadline(self):
        live = (ROOT / "Tools/lab/verdict-live.py").read_text()
        library = (ROOT / "Tools/lab/tart/lib.sh").read_text()
        used = set(re.findall(r'HARNESS\.seconds\("([A-Z0-9_]+)"', live))
        used |= {name for pair in re.findall(r'HARNESS\.seconds\("([A-Z0-9_]+)" if [^"]+ else "([A-Z0-9_]+)"\)', live) for name in pair}
        self.assertEqual(used, set(H.names()) - SCALE_ONLY_NAMES - RELAY_NAMES)
        for name in SCALE_ONLY_NAMES:
            self.assertIn("HARNESS_" + name + " ", library.replace("*", " "), name)
        relay = (ROOT / "Tools/lab/relay-manager.py").read_text()
        self.assertEqual(set(re.findall(r'HARNESS\.seconds\("([A-Z0-9_]+)"\)', relay)), RELAY_NAMES)
        self.assertIn('source "$LAB_DIR/../harness-deadlines.sh"', library)

    def test_literal_seconds_left_in_the_driver_are_expectations_or_long_steps(self):
        live = (ROOT / "Tools/lab/verdict-live.py").read_text()
        found = re.findall(r'(?:timeout|deadline)=\d+|monotonic\(\) \+ \d+|await_ssh\(\d+|min\(\d+, |"--seconds", "\d+"|--seconds \d+', live)
        # Harness, unchanged: CommandRunner default (never reached: Session.command always passes one), build, install,
        # observe. Expectations: await_status's 60 s default and the rows' 120 s (three, plus ONDEMAND-ETH's arm) and 60 s recovery
        # waits (two, plus ONDEMAND-ETH's three: after the daemon restart, after en0 returns and for blocked once the rule is withdrawn).
        # M04-T13: 25 s guest action / 30 s transport caps contain the unscaled 15 s rollback expectation.
        self.assertEqual(sorted(found), sorted(["deadline=25", "timeout=30", "timeout=100", "timeout=1800", "timeout=900", "deadline=600", "timeout=60",
                                                "timeout=60", "timeout=60", "timeout=60", "timeout=60",
                                                "timeout=120", "timeout=120", "timeout=120", "timeout=120"]))

    def test_literal_seconds_left_in_profile_and_relay_manager(self):
        profile = (ROOT / "Tools/lab/profile.sh").read_text()
        alarms = re.findall(r"""'alarm shift; exec @ARGV or die "exec failed\\n"' (\S+) "\$peer" shell wg-peer""", profile)
        self.assertEqual(alarms, ['"$LAB_PEER_SHELL"'] * 3)
        self.assertEqual(profile.count("alarm shift"), 3)
        relay = (ROOT / "Tools/lab/relay-manager.py").read_text()
        # The 0.1 s stop-loop poll is pacing, not a deadline.
        self.assertEqual(re.findall(r"timeout=\d+|monotonic\(\) \+ \d+|sleep\(\d+\)", relay), [])

    def test_file_format_and_scale_bounds(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            bad = Path(directory) / "bad.sh"
            for text in ["HARNESS_X=1\nHARNESS_X=2\n", "HARNESS_X=$(id)\n", "OTHER=1\n", "HARNESS_X=0\n"]:
                bad.write_text(text)
                with self.assertRaises(ValueError, msg=text):
                    H.read_bases(bad)
        for raw in ["0", "9", "x", "4.0", " 4"]:
            with self.assertRaises(ValueError, msg=raw):
                H.scale({H.SCALE_VARIABLE: raw})
            with scaled(raw), self.assertRaises(ValueError):
                session()
        self.assertEqual(H.scale({}), 4)

    def test_default_values_are_at_least_four_times_the_old_ones(self):
        with scaled(None):
            for name in H.names():
                self.assertGreaterEqual(H.seconds(name), 4 * H.BASES["HARNESS_" + name], name)
            self.assertGreaterEqual(H.seconds("READINESS_ATTEMPT"), 60)

    def test_lib_sh_bounds_scale_and_connect_accepts_the_python_budget(self):
        library = str(ROOT / "Tools/lab/tart/lib.sh")
        script = ('source "$1"; LAB_KNOWN_HOSTS=/dev/null; lab_harness; '
                  'printf "%s\\n" "$LAB_CONNECT_PROBE" "$LAB_WAIT_STOPPED" "$LAB_WAIT_READY" "${LAB_SSH[*]}" "$LAB_PEER_SHELL"')
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                out = subprocess.run(["bash", "-c", script, "fixture", library], capture_output=True, check=True, text=True).stdout.splitlines()
                self.assertEqual(out[:3], [str(expected(name, scale)) for name in ("CONNECT_PROBE", "WAIT_STOPPED", "WAIT_READY")])
                self.assertIn(f"-o ConnectTimeout={expected('SSH_CONNECT_TIMEOUT', scale)} ", out[3])
                self.assertIn(f"-o ServerAliveInterval=5 -o ServerAliveCountMax={expected('SSH_ALIVE_COUNT', scale)} ", out[3])
                self.assertEqual(out[4], str(expected("PEER_SHELL", scale)))
        connect = 'source "$1"; LAB_DRY=1; LAB_KNOWN_HOSTS=/dev/null; lab_harness; lab_connect'
        for budget, code in [(str(expected("CONNECT_BUDGET", None)), 0), ("901", 1)]:
            with scaled(None):
                result = subprocess.run(["bash", "-c", connect, "fixture", library], capture_output=True,
                                        env=dict(os.environ, WGEX_LAB_CONNECT_TIMEOUT=budget))
            self.assertEqual(result.returncode, code, budget)


    def lib_tree(self, root):
        """A copy of the lab layout: root/Tools/lab/harness-deadlines.sh, and root/Tools/lab/tart a symlink to a directory
        elsewhere that holds lib.sh and no harness-deadlines.sh next to it (M1-10s LOW-1)."""
        lab = Path(root) / "tree/Tools/lab"
        real = Path(root) / "elsewhere/real/tart"
        lab.mkdir(parents=True)
        real.mkdir(parents=True)
        (lab / "harness-deadlines.sh").write_text((ROOT / "Tools/lab/harness-deadlines.sh").read_text())
        (real / "lib.sh").write_text((ROOT / "Tools/lab/tart/lib.sh").read_text())
        (lab / "tart").symlink_to(real)
        return lab, real

    def test_lib_sh_guard_tests_the_path_it_sources_under_a_symlinked_tart_directory(self):
        """M1-10s LOW-1: the guard named tree/Tools/lab/harness-deadlines.sh (lexical "..") while the source line resolved
        ".." physically; with tart a symlink the guard passed and the source then failed with the bare "No such file"."""
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as root:
            lab, real = self.lib_tree(root)
            result = subprocess.run(["bash", "-c", 'source "$1"', "x", str(lab / "tart/lib.sh")], capture_output=True, text=True, cwd=root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("lab: harness deadlines missing:", result.stderr)
            self.assertIn("tested as", result.stderr)
            self.assertNotIn("No such file or directory", result.stderr)
            # The file the source line reaches (physically next to the real tart directory) is the one tested and loaded.
            (real.parent / "harness-deadlines.sh").write_text("HARNESS_SCALE_DEFAULT=7\n")
            result = subprocess.run(["bash", "-c", 'source "$1"; printf "%s" "$HARNESS_SCALE_DEFAULT"', "x", str(lab / "tart/lib.sh")],
                                    capture_output=True, text=True, cwd=root)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "7", ""))

    def test_lib_sh_resolves_its_own_location_with_cdpath_set(self):
        """M1-10s NOTE-1: CDPATH containing "." made cd print the directory into LAB_DIR and fail on a relative BASH_SOURCE."""
        script = 'source "$1"; printf "%s\\n%s" "$LAB_DIR" "$LAB_ROOT"'
        for cdpath in (".:/tmp", ":", "/tmp"):
            with self.subTest(cdpath=cdpath):
                result = subprocess.run(["bash", "-c", script, "x", "tart/lib.sh"], capture_output=True, text=True,
                                        cwd=ROOT / "Tools/lab", env=dict(os.environ, CDPATH=cdpath))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, "")
                lab_dir, lab_root = result.stdout.split("\n")
                self.assertEqual((os.path.realpath(lab_dir), os.path.realpath(lab_root)),
                                 (os.path.realpath(ROOT / "Tools/lab/tart"), os.path.realpath(ROOT)))

    def test_every_cd_in_lib_sh_is_cdpath_safe(self):
        library = (ROOT / "Tools/lab/tart/lib.sh").read_text()
        unsafe = [line for line in library.splitlines() if re.search(r"(?<![\w-])cd (?!--)", line) and "CDPATH='' cd" not in line
                  and not line.lstrip().startswith("#")]
        self.assertEqual(unsafe, [])
        self.assertEqual(len(re.findall(r"CDPATH='' cd -- ", library)), library.count("cd -- "))


class DriverDeadlineTests(unittest.TestCase):
    def test_command_default(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                runner, live = session()
                live.lab("relay", "start")
                self.assertEqual(runner.calls[-1]["timeout"], expected("COMMAND", scale))

    def test_ssh_command_default_and_background_ssh(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                runner, live = session()
                live.ssh("true")
                call = runner.calls[-1]
                self.assertEqual(call["env"]["WGEX_LAB_SSH_DEADLINE"], str(expected("SSH_COMMAND", scale)))
                self.assertEqual(call["timeout"], expected("SSH_COMMAND", scale) + 10)
                with patch.object(runner, "start", return_value=Process()) as start:
                    live.start(["just", "lab", "ssh", "--", "true"])
                self.assertEqual(start.call_args.kwargs["env"]["WGEX_LAB_SSH_DEADLINE"], str(expected("SSH_COMMAND", scale)))

    def test_connect_budget(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                runner, live = session()
                live.ssh("true", deadline=900)
                self.assertEqual(runner.calls[-1]["env"]["WGEX_LAB_CONNECT_TIMEOUT"], str(expected("CONNECT_BUDGET", scale)))
                live.ssh("true", deadline=7)
                self.assertEqual(runner.calls[-1]["env"]["WGEX_LAB_CONNECT_TIMEOUT"], "7")

    def test_restore(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                runner, live = session()
                with patch.object(live, "check_peer_key"), patch.object(live, "await_guest", side_effect=RuntimeError("stop")):
                    with self.assertRaises(RuntimeError):
                        live.prepare("default")
                restore = next(c for c in runner.calls if c["argv"][2:3] == ["restore"])
                self.assertEqual(restore["timeout"], expected("RESTORE", scale))

    def test_readiness_and_readiness_attempt(self):
        class Missing(Timed):
            def run(self, argv, **kwargs):
                result = super().run(argv, **kwargs)
                return self.reply(argv, code=1) if argv[-1] == "true" else result
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                runner, live = session(Missing())
                started = runner.clock
                with self.assertRaises(LIVE.PollDeadline):
                    live.await_guest()
                budget, attempt = expected("READINESS", scale), expected("READINESS_ATTEMPT", scale)
                self.assertGreaterEqual(runner.clock - started, budget)
                self.assertLess(runner.clock - started, budget + 1)
                first = next(c for c in runner.calls if c["argv"][-1] == "true")
                self.assertEqual(first["env"]["WGEX_LAB_SSH_DEADLINE"], str(attempt))
                self.assertEqual(first["env"]["WGEX_LAB_CONNECT_TIMEOUT"], str(attempt))
                self.assertGreaterEqual(attempt, 60)
                self.assertGreater(sum(c["argv"][-1] == "true" for c in runner.calls), 2, "retries with backoff")

    def test_ssh_retry_attempt(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                _, live = session()
                with patch.object(live, "ssh", side_effect=[RuntimeError("down"), b""]) as ssh:
                    live.await_ssh(1000, "unused")
                self.assertEqual([c.kwargs["timeout"] for c in ssh.call_args_list], [expected("SSH_RETRY_ATTEMPT", scale)] * 2)

    def test_ssh_return_after_reboot(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                _, live = session()
                with patch.object(live, "quit_app"), patch.object(live, "guest_action"), patch.object(live, "daemon_pid", return_value=282), \
                        patch.object(live, "await_ssh", side_effect=RuntimeError("stop")) as wait, self.assertRaises(RuntimeError):
                    live.reboot_probe()
                self.assertEqual(wait.call_args.args[0], expected("SSH_RETURN_AFTER_REBOOT", scale))

    def test_en0_loss_trigger_and_ssh_return(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                _, live = session()
                with patch.object(live, "guest_action") as action, \
                        patch.object(live, "await_ssh", side_effect=RuntimeError("stop")) as wait, self.assertRaises(RuntimeError):
                    live.en0_loss("default", 20)
                trigger = expected("EN0_LOSS_TRIGGER", scale)
                self.assertEqual((action.call_args.kwargs["deadline"], action.call_args.kwargs["timeout"]), (trigger, trigger + 10))
                self.assertEqual(wait.call_args.args[0], expected("SSH_RETURN_AFTER_EN0_LOSS", scale))

    def test_en0_generator_record(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                runner, live = session()
                reads = []
                def ssh(command, **kw):
                    if command.startswith("cat "):
                        reads.append(runner.clock)
                    return b""
                collect = "down 1700000000.1\nup 1700000020.1\n__SAMPLES__\n"
                with patch.object(live, "ssh", side_effect=ssh), patch.object(live, "await_ssh"), \
                        patch.object(live, "guest_action", side_effect=lambda name, *a, **k: collect.encode() if name == "en0-collect" else b""):
                    with self.assertRaisesRegex(RuntimeError, "generator record missing"):
                        live.en0_loss("full4", 20)
                self.assertGreaterEqual(reads[-1] - reads[0], expected("EN0_GENERATOR_RECORD", scale))
                self.assertLess(reads[-1] - reads[0], expected("EN0_GENERATOR_RECORD", scale) + 1.5)

    def test_quit_step_wait_and_probe(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                runner = TimedQuit()
                live = LIVE.Session("fixture", {}, runner=runner)
                started = runner.clock
                with self.assertRaisesRegex(RuntimeError, "app quit deadline"):
                    live.quit_app()
                step, wait, probe = (expected(name, scale) for name in ("QUIT_STEP", "QUIT_WAIT", "QUIT_PROBE"))
                joined = [" ".join(c["argv"]) for c in runner.calls]
                activate = runner.calls[0]
                self.assertIn("gui activate WGEX", joined[0])
                self.assertEqual((activate["timeout"], activate["env"]["WGEX_LAB_SSH_DEADLINE"]), (step, str(step)))
                quit_event = next(c for c, j in zip(runner.calls, joined) if 'to quit' in j)
                self.assertEqual((quit_event["timeout"], quit_event["env"]["WGEX_LAB_SSH_DEADLINE"]), (step, str(step)))
                pkill = next(c for c, j in zip(runner.calls, joined) if "pkill -x WGEX" in j)
                self.assertEqual((pkill["timeout"], pkill["env"]["WGEX_LAB_SSH_DEADLINE"]), (probe, str(probe)))
                probes = [c for c, j in zip(runner.calls, joined) if "exists menu bar 1" in j or "pgrep -x WGEX" in j]
                self.assertEqual(probes[0]["timeout"], probe)
                self.assertTrue(all(c["timeout"] <= probe for c in probes))
                # Menu probe loop, then one exit wait each after the Apple event and pkill.
                self.assertGreaterEqual(runner.clock - started, 3 * wait)
                self.assertLess(runner.clock - started, 3 * wait + 2)

    def test_status_poll(self):
        reply = b'{"phase":"reasserting","protection":"blocked"}'
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                poll = expected("STATUS_POLL", scale)
                _, live = session()
                with patch.object(live, "ssh", return_value=reply) as ssh, patch.object(live, "status_stream", return_value=[]):
                    live.await_status("blocked", timeout=1000)
                    self.assertEqual((ssh.call_args.kwargs["deadline"], ssh.call_args.kwargs["timeout"]), (poll, poll))
                    live.await_loss_blocked("fixture")
                    self.assertEqual((ssh.call_args.kwargs["deadline"], ssh.call_args.kwargs["timeout"]), (poll, poll))
                    live.await_status("blocked", timeout=2)
                    self.assertLessEqual(ssh.call_args.kwargs["timeout"], 2, "the expectation deadline still bounds the poll")

    def test_diagnostics_tail(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                tail = expected("DIAGNOSTICS_TAIL", scale)
                _, live = session()
                with patch.object(live, "guest_action", return_value=b"") as action:
                    live.diagnostics_lines()
                    live.status_stream()
                    with self.assertRaises(LIVE.PollDeadline):
                        live.poll_deadline("fixture", 1)
                self.assertEqual([(c.kwargs["deadline"], c.kwargs["timeout"]) for c in action.call_args_list], [(tail, tail)] * 3)

    def test_boot_observe(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                _, live = session()
                with patch.object(live, "guest_action", side_effect=RuntimeError("unreadable")) as action:
                    self.assertIsNone(live.boot_observe())
                observe = expected("BOOT_OBSERVE", scale)
                self.assertEqual((action.call_args.kwargs["deadline"], action.call_args.kwargs["timeout"]), (observe, observe + 10))

    def elapsed(self, runner, operation, error):
        started = runner.clock
        with self.assertRaises(error):
            operation()
        return runner.clock - started

    def test_gui_search_and_short_search(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                runner, live = session()
                search, short = expected("GUI_SEARCH", scale), expected("GUI_SEARCH_SHORT", scale)
                took = self.elapsed(runner, lambda: live.click("No such control"), ValueError)
                self.assertTrue(search <= took < search + 1, took)
                took = self.elapsed(runner, lambda: live.click_first([(None, "wgex.none.a"), (None, "wgex.none.b")]), ValueError)
                self.assertTrue(search + short <= took < search + short + 1, took)

    def test_gui_settings_open(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                runner, live = session()
                took = self.elapsed(runner, live.open_settings, LIVE.RowFailure)
                self.assertTrue(expected("GUI_SETTINGS_OPEN", scale) <= took < expected("GUI_SETTINGS_OPEN", scale) + 1.5, took)

    def test_gui_import_review(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                runner, live = session()
                runner.review_remaining = 10 ** 6
                took = self.elapsed(runner, live.import_review, ValueError)
                self.assertTrue(expected("GUI_IMPORT_REVIEW", scale) <= took < expected("GUI_IMPORT_REVIEW", scale) + 1, took)

    def test_gui_profile_select(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                runner, live = session()
                with patch.object(live, "guest_action", return_value=b"not a uuid"):
                    took = self.elapsed(runner, lambda: live.select_profile("full4"), ValueError)
                self.assertTrue(expected("GUI_PROFILE_SELECT", scale) <= took < expected("GUI_PROFILE_SELECT", scale) + 1, took)

    def test_gui_title_settle(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                runner = Timed()
                runner.auto_select, runner.keys_work = False, False
                replay.LiveReplayTests().run_recorded("M5.1-08", runner, accepted=False)
                keys = max(i for i, c in enumerate(runner.calls) if c["argv"][2:4] == ["gui", "keys"])
                after = next(c for c in runner.calls[keys + 1:] if c["argv"][2:4] != ["gui", "dump"])
                settle = expected("GUI_TITLE_SETTLE", scale)
                self.assertTrue(settle <= after["at"] - runner.calls[keys]["at"] < settle + 1)

    def test_lockdown_confirm(self):
        """M1-10o fix pass 2 (F3): a second press only when the toggle reads off; reading on, the journal gets a second
        LOCKDOWN_CONFIRM without a press; unreadable, the row stops after the first."""
        for scale in SCALES:
            for toggle, waits, presses in ((False, 2, 2), (True, 2, 1), (None, 1, 1)):
                with self.subTest(scale=scale, toggle=toggle), scaled(scale):
                    runner, live = session()
                    with patch.object(live, "lab"), patch.object(live, "click_id") as click, \
                            patch.object(live, "journal_lockdown", return_value=False), patch.object(live, "lockdown_toggle", return_value=toggle):
                        took = self.elapsed(runner, lambda: live.set_lockdown(True), LIVE.RowFailure)
                    confirm = expected("LOCKDOWN_CONFIRM", scale)
                    self.assertTrue(waits * confirm <= took < waits * confirm + 2, took)
                    self.assertEqual(click.call_count, presses)

    def test_boot_intent_confirm(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                runner, live = session()
                with patch.object(live, "open_settings", return_value="2"), patch.object(live, "click_first"), patch.object(live, "click"), \
                        patch.object(live, "select_settings_tab"), patch.object(live, "boot_intent", return_value=False):
                    took = self.elapsed(runner, lambda: live.set_startup_boot("00000000-0000-0000-0000-000000000000"), LIVE.RowFailure)
                confirm = expected("BOOT_INTENT_CONFIRM", scale)
                self.assertTrue(confirm <= took < confirm + 1, took)

    def test_allow_lan_confirm(self):
        """M1-10t (M1-10r VERIFY N3): Allow LAN's compare-and-press waits LOCKDOWN_CONFIRM after each press and presses only
        while the toggle reads on: on at both reads, two presses and two waits; reading off, one wait and no press;
        unreadable, neither."""
        for scale in SCALES:
            for toggle, waits, presses in ((True, 2, 2), (False, 1, 0), (None, 0, 0)):
                with self.subTest(scale=scale, toggle=toggle), scaled(scale):
                    runner, live = session()
                    with patch.object(live, "lab"), patch.object(live, "click_id") as click, \
                            patch.object(live, "journal_allow_lan", return_value=True), patch.object(live, "toggle_value", return_value=toggle):
                        took = self.elapsed(runner, live.set_allow_lan_off, LIVE.RowFailure)
                    confirm = expected("LOCKDOWN_CONFIRM", scale)
                    self.assertTrue(waits * confirm <= took < waits * confirm + 2, took)
                    self.assertEqual(click.call_count, presses)

    def position_session(self, *dumps, **kwargs):
        runner = element.DumpRunner(dumps, **kwargs)
        return runner, LIVE.Session("fixture", {}, runner=runner)

    def test_startup_position_search_is_bounded_by_gui_search(self):
        """M1-10t: a group that never shows its buttons is searched for GUI_SEARCH, then named."""
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                runner, live = self.position_session(startup.SERVICE.replace(startup.GROUP, "wgex.onboarding.other"))
                took = self.elapsed(runner, lambda: live.select_startup_option("1", "boot"), LIVE.RowFailure)
                search = expected("GUI_SEARCH", scale)
                self.assertTrue(search <= took < search + 1, took)
                self.assertEqual(element.gui(runner, "press"), [])

    def test_startup_position_confirm_is_bounded_by_boot_intent_confirm(self):
        """M1-10t: after the press, the radio values that never change are read for BOOT_INTENT_CONFIRM, then named."""
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                runner, live = self.position_session(startup.SERVICE)
                took = self.elapsed(runner, lambda: live.select_startup_option("1", "boot"), LIVE.RowFailure)
                confirm = expected("BOOT_INTENT_CONFIRM", scale)
                self.assertTrue(confirm <= took < confirm + 1, took)
                self.assertEqual(len(element.gui(runner, "press")), 1)

    def test_startup_position_miss_and_ambiguous_layout_wait_for_nothing(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                runner, live = self.position_session(startup.SERVICE, press=b"path=miss\n")
                self.assertLess(self.elapsed(runner, lambda: live.select_startup_option("1", "boot"), LIVE.RowFailure), 1)
                mirrored = startup.with_frames(startup.SERVICE, [(814, 744), (692, 744), (466, 744)])
                runner, live = self.position_session(mirrored)
                self.assertLess(self.elapsed(runner, lambda: live.select_startup_option("1", "boot"), LIVE.RowFailure), 1)
                self.assertEqual(element.gui(runner, "press"), [])

    def test_startup_position_dump_failure_is_bounded_by_gui_search(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                runner = startup.FailingDumpRunner([startup.SERVICE])
                live = LIVE.Session("fixture", {}, runner=runner)
                took = self.elapsed(runner, lambda: live.select_startup_option("1", "boot"), LIVE.RowFailure)
                search = expected("GUI_SEARCH", scale)
                self.assertTrue(search <= took < search + 2, took)

    def test_receiver_ready(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                runner, live = session()
                with patch.object(live, "guest_file"), patch.object(live, "peer_file"), patch.object(live, "start"), \
                        patch.object(live, "peer", return_value=b""):
                    took = self.elapsed(runner, lambda: live.start_receivers(dict(format="marker")), RuntimeError)
                self.assertTrue(expected("RECEIVER_READY", scale) <= took < expected("RECEIVER_READY", scale) + 1, took)

    def test_receiver_lifetime_is_a_scaled_cap_and_the_row_stops_both(self):
        for scale, lifetime in [("1", 900), ("2", 1800), (None, 3600)]:
            with self.subTest(scale=scale), scaled(scale):
                self.assertEqual(expected("RECEIVER_LIFETIME", scale), lifetime)
                runner, live = session()
                peer = MagicMock(return_value=b'{"ready":true}')
                with patch.object(live, "guest_file"), patch.object(live, "peer_file"), patch.object(live, "start") as start, \
                        patch.object(live, "peer", peer):
                    (live.output / "host.ready").write_text("{}")
                    live.start_receivers(dict(format="marker"))
                    host = start.call_args.args[0]
                    self.assertEqual(host[host.index("--seconds") + 1], str(lifetime))
                    self.assertIn(f" --seconds {lifetime} ", peer.call_args_list[0].args[2])
                    live.processes = [Process()]
                    live.collect()
                self.assertTrue((live.output / "host.stop").exists())
                self.assertIn(("sudo", "-n", "touch", live.peer_stage + "/peer.stop"), [c.args for c in peer.call_args_list])

    def test_system_resolve_and_generator_wait(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                _, live = session()
                process = Process()
                def ssh(command, **kw):
                    return b'{"windows":[]}' if command.startswith("cat ") else b""
                with patch.object(live, "start", return_value=process), patch.object(live, "ssh", side_effect=ssh) as calls, \
                        patch.object(live, "sample_phase"):
                    live.generate("blocked")
                query = next(c for c in calls.call_args_list if "system-resolve" in c.args[0])
                self.assertEqual(query.kwargs["timeout"], expected("SYSTEM_RESOLVE", scale))
                self.assertEqual(process.timeouts, [expected("GENERATOR_WAIT", scale)])

    def test_iperf3_ready_and_client(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                runner, live = session()
                with patch.object(live, "ssh", return_value=b"present"), patch.object(live, "peer", return_value=b""):
                    took = self.elapsed(runner, live.iperf, RuntimeError)
                self.assertTrue(expected("IPERF3_READY", scale) <= took < expected("IPERF3_READY", scale) + 1, took)
                result = json.dumps(dict(end=dict(sum_received=dict(bits_per_second=2e8)))).encode()
                with patch.object(live, "ssh", side_effect=[b"present", result]) as ssh, patch.object(live, "peer", return_value=b"LISTEN"):
                    live.iperf()
                self.assertEqual(ssh.call_args.kwargs["timeout"], expected("IPERF3_CLIENT", scale))

    def test_receiver_record_and_process_stop(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                runner, live = session()
                process = Process()
                live.receiver_started, live.processes = True, [process]
                with patch.object(live, "peer", return_value=b""):
                    started = runner.clock
                    self.assertIn("receiver collection incomplete", live.collect())
                record = expected("RECEIVER_RECORD", scale)
                self.assertTrue(record <= runner.clock - started < record + 1.5)
                self.assertEqual(process.timeouts, [expected("PROCESS_STOP", scale)])

    def test_pcap_read(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale):
                runner = Timed()
                replay.LiveReplayTests().run_recorded("M5.1-04", runner)
                reads = [c for c in runner.calls if c["argv"][0] == "tcpdump"]
                self.assertTrue(reads)
                self.assertTrue(all(c["timeout"] == expected("PCAP_READ", scale) for c in reads))


class RelayDeadlineTests(unittest.TestCase):
    def manager(self, directory, runner=None):
        module = replay.module("deadline_relay_manager", "relay-manager.py")
        state = Path(directory)
        runner = runner or RelayInventory(ROOT / "Tools/lab/tart/host/udp-relay.py", state / "control.json")
        return module, runner, module.RelayManager(ROOT, state, runner)

    def test_relay_inventory(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale), tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
                module, _, _ = self.manager(directory)
                result = subprocess.CompletedProcess([], 1, b"", b"")
                with patch.object(module.subprocess, "run", return_value=result) as run:
                    module.RelayRunner().candidates()
                    module.RelayRunner().command(123)
                self.assertEqual([c.kwargs["timeout"] for c in run.call_args_list], [expected("RELAY_INVENTORY", scale)] * 2)

    def test_relay_stop(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale), tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
                _, runner, manager = self.manager(directory)
                runner.terminate = lambda pid: runner.killed.append(pid)
                with self.assertRaisesRegex(RuntimeError, "did not stop"):
                    manager.stop_pid(123)
                stop = expected("RELAY_STOP", scale)
                self.assertTrue(stop <= runner.clock < stop + 0.2, runner.clock)

    def test_relay_bind_settle(self):
        for scale in SCALES:
            with self.subTest(scale=scale), scaled(scale), tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
                _, runner, manager = self.manager(directory)
                runner.processes.clear()
                self.assertEqual(manager.start(), "relay running")
                self.assertEqual(runner.clock, expected("RELAY_BIND_SETTLE", scale))

    def test_relay_refuses_an_invalid_scale(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            module, _, _ = self.manager(directory)
            for raw in ["0", "9", "x"]:
                with self.subTest(raw=raw), scaled(raw), patch("sys.argv", ["relay-manager.py", "status"]), \
                        patch("sys.stderr", new_callable=io.StringIO) as error, patch.object(module, "RelayManager") as manager:
                    self.assertEqual(module.main(), 1)
                    self.assertIn("WGEX_LAB_HARNESS_SCALE must be an integer 1..8", error.getvalue())
                    manager.assert_not_called()


class HostLoadTests(unittest.TestCase):
    def test_sample_parses_sysctl_and_never_raises(self):
        def reply(stdout, code=0):
            return lambda argv, **kw: subprocess.CompletedProcess(argv, code, stdout, b"")
        sample = H.host_load(reply(b"{ 56.57 60.85 64.27 }\n12\n"))
        self.assertEqual({k: sample[k] for k in ("available", "load1", "load5", "load15", "cores")},
                         dict(available=True, load1=56.57, load5=60.85, load15=64.27, cores=12))
        self.assertFalse(H.host_load(reply(b"garbage\n"))["available"])
        self.assertFalse(H.host_load(reply(b"{ 1.0 1.0 1.0 }\n12\n", code=1))["available"])
        self.assertFalse(H.host_load(MagicMock(side_effect=OSError("no sysctl")))["available"])
        self.assertTrue(H.overloaded(OVERLOADED))
        self.assertFalse(H.overloaded(dict(OVERLOADED, load1=24.0)), "the rule is strictly more than 2 x cores")
        self.assertIsNone(H.warning(QUIET, "start"))

    def run_dry(self, row, samples):
        runner = replay.module("harness_dry_run", "verdict-run.py")
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            with patch.object(runner.HARNESS, "host_load", side_effect=samples), patch("sys.stderr", stderr), \
                    patch("sys.stdout", io.StringIO()):
                code = runner.main([row, "--dry-run", "--report-root", directory])
            report = json.loads((Path(directory) / row / "verdict.json").read_text())
        return code, report, stderr.getvalue()

    def test_host_load_lands_in_the_dry_run_verdict_and_never_changes_it(self):
        for row in ["M5.3-10", "REBOOT-INTENT"]:
            quiet_code, quiet, quiet_err = self.run_dry(row, [QUIET, QUIET])
            loaded_code, loaded, loaded_err = self.run_dry(row, [OVERLOADED, OVERLOADED])
            self.assertEqual(quiet["hostLoad"]["start"], QUIET)
            self.assertEqual(loaded["hostLoad"]["end"], OVERLOADED)
            self.assertTrue(loaded["hostLoad"]["overloaded"])
            self.assertFalse(quiet["hostLoad"]["overloaded"])
            self.assertEqual(loaded["hostLoad"]["harnessScale"], H.scale())
            self.assertEqual((quiet_code, quiet["expectationsMet"]), (loaded_code, loaded["expectationsMet"]))
            for key in ("states", "checks", "gaps", "familiesCovered", "replayExpectationsMet"):
                self.assertEqual(quiet.get(key), loaded.get(key), key)
            self.assertEqual(quiet_err, "")
            self.assertEqual(len(loaded_err.splitlines()), 1)
            self.assertRegex(loaded_err, r"^verdict: warning: host 1-minute load 56\.57 at start exceeds 2 x 12 cores")
            # Loaded only at the end: still one line.
            _, _, late = self.run_dry(row, [QUIET, OVERLOADED])
            self.assertRegex(late, r"^verdict: warning: [^\n]* at end [^\n]*\n$")

    def test_live_capture_metadata_records_start_and_end(self):
        with patch.object(H, "host_load", side_effect=[OVERLOADED, QUIET]):
            _, result = replay.LiveReplayTests().run_recorded("M5.1-04")
        self.assertEqual((result["hostLoad"]["start"], result["hostLoad"]["end"]), (OVERLOADED, QUIET))
        self.assertTrue(result["expectationsMet"], "load never changes a verdict")
        metadata = json.loads((Path(result["buildRoot"]) / "host-load.json").read_text())
        self.assertEqual(metadata, result["hostLoad"])
        self.assertIn("host-load.json", result["recordHashes"])


if __name__ == "__main__":
    unittest.main()
