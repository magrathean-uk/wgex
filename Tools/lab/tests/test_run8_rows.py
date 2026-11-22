# SPDX-License-Identifier: MIT
"""Guest run 8 rows (M1-10h): REBOOT-LOCKDOWN, BOOT-SECRETS, EN0-LOSS and M5.3-10 through the real driver with recorded
replies, their dry-run fixtures, the boot observation for REBOOT-INTENT and the guest-script shapes. Never a VM."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

import test_live_replay as replay

ROOT, LIVE, V = replay.ROOT, replay.LIVE, replay.V
GUEST = ROOT / "Tools/lab/tart/guest"
ROWS = json.loads((ROOT / "Tools/lab/rows.json").read_text())["rows"]
TABLE = replay.TABLE
# Controls the run 8 flows press; the coordinates are recorded-runner data only.
CONTROLS = {
    "wgex.protection.lockdown": ("AXCheckBox", "Lockdown", (300, 300)),
    "wgex.main.openCaptiveWindow": ("AXButton", "Open Captive Window…", (310, 300)),
    "wgex.protection.confirmCaptiveWindow": ("AXButton", "Open Captive Window", (320, 300)),
    "wgex.protection.endCaptiveWindow": ("AXButton", "End Captive Window", (330, 300)),
    "wgex.settings.tab.service": ("AXButton", "Service", (340, 300)),
    "wgex.settings.tab.protection": ("AXButton", "Protection", (350, 300)),
    "wgex.settings.captiveWindow": ("AXPopUpButton", "Captive window", (360, 300)),
    "": ("AXRadioButton", LIVE.BOOT_STARTUP_LABEL, (370, 300)),
    "wgex.protection.allowLocalNetwork": ("AXCheckBox", "Allow local network", (390, 300)),
}
POSITIONS = {(x + 10, y + 10): identifier or name for identifier, (_, name, (x, y)) in CONTROLS.items()}
TYPED = "request failed, type: DaemonPortError case: system code: 754"
UNTYPED = "request failed, type: UnknownError case: withheld code: -1"


class Run8Runner(replay.RecordedRunner):
    """RecordedRunner plus Lockdown, startup, captive window, boot observation and en0 loss seams."""

    def __init__(self):
        super().__init__()
        self.clock = 1793294000.0  # ps etime and log stamps are wall-clock epochs
        self.lockdown = False
        self.toggle_works = True
        # M1-10q: Allow LAN (default on) and whether its main window toggle reaches the daemon journal.
        self.allow_lan, self.allow_lan_works = True, True
        self.boot_intent = False
        self.boot_choice_works = True
        self.popup_value = "5 minutes"
        self.captive_until = None
        self.captive_seconds = 300
        self.captive_never_closes = False
        self.refusal_line = TYPED
        self.rebooted_at = None
        self.app_after_boot = None  # ps etime of an app process after boot, or None
        self.daemon_runs = 1
        # M03-T07: None lets run_row decide (REBOOT-INTENT restores the intent); a test sets False for a lost intent.
        self.boot_restores_protected = None
        # M1-10v fix pass 1: the guest's count of the app's own log lines since the daemon's start (None prints unknown), and boot-observe
        # calls (1-based) that fail: "runtime" (the SSH call fails) or "value" (a reply the parser rejects).
        self.app_log_lines, self.boot_observe_calls, self.boot_observe_failures = 0, 0, {}
        # M1-10u fix pass 1: the guest clock's distance from the host clock (boot-observe stamps), and a second post-boot
        # daemon (this pid) that replaced the first one, which logged an unprotected line before it died.
        self.skew, self.replaced_pid = 0.0, None
        self.en0, self.en0_recovery, self.loss_leak, self.loss_noticed = {}, 1.9, False, True
        self.fail_refusal_down = False
        self.tail_lines = []
        # M1-10n: the selected Settings tab titles the window (macOS Settings) until Command-W closes it.
        self.settings_tab = None

    def title(self):
        return self.settings_tab or super().title()

    def toggle_shown(self):
        """The Allow LAN toggle's AX value as the main window dump shows it (M1-10t: the driver reads it before every press);
        optimistic here, it follows the press at once. AllowLANToggleRunner overrides it."""
        return "1" if self.allow_lan else "0"

    def captive_open(self):
        if self.captive_until is not None and self.clock >= self.captive_until and not self.captive_never_closes:
            self.captive_until = None
        return self.captive_until is not None

    def status(self):
        if self.captive_open():
            self.status_calls += 1
            return dict(phase="captiveWindow", protection="captiveWindow")
        if not self.connected and self.lockdown:
            self.status_calls += 1
            return dict(phase="idle", protection="blocked")
        return super().status()

    def dump(self):
        lines = [f"AXWindow | name={self.title()} | value= | desc= | id= | pos=0,0 size=800x600 en="]
        lines.append("AXTabGroup | name=Settings | value= | desc= | id=wgex.settings.surface | pos=0,0 size=10x10 en=true")
        # The startup radio buttons carry no identifier; their group does (M1-10j element path with a child label).
        lines.append(f"AXRadioGroup | name= | value= | desc=Connection at startup | id={LIVE.BOOT_STARTUP_GROUP} | pos=365,295 size=30x30 en=true")
        for identifier, (role, name, (x, y)) in CONTROLS.items():
            value = self.popup_value if role == "AXPopUpButton" else ""
            if identifier == "wgex.protection.allowLocalNetwork":
                value = self.toggle_shown()
            lines.append(f"{role} | name={name} | value={value} | desc= | id={identifier} | pos={x},{y} size=20x20 en=true")
        return lines

    def boot_observe(self):
        shift = self.skew
        stamp = lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t + shift)) + f".{int((t + shift) * 1000) % 1000:03d}"
        boot = int(self.rebooted_at or self.clock - 600)
        def etime(seconds):
            return f"{int(seconds) // 60:02d}:{int(seconds) % 60:02d}"
        replaced = self.replaced_pid
        pid = replaced or 336
        # A replaced daemon started later (boot + 8 s); the previous daemon (pid 336) died after an unprotected line.
        lines = [f"now={self.clock + shift:.3f}", "tz=+0000", f"boot={boot}",
                 f"app={self.app_after_boot or 'none'}", f"daemon={etime(self.clock - boot - (9 if replaced else 3))}", f"daemonpid={pid}",
                 f"appLogLines={'unknown' if self.app_log_lines is None else self.app_log_lines}", f"runs={self.daemon_runs}", "__TIMELINE__"]
        # M1-10u: the previous daemon's last protected line (pid 282) is in the log since boot, dated before the new daemon's start.
        lines += [f"{stamp(boot + 0.5)} status: phase=active protection=protected reason=none pid=282"]
        if replaced:
            lines += [f"{stamp(boot + 4.2)} status: phase=idle protection=unknown reason=none pid=336",
                      f"{stamp(boot + 5.4)} status: phase=active protection=unprotected reason=none pid=336",
                      f"{stamp(boot + 9.5)} status: phase=idle protection=blocked reason=none pid={replaced}"]
        else:
            lines += [f"{stamp(boot + 4.2)} status: phase=idle protection=unknown reason=none pid=336",
                      f"{stamp(boot + 5.4)} status: phase=idle protection=blocked reason=none pid=336"]
        return ("\n".join(lines) + "\n").encode()

    def en0_text(self, label):
        trigger = self.en0[label]
        down, up = trigger + 2, trigger + 22
        lines = [f"down {down:.3f}", f"up {up:.3f}", "__SAMPLES__"]
        t = down - 2
        while t < up + 40:
            state = (("active", "protected") if t < down + 1 or t >= up + self.en0_recovery or not self.loss_noticed
                     else ("failed", "blocked"))
            lines.append(f'{t:.3f} refs=1 {{"phase":"{state[0]}","protection":"{state[1]}","sequence":4}}')
            t += 0.25
        return ("\n".join(lines) + "\n").encode()

    def handled(self, argv, env, output=b""):
        """A reply this runner owns, recorded like RecordedRunner.run records every command."""
        self.commands.append(list(argv))
        self.environments.append(env)
        self.clock += 0.01
        return self.reply(argv, output)

    def run(self, argv, data=None, timeout=100, env=None):
        args = argv[2:] if argv[:1] == ["just"] else []
        if args[:2] == ["gui", "dump"]:
            base = super().run(argv, data, timeout, env).stdout.decode().splitlines()
            return self.reply(argv, ("\n".join(base + self.dump()[1:]) + "\n").encode())
        if args[:2] in (["gui", "click"], ["gui", "press"]):
            # gui press APP WINDOW IDENTIFIER press X Y ROLE [LABEL] actuates the control at its fallback point (M1-10j).
            target = POSITIONS.get(replay.press_point(args))
            if target == "wgex.protection.lockdown" and self.toggle_works:
                self.lockdown = not self.lockdown
            elif target == "wgex.protection.allowLocalNetwork" and self.allow_lan_works:
                self.allow_lan = not self.allow_lan
            elif target == LIVE.BOOT_STARTUP_LABEL and self.boot_choice_works:
                self.boot_intent = True
            elif target == "wgex.protection.confirmCaptiveWindow":
                if self.connected:
                    self.captive_until = self.clock + self.captive_seconds
                else:
                    self.tail_lines.append(f"2026-10-30 10:00:00.000 {self.refusal_line}")
            elif target == "wgex.protection.endCaptiveWindow":
                self.captive_until = None
            elif target in ("wgex.settings.tab.service", "wgex.settings.tab.protection"):
                self.settings_tab = CONTROLS[target][1]
        if args[:2] == ["gui", "run"] and any('keystroke "w" using command down' in arg for arg in args):
            self.settings_tab = None
        if args[:2] == ["gui", "run"] and any('keystroke "1 minute"' in arg for arg in args):
            self.popup_value, self.captive_seconds = "1 minute", 60
        if args[:2] == ["ssh", "--"]:
            command = args[2]
            words = shlex.split(command)
            action = words[2] if len(words) > 2 and words[1].endswith("verdict-actions.sh") else None
            if command.startswith("nohup ") and " generate " in command:
                inner = command[len("nohup "):].split(" >/dev/null")[0]
                path = shlex.split(inner)[shlex.split(inner).index("--record") + 1]
                self.start(["just", "lab", "ssh", "--", inner])
                if self.loss_leak:
                    sent = next(o for o in self.generator["observations"] if o.get("scope") == "outside_tunnel")
                    self.generator["receiverRecords"][0]["observations"].append(dict(sent, kind="received"))
                self.files[path] = self.generator
                return self.handled(argv, env)
            if action == "lockdown-state":
                return self.handled(argv, env, b"lockdown=true\n" if self.lockdown else b"lockdown=false\n")
            if action == "allow-lan-state":
                return self.handled(argv, env, b"allowLAN=true\n" if self.allow_lan else b"allowLAN=false\n")
            if action == "boot-intent":
                return self.handled(argv, env, b"bootIntent=true\n" if self.boot_intent else b"bootIntent=false\n")
            if action == "daemon-pid":
                return self.handled(argv, env, b"daemonpid=282\n")
            if action == "boot-observe":
                self.boot_observe_calls += 1
                failure = self.boot_observe_failures.get(self.boot_observe_calls)
                if failure == "runtime":
                    self.commands.append(list(argv))
                    return self.reply(argv, code=1)
                return self.handled(argv, env, b"not a boot observation\n" if failure == "value" else self.boot_observe())
            if action == "anchor-rules":
                rules = "block drop out quick on en0 all\n"
                if self.captive_open():
                    rules += ("pass out quick on en0 proto tcp from any to any port = 80 user = 501 flags S/SA keep state\n"
                              "pass out quick on en0 proto tcp from any to any port = 443 user = 501 flags S/SA keep state\n")
                return self.handled(argv, env, rules.encode())
            if action == "kill-app-process":
                return self.handled(argv, env)
            if action == "down" and self.fail_refusal_down and any("verdict-actions.sh kill-app-process" in c for c in commands(self)):
                self.commands.append(list(argv))
                return self.reply(argv, code=1)
            if action == "diagnostics-tail":
                return self.handled(argv, env, self.diagnostics_tail + "".join(line + "\n" for line in self.tail_lines).encode())
            if action == "en0-loss":
                self.en0[words[4]] = self.clock
                return self.handled(argv, env)
            if action == "en0-collect":
                return self.handled(argv, env, self.en0_text(words[3]))
            if action == "reboot":
                self.rebooted_at = self.clock
                if self.lockdown and not self.connected:
                    self.boot_status_count = 0
                    return self.handled(argv, env)
        return super().run(argv, data, timeout, env)

    def start(self, argv, env=None):
        process = super().start(argv, env)
        if "--state" in argv[-1] and self.lockdown and self.rebooted_at is not None and self.boot_status_count is not None:
            # REBOOT-LOCKDOWN never connects: after its boot no probe can reach the in-tunnel peer (run 8e peer.json: 0).
            for receiver in self.generator["receiverRecords"]:
                receiver["observations"] = [o for o in receiver["observations"] if o.get("scope") != "in_tunnel"]
        return process


def run_row(name, runner=None, accepted=True):
    runner = runner or Run8Runner()
    if name == "REBOOT-INTENT" and runner.boot_restores_protected is None:
        # M03-T07: REBOOT-INTENT passes only when the persisted intent comes back after the reboot, as the guest's daemon does.
        runner.boot_restores_protected = True
    return replay.LiveReplayTests().run_recorded(name, runner, accepted=accepted)


def commands(runner):
    return [" ".join(argv) for argv in runner.commands]


def check(result, name):
    return next(item for item in result["checks"] if item["name"] == name)


class RebootLockdownTests(unittest.TestCase):
    def test_lockdown_is_set_by_the_gui_toggle_before_the_reboot_and_never_turned_off(self):
        """M1-10o (guest run 8e): turning lockdown off raises the administrator prompt, so the row never presses the toggle
        again: the positive control leads (an unprotected window while the guest is idle, before the lockdown press), the
        trailing tail is skipped for lockdownOffNeedsAdmin and the lead window stands in for it."""
        runner, result = run_row("REBOOT-LOCKDOWN")
        lines = commands(runner)
        toggles = [i for i, c in enumerate(lines) if replay.actuates(c, 310, 310)]
        lead = next(i for i, c in enumerate(lines) if " generate " in c and "--state unprotected" in c)
        self.assertEqual([c for c in lines if " generate " in c and "--state unprotected" in c], [lines[lead]], "one unprotected window")
        boot = next(i for i, c in enumerate(lines) if c.endswith("verdict-actions.sh reboot"))
        first = next(i for i, c in enumerate(lines) if i > boot and "status --json" in c)
        self.assertEqual(len(toggles), 1, "lockdown on only")
        self.assertLess(lead, toggles[0], "the lead control runs before the lockdown press")
        self.assertLess(toggles[0], boot)
        self.assertFalse(any(c.startswith("just lab gui") for c in lines[boot:]), "no GUI step after the reboot: never a lockdown-off press")
        self.assertTrue(any("lockdown-state" in c for c in lines[:boot]))
        self.assertTrue(any("lockdown-state" in c for c in lines[first:]), "the tail's need is decided by the journal alone")
        self.assertFalse(any(c.endswith("verdict-actions.sh down") for c in lines[boot:]), "no tail under lockdown")
        self.assertTrue(any("boot-observe" in c for c in lines[boot:first]))
        self.assertEqual(sorted(c["name"] for c in result["checks"] if c["met"]),
                         sorted(["allowLANOffReachedDaemon", "idleBlockedAfterBoot", "lockdownReachedDaemon", "neverUnprotectedAfterBoot",
                                 "noRestartLoop", "offlineEn0Capture", "oneReferenceAfterBoot", "postRestartTimelineConsistent",
                                 "zeroLANReceiptsAfterBoot", "zeroOffSubnetReceiptsAfterBoot", "zeroReceiptsBeforeFirstStatus"]))
        self.assertEqual(result["gaps"], [])
        self.assertEqual(result["states"][0]["role"], "unprotectedLead")
        self.assertNotIn("unprotectedTail", [w["role"] for w in result["states"]])
        self.assertEqual(result["tailControlPosition"], "lead")
        self.assertEqual((result["tailControl"]["met"], result["tailControl"]["trailSkipped"]), (True, "lockdownOffNeedsAdmin"))
        self.assertTrue(result["captureChecks"]["tailSystemResolverObserved"])
        self.assertTrue(result["rowCompleted"])
        self.assertEqual(check(result, "idleBlockedAfterBoot")["firstStatus"], dict(phase="idle", protection="blocked"))
        self.assertIsNone(result["bootObservation"]["daemonDrivenReconnect"], "lockdown has no tunnel to reconnect")

    def test_a_toggle_that_never_reaches_the_daemon_fails_with_a_named_gap(self):
        runner = Run8Runner()
        runner.toggle_works = False
        _, result = run_row("REBOOT-LOCKDOWN", runner, accepted=False)
        self.assertTrue(any(gap.startswith("lockdownNotApplied:") for gap in result["gaps"]), result["gaps"])
        self.assertFalse(any(c.endswith("verdict-actions.sh reboot") for c in commands(runner)))

    def test_a_restart_loop_fails_the_row(self):
        runner = Run8Runner()
        runner.daemon_runs = 3
        _, result = run_row("REBOOT-LOCKDOWN", runner, accepted=False)
        self.assertFalse(check(result, "noRestartLoop")["met"])


class BootSecretsTests(unittest.TestCase):
    def runner(self):
        runner = Run8Runner()
        runner.boot_secret_mode = True
        return runner

    def test_startup_boot_is_chosen_in_settings_and_daemon_held_secrets_pass_without_an_app(self):
        runner, result = run_row("BOOT-SECRETS", self.runner())
        lines = commands(runner)
        boot = next(i for i, c in enumerate(lines) if c.endswith("verdict-actions.sh reboot"))
        choice = next(i for i, c in enumerate(lines) if replay.actuates(c, 380, 310))
        self.assertLess(choice, boot)
        self.assertTrue(any("keystroke \",\" using command down" in c for c in lines[:choice]))
        self.assertFalse(any(c.endswith("verdict-actions.sh down") for c in lines[choice:boot]), "an explicit down deletes the bundle")
        self.assertTrue(check(result, "daemonSecretsBeforeApp")["met"])
        self.assertFalse(result["bootObservation"]["appRunningAfterBoot"])
        self.assertTrue(result["bootObservation"]["protectedBeforeAppSeen"])
        self.assertIsNone(result["bootObservation"]["daemonDrivenReconnect"], "timing only: who restored protection is not measured")

    def test_an_app_running_after_boot_is_protected_only_after_app_seen_a_gap_not_a_pass(self):
        runner = self.runner()
        runner.app_after_boot = "09:59"
        _, result = run_row("BOOT-SECRETS", runner, accepted=False)
        self.assertFalse(check(result, "daemonSecretsBeforeApp")["met"])
        self.assertTrue(any(gap.startswith("protectedOnlyAfterAppSeen:") for gap in result["gaps"]), result["gaps"])
        self.assertFalse(result["rowCompleted"])

    def test_a_boot_choice_that_never_reaches_the_daemon_stops_before_the_reboot(self):
        runner = self.runner()
        runner.boot_choice_works = False
        _, result = run_row("BOOT-SECRETS", runner, accepted=False)
        self.assertTrue(any(gap.startswith("bootIntentNotApplied:") for gap in result["gaps"]), result["gaps"])
        self.assertFalse(any(c.endswith("verdict-actions.sh reboot") for c in commands(runner)))


class RebootIntentObservationTests(unittest.TestCase):
    def test_app_running_after_boot_is_recorded_for_c8(self):
        runner = Run8Runner()
        runner.app_after_boot = "00:20"
        _, result = run_row("REBOOT-INTENT", runner)
        observation = result["bootObservation"]
        self.assertTrue(observation["appRunningAfterBoot"])
        self.assertIsNotNone(observation["appStartedAt"])
        _, result = run_row("REBOOT-INTENT")
        self.assertFalse(result["bootObservation"]["appRunningAfterBoot"])

    def test_an_unreadable_boot_sample_is_unknown_not_absent(self):
        _, result = replay.LiveReplayTests().run_recorded("REBOOT-INTENT", accepted=False) # M1-10u fix pass 1: REBOOT-INTENT needs launchd runs == 1; this runner has no boot-observe, so the row is not accepted
        self.assertFalse(check(result, "noRestartLoop")["met"], "unreadable launchd runs fail closed, as in the other boot rows")
        self.assertIsNone(result["bootObservation"]["appRunningAfterBoot"])
        self.assertIsNone(result["bootObservation"]["daemonDrivenReconnect"])


class En0LossTests(unittest.TestCase):
    def test_both_profiles_lose_and_regain_en0_with_a_detached_generator_only_on_full4(self):
        runner, result = run_row("EN0-LOSS")
        lines = commands(runner)
        losses = [c for c in lines if "verdict-actions.sh en0-loss 20 " in c]
        self.assertEqual(len(losses), 2)
        detached = [c for c in lines if "nohup " in c and " generate " in c]
        self.assertEqual(len(detached), 1)
        self.assertIn("--state blocked", detached[0])
        names = {c["name"] for c in result["checks"]}
        for variant in ["default", "full4"]:
            for expectation in ["linkCycled", "lossDetected", "protectedWithin10sOfLinkUp", "neverUnprotectedDuringLoss", "onePfReferenceThroughout"]:
                self.assertIn(f"{expectation}:{variant}", names)
        self.assertIn("zeroLanReceiptsDuringLoss:full4", names)
        self.assertNotIn("zeroLanReceiptsDuringLoss:default", names)
        self.assertGreater(check(result, "zeroLanReceiptsDuringLoss:full4")["probeAttempts"], 0)
        roles = [w["role"] for w in result["states"]]
        self.assertIn("linkLoss:full4", roles)
        self.assertIn("automaticRecovery:default", roles)
        split = next(w for w in result["states"] if w["role"] == "protected:default")
        self.assertIn("splitTunnel", split)

    def test_slow_recovery_fails(self):
        runner = Run8Runner()
        runner.en0_recovery = 15
        _, result = run_row("EN0-LOSS", runner, accepted=False)
        self.assertFalse(check(result, "protectedWithin10sOfLinkUp:default")["met"])

    def test_a_loss_the_daemon_never_notices_fails(self):
        """M1-10h VERIFY F2: every sample protected through the loss used to pass with a 0 s recovery."""
        runner = Run8Runner()
        runner.loss_noticed = False
        _, result = run_row("EN0-LOSS", runner, accepted=False)
        for variant in ["default", "full4"]:
            self.assertFalse(check(result, "lossDetected:" + variant)["met"])
            self.assertFalse(check(result, "protectedWithin10sOfLinkUp:" + variant)["met"], "a stale protected status is no recovery")

    def test_a_lan_receipt_during_the_loss_fails(self):
        runner = Run8Runner()
        runner.loss_leak = True
        _, result = run_row("EN0-LOSS", runner, accepted=False)
        self.assertFalse(check(result, "zeroLanReceiptsDuringLoss:full4")["met"])


class CaptiveTests(unittest.TestCase):
    def test_expiry_end_and_app_kill_close_the_window_and_the_refusal_is_typed(self):
        runner, result = run_row("M5.3-10")
        lines = commands(runner)
        # M1-10o: down, the lead control, connect again, then lockdown on once and never off; the trailing tail is skipped.
        toggles = [i for i, c in enumerate(lines) if replay.actuates(c, 310, 310)]
        self.assertEqual(len(toggles), 1, "lockdown on only")
        lead = next(i for i, c in enumerate(lines) if " generate " in c and "--state unprotected" in c)
        down = max(i for i, c in enumerate(lines[:lead]) if c.endswith("verdict-actions.sh down"))
        connect = next(i for i, c in enumerate(lines) if i > lead and replay.actuates(c, 40, 20))
        protected = next(i for i, c in enumerate(lines) if i > connect and "status --json" in c)
        self.assertTrue(down < lead < connect < protected < toggles[0])
        self.assertEqual(result["gaps"], [])
        self.assertEqual(result["tailControlPosition"], "lead")
        self.assertEqual([w["role"] for w in result["states"]][0], "unprotectedLead")
        self.assertNotIn("unprotectedTail", [w["role"] for w in result["states"]])
        refusal = max(i for i, c in enumerate(lines) if replay.actuates(c, 330, 310))
        self.assertFalse(any(c.endswith("verdict-actions.sh down") for c in lines[refusal:]), "no tail under lockdown")
        self.assertEqual(sum(replay.actuates(c, 320, 310) for c in lines), 4, "four opens: expiry, End, app kill, D8 refusal")
        self.assertEqual(sum(replay.actuates(c, 330, 310) for c in lines), 4, "each open is confirmed in the sheet")
        self.assertEqual(sum(replay.actuates(c, 340, 310) for c in lines), 1, "one manual End")
        self.assertTrue(any("verdict-actions.sh kill-app-process" in c for c in lines))
        stop = next(i for i, c in enumerate(lines) if "lab relay stop" in c)
        first_open = next(i for i, c in enumerate(lines) if replay.actuates(c, 320, 310))
        self.assertLess(stop, first_open)
        for name in ["lockdownReachedDaemon", "d8FailedIntentOpens", "expiryCloses", "manualEndCloses", "appKillCannotExtend", "d8TypedRefusal"]:
            self.assertTrue(check(result, name)["met"], name)
        self.assertEqual(check(result, "expiryCloses")["durationSeconds"], 60)
        self.assertEqual([w["role"] for w in result["states"]][1:4], ["afterExpiry", "afterEnd", "afterAppKill"])

    def test_an_untyped_refusal_fails(self):
        runner = Run8Runner()
        runner.refusal_line = UNTYPED
        _, result = run_row("M5.3-10", runner, accepted=False)
        self.assertFalse(check(result, "d8TypedRefusal")["met"])

    def test_a_window_that_never_closes_fails_closed_and_restores_the_relay(self):
        runner = Run8Runner()
        runner.captive_never_closes = True
        _, result = run_row("M5.3-10", runner, accepted=False)
        self.assertTrue(any(gap.startswith("captiveNotClosed:") for gap in result["gaps"]), result["gaps"])
        lines = commands(runner)
        stop = next(i for i, c in enumerate(lines) if "lab relay stop" in c)
        self.assertTrue(any("lab relay start" in c for c in lines[stop:]))

    def test_a_failed_down_before_the_refusal_is_its_own_failure(self):
        """M1-10h VERIFY N4: the window is never opened after a failed `down`, so no misattributed d8TypedRefusal FAIL."""
        runner = Run8Runner()
        runner.fail_refusal_down = True
        _, result = run_row("M5.3-10", runner, accepted=False)
        self.assertTrue(any(gap.startswith("captiveRefusalDownFailed:") for gap in result["gaps"]), result["gaps"])
        self.assertEqual(sum(replay.actuates(c, 320, 310) for c in commands(runner)), 3, "no fourth open after the failed down")
        self.assertFalse(any(c["name"] == "d8TypedRefusal" and c["met"] for c in result["checks"]))

    def test_an_unconfirmed_duration_falls_back_to_the_default_deadline(self):
        session = LIVE.Session("fixture", {}, runner=Run8Runner())
        session.runner.popup_value = "5 minutes"
        with patch.object(session, "keystroke"):
            self.assertEqual(session.set_captive_duration(), (300, True))
        session.runner.popup_value = "unreadable"
        with patch.object(session, "keystroke"):
            self.assertEqual(session.set_captive_duration(), (LIVE.CAPTIVE_SECONDS_DEFAULT, False))


class ParserTests(unittest.TestCase):
    def test_boot_observation_reads_etime_offsets_and_status_lines(self):
        text = ("now=1793294330.500\ntz=-0700\nboot=1793294290\napp=1-00:00:05\ndaemon=00:37\nruns=1\n__TIMELINE__\n"
                "2026-10-30 10:18:15.440 status: phase=idle protection=blocked reason=none\n"
                "<event omitted; non-diagnostic content>\n")
        value = V.parse_boot_observe(text)
        self.assertEqual(value["appStartedAt"], 1793294330.5 - 86405 - 1)
        self.assertEqual(value["daemonStartedAt"], 1793294330.5 - 37 - 1)
        self.assertTrue(value["appRunning"])
        self.assertEqual(value["daemonRuns"], 1)
        # [epoch, phase, protection, pid (None: the line carried none), position in the log]
        self.assertEqual(value["timeline"], [[V.guest_epoch("2026-10-30 10:18:15.440", "-0700"), "idle", "blocked", None, 0]])
        self.assertAlmostEqual(V.guest_epoch("1970-01-01 01:00:00.5", "+0100"), 0.5)
        none = V.parse_boot_observe("now=1793294330.5\ntz=+0000\nboot=1793294290\napp=none\ndaemon=none\nruns=unknown\n__TIMELINE__\n")
        self.assertEqual((none["appRunning"], none["appStartedAt"], none["daemonRuns"]), (False, None, None))
        for broken in ["", "now=12\nboot=1793294290\n", "now=1793294330\nboot=x\n"]:
            with self.assertRaises(ValueError):
                V.parse_boot_observe(broken)

    def test_captive_pass_counts_accept_numeric_and_service_ports_only_on_pass_tcp_rules(self):
        rules = ("pass out quick on en0 proto tcp from any to any port = 80 user = 501 flags S/SA keep state\n"
                 "pass out quick on en0 proto tcp from any to any port = https user = 501 flags S/SA keep state\n"
                 "pass out quick on en0 proto tcp from any to any port 443 user 501 flags S/SA keep state\n"
                 "block drop out quick proto tcp from any to any port = 80\n"
                 "pass out quick on en0 proto udp from any to any port = 443\n"
                 "pass out quick on en0 proto tcp from any to any port = 8080\n")
        self.assertEqual(V.captive_passes(rules), {"port80": 1, "port443": 2})
        self.assertEqual(V.captive_passes(""), {"port80": 0, "port443": 0})

    def test_request_failures_and_en0_samples(self):
        lines = ["2026-10-30 10:00:00.000 " + TYPED, UNTYPED, "status: phase=idle protection=blocked reason=none"]
        self.assertEqual(V.request_failures(lines), [["DaemonPortError", "system", 754], ["UnknownError", "withheld", -1]])
        parsed = V.parse_en0('down 1793300761.490\nup 1793300781.520\n__SAMPLES__\n1793300760.000 refs=1 {"phase":"active","protection":"protected"}\n'
                             "1793300762.000 refs=0 unavailable\n")
        self.assertEqual(parsed["samples"], [[1793300760.0, "active", "protected", 1], [1793300762.0, "unavailable", "unknown", 0]])
        self.assertEqual((parsed["down"], parsed["up"]), (1793300761.49, 1793300781.52))

    def test_the_log_tail_keeps_a_typed_captive_request_failure(self):
        source = b"Filtering the log data\n" + (b"2026-10-30 10:00:00.000000-0700 0x1 Default 0x0 1 0 WGEXDaemon: [lab] " + TYPED.encode() + b"\n")
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            result = subprocess.run(["perl", str(GUEST / "daemon-log-tail.pl"), directory], input=source, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0)
            self.assertIn(TYPED, (Path(directory) / "daemon-log-tail").read_text())


class DryRunTests(unittest.TestCase):
    RUNNER = replay.module("run8_runner", "verdict-run.py")

    def test_new_rows_replay_with_every_failing_fixture_rejected(self):
        for name in ["REBOOT-LOCKDOWN", "BOOT-SECRETS", "EN0-LOSS", "M5.3-10"]:
            with self.subTest(row=name):
                result = self.RUNNER.replay(ROWS[name], TABLE, {})
                self.assertTrue(result["expectationsMet"])
                self.assertTrue(result["checks"] and all(c["met"] for c in result["checks"]))
                self.assertTrue(all(case["rejected"] for case in result["failingFixtures"]))
                self.assertEqual(result["failingFixturesUncovered"], [])
                covered = {case["expectation"] for case in result["failingFixtures"]}
                self.assertEqual(covered, {c["name"] for c in result["checks"]})

    def test_a_missing_failing_fixture_or_one_that_passes_fails_the_replay(self):
        read = self.RUNNER.read
        def drop_first(path, hashes, label):
            value = read(path, hashes, label)
            if label == "fixture:rows:captive":
                value["failing"] = [case for case in value["failing"] if case["expectation"] != "d8TypedRefusal"]
            return value
        with patch.object(self.RUNNER, "read", side_effect=drop_first):
            result = self.RUNNER.replay(ROWS["M5.3-10"], TABLE, {})
        self.assertFalse(result["expectationsMet"])
        self.assertEqual(result["failingFixturesUncovered"], ["d8TypedRefusal"])
        def harmless(path, hashes, label):
            value = read(path, hashes, label)
            if label == "fixture:rows:reboot-lockdown":
                value["failing"][0]["set"] = [[["lockdownBeforeReboot"], True]]
            return value
        with patch.object(self.RUNNER, "read", side_effect=harmless):
            self.assertFalse(self.RUNNER.replay(ROWS["REBOOT-LOCKDOWN"], TABLE, {})["expectationsMet"])

    def test_reboot_intent_replay_reports_the_app_running_observation(self):
        result = self.RUNNER.replay(ROWS["REBOOT-INTENT"], TABLE, {})
        self.assertTrue(result["expectationsMet"])
        self.assertTrue(result["bootObservation"]["appRunningAfterBoot"])
        self.assertFalse(result["bootObservation"]["protectedBeforeAppSeen"])
        self.assertIsNone(result["bootObservation"]["daemonDrivenReconnect"])


class CatalogueTests(unittest.TestCase):
    def test_run8_rows_are_live_and_the_rest_of_gate_row_6_stays_gap_declared(self):
        for name in ["REBOOT-LOCKDOWN", "BOOT-SECRETS", "EN0-LOSS", "M5.3-10"]:
            self.assertNotIn("gap", ROWS[name], name)
            self.assertIn(ROWS[name]["checks"], V.ROW_CHECKS, name)
        for name in ["M5.2-01", "M5.2-03"]:
            self.assertIn("the maintainer's call", ROWS[name]["gap"], name)
        # M1-47: POWER-WAKE is live through an injected power event; the owner row RT-21 stays a gap.
        self.assertNotIn("gap", ROWS["POWER-WAKE"])
        self.assertIn(ROWS["POWER-WAKE"]["checks"], V.ROW_CHECKS)
        self.assertFalse(ROWS["REBOOT-LOCKDOWN"]["connect"])
        self.assertEqual(ROWS["EN0-LOSS"]["profiles"], ["default", "full4"])
        self.assertIn("80/53 listeners are out of scope", ROWS["M5.3-10"]["limitations"][0])

    def test_guest_actions_count_references_and_never_keep_the_replayed_journal(self):
        script = (GUEST / "verdict-actions.sh").read_text()
        for action in ["lockdown-state", "boot-intent", "boot-observe", "anchor-rules", "kill-app-process",
                       "en0-loss", "en0-cycle", "en0-observe", "en0-collect"]:
            self.assertRegex(script, rf"(?m)^  {action}\)")
        block = script[script.index("  lockdown-state)"):script.index("  boot-intent)")]
        self.assertIn("trap 'rm -f \"$replayed\"' EXIT", block)
        self.assertIn("umask 077", block)
        self.assertIn("printf 'lockdown=%s\\n'", block)
        observe = script[script.index("  en0-observe)"):script.index("  en0-collect)")]
        self.assertIn("{n++} END {print n + 0}", observe, "reference rows are counted, never printed")
        cycle = script[script.index("  en0-cycle)"):script.index("  en0-observe)")]
        self.assertIn("trap '/sbin/ifconfig en0 up' EXIT", cycle)
        self.assertIn("sleep $((seconds + 70)); /sbin/ifconfig en0 up", script)
        self.assertIn("/usr/bin/log show --style compact", script)
        self.assertIn('"journal-replay.pl"', (ROOT / "Tools/lab/verdict-live.py").read_text())


if __name__ == "__main__":
    unittest.main()
