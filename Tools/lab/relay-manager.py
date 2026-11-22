# SPDX-License-Identifier: MIT
"""Own relays by exact script/endpoints, including relays from older build roots."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


STATE = module("relay_state", ROOT / "Tools/lab/state.py")
LISTENERS = module("relay_listeners", ROOT / "Tools/lab/tart/host/relay-listener.py")
# Scaled bounds (M1-10i): the relay is driven mid-row, so a slow pgrep or ps on a loaded host must not become a row fault.
HARNESS = module("relay_harness", ROOT / "Tools/lab/harness.py")


class RelayRunner:
    sleep = staticmethod(time.sleep)
    monotonic = staticmethod(time.monotonic)

    def candidates(self):
        result = subprocess.run(["pgrep", "-f", "udp-relay.py"], capture_output=True, check=False,
                                timeout=HARNESS.seconds("RELAY_INVENTORY"))
        if result.returncode not in (0, 1):
            raise RuntimeError("relay process inventory failed")
        return [int(s) for s in result.stdout.split() if s.isdigit()]

    def command(self, pid):
        result = subprocess.run(["ps", "-p", str(pid), "-o", "command="], capture_output=True, check=False,
                                timeout=HARNESS.seconds("RELAY_INVENTORY"))
        return result.stdout.decode(errors="replace").strip() if result.returncode == 0 else ""

    def listeners(self):
        return LISTENERS.listener_pids("192.168.64.1", 51820)

    def alive(self, pid):
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False

    def terminate(self, pid):
        os.kill(pid, signal.SIGTERM)

    def start(self, argv, log):
        with log.open("ab") as output:
            return subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output, stderr=output, start_new_session=True).pid


class RelayManager:
    def __init__(self, root, state, runner=None):
        self.script = str(root / "Tools/lab/tart/host/udp-relay.py")
        self.state, self.runner = state, runner or RelayRunner()
        self.control = state / "control.json"

    def own_control(self, pid):
        try:
            words = shlex.split(self.runner.command(pid))
            index = words.index(self.script)
            if any(word not in ("-I", "-B", "-u") for word in words[1:index]):
                return False
            if index < 1 or not Path(words[0]).name.casefold().startswith("python") or words[index + 1:index + 3] != ["192.168.64.1:51820", "192.168.64.12:51820"]:
                return False
            rest = words[index + 3:]
            if rest and (len(rest) != 2 or rest[0] != "--control" or not rest[1].startswith("/")):
                return False
            return rest[1] if rest else None
        except (ValueError, IndexError):
            return False

    def owned(self):
        return {pid: control for pid in self.runner.candidates() if (control := self.own_control(pid)) is not False}

    def save_pid(self, pid):
        path = self.state / "relay.pid"
        if path.is_symlink():
            raise RuntimeError("unsafe relay PID file")
        path.write_text(str(pid) + "\n")

    def stop_pid(self, pid):
        if self.own_control(pid) is False:
            raise RuntimeError("relay identity changed; process retained")
        self.runner.terminate(pid)
        deadline = self.runner.monotonic() + HARNESS.seconds("RELAY_STOP")
        while self.runner.alive(pid) and self.runner.monotonic() < deadline:
            if self.own_control(pid) is False:
                return
            self.runner.sleep(0.1)
        if self.runner.alive(pid):
            raise RuntimeError("relay did not stop")

    def start(self):
        STATE.ensure_directory(self.state)
        if self.control.is_symlink():
            raise RuntimeError("unsafe relay control file")
        owned = self.owned()
        foreign = set(self.runner.listeners()) - set(owned)
        if foreign:
            raise RuntimeError("foreign listener on 192.168.64.1:51820; PID(s): " + ",".join(map(str, sorted(foreign))))
        if len(owned) == 1 and next(iter(owned.values())) == str(self.control):
            self.save_pid(next(iter(owned)))
            return "relay running; own process adopted"
        for pid in owned:
            self.stop_pid(pid)
        lock = self.state / "start-lock"
        try:
            lock.mkdir()
        except FileExistsError:
            raise RuntimeError("relay start locked; inspect existing run") from None
        try:
            for name in ["control.json", "relay.log"]:
                if (self.state / name).is_symlink():
                    raise RuntimeError("unsafe relay state file")
            self.control.write_text('{"maxDatagram":null}\n')
            pid = self.runner.start([sys.executable, "-I", "-B", self.script, "192.168.64.1:51820", "192.168.64.12:51820", "--control", str(self.control)], self.state / "relay.log")
            self.save_pid(pid)
            self.runner.sleep(HARNESS.seconds("RELAY_BIND_SETTLE"))
            if not self.runner.alive(pid) or self.own_control(pid) is False:
                raise RuntimeError("relay failed to bind; inspect stable relay.log")
            return "relay running"
        finally:
            lock.rmdir()

    def stop(self):
        STATE.ensure_directory(self.state)
        for pid in self.owned():
            self.stop_pid(pid)
        foreign = self.runner.listeners()
        if foreign:
            raise RuntimeError("foreign listener retained; PID(s): " + ",".join(map(str, foreign)))
        (self.state / "relay.pid").unlink(missing_ok=True)
        return "relay stopped"

    def status(self):
        owned = self.owned()
        if owned:
            return "relay running; own PID(s): " + ",".join(map(str, sorted(owned)))
        foreign = self.runner.listeners()
        if foreign:
            raise RuntimeError("foreign listener; PID(s): " + ",".join(map(str, foreign)))
        raise RuntimeError("relay stopped")

    def mtu(self, limit):
        self.start()
        temporary = self.state / "control-next.json"
        if temporary.is_symlink():
            raise RuntimeError("unsafe relay control file")
        temporary.write_text(json.dumps(dict(maxDatagram=1252 if limit == "on" else None)) + "\n")
        temporary.replace(self.control)
        return "relay datagram size filter " + limit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["start", "stop", "status", "mtu"])
    parser.add_argument("limit", nargs="?", choices=["on", "off"])
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if (args.action == "mtu") != (args.limit is not None):
        parser.error("mtu requires on|off")
    try:
        HARNESS.scale()
    except ValueError as error:
        sys.stderr.write("relay: " + str(error) + "\n")
        return 1
    directory = STATE.state_directory() / "relay"
    if args.dry_run:
        sys.stdout.write(f"dry-run: relay {args.action}; 192.168.64.1:51820 -> 192.168.64.12:51820; pid {directory}/relay.pid\n")
        return 0
    os.umask(0o077)
    manager = RelayManager(ROOT, directory)
    try:
        message = manager.mtu(args.limit) if args.action == "mtu" else getattr(manager, args.action)()
        sys.stdout.write(message + "\n")
        return 0
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        message = str(error) if isinstance(error, RuntimeError) else "relay state or inventory failed"
        sys.stderr.write("relay: " + message + "\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
