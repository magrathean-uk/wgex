# SPDX-License-Identifier: MIT
# shellcheck shell=bash
# Shared helpers for Config/Scripts. Source, do not execute.

WGEX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Read-only metadata queries must not opportunistically refresh the real index.
export GIT_OPTIONAL_LOCKS=0

# build_root: isolated output for this checkout, including on non-managed hosts.
build_root() {
  python3 -I -B "$WGEX_ROOT/Config/Scripts/build_root.py" "$WGEX_ROOT"
}

# dependency_cache: survives session cleanup when a persistent cache is supplied.
dependency_cache() {
  local cache
  cache="${CLEAN_DEVELOPMENT_CACHE_ROOT:-$(build_root)}" || return
  printf '%s/wgex-deps' "$cache"
}

# configure_caches: share dependencies, isolate compiler output by checkout.
configure_caches() {
  local root cache
  root="$(build_root)" || return
  cache="$(dependency_cache)" || return
  GOCACHE="$cache/go"
  export GOCACHE
  CLANG_MODULE_CACHE_PATH="$root/module-cache"
  export CLANG_MODULE_CACHE_PATH
  export SWIFTPM_MODULECACHE_OVERRIDE="$CLANG_MODULE_CACHE_PATH"
  mkdir -p "$GOCACHE" "$CLANG_MODULE_CACHE_PATH" "$cache/swiftpm"
}

# require_current_engine: never link an archive from a different source tree.
require_current_engine() {
  local flags=()
  [[ "${1:-}" != --test-support ]] || flags+=(--test-support)
  python3 -I "$WGEX_ROOT/Engine/scripts/source-digest.py" --verify "$WGEX_ROOT/Packages/WGEXEngine/Binary" ${flags[@]+"${flags[@]}"}
}

# xcconfig_value <name> <Debug|Release>: value of a setting in Base.xcconfig,
# honouring a [config=<configuration>] conditional when one exists.
xcconfig_value() {
  local name="$1" configuration="$2" file value="" local_file="$WGEX_ROOT/Config/Local.xcconfig"
  # The git-ignored Config/Local.xcconfig overrides Base.xcconfig, as its include does in Xcode.
  for file in "$local_file" "$WGEX_ROOT/Config/Base.xcconfig"; do
    [[ -f "$file" ]] || continue
    value="$(sed -nE "s/^${name}\\[config=${configuration}\\][[:space:]]*=[[:space:]]*(.*)$/\\1/p" "$file" | tail -n 1)"
    if [[ -z "$value" ]]; then
      value="$(sed -nE "s/^${name}[[:space:]]*=[[:space:]]*(.*)$/\\1/p" "$file" | tail -n 1)"
    fi
    [[ -z "$value" ]] || break
  done
  if [[ -z "$value" ]]; then
    echo "xcconfig_value: $name not found in Config/Local.xcconfig or Config/Base.xcconfig" >&2
    return 1
  fi
  printf '%s' "$value"
}

# derived_data: xcodebuild output directory (plan 03 §7).
derived_data() {
  local root
  root="$(build_root)" || return
  printf '%s/derived-data' "$root"
}

# configuration_name <debug|release>: Xcode configuration name.
configuration_name() {
  case "$1" in
    debug | Debug) printf 'Debug' ;;
    release | Release) printf 'Release' ;;
    *)
      echo "unknown configuration: $1 (expected debug or release)" >&2
      return 1
      ;;
  esac
}

# xcodebuild_log_path <label>: env-free xcodebuild log of this run of a step. The label is reduced to [A-Za-z0-9._-]
# and the shell's pid ($$, the same in the pipeline's subshells) makes the file this run's own, so concurrent runs of
# one label never share a file and a leftover from an earlier run is never mistaken for this one.
xcodebuild_log_path() {
  local label="${1:-xcodebuild}" root
  root="$(build_root)" || return
  printf '%s/logs/xcodebuild-%s-%s.log' "$root" "${label//[^A-Za-z0-9._-]/_}" "$$"
}

# xcodebuild_log_open <log> <label>: logs directory 0700, then retention, then a fresh empty log 0600 whatever the
# umask (never left to tee to create under the caller's). Retention runs before this run's log exists and never
# considers it: of the other runs of the label only the newest 2 are kept (so 3 with this run), and a candidate is
# never removed while its pid (from the file name) is alive or while its mtime is under an hour old (a future mtime
# counts), so a log that another run is still writing survives. Fails (leaving no log behind to be misread) when the
# log cannot be created.
xcodebuild_log_open() {
  local log="$1" label="$2" dir prefix rest old mtime now index=0 runs=()
  dir="$(dirname "$log")"
  prefix="xcodebuild-${label//[^A-Za-z0-9._-]/_}-"
  (umask 077 && mkdir -p "$dir") 2>/dev/null && chmod 700 "$dir" 2>/dev/null || return 1
  # Only <prefix><digits>.log counts as a run of this label (xcodebuild-a-b-1.log is label a-b, not a).
  for old in "$dir/$prefix"*.log; do
    rest="${old##*/}"
    rest="${rest#"$prefix"}"
    if [[ "$old" != "$log" && -e "$old" && "$rest" =~ ^[0-9]+\.log$ ]]; then runs+=("$old"); fi
  done
  if ((${#runs[@]} > 2)); then # BSD stat (xcodebuild is macOS-only): newest first
    now="$(date +%s)"
    stat -f '%m %N' -- "${runs[@]}" 2>/dev/null | sort -rn |
      while read -r mtime old; do
        index=$((index + 1))
        ((index > 2)) || continue
        rest="${old##*-}"
        if kill -0 "${rest%.log}" 2>/dev/null || ((now - mtime < 3600)); then continue; fi
        rm -f -- "$old" 2>/dev/null
      done
  fi
  rm -f "$log" 2>/dev/null
  (umask 077 && : >"$log") 2>/dev/null && chmod 600 "$log" 2>/dev/null || return 1
  return 0
}

# xcodebuild_filter [label]: stdin to stdout for every gate step that runs xcodebuild (M1-23). Drops the script-phase
# environment dump: any `    export <name>=value` line, whatever the name token (an identifier, a quoted name with
# escapes, or any run of non-space, non-= characters, with or without an escaped `\=`), plus every continuation line
# of a multi-line value (a value that opens a double quote with no unescaped closing quote swallows lines up to one
# ending in an unescaped `"`). If the input ends inside such a value, one line saying how many lines were withheld is
# emitted into the stream. The env-free stream is kept whole in xcodebuild_log_path <label> (mode 0600, see
# xcodebuild_log_open), then condensed with xcbeautify --quiet when installed; a formatter that exits early is drained
# so xcodebuild and the log are never cut short. Callers merge stderr (2>&1), read xcodebuild's own status from
# PIPESTATUS (never this function's) and then call xcodebuild_finish. Printed text only ever comes from the env-free
# stream.
xcodebuild_filter() {
  local label="${1:-xcodebuild}" log formatter_status
  log="$(xcodebuild_log_path "$label")" || log=""
  if [[ -z "$log" ]] || ! xcodebuild_log_open "$log" "$label"; then
    echo "xcodebuild_filter: cannot create an env-free log for $label; none will be kept" >&2
    log=/dev/null
  fi
  LC_ALL=C awk '
    function open_quote(text) { # text opens a double quote that has no unescaped closing quote
      if (text !~ /^"/) return 0
      text = substr(text, 2)
      gsub(/\\./, "", text)
      return text !~ /"/
    }
    function closes(text) { # text ends in an unescaped double quote
      sub(/\r$/, "", text)
      gsub(/\\./, "", text)
      return text ~ /"$/
    }
    function open_name(text) { # text opens a double-quoted name that has no unescaped closing quote
      sub(/^[ \t]*export "/, "", text)
      sub(/\r$/, "", text)
      gsub(/\\./, "", text)
      return text !~ /"/
    }
    function after_name(text) { # text is a later line of a name; the rest of the line after the name closes, if it does
      if (!match(text, /^([^"\\]|\\.)*"\\?=/)) return -1
      return RLENGTH
    }
    function resolve(value) { # the text after `=`: an open double quote withholds lines up to the closing one
      sub(/\r$/, "", value)
      if (open_quote(value)) skip = 1
    }
    skip { withheld++; if (closes($0)) skip = 0; next }
    name { # inside a newline in an exported name: skipped until the line where the name closes, followed by `=`
      withheld++
      cut = after_name($0)
      if (cut >= 0) { name = 0; resolve(substr($0, cut + 1)) }
      next
    }
    match($0, /^[ \t]*export ("([^"\\]|\\.)*"|[^ \t=]+)\\?=/) {
      withheld = 1
      resolve(substr($0, RLENGTH + 1))
      next
    }
    /^[ \t]*export "/ && open_name($0) { name = 1; withheld = 1; next }
    { print; fflush() }
    END {
      if (skip || name) {
        print "xcodebuild_filter: " withheld (withheld == 1 ? " line" : " lines") " withheld after an unterminated exported value"
        fflush()
      }
    }' |
    tee "$log" |
    if command -v xcbeautify >/dev/null 2>&1; then
      xcbeautify --quiet --disable-logging
      formatter_status=$?
      cat >/dev/null
      exit "$formatter_status"
    else
      cat
    fi
}

# xcodebuild_finish <label> <xcodebuild status> [<filter status>]: after the formatter has exited, prints the lines
# xcbeautify --quiet drops (run totals, failure blocks, banners) from the env-free log, the last 80 lines of that log
# when xcodebuild failed, and a "formatter failed" line when the filter pipeline did. Returns xcodebuild's own status.
xcodebuild_finish() {
  local label="$1" status="$2" filter_status="${3:-0}" log=""
  log="$(xcodebuild_log_path "$label")" || log=""
  if [[ -n "$log" && -s "$log" ]]; then
    local summary
    summary="$(LC_ALL=C awk '
      /Test run with [0-9]+ tests?/ { print; block = 0; next }
      /^\*\* [A-Z ]+ \*\*[ \t\r]*$/ { print; block = 0; next }
      /^(Testing failed|Failing tests|The following build commands failed):/ { print; block = 1; next }
      block && /^[ \t]/ { print; next }
      block && /^\([0-9]+ failures?\)/ { print; block = 0; next }
      { block = 0 }' "$log")" || summary=""
    if [[ -n "$summary" ]]; then
      printf 'xcodebuild summary (%s):\n%s\n' "$label" "$summary"
    fi
    if [[ "$status" != 0 ]]; then
      printf 'xcodebuild failed with status %s; last 80 lines of the env-free log %s:\n' "$status" "$log"
      tail -n 80 "$log" || true
    fi
  elif [[ "$status" != 0 ]]; then
    if [[ -n "$log" && -e "$log" ]]; then
      printf 'xcodebuild failed with status %s; env-free log kept but empty for %s: %s\n' "$status" "$label" "$log"
    else
      printf 'xcodebuild failed with status %s; no env-free log was kept for %s\n' "$status" "$label"
    fi
  fi
  if [[ "$filter_status" != 0 ]]; then
    printf 'xcodebuild_filter: formatter failed for %s (exit status %s); output above may be incomplete%s\n' \
      "$label" "$filter_status" "${log:+, full env-free log: $log}" >&2
  fi
  return "$status"
}

# with_deadline <seconds> <cmd...>: macOS has no GNU timeout. The command runs in a process group of its own; when it is
# still running after the deadline the whole group is killed (so a child it forked cannot keep a $(...) pipe open and hang
# the caller) and the status is 142, as a SIGALRM death was. Otherwise the command's status (128+signal if it was
# signalled). The group is also killed if this wrapper is terminated (HUP, INT, TERM). The command also arms its own alarm
# one second after the deadline, before exec (an alarm survives exec), so a wrapper that is SIGKILLed cannot leave it
# running without a deadline; the wrapper's alarm fires first, and a command that dies of that backup alarm gets its group
# killed too.
# Limits, which callers must not rely on past: a descendant that leaves the process group (setsid, setpgid, a daemon) is
# not reached by the group kill and can keep a $(...) pipe open, so the caller can still wait for it; and a wrapper that is
# SIGKILLed cannot kill the group, so only the command itself dies at the deadline, not what it forked.
with_deadline() {
  local secs="$1"
  shift
  perl -e '
    use POSIX ();
    my $secs = shift;
    my $pid = fork;
    die "fork failed\n" unless defined $pid;
    if (!$pid) {
      POSIX::setpgid(0, 0);
      alarm $secs + 1;
      exec @ARGV or die "exec failed\n";
    }
    POSIX::setpgid($pid, $pid);
    $SIG{ALRM} = sub { kill "KILL", -$pid; exit 142 };
    for my $signal ([HUP => 129], [INT => 130], [TERM => 143]) {
      $SIG{$signal->[0]} = sub { kill "KILL", -$pid; exit $signal->[1] };
    }
    alarm $secs;
    waitpid $pid, 0;
    alarm 0;
    kill "KILL", -$pid if ($? & 127) == 14;
    exit($? & 127 ? 128 + ($? & 127) : $? >> 8);
  ' "$secs" "$@"
}

# simctl_limit <variable> <default> <min> <max>: the whole-number value of an environment override, else the default.
simctl_limit() {
  local value="${!1:-}"
  if [[ "$value" =~ ^[0-9]+$ ]] && ((10#$value >= $3 && 10#$value <= $4)); then
    printf '%d' "$((10#$value))"
  else
    printf '%s' "$2"
  fi
}

# simulator_reduce <text>: the part of a key that may appear in a device name. LC_ALL=C keeps the ranges ASCII; letters,
# digits and "-" survive (simctl names allow "-"), "_" becomes "." (so x-ab_cd and x-abcd stay distinct, and a "." in
# the input is dropped first so nothing else can produce one), everything else is dropped.
simulator_reduce() {
  local LC_ALL=C key="$1"
  key="${key//[^A-Za-z0-9_-]/}"
  printf '%s' "${key//_/.}"
}

# simulator_key: the build key's distinguishing part, so concurrent trees never share a simulator device (M1-26). A
# stable key names the device: CLEAN_DEV_SESSION x-<key> (the orchestrated wrapper), else the last 12 characters of
# CODEX_THREAD_ID (the whole id when it is shorter; the same rule the routing applies). An interactive session key
# (c-<hex>) is new for every session, so it would leave a device per session: those runs use the checkout directory name,
# one device per tree. A key that reduces to nothing falls back to the checkout name too.
simulator_key() {
  local session="${CLEAN_DEV_SESSION:-}" key="" thread="${CODEX_THREAD_ID:-}"
  case "$session" in
    c-*) ;;
    x-*) key="${session#x-}" ;;
    "")
      key="$thread"
      ((${#key} <= 12)) || key="${key: -12}"
      ;;
    *) key="$session" ;;
  esac
  key="$(simulator_reduce "$key")"
  [[ -n "$key" ]] || key="$(simulator_reduce "$(basename "$WGEX_ROOT")")"
  if [[ -z "$key" ]]; then
    echo "simulator_key: no usable build key" >&2
    return 1
  fi
  printf '%s' "$key"
}

# simulator_name <iOS|tvOS>: name of the WGEX-owned simulator device for this build key.
simulator_name() {
  local key
  key="$(simulator_key)" || return
  case "$1" in
    iOS) printf 'WGEX iPhone %s' "$key" ;;
    tvOS) printf 'WGEX Apple TV %s' "$key" ;;
    *)
      echo "simulator_name: unknown platform $1 (expected iOS or tvOS)" >&2
      return 2
      ;;
  esac
}

# simulator_tool <select|prune> <arguments>: the one place that talks to simctl (M1-26). Every simctl call runs under a
# deadline, killed with its process group when exceeded: WGEX_SIMCTL_LIST_DEADLINE (list, default 60 s, 1-600) and
# WGEX_SIMCTL_CREATE_DEADLINE (create and delete, default 180 s, 1-900). WGEX_SIMCTL_RETRY_SECONDS (default 5, 0-30) is
# the wait before the one retry of an empty runtime list or a device list with no entry for the chosen runtime (a cold
# CoreSimulator answers like that for a moment).
#
# select <iOS|tvOS> <name> <lookup|ensure|ensure-if-installed>: finds the available, not "Creating" simulator device whose
# name is exactly <name> on the newest installed, available <platform> 27.x runtime; the name must start with "WGEX ", so
# no other device can ever be returned. stdout: <udid> TAB <runtime> TAB <device type> TAB <reused|created>.
# lookup: exit 3 when there is no such device. ensure: creates it from that runtime and the newest device type of the
# platform's family the runtime supports (iPhone, or Apple TV), derived from simctl's JSON, but only when the device
# list has an entry for the runtime (else one retry, then exit 1); afterwards the list is read again: with more than one
# device of that name on the runtime the lowest UDID is kept and the others are deleted when they are WGEX-owned and
# Shutdown, and a create that fails (or answers no UDID) deletes the device of that name it left behind (a UDID not in
# the list read before the create). Exit 4 when no such runtime is installed (stderr names it; the list is retried once
# when simctl lists no runtime at all), 5 when it supports no device type. ensure-if-installed is ensure with exit 4
# silent. Exit 2: refused name; 1: simctl failed, timed out or answered unexpectedly. The simctl verbs used are list,
# create and (only for devices this run made) delete; never boot, shutdown, erase, runtime download or a CoreSimulator
# restart.
#
# prune [--apply]: manual housekeeping (`just sim-prune`; never part of a gate). Looks only at devices named
# "WGEX (iPhone|Apple TV) ..." and deletes only the Shutdown ones (never Booted, Booting or Creating) that are
# duplicates of a surviving device of the same name on the same runtime (lowest UDID survives), sit on a runtime that is
# no longer installed or available, or were not booted for more than 14 days (the newer of lastBootedAt and lastUsedAt;
# a device without a usable one is kept). A dry run by default; --apply deletes. One line per WGEX device: decision,
# name, UDID, reason.
simulator_tool() {
  WGEX_SIMCTL_LIST_DEADLINE="$(simctl_limit WGEX_SIMCTL_LIST_DEADLINE 60 1 600)" \
  WGEX_SIMCTL_CREATE_DEADLINE="$(simctl_limit WGEX_SIMCTL_CREATE_DEADLINE 180 1 900)" \
  WGEX_SIMCTL_RETRY_SECONDS="$(simctl_limit WGEX_SIMCTL_RETRY_SECONDS 5 0 30)" \
    python3 -I - "$@" <<'PY'
import datetime
import json
import os
import re
import signal
import subprocess
import sys
import time

LIST_DEADLINE = int(os.environ["WGEX_SIMCTL_LIST_DEADLINE"])
CREATE_DEADLINE = int(os.environ["WGEX_SIMCTL_CREATE_DEADLINE"])
RETRY_SECONDS = int(os.environ["WGEX_SIMCTL_RETRY_SECONDS"])
STALE_DAYS = 14
FAMILY = {"iOS": "iPhone", "tvOS": "Apple TV"}
OWNED = re.compile(r"WGEX (iPhone|Apple TV) ")  # the only devices that are ever deleted
UDID = re.compile(r"[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}")


def fail(status, message):
    print(f"simulator: {message}", file=sys.stderr)
    sys.exit(status)


def unexpected(kind, value, _trace):
    print(f"simulator: unexpected simctl answer ({kind.__name__}: {value})", file=sys.stderr)


sys.excepthook = unexpected  # an uncaught error is a one-line message and exit status 1, never a traceback


def attempt(deadline, *arguments):
    """`xcrun simctl <arguments>` under a deadline: (succeeded, stdout, first stderr line or the failure)."""
    process = subprocess.Popen(["xcrun", "simctl", *arguments], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        out, err = process.communicate(timeout=deadline)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            process.kill()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        return False, "", f"timed out after {deadline} s (CoreSimulator is not answering)"
    if process.returncode != 0:
        return False, out, (err.strip().splitlines() or [f"exit status {process.returncode}"])[0]
    return True, out, ""


def simctl(deadline, *arguments):
    done, out, detail = attempt(deadline, *arguments)
    if not done:
        fail(1, f"simctl {' '.join(arguments)} failed: {detail}")
    return out


def listing(kind):
    try:
        return json.loads(simctl(LIST_DEADLINE, "list", kind, "-j"))
    except ValueError:
        fail(1, f"simctl list {kind} did not return JSON")


def all_devices():
    return listing("devices")["devices"]


def all_runtimes():
    """The runtime list; one that is empty (a cold CoreSimulator) is read once more after a short wait."""
    runtimes = listing("runtimes")["runtimes"]
    if not runtimes:
        time.sleep(RETRY_SECONDS)
        runtimes = listing("runtimes")["runtimes"]
    return runtimes


def accepted_runtimes(platform):
    """Installed, available <platform> 27.x runtimes, newest first. At the same version the generic runtime
    (SimRuntime.iOS-27-2) wins over a device-specific build (SimRuntime.iOS-27-2-iPhone19-4), whose simulators can fail
    their first boot with "Data Migration Failed" (M04-T31)."""
    marker = f".SimRuntime.{platform}-"
    generic = re.compile(r"\.SimRuntime\.[A-Za-z]+-\d+(-\d+)*$")
    found = []
    for runtime in all_runtimes():
        version = runtime.get("version", "")
        if marker in runtime["identifier"] and runtime.get("isAvailable", True) and re.fullmatch(r"27(\.\d+)*", version):
            found.append(((tuple(int(part) for part in version.split(".")), bool(generic.search(runtime["identifier"]))), runtime))
    return [runtime for _, runtime in sorted(found, key=lambda entry: entry[0], reverse=True)]


def usable(devices, runtime_id, name):
    """Devices named exactly <name> on the runtime that can be used: available and not still being created; lowest UDID first."""
    return sorted((device for device in devices.get(runtime_id) or []
                   if device["name"] == name and device.get("isAvailable", True) and device.get("state") != "Creating"),
                  key=lambda device: device["udid"])


def delete(device, own=False):
    """simctl delete for a WGEX-owned device that is Shutdown (or, for a device this very run made, still Creating);
    anything else is refused. (succeeded, detail)"""
    if not OWNED.match(device["name"]) or device.get("state") not in (("Shutdown", "Creating") if own else ("Shutdown",)):
        return False, "refused: not a WGEX-owned Shutdown device"
    done, _, detail = attempt(CREATE_DEADLINE, "delete", device["udid"])
    return done, detail


def reply(device, runtime_id, state):
    print("\t".join((device["udid"], runtime_id, device.get("deviceTypeIdentifier", ""), state)))
    sys.exit(0)


def select(platform, name, mode):
    if platform not in FAMILY or mode not in ("lookup", "ensure", "ensure-if-installed"):
        fail(2, f"unknown platform or mode: {platform} {mode}")
    if not name.startswith("WGEX ") or len(name) == len("WGEX "):
        fail(2, f"refusing {name!r}: only devices whose name starts with 'WGEX ' are ever selected")
    runtimes = accepted_runtimes(platform)
    if not runtimes:
        if mode == "lookup":
            sys.exit(3)
        if mode == "ensure":
            fail(4, f"no available {platform} 27.x simulator runtime is installed (looked for "
                    f"com.apple.CoreSimulator.SimRuntime.{platform}-27-*); install it in Xcode, nothing is downloaded here")
        sys.exit(4)
    runtime = runtimes[0]
    runtime_id = runtime["identifier"]
    devices = all_devices()
    found = usable(devices, runtime_id, name)
    if found:
        reply(found[0], runtime_id, "reused")
    if mode == "lookup":
        sys.exit(3)
    if runtime_id not in devices:
        # simctl lists every installed runtime, even with no devices: no entry is a fault, never a licence to create
        time.sleep(RETRY_SECONDS)
        devices = all_devices()
        found = usable(devices, runtime_id, name)
        if found:
            reply(found[0], runtime_id, "reused")
        if runtime_id not in devices:
            fail(1, f"simctl listed no devices entry for {runtime_id}; not creating {name!r}")

    supported = {entry["identifier"] for entry in runtime.get("supportedDeviceTypes", [])}
    ranked = []
    for device_type in listing("devicetypes")["devicetypes"]:
        model = re.search(r"(\d+),(\d+)$", device_type.get("modelIdentifier", ""))
        if device_type.get("productFamily") == FAMILY[platform] and device_type["identifier"] in supported and model:
            # Newest generation first; within a generation the lowest model number is the flagship (Pro before Pro Max, e).
            ranked.append(((int(model.group(1)), -int(model.group(2))), device_type["identifier"]))
    if not ranked:
        fail(5, f"{runtime_id} supports no {FAMILY[platform]} device type")
    device_type = max(ranked)[1]

    before = {device["udid"] for group in devices.values() for device in group or []}
    done, out, detail = attempt(CREATE_DEADLINE, "create", name, device_type, runtime_id)
    udid = out.strip()
    if not done or not UDID.fullmatch(udid):
        # a device this run made before failing is this run's own: remove it so the next run starts clean
        notes = []
        try:
            for group in all_devices().values():
                for device in group or []:
                    if device["name"] == name and device["udid"] not in before:
                        removed, why = delete(device, own=True)
                        notes.append(f"removed the half-made device {device['udid']}" if removed
                                     else f"could not remove the half-made device {device['udid']}: {why}")
        except SystemExit:
            notes.append("could not list devices to remove a half-made one")
        fail(1, f"simctl create {name} {device_type} {runtime_id} " + (f"failed: {detail}" if not done else "did not return a UDID")
                + "".join(f"; {note}" for note in notes))

    after = usable(all_devices(), runtime_id, name)
    if not after:
        fail(1, f"simctl created {udid} but the device list has no usable device named {name!r}")
    kept = after[0]
    for extra in after[1:]:  # a concurrent first run made a twin: keep the lowest UDID, drop the rest if WGEX-owned and Shutdown
        removed, why = delete(extra)
        if not removed:
            print(f"simulator: duplicate {extra['udid']} of {name!r} kept: {why}", file=sys.stderr)
    reply(kept, runtime_id, "created" if kept["udid"].upper() == udid.upper() else "reused")


def prune(arguments):
    if arguments not in ([], ["--apply"]):
        fail(2, f"usage: prune [--apply] (got {' '.join(arguments)})")
    apply = bool(arguments)
    installed = {runtime["identifier"] for runtime in all_runtimes() if runtime.get("isAvailable", True)}
    if not installed:
        fail(1, "refusing to prune: simctl lists no available runtime, so every device would look orphaned")
    devices = all_devices()
    now = datetime.datetime.now(datetime.timezone.utc)
    owned = sorted(((device["udid"], runtime_id, device) for runtime_id, group in devices.items() for device in group or []
                    if OWNED.match(device.get("name", ""))), key=lambda entry: entry[0])
    decisions = {}  # udid -> (delete?, reason)
    survivors = {}
    for udid, runtime_id, device in owned:
        if device.get("state") != "Shutdown":
            decisions[udid] = (False, f"state {device.get('state')}: never deleted")
        elif runtime_id not in installed or not device.get("isAvailable", True):
            decisions[udid] = (True, f"runtime {runtime_id} is no longer installed or available")
        else:
            stamps = []  # (moment, field): the newer of lastBootedAt and lastUsedAt counts, whichever field carries it
            for field in ("lastBootedAt", "lastUsedAt"):
                if device.get(field):
                    try:
                        moment = datetime.datetime.fromisoformat(device[field].replace("Z", "+00:00"))
                        stamps.append((moment if moment.tzinfo else moment.replace(tzinfo=datetime.timezone.utc), field))
                    except ValueError:
                        pass
            seen, source = max(stamps, default=(None, None))
            if seen is None:
                decisions[udid] = (False, "no usable boot or creation time reported: kept")
            elif now - seen > datetime.timedelta(days=STALE_DAYS):
                decisions[udid] = (True, f"not booted for {(now - seen).days} days ({source} {device[source]})")
            else:
                survivors.setdefault((device["name"], runtime_id), []).append(udid)
    for (name, runtime_id), udids in survivors.items():
        decisions[udids[0]] = (False, f"kept: the lowest UDID of {name!r} on {runtime_id}")
        for udid in udids[1:]:
            decisions[udid] = (True, f"duplicate of {udids[0]}")

    current = {device["udid"]: device for group in all_devices().values() for device in group or []} if apply else {}
    failures = 0
    print(f"sim-prune: {'applying' if apply else 'dry run (pass --apply to delete)'}; "
          f"{len(owned)} WGEX device(s), {STALE_DAYS}-day limit")
    for udid, _, device in owned:
        remove, reason = decisions[udid]
        verdict = "keep" if not remove else "would-delete"
        if remove and apply:
            now_device = current.get(udid)
            if now_device is None or now_device["name"] != device["name"] or now_device.get("state") != "Shutdown":
                verdict, reason = "skipped", "changed since it was listed"
            else:
                removed, why = delete(now_device)
                verdict = "deleted" if removed else "delete-failed"
                failures += not removed
                reason = reason if removed else f"{reason} ({why})"
        print(f"{verdict}\t{device['name']}\t{udid}\t{reason}")
    sys.exit(1 if failures else 0)


command, *rest = sys.argv[1:]
if command == "select" and len(rest) == 3:
    select(*rest)
elif command == "prune":
    prune(rest)
else:
    fail(2, f"unknown command: {command} {' '.join(rest)}")
PY
}

# simulator_select <iOS|tvOS> <name> <lookup|ensure|ensure-if-installed>: see simulator_tool.
simulator_select() {
  simulator_tool select "$@"
}

# simulator_device <iOS|tvOS> <lookup|ensure|ensure-if-installed>: simulator_select for this build key's WGEX device.
simulator_device() {
  local name
  name="$(simulator_name "$1")" || return
  simulator_select "$1" "$name" "$2"
}

# simulator_prune [--apply]: see simulator_tool (`just sim-prune`).
simulator_prune() {
  simulator_tool prune "$@"
}
