#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Compares the host toolchain with Toolchain.lock and reports host readiness.
# Exit status: 0 when every tool meets its minimum (Go modules match exactly), 1 on any FAIL row.
# Usage: Tools/doctor/doctor.sh [--quiet] [--redact]
#   --quiet   show FAIL rows and the summary; warnings alone do not fail
#   --redact  mask device UDIDs, identity holder names and $HOME (for evidence files)
# Read-only apart from writing Config/host-uuid.local (git-ignored).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=Config/Scripts/lib.sh
source "$ROOT/Config/Scripts/lib.sh"
LOCK="$ROOT/Toolchain.lock"
SPARKLE_DIR="${WGEX_SPARKLE_DIR:-$HOME/.wgex/tools/sparkle}"
DEVID_KEYCHAIN="${WGEX_DEVID_KEYCHAIN:-$HOME/.wgex/developer_id_application.keychain-db}"
CERT_WARN_DAYS=60
REDACT=0
QUIET=0
for argument in "$@"; do
  case "$argument" in
    --redact) REDACT=1 ;;
    --quiet) QUIET=1 ;;
    *)
      echo "doctor: unknown argument $argument" >&2
      exit 2
      ;;
  esac
done

FAILS=0
WARNS=0

# lock <section> <key>: value of key in [section] of Toolchain.lock
lock() {
  awk -v sec="[$1]" -v key="$2" '
    /^\[/ { insec = ($0 == sec); next }
    insec && $1 == key { sub(/^[^=]*= *"/, ""); sub(/".*$/, ""); print; exit }
  ' "$LOCK"
}

redact() {
  if ((REDACT)); then
    sed -E -e "s#${HOME}#~#g" \
      -e 's/[0-9A-F]{8}-[0-9A-F]{4,16}(-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})?/<udid>/g' \
      -e 's/: [^"(]+ \(/: <name> (/'
  else
    sed -e "s#${HOME}#~#g"
  fi
}

row() { # row <status> <item> <detail>
  local status="$1" item="$2" detail="$3"
  case "$status" in
    FAIL) FAILS=$((FAILS + 1)) ;;
    WARN) WARNS=$((WARNS + 1)) ;;
  esac
  ((QUIET == 0)) || [[ "$status" == FAIL ]] || return 0
  printf '%-5s %-26s %s\n' "$status" "$item" "$(printf '%s' "$detail" | redact)"
}

# check_exact <item> <expected> <actual>: offline Go module identities only.
check_exact() {
  if [[ -z "$3" ]]; then
    row FAIL "$1" "missing (expected $2)"
  elif [[ "$3" == "$2" ]]; then
    row OK "$1" "$3"
  else
    row FAIL "$1" "found $3, expected $2"
  fi
}

# Numeric dotted versions, with an optional Go prefix; absent trailing components are zero.
# Keep this self-contained helper in sync with Engine/scripts/lib.sh (test_toolchain.py covers both).
version_at_least() {
  awk -v found="$1" -v floor="$2" 'BEGIN {
    sub(/^go/, "", found); sub(/^go/, "", floor)
    if (found !~ /^[0-9]+(\.[0-9]+)*$/ || floor !~ /^[0-9]+(\.[0-9]+)*$/) exit 1
    nf = split(found, f, "."); nm = split(floor, m, ".")
    for (i = 1; i <= nf || i <= nm; i++)
      if (f[i]+0 != m[i]+0) exit (f[i]+0 < m[i]+0)
    exit 0
  }'
}

# check <item> <minimum> <actual>
check() {
  if [[ -z "$3" ]]; then
    row FAIL "$1" "missing (minimum $2)"
  elif version_at_least "$3" "$2"; then
    row OK "$1" "$3 (minimum $2)"
  else
    row FAIL "$1" "found $3, minimum $2"
  fi
}

# with_deadline <seconds> <cmd...> comes from Config/Scripts/lib.sh (macOS has no GNU timeout)

first_match() { grep -Eo "$1" | head -n1; }

if [[ ! -f "$LOCK" ]]; then
  echo "doctor: $LOCK not found" >&2
  exit 1
fi

((QUIET)) || printf '%-5s %-26s %s\n' "STATE" "ITEM" "DETAIL"
((QUIET)) || printf '%s\n' "------------------------------------------------------------------------------"

# Xcode and Swift
dev_dir="$(xcode-select -p 2>/dev/null || true)"
if [[ -d "$dev_dir" ]]; then row OK "xcode-select" "$dev_dir"; else row FAIL "xcode-select" "no developer directory"; fi
xb="$(xcodebuild -version 2>/dev/null || true)"
check "xcode version" "$(lock xcode version)" "$(printf '%s' "$xb" | sed -n 's/^Xcode //p')"
row INFO "xcode build" "$(printf '%s' "$xb" | sed -n 's/^Build version //p')"
sv="$(swift --version 2>/dev/null || true)"
check "swift version" "$(lock swift version)" "$(printf '%s' "$sv" | sed -nE 's/.*Swift version ([0-9.]+).*/\1/p' | head -n1)"
row INFO "swift build" "$(printf '%s' "$sv" | first_match 'swiftlang-[0-9.]+')"

# Go and XcodeGen
check "go" "$(lock go version)" "$(go version 2>/dev/null | first_match 'go[0-9]+\.[0-9]+(\.[0-9]+)?' || true)"
check "xcodegen" "$(lock xcodegen version)" "$(xcodegen --version 2>/dev/null | sed -n 's/^Version: //p')"

# Engine artefacts (M1-28): a link in Binary/ or on Binary itself, Packages/WGEXEngine or Packages can point into another
# tree's build, so verification would pass or fail on that tree's provenance and each tree's build would overwrite the
# other's. One root-anchored rule, the same as the writers and source-digest.py --verify: Binary must resolve to exactly
# "$(cd "$ROOT" && pwd -P)/Packages/WGEXEngine/Binary". FAIL with the fix.
engine_binary="$ROOT/Packages/WGEXEngine/Binary"
engine_links=""
engine_dir_link=""
for engine_part in Packages Packages/WGEXEngine Packages/WGEXEngine/Binary; do
  if [[ -L "$ROOT/$engine_part" ]]; then
    engine_dir_link="$engine_part is a symlink to $(readlink "$ROOT/$engine_part")"
    break
  fi
done
if [[ -z "$engine_dir_link" ]]; then
  engine_deepest="$engine_binary"
  while [[ ! -e "$engine_deepest" && "$engine_deepest" != "$ROOT" ]]; do
    engine_deepest="$(dirname "$engine_deepest")"
  done
  engine_real="$(cd "$engine_deepest" && pwd -P)"
  if [[ "$engine_real" != "$(cd "$ROOT" && pwd -P)${engine_deepest#"$ROOT"}" ]]; then
    engine_dir_link="${engine_deepest#"$ROOT"/} resolves to $engine_real"
  fi
fi
if [[ -n "$engine_dir_link" ]]; then
  engine_links="Packages/WGEXEngine/Binary or a parent is a link ($engine_dir_link); remove it and run just engine"
else
  for artefact in provenance.json provenance-test.json WGEXEngine.xcframework WGEXEngineTest.xcframework; do
    if [[ -L "$engine_binary/$artefact" ]]; then
      engine_links="$engine_links${engine_links:+; }$artefact is a symlink to $(readlink "$engine_binary/$artefact")"
    fi
  done
  [[ -z "$engine_links" ]] || engine_links="$engine_links; remove the link and run just engine"
fi
if [[ -n "$engine_links" ]]; then
  row FAIL "engine artefacts" "$engine_links"
elif [[ -d "$engine_binary" ]]; then
  row OK "engine artefacts" "no symlinks in Packages/WGEXEngine/Binary"
else
  row OK "engine artefacts" "not built yet (just engine)"
fi

# Homebrew tools
brew_tool() { # brew_tool <lock key> <command> <version command...>
  local key="$1" cmd="$2"
  shift 2
  if ! command -v "$cmd" >/dev/null 2>&1; then
    row FAIL "$key" "missing (minimum $(lock homebrew "$key"))"
    return
  fi
  check "$key" "$(lock homebrew "$key")" "$("$@" 2>/dev/null | first_match '[0-9]+\.[0-9]+\.[0-9]+' || true)"
}
brew_tool swiftlint swiftlint swiftlint version
brew_tool swiftformat swiftformat swiftformat --version
brew_tool just just just --version
brew_tool xcbeautify xcbeautify xcbeautify --version
brew_tool typos typos typos --version
brew_tool shellcheck shellcheck shellcheck --version
brew_tool shfmt shfmt shfmt --version
brew_tool pre-commit pre-commit pre-commit --version
brew_tool gitleaks gitleaks gitleaks version
brew_tool python3 python3 python3 -I --version
brew_tool rg rg rg --version

# Go tools: compare module path and version embedded in the binary
for tool in staticcheck go-licenses govulncheck; do
  want="$(lock go_tools "$tool")"
  bin="$(command -v "$tool" 2>/dev/null || true)"
  if [[ -z "$bin" ]]; then
    row FAIL "$tool" "missing (expected $want)"
    continue
  fi
  got="$(go version -m "$bin" 2>/dev/null | awk '$1 == "path" { p = $2 } $1 == "mod" { v = $3 } END { print p "@" v }')"
  check_exact "$tool" "$want" "$got"
done

# SDKs
for sdk in macosx iphoneos iphonesimulator appletvos appletvsimulator; do
  path="$(xcrun --sdk "$sdk" --show-sdk-path 2>/dev/null || true)"
  if [[ -n "$path" && -d "$path" ]]; then
    row OK "sdk $sdk" "$(basename "$path")"
  else
    row FAIL "sdk $sdk" "not installed"
  fi
done

# Simulator runtimes (iOS required; tvOS pending P0-11, so a warning).
# A cold CoreSimulator can fail or list nothing on the first call: retry once after about 5 s (M1-23) and
# report a simctl failure ("simctl unavailable: <first stderr line>") apart from a missing runtime.
runtimes=""
simctl_error=""
# The stderr file is optional: with TMPDIR missing or unwritable the row falls back to "exit status N". It is removed on
# every exit path, including a TERM, INT or HUP while simctl is still running (a leftover turns the next self-test red).
simctl_errfile=/dev/null
remove_simctl_errfile() { [[ "$simctl_errfile" == /dev/null ]] || rm -f "$simctl_errfile"; }
trap remove_simctl_errfile EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
simctl_errfile="$(mktemp "${TMPDIR:-/tmp}/wgex-doctor-simctl.XXXXXX" 2>/dev/null)" || simctl_errfile=/dev/null
# Retry wait in whole seconds, 0-30; anything else (empty, negative, fractional, units) uses 5.
simctl_retry="${WGEX_DOCTOR_SIMCTL_RETRY_SECONDS:-5}"
[[ "$simctl_retry" =~ ^(0|[1-9]|[12][0-9]|30)$ ]] || simctl_retry=5
simctl_deadline="$(simctl_limit WGEX_SIMCTL_LIST_DEADLINE 60 1 600)"
for simctl_attempt in 1 2; do
  simctl_status=0
  simctl_output="$(with_deadline "$simctl_deadline" xcrun simctl list runtimes 2>"$simctl_errfile")" || simctl_status=$?
  simctl_error=""
  if ((simctl_status != 0)); then
    simctl_error="$(head -n 1 "$simctl_errfile")"
    # with_deadline exits 142 explicitly when its alarm fires (the wrapper's own status, not a signal death): a wedged
    # CoreSimulator is named, not shown as a bare status
    if ((simctl_status == 142)); then simctl_error="simctl list runtimes timed out after $simctl_deadline s"; fi
    : "${simctl_error:=exit status $simctl_status}"
  fi
  runtimes="$(printf '%s\n' "$simctl_output" | grep -E '^(iOS|tvOS|watchOS|visionOS|xrOS) ' || true)"
  [[ -n "$simctl_error" || -z "$runtimes" ]] || break
  ((simctl_attempt == 2)) || sleep "$simctl_retry"
done
[[ "$simctl_errfile" == /dev/null ]] || rm -f "$simctl_errfile"
for os in iOS tvOS; do
  line="$(printf '%s\n' "$runtimes" | grep -E "^$os 27" | head -n1 | sed -E 's/ - com\.apple.*$//')"
  if [[ -n "$line" ]]; then
    row OK "simulator $os" "$line"
  elif [[ -n "$simctl_error" ]]; then
    row "$([[ "$os" == tvOS ]] && echo WARN || echo FAIL)" "simulator $os" "simctl unavailable: $simctl_error"
  elif [[ "$os" == "tvOS" ]]; then
    row WARN "simulator $os" "no tvOS 27 runtime (download pending, ticket P0-11)"
  else
    row FAIL "simulator $os" "no $os 27 runtime"
  fi
done

# WGEX-owned iOS simulator device for this build key (M1-26): informational, created on first hosted test; read-only here.
if sim_name="$(simulator_name iOS 2>/dev/null)"; then
  sim_status=0
  sim_line="$(simulator_select iOS "$sim_name" lookup 2>/dev/null)" || sim_status=$?
  case "$sim_status" in
    0) row INFO "wgex simulator" "$sim_name (present, $(printf '%s' "$sim_line" | cut -f1))" ;;
    3) row INFO "wgex simulator" "$sim_name (will be created on first hosted test)" ;;
    *) row INFO "wgex simulator" "$sim_name (state unknown: simctl unavailable)" ;;
  esac
else
  row INFO "wgex simulator" "no usable build key"
fi

# Code-signing identities: names only, never hashes; certificate expiry warnings
ids="$(security find-identity -v -p codesigning 2>/dev/null | sed -nE 's/^ *[0-9]+\) [0-9A-F]+ "(.*)"$/\1/p' || true)"
if [[ -z "$ids" ]]; then
  row WARN "signing identities" "none in the default keychain search list"
else
  while IFS= read -r name; do
    expiry="$(security find-certificate -c "$name" -p 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | sed 's/^notAfter=//')"
    if security find-certificate -c "$name" -p 2>/dev/null |
      openssl x509 -noout -checkend $((CERT_WARN_DAYS * 86400)) >/dev/null 2>&1; then
      row OK "signing identity" "$name (expires $expiry)"
    else
      row WARN "signing identity" "$name expires within $CERT_WARN_DAYS days ($expiry)"
    fi
  done <<<"$ids"
fi

# Developer ID keychain: presence only, never unlocked or read
if [[ -f "$DEVID_KEYCHAIN" ]]; then
  row OK "developer id keychain" "present"
else
  row WARN "developer id keychain" "not found at $DEVID_KEYCHAIN"
fi

# Offline floor verification must not inspect the lab or contact devices.
if [[ "${WGEX_OFFLINE:-0}" == 1 ]]; then
  row INFO "devices and lab" "skipped (WGEX_OFFLINE=1)"
else
  # Paired physical devices
  devs="$(with_deadline 30 xcrun devicectl list devices 2>/dev/null | awk '/ physical *$/' || true)"
  if [[ -z "$devs" ]]; then
    row INFO "devices" "no physical devices known to devicectl"
  else
    while IFS= read -r d; do
      d="$(printf '%s' "$d" | sed -E 's/ +physical *$//; s/  +/  /g')"
      ((REDACT)) && d="<device>  $(printf '%s' "$d" | sed -E 's/^.*\(UDID\) *//')"
      row INFO "device" "$d"
    done <<<"$devs"
  fi

  # Lab VMs and containers (informational)
  if command -v tart >/dev/null 2>&1; then
    n="$(with_deadline 20 tart list --quiet 2>/dev/null | grep -c . || true)"
    row INFO "tart" "$(tart --version 2>/dev/null), ${n:-0} VM(s)"
  else
    row INFO "tart" "not installed (lab)"
  fi
  if command -v limactl >/dev/null 2>&1; then
    n="$(with_deadline 20 limactl list --quiet 2>/dev/null | grep -c . || true)"
    row INFO "lima" "$(limactl --version 2>/dev/null | first_match '[0-9]+\.[0-9]+\.[0-9]+'), ${n:-0} instance(s)"
  else
    row INFO "lima" "not installed (lab)"
  fi
  if command -v docker >/dev/null 2>&1; then
    if server="$(with_deadline 10 docker info --format '{{.ServerVersion}}' 2>/dev/null)" && [[ -n "$server" ]]; then
      row INFO "docker" "client $(docker --version | first_match '[0-9]+\.[0-9]+\.[0-9]+'), daemon $server running"
    else
      row INFO "docker" "client $(docker --version | first_match '[0-9]+\.[0-9]+\.[0-9]+'), daemon not running"
    fi
  else
    row INFO "docker" "not installed"
  fi

fi

# Sparkle release archive
sp_ver="$(lock sparkle version)"
sp_file="$SPARKLE_DIR/$sp_ver/$(lock sparkle archive)"
if [[ ! -f "$sp_file" ]]; then
  row WARN "sparkle archive" "missing: $sp_file"
else
  if [[ "$(lock sparkle sha256)" == "$(shasum -a 256 "$sp_file" | awk '{ print $1 }')" ]]; then
    row OK "sparkle sha256" "matches pin"
  else
    row WARN "sparkle sha256" "does not match pin (required at M3)"
  fi
fi

# Host IOPlatformUUID into Config/host-uuid.local (git-ignored; value not printed)
uuid="$(ioreg -rd1 -c IOPlatformExpertDevice | sed -nE 's/.*"IOPlatformUUID" = "([^"]+)".*/\1/p')"
if [[ -n "$uuid" ]]; then
  printf '%s\n' "$uuid" >"$ROOT/Config/host-uuid.local"
  row OK "host uuid" "written to Config/host-uuid.local"
else
  row FAIL "host uuid" "IOPlatformUUID not found"
fi

((QUIET)) || printf '%s\n' "------------------------------------------------------------------------------"
printf 'doctor: %d failure(s), %d warning(s)\n' "$FAILS" "$WARNS"
((FAILS == 0))
