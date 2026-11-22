# SPDX-License-Identifier: MIT
# shellcheck shell=bash
# shellcheck disable=SC2034 # variables set here are read by the sourcing scripts
# Shared helpers for the engine build scripts. Source, do not execute.
# bash 3.2 compatible: no associative arrays, no mapfile, no ${var,,}.

ENGINE_SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$ENGINE_SCRIPTS/../.." && pwd)"
GO_DIR="$ROOT/Engine/go"
LOCK="$ROOT/Toolchain.lock"
BIN_DIR="$ROOT/Packages/WGEXEngine/Binary"
MIN_OS="26.0"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}
log() { printf '==> %s\n' "$*"; }

# require_own_binary: Packages/WGEXEngine/Binary must be this tree's own real directory (M1-28). One root-anchored rule:
# it resolves to exactly "$(cd "$ROOT" && pwd -P)/Packages/WGEXEngine/Binary", so a link on Binary, on
# Packages/WGEXEngine or on Packages is refused. Writing through a linked directory is never correct, because the link
# can lead into another tree's build. Run before any build step. source-digest.py --verify and doctor apply the same rule.
require_own_binary() {
  local part deepest want real
  for part in Packages Packages/WGEXEngine Packages/WGEXEngine/Binary; do
    [[ ! -L "$ROOT/$part" ]] || die "Packages/WGEXEngine/Binary or a parent is a link; remove it and run just engine"
  done
  deepest="$ROOT/Packages/WGEXEngine/Binary"
  while [[ ! -e "$deepest" && "$deepest" != "$ROOT" ]]; do
    deepest="$(dirname "$deepest")"
  done
  want="$(cd "$ROOT" && pwd -P)${deepest#"$ROOT"}"
  real="$(cd "$deepest" && pwd -P)" || die "cannot enter $deepest"
  [[ "$real" == "$want" ]] || die "Packages/WGEXEngine/Binary or a parent is a link; remove it and run just engine"
}

# rename_exclusive <from> <to>: renames, and fails instead of replacing or nesting when <to> exists (renamex_np with
# RENAME_EXCL where the filesystem has it, else an existence check).
rename_exclusive() {
  python3 -I -c '
import ctypes, ctypes.util, errno, os, sys
source, target = sys.argv[1:]
try:
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    if libc.renamex_np(os.fsencode(source), os.fsencode(target), 4) == 0:
        sys.exit(0)
    code = ctypes.get_errno()
except (AttributeError, OSError):
    code = errno.ENOTSUP
if code not in (errno.ENOTSUP, errno.ENOSYS, errno.EINVAL):
    sys.stderr.write("error: cannot rename %s over %s: %s\n" % (source, target, os.strerror(code)))
    sys.exit(1)
if os.path.lexists(target):
    sys.stderr.write("error: refusing to rename over existing %s\n" % target)
    sys.exit(1)
os.rename(source, target)
' "$1" "$2"
}

# publish <temporary> <final>: puts a path made in the same directory in place of <final>. The old <final> is renamed
# aside first (a link is moved as a link, never followed), then the new one is renamed in with rename_exclusive, so a
# concurrent target can never receive the new directory inside itself. Both writers use this one copy. While the old
# output is aside, PUBLISH_ASIDE and PUBLISH_FINAL name it, so the writers' EXIT trap can put it back (restore_publish_aside).
PUBLISH_ASIDE=""
PUBLISH_FINAL=""
publish() {
  local aside=""
  if [[ -e "$2" || -L "$2" ]]; then
    aside="$(dirname "$2")/.old-$$-$(basename "$2")"
    rm -rf -- "$aside"
    PUBLISH_ASIDE="$aside"
    PUBLISH_FINAL="$2"
    mv -- "$2" "$aside"
  fi
  rename_exclusive "$1" "$2" || return 1
  [[ -z "$aside" ]] || rm -rf -- "$aside"
  PUBLISH_ASIDE=""
  PUBLISH_FINAL=""
}

# restore_publish_aside: if a signal or a failed rename stopped publish with the old output aside and nothing at the final
# name, puts the old output back (M1-35 N6). Never replaces anything. Call from the EXIT trap, before release_binary_lock.
restore_publish_aside() {
  if [[ -n "$PUBLISH_ASIDE" && (-e "$PUBLISH_ASIDE" || -L "$PUBLISH_ASIDE") && ! -e "$PUBLISH_FINAL" && ! -L "$PUBLISH_FINAL" ]]; then
    rename_exclusive "$PUBLISH_ASIDE" "$PUBLISH_FINAL" || true
  fi
  PUBLISH_ASIDE=""
  PUBLISH_FINAL=""
}

# One engine build per tree at a time (M1-28, M1-35). acquire_binary_lock <binary dir> opens the lock file beside the
# directory (.Binary.build.lock) on fd 9 and takes an exclusive flock on it, polling up to WGEX_ENGINE_LOCK_WAIT whole
# seconds (default 1800). The kernel owns the lock: it is released when the last process that has the open file dies,
# so there is no stale lock, no takeover and no pid reuse; an orphaned assembler child that inherited fd 9 keeps it held,
# which is wanted. The file is never removed (removing it would not release the lock and would let a second build in).
# The pid of the last writer is written into it, for the message only (it may have exited; the holders come from lsof).
# lock_holders <lock file>: one "  <pid> <command>" line per live process other than this one that has the file open
# (lsof), each preceded by a newline; empty when there is none. The recorded pid is only the last writer, so the real
# holders (a build step, an orphaned child, a daemonised helper) are found from the open file, never from the pid in it.
lock_holders() {
  local pid line
  while IFS= read -r pid; do
    [[ "$pid" =~ ^[0-9]+$ && "$pid" != "$$" ]] || continue
    line="$(ps -o pid=,command= -p "$pid" 2>/dev/null | head -n 1 | cut -c1-200)"
    printf '\n  %s' "${line:-$pid (gone)}"
  done < <(lsof -t "$1" 2>/dev/null | sort -u)
}

BINARY_LOCK=""
acquire_binary_lock() {
  local limit parent lock status=0 writer holders
  limit="${WGEX_ENGINE_LOCK_WAIT-1800}"
  [[ "$limit" =~ ^[0-9]+$ ]] || die "WGEX_ENGINE_LOCK_WAIT must be whole seconds (got '$limit')"
  parent="$(dirname "$1")"
  mkdir -p "$parent"
  lock="$parent/.$(basename "$1").build.lock"
  if [[ -L "$lock" || -d "$lock" ]]; then
    die "$lock must be a plain lock file, not a link or a directory (a directory is an old-style lock); remove it and run again"
  fi
  if ! { exec 9>>"$lock"; } 2>/dev/null; then
    die "cannot open the engine build lock $lock"
  fi
  python3 -I -c '
import errno, fcntl, sys, time
limit, lock = float(sys.argv[1]), sys.argv[2]
deadline = time.monotonic() + limit
noticed = False
while True:
    try:
        fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)
        sys.exit(0)
    except OSError as error:
        if error.errno not in (errno.EWOULDBLOCK, errno.EAGAIN):
            sys.stderr.write("error: cannot lock %s: %s\n" % (lock, error))
            sys.exit(2)
    if not noticed:
        noticed = True
        print("==> waiting for the engine build that holds %s" % lock, flush=True)
    if time.monotonic() >= deadline:
        sys.exit(1)
    time.sleep(0.2)
' "$limit" "$lock" || status=$?
  case "$status" in
    0) ;;
    1)
      writer="$(head -n 1 "$lock" 2>/dev/null || true)"
      exec 9>&-
      holders="$(lock_holders "$lock")"
      [[ -n "$holders" ]] || holders=$'\n  none found (lsof is missing, or the holder belongs to another user)'
      die "another engine build holds $lock; waited $limit s.
Holders (processes with the lock file open):$holders
Last writer pid: ${writer:-unknown} (may have exited; not necessarily a holder).
Stop a holder only if it is not an engine build; deleting the lock file does not free the lock"
      ;;
    *)
      exec 9>&-
      die "cannot take the engine build lock $lock"
      ;;
  esac
  printf '%s\n' "$$" >"$lock"
  BINARY_LOCK="$lock"
}

# release_binary_lock: closes this process's hold on the lock; safe to call from an EXIT trap more than once. Children that
# inherited fd 9 keep the lock until they exit.
release_binary_lock() {
  if [[ -n "$BINARY_LOCK" ]]; then
    exec 9>&-
  fi
  BINARY_LOCK=""
}

# remove_build_leftovers <binary dir>: temporaries of dead writers (.new-<pid>-*.xcframework, .old-<pid>-*,
# .provenance*.json.*). Only while this process holds the lock, so no other writer is alive.
remove_build_leftovers() {
  local path
  [[ -n "$BINARY_LOCK" ]] || die "remove_build_leftovers needs the engine build lock (acquire_binary_lock first)"
  for path in "$1"/.new-*-WGEXEngine.xcframework "$1"/.new-*-WGEXEngineTest.xcframework \
    "$1"/.old-*-WGEXEngine.xcframework "$1"/.old-*-WGEXEngineTest.xcframework \
    "$1"/.old-*-provenance.json "$1"/.old-*-provenance-test.json "$1"/.provenance*.json.*; do
    if [[ -e "$path" || -L "$path" ]]; then
      rm -rf -- "$path"
    fi
  done
}

# Use the same root and dependency-cache implementation as every other build.
# shellcheck source=Config/Scripts/lib.sh
source "$ROOT/Config/Scripts/lib.sh"

source_digest() { python3 -I "$ENGINE_SCRIPTS/source-digest.py"; }

# lock <section> <key>: quoted string value of key in [section] of Toolchain.lock
lock() {
  sed -n "/^\[$1\]/,/^\[/p" "$LOCK" |
    sed -nE "s/^$2[[:space:]]*=[[:space:]]*\"([^\"]*)\".*/\1/p" | head -n 1
}

# sha256 <file>: hex digest
sha256() { shasum -a 256 "$1" | awk '{ print $1 }'; }

# script_sha: separate pipeline checksum for provenance.script_sha256.
# build_info.script_sha embeds source_digest, including unstaged sources and resolved version/build.
script_sha() {
  cat "$ENGINE_SCRIPTS/build-xcframework.sh" "$ENGINE_SCRIPTS/lib.sh" "$ENGINE_SCRIPTS/verify-slices.sh" |
    shasum -a 256 | awk '{ print $1 }'
}

# slice_params <slice>: sets GOOS_FOR, SDK_FOR, TRIPLE_FOR, PLATFORM_FOR
# (LC_BUILD_VERSION platform number) and EXTRA_LDFLAGS_FOR. The simulator
# slices (ADR-006 amendment) are GOOS=ios against the simulator SDKs: the Go
# linker copies the platform of the first cgo object into go.o, so every
# member carries platform 7 (iOS Simulator) or 8 (tvOS Simulator).
slice_params() {
  MIN_OS="27.0"
  [[ "$1" != macos ]] || MIN_OS="26.0"
  TRIPLE_FOR="arm64-apple-$1$MIN_OS"
  case "$1" in
    macos)
      GOOS_FOR=darwin SDK_FOR=macosx PLATFORM_FOR=1
      EXTRA_LDFLAGS_FOR="-macos=$MIN_OS -macsdk=$(xcrun --sdk macosx --show-sdk-version)"
      ;;
    ios)
      GOOS_FOR=ios SDK_FOR=iphoneos PLATFORM_FOR=2 EXTRA_LDFLAGS_FOR=""
      ;;
    tvos)
      # Go has no GOOS=tvos: GOOS=ios plus the appletvos SDK and a tvOS triple
      GOOS_FOR=ios SDK_FOR=appletvos PLATFORM_FOR=3 EXTRA_LDFLAGS_FOR=""
      ;;
    ios-simulator)
      GOOS_FOR=ios SDK_FOR=iphonesimulator PLATFORM_FOR=7 EXTRA_LDFLAGS_FOR=""
      TRIPLE_FOR="arm64-apple-ios$MIN_OS-simulator"
      ;;
    tvos-simulator)
      GOOS_FOR=ios SDK_FOR=appletvsimulator PLATFORM_FOR=8 EXTRA_LDFLAGS_FOR=""
      TRIPLE_FOR="arm64-apple-tvos$MIN_OS-simulator"
      ;;
    *) die "unknown slice '$1' (expected macos, ios, tvos, ios-simulator or tvos-simulator)" ;;
  esac
}

# Numeric dotted versions, with an optional Go prefix; absent trailing components are zero.
# Keep this self-contained helper in sync with Tools/doctor/doctor.sh (test_toolchain.py covers both).
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

# assert_toolchain <sdk...>: Go and Xcode meet Toolchain.lock floors, SDKs exist, and the
# offline Go settings are exported and in effect
assert_toolchain() {
  local want got xb sdk path module_floor
  [[ -f "$LOCK" ]] || die "missing $LOCK"

  export GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off CGO_ENABLED=1 GOARCH=arm64

  want="$(lock go version)"
  got="$(go version 2>/dev/null | awk '{ print $3 }' || true)"
  version_at_least "$got" "$want" || die "go is '${got:-missing}', Toolchain.lock minimum is '$want'"
  module_floor="$(sed -n 's/^toolchain //p' "$GO_DIR/go.mod")"
  if [[ -n "$module_floor" ]]; then
    version_at_least "$got" "$module_floor" || die "go is '$got', Engine/go/go.mod toolchain minimum is '$module_floor'"
  fi

  xb="$(xcodebuild -version 2>/dev/null || true)"
  want="$(lock xcode version)"
  got="$(printf '%s\n' "$xb" | sed -n 's/^Xcode //p')"
  version_at_least "$got" "$want" || die "Xcode is '${got:-missing}', Toolchain.lock minimum is '$want'"

  for sdk in "$@"; do
    path="$(xcrun --sdk "$sdk" --show-sdk-path 2>/dev/null || true)"
    [[ -n "$path" && -d "$path" ]] || die "SDK $sdk is not installed"
  done

  # go env reports the effective values, including any go env -w overrides
  got="$(cd "$GO_DIR" && go env GOTOOLCHAIN GOFLAGS GOPROXY | paste -sd' ' -)"
  [[ "$got" == "local -mod=vendor off" ]] || die "Go environment is '$got', want 'local -mod=vendor off'"
  [[ -f "$GO_DIR/vendor/modules.txt" ]] || die "Engine/go/vendor is missing; run 'go mod vendor' in a reviewed commit"
}

# detect_toolchain: sets the found compiling toolchain, shared by both archive builders so they key the same way:
# go_output (whole `go version` output), go_version (its third word), xcode_info, xcode_version, xcode_build, the
# toolchain array (the three strings the cache key hashes) and TOOLCHAIN_SHA (source-digest.py --toolchain). The key is
# the found tools, never the Toolchain.lock floors: a floor edit does not rebuild, a toolchain change rebuilds once.
detect_toolchain() {
  go_output="$(go version)"
  go_version="$(printf '%s\n' "$go_output" | awk '{ print $3 }')"
  xcode_info="$(xcodebuild -version)"
  xcode_version="$(printf '%s\n' "$xcode_info" | sed -n 's/^Xcode //p')"
  xcode_build="$(printf '%s\n' "$xcode_info" | sed -n 's/^Build version //p')"
  toolchain=("$go_output" "$xcode_version" "$xcode_build")
  TOOLCHAIN_SHA="$(python3 -I "$ENGINE_SCRIPTS/source-digest.py" --toolchain "${toolchain[@]}")"
}

# app_version_values: sets APP_VERSION and APP_BUILD from WGEX_APP_VERSION /
# WGEX_BUILD, else MARKETING_VERSION / CURRENT_PROJECT_VERSION in
# Config/Base.xcconfig when present, else 0.0.0 / 0
app_version_values() {
  local values
  values="$(python3 -I "$ENGINE_SCRIPTS/source-digest.py" --app-version-values)" || return
  APP_VERSION="${values%%$'\n'*}"
  APP_BUILD="${values#*$'\n'}"
}

# build_slice <slice> <out_dir> <gocache_dir> <tags>: c-archive for one device
# slice into <out_dir>/libwgex.a; the cgo-generated header is discarded
build_slice() {
  local slice="$1" out="$2" cache="$3" tags="$4" sdk_path ldflags
  slice_params "$slice"
  sdk_path="$(xcrun --sdk "$SDK_FOR" --show-sdk-path)"
  ldflags="-w -X main.appVersion=$APP_VERSION -X main.build=$APP_BUILD -X main.scriptSHA=$SCRIPT_SHA"
  if [[ -n "$EXTRA_LDFLAGS_FOR" ]]; then
    ldflags="$ldflags $EXTRA_LDFLAGS_FOR"
  fi
  mkdir -p "$out" "$cache"
  log "build $slice ($TRIPLE_FOR, GOOS=$GOOS_FOR, SDK $SDK_FOR${tags:+, tags $tags})"
  (
    cd "$GO_DIR" || exit 1
    export GOOS="$GOOS_FOR" GOCACHE="$cache"
    CC="$(xcrun -f clang)"
    export CC
    # -O2 restores the optimisation Go's default CGO_CFLAGS (-O2 -g) carries;
    # setting CGO_CFLAGS replaces that default
    export CGO_CFLAGS="-O2 -isysroot $sdk_path -target $TRIPLE_FOR"
    export CGO_LDFLAGS="-isysroot $sdk_path -target $TRIPLE_FOR"
    # Reproducibility: without ZERO_AR_DATE Apple's ar stamps the symbol table
    # member with the build time and the caller's uid/gid; archive member modes
    # follow the umask, so pin it
    export ZERO_AR_DATE=1
    umask 022
    # Fails with "cannot find module providing package" on an unvendored import
    go build -buildmode=c-archive -trimpath -buildvcs=false -tags "$tags" \
      -ldflags "$ldflags" -o "$out/libwgex.a" ./bridge
  )
  rm -f "$out/libwgex.h"
}

# create_xcframework <output> <xcodebuild -create-xcframework args...>:
# assembles the XCFramework, then sorts Info.plist AvailableLibraries by
# LibraryIdentifier (xcodebuild emits them in a different order on every run)
create_xcframework() {
  local xcf="$1"
  shift
  mkdir -p "$(dirname "$xcf")"
  rm -rf "$xcf"
  xcodebuild -create-xcframework "$@" -output "$xcf" >/dev/null
  python3 -I -c '
import plistlib, sys
path = sys.argv[1]
with open(path, "rb") as f:
    info = plistlib.load(f)
info["AvailableLibraries"].sort(key=lambda lib: lib["LibraryIdentifier"])
with open(path, "wb") as f:
    plistlib.dump(info, f, sort_keys=True)
' "$xcf/Info.plist"
}
