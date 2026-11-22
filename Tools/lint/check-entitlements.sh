#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Verifies built products (ticket P0-20, plan 03 §3-§4): signing identifier,
# entitlements from `codesign -d --entitlements - --xml` against the expected
# set per target and configuration, Info.plist keys with `plutil -extract`,
# bundle layout and the installed launchd plist.
#
# Usage: check-entitlements.sh [--configuration Debug|Release] [--products DIR]
#                              [--require mac,ios,ios-device,tv] [--variant auto|unrestricted|full]
#                              [--profile DECODED_PLIST|-] [--own-mac]
#   --products  Build/Products directory (default: the `just build` derived data)
#   --require   platforms that must be present; others are checked when built
# The expected entitlements are the target's entitlements file for the signing
# variant found (ad hoc: *.adhoc.entitlements), with variables expanded, plus
# what Xcode injects: get-task-allow on macOS Debug, and an application
# identifier on the command-line tools. A decoded profile authorises the
# application/team identifiers injected into an explicitly full Mac app.
# ios-device (M06-T09) is the Development-signed Debug device build
# (Debug-iphoneos): always the full entitlements, whatever --variant says, plus
# only what development signing injects (application and team identifiers,
# get-task-allow, a default keychain group where the target names none), on an
# Apple Development signature for the WGEX team with an embedded profile.
set -uo pipefail
# shellcheck source=Tools/lint/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=Config/Scripts/lib.sh
source "$LINT_ROOT/Config/Scripts/lib.sh"

configuration=Debug
products=""
require=""
variant=auto
profile=""
own_mac=no
while (($#)); do
  case "$1" in
    --configuration) configuration="${2:?}" && shift 2 ;;
    --products) products="${2:?}" && shift 2 ;;
    --require) require="${2:?}" && shift 2 ;;
    --variant) variant="${2:?}" && shift 2 ;;
    --profile) profile="${2:?}" && shift 2 ;;
    --own-mac) own_mac=yes && shift ;;
    *)
      echo "check-entitlements: unknown argument $1" >&2
      exit 2
      ;;
  esac
done
case "$configuration" in debug | Debug) configuration=Debug ;; release | Release) configuration=Release ;; *)
  echo "check-entitlements: configuration must be Debug or Release" >&2
  exit 2
  ;;
esac
case "$variant" in auto | unrestricted | full) ;; *)
  echo "check-entitlements: variant must be auto, unrestricted or full" >&2
  exit 2
  ;;
esac
if [[ -n "$profile" && ("$variant" != full || "$configuration" != Release) ]]; then
  echo "check-entitlements: a profile requires full Release expectations" >&2
  exit 2
fi
if [[ "$own_mac" == yes && ("$variant" != full || "$configuration" != Release || -z "$profile") ]]; then
  echo "check-entitlements: own-Mac expectations require a profile and full Release" >&2
  exit 2
fi
if [[ -z "$products" ]]; then
  products="$(derived_data)" || exit
  products="$products/Build/Products"
fi

xcconfig() { # xcconfig <name>: value for $configuration from Config/Local.xcconfig (git-ignored), else Config/Base.xcconfig
  local file value=""
  for file in "$LINT_ROOT/Config/Local.xcconfig" "$LINT_ROOT/Config/Base.xcconfig"; do
    [[ -f "$file" ]] || continue
    value="$(sed -nE "s/^$1\\[config=$configuration\\][[:space:]]*=[[:space:]]*(.*)$/\\1/p" "$file" | tail -n 1)"
    [[ -n "$value" ]] || value="$(sed -nE "s/^$1[[:space:]]*=[[:space:]]*(.*)$/\\1/p" "$file" | tail -n 1)"
    [[ -z "$value" ]] || break
  done
  printf '%s' "$value"
}
base="$(xcconfig WGEX_BUNDLE_ID_BASE)"
team="$(xcconfig WGEX_TEAM)"

if [[ -n "$profile" ]]; then
  if ! python3 -I -c 'import plistlib, sys
path, team, base, own_mac = sys.argv[1:]
def covers(patterns, value):
    return isinstance(patterns, list) and any(
        isinstance(pattern, str) and (pattern == value or
        (pattern.endswith(".*") and "*" not in pattern[:-1] and
         value.startswith(pattern[:-1]) and len(value) > len(pattern) - 1)) for pattern in patterns)
try:
    with (sys.stdin.buffer if path == "-" else open(path, "rb")) as source:
        data = plistlib.loads(source.read())
    ent = data["Entitlements"]
    appid = team + "." + base
    ids = [ent[k] for k in ("application-identifier", "com.apple.application-identifier") if k in ent]
    assert data["TeamIdentifier"] == [team] and data["ApplicationIdentifierPrefix"] == [team]
    assert ids and all(value == appid for value in ids)
    assert ent.get("com.apple.developer.team-identifier") == team
    assert covers(ent["keychain-access-groups"], appid)
    assert covers(ent["com.apple.security.application-groups"], appid if own_mac == "yes" else "group." + base)
except (OSError, ValueError, KeyError, TypeError, AssertionError, plistlib.InvalidFileException):
    sys.exit("check-entitlements: profile does not authorise the expected Mac entitlements")' "$profile" "$team" "$base" "$own_mac"; then
    exit 1
  fi
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/wgex-entitlements.XXXXXX")"
# The trap fails closed: bash 3.2 hands an EXIT trap status 0 after a shell error under set -e (unbound variable, ${x:?},
# readonly, bad substitution, failed source), so the script sets finished=1 just before each intended successful end.
# finished=0 first: an exported finished=1 in the caller must not mark an erroring script as finished.
finished=0
trap 'rc=$?; ((rc != 0)) || ((${finished:-0})) || rc=1; rm -rf "$work"; exit "$rc"' EXIT
failures=0
checks=0
ok() { checks=$((checks + 1)); }
bad() {
  checks=$((checks + 1))
  failures=$((failures + 1))
  echo "check-entitlements: FAIL $*" >&2
}

# canonical <plist-file>: sorted JSON of a property list (stdout)
canonical() {
  python3 -I -c 'import json, plistlib, sys
with open(sys.argv[1], "rb") as handle:
    data = handle.read()
print(json.dumps(plistlib.loads(data) if data.strip() else {}, sort_keys=True, default=str))' "$1"
}

# expected_entitlements <source.entitlements|-> <identifier> <inject-task-allow> <inject-app-id> <profile-app>:
# sorted JSON of the entitlements file with variables expanded plus injections
expected_entitlements() {
  # shellcheck disable=SC2016 # Python program; $(...) are entitlement variables
  python3 -I -c 'import json, plistlib, sys
source, identifier, task, appid, base, team, profile, own_mac, tool_team = sys.argv[1:]
expected = {}
if source != "-":
    with open(source, "rb") as handle:
        text = handle.read().decode()
    mac_group = team + "." + base if own_mac == "yes" else "group." + base
    for name, value in (("$(WGEX_MAC_APP_GROUP)", mac_group), ("$(WGEX_BUNDLE_ID_BASE)", base), ("$(AppIdentifierPrefix)", team + "."), ("$(TeamIdentifierPrefix)", team + ".")):
        text = text.replace(name, value)
    expected = plistlib.loads(text.encode())
if task == "yes":
    expected["com.apple.security.get-task-allow"] = True
if appid == "yes":
    expected["com.apple.application-identifier"] = team + "." + identifier if own_mac == "yes" else identifier
    if own_mac == "yes" and tool_team == "yes":
        expected["com.apple.developer.team-identifier"] = team
if profile == "yes":
    expected["com.apple.application-identifier"] = team + "." + identifier
    expected["com.apple.developer.team-identifier"] = team
print(json.dumps(expected, sort_keys=True))' "$1" "$2" "$3" "$4" "$base" "$team" "$5" "$own_mac" "${6:-no}"
}

# check_signature <path> <identifier> <entitlements-source|-> <variant-file-stem> <macos yes|no> <tool yes|no>
check_signature() {
  local path="$1" identifier="$2" stem="$3" macos="$4" tool="$5" info signature source actual expected alternate selected="$variant"
  if ! info="$(codesign -dv "$path" 2>&1)"; then
    bad "$(rel "$path"): could not inspect signature"
    return
  fi
  if grep -qx "Identifier=$identifier" <<<"$info"; then ok; else bad "$(rel "$path"): identifier is not $identifier"; fi
  signature="$(sed -n 's/^Signature=//p' <<<"$info")"
  source="-"
  if [[ "$stem" != "-" ]]; then
    if [[ "$selected" == auto ]]; then
      if [[ "$signature" == adhoc ]]; then selected=unrestricted; else selected=full; fi
    fi
    if [[ "$selected" == unrestricted ]]; then source="$LINT_ROOT/$stem.adhoc.entitlements"; else source="$LINT_ROOT/$stem.entitlements"; fi
  fi
  if ! codesign -d --entitlements - --xml "$path" >"$work/actual.plist" 2>/dev/null || ! actual="$(canonical "$work/actual.plist")"; then
    bad "$(rel "$path"): could not read entitlements"
    return
  fi
  local task=no appid=no profile_app=no
  [[ "$macos" == yes && "$configuration" == Debug ]] && task=yes
  [[ "$tool" == yes ]] && appid=yes
  [[ -n "$profile" && "$stem" == Apps/WGEXMac/WGEXMac ]] && profile_app=yes
  expected="$(expected_entitlements "$source" "$identifier" "$task" "$appid" "$profile_app")"
  alternate="$expected"
  if [[ "$own_mac" == yes && "$tool" == yes ]]; then
    alternate="$(expected_entitlements "$source" "$identifier" "$task" "$appid" "$profile_app" yes)"
  fi
  if [[ "$actual" == "$expected" || "$actual" == "$alternate" ]]; then
    ok
  else
    bad "$(rel "$path"): entitlements differ (signature ${signature:-unknown})"
    printf '  expected %s\n  actual   %s\n' "$expected" "$actual" >&2
  fi
  if [[ "$macos" == yes && "$configuration" == Release ]] && grep -qE 'get-task-allow|com\.apple\.security\.cs\.allow-' <<<"$actual"; then
    bad "$(rel "$path"): Release carries get-task-allow or a cs.allow-* exception"
  fi
}

# check_device_signature <path> <identifier> <entitlements-stem|-> <restricted yes|no>: a Development-signed device
# product. restricted=yes also requires the App Group, keychain group and Network Extension entitlements themselves.
check_device_signature() {
  local path="$1" identifier="$2" stem="$3" restricted="$4" info source="-" expected report
  if ! info="$(codesign -dvv "$path" 2>&1)"; then
    bad "$(rel "$path"): could not inspect signature"
    return
  fi
  if grep -qx "Identifier=$identifier" <<<"$info"; then ok; else bad "$(rel "$path"): identifier is not $identifier"; fi
  if grep -qx 'Signature=adhoc' <<<"$info"; then bad "$(rel "$path"): ad hoc signature on a device build"; else ok; fi
  if grep -qx "TeamIdentifier=$team" <<<"$info"; then ok; else bad "$(rel "$path"): team is not $team"; fi
  if grep -q '^Authority=Apple Development: ' <<<"$info" &&
    ! grep -qE '^Authority=(Apple Distribution|iPhone Distribution|Developer ID)' <<<"$info"; then
    ok
  else
    bad "$(rel "$path"): not signed with an Apple Development certificate"
  fi
  if [[ -f "$path/embedded.mobileprovision" ]]; then ok; else bad "$(rel "$path"): embedded.mobileprovision is missing"; fi
  [[ "$stem" == "-" ]] || source="$LINT_ROOT/$stem.entitlements"
  if ! codesign -d --entitlements - --xml "$path" >"$work/actual.plist" 2>/dev/null; then
    bad "$(rel "$path"): could not read entitlements"
    return
  fi
  expected="$(expected_entitlements "$source" "$identifier" no no no)" || {
    bad "$(rel "$path"): could not expand $(rel "$source")"
    return
  }
  if report="$(python3 -I -c 'import json, plistlib, sys
actual_path, expected, team, identifier, restricted = sys.argv[1:]
expected = json.loads(expected)
with open(actual_path, "rb") as handle:
    data = handle.read()
try:
    actual = plistlib.loads(data) if data.strip() else {}
except Exception:
    sys.exit("unreadable entitlements")
problems = []
if restricted == "yes":
    for name in ("com.apple.security.application-groups", "keychain-access-groups", "com.apple.developer.networking.networkextension"):
        if not expected.get(name):
            problems.append("the entitlements file names no " + name)
injected = {"application-identifier": team + "." + identifier, "com.apple.developer.team-identifier": team, "get-task-allow": True}
optional = {} if "keychain-access-groups" in expected else {"keychain-access-groups": [team + "." + identifier]}
for name, value in sorted({**expected, **injected}.items()):
    if actual.get(name) != value:
        problems.append("%s is %s, expected %s" % (name, json.dumps(actual.get(name), default=str), json.dumps(value)))
for name in sorted(set(actual) - set(expected) - set(injected)):
    if name not in optional or actual[name] != optional[name]:
        problems.append("unexpected %s = %s" % (name, json.dumps(actual[name], default=str)))
print("; ".join(problems))' "$work/actual.plist" "$expected" "$team" "$identifier" "$restricted")" && [[ -z "$report" ]]; then
    ok
  else
    bad "$(rel "$path"): device entitlements differ: ${report:-unreadable}"
  fi
}

# key <plist> <keypath> <expected raw value>
key() {
  local value
  if value="$(plutil -extract "$2" raw -o - "$1" 2>/dev/null)" && [[ "$value" == "$3" ]]; then
    ok
  else
    bad "$(rel "$1"): $2 is '${value:-<missing>}', expected '$3'"
  fi
}
present() { # present <plist> <keypath>
  if plutil -extract "$2" raw -o - "$1" >/dev/null 2>&1 || plutil -extract "$2" xml1 -o - "$1" >/dev/null 2>&1; then
    ok
  else
    bad "$(rel "$1"): $2 is missing"
  fi
}
absent() { # absent <plist> <keypath>
  if plutil -extract "$2" xml1 -o - "$1" >/dev/null 2>&1; then bad "$(rel "$1"): $2 must not exist"; else ok; fi
}

common_app_keys() { # common_app_keys <Info.plist> <bonjour|no-bonjour>
  key "$1" CFBundleIdentifier "$base"
  key "$1" CFBundleExecutable WGEX
  present "$1" NSLocalNetworkUsageDescription
  # macOS and tvOS advertise the pairing service; iOS has no NSBonjourServices on purpose (IOSSettingsParityTests).
  if [[ "$2" == bonjour ]]; then
    key "$1" NSBonjourServices.0 _wgex-pair._tcp
  else
    absent "$1" NSBonjourServices
  fi
}
document_keys() { # document_keys <Info.plist>
  key "$1" CFBundleDocumentTypes.0.LSItemContentTypes.0 com.wireguard.config
  key "$1" UTImportedTypeDeclarations.0.UTTypeIdentifier com.wireguard.config
  key "$1" UTImportedTypeDeclarations.0.UTTypeTagSpecification.public\\.filename-extension.0 conf
}

checked=()
check_mac() {
  local app="$products/$configuration/WGEX.app"
  [[ -d "$app" ]] || return 1
  checked+=(mac)
  local listing
  listing="$(find "$app/Contents/MacOS" -mindepth 1 -maxdepth 1 -exec basename {} \; | sort | tr '\n' ' ')"
  if [[ "$listing" == "WGEX WGEXDaemon " ]]; then ok; else bad "$(rel "$app"): Contents/MacOS is '$listing', expected 'WGEX WGEXDaemon'"; fi
  if [[ -x "$app/Contents/Helpers/wgex" ]]; then ok; else bad "$(rel "$app"): Contents/Helpers/wgex is missing"; fi
  check_signature "$app" "$base" Apps/WGEXMac/WGEXMac yes no
  check_signature "$app/Contents/MacOS/WGEXDaemon" "$base.daemon" - yes yes
  check_signature "$app/Contents/Helpers/wgex" "$base.cli" - yes yes
  local info="$app/Contents/Info.plist"
  common_app_keys "$info" bonjour
  document_keys "$info"
  # ADR-030 section 3: Location is requested only to read the Wi-Fi network name; the prompt needs its usage strings.
  present "$info" NSLocationUsageDescription
  present "$info" NSLocationWhenInUseUsageDescription
  for tool in "MacOS/WGEXDaemon:$base.daemon" "Helpers/wgex:$base.cli"; do
    local embedded="$work/embedded.plist"
    rm -f "$embedded"
    if segedit "$app/Contents/${tool%%:*}" -extract __TEXT __info_plist "$embedded" 2>/dev/null; then
      key "$embedded" CFBundleIdentifier "${tool#*:}"
      present "$embedded" CFBundleVersion
    else
      bad "$(rel "$app")/Contents/${tool%%:*}: no embedded Info.plist"
    fi
  done
  local daemon="$app/Contents/Library/LaunchDaemons/$base.daemon.plist"
  if [[ -f "$daemon" ]]; then
    key "$daemon" Label "$base.daemon"
    key "$daemon" BundleProgram Contents/MacOS/WGEXDaemon
    local service="$base.daemon"
    key "$daemon" "MachServices.${service//./\\.}" true
    key "$daemon" AssociatedBundleIdentifiers.0 "$base"
    absent "$daemon" EnvironmentVariables
  else
    bad "$(rel "$daemon"): launchd plist missing"
  fi
}

check_ios() {
  local app="$products/$configuration-iphonesimulator/WGEX.app"
  [[ -d "$app" ]] || return 1
  checked+=(ios)
  check_signature "$app" "$base" Apps/WGEXiOS/WGEXiOS no no
  check_signature "$app/PlugIns/WGEXTunnel.appex" "$base.tunnel" Extensions/WGEXTunnel-iOS/WGEXTunnel-iOS no no
  check_signature "$app/PlugIns/WGEXLiveActivity.appex" "$base.liveactivity" - no no
  common_app_keys "$app/Info.plist" no-bonjour
  document_keys "$app/Info.plist"
  present "$app/Info.plist" NSCameraUsageDescription
  key "$app/Info.plist" NSSupportsLiveActivities true
  key "$app/PlugIns/WGEXTunnel.appex/Info.plist" NSExtension.NSExtensionPointIdentifier com.apple.networkextension.packet-tunnel
  key "$app/PlugIns/WGEXLiveActivity.appex/Info.plist" NSExtension.NSExtensionPointIdentifier com.apple.widgetkit-extension
}

check_ios_device() {
  local app="$products/$configuration-iphoneos/WGEX.app"
  [[ -d "$app" ]] || return 1
  checked+=(ios-device)
  check_device_signature "$app" "$base" Apps/WGEXiOS/WGEXiOS yes
  check_device_signature "$app/PlugIns/WGEXTunnel.appex" "$base.tunnel" Extensions/WGEXTunnel-iOS/WGEXTunnel-iOS yes
  check_device_signature "$app/PlugIns/WGEXLiveActivity.appex" "$base.liveactivity" - no
  common_app_keys "$app/Info.plist" no-bonjour
  document_keys "$app/Info.plist"
  present "$app/Info.plist" NSCameraUsageDescription
  key "$app/Info.plist" NSSupportsLiveActivities true
  key "$app/PlugIns/WGEXTunnel.appex/Info.plist" NSExtension.NSExtensionPointIdentifier com.apple.networkextension.packet-tunnel
  key "$app/PlugIns/WGEXLiveActivity.appex/Info.plist" NSExtension.NSExtensionPointIdentifier com.apple.widgetkit-extension
}

check_tv() {
  local app="$products/$configuration-appletvsimulator/WGEX.app"
  [[ -d "$app" ]] || return 1
  checked+=(tv)
  check_signature "$app" "$base" Apps/WGEXTV/WGEXTV no no
  check_signature "$app/PlugIns/WGEXTunnel.appex" "$base.tunnel" Extensions/WGEXTunnel-tvOS/WGEXTunnel-tvOS no no
  common_app_keys "$app/Info.plist" bonjour
  key "$app/PlugIns/WGEXTunnel.appex/Info.plist" NSExtension.NSExtensionPointIdentifier com.apple.networkextension.packet-tunnel
}

for platform in mac ios ios-device tv; do
  if ! "check_${platform/-/_}"; then
    if [[ ",$require," == *",$platform,"* ]]; then
      bad "$platform: no $configuration product under $(rel "$products")"
    else
      echo "check-entitlements: $platform not built for $configuration; skipped"
    fi
  fi
done

if ((${#checked[@]} == 0)); then
  echo "check-entitlements: FAIL no built products under $products" >&2
  exit 1
fi
if ((failures)); then
  echo "check-entitlements: FAIL ($failures of $checks checks; $configuration; ${checked[*]})" >&2
  exit 1
fi
finished=1
echo "check-entitlements: ok ($checks checks; $configuration; ${checked[*]})"
