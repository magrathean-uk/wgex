#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# `just install-ios-device <udid>` (M06-T09): installs the Development-signed
# Debug device build from `just build ios-device` on a connected iPhone or iPad
# with `xcrun devicectl`. Every precondition is checked before devicectl
# installs anything: the build exists, it is signed for development on the WGEX
# team with an embedded profile (never ad hoc, Developer ID or distribution),
# and the device is paired and reachable. A failed check prints why and
# changes nothing; only devicectl's own JSON listing goes to a temporary file,
# which is removed on exit.
set -euo pipefail
# shellcheck source=Config/Scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$WGEX_ROOT"

usage() {
  echo "usage: install-ios-device.sh <udid>   (the device UDID or CoreDevice identifier, from Finder or 'xcrun devicectl list devices')" >&2
  exit 2
}
fail() {
  echo "install-ios-device: $*" >&2
  exit 1
}

(($# == 1)) || usage
udid="$1"
# A UDID (00008110-001A2B3C4D5E801E, 40 hex digits) or a CoreDevice identifier (a UUID); nothing else reaches devicectl.
[[ "$udid" =~ ^[A-Fa-f0-9-]{24,40}$ ]] || {
  echo "install-ios-device: '$udid' is not a device UDID or identifier (hex digits and hyphens)" >&2
  usage
}

configuration=Debug
team="$(xcconfig_value WGEX_TEAM "$configuration")"
products="$(derived_data)" || exit
app="$products/Build/Products/$configuration-iphoneos/WGEX.app"

# 1. The build.
[[ -d "$app" ]] || fail "no device build at $app; run 'just build ios-device' first (nothing installed)"

# 2. Signing: Apple Development on the WGEX team with an embedded provisioning profile, for the app and its extensions.
signed() { # signed <bundle>: a Development signature on $team with an embedded profile
  local bundle="$1" info
  info="$(codesign -dvv "$bundle" 2>&1)" || return 1
  [[ -f "$bundle/embedded.mobileprovision" ]] || return 1
  grep -qx 'Signature=adhoc' <<<"$info" && return 1
  grep -qx "TeamIdentifier=$team" <<<"$info" || return 1
  grep -q '^Authority=Apple Development: ' <<<"$info" || return 1
  ! grep -qE '^Authority=(Apple Distribution|iPhone Distribution|Developer ID)' <<<"$info"
}
bundles=("$app")
for extension in "$app"/PlugIns/*.appex; do
  [[ -d "$extension" ]] && bundles+=("$extension")
done
for bundle in "${bundles[@]}"; do
  signed "$bundle" || fail "$bundle is not Development-signed on team $team with an embedded profile (ad hoc or simulator build?); run 'just build ios-device' with Xcode signed in to the team (nothing installed)"
done

# 3. The device: listed by devicectl, paired, and not unavailable.
work="$(mktemp -d "${TMPDIR:-/tmp}/wgex-install-ios-device.XXXXXX")"
trap 'rm -rf "$work"' EXIT
if ! xcrun devicectl list devices --quiet --json-output "$work/devices.json" >/dev/null 2>"$work/list.err"; then
  sed 's/^/  /' "$work/list.err" >&2
  fail "could not list devices with 'xcrun devicectl list devices' (nothing installed)"
fi
if ! state="$(python3 -I -c 'import json, sys
path, wanted = sys.argv[1], sys.argv[2].lower()
try:
    with open(path) as handle:
        devices = json.load(handle)["result"]["devices"]
except (OSError, ValueError, KeyError, TypeError):
    print("unreadable"); sys.exit()
for device in devices if isinstance(devices, list) else []:
    hardware = device.get("hardwareProperties") or {}
    connection = device.get("connectionProperties") or {}
    if wanted not in (str(device.get("identifier", "")).lower(), str(hardware.get("udid", "")).lower()):
        continue
    if hardware.get("platform") not in (None, "iOS"):
        print("platform " + str(hardware.get("platform"))); sys.exit()
    if connection.get("pairingState") != "paired":
        print("unpaired"); sys.exit()
    if connection.get("tunnelState") in (None, "unavailable"):
        print("unavailable"); sys.exit()
    print("ok"); sys.exit()
print("missing")' "$work/devices.json" "$udid")"; then
  fail "could not read the device list (nothing installed)"
fi
case "$state" in
  ok) ;;
  missing) fail "no device $udid is known to devicectl; connect it by cable or on the same network, unlock it and trust this Mac (nothing installed)" ;;
  unpaired) fail "device $udid is not paired with this Mac; unlock it and accept 'Trust This Computer' (nothing installed)" ;;
  unavailable) fail "device $udid is not connected; connect it by cable or on the same network and unlock it (nothing installed)" ;;
  platform*) fail "device $udid is not an iPhone or iPad (${state#platform }) (nothing installed)" ;;
  *) fail "could not read the device list from devicectl (nothing installed)" ;;
esac

# 4. Install.
echo "install-ios-device: installing $app on $udid"
xcrun devicectl device install app --device "$udid" "$app"
echo "install-ios-device: installed $(basename "$app") on $udid"
