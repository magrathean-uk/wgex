#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Privileged reads intentionally redirect into the console user's private temp directory.
# shellcheck disable=SC2024
# M04-T13: guest-only fresh-name failure and DNS-only observation under the daemon's actual connecting rules.
set -euo pipefail
# shellcheck source=Tools/lab/tart/guest/guard.sh
source "$(dirname "$0")/guard.sh"
guest_guard
stage="$(dirname "$0")"
cli=/Applications/WGEX.app/Contents/Helpers/wgex
mode="${1:?action required}"
now() { perl -MTime::HiRes=time -e 'printf "%.6f", time'; }
if [[ "$mode" == fresh-profile ]]; then
  [[ ! -e "$stage/endpoint-name" ]] || exit 1
  name="never-$(uuidgen | tr '[:upper:]' '[:lower:]').invalid"
  umask 077
  printf '%s\n' "$name" >"$stage/endpoint-name"
  profile="$HOME/lab/wgex-lab-full4-name.conf"
  [[ -f "$profile" && ! -L "$profile" ]]
  # The file contains fixture secrets. Edit in place without printing its contents or storing another copy.
  perl -i -pe 's/^Endpoint\s*=.*/Endpoint = '"$name"':51820/' "$profile"
  exit 0
fi
[[ "$mode" == endpoint-name-fail || "$mode" == endpoint-name-lookup ]] || exit 1
id="${2:?profile UUID required}"
[[ "$id" =~ ^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$ ]] || exit 1
read -r name <"$stage/endpoint-name"
[[ "$name" =~ ^never-[0-9a-f-]+\.invalid$ ]] || exit 1
umask 077
work="$(mktemp -d "$stage/name-check.XXXXXX")"
anchor=com.apple/000-wgex-name-fault
vps_guard=com.apple/000-wgex-vps-guard
cleanup() {
  sudo -n pfctl -a "$anchor" -F rules >/dev/null 2>&1 || true
  sudo -n pfctl -a "$vps_guard" -F rules >/dev/null 2>&1 || true
  if [[ -s "$work/enable" ]]; then
    token="$(awk '/Token/ {print $3}' "$work/enable")"
    if [[ "$token" =~ ^[0-9]+$ ]]; then sudo -n pfctl -X "$token" >/dev/null 2>&1 || true; fi
  fi
  rm -rf "$work"
}
trap cleanup EXIT
# An outer fresh restore and unique .invalid hostname exclude both the in-memory resolver cache and last-good reuse.
sudo -n perl "$stage/journal-replay.pl" '/Library/Application Support/WGEX' >"$work/journal"
perl -MJSON::PP -e 'local $/; my $j=decode_json(<>); exit scalar keys %{$j->{lastGoodAddresses}//{}} != 0' <"$work/journal"
perl -e 'alarm 2; exec @ARGV' "$cli" status --json >"$work/before"
perl -MJSON::PP -e 'local $/; my $s=decode_json(<>); exit !($s->{phase} eq "idle" && $s->{protection} eq "unprotected" && !$s->{policyEnforcing})' <"$work/before"
# A separate guest fixture anchor sorts before com.apple/wgex; no renderer rule or daemon anchor is modified.
# Any prior DNS state could bypass the fault, so the row requires its packet counter to increment.
[[ -z "$(sudo -n pfctl -a "$anchor" -sr 2>/dev/null)" ]]
[[ -z "$(sudo -n pfctl -a "$vps_guard" -sr 2>/dev/null)" ]]
sudo -n pfctl -E >"$work/enable" 2>&1
# Defence in depth: even an unexpected answer for .invalid cannot send a handshake to the real VPS.
printf 'block drop out quick to 203.0.113.75\n' | sudo -n pfctl -a "$vps_guard" -f - 2>/dev/null
printf 'block drop out quick proto { udp tcp } from any to any port 53\n' | sudo -n pfctl -a "$anchor" -f - 2>/dev/null
started="$(now)"
# asu uses the console bootstrap, as the cutover rehearsal does. The only trial endpoint is .invalid, never the VPS.
# The alarm also bounds the background request on any fixture failure; no abort is used by this script.
bash "$stage/asu.sh" perl -e 'alarm 14; exec @ARGV' "$cli" cutover start "$id" --confirm-within 60s --json >"$work/reply" 2>/dev/null &
request=$!
connecting_before=false
connecting_after=false
fault_packets=0
if [[ "$mode" == endpoint-name-lookup ]]; then
  for ((attempt = 0; attempt < 40; attempt++)); do
    sudo -n pfctl -a com.apple/wgex -sr >"$work/rules" 2>/dev/null
    fault_packets="$(sudo -n pfctl -a "$anchor" -vsr 2>/dev/null | awk '/Packets:/ {for(i=1;i<=NF;i++) if($i=="Packets:") n+=$(i+1)} END {print n+0}')"
    if grep -q 'group = 1464288600.*wgex-resolver' "$work/rules" && ((fault_packets > 0)); then break; fi
    sleep 0.05
  done
  grep -q 'group = 1464288600.*wgex-resolver' "$work/rules"
  # Read the exact resolver/interface from the narrow daemon pass, not from the host or a public resolver override.
  resolver="$(awk '/proto udp/ && /wgex-resolver/ {for(i=1;i<=NF;i++) if($i=="to") {print $(i+1); exit}}' "$work/rules")"
  [[ "$resolver" =~ ^[0-9a-fA-F:.]+$ ]]
  connecting_before=true
  sudo -n pfctl -a "$anchor" -F rules >/dev/null 2>&1
  # setgid is confined to this disposable root process; pf reads its socket's process credentials, as in the broker.
  # dig can only send DNS to the resolver allowed by the actual connecting policy, never to the VPS address.
  sudo -n perl -e '$(=1464288600; $)=1464288600; exec @ARGV' /usr/bin/dig "@$resolver" cdn.example.net A +short +time=1 +tries=1 >"$work/addresses"
  sudo -n pfctl -a com.apple/wgex -sr >"$work/after-rules" 2>/dev/null
  if cmp -s "$work/rules" "$work/after-rules"; then connecting_after=true; fi
fi
code=0
wait "$request" || code=$?
if [[ "$mode" == endpoint-name-fail ]]; then
  fault_packets="$(sudo -n pfctl -a "$anchor" -vsr 2>/dev/null | awk '/Packets:/ {for(i=1;i<=NF;i++) if($i=="Packets:") n+=$(i+1)} END {print n+0}')"
fi
# This bounded status read is part of the 15 s rollback measurement, not a later abort or retry.
perl -e 'alarm 1; exec @ARGV' "$cli" status --json >"$work/after"
finished="$(now)"
# Export public status fields only. Tokens, full journal and fixture credentials never leave the guest's private temp dir.
perl -MJSON::PP -e '
  my ($dir,$mode,$code,$start,$end,$packets,$before,$after)=@ARGV;
  sub read_json { open my $f,"<",$_[0] or die; local $/; return decode_json(<$f>); }
  sub status { my $s=read_json($_[0]); return {map {$_=>$s->{$_}} qw(phase protection policyEnforcing activeProfileID operationInFlight cutover cutoverRollbackFailures)}; }
  my $reply=read_json("$dir/reply");
  my $r={freshName=>JSON::PP::true,noLastGood=>JSON::PP::true,exitCode=>0+$code,error=>$reply->{error},
    faultPackets=>0+$packets,elapsedSeconds=>$end-$start,before=>status("$dir/before"),after=>status("$dir/after")};
  if($mode eq "endpoint-name-lookup") {
    open my $f,"<","$dir/addresses" or die; chomp(my @a=<$f>);
    $r->{lookupHost}="cdn.example.net"; $r->{addresses}=\@a;
    $r->{connectingBeforeLookup}=$before eq "true"?JSON::PP::true:JSON::PP::false;
    $r->{connectingAfterLookup}=$after eq "true"?JSON::PP::true:JSON::PP::false;
  }
  print encode_json($r),"\n";
' "$work" "$mode" "$code" "$started" "$finished" "$fault_packets" "$connecting_before" "$connecting_after"
