#!/bin/bash
# SPDX-License-Identifier: MIT
# Seed TCC allow rows so SSH-driven automation can use System Events,
# post input events and capture the screen in the lab guest. Lab only:
# requires SIP disabled in the guest (the owner did this in Recovery) and
# passwordless sudo. Never run on a real Mac.
#
# TCC attributes an SSH session to /usr/libexec/sshd-keygen-wrapper, not to
# sshd-session or the tool itself, so that binary needs the rows. Rows are
# keyed by the binary's designated requirement; tccd is restarted afterwards.
set -euo pipefail
# shellcheck source=Tools/lab/tart/guest/guard.sh
source "$(dirname "$0")/guard.sh"
guest_guard
# The console user comes from the checked marker before any TCC or launchd change.
user="$(guest_lab_user --console)"
uid="$(id -u "$user")"
sip="$(csrutil status)" || sip=
grep -q disabled <<<"$sip" || {
  echo 'SIP must be disabled in the guest' >&2
  exit 1
}
db='/Library/Application Support/com.apple.TCC/TCC.db'
services=(kTCCServiceAccessibility kTCCServicePostEvent kTCCServiceListenEvent kTCCServiceScreenCapture kTCCServiceSystemPolicyAllFiles)
clients=("$@")
((${#clients[@]})) || clients=(/usr/libexec/sshd-keygen-wrapper /usr/libexec/sshd-session /usr/sbin/sshd /usr/bin/osascript /usr/sbin/screencapture /usr/bin/open /bin/launchctl /usr/bin/sudo /bin/bash /bin/zsh /usr/bin/perl)
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
now="$(date +%s)"
for client in "${clients[@]}"; do
  [[ -x "$client" ]] || {
    echo "skip (missing): $client" >&2
    continue
  }
  requirement="$( (sudo -n codesign -d -r- "$client" 2>&1 || true) | sed -n 's/^designated => //p')"
  [[ -n "$requirement" ]] || {
    echo "skip (unsigned): $client" >&2
    continue
  }
  csreq -r="$requirement" -b "$work/req.bin"
  for service in "${services[@]}"; do
    sudo -n sqlite3 "$db" "delete from access where service='$service' and client='$client';
      insert into access (service,client,client_type,auth_value,auth_reason,auth_version,csreq,policy_id,indirect_object_identifier_type,indirect_object_identifier,indirect_object_code_identity,flags,last_modified,pid,pid_version,boot_uuid,last_reminded)
      values ('$service','$client',1,2,4,1,readfile('$work/req.bin'),NULL,0,'UNUSED',NULL,0,$now,NULL,NULL,'UNUSED',$now);"
  done
  sudo -n sqlite3 "$db" "delete from access where service='kTCCServiceAppleEvents' and client='$client' and indirect_object_identifier='com.apple.systemevents';
    insert into access (service,client,client_type,auth_value,auth_reason,auth_version,csreq,policy_id,indirect_object_identifier_type,indirect_object_identifier,indirect_object_code_identity,flags,last_modified,pid,pid_version,boot_uuid,last_reminded)
    values ('kTCCServiceAppleEvents','$client',1,2,4,1,readfile('$work/req.bin'),NULL,0,'com.apple.systemevents',NULL,0,$now,NULL,NULL,'UNUSED',$now);"
  echo "seeded: $client"
done
sudo -n launchctl kickstart -k system/com.apple.tccd.system
sudo -n launchctl kickstart -k "gui/$uid/com.apple.tccd" || true
sudo -n sqlite3 "$db" "select service, client from access where auth_value=2 and client in ($(printf "'%s'," "${clients[@]}" | sed 's/,$//')) order by client, service" | sed 's/^/row: /'
