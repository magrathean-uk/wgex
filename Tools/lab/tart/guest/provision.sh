#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Bootstrap exception: verify VM and OS before creating the marker.
set -euo pipefail
set +x # password handling must remain untraced, even if inherited
# The same guest VM check as guard.sh guest_vm_check; the marker check cannot run because this script creates it.
[[ "$(sw_vers -productVersion)" == 2[67].* && "$(sysctl -n kern.hv_vmm_present)" == 1 ]] || {
  echo 'guest: macOS 26 or 27 VM required' >&2
  exit 1
}
# The expected lab administrator (M03-T11): labuser unless the host passes another (the macOS 27 guest's admin).
lab_user="${2:-labuser}"
[[ "$lab_user" =~ ^[a-z_][a-z0-9_-]{0,31}$ && "$(id -un)" == "$lab_user" ]] || exit 1
sudo -n true || {
  echo 'Enable passwordless sudo in the guest first; see README.' >&2
  exit 1
}
# Receive the password on stdin only. Feed dscl its command language over a
# private pipe; the password never becomes an OS process argument or file.
if ! id tester >/dev/null 2>&1; then
  IFS= read -r tester_password || {
    echo 'tester password required on stdin' >&2
    exit 1
  }
  [[ -n "$tester_password" && "$tester_password" != *$'\r'* ]] || exit 1
  uid=501
  while taken="$(dscl . -search /Users UniqueID "$uid")" && grep -q . <<<"$taken"; do uid=$((uid + 1)); done
  sudo -n dscl . -create /Users/tester
  sudo -n dscl . -create /Users/tester UniqueID "$uid"
  sudo -n dscl . -create /Users/tester PrimaryGroupID 20
  sudo -n dscl . -create /Users/tester UserShell /bin/zsh
  sudo -n dscl . -create /Users/tester NFSHomeDirectory /Users/tester
  sudo -n dscl . -create /Users/tester RealName 'WGEX test user'
  escaped_password="${tester_password//\\/\\\\}"
  escaped_password="${escaped_password//\"/\\\"}"
  { printf 'passwd /Users/tester "%s"\nquit\n' "$escaped_password"; } | sudo -n dscl . >/dev/null 2>&1
  unset tester_password escaped_password
  [[ "$(sudo -n dscl . -read /Users/tester AuthenticationAuthority)" == *ShadowHash* ]] || {
    echo 'tester password was not installed' >&2
    exit 1
  }
  sudo -n createhomedir -c -u tester >/dev/null
fi
membership="$(dsmemberutil checkmembership -U tester -G admin)" || membership=
if grep -q 'is a member' <<<"$membership"; then
  echo 'tester must not be an administrator' >&2
  exit 1
fi
sudo -n systemsetup -setremotelogin on
if [[ ! -f /etc/sudoers.d/wgex-lab ]]; then
  printf '%s ALL=(ALL) NOPASSWD: ALL\n' "$lab_user" | sudo -n tee /etc/sudoers.d/wgex-lab >/dev/null
  sudo -n chmod 0440 /etc/sudoers.d/wgex-lab
  sudo -n visudo -cf /etc/sudoers.d/wgex-lab
fi
[[ ! -L /var/db/wgex-lab-host ]] || exit 1
# The marker names a non-default lab user for the guest scripts (guard.sh guest_lab_user); labuser guests keep {}.
if [[ "$lab_user" == labuser ]]; then marker='{}'; else marker="{\"user\":\"$lab_user\"}"; fi
printf '%s\n' "$marker" | sudo -n tee /var/db/wgex-lab-host >/dev/null
sudo -n chown root:wheel /var/db/wgex-lab-host
sudo -n chmod 0644 /var/db/wgex-lab-host
base="/Users/$lab_user/lab"
mkdir -p "$base/capture" "$base/pcap"
cp "$1/guard.sh" "$base/capture/guard.sh"
cp "$1/start-capture.sh" "$1/stop-capture.sh" "$base/capture/"
chmod 0755 "$base/capture/"*.sh
{
  sw_vers
  sysctl kern.hv_vmm_present
  stat -f 'marker owner=%u mode=%Lp type=%HT' /var/db/wgex-lab-host
  cat /var/db/wgex-lab-host
  id tester
  dsmemberutil checkmembership -U tester -G admin
} >"$base/provisioning-report.txt"
