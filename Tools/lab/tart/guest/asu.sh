#!/bin/bash
# SPDX-License-Identifier: MIT
# Run a command inside the console user's login session (the auto-logged-in
# `labuser` desktop; `admin` on the macOS 27 guest, named by the lab marker's
# "user"). SSH sessions have no WindowServer access; `launchctl asuser`
# borrows the console session's bootstrap so `open`, `osascript` and
# `screencapture` see the display. Passwordless sudo is required.
# shellcheck source=Tools/lab/tart/guest/guard.sh
source "$(dirname "$0")/guard.sh"
# The guest VM and marker checks run before launchctl or any other command.
guest_guard
user="$(guest_lab_user --console)"
uid="$(id -u "$user")"
exec sudo -n launchctl asuser "$uid" sudo -n -u "$user" "$@"
