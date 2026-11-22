# SPDX-License-Identifier: MIT
# shellcheck shell=bash
# shellcheck disable=SC2034 # consumed by Tools/lab/tart/lib.sh and Tools/lab/harness.py
# Harness deadlines (M1-10i): the one source for every fixed bound on a host-side, SSH, scp or GUI-automation step
# of the verdict pipeline. Each value is the pre-M1-10i base in seconds (counts where named); the effective value is
# base x WGEX_LAB_HARNESS_SCALE (integer 1..8, default HARNESS_SCALE_DEFAULT), so a load-60 host (guest run 8: 19 s
# for a trivial SSH, 20-34 s GUI dumps, 161 s restore) does not turn a slow hop into a verdict. A *_MIN entry is an
# unscaled floor for the entry it names. Verdict expectations are never here: verdict.py EN0_RECOVERY_SECONDS and
# CAPTIVE_*, verdict-live.py LOSS_BLOCKED_SECONDS, CAPTIVE_OPEN_SECONDS and await_status timeouts, and the 180 s
# rollback deadline in cutover-rehearsal.sh. Data only: NAME=integer lines; harness.py refuses anything else.
HARNESS_SCALE_DEFAULT=4

# Tools/lab/tart/lib.sh and snapshot.sh: every just lab ssh, gui, restore call.
HARNESS_SSH_CONNECT_TIMEOUT=5
HARNESS_SSH_ALIVE_COUNT=3
HARNESS_CONNECT_PROBE=5
HARNESS_WAIT_STOPPED=30
HARNESS_WAIT_READY=300
# Tools/lab/profile.sh: each vm-lima shell wg-peer call (every row's prepare runs just lab profile).
HARNESS_PEER_SHELL=30

# Tools/lab/verdict-live.py: subprocess and SSH defaults.
HARNESS_COMMAND=100
HARNESS_SSH_COMMAND=90
HARNESS_CONNECT_BUDGET=120
HARNESS_RESTORE=420
# Post-restore readiness: whole budget, then each key-only SSH attempt (60 s floor).
HARNESS_READINESS=120
HARNESS_READINESS_ATTEMPT=10
HARNESS_READINESS_ATTEMPT_MIN=60
# SSH return after an en0 loss and after a reboot, and each attempt.
HARNESS_SSH_RETRY_ATTEMPT=20
HARNESS_SSH_RETURN_AFTER_EN0_LOSS=180
HARNESS_SSH_RETURN_AFTER_REBOOT=300
# App quit path: activate, menu click and Apple-event quit; the menu and pgrep wait loops; each probe and pkill.
HARNESS_QUIT_STEP=10
HARNESS_QUIT_WAIT=10
HARNESS_QUIT_PROBE=5
# One status query; callers still stop at their own expectation deadline.
HARNESS_STATUS_POLL=10
HARNESS_DIAGNOSTICS_TAIL=10
HARNESS_BOOT_OBSERVE=60
# GUI automation: control search (last choice, earlier choices), Settings window, import review, profile selection.
HARNESS_GUI_SEARCH=30
HARNESS_GUI_SEARCH_SHORT=5
HARNESS_GUI_SETTINGS_OPEN=15
HARNESS_GUI_IMPORT_REVIEW=30
HARNESS_GUI_PROFILE_SELECT=30
HARNESS_GUI_TITLE_SETTLE=5
# Read-back of a GUI setting by the daemon (journal lockdown flag, registry boot intent).
HARNESS_LOCKDOWN_CONFIRM=15
HARNESS_BOOT_INTENT_CONFIRM=20
# Guest-load settle before the first GUI step after a restore or a reboot (M1-10m; guest run 8d: every row's own restore
# left the guest at load 19-52 when its GUI started): the guest's 1-minute load is polled until it is below
# GUEST_SETTLE_LOAD, for at most GUEST_SETTLE seconds; then the GUI starts anyway. A *_LOAD entry is an unscaled load
# threshold, not seconds: harness.py threshold() reads it and names() leaves it out of the scaled deadlines.
HARNESS_GUEST_SETTLE=75
HARNESS_GUEST_SETTLE_LOAD=2
# Guest helpers started over SSH, and the peer and host fixtures.
HARNESS_EN0_LOSS_TRIGGER=20
HARNESS_EN0_GENERATOR_RECORD=30
# ONDEMAND-ETH: the replacement daemon after a SIGTERM must report the armed rule and an active tunnel within this wait.
HARNESS_ONDEMAND_DAEMON_RESTART=90
# UNINSTALL: the CLI's run including the console approval, the app's finish offer (and the secure install action), the
# daemon's return after Register, and the secure install including its console approval.
HARNESS_UNINSTALL_CLI=60
HARNESS_UNINSTALL_FINISH_OFFER=15
HARNESS_UNINSTALL_REGISTER=30
HARNESS_UNINSTALL_SECURE_INSTALL=30
HARNESS_SYSTEM_RESOLVE=20
HARNESS_GENERATOR_WAIT=120
HARNESS_RECEIVER_READY=10
HARNESS_RECEIVER_RECORD=8
# Leak-probe receivers (host and peer): a cap only; Session.cleanup stops both through their stop files at the row's end.
# Base 900 (M03-T16, DEC-048): 3600 s at the default scale so receivers outlive the longest row; never below the old 600 s.
HARNESS_RECEIVER_LIFETIME=900
HARNESS_RECEIVER_LIFETIME_MIN=600
HARNESS_PROCESS_STOP=5
HARNESS_IPERF3_READY=10
HARNESS_IPERF3_CLIENT=40
HARNESS_PCAP_READ=30

# M03-T02 kept-gap rows: the guest-side fault sampling (token, pf-disable, rt22), the console logout and the lab user's
# relogin at the guest console (the maintainer or the ready guest supplies the login; no password is scripted), and the protected wait after it.
HARNESS_FAULT_SAMPLING=90
HARNESS_CONSOLE_LOGOUT=30
HARNESS_CONSOLE_RELOGIN=120
HARNESS_RELOGIN_PROTECTED=120

# Tools/lab/relay-manager.py (just lab relay, driven mid-row as fault injection): each pgrep/ps inventory call, the
# stop wait after SIGTERM, and the settle before the bind check.
HARNESS_RELAY_INVENTORY=5
HARNESS_RELAY_STOP=5
HARNESS_RELAY_BIND_SETTLE=1
