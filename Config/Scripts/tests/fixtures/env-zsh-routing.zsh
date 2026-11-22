# SPDX-License-Identifier: MIT
# Synthetic session routing for the real-timed-step test: the contract of the machine's env.zsh that the gate relies on,
# restated so the test reads nothing from the host's home. Executed only under a scratch HOME in the test.
#   session key  c-<last 12 characters of CLAUDE_CODE_SESSION_ID>, else x-<last 12 of CODEX_THREAD_ID>
#   stamp        internal|<cache root>|<key>; a caller that already holds this stamp keeps the routing it arrived with
#   cache root   INTERNAL_ROOT from $HOME/.config/wgex/storage.conf (data, read as KEY=value lines, never evaluated)
__cd_root=""
if [ -r "$HOME/.config/wgex/storage.conf" ]; then
  while IFS='=' read -r __cd_k __cd_v; do
    case "$__cd_k" in INTERNAL_ROOT) __cd_v="${__cd_v#\"}"; __cd_root="${__cd_v%\"}" ;; esac
  done < "$HOME/.config/wgex/storage.conf"
fi
__cd_id=""; __cd_h=""
if [ -n "${CLAUDE_CODE_SESSION_ID:-}" ]; then __cd_id="$CLAUDE_CODE_SESSION_ID"; __cd_h=c
elif [ -n "${CODEX_THREAD_ID:-}" ]; then __cd_id="$CODEX_THREAD_ID"; __cd_h=x
fi
__cd_key=""
if [ -n "$__cd_root" ] && [ "${#__cd_id}" -ge 12 ]; then
  __cd_pre="${__cd_id%????????????}"
  __cd_key="$__cd_h-${__cd_id#"$__cd_pre"}"
fi
__cd_stamp="internal|$__cd_root|$__cd_key"
__cd_keep=0
if [ "${CLEAN_DEV_STAMP:-}" = "$__cd_stamp" ]; then __cd_keep=1; fi
__cd_route() {
  if [ "$__cd_keep" = 1 ]; then
    eval "__cd_cur=\${$1:-}"
    if [ -n "$__cd_cur" ]; then eval "export $1"; return 0; fi
  fi
  eval "$1=\$2; export $1"
}
if [ -n "$__cd_key" ]; then
  CLEAN_DEV_STAMP="$__cd_stamp"; export CLEAN_DEV_STAMP
  __cd_route CLEAN_DEV_SESSION "$__cd_key"
  __cd_route CLEAN_DEV_SCRATCH "$__cd_root/scratch/$__cd_key"
  __cd_route CLEAN_DEV_BUILDS "$__cd_root/builds/$__cd_key"
  __cd_route TMPDIR "$__cd_root/scratch/$__cd_key/tmp"
fi
unset -f __cd_route
unset __cd_root __cd_k __cd_v __cd_id __cd_h __cd_key __cd_pre __cd_stamp __cd_keep __cd_cur
:
