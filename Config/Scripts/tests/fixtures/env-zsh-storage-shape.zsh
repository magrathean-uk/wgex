# SPDX-License-Identifier: MIT
# Synthetic storage routing source for the allowlist self-test.
DEVMACHINE="$HOME/work/machine"
unset STORAGE_ROOT STORAGE_CACHE \
  STORAGE_INTERNAL STORAGE_EXTERNAL

if [ -r "$HOME/.config/storage.conf" ]; then
  while IFS='=' read -r name value; do
    case "$name" in
      STORAGE_ROOT|STORAGE_CACHE|STORAGE_INTERNAL|STORAGE_EXTERNAL) eval "$name=\$value" ;;
    esac
  done < "$HOME/.config/storage.conf"
fi
STORAGE_ROOT="${STORAGE_ROOT:-$HOME/work}"
STORAGE_CACHE="${STORAGE_CACHE:-$STORAGE_ROOT/cache}"
STORAGE_INTERNAL="${STORAGE_INTERNAL:-$STORAGE_ROOT/internal}"
STORAGE_EXTERNAL="${STORAGE_EXTERNAL:-$STORAGE_ROOT/external}"
if [ -d "$STORAGE_EXTERNAL" ]; then
  CLEAN_DEV_MODE=external
else
  CLEAN_DEV_MODE=internal
fi

# ---- session key
__cd_id="${CLAUDE_CODE_SESSION_ID:-${CODEX_THREAD_ID:-}}"
__cd_key="$__cd_id"
__cd_h="$__cd_key"
__cd_state="$STORAGE_ROOT/session"

# ---- mode
CLEAN_DEV_STAMP="$__cd_h"
CLEAN_DEV_SESSION="$__cd_key"
CLEAN_DEV_SCRATCH="$STORAGE_CACHE/scratch"
CLEAN_DEV_BUILDS="$STORAGE_CACHE/builds"
CLEAN_DEVELOPMENT_ROOT="$STORAGE_ROOT"
CLEAN_DEVELOPMENT_CACHE_ROOT="$STORAGE_CACHE"
DEVCACHE="$STORAGE_CACHE"
