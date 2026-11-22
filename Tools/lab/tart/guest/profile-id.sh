# SPDX-License-Identifier: MIT
# shellcheck shell=bash
# Public profile metadata only; never transport a document or secret reference.
profile_id() {
  local directory="$1" expected="$2" file name identity filename found=
  [[ -d "$directory" && ! -L "$directory" && "$expected" =~ ^wgex-lab-[a-z0-9-]+$ ]] || return 1
  for file in "$directory"/*.json; do
    [[ -f "$file" && ! -L "$file" ]] || continue
    name="$(/usr/bin/plutil -extract profile.name raw -o - "$file" 2>/dev/null)" || continue
    [[ "$name" == "$expected" ]] || continue
    identity="$(/usr/bin/plutil -extract profile.id raw -o - "$file" 2>/dev/null)" || return 1
    [[ "$identity" =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ ]] || return 1
    identity="$(printf '%s' "$identity" | tr '[:lower:]' '[:upper:]')"
    filename="${file##*/}"
    filename="$(printf '%s' "${filename%.json}" | tr '[:lower:]' '[:upper:]')"
    [[ "$identity" == "$filename" && -z "$found" ]] || return 1
    found="$identity"
  done
  [[ -n "$found" ]] || return 1
  printf '%s\n' "$found"
}
