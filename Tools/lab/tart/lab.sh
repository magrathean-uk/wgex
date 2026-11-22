#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Dispatcher for the paste-in just recipe.
set -euo pipefail
# shellcheck source=Tools/lab/tart/lib.sh
source "$(dirname "$0")/lib.sh"
# Offline dispatch precedes lab_init: help, fixture replay and peer plans never
# resolve an address, inspect a VM or require a mounted Tart installation.
if [[ $# == 0 || "${1:-}" == help || "${1:-}" == --help ]]; then
  cat <<'HELP'
just lab [--dry-run] SUBCOMMAND
  up | down | ssh [-- CMD...] | ssh --clock GUEST-LEAKPROBE | trust
  test [smoke] [--keep] | snapshot NAME | snapshot list | restore NAME
  build | install [WGEX.app] | pcaps | reset-btm --yes-reset
  gui shot OUT.png | gui dump APP [WINDOW [IDENTIFIER]] | gui click X Y | gui activate APP
  gui keys APP WINDOW IDENTIFIER up|down COUNT
  gui press APP WINDOW IDENTIFIER press|confirm X Y ROLE [LABEL] | gui press APP WINDOW IDENTIFIER press-only ROLE [LABEL] | gui scroll APP WINDOW IDENTIFIER [LABEL]
  gui open-pane TARGET | gui run CMD... | gui seed-tcc [BINARY...]
  verdict ROW [--dry-run] [--no-install] [--list] [--report-root DIR]
  peer up [--adopt] [--variant NAME] [--dry-run] WGEX_LAB_APT_MIRROR configures guest apt
  relay [start|stop|status] [--dry-run] | relay mtu on|off [--dry-run]
  profile [default|full4|dual|dns|lockdown|wrong-key] [--dry-run]
  iperf3 fetch|path [--dry-run]  pinned static guest iperf3, verified host-side
HELP
  exit
fi
prefix=()
if [[ "${1:-}" == --dry-run ]]; then
  prefix=(--dry-run)
  shift
fi
case "${1:-}" in
  verdict | peer | relay | profile)
    action="$1"
    shift
    [[ "$action" != verdict ]] || action=verdict-run
    exec bash "$LAB_DIR/../$action.sh" ${prefix[@]+"${prefix[@]}"} "$@"
    ;;
  iperf3)
    shift
    exec python3 -I -B "$LAB_DIR/../iperf3-asset.py" ${prefix[@]+"${prefix[@]}"} "$@"
    ;;
esac
if ((${#prefix[@]})); then set -- --dry-run "$@"; fi
# shellcheck source=Config/Scripts/lib.sh
source "$LAB_ROOT/Config/Scripts/lib.sh"
if [[ "${1:-}" == build || ("${1:-}" == --dry-run && "${2:-}" == build) ]]; then
  [[ "${1:-}" != --dry-run ]] || LAB_DRY=1
else
  lab_init "${1:-}"
fi
dry=()
if [[ "${1:-}" == --dry-run ]]; then
  dry+=(--dry-run)
  shift
fi
action="${1:?usage: lab.sh [--dry-run] <up|down|ssh|test|snapshot|restore|build|install|pcaps|reset-btm|gui|trust>}"
shift
case "$action" in
  up)
    (($# == 0)) || lab_die 'up takes no arguments'
    exec bash "$LAB_DIR/snapshot.sh" ${dry[@]+"${dry[@]}"} restore approved
    ;;
  down)
    (($# == 0)) || lab_die 'down takes no arguments'
    lab_stop
    ;;
  snapshot) exec bash "$LAB_DIR/snapshot.sh" ${dry[@]+"${dry[@]}"} "$@" ;;
  restore) exec bash "$LAB_DIR/snapshot.sh" ${dry[@]+"${dry[@]}"} restore "$@" ;;
  test) exec bash "$LAB_DIR/run-tests.sh" ${dry[@]+"${dry[@]}"} "$@" ;;
  build) exec bash "$LAB_DIR/build.sh" ${dry[@]+"${dry[@]}"} "$@" ;;
  install)
    app="${1:-$(build_root)/derived-data/Build/Products/Lab/WGEX.app}"
    (($# <= 1)) || lab_die 'install takes one optional app path'
    exec bash "$LAB_DIR/install-app.sh" ${dry[@]+"${dry[@]}"} "$app"
    ;;
  pcaps) exec bash "$LAB_DIR/fetch-pcaps.sh" ${dry[@]+"${dry[@]}"} "$@" ;;
  gui) exec bash "$LAB_DIR/gui.sh" ${dry[@]+"${dry[@]}"} "$@" ;;
  trust)
    (($# == 0)) || lab_die 'trust takes no arguments'
    lab_trust
    ;;
  ssh)
    timed_clock=0
    if [[ "${1:-}" == --clock ]]; then
      timed_clock=1
      shift
    fi
    [[ "${1:-}" != -- ]] || shift
    lab_connect
    guest_is_lab
    if [[ "$timed_clock" == 1 ]]; then
      [[ "$#" == 1 && "$1" =~ ^/Users/$LAB_USER/lab/verdict-lab-[a-z0-9]+/leakprobe$ ]] || lab_die 'clock needs the staged leakprobe path'
      if [[ "$LAB_DRY" == 1 ]]; then lab_print ssh "${LAB_SSH[@]}" "$LAB_USER@$LAB_ADDRESS" "$1 clock"; else
        python3 -I -B "$LAB_DIR/../clock-hop.py" ssh "${LAB_SSH[@]}" "$LAB_USER@$LAB_ADDRESS" "$1 clock"
      fi
    elif (($# == 1)); then
      lab_ssh "$1" # one argument: a shell command line for the guest, passed verbatim
    elif (($#)); then
      printf -v command '%q ' "$@"
      lab_ssh "$command"
    else
      if [[ "$LAB_DRY" == 1 ]]; then lab_mutate ssh -t "${LAB_SSH[@]}" "$LAB_USER@$LAB_ADDRESS"; else lab_local ssh -t "${LAB_SSH[@]}" "$LAB_USER@$LAB_ADDRESS"; fi
    fi
    ;;
  reset-btm)
    [[ "${1:-}" == --yes-reset && "$#" == 1 ]] || lab_die 'explicit reset-btm --yes-reset required'
    lab_connect
    guest_is_lab
    stage="/Users/$LAB_USER/lab/reset-btm.sh"
    lab_scp "$LAB_DIR/reset-btm.sh" "$LAB_USER@$LAB_ADDRESS:$stage"
    lab_ssh "bash '$stage' --yes-reset" </dev/null
    ;;
  *) lab_die 'unknown lab action' ;;
esac
