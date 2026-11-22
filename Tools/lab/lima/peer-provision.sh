#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Run only by vm-lima in the dedicated Linux peer. No key material is echoed.
set +x
set -euo pipefail
# shellcheck source=Tools/lab/lima/peer-state.sh
source "$(dirname "$0")/peer-state.sh"
peer_guard "$@"
[[ "${1:-}" != --dry-run ]] || shift
action="${1:-up}"
case "$action" in
  up)
    mirror="${2:-https://deb.debian.org/debian}"
    shift
    if (($#)); then shift; fi
    adopt=0
    variant=default
    while (($#)); do
      case "$1" in
        --adopt) adopt=1 ;;
        --variant)
          [[ $# -ge 2 ]] || peer_die '--variant needs a profile name'
          variant="$2"
          shift
          ;;
        *) peer_die 'usage: up MIRROR [--adopt] [--variant default|full4|dual|dns|lockdown|wrong-key]' ;;
      esac
      shift
    done
    peer_variant "$variant"
    [[ "$mirror" =~ ^https?://[a-zA-Z0-9./:_-]+$ ]] || exit 1
    export DEBIAN_FRONTEND=noninteractive
    if ! command -v wg >/dev/null || ! command -v iperf3 >/dev/null || ! command -v python3 >/dev/null; then
      # An isolated source list: never rewrites the guest's apt configuration.
      sources="$(mktemp /var/tmp/wgex-apt.XXXXXX)"
      trap 'rm -f "$sources"' EXIT
      printf 'deb %s trixie main\n' "$mirror" >"$sources"
      options=(-o Acquire::Retries=2 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 -o Dpkg::Lock::Timeout=30
        -o "Dir::Etc::sourcelist=$sources" -o Dir::Etc::sourceparts=-)
      peer_exec timeout 180 apt-get "${options[@]}" update >/dev/null 2>&1
      peer_exec timeout 180 apt-get "${options[@]}" install -y --no-install-recommends wireguard-tools iperf3 python3 iproute2 >/dev/null 2>&1
    fi
    [[ -f "$state/server.key" && -f "$state/client1.pub" ]] || exit 1
    boot_dir="$(dirname "$boot_conf")"
    [[ -d "$boot_dir" && ! -L "$boot_dir" && ! -L "$boot_conf" ]] || peer_die 'wg-quick configuration directory missing or unsafe'
    # Adoption is explicit and restricted to an existing WireGuard interface on wg-peer.
    if peer_exec ip link show wg0 >/dev/null 2>&1; then
      peer_exec wg show wg0 >/dev/null 2>&1 || peer_die 'wg0 is not a WireGuard interface; adoption refused'
      [[ -f "$state/owned" || "$adopt" == 1 ]] || peer_die 'wg0 ownership marker missing; verify dedicated ownership, then run just lab peer up --adopt'
    else
      peer_exec ip link add wg0 type wireguard
    fi
    umask 077
    touch "$state/owned"
    {
      printf '[Interface]\nPrivateKey = '
      cat "$state/server.key"
      printf '\nListenPort = 51820\n[Peer]\nPublicKey = '
      cat "$state/client1.pub"
      printf '\nAllowedIPs = 10.77.0.2/32'
      if [[ "$variant" == dual ]]; then printf ', fd77::2/128'; fi
      printf '\n'
    } >"$state/wg0.conf"
    peer_exec wg syncconf wg0 "$state/wg0.conf" >/dev/null 2>&1
    peer_exec ip address replace 10.77.0.1/24 dev wg0
    if [[ "$variant" == dual ]]; then
      peer_exec ip -6 address replace fd77::1/64 dev wg0
    fi
    peer_exec ip link set wg0 up
    touch "$state/owned"
    # Persist the same keys for wg-quick@wg0, or the next peer boot restores the old wg0.conf (L10).
    if [[ -f "$boot_conf" && ! -e "$state/wg0.conf.pre-wgex-lab" ]]; then
      cp "$boot_conf" "$state/wg0.conf.pre-wgex-lab"
      chmod 0600 "$state/wg0.conf.pre-wgex-lab"
    fi
    addresses=10.77.0.1/24
    if [[ "$variant" == dual ]]; then addresses+=', fd77::1/64'; fi
    boot_next="$(mktemp "$boot_dir/.wg0.conf.XXXXXX")" || peer_die 'wg-quick boot configuration temporary file creation failed'
    if ! { printf '[Interface]\nAddress = %s\n' "$addresses" && sed '1d' "$state/wg0.conf"; } >"$boot_next" ||
      ! chmod 0600 "$boot_next" || ! mv -f "$boot_next" "$boot_conf"; then
      rm -f "$boot_next"
      peer_die 'wg-quick boot configuration write failed'
    fi
    printf 'peer: wg0 ready; dedicated fixture keys; 10.77.0.1/24; variant %s; wg-quick@wg0 boot configuration persisted\n' "$variant"
    ;;
  profile)
    variant="${2:-default}"
    peer_variant "$variant"
    # stdout is a private pipe directly into the guest's mode-0600 import file.
    printf '[Interface]\nPrivateKey = '
    if [[ "$variant" == wrong-key ]]; then cat "$state/client2.key"; else cat "$state/client1.key"; fi
    if [[ "$variant" == dual ]]; then
      printf '\nAddress = 10.77.0.2/24, fd77::2/64\n'
    else
      printf '\nAddress = 10.77.0.2/24\n'
    fi
    # Every variant carries the tunnel resolver: since M1-06 a DNS-less tunnel never reports protected (L11).
    printf 'DNS = 10.77.0.1\n'
    printf '\n[Peer]\nPublicKey = '
    peer_exec wg pubkey <"$state/server.key"
    if [[ "$variant" == full4-name ]]; then
      printf 'Endpoint = 192-168-64-1.sslip.io:51820\n'
    else
      printf 'Endpoint = 192.168.64.1:51820\n'
    fi
    printf 'AllowedIPs = '
    case "$variant" in
      default | dns) printf '10.77.0.0/24\n' ;;
      dual) printf '0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1\n' ;;
      full4 | full4-name | lockdown | wrong-key) printf '0.0.0.0/1, 128.0.0.0/1\n' ;;
    esac
    printf 'PersistentKeepalive = 25\n'
    ;;
  *) exit 1 ;;
esac
