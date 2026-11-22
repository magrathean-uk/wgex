// SPDX-License-Identifier: MIT

package tun

import (
	"fmt"
	"strings"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// CreateUTun creates a utun interface (tun_kind 2). It needs root and is used
// only by the macOS daemon; tests never call it.
func CreateUTun(name string, mtu int) (wgtun.Device, error) {
	if !strings.HasPrefix(name, "utun") {
		return nil, fmt.Errorf("interface name %q must start with utun", name)
	}
	if mtu <= 0 || mtu > MaxPacketFDMTU {
		return nil, fmt.Errorf("mtu %d out of range", mtu)
	}
	return wgtun.CreateTUN(name, mtu)
}
