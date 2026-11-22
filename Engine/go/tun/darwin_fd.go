// SPDX-License-Identifier: MIT

package tun

import (
	"errors"
	"os"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// ErrMTUNotAllowed is returned when an NE utun descriptor is given an MTU:
// NetworkExtension owns the interface MTU (tun_kind 0 requires mtu == 0).
var ErrMTUNotAllowed = errors.New("tun_kind 0 requires mtu 0; NetworkExtension sets the MTU")

// FromUTunFD wraps a duplicate of an NE-owned utun descriptor (tun_kind 0).
// The caller keeps its descriptor.
func FromUTunFD(fd, mtu int) (wgtun.Device, error) {
	if mtu != 0 {
		return nil, ErrMTUNotAllowed
	}
	nfd, err := dupNonblock(fd)
	if err != nil {
		return nil, err
	}
	return wgtun.CreateTUNFromFile(os.NewFile(uintptr(nfd), "/dev/tun"), 0)
}
