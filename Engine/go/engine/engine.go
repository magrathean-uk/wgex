// SPDX-License-Identifier: MIT

// Package engine holds the WGEX domain logic around wireguard-go
// (02-architecture §6): the Engine type (device, tun, SwitchBind, public
// statistics, health events, callback dispatch) and the process memory
// governor. The C ABI in package main (bridge) and the registry in package
// cabi are thin layers over it.
package engine

import (
	"runtime/debug"
)

// WireGuardModule is the module path of the pinned userspace engine.
const WireGuardModule = "golang.zx2c4.com/wireguard"

// WireGuardCommit is the pinned wireguard-go revision (ADR-005).
const WireGuardCommit = "b3bc704ef0ee21a36298601a9e1e5ff90377ac52"

// Version returns the wireguard-go module version linked into the running
// binary, or "unknown" when the binary carries no module information.
func Version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path != WireGuardModule {
			continue
		}
		if dep.Replace != nil {
			return dep.Replace.Version
		}
		return dep.Version
	}
	return "unknown"
}
