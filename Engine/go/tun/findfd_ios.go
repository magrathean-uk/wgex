// SPDX-License-Identifier: MIT

package tun

// FindUTunFD returns the utun descriptor NetworkExtension opened in this
// process, or -1 (GOOS=ios, which also covers tvOS). The kernel-control
// headers are absent from the iOS and tvOS SDKs, so the scan runs in Go
// (ADR-013).
func FindUTunFD() int { return scanUTunFD() }
