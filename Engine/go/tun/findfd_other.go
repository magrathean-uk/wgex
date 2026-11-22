// SPDX-License-Identifier: MIT

//go:build !ios

package tun

// FindUTunFD returns -1 outside GOOS=ios: on macOS the daemon creates its own
// utun (tun_kind 2) and never scans descriptors.
func FindUTunFD() int { return -1 }

// ScanUTunFD exposes the descriptor scan to macOS tests, which can run it but
// cannot create a utun without root.
func ScanUTunFD() int { return scanUTunFD() }
