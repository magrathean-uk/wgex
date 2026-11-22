// SPDX-License-Identifier: MIT

package tun

import "golang.org/x/sys/unix"

// utunControl is the kernel control name of utun interfaces.
const utunControl = "com.apple.net.utun_control"

// maxScanFD is the highest descriptor the utun scan inspects.
const maxScanFD = 1024

// scanUTunFD returns the lowest descriptor in 0...maxScanFD that is a
// kernel-control socket connected to utun_control, or -1. It never creates a
// socket: each candidate's peer address is read with getpeername and its
// control id looked up with CTLIOCGINFO on the candidate itself.
func scanUTunFD() int {
	for fd := 0; fd <= maxScanFD; fd++ {
		sa, err := unix.Getpeername(fd)
		if err != nil {
			continue
		}
		ctl, ok := sa.(*unix.SockaddrCtl)
		if !ok {
			continue
		}
		var info unix.CtlInfo
		copy(info.Name[:], utunControl)
		if err := unix.IoctlCtlInfo(fd, &info); err != nil {
			continue
		}
		if ctl.ID == info.Id {
			return fd
		}
	}
	return -1
}
