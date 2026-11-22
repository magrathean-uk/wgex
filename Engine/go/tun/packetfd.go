// SPDX-License-Identifier: MIT

// Package tun builds the wireguard-go tun.Device for each wgex_create
// tun_kind (02-architecture §6.1): an NE utun descriptor (kind 0), a packet
// descriptor (kind 1) and a root-created utun (kind 2), plus the iOS/tvOS
// utun descriptor scan behind wgex_find_utun_fd.
package tun

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

// MinPacketFDMTU and MaxPacketFDMTU bound the MTU of a packet-descriptor tun.
const (
	MinPacketFDMTU = 576
	MaxPacketFDMTU = 65535
)

// PacketFD is a tun.Device over one end of a SOCK_DGRAM socketpair: one raw
// IP packet per datagram, no address-family header (tun_kind 1). It is the
// test and packetFlow-fallback path; the peer end belongs to the caller.
type PacketFD struct {
	file      *os.File
	mtu       int
	events    chan wgtun.Event
	closeOnce sync.Once
}

var _ wgtun.Device = (*PacketFD)(nil)

// dupNonblock duplicates fd (close-on-exec) and puts the duplicate into
// non-blocking mode so os.File uses the runtime poller and Close unblocks
// pending reads. The caller keeps ownership of fd. O_NONBLOCK is a property of
// the open file description, so the caller's descriptor becomes non-blocking
// as well.
func dupNonblock(fd int) (int, error) {
	if fd < 0 {
		return -1, fmt.Errorf("invalid descriptor %d", fd)
	}
	nfd, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("dup descriptor: %w", err)
	}
	if err := unix.SetNonblock(nfd, true); err != nil {
		unix.Close(nfd)
		return -1, fmt.Errorf("set non-blocking: %w", err)
	}
	return nfd, nil
}

// NewPacketFD wraps a duplicate of fd, which must be a SOCK_DGRAM socket.
func NewPacketFD(fd, mtu int) (*PacketFD, error) {
	if mtu < MinPacketFDMTU || mtu > MaxPacketFDMTU {
		return nil, fmt.Errorf("mtu %d outside %d...%d", mtu, MinPacketFDMTU, MaxPacketFDMTU)
	}
	nfd, err := dupNonblock(fd)
	if err != nil {
		return nil, err
	}
	typ, err := unix.GetsockoptInt(nfd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || typ != unix.SOCK_DGRAM {
		unix.Close(nfd)
		if err == nil {
			err = fmt.Errorf("socket type %d", typ)
		}
		return nil, fmt.Errorf("descriptor is not a SOCK_DGRAM socket: %w", err)
	}
	// Unix datagram sockets cap a datagram at the send buffer size (2 KiB by
	// default on Darwin); make room for full-MTU packets in both directions.
	buf := max(4*mtu, 64<<10)
	_ = unix.SetsockoptInt(nfd, unix.SOL_SOCKET, unix.SO_SNDBUF, buf)
	_ = unix.SetsockoptInt(nfd, unix.SOL_SOCKET, unix.SO_RCVBUF, buf)
	return &PacketFD{
		file:   os.NewFile(uintptr(nfd), "wgex-packetfd"),
		mtu:    mtu,
		events: make(chan wgtun.Event, 1),
	}, nil
}

// File returns the duplicated descriptor.
func (t *PacketFD) File() *os.File { return t.file }

// Read reads one packet into bufs[0][offset:].
func (t *PacketFD) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.file.Read(bufs[0][offset:])
	if err != nil {
		if errors.Is(err, os.ErrClosed) {
			return 0, os.ErrClosed
		}
		return 0, err
	}
	if n == 0 {
		// A zero-length datagram is never an IP packet; the peer end closed.
		return 0, io.EOF
	}
	sizes[0] = n
	return 1, nil
}

// Write writes each packet as one datagram.
func (t *PacketFD) Write(bufs [][]byte, offset int) (int, error) {
	for i, b := range bufs {
		if _, err := t.file.Write(b[offset:]); err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}

// MTU returns the configured MTU.
func (t *PacketFD) MTU() (int, error) { return t.mtu, nil }

// Name returns "packetfd".
func (t *PacketFD) Name() (string, error) { return "packetfd", nil }

// Events returns a channel that delivers no events: the device is brought up
// by wgex_up, never by the descriptor.
func (t *PacketFD) Events() <-chan wgtun.Event { return t.events }

// Close closes the duplicated descriptor and the event channel.
func (t *PacketFD) Close() error {
	var err error
	t.closeOnce.Do(func() {
		err = t.file.Close()
		close(t.events)
	})
	return err
}

// BatchSize returns 1.
func (t *PacketFD) BatchSize() int { return 1 }
