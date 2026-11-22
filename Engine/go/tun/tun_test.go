// SPDX-License-Identifier: MIT

package tun

import (
	"errors"
	"os"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func socketpair(t *testing.T) (int, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fds[0]); unix.Close(fds[1]) })
	for _, fd := range fds {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 1<<17)
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<17)
	}
	return fds[0], fds[1]
}

func ipv4Packet(n int, seq byte) []byte {
	p := make([]byte, n)
	p[0] = 0x45
	p[2], p[3] = byte(n>>8), byte(n)
	for i := 20; i < n; i++ {
		p[i] = seq
	}
	return p
}

// P1-19: packets cross a socketpair one datagram each, in both directions,
// with no address-family header, up to the MTU.
func TestPacketFDEcho(t *testing.T) {
	const mtu = 1420
	ours2, theirs2 := socketpair(t)
	dev2, err := NewPacketFD(ours2, mtu)
	if err != nil {
		t.Fatal(err)
	}
	echoed := make(chan int, 1)
	go func() {
		buf := make([]byte, mtu+16)
		sizes := []int{0}
		count := 0
		for {
			if _, err := dev2.Read([][]byte{buf}, sizes, 16); err != nil {
				echoed <- count
				return
			}
			if _, err := dev2.Write([][]byte{buf[:16+sizes[0]]}, 16); err != nil {
				echoed <- count
				return
			}
			count++
		}
	}()
	for i, size := range []int{20, 576, 1280, mtu} {
		pkt := ipv4Packet(size, byte(i))
		if _, err := unix.Write(theirs2, pkt); err != nil {
			t.Fatalf("write %d: %v", size, err)
		}
		got := make([]byte, mtu+100)
		_ = unix.SetsockoptTimeval(theirs2, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2})
		n, err := unix.Read(theirs2, got)
		if err != nil || n != size || string(got[:n]) != string(pkt) {
			t.Fatalf("echo of %d bytes: got %d bytes, %v", size, n, err)
		}
	}
	start := time.Now()
	if err := dev2.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case n := <-echoed:
		if n != 4 {
			t.Fatalf("echoed %d packets", n)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock Read")
	}
	t.Logf("Close unblocked the reader in %v", time.Since(start))
	if _, err := dev2.Read([][]byte{make([]byte, 10)}, []int{0}, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("read after close = %v", err)
	}
	// The caller's descriptor stays open after the device closes.
	if _, err := unix.FcntlInt(uintptr(ours2), unix.F_GETFD, 0); err != nil {
		t.Fatalf("caller descriptor closed: %v", err)
	}
}

func TestPacketFDRejectsBadInput(t *testing.T) {
	ours, _ := socketpair(t)
	for _, mtu := range []int{0, 575, 65536} {
		if _, err := NewPacketFD(ours, mtu); err == nil {
			t.Errorf("mtu %d accepted", mtu)
		}
	}
	if _, err := NewPacketFD(-1, 1280); err == nil {
		t.Error("fd -1 accepted")
	}
	stream, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(stream[0])
	defer unix.Close(stream[1])
	if _, err := NewPacketFD(stream[0], 1280); err == nil {
		t.Error("SOCK_STREAM accepted")
	}
}

func TestUTunFDRequiresZeroMTU(t *testing.T) {
	if _, err := FromUTunFD(0, 1280); !errors.Is(err, ErrMTUNotAllowed) {
		t.Fatalf("FromUTunFD with mtu = %v", err)
	}
	ours, _ := socketpair(t)
	if _, err := FromUTunFD(ours, 0); err == nil {
		t.Fatal("a socketpair was accepted as a utun descriptor")
	}
}

func TestFindUTunFD(t *testing.T) {
	if runtime.GOOS != "ios" && FindUTunFD() != -1 {
		t.Fatal("FindUTunFD must return -1 on macOS")
	}
	// The scan itself runs on macOS; this process holds no utun descriptor.
	_, _ = socketpair(t)
	if fd := ScanUTunFD(); fd != -1 {
		t.Fatalf("scan found fd %d", fd)
	}
}

func TestCreateUTunValidates(t *testing.T) {
	if _, err := CreateUTun("en0", 1280); err == nil {
		t.Fatal("non-utun name accepted")
	}
	if _, err := CreateUTun("utun", 0); err == nil {
		t.Fatal("mtu 0 accepted")
	}
}
