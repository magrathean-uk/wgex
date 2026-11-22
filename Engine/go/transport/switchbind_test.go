// SPDX-License-Identifier: MIT

package transport

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// fakeInner delivers datagrams pushed with inject and records sends.
type fakeInner struct {
	kind     string
	mu       sync.Mutex
	r        *Receiver
	sent     [][]byte
	notReady bool
	opens    int
	failOpen bool
}

func (f *fakeInner) Kind() string { return f.kind }
func (f *fakeInner) Open(_ uint16, r *Receiver) (uint16, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOpen {
		return 0, errors.New("open failed")
	}
	f.r = r
	f.opens++
	return 4242, nil
}
func (f *fakeInner) Send(b []byte, _ netip.AddrPort) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.notReady {
		return ErrNotReady
	}
	f.sent = append(f.sent, append([]byte(nil), b...))
	return nil
}
func (f *fakeInner) Close() error {
	f.mu.Lock()
	f.r = nil
	f.mu.Unlock()
	return nil
}
func (f *fakeInner) inject(t *testing.T, payload string, from netip.AddrPort) {
	t.Helper()
	f.mu.Lock()
	r := f.r
	f.mu.Unlock()
	if r == nil {
		t.Fatal("inner not open")
	}
	p := r.Get()
	p.N = copy(p.Buf[:], payload)
	p.From = from
	if !r.Deliver(p) {
		t.Fatal("deliver refused")
	}
}

func recvOne(t *testing.T, fn conn.ReceiveFunc) (string, conn.Endpoint, error) {
	t.Helper()
	bufs := [][]byte{make([]byte, 2048)}
	sizes := []int{0}
	eps := []conn.Endpoint{nil}
	n, err := fn(bufs, sizes, eps)
	if err != nil {
		return "", nil, err
	}
	if n != 1 {
		t.Fatalf("n = %d", n)
	}
	return string(bufs[0][:sizes[0]]), eps[0], nil
}

func TestSwitchBindReceiveSurvivesSwapAndEndsOnClose(t *testing.T) {
	a, b := &fakeInner{kind: "a"}, &fakeInner{kind: "b"}
	sb := New(a)
	fns, port, err := sb.Open(0)
	if err != nil || len(fns) != 1 || port != 4242 {
		t.Fatalf("Open = %d fns, port %d, %v", len(fns), port, err)
	}
	if _, _, err := sb.Open(0); !errors.Is(err, conn.ErrBindAlreadyOpen) {
		t.Fatalf("second Open = %v", err)
	}
	from := netip.MustParseAddrPort("192.0.2.1:51820")
	a.inject(t, "one", from)
	got, ep, err := recvOne(t, fns[0])
	if err != nil || got != "one" || ep.DstToString() != from.String() {
		t.Fatalf("receive = %q %v %v", got, ep, err)
	}

	if err := sb.Swap(b); err != nil {
		t.Fatal(err)
	}
	if sb.Inner().Kind() != "b" {
		t.Fatal("swap did not take effect")
	}
	b.inject(t, "two", from)
	if got, _, err := recvOne(t, fns[0]); err != nil || got != "two" {
		t.Fatalf("receive after swap = %q %v", got, err)
	}
	ep2, _ := sb.ParseEndpoint("192.0.2.1:51820")
	if err := sb.Send([][]byte{[]byte("x")}, ep2); err != nil || len(b.sent) != 1 || len(a.sent) != 0 {
		t.Fatalf("send after swap: %v, a=%d b=%d", err, len(a.sent), len(b.sent))
	}

	b.notReady = true
	if err := sb.Send([][]byte{[]byte("y")}, ep2); err != nil || sb.Drops() != 1 {
		t.Fatalf("send while not ready: %v, drops %d", err, sb.Drops())
	}

	done := make(chan error, 1)
	go func() { _, _, err := recvOne(t, fns[0]); done <- err }()
	time.Sleep(20 * time.Millisecond)
	if err := sb.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("receive after Close = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("receive did not end on Close")
	}
	if err := sb.Send([][]byte{[]byte("z")}, ep2); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("send after Close = %v", err)
	}
	if err := sb.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
	if _, _, err := sb.Open(0); err != nil {
		t.Fatalf("reopen = %v", err)
	}
	_ = sb.Close()
}

func TestSwitchBindSwapFailureKeepsPrevious(t *testing.T) {
	a, bad := &fakeInner{kind: "a"}, &fakeInner{kind: "bad", failOpen: true}
	sb := New(a)
	if _, _, err := sb.Open(0); err != nil {
		t.Fatal(err)
	}
	defer sb.Close()
	if err := sb.Swap(bad); err == nil {
		t.Fatal("swap to a failing transport succeeded")
	}
	if sb.Inner().Kind() != "a" || a.opens != 2 {
		t.Fatalf("inner %s, opens %d", sb.Inner().Kind(), a.opens)
	}
}

func TestSwitchBindRejectsForeignEndpoint(t *testing.T) {
	sb := New(&fakeInner{kind: "a"})
	if _, err := sb.ParseEndpoint("example.com:1"); err == nil {
		t.Fatal("hostname endpoint accepted")
	}
	ep, err := sb.ParseEndpoint("[::ffff:192.0.2.1]:7")
	if err != nil || ep.DstIP() != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("mapped address not unmapped: %v %v", ep, err)
	}
	if err := sb.Send(nil, &conn.StdNetEndpoint{}); !errors.Is(err, conn.ErrWrongEndpointType) {
		t.Fatalf("foreign endpoint = %v", err)
	}
	if sb.BatchSize() != 1 {
		t.Fatal("batch size")
	}
}

func TestUDPLoopbackBoundToInterface(t *testing.T) {
	lo, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skip("no lo0")
	}
	for _, idx := range []uint32{0, uint32(lo.Index)} {
		u := NewUDP(idx, idx)
		sb := New(u)
		fns, port, err := sb.Open(0)
		if err != nil {
			t.Fatalf("ifindex %d: %v", idx, err)
		}
		v4, v6 := u.LocalPorts()
		if v4 != port || (v6 != 0 && v6 != port) {
			t.Fatalf("ports v4 %d v6 %d, want %d", v4, v6, port)
		}
		peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		ep, _ := sb.ParseEndpoint(peer.LocalAddr().String())
		if err := sb.Send([][]byte{[]byte("ping")}, ep); err != nil {
			t.Fatalf("ifindex %d: send: %v", idx, err)
		}
		buf := make([]byte, 16)
		_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, from, err := peer.ReadFromUDPAddrPort(buf)
		if err != nil || string(buf[:n]) != "ping" || from.Port() != port {
			t.Fatalf("ifindex %d: peer got %q from %v: %v", idx, buf[:n], from, err)
		}
		if _, err := peer.WriteToUDPAddrPort([]byte("pong"), netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)); err != nil {
			t.Fatal(err)
		}
		got, rep, err := recvOne(t, fns[0])
		if err != nil || got != "pong" || rep.DstToString() != peer.LocalAddr().String() {
			t.Fatalf("ifindex %d: received %q from %v: %v", idx, got, rep, err)
		}
		peer.Close()
		if err := sb.Close(); err != nil {
			t.Fatal(err)
		}
		// Rebinding the same port after Close works (BindUpdate keeps the port).
		if _, p2, err := sb.Open(port); err != nil || p2 != port {
			t.Fatalf("reopen on %d: %d %v", port, p2, err)
		}
		_ = sb.Close()
	}
}

func TestUDPBadInterfaceFailsOpen(t *testing.T) {
	sb := New(NewUDP(999999, 0))
	if _, _, err := sb.Open(0); err == nil {
		sb.Close()
		t.Fatal("binding to a missing interface succeeded")
	}
}
