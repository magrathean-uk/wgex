// SPDX-License-Identifier: MIT

package transport

import (
	"golang.zx2c4.com/wireguard/conn"
	"net/netip"
	"sync"
	"testing"
)

func TestReceiveReusesOnlyImmutableEndpoints(t *testing.T) {
	pool := &sync.Pool{New: func() any { return new(Packet) }}
	r := newReceiver(pool)
	defer r.close()
	from := netip.MustParseAddrPort("127.0.0.1:1234")
	receive := func(address netip.AddrPort) conn.Endpoint {
		p := r.Get()
		p.From = address
		p.N = 1
		p.Buf[0] = 1
		r.Deliver(p)
		eps := make([]conn.Endpoint, 1)
		_, err := r.receive([][]byte{make([]byte, 1)}, make([]int, 1), eps)
		if err != nil {
			t.Fatal(err)
		}
		return eps[0]
	}
	first := receive(from)
	if first != receive(from) {
		t.Fatal("same sender allocates per packet")
	}
	for port := uint16(2000); port < 2128; port++ {
		_ = receive(netip.AddrPortFrom(from.Addr(), port))
	}
	if first.DstToString() != from.String() {
		t.Fatal("retained endpoint mutated")
	}
}
