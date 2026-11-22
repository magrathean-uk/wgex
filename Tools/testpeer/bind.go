// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// addrBind is a minimal conn.Bind that listens on explicit local addresses
// instead of the wildcard sockets conn.NewDefaultBind opens. It is used when
// --listen names a specific address (for example a LAN or loopback address).
type addrBind struct {
	addrs []netip.AddrPort

	mu    sync.Mutex
	conns []*net.UDPConn
}

func newAddrBind(addrs []netip.AddrPort) *addrBind { return &addrBind{addrs: addrs} }

type udpEndpoint struct{ dst netip.AddrPort }

func (e *udpEndpoint) ClearSrc()           {}
func (e *udpEndpoint) SrcToString() string { return "" }
func (e *udpEndpoint) DstToString() string { return e.dst.String() }
func (e *udpEndpoint) DstToBytes() []byte {
	b, _ := e.dst.MarshalBinary()
	return b
}
func (e *udpEndpoint) DstIP() netip.Addr { return e.dst.Addr() }
func (e *udpEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

func unmapAddrPort(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func (b *addrBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conns != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	actual := port
	var conns []*net.UDPConn
	for _, a := range b.addrs {
		network := "udp4"
		if a.Addr().Is6() {
			network = "udp6"
		}
		c, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(a.Addr(), actual)))
		if err != nil {
			for _, o := range conns {
				o.Close()
			}
			return nil, 0, err
		}
		if actual == 0 {
			actual = c.LocalAddr().(*net.UDPAddr).AddrPort().Port()
		}
		conns = append(conns, c)
	}
	b.conns = conns
	fns := make([]conn.ReceiveFunc, 0, len(conns))
	for _, c := range conns {
		fns = append(fns, func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, ap, err := c.ReadFromUDPAddrPort(packets[0])
			if err != nil {
				return 0, err
			}
			sizes[0] = n
			eps[0] = &udpEndpoint{dst: unmapAddrPort(ap)}
			return 1, nil
		})
	}
	return fns, actual, nil
}

func (b *addrBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	var err error
	for _, c := range b.conns {
		err = errors.Join(err, c.Close())
	}
	b.conns = nil
	return err
}

func (b *addrBind) SetMark(uint32) error { return nil }
func (b *addrBind) BatchSize() int       { return 1 }

func (b *addrBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &udpEndpoint{dst: unmapAddrPort(ap)}, nil
}

func (b *addrBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(*udpEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	b.mu.Lock()
	var c *net.UDPConn
	for _, cc := range b.conns {
		if cc.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap().Is4() == e.dst.Addr().Is4() {
			c = cc
			break
		}
	}
	b.mu.Unlock()
	if c == nil {
		return fmt.Errorf("no listening socket for the address family of %s", e.dst)
	}
	for _, buf := range bufs {
		if _, err := c.WriteToUDPAddrPort(buf, e.dst); err != nil {
			return err
		}
	}
	return nil
}

// ChaosConfig describes impairments applied to WireGuard UDP on the server.
// Source filters act on inbound datagrams only and match the UDP source
// address, so traffic forwarded by a relay (whose source is the relay) is
// unaffected unless the relay itself is named.
type ChaosConfig struct {
	DropFrom      []netip.Prefix
	AllowOnlyFrom []netip.Prefix
	DropAfter     time.Duration // deprecated: global, hits relay traffic too
	LossPct       float64       // per direction
	Latency       time.Duration // added to outbound datagrams
}

func (c ChaosConfig) active() bool {
	return len(c.DropFrom) > 0 || len(c.AllowOnlyFrom) > 0 || c.DropAfter > 0 || c.LossPct > 0 || c.Latency > 0
}

type chaosCounters struct {
	dropFrom, allowOnly, dropAfter, lossIn, lossOut, delayed, queueFull, v6Disabled atomic.Uint64
}

type delayedSend struct {
	due  time.Time
	bufs [][]byte
	ep   conn.Endpoint
}

// chaosBind wraps another conn.Bind (normally conn.NewDefaultBind()) and
// applies ChaosConfig to the datagrams passing through it.
type chaosBind struct {
	inner    conn.Bind
	cfg      ChaosConfig
	acceptV6 bool
	ev       *Events
	start    time.Time

	counters chaosCounters

	mu     sync.Mutex
	logged map[string]bool

	afterLogged atomic.Bool

	queue    chan delayedSend
	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

func newChaosBind(inner conn.Bind, cfg ChaosConfig, acceptV6 bool, ev *Events) *chaosBind {
	b := &chaosBind{
		inner:    inner,
		cfg:      cfg,
		acceptV6: acceptV6,
		ev:       ev,
		start:    time.Now(),
		logged:   map[string]bool{},
		stop:     make(chan struct{}),
	}
	if cfg.Latency > 0 {
		b.queue = make(chan delayedSend, 4096)
		b.wg.Add(1)
		go b.delayLoop()
	}
	return b
}

func (b *chaosBind) shutdown() {
	b.stopOnce.Do(func() { close(b.stop) })
	b.wg.Wait()
}

func (b *chaosBind) delayLoop() {
	defer b.wg.Done()
	t := time.NewTimer(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-b.stop:
			return
		case d := <-b.queue:
			if wait := time.Until(d.due); wait > 0 {
				t.Reset(wait)
				select {
				case <-b.stop:
					return
				case <-t.C:
				}
			}
			_ = b.inner.Send(d.bufs, d.ep)
		}
	}
}

func (b *chaosBind) logOnce(rule string, src netip.Addr) {
	key := rule + "|" + src.String()
	b.mu.Lock()
	seen := b.logged[key]
	b.logged[key] = true
	b.mu.Unlock()
	if !seen {
		b.ev.Emit("chaos_drop", "rule", rule, "src", src.String(), "note", "first drop for this rule and source; later drops are counted")
	}
}

func lossHit(pct float64) bool {
	if pct <= 0 {
		return false
	}
	if pct >= 100 {
		return true
	}
	return rand.Float64()*100 < pct
}

// dropInbound reports whether an inbound datagram from src must be dropped.
func (b *chaosBind) dropInbound(src netip.Addr) bool {
	src = src.Unmap()
	if src.Is6() && !b.acceptV6 {
		b.counters.v6Disabled.Add(1)
		b.logOnce("ipv6_underlay_disabled", src)
		return true
	}
	for _, p := range b.cfg.DropFrom {
		if p.Contains(src) {
			b.counters.dropFrom.Add(1)
			b.logOnce("drop_udp_from", src)
			return true
		}
	}
	if len(b.cfg.AllowOnlyFrom) > 0 {
		allowed := false
		for _, p := range b.cfg.AllowOnlyFrom {
			if p.Contains(src) {
				allowed = true
				break
			}
		}
		if !allowed {
			b.counters.allowOnly.Add(1)
			b.logOnce("allow_udp_only_from", src)
			return true
		}
	}
	if b.cfg.DropAfter > 0 && time.Since(b.start) >= b.cfg.DropAfter {
		if b.afterLogged.CompareAndSwap(false, true) {
			b.ev.Emit("chaos_drop_after_active", "after_s", b.cfg.DropAfter.Seconds(), "note", "all WireGuard UDP is now dropped, including relay-forwarded traffic")
		}
		b.counters.dropAfter.Add(1)
		return true
	}
	if lossHit(b.cfg.LossPct) {
		b.counters.lossIn.Add(1)
		return true
	}
	return false
}

func (b *chaosBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.inner.Open(port)
	if err != nil {
		return nil, 0, err
	}
	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		wrapped[i] = func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, err := fn(packets, sizes, eps)
			for j := 0; j < n; j++ {
				// The device skips entries whose size is below the minimum
				// WireGuard message size, so zeroing the size drops it.
				if sizes[j] > 0 && eps[j] != nil && b.dropInbound(eps[j].DstIP()) {
					sizes[j] = 0
				}
			}
			return n, err
		}
	}
	return wrapped, actual, nil
}

func (b *chaosBind) Close() error                                  { return b.inner.Close() }
func (b *chaosBind) SetMark(mark uint32) error                     { return b.inner.SetMark(mark) }
func (b *chaosBind) ParseEndpoint(s string) (conn.Endpoint, error) { return b.inner.ParseEndpoint(s) }
func (b *chaosBind) BatchSize() int                                { return b.inner.BatchSize() }

func (b *chaosBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if b.cfg.LossPct > 0 {
		kept := make([][]byte, 0, len(bufs))
		for _, buf := range bufs {
			if lossHit(b.cfg.LossPct) {
				b.counters.lossOut.Add(1)
				continue
			}
			kept = append(kept, buf)
		}
		bufs = kept
		if len(bufs) == 0 {
			return nil
		}
	}
	if b.cfg.Latency <= 0 {
		return b.inner.Send(bufs, ep)
	}
	// The device reuses its buffers once Send returns, so copy them.
	cp := make([][]byte, len(bufs))
	for i, buf := range bufs {
		cp[i] = append([]byte(nil), buf...)
	}
	select {
	case b.queue <- delayedSend{due: time.Now().Add(b.cfg.Latency), bufs: cp, ep: ep}:
		b.counters.delayed.Add(uint64(len(cp)))
	default:
		b.counters.queueFull.Add(uint64(len(cp)))
	}
	return nil
}

func (b *chaosBind) counterAttrs() []any {
	c := &b.counters
	return []any{
		"drop_udp_from", c.dropFrom.Load(),
		"allow_udp_only_from", c.allowOnly.Load(),
		"drop_udp_after", c.dropAfter.Load(),
		"loss_in", c.lossIn.Load(),
		"loss_out", c.lossOut.Load(),
		"delayed", c.delayed.Load(),
		"delay_queue_full", c.queueFull.Load(),
		"ipv6_underlay_disabled", c.v6Disabled.Load(),
	}
}
