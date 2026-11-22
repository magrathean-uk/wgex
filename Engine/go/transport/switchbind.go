// SPDX-License-Identifier: MIT

// Package transport holds SwitchBind, the only conn.Bind WGEX gives to
// device.NewDevice (02-architecture §8.2, ADR-014), and its inner transports.
//
// SwitchBind decouples wireguard-go's receive routines from the transport that
// actually moves datagrams: Open returns immediately with receive functions
// that read from a channel, and whichever inner transport is active feeds that
// channel. Swapping inner transports happens under SwitchBind's own mutex and
// does not end the receive functions; only Close does. wireguard-go's
// BindUpdate (Close then Open) is used for UDP rebinds only.
package transport

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

// BatchSize is the constant number of datagrams SwitchBind hands over per
// receive call and accepts per Send. It never changes for a device's lifetime.
const BatchSize = 1

// PacketSize is the receive buffer size: the largest datagram wireguard-go
// accepts on this platform (65535 on macOS, 1700 on iOS/tvOS).
const PacketSize = device.MaxMessageSize

// receiveQueue bounds the datagrams buffered between an inner transport and
// wireguard-go's receive routine; a full queue back-pressures the transport.
const receiveQueue = 64

// Packet is one received datagram. Inner transports obtain packets from a
// Receiver, fill Buf[:N] and From, and hand them back through Deliver.
type Packet struct {
	Buf  [PacketSize]byte
	N    int
	From netip.AddrPort
}

// Inner is a transport SwitchBind routes datagrams through.
type Inner interface {
	// Kind names the transport ("udp", later "vless").
	Kind() string
	// Open starts delivering datagrams to r and returns at once; it must never
	// wait on the network. port is the requested local UDP port (0 = any) and
	// is meaningful only to transports that bind a local port; actualPort is
	// what was bound (0 for transports without one).
	Open(port uint16, r *Receiver) (actualPort uint16, err error)
	// Send transmits one datagram to ep. It must not block on the network.
	Send(b []byte, ep netip.AddrPort) error
	// Close stops delivery. After Close returns the transport never calls r again.
	Close() error
}

// Endpoint is SwitchBind's neutral endpoint: a literal address and port that
// is valid for every inner transport.
type Endpoint struct {
	netip.AddrPort
}

var _ conn.Endpoint = (*Endpoint)(nil)

// ClearSrc is a no-op: SwitchBind keeps no source address.
func (*Endpoint) ClearSrc() {}

// SrcToString returns "" (no source address is cached).
func (*Endpoint) SrcToString() string { return "" }

// DstToString returns the peer address as ip:port.
func (e *Endpoint) DstToString() string { return e.AddrPort.String() }

// DstToBytes returns the address and port in binary form, for mac2 cookies.
func (e *Endpoint) DstToBytes() []byte {
	b, _ := e.AddrPort.MarshalBinary()
	return b
}

// DstIP returns the peer address.
func (e *Endpoint) DstIP() netip.Addr { return e.AddrPort.Addr() }

// SrcIP returns the zero address.
func (*Endpoint) SrcIP() netip.Addr { return netip.Addr{} }

// Receiver is the delivery side of one SwitchBind open generation.
type Receiver struct {
	ch            chan *Packet
	done          chan struct{}
	pool          *sync.Pool
	endpointMu    sync.Mutex
	endpoints     map[netip.AddrPort]*Endpoint
	nextEndpoint  int
	endpointOrder [64]netip.AddrPort
}

func newReceiver(pool *sync.Pool) *Receiver {
	return &Receiver{ch: make(chan *Packet, receiveQueue), done: make(chan struct{}), pool: pool, endpoints: make(map[netip.AddrPort]*Endpoint)}
}

// Get returns an empty packet to fill.
func (r *Receiver) Get() *Packet { return r.pool.Get().(*Packet) }

// Put returns an unused packet.
func (r *Receiver) Put(p *Packet) { r.pool.Put(p) }

// Deliver hands p to wireguard-go. It blocks while the queue is full and
// returns false, recycling p, once the generation has closed.
func (r *Receiver) Deliver(p *Packet) bool {
	select {
	case <-r.done:
		r.pool.Put(p)
		return false
	default:
	}
	select {
	case r.ch <- p:
		return true
	case <-r.done:
		r.pool.Put(p)
		return false
	}
}

// Done is closed when this generation is closed.
func (r *Receiver) Done() <-chan struct{} { return r.done }

func (r *Receiver) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	select {
	case p := <-r.ch:
		n := copy(packets[0], p.Buf[:p.N])
		sizes[0] = n
		eps[0] = r.endpoint(p.From)
		r.pool.Put(p)
		return 1, nil
	case <-r.done:
		return 0, net.ErrClosed
	}
}

// endpoint interns immutable snapshots in a bounded per-generation pool. Upstream
// retains conn.Endpoint after receive returns, so mutable endpoint reuse is unsafe.
func (r *Receiver) endpoint(from netip.AddrPort) *Endpoint {
	r.endpointMu.Lock()
	defer r.endpointMu.Unlock()
	if ep := r.endpoints[from]; ep != nil {
		return ep
	}
	delete(r.endpoints, r.endpointOrder[r.nextEndpoint])
	ep := &Endpoint{AddrPort: from}
	r.endpoints[from] = ep
	r.endpointOrder[r.nextEndpoint] = from
	r.nextEndpoint = (r.nextEndpoint + 1) % len(r.endpointOrder)
	return ep
}

func (r *Receiver) close() {
	close(r.done)
	for {
		select {
		case p := <-r.ch:
			r.pool.Put(p)
		default:
			return
		}
	}
}

// SwitchBind implements conn.Bind over a swappable inner transport.
type SwitchBind struct {
	mu    sync.RWMutex
	inner Inner
	recv  *Receiver // nil while closed
	port  uint16
	pool  sync.Pool
	drops atomic.Uint64
}

var _ conn.Bind = (*SwitchBind)(nil)

// New returns a closed SwitchBind routing through inner.
func New(inner Inner) *SwitchBind {
	b := &SwitchBind{inner: inner}
	b.pool.New = func() any { return new(Packet) }
	return b
}

// Open opens the active inner transport and returns one receive function.
func (b *SwitchBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.recv != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	r := newReceiver(&b.pool)
	actual, err := b.inner.Open(port, r)
	if err != nil {
		r.close()
		return nil, 0, err
	}
	b.recv = r
	b.port = actual
	return []conn.ReceiveFunc{r.receive}, actual, nil
}

// Close closes the inner transport and ends the receive functions with
// net.ErrClosed. Closing a closed bind is a no-op.
func (b *SwitchBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.recv == nil {
		return nil
	}
	// Unblock transport readers waiting in Deliver before waiting for them.
	r := b.recv
	b.recv = nil
	r.close()
	return b.inner.Close()
}

// SetMark is a no-op on Apple platforms.
func (*SwitchBind) SetMark(uint32) error { return nil }

// Send routes bufs to the active inner transport.
func (b *SwitchBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(*Endpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.recv == nil {
		return net.ErrClosed
	}
	var first error
	for _, buf := range bufs {
		if err := b.inner.Send(buf, e.AddrPort); err != nil {
			if errors.Is(err, ErrNotReady) {
				b.drops.Add(1)
				continue
			}
			if first == nil {
				first = err
			}
		}
	}
	return first
}

// ParseEndpoint parses a literal ip:port into the neutral endpoint type.
func (*SwitchBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &Endpoint{AddrPort: netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())}, nil
}

// BatchSize returns the constant BatchSize.
func (*SwitchBind) BatchSize() int { return BatchSize }

// Inner returns the active inner transport.
func (b *SwitchBind) Inner() Inner {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.inner
}

// Drops returns the number of datagrams dropped because the inner transport
// was not ready (a carrier reconnecting).
func (b *SwitchBind) Drops() uint64 { return b.drops.Load() }

// Swap replaces the inner transport under SwitchBind's mutex without ending
// the receive functions. If the bind is open, the old transport is closed and
// next is opened on the same receive generation and port; if opening next
// fails, the old transport is reopened and the error returned. Used for
// carrier transports; UDP rebinds go through device.BindUpdate instead.
func (b *SwitchBind) Swap(next Inner) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	prev := b.inner
	if b.recv == nil {
		b.inner = next
		return nil
	}
	_ = prev.Close()
	if _, err := next.Open(b.port, b.recv); err != nil {
		if _, rerr := prev.Open(b.port, b.recv); rerr != nil {
			return errors.Join(err, rerr)
		}
		return err
	}
	b.inner = next
	return nil
}

// ErrNotReady is returned by an inner transport's Send while it cannot carry
// traffic (for example a carrier reconnecting). SwitchBind counts the datagram
// as dropped and reports success, as WireGuard tolerates loss.
var ErrNotReady = errors.New("transport not ready")
