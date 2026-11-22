/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2026 Magrathean UK.
 *
 * The listen sequence (IPv4 first, IPv6 on the same port, retry on a port
 * clash when the port was chosen by the kernel, IPv6-only or IPv4-only hosts
 * tolerated) and the socket buffer sizes follow conn.StdNetBind.Open and
 * conn/controlfns_unix.go in golang.zx2c4.com/wireguard (MIT).
 */

package transport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const socketBufferSize = 7 << 20

// UDP is the udp inner transport: one unconnected socket per family, each
// bound to the underlay interface with IP_BOUND_IF / IPV6_BOUND_IF when an
// interface index is set (0 = unbound).
type UDP struct {
	mu     sync.Mutex
	ifV4   uint32
	ifV6   uint32
	c4, c6 *net.UDPConn
	wg     sync.WaitGroup
}

var _ Inner = (*UDP)(nil)

// NewUDP returns a closed UDP transport bound to the given interface indexes.
func NewUDP(ifindexV4, ifindexV6 uint32) *UDP {
	return &UDP{ifV4: ifindexV4, ifV6: ifindexV6}
}

// Kind returns "udp".
func (*UDP) Kind() string { return "udp" }

// SetInterfaces changes the interface indexes; they apply from the next Open.
func (u *UDP) SetInterfaces(ifindexV4, ifindexV6 uint32) {
	u.mu.Lock()
	u.ifV4, u.ifV6 = ifindexV4, ifindexV6
	u.mu.Unlock()
}

// Interfaces returns the interface indexes the next Open uses.
func (u *UDP) Interfaces() (v4, v6 uint32) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.ifV4, u.ifV6
}

// LocalPorts returns the bound local ports (0 when a family is not open).
func (u *UDP) LocalPorts() (v4, v6 uint16) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.c4 != nil {
		v4 = uint16(u.c4.LocalAddr().(*net.UDPAddr).Port)
	}
	if u.c6 != nil {
		v6 = uint16(u.c6.LocalAddr().(*net.UDPAddr).Port)
	}
	return v4, v6
}

func boundListenConfig(ifindex uint32) *net.ListenConfig {
	return &net.ListenConfig{
		Control: func(network, _ string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, socketBufferSize)
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, socketBufferSize)
				if network == "udp6" {
					if opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); opErr != nil {
						return
					}
				}
				if ifindex == 0 {
					return
				}
				if network == "udp6" {
					opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, int(ifindex))
				} else {
					opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, int(ifindex))
				}
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}
}

func listenUDP(network string, port int, ifindex uint32) (*net.UDPConn, int, error) {
	pc, err := boundListenConfig(ifindex).ListenPacket(context.Background(), network, ":"+strconv.Itoa(port))
	if err != nil {
		return nil, 0, err
	}
	c := pc.(*net.UDPConn)
	return c, c.LocalAddr().(*net.UDPAddr).Port, nil
}

func unsupportedFamily(err error) bool {
	return errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT) ||
		errors.Is(err, syscall.EADDRNOTAVAIL)
}

// Open binds both families and starts one reader per socket. Binding a local
// socket does not touch the network.
func (u *UDP) Open(uport uint16, r *Receiver) (uint16, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.c4 != nil || u.c6 != nil {
		return 0, errors.New("udp transport already open")
	}
	var (
		c4, c6 *net.UDPConn
		port   int
		err    error
	)
	for tries := 0; ; tries++ {
		c4, port, err = listenUDP("udp4", int(uport), u.ifV4)
		if err != nil && !unsupportedFamily(err) {
			return 0, err
		}
		if c4 == nil {
			port = int(uport)
		}
		c6, port, err = listenUDP("udp6", port, u.ifV6)
		if uport == 0 && c4 != nil && errors.Is(err, syscall.EADDRINUSE) && tries < 100 {
			c4.Close()
			continue
		}
		if err != nil && !unsupportedFamily(err) {
			if c4 != nil {
				c4.Close()
			}
			return 0, err
		}
		if c6 == nil && c4 != nil {
			port = c4.LocalAddr().(*net.UDPAddr).Port
		}
		break
	}
	if c4 == nil && c6 == nil {
		return 0, syscall.EAFNOSUPPORT
	}
	u.c4, u.c6 = c4, c6
	for _, c := range []*net.UDPConn{c4, c6} {
		if c == nil {
			continue
		}
		u.wg.Add(1)
		go u.read(c, r)
	}
	return uint16(port), nil
}

func (u *UDP) read(c *net.UDPConn, r *Receiver) {
	defer u.wg.Done()
	for {
		p := r.Get()
		n, from, err := c.ReadFromUDPAddrPort(p.Buf[:])
		if err != nil {
			r.Put(p)
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Transient socket error: keep the reader alive, without spinning.
			select {
			case <-r.Done():
				return
			case <-time.After(10 * time.Millisecond):
			}
			continue
		}
		p.N = n
		p.From = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		if !r.Deliver(p) {
			return
		}
	}
}

// Send writes b to ep on the socket of ep's family.
func (u *UDP) Send(b []byte, ep netip.AddrPort) error {
	u.mu.Lock()
	c := u.c6
	if ep.Addr().Is4() {
		c = u.c4
	}
	u.mu.Unlock()
	if c == nil {
		if u.closed() {
			return net.ErrClosed
		}
		return syscall.EAFNOSUPPORT
	}
	_, err := c.WriteToUDPAddrPort(b, ep)
	return err
}

func (u *UDP) closed() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.c4 == nil && u.c6 == nil
}

// Close closes both sockets and waits for the readers to stop.
func (u *UDP) Close() error {
	u.mu.Lock()
	var err error
	if u.c4 != nil {
		err = u.c4.Close()
		u.c4 = nil
	}
	if u.c6 != nil {
		err = errors.Join(err, u.c6.Close())
		u.c6 = nil
	}
	u.mu.Unlock()
	u.wg.Wait()
	return err
}
