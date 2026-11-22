// SPDX-License-Identifier: MIT

//go:build wgextest

package testsupport

import (
	"sync"
	"sync/atomic"

	etun "github.com/magrathean-uk/wgex/engine/tun"
)

type echo struct {
	dev   *etun.PacketFD
	count atomic.Int64
	done  chan struct{}
}

var echoes = struct {
	sync.Mutex
	next int64
	m    map[int64]*echo
}{m: map[int64]*echo{}}

// StartEcho wraps a duplicate of fd as a packet-descriptor tun and writes
// every packet it reads back to the descriptor.
func StartEcho(fd, mtu int) (int64, error) {
	dev, err := etun.NewPacketFD(fd, mtu)
	if err != nil {
		return 0, err
	}
	e := &echo{dev: dev, done: make(chan struct{})}
	go func() {
		defer close(e.done)
		buf := make([]byte, mtu)
		bufs, sizes := [][]byte{buf}, []int{0}
		for {
			n, err := dev.Read(bufs, sizes, 0)
			if err != nil {
				return
			}
			if n == 1 {
				if _, err := dev.Write([][]byte{buf[:sizes[0]]}, 0); err != nil {
					return
				}
				e.count.Add(1)
			}
		}
	}()
	echoes.Lock()
	echoes.next++
	h := echoes.next
	echoes.m[h] = e
	echoes.Unlock()
	return h, nil
}

// StopEcho stops an echo and returns how many packets it echoed, or -1.
func StopEcho(h int64) int64 {
	echoes.Lock()
	e, ok := echoes.m[h]
	delete(echoes.m, h)
	echoes.Unlock()
	if !ok {
		return -1
	}
	_ = e.dev.Close()
	<-e.done
	return e.count.Load()
}
