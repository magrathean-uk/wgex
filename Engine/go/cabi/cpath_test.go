// SPDX-License-Identifier: MIT

//go:build wgexcabitest

package cabi

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/magrathean-uk/wgex/engine/engine"
)

func socketpair(t *testing.T) [2]int {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	return fds
}

// The C path: wgex_create_params decoding, tun_kind 1 over a socketpair, C
// callbacks through the trampolines.
func TestCParamsPacketFDAndCallbacks(t *testing.T) {
	fds := socketpair(t)
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	hn := NewHarness(false)
	p := hn.Params(int32(engine.TunPacketFD), int32(fds[0]), 1420, `{"kind":"udp"}`)
	defer FreeC(p)
	h := Create(p)
	if h <= 0 {
		t.Fatalf("create = %d", h)
	}
	if c := SetConfig(h, configDoc(t)); c != 0 {
		t.Fatal(c)
	}
	if c := SetTransport(h, []byte(`{"kind":"udp"}`)); c != 0 {
		t.Fatal(c)
	}
	deadline := time.Now().Add(2 * time.Second)
	for hn.Logs() == 0 || hn.Events() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("callbacks: %d logs, %d events", hn.Logs(), hn.Events())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if c := Destroy(h); c != 0 {
		t.Fatal(c)
	}
	logs, events := hn.Logs(), hn.Events()
	time.Sleep(50 * time.Millisecond)
	if hn.Logs() != logs || hn.Events() != events {
		t.Fatal("callbacks after destroy returned")
	}
	hn.Free()
}

// P1-19: tun_kind 0 with a non-zero mtu and bad parameters return EINVAL.
func TestCParamsValidation(t *testing.T) {
	fds := socketpair(t)
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	hn := NewHarness(false)
	defer hn.Free()
	for name, p := range map[string][4]any{
		"kind 0 with mtu":    {int32(engine.TunNEUTun), int32(fds[0]), int32(1280), ""},
		"kind 1 without mtu": {int32(engine.TunPacketFD), int32(fds[0]), int32(0), ""},
		"vless":              {int32(engine.TunPacketFD), int32(fds[0]), int32(1280), `{"kind":"vless"}`},
		"bad json":           {int32(engine.TunPacketFD), int32(fds[0]), int32(1280), `{`},
		"unknown kind":       {int32(9), int32(fds[0]), int32(1280), ""},
	} {
		cp := hn.Params(p[0].(int32), p[1].(int32), p[2].(int32), p[3].(string))
		if h := Create(cp); h != int64(engine.EINVAL) {
			t.Errorf("%s: create = %d, want EINVAL", name, h)
			if h > 0 {
				Destroy(h)
			}
		}
		FreeC(cp)
	}
	if h := Create(nil); h != int64(engine.EINVAL) {
		t.Errorf("create(NULL) = %d", h)
	}
	if c := ConfigureProcess(nil); c != int32(engine.EINVAL) {
		t.Errorf("configure_process(NULL) = %d", c)
	}
	pp := ProcessParamsC(0, 0, 7)
	defer FreeC(pp)
	if c := ConfigureProcess(pp); c != int32(engine.EINVAL) {
		t.Errorf("configure_process(profile 7) = %d", c)
	}
}

// wgex_destroy called from inside a C event callback returns at once and
// the engine is torn down after the callback returns.
func TestCDestroyFromInsideCallback(t *testing.T) {
	fds := socketpair(t)
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	hn := NewHarness(true)
	p := hn.Params(int32(engine.TunPacketFD), int32(fds[0]), 1420, "")
	defer FreeC(p)
	h := Create(p)
	if h <= 0 {
		t.Fatal(h)
	}
	hn.SetHandle(h)
	if c := SetConfig(h, configDoc(t)); c != 0 {
		t.Fatal(c)
	}
	if c := SetTransport(h, []byte(`{"kind":"udp"}`)); c != 0 { // emits an event
		t.Fatal(c)
	}
	deadline := time.Now().Add(5 * time.Second)
	for hn.DestroyRC() == 1 {
		if time.Now().After(deadline) {
			t.Fatal("in-callback destroy did not return (deadlock)")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if rc := hn.DestroyRC(); rc != 0 {
		t.Fatalf("in-callback destroy = %d", rc)
	}
	if c := Destroy(h); c != 0 { // waits for the asynchronous teardown
		t.Fatalf("second destroy = %d", c)
	}
	if live, closing := Counts(); live != 0 || closing != 0 {
		t.Fatalf("registry %d/%d", live, closing)
	}
	hn.Free()
}

// RT-10 over the C path with packet-descriptor tuns: descriptors and
// goroutines return to the baseline.
func TestCConcurrentLifecycle(t *testing.T) {
	const workers, cycles = 8, 400
	baseG, baseFD := runtime.NumGoroutine(), openFDs(t)
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hn := NewHarness(false)
			defer hn.Free()
			for i := w; i < cycles; i += workers {
				fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
				if err != nil {
					errs <- err
					return
				}
				p := hn.Params(int32(engine.TunPacketFD), int32(fds[0]), 1420, "")
				h := Create(p)
				FreeC(p)
				if h <= 0 {
					errs <- fmt.Errorf("create %d", h)
					return
				}
				if c := SetConfig(h, configDoc(t)); c != 0 {
					errs <- fmt.Errorf("set_config %d", c)
					return
				}
				if i%2 == 0 && Up(h) != 0 {
					errs <- fmt.Errorf("up")
					return
				}
				if c := Destroy(h); c != 0 {
					errs <- fmt.Errorf("destroy %d", c)
					return
				}
				unix.Close(fds[0])
				unix.Close(fds[1])
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	settle(t, "goroutines", baseG, runtime.NumGoroutine)
	settle(t, "descriptors", baseFD, func() int { return openFDs(t) })
	t.Logf("%d C-path cycles: goroutines %d -> %d, descriptors %d -> %d", cycles, baseG, runtime.NumGoroutine(), baseFD, openFDs(t))
}
