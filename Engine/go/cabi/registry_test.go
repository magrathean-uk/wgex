// SPDX-License-Identifier: MIT

package cabi

import (
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/magrathean-uk/wgex/engine/engine"
	"github.com/magrathean-uk/wgex/engine/internal/testkeys"
)

type fakeTUN struct {
	events chan wgtun.Event
	closed chan struct{}
	once   sync.Once
}

func newFakeTUN() *fakeTUN {
	return &fakeTUN{events: make(chan wgtun.Event), closed: make(chan struct{})}
}
func (t *fakeTUN) File() *os.File { return nil }
func (t *fakeTUN) Read([][]byte, []int, int) (int, error) {
	<-t.closed
	return 0, os.ErrClosed
}
func (t *fakeTUN) Write(b [][]byte, _ int) (int, error) { return len(b), nil }
func (t *fakeTUN) MTU() (int, error)                    { return 1420, nil }
func (t *fakeTUN) Name() (string, error)                { return "fake0", nil }
func (t *fakeTUN) Events() <-chan wgtun.Event           { return t.events }
func (t *fakeTUN) BatchSize() int                       { return 1 }
func (t *fakeTUN) Close() error {
	t.once.Do(func() { close(t.closed); close(t.events) })
	return nil
}

func hexKey(t testing.TB) string {
	t.Helper()
	priv, _, err := testkeys.Load(0)
	if err != nil {
		t.Fatal("cannot load repository fixture identity")
	}
	return hex.EncodeToString(priv[:])
}

func configDoc(t testing.TB) []byte {
	return []byte(fmt.Sprintf("private_key=%s\nlisten_port=0\nreplace_peers=true\npublic_key=%s\nallowed_ip=10.96.0.2/32\nendpoint=127.0.0.1:9\n",
		hexKey(t), hexKey(t)))
}

func openFDs(t testing.TB) int {
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func settle(t *testing.T, what string, want int, get func() int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := get()
		if got <= want {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			t.Fatalf("%s: %d, want <= %d\n%s", what, got, want, buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// RT-10: concurrent create / set_config / up / destroy from 8 goroutines,
// 1000 cycles in all; goroutine and descriptor counts return to the baseline.
func TestConcurrentLifecycleRT10(t *testing.T) {
	const workers, cycles = 8, 1000
	baseG, baseFD := runtime.NumGoroutine(), openFDs(t)
	var logs, events atomic.Int64
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := w; i < cycles; i += workers {
				h := CreateGo(engine.Params{LogLevel: engine.LogLevelDebug,
					TUN:   newFakeTUN(),
					Log:   func(int32, []byte) { logs.Add(1) },
					Event: func(engine.EventKind, []byte) { events.Add(1) },
				})
				if h <= 0 {
					errs <- fmt.Errorf("create: %d", h)
					return
				}
				if c := SetConfig(h, configDoc(t)); c != 0 {
					errs <- fmt.Errorf("set_config: %d", c)
					return
				}
				if i%2 == 0 {
					if c := Up(h); c != 0 {
						errs <- fmt.Errorf("up: %d", c)
						return
					}
				}
				if i%3 == 0 {
					_ = PublicStatsJSON(h)
					_ = BumpSockets(h, 0, 0)
				}
				if c := Destroy(h); c != 0 {
					errs <- fmt.Errorf("destroy: %d", c)
					return
				}
				if c := Destroy(h); c != 0 {
					errs <- fmt.Errorf("second destroy: %d", c)
					return
				}
				if c := Up(h); c != int32(engine.EHANDLE) {
					errs <- fmt.Errorf("up after destroy: %d", c)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if live, closing := Counts(); live != 0 || closing != 0 {
		t.Fatalf("registry holds %d live and %d closing engines", live, closing)
	}
	settle(t, "goroutines", baseG, runtime.NumGoroutine)
	settle(t, "open descriptors", baseFD, func() int { return openFDs(t) })
	t.Logf("%d cycles: goroutines %d -> %d, descriptors %d -> %d, %d log lines, %d events",
		cycles, baseG, runtime.NumGoroutine(), baseFD, openFDs(t), logs.Load(), events.Load())
}

// wgex_destroy returns only after the callback in flight has returned, and no
// callback starts afterwards.
func TestDestroyDrainsCallbacks(t *testing.T) {
	var inFlight, after atomic.Int32
	var destroyed atomic.Bool
	entered := make(chan struct{}, 1)
	h := CreateGo(engine.Params{LogLevel: engine.LogLevelDebug,
		TUN: newFakeTUN(),
		Log: func(int32, []byte) {
			if destroyed.Load() {
				after.Add(1)
			}
			inFlight.Add(1)
			select {
			case entered <- struct{}{}:
			default:
			}
			time.Sleep(30 * time.Millisecond)
			inFlight.Add(-1)
		},
	})
	if h <= 0 {
		t.Fatal(h)
	}
	if c := SetConfig(h, configDoc(t)); c != 0 {
		t.Fatal(c)
	}
	<-entered
	if c := Destroy(h); c != 0 {
		t.Fatal(c)
	}
	destroyed.Store(true)
	if n := inFlight.Load(); n != 0 {
		t.Fatalf("%d callbacks in flight after destroy returned", n)
	}
	time.Sleep(100 * time.Millisecond)
	if n := after.Load(); n != 0 {
		t.Fatalf("%d callbacks after destroy returned", n)
	}
}

// Destroy called from inside one of the engine's own callbacks must not
// deadlock; it returns at once and the teardown completes afterwards.
func TestDestroyFromInsideCallback(t *testing.T) {
	base := runtime.NumGoroutine()
	var h atomic.Int64
	result := make(chan int32, 1)
	var once sync.Once
	handle := CreateGo(engine.Params{LogLevel: engine.LogLevelDebug,
		TUN: newFakeTUN(),
		Event: func(kind engine.EventKind, _ []byte) {
			once.Do(func() {
				done := make(chan int32)
				go func() { done <- 0 }() // the destroy below must not need other goroutines
				<-done
				result <- Destroy(h.Load())
			})
		},
		Log: func(int32, []byte) {},
	})
	if handle <= 0 {
		t.Fatal(handle)
	}
	h.Store(handle)
	if c := SetTransport(handle, []byte(`{"kind":"udp"}`)); c != 0 {
		t.Fatal(c)
	}
	select {
	case c := <-result:
		if c != 0 {
			t.Fatalf("destroy from callback = %d", c)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("destroy from inside a callback deadlocked")
	}
	// A second destroy from outside waits for the teardown and succeeds.
	if c := Destroy(handle); c != 0 {
		t.Fatalf("destroy after in-callback destroy = %d", c)
	}
	settle(t, "closing engines", 0, func() int { _, c := Counts(); return c })
	settle(t, "goroutines", base, runtime.NumGoroutine)
}

func TestUnknownHandles(t *testing.T) {
	for _, h := range []int64{0, -1, 1 << 40} {
		if c := Destroy(h); c != int32(engine.EHANDLE) {
			t.Errorf("destroy(%d) = %d", h, c)
		}
		if c := Up(h); c != int32(engine.EHANDLE) {
			t.Errorf("up(%d) = %d", h, c)
		}
		if PublicStatsJSON(h) != nil || TunName(h) != nil {
			t.Errorf("stats or name for handle %d", h)
		}
	}
	h := CreateGo(engine.Params{LogLevel: engine.LogLevelDebug, TUN: newFakeTUN()})
	if name := TunName(h); name == nil {
		t.Fatal("no tun name")
	}
	if c := SetConfig(h, nil); c != int32(engine.EINVAL) {
		t.Fatalf("empty set_config = %d", c)
	}
	if c := BumpSockets(h, -1, 0); c != int32(engine.EINVAL) {
		t.Fatalf("negative ifindex = %d", c)
	}
	Destroy(h)
	if TunName(h) != nil {
		t.Fatal("tun name after destroy")
	}
}

func TestConfigureProcess(t *testing.T) {
	reg.mu.Lock()
	savedCreated, savedSet, savedArgs := reg.created, reg.procSet, reg.procArgs
	reg.mu.Unlock()
	defer func() {
		reg.mu.Lock()
		reg.created, reg.procSet, reg.procArgs = savedCreated, savedSet, savedArgs
		reg.mu.Unlock()
		debug.SetGCPercent(100)
		debug.SetMemoryLimit(1<<63 - 1)
	}()
	reg.mu.Lock()
	reg.created, reg.procSet = false, false
	reg.mu.Unlock()

	p := engine.ProcessParams{MemoryLimitBytes: 1 << 40, GCPercent: 100, QueueProfile: engine.QueueProfileConstrained}
	if c := ConfigureProcessParams(engine.ProcessParams{QueueProfile: 9}); c != int32(engine.EINVAL) {
		t.Fatalf("invalid = %d", c)
	}
	if c := ConfigureProcessParams(p); c != 0 {
		t.Fatalf("first = %d", c)
	}
	if got := debug.SetMemoryLimit(-1); got != 1<<40 {
		t.Fatalf("memory limit %d", got)
	}
	if c := ConfigureProcessParams(p); c != 0 {
		t.Fatalf("identical repeat = %d", c)
	}
	q := p
	q.GCPercent = 50
	if c := ConfigureProcessParams(q); c != int32(engine.ESTATE) {
		t.Fatalf("different repeat = %d", c)
	}

	reg.mu.Lock()
	reg.procSet = false
	reg.mu.Unlock()
	h := CreateGo(engine.Params{LogLevel: engine.LogLevelDebug, TUN: newFakeTUN()})
	defer Destroy(h)
	if c := ConfigureProcessParams(p); c != int32(engine.ESTATE) {
		t.Fatalf("after create = %d", c)
	}
}

// Queued logs, events and teardown logs must never escape an in-callback destroy.
func TestVerifyNoCallbackAfterInCallbackDestroy(t *testing.T) {
	var handle atomic.Int64
	var returned atomic.Bool
	var late atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	result := make(chan int32, 1)
	var once sync.Once
	callback := func() {
		if returned.Load() {
			late.Add(1)
			return
		}
		once.Do(func() {
			close(started)
			<-release
			result <- Destroy(handle.Load())
			returned.Store(true)
		})
	}
	h := CreateGo(engine.Params{LogLevel: engine.LogLevelDebug, TUN: newFakeTUN(), Log: func(int32, []byte) { callback() }, Event: func(engine.EventKind, []byte) { callback() }})
	if h <= 0 {
		t.Fatal("create failed")
	}
	handle.Store(h)
	e, ok := Lookup(h)
	if !ok {
		t.Fatal("lookup failed")
	}
	<-started
	if c := SetConfig(h, configDoc(t)); c != 0 {
		t.Fatal("set config failed")
	}
	close(release)
	if c := <-result; c != 0 {
		t.Fatal("destroy failed")
	}
	select {
	case <-e.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("teardown timed out")
	}
	if n := late.Load(); n != 0 {
		t.Fatalf("%d callbacks after destroy returned", n)
	}
}

func TestCallbackDestroyWithConcurrentClose(t *testing.T) {
	var handle atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	callbackDone := make(chan int32, 1)
	var once sync.Once
	h := CreateGo(engine.Params{LogLevel: engine.LogLevelDebug, TUN: newFakeTUN(), Log: func(int32, []byte) {
		once.Do(func() { close(started); <-release; callbackDone <- Destroy(handle.Load()) })
	}})
	if h <= 0 {
		t.Fatal("create failed")
	}
	handle.Store(h)
	<-started
	destroyDone := make(chan int32, 1)
	go func() { destroyDone <- Destroy(h) }()
	deadline := time.Now().Add(time.Second)
	for {
		if _, live := Lookup(h); !live {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("destroy did not begin")
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	for _, done := range []chan int32{callbackDone, destroyDone} {
		select {
		case result := <-done:
			if result != 0 {
				t.Fatal("destroy failed")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("concurrent destroy deadlocked")
		}
	}
}
