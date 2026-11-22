// SPDX-License-Identifier: MIT

package engine

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

func newFakeEngine(t *testing.T, o options, rec *recorder) *Engine {
	t.Helper()
	p := Params{TUN: newFakeTUN()}
	if rec != nil {
		p.Log, p.Event = rec.log, rec.event
	}
	e, err := newEngine(p, o)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func minimalDoc(t *testing.T, extra string) []byte {
	k := newKeyPair(t)
	peer := newKeyPair(t)
	return []byte(fmt.Sprintf("private_key=%s\nlisten_port=0\nreplace_peers=true\npublic_key=%s\nallowed_ip=10.98.0.2/32\n%s",
		hexKey(k.priv), hexKey(peer.pub), extra))
}

// RT-11: a failing IpcSet with no previous configuration closes the device
// and leaks nothing.
func TestSetConfigFailureWithoutPreviousClosesDevice(t *testing.T) {
	base := goroutines()
	rec := newRecorder()
	e := newFakeEngine(t, defaultOptions(), rec)
	if err := e.SetConfig(minimalDoc(t, "allowed_ip=1.2.3.4/40\n")); CodeOf(err) != EDEVICECLOSED {
		t.Fatalf("set_config = %v, want EDEVICECLOSED", err)
	}
	if !e.failed.Load() {
		t.Fatal("device not closed after a failed first configuration")
	}
	for name, op := range map[string]func() error{
		"up": e.Up, "force_handshake": e.ForceHandshake,
		"set_config": func() error { return e.SetConfig(minimalDoc(t, "")) },
		"bump":       func() error { return e.BumpSockets(0, 0) },
	} {
		if err := op(); CodeOf(err) != EDEVICECLOSED {
			t.Errorf("%s after failure = %v, want EDEVICECLOSED", name, err)
		}
	}
	for range 2 {
		if e.Down() != nil {
			t.Fatal("closed device Down must be idempotent")
		}
	}
	select {
	case <-e.dev.Wait():
	case <-time.After(time.Second):
		t.Fatal("device not closed")
	}
	e.Close()
	waitFor(t, time.Second, "deviceClosed event", func() bool { return len(rec.eventsOf(EventEngine)) > 0 })
	settleGoroutines(t, base)
}

// RT-12: a socket bump stuck in its retry loop is cancelled by Close within
// 100 ms.
func TestBumpSocketsCancelledByClose(t *testing.T) {
	base := goroutines()
	rec := newRecorder()
	e := newFakeEngine(t, defaultOptions(), rec)
	if err := e.SetConfig(minimalDoc(t, "")); err != nil {
		t.Fatal(err)
	}
	if err := e.Up(); err != nil {
		t.Fatal(err)
	}
	// No interface has this index: IP_BOUND_IF fails, so every attempt fails
	// and the bump waits BumpInterval between attempts.
	if err := e.BumpSockets(999999, 999999); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, "first failed bump attempt", func() bool { return rec.count("bump_sockets attempt 1") > 0 })
	start := time.Now()
	e.Close()
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("Close took %v with a bump in flight, want < 100ms", d)
	} else {
		t.Logf("Close with a bump in flight took %v", d)
	}
	settleGoroutines(t, base)
}

func TestBumpSocketsCancelsPreviousAttempt(t *testing.T) {
	rec := newRecorder()
	e := newFakeEngine(t, defaultOptions(), rec)
	defer e.Close()
	if err := e.SetConfig(minimalDoc(t, "")); err != nil {
		t.Fatal(err)
	}
	if err := e.Up(); err != nil {
		t.Fatal(err)
	}
	if err := e.BumpSockets(999999, 999999); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, "first failed attempt", func() bool { return rec.count("bump_sockets attempt 1") > 0 })
	if err := e.BumpSockets(0, 0); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, "second bump to succeed", func() bool {
		for _, ev := range rec.eventsOf(EventEngine) {
			if ev["event"] == "socketsBumped" && ev["ok"] == true && ev["attempts"] == float64(1) {
				return true
			}
		}
		return false
	})
	time.Sleep(700 * time.Millisecond)
	if n := rec.count("bump_sockets attempt 2"); n != 0 {
		t.Fatalf("cancelled bump kept retrying (%d more attempts)", n)
	}
}

func TestCloseIsIdempotentAndEndsOperations(t *testing.T) {
	e := newFakeEngine(t, defaultOptions(), newRecorder())
	e.Close()
	e.Close()
	e.CloseAsync()
	<-e.Done()
	for name, op := range map[string]func() error{
		"up": e.Up, "set_config": func() error { return e.SetConfig(minimalDoc(t, "")) },
		"stats": func() error { _, err := e.PublicStatsJSON(); return err },
	} {
		if err := op(); CodeOf(err) != EHANDLE {
			t.Errorf("%s after close = %v, want EHANDLE", name, err)
		}
	}
}

// RT-07: the statistics of a configured engine never contain key material.
func TestStatsOfLiveEngineHaveNoSecrets(t *testing.T) {
	e := newFakeEngine(t, defaultOptions(), nil)
	defer e.Close()
	k, peer := newKeyPair(t), newKeyPair(t)
	psk := newKeyPair(t).priv
	doc := fmt.Sprintf("private_key=%s\nlisten_port=0\nreplace_peers=true\npublic_key=%s\npreshared_key=%s\nendpoint=127.0.0.1:51820\npersistent_keepalive_interval=25\nallowed_ip=10.98.0.2/32\n",
		hexKey(k.priv), hexKey(peer.pub), hexKey(psk))
	if err := e.SetConfig([]byte(doc)); err != nil {
		t.Fatal(err)
	}
	b, err := e.PublicStatsJSON()
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecrets(t, b, [][32]byte{k.priv, psk})
	if !strings.Contains(string(b), `"persistent_keepalive_interval":25`) || !strings.Contains(string(b), `"endpoint":"127.0.0.1:51820"`) {
		t.Fatalf("stats lack expected fields: %s", b)
	}
}

func TestCreateValidatesParams(t *testing.T) {
	for name, p := range map[string]Params{
		"kind 0 with mtu":     {TunKind: TunNEUTun, TunFD: 0, MTU: 1280},
		"kind 0 without fd":   {TunKind: TunNEUTun, TunFD: -1},
		"kind 1 without mtu":  {TunKind: TunPacketFD, TunFD: 0},
		"kind 2 without name": {TunKind: TunCreateUTun, MTU: 1280},
		"unknown kind":        {TunKind: 7},
		"vless transport":     {TUN: newFakeTUN(), TransportJSON: []byte(`{"kind":"vless"}`)},
	} {
		if _, err := New(p); CodeOf(err) != EINVAL {
			t.Errorf("%s: New = %v, want EINVAL", name, err)
		}
	}
}

func TestFullReplaceRequiresRestorableInterface(t *testing.T) {
	e := newFakeEngine(t, defaultOptions(), nil)
	defer e.Close()
	good := minimalDoc(t, "")
	if err := e.SetConfig(good); err != nil {
		t.Fatal(err)
	}
	for _, missing := range []string{"private_key", "listen_port"} {
		var doc []byte
		for _, line := range strings.Split(string(good), "\n") {
			if !strings.HasPrefix(line, missing+"=") {
				doc = append(doc, []byte(line+"\n")...)
			}
		}
		if err := e.SetConfig(doc); CodeOf(err) != EINVAL {
			t.Fatalf("missing %s: want EINVAL", missing)
		}
	}
	before, err := e.sample()
	if err != nil {
		t.Fatal(err)
	}
	bad := append(bytes.Replace(good, []byte("listen_port=0"), []byte("listen_port=51823"), 1), []byte("allowed_ip=1.2.3.4/40\n")...)
	if err := e.SetConfig(bad); CodeOf(err) != ECONFIG {
		t.Fatal("expected rollback")
	}
	after, err := e.sample()
	if err != nil {
		t.Fatal(err)
	}
	if after.ListenPort != before.ListenPort {
		t.Fatal("rollback changed listen port")
	}
}

func TestBumpRetryPreservesSelectedPort(t *testing.T) {
	rec := newRecorder()
	e := newFakeEngine(t, defaultOptions(), rec)
	defer e.Close()
	if err := e.SetConfig(minimalDoc(t, "")); err != nil {
		t.Fatal(err)
	}
	if err := e.Up(); err != nil {
		t.Fatal(err)
	}
	before, err := e.sample()
	if err != nil {
		t.Fatal(err)
	}
	if before.ListenPort == 0 {
		t.Fatal("no selected port")
	}
	if err := e.BumpSockets(999999, 999999); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, "failed bump", func() bool { return rec.count("bump_sockets attempt 1") > 0 })
	// Recover during the same retry sequence, after upstream has cleared its port.
	e.udp.SetInterfaces(0, 0)
	waitFor(t, 2*time.Second, "retry success", func() bool {
		for _, ev := range rec.eventsOf(EventEngine) {
			if ev["event"] == "socketsBumped" && ev["ok"] == true {
				return true
			}
		}
		return false
	})
	after, err := e.sample()
	if err != nil {
		t.Fatal(err)
	}
	if after.ListenPort != before.ListenPort {
		t.Fatalf("port changed: %d -> %d", before.ListenPort, after.ListenPort)
	}
}
