// SPDX-License-Identifier: MIT

package engine

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	wgtun "golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/magrathean-uk/wgex/engine/internal/testkeys"
)

// fakeTUN is an in-memory tun.Device: reads block until Close.
type fakeTUN struct {
	in     chan []byte
	events chan wgtun.Event
	closed chan struct{}
	once   sync.Once
}

func newFakeTUN() *fakeTUN {
	return &fakeTUN{in: make(chan []byte), events: make(chan wgtun.Event), closed: make(chan struct{})}
}

func (t *fakeTUN) File() *os.File { return nil }
func (t *fakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case p := <-t.in:
		sizes[0] = copy(bufs[0][offset:], p)
		return 1, nil
	case <-t.closed:
		return 0, os.ErrClosed
	}
}
func (t *fakeTUN) Write(bufs [][]byte, _ int) (int, error) { return len(bufs), nil }
func (t *fakeTUN) MTU() (int, error)                       { return 1420, nil }
func (t *fakeTUN) Name() (string, error)                   { return "fake", nil }
func (t *fakeTUN) Events() <-chan wgtun.Event              { return t.events }
func (t *fakeTUN) BatchSize() int                          { return 1 }
func (t *fakeTUN) Close() error {
	t.once.Do(func() { close(t.closed); close(t.events) })
	return nil
}

type keyPair struct{ priv, pub [32]byte }

var fixtureSequence atomic.Uint32

func newKeyPair(t testing.TB) keyPair {
	t.Helper()
	priv, pub, err := testkeys.Load(int(fixtureSequence.Add(1) % 3))
	if err != nil {
		t.Fatal("cannot load repository fixture identity")
	}
	return keyPair{priv: priv, pub: pub}
}

func hexKey(k [32]byte) string { return hex.EncodeToString(k[:]) }

// recorder captures log lines and events.
type recorder struct {
	mu     sync.Mutex
	logs   []string
	events []recordedEvent
	cond   chan struct{}
}

type recordedEvent struct {
	kind EventKind
	data map[string]any
}

func newRecorder() *recorder { return &recorder{cond: make(chan struct{}, 1)} }

func (r *recorder) poke() {
	select {
	case r.cond <- struct{}{}:
	default:
	}
}

func (r *recorder) log(_ int32, msg []byte) {
	r.mu.Lock()
	r.logs = append(r.logs, string(msg))
	r.mu.Unlock()
	r.poke()
}

func (r *recorder) event(kind EventKind, data []byte) {
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	r.mu.Lock()
	r.events = append(r.events, recordedEvent{kind, m})
	r.mu.Unlock()
	r.poke()
}

func (r *recorder) count(substr string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, l := range r.logs {
		if strings.Contains(l, substr) {
			n++
		}
	}
	return n
}

func (r *recorder) eventsOf(kind EventKind) []map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []map[string]any
	for _, e := range r.events {
		if e.kind == kind {
			out = append(out, e.data)
		}
	}
	return out
}

// waitFor polls cond until it holds or the timeout expires.
func waitFor(t testing.TB, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", timeout, what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func fastOptions() options {
	o := defaultOptions()
	o.healthInterval = 50 * time.Millisecond
	o.rxEvery = 200 * time.Millisecond
	return o
}

// side is one netstack engine of a loopback pair.
type side struct {
	e    *Engine
	net  *netstack.Net
	addr netip.Addr
	key  keyPair
	port uint16
	rec  *recorder
	srv  *http.Server
}

type pair struct{ a, b *side }

func newSide(t *testing.T, o options, addr netip.Addr, quirks bool) *side {
	t.Helper()
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	rec := newRecorder()
	e, err := newEngine(Params{LogLevel: LogLevelDebug, TUN: tdev, Log: rec.log, Event: rec.event, MobileQuirks: quirks}, o)
	if err != nil {
		t.Fatal(err)
	}
	s := &side{e: e, net: tnet, addr: addr, key: newKeyPair(t), rec: rec}
	l, err := tnet.ListenTCPAddrPort(netip.AddrPortFrom(addr, 80))
	if err != nil {
		t.Fatal(err)
	}
	s.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok "+addr.String())
	}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = s.srv.Serve(l) }()
	t.Cleanup(func() {
		_ = s.srv.Close()
		s.e.Close()
	})
	return s
}

func (s *side) doc(peer *side, port uint16, endpoint string, extra string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "private_key=%s\nlisten_port=%d\nreplace_peers=true\n", hexKey(s.key.priv), port)
	fmt.Fprintf(&b, "public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\n", hexKey(peer.key.pub), peer.addr)
	if endpoint != "" {
		fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	}
	b.WriteString(extra)
	return b.Bytes()
}

func (s *side) stats(t testing.TB) PublicStats {
	t.Helper()
	b, err := s.e.PublicStatsJSON()
	if err != nil {
		t.Fatal(err)
	}
	var st PublicStats
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

func loopback(port uint16) string {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port).String()
}

// newPair builds two netstack engines over loopback UDP. endpointForA is the
// endpoint B is configured with for A ("" = A's real port, "none" = none).
func newPair(t *testing.T, o options, endpointForA string) *pair {
	t.Helper()
	p := &pair{
		a: newSide(t, o, netip.MustParseAddr("10.99.0.1"), false),
		b: newSide(t, o, netip.MustParseAddr("10.99.0.2"), false),
	}
	for _, s := range []*side{p.a, p.b} {
		peer := p.b
		if s == p.b {
			peer = p.a
		}
		if err := s.e.SetConfig(s.doc(peer, 0, "", "")); err != nil {
			t.Fatal(err)
		}
		if err := s.e.Up(); err != nil {
			t.Fatal(err)
		}
		s.port = s.stats(t).ListenPort
		if s.port == 0 {
			t.Fatal("no listen port after up")
		}
	}
	if err := p.a.e.SetConfig(p.a.doc(p.b, p.a.port, loopback(p.b.port), "")); err != nil {
		t.Fatal(err)
	}
	epA := loopback(p.a.port)
	switch endpointForA {
	case "":
	case "none":
		epA = ""
	default:
		epA = endpointForA
	}
	if err := p.b.e.SetConfig(p.b.doc(p.a, p.b.port, epA, "")); err != nil {
		t.Fatal(err)
	}
	return p
}

// get performs an HTTP request through from's tunnel to to's server.
func get(from, to *side, timeout time.Duration) error {
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{
		DialContext:       from.net.DialContext,
		DisableKeepAlives: true,
	}}
	resp, err := client.Get("http://" + net.JoinHostPort(to.addr.String(), "80") + "/")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 || string(body) != "ok "+to.addr.String() {
		return fmt.Errorf("unexpected response %d %q", resp.StatusCode, body)
	}
	return nil
}

func mustGet(t *testing.T, from, to *side) {
	t.Helper()
	if err := get(from, to, 10*time.Second); err != nil {
		t.Fatalf("GET %s -> %s: %v", from.addr, to.addr, err)
	}
}

// Log lines wireguard-go writes for handshake messages.
const (
	logSentInit = "Sending handshake initiation"
	logRecvInit = "Received handshake initiation"
)

func goroutines() int { return runtime.NumGoroutine() }

// settleGoroutines waits until the goroutine count drops to at most want.
func settleGoroutines(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		n := goroutines()
		if n <= want {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			t.Fatalf("goroutines: %d, want <= %d\n%s", n, want, buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
