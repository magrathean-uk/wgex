// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var (
	server4  = netip.MustParseAddr("10.77.0.1")
	client4  = netip.MustParseAddr("10.77.0.2")
	client4b = netip.MustParseAddr("10.77.0.3")
)

const eventWaitTimeout = 10 * time.Second

// eventSink collects JSON event lines written by the server.
type eventSink struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	events []map[string]any
}

func (s *eventSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf.Write(p)
	for {
		line, err := s.buf.ReadBytes('\n')
		if err != nil {
			s.buf.Write(line) // keep the partial line
			break
		}
		var m map[string]any
		if json.Unmarshal(line, &m) == nil {
			s.events = append(s.events, m)
		}
	}
	return len(p), nil
}

func (s *eventSink) find(pred func(map[string]any) bool) (map[string]any, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.events {
		if pred(e) {
			return e, true
		}
	}
	return nil, false
}

func (s *eventSink) wait(t *testing.T, d time.Duration, pred func(map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if e, ok := s.find(pred); ok {
			return e
		}
		if !time.Now().Before(deadline) {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestEventSinkWaitChecksAnExpiredDeadline(t *testing.T) {
	sink := &eventSink{events: []map[string]any{{"event": "present"}}}
	if got := sink.wait(t, -time.Second, isEvent("present")); got == nil {
		t.Fatal("wait did not check for an event after the deadline")
	}
	if got := sink.wait(t, -time.Second, isEvent("missing")); got != nil {
		t.Fatalf("wait returned an unexpected event: %v", got)
	}
}

func (s *eventSink) text() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b strings.Builder
	for _, e := range s.events {
		j, _ := json.Marshal(e)
		b.Write(j)
		b.WriteByte('\n')
	}
	return b.String()
}

func isEvent(name string, kv ...string) func(map[string]any) bool {
	return func(e map[string]any) bool {
		if e["event"] != name {
			return false
		}
		for i := 0; i+1 < len(kv); i += 2 {
			if fmt.Sprint(e[kv[i]]) != kv[i+1] {
				return false
			}
		}
		return true
	}
}

func mustKey(t *testing.T) (Key, Key) {
	t.Helper()
	priv, err := generatePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := priv.Public()
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

type testClient struct {
	dev  *device.Device
	tnet *netstack.Net
	pub  Key
}

// handshaked reports whether the client completed a handshake.
func (c *testClient) handshaked() bool {
	text, err := c.dev.IpcGet()
	if err != nil {
		return false
	}
	for _, l := range strings.Split(text, "\n") {
		if v, ok := strings.CutPrefix(l, "last_handshake_time_sec="); ok && v != "0" {
			return true
		}
	}
	return false
}

func (c *testClient) waitHandshake(d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if c.handshaked() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func (c *testClient) httpClient() *http.Client {
	return &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{DialContext: c.tnet.DialContext, DisableKeepAlives: true},
	}
}

// newClient starts an in-process client engine (wireguard-go on its own
// netstack) bound to bindAddr and peered with the server at endpoint.
func newClient(t *testing.T, priv Key, serverPub Key, bindAddr, endpoint netip.AddrPort, tunAddr netip.Addr, keepalive int) *testClient {
	t.Helper()
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{tunAddr}, []netip.Addr{server4}, defaultMTU)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tdev, newAddrBind([]netip.AddrPort{bindAddr}), device.NewLogger(device.LogLevelSilent, ""))
	uapi := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=10.77.0.0/24\n", priv.hex(), serverPub.hex(), endpoint)
	if keepalive > 0 {
		uapi += fmt.Sprintf("persistent_keepalive_interval=%d\n", keepalive)
	}
	if err := dev.IpcSet(uapi); err != nil {
		t.Fatal("client IpcSet failed")
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dev.Close)
	pub, _ := priv.Public()
	return &testClient{dev: dev, tnet: tnet, pub: pub}
}

func startTestServer(t *testing.T, cfg Config) (*Server, *eventSink, Key) {
	t.Helper()
	sink := &eventSink{}
	priv, pub := mustKey(t)
	cfg.PrivateKey = priv
	cfg.Server4 = server4
	cfg.Events = newEvents(sink, true, slog.LevelDebug)
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 50 * time.Millisecond
	}
	srv, err := StartServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	return srv, sink, pub
}

func TestTunnelServices(t *testing.T) {
	t.Parallel()
	cpriv, cpub := mustKey(t)
	// Wildcard listen: exercises the chaos wrapper around conn.NewDefaultBind().
	srv, sink, spub := startTestServer(t, Config{
		Listen:          []netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:0")},
		Peers:           []PeerSpec{{Name: "client-1", PublicKey: cpub, Addrs: []netip.Addr{client4}}},
		CounterInterval: 200 * time.Millisecond,
	})
	c := newClient(t, cpriv, spub, netip.MustParseAddrPort("127.0.0.1:0"),
		netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), srv.Port()), client4, 0)
	hc := c.httpClient()

	get := func(path string) []byte {
		t.Helper()
		resp, err := hc.Get("http://10.77.0.1" + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("GET %s: status %d err %v", path, resp.StatusCode, err)
		}
		return b
	}

	if got := strings.TrimSpace(string(get("/ip"))); got != client4.String() {
		t.Fatalf("/ip = %q, want %s", got, client4)
	}

	body := make([]byte, 256<<10)
	_, _ = rand.Read(body)
	pr, pw := io.Pipe()
	go func() {
		// Stream the upload in chunks to exercise the full-duplex echo.
		for i := 0; i < len(body); i += 16 << 10 {
			if _, err := pw.Write(body[i : i+16<<10]); err != nil {
				return
			}
		}
		pw.Close()
	}()
	resp, err := hc.Post("http://10.77.0.1/echo", "application/octet-stream", pr)
	if err != nil {
		t.Fatal(err)
	}
	echoed, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || !bytes.Equal(echoed, body) {
		t.Fatalf("/echo returned %d bytes (err %v), want identical %d", len(echoed), err, len(body))
	}

	if n := len(get("/big?bytes=1048576")); n != 1048576 {
		t.Fatalf("/big returned %d bytes", n)
	}

	start := time.Now()
	get("/delay?ms=200")
	if el := time.Since(start); el < 200*time.Millisecond {
		t.Fatalf("/delay returned after %v", el)
	}

	addrs, err := c.tnet.LookupHost("foo.test.wgex")
	if err != nil || len(addrs) != 1 || addrs[0] != server4.String() {
		t.Fatalf("LookupHost foo.test.wgex = %v, %v", addrs, err)
	}
	if _, err := c.tnet.LookupHost("example.com"); err == nil {
		t.Fatal("non-test name resolved")
	}

	uc, err := c.tnet.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(server4, tunnelEchoPort))
	if err != nil {
		t.Fatal(err)
	}
	_ = uc.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := uc.Write([]byte("hello udp")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := uc.Read(buf)
	uc.Close()
	if err != nil || string(buf[:n]) != "hello udp" {
		t.Fatalf("UDP echo = %q, %v", buf[:n], err)
	}

	// ICMP echo is answered by the server's gVisor stack itself.
	pc, err := c.tnet.DialPingAddr(client4, server4)
	if err != nil {
		t.Fatal(err)
	}
	echo := icmpEcho(0x5747, 1, []byte("wgex-ping"))
	_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := pc.Write(echo); err != nil {
		t.Fatal(err)
	}
	n, err = pc.Read(buf)
	pc.Close()
	if err != nil || n < 8 || buf[0] != 0 || !bytes.HasSuffix(buf[:n], []byte("wgex-ping")) {
		t.Fatalf("ICMP echo reply = % x, %v", buf[:n], err)
	}

	if sink.wait(t, eventWaitTimeout, isEvent("handshake", "peer", "client-1")) == nil {
		t.Fatalf("no handshake event:\n%s", sink.text())
	}
	if sink.wait(t, eventWaitTimeout, isEvent("endpoint_change", "peer", "client-1")) == nil {
		t.Fatal("no endpoint_change event")
	}
	if sink.wait(t, eventWaitTimeout, isEvent("counters", "peer", "client-1")) == nil {
		t.Fatal("no counters event")
	}
	if sink.wait(t, eventWaitTimeout, isEvent("dns_query", "scope", "in_tunnel", "name", "foo.test.wgex.", "peer", "client-1")) == nil {
		t.Fatal("no in-tunnel dns_query event")
	}
}

func icmpEcho(id, seq uint16, payload []byte) []byte {
	b := []byte{8, 0, 0, 0, byte(id >> 8), byte(id), byte(seq >> 8), byte(seq)}
	b = append(b, payload...)
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	cs := ^uint16(sum)
	b[2], b[3] = byte(cs>>8), byte(cs)
	return b
}

func dnsQuery(t *testing.T, server netip.AddrPort, name string) []netip.Addr {
	t.Helper()
	q := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x77, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	pkt, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("udp", server.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(pkt); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(buf[:n]); err != nil {
		t.Fatal(err)
	}
	var out []netip.Addr
	for _, a := range m.Answers {
		if r, ok := a.Body.(*dnsmessage.AResource); ok {
			out = append(out, netip.AddrFrom4(r.A))
		}
	}
	return out
}

func TestMarkerListener(t *testing.T) {
	t.Parallel()
	cpriv, cpub := mustKey(t)
	loop := netip.MustParseAddr("127.0.0.1")
	srv, sink, spub := startTestServer(t, Config{
		Listen:       []netip.AddrPort{netip.AddrPortFrom(loop, 0)},
		Peers:        []PeerSpec{{Name: "client-1", PublicKey: cpub, Addrs: []netip.Addr{client4}}},
		MarkerListen: []netip.AddrPort{netip.AddrPortFrom(loop, 0)},
	})
	httpUDP, dnsAddrs := srv.MarkerAddrs()
	if len(httpUDP) != 1 || len(dnsAddrs) != 1 {
		t.Fatalf("marker addrs %v %v", httpUDP, dnsAddrs)
	}
	outside := func(proto, nonce string) func(map[string]any) bool {
		return isEvent("marker", "scope", "outside_tunnel", "proto", proto, "nonce", nonce)
	}

	// Clear-text markers sent straight over loopback (no tunnel).
	resp, err := http.Get("http://" + httpUDP[0].String() + "/leak/out-http-1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	uc, err := net.Dial("udp", httpUDP[0].String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = uc.Write([]byte("WGEXLEAK out-udp-1 seq=1"))
	uc.Close()
	if got := dnsQuery(t, dnsAddrs[0], "out-dns-1.leak.wgex.test."); len(got) != 1 || got[0] != loop {
		t.Fatalf("marker DNS answered %v", got)
	}
	for _, m := range [][2]string{{"http", "out-http-1"}, {"udp", "out-udp-1"}, {"dns", "out-dns-1"}} {
		if e := sink.wait(t, eventWaitTimeout, outside(m[0], m[1])); e == nil {
			t.Fatalf("no outside_tunnel %s marker:\n%s", m[0], sink.text())
		} else if e["level"] != "WARN" || e["src"] != "127.0.0.1" {
			t.Fatalf("outside marker event %v", e)
		}
	}

	// The same markers through the tunnel are in_tunnel and never outside.
	c := newClient(t, cpriv, spub, netip.MustParseAddrPort("127.0.0.1:0"), netip.AddrPortFrom(loop, srv.Port()), client4, 0)
	resp, err = c.httpClient().Get("http://10.77.0.1/leak/in-http-1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if a, err := c.tnet.LookupHost("in-dns-1.leak.wgex.test"); err != nil || len(a) != 1 || a[0] != server4.String() {
		t.Fatalf("in-tunnel leak lookup = %v, %v", a, err)
	}
	tu, err := c.tnet.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(server4, tunnelMarkerPort))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = tu.Write([]byte("WGEXLEAK in-udp-1"))
	tu.Close()
	for _, m := range [][2]string{{"http", "in-http-1"}, {"dns", "in-dns-1"}, {"udp", "in-udp-1"}} {
		if sink.wait(t, eventWaitTimeout, isEvent("marker", "scope", "in_tunnel", "proto", m[0], "nonce", m[1], "peer", "client-1")) == nil {
			t.Fatalf("no in_tunnel %s marker:\n%s", m[0], sink.text())
		}
	}
	time.Sleep(300 * time.Millisecond)
	if e, ok := sink.find(func(e map[string]any) bool {
		return e["scope"] == "outside_tunnel" && strings.HasPrefix(fmt.Sprint(e["nonce"]), "in-")
	}); ok {
		t.Fatalf("in-tunnel marker logged as outside: %v", e)
	}
}

func TestDropUDPFromIsSourceScoped(t *testing.T) {
	t.Parallel()
	privA, pubA := mustKey(t)
	privB, pubB := mustKey(t)
	v4, v6 := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")
	// Two underlay sources without privileges: IPv4 and IPv6 loopback.
	srv, sink, spub := startTestServer(t, Config{
		Listen: []netip.AddrPort{netip.AddrPortFrom(v4, 0), netip.AddrPortFrom(v6, 0)},
		Peers: []PeerSpec{
			{Name: "client-a", PublicKey: pubA, Addrs: []netip.Addr{client4}},
			{Name: "client-b", PublicKey: pubB, Addrs: []netip.Addr{client4b}},
		},
		Chaos: ChaosConfig{DropFrom: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}},
	})
	a := newClient(t, privA, spub, netip.AddrPortFrom(v4, 0), netip.AddrPortFrom(v4, srv.Port()), client4, 1)
	b := newClient(t, privB, spub, netip.AddrPortFrom(v6, 0), netip.AddrPortFrom(v6, srv.Port()), client4b, 1)
	if !b.waitHandshake(8 * time.Second) {
		t.Fatal("client-b (::1, not dropped) did not complete a handshake")
	}
	if a.waitHandshake(6 * time.Second) {
		t.Fatal("client-a (127.0.0.1, dropped) completed a handshake")
	}
	if sink.wait(t, eventWaitTimeout, isEvent("chaos_drop", "rule", "drop_udp_from", "src", "127.0.0.1")) == nil {
		t.Fatalf("no chaos_drop event:\n%s", sink.text())
	}
	if _, ok := sink.find(isEvent("chaos_drop", "src", "::1")); ok {
		t.Fatal("::1 was dropped")
	}
	if sink.wait(t, eventWaitTimeout, isEvent("handshake", "peer", "client-b")) == nil {
		t.Fatal("no server handshake event for client-b")
	}
	if _, ok := sink.find(isEvent("handshake", "peer", "client-a")); ok {
		t.Fatal("server logged a handshake for the dropped client")
	}
}

func TestLoss(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		loss float64
		want bool
	}{{100, false}, {0, true}} {
		t.Run(fmt.Sprintf("loss=%v", tc.loss), func(t *testing.T) {
			t.Parallel()
			cpriv, cpub := mustKey(t)
			loop := netip.MustParseAddr("127.0.0.1")
			srv, _, spub := startTestServer(t, Config{
				Listen: []netip.AddrPort{netip.AddrPortFrom(loop, 0)},
				Peers:  []PeerSpec{{Name: "client-1", PublicKey: cpub, Addrs: []netip.Addr{client4}}},
				Chaos:  ChaosConfig{LossPct: tc.loss},
			})
			c := newClient(t, cpriv, spub, netip.AddrPortFrom(loop, 0), netip.AddrPortFrom(loop, srv.Port()), client4, 1)
			if got := c.waitHandshake(10 * time.Second); got != tc.want {
				t.Fatalf("loss %v: handshake within 10 s = %v, want %v", tc.loss, got, tc.want)
			}
		})
	}
}

// latencyHandshakeWindow is the wait for the first handshake through 150 ms of injected latency. The race
// detector slows the handshake enough that a loaded host (load 17-18, 31 Oct 2026) took 6.5-8.4 s.
func latencyHandshakeWindow() time.Duration {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "-race" && setting.Value == "true" {
				return 15 * time.Second
			}
		}
	}
	return 10 * time.Second
}

func TestLatency(t *testing.T) {
	t.Parallel()
	cpriv, cpub := mustKey(t)
	loop := netip.MustParseAddr("127.0.0.1")
	srv, _, spub := startTestServer(t, Config{
		Listen: []netip.AddrPort{netip.AddrPortFrom(loop, 0)},
		Peers:  []PeerSpec{{Name: "client-1", PublicKey: cpub, Addrs: []netip.Addr{client4}}},
		Chaos:  ChaosConfig{Latency: 150 * time.Millisecond},
	})
	c := newClient(t, cpriv, spub, netip.AddrPortFrom(loop, 0), netip.AddrPortFrom(loop, srv.Port()), client4, 1)
	if !c.waitHandshake(latencyHandshakeWindow()) {
		t.Fatal("no handshake with latency")
	}
	uc, err := c.tnet.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(server4, tunnelEchoPort))
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	_ = uc.SetDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	_, _ = uc.Write([]byte("x"))
	if _, err := uc.Read(make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	if rtt := time.Since(start); rtt < 150*time.Millisecond {
		t.Fatalf("rtt %v below injected latency", rtt)
	}
}

func TestRunDoesNotPrintSecretsWithoutPrintKeys(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, printKeys := range []bool{false, true} {
		var stdout, stderr bytes.Buffer
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		args := []string{"--listen", "127.0.0.1:0", "--key-file", "testdata/server.key", "--peers", "2",
			"--public-address", "192.0.2.10", "--out-dir", dir, "--counters-interval", "200ms"}
		if printKeys {
			args = append(args, "--print-keys")
		}
		code := run(ctx, args, &stdout, &stderr)
		cancel()
		if code != 0 {
			t.Fatalf("run exit %d: %s %s", code, stdout.String(), stderr.String())
		}
		serverKey, err := readKeyFile("testdata/server.key")
		if err != nil {
			t.Fatal(err)
		}
		secrets := []string{serverKey.String()}
		for _, n := range []string{"client-1", "client-2"} {
			k, err := readKeyFile(dir + "/" + n + ".conf")
			if err != nil {
				t.Fatal(err)
			}
			secrets = append(secrets, k.String())
		}
		out := stdout.String() + stderr.String()
		for _, s := range secrets {
			if strings.Contains(out, s) != printKeys {
				t.Fatalf("print-keys=%v: secret presence in output = %v", printKeys, !printKeys)
			}
		}
		if !strings.Contains(stdout.String(), `"event":"started"`) || !strings.Contains(stdout.String(), `"event":"client"`) {
			t.Fatalf("missing started/client events:\n%s", stdout.String())
		}
	}
}
