// SPDX-License-Identifier: MIT

package main

import (
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestReadKeyFileFormats(t *testing.T) {
	want, err := readKeyFile("testdata/server.key")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	conf := filepath.Join(dir, "x.conf")
	if err := os.WriteFile(conf, []byte("[Interface]\nAddress = 10.0.0.2/32\nPrivateKey = "+want.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readKeyFile(conf)
	if err != nil || got != want {
		t.Fatalf("wg-quick form: %v", err)
	}
	bad := filepath.Join(dir, "bad")
	_ = os.WriteFile(bad, []byte("not-a-key\n"), 0o600)
	if _, err := readKeyFile(bad); err == nil || strings.Contains(err.Error(), "not-a-key") {
		t.Fatalf("bad key error must not echo content: %v", err)
	}
}

func TestMarkerParsing(t *testing.T) {
	for in, want := range map[string]string{"WGEXLEAK abc-1": "abc-1", "x WGEXLEAK n_2 seq=3": "n_2", "WGEXLEAK a\nb": "a"} {
		if n, ok := udpMarkerNonce([]byte(in)); !ok || n != want {
			t.Errorf("%q -> %q %v", in, n, ok)
		}
	}
	for _, in := range []string{"WGEXLEAK", "WGEXLEAK  ", "WGEXLEAK a/b", "hello"} {
		if _, ok := udpMarkerNonce([]byte(in)); ok {
			t.Errorf("%q accepted", in)
		}
	}
	if n, ok := leakNonce("abc.v4.leak.wgex.test."); !ok || n != "abc.v4" {
		t.Errorf("leakNonce = %q %v", n, ok)
	}
	if _, ok := leakNonce("leak.wgex.test."); ok {
		t.Error("bare zone accepted")
	}
}

func dnsAsk(t *testing.T, a dnsAnswerer, name string, typ dnsmessage.Type) dnsmessage.Message {
	t.Helper()
	q := dnsmessage.Message{Header: dnsmessage.Header{ID: 9}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}}}
	pkt, _ := q.Pack()
	out, _, ok := a.handle(pkt)
	if !ok {
		t.Fatalf("no answer for %s", name)
	}
	var m dnsmessage.Message
	if err := m.Unpack(out); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDNSAnswerer(t *testing.T) {
	a := dnsAnswerer{answer4: server4, answer6: netip.MustParseAddr("fd77:6765:7800::1"), testZoneOn: true}
	if m := dnsAsk(t, a, "Foo.TEST.wgex.", dnsmessage.TypeA); m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 || m.Answers[0].Header.TTL != 0 {
		t.Fatalf("A: %+v", m)
	}
	if m := dnsAsk(t, a, "foo.test.wgex.", dnsmessage.TypeAAAA); len(m.Answers) != 1 {
		t.Fatalf("AAAA: %+v", m)
	}
	if m := dnsAsk(t, a, "example.com.", dnsmessage.TypeA); m.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("other: %+v", m)
	}
	outside := dnsAnswerer{answer4: netip.MustParseAddr("192.0.2.5")}
	if m := dnsAsk(t, outside, "foo.test.wgex.", dnsmessage.TypeA); m.RCode != dnsmessage.RCodeNameError {
		t.Fatal("marker DNS answered the test zone")
	}
	if m := dnsAsk(t, outside, "n1.leak.wgex.test.", dnsmessage.TypeAAAA); m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Fatalf("v4 marker listener AAAA: %+v", m)
	}
}

func TestChaosRules(t *testing.T) {
	ev := newEvents(io.Discard, true, slog.LevelInfo)
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.7")
	allow := newChaosBind(nil, ChaosConfig{AllowOnlyFrom: []netip.Prefix{netip.PrefixFrom(b, 32)}}, true, ev)
	if !allow.dropInbound(a) || allow.dropInbound(b) {
		t.Fatal("allow-udp-only-from")
	}
	drop := newChaosBind(nil, ChaosConfig{DropFrom: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}, true, ev)
	if !drop.dropInbound(a) || drop.dropInbound(b) || drop.dropInbound(netip.MustParseAddr("::ffff:198.51.100.7")) {
		t.Fatal("drop-udp-from")
	}
	if !drop.dropInbound(netip.MustParseAddr("::ffff:192.0.2.9")) {
		t.Fatal("v4-mapped source not matched")
	}
	after := newChaosBind(nil, ChaosConfig{DropAfter: 50 * time.Millisecond}, true, ev)
	if after.dropInbound(a) {
		t.Fatal("drop-after fired early")
	}
	time.Sleep(60 * time.Millisecond)
	if !after.dropInbound(a) || !after.dropInbound(b) {
		t.Fatal("drop-after is global")
	}
	noV6 := newChaosBind(nil, ChaosConfig{}, false, ev)
	if !noV6.dropInbound(netip.MustParseAddr("2001:db8::1")) || noV6.dropInbound(a) {
		t.Fatal("ipv6 underlay filter")
	}
}

func TestHostsAndConf(t *testing.T) {
	h, err := hosts(netip.MustParsePrefix("10.77.0.0/24"), 2)
	if err != nil || h[0] != server4 || h[2] != client4b {
		t.Fatalf("hosts = %v %v", h, err)
	}
	if _, err := hosts(netip.MustParsePrefix("10.77.0.0/24"), 254); err == nil {
		t.Fatal("broadcast address handed out")
	}
	priv, pub := mustKey(t)
	_, spub := mustKey(t)
	c := clientConf{Name: "client-1", Private: priv, Public: pub, Addrs: []netip.Addr{client4, netip.MustParseAddr("fd77:6765:7800::2")}}
	conf := c.render(confParams{ServerPublic: spub, Endpoint: netip.MustParseAddrPort("[2001:db8::1]:51820"),
		DNS: []netip.Addr{server4}, AllowedIPs: []string{"0.0.0.0/0", "::/0"}, MTU: 1420})
	for _, want := range []string{"Address = 10.77.0.2/32, fd77:6765:7800::2/128", "Endpoint = [2001:db8::1]:51820", "PublicKey = " + spub.String()} {
		if !strings.Contains(conf, want) {
			t.Fatalf("conf missing %q:\n%s", want, conf)
		}
	}
	dir := t.TempDir()
	cp, pp, err := writeClientFiles(dir, c.Name, conf)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{cp, pp} {
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v %v", p, st.Mode(), err)
		}
	}
	png, _ := os.ReadFile(pp)
	if len(png) < 8 || string(png[1:4]) != "PNG" {
		t.Fatal("QR file is not a PNG")
	}
	if q, err := terminalQR(conf); err != nil || !strings.ContainsAny(q, "█▀▄") {
		t.Fatalf("terminal QR: %v", err)
	}
}
