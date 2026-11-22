// SPDX-License-Identifier: MIT

package resolver

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// stub is a loopback DNS server on one port for UDP and TCP.
type stub struct {
	udp     *net.UDPConn
	tcp     *net.TCPListener
	addr    netip.AddrPort
	udpHits atomic.Int32
	tcpHits atomic.Int32
}

func newStub(t *testing.T) *stub {
	t.Helper()
	for range 20 {
		u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		port := u.LocalAddr().(*net.UDPAddr).Port
		l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			u.Close()
			continue
		}
		s := &stub{udp: u, tcp: l, addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))}
		go s.serveUDP()
		go s.serveTCP()
		t.Cleanup(func() { u.Close(); l.Close() })
		return s
	}
	t.Fatal("no free port pair")
	return nil
}

func answer(req []byte, tcp bool) []byte {
	var m dnsmessage.Message
	if err := m.Unpack(req); err != nil || len(m.Questions) != 1 {
		return nil
	}
	q := m.Questions[0]
	h := dnsmessage.Header{ID: m.Header.ID, Response: true, RecursionAvailable: true}
	name := strings.ToLower(q.Name.String())
	var answers []dnsmessage.Resource
	add := func(ttl uint32, body dnsmessage.ResourceBody) {
		answers = append(answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: ttl}, Body: body})
	}
	switch name {
	case "relay.example.":
		if q.Type == dnsmessage.TypeA {
			add(300, &dnsmessage.AResource{A: [4]byte{192, 0, 2, 10}})
			add(60, &dnsmessage.AResource{A: [4]byte{192, 0, 2, 11}})
		} else if q.Type == dnsmessage.TypeAAAA {
			add(120, &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::10").As16()})
		}
	case "big.example.":
		if !tcp {
			h.Truncated = true
		} else if q.Type == dnsmessage.TypeA {
			for i := range 3 {
				add(30, &dnsmessage.AResource{A: [4]byte{198, 51, 100, byte(i + 1)}})
			}
		}
	case "nx.example.":
		h.RCode = dnsmessage.RCodeNameError
	case "nodata.example.":
	default:
		h.RCode = dnsmessage.RCodeServerFailure
	}
	b := dnsmessage.NewBuilder(nil, h)
	_ = b.StartQuestions()
	_ = b.Question(q)
	_ = b.StartAnswers()
	for _, a := range answers {
		switch body := a.Body.(type) {
		case *dnsmessage.AResource:
			_ = b.AResource(a.Header, *body)
		case *dnsmessage.AAAAResource:
			_ = b.AAAAResource(a.Header, *body)
		}
	}
	out, _ := b.Finish()
	return out
}

func (s *stub) serveUDP() {
	buf := make([]byte, 512)
	for {
		n, from, err := s.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		s.udpHits.Add(1)
		if resp := answer(buf[:n], false); resp != nil {
			_, _ = s.udp.WriteToUDPAddrPort(resp, from)
		}
	}
}

func (s *stub) serveTCP() {
	for {
		c, err := s.tcp.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			var lb [2]byte
			if _, err := io.ReadFull(c, lb[:]); err != nil {
				return
			}
			req := make([]byte, binary.BigEndian.Uint16(lb[:]))
			if _, err := io.ReadFull(c, req); err != nil {
				return
			}
			s.tcpHits.Add(1)
			resp := answer(req, true)
			out := binary.BigEndian.AppendUint16(nil, uint16(len(resp)))
			_, _ = c.Write(append(out, resp...))
		}()
	}
}

func resolveJSON(t *testing.T, host string, v4 int32, servers ...string) Result {
	t.Helper()
	doc, _ := json.Marshal(map[string]any{"servers": servers, "timeout_ms": 300})
	var r Result
	if err := json.Unmarshal(ResolveJSON(context.Background(), host, v4, 0, doc), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestResolveAAndAAAA(t *testing.T) {
	s := newStub(t)
	r := resolveJSON(t, "relay.example", 0, s.addr.String())
	if r.Error != "" || strings.Join(r.A, ",") != "192.0.2.10,192.0.2.11" || strings.Join(r.AAAA, ",") != "2001:db8::10" || r.TTL != 60 {
		t.Fatalf("result %+v", r)
	}
	if s.tcpHits.Load() != 0 {
		t.Fatal("TCP used without truncation")
	}
}

func TestResolveTruncatedFallsBackToTCP(t *testing.T) {
	s := newStub(t)
	r := resolveJSON(t, "big.example", 0, s.addr.String())
	if r.Error != "" || len(r.A) != 3 || r.TTL != 30 || s.tcpHits.Load() == 0 {
		t.Fatalf("result %+v, tcp hits %d", r, s.tcpHits.Load())
	}
}

func TestResolveNegativeAnswers(t *testing.T) {
	s := newStub(t)
	if r := resolveJSON(t, "nx.example", 0, s.addr.String()); r.Error != ErrNXDomain || len(r.A)+len(r.AAAA) != 0 {
		t.Fatalf("nx: %+v", r)
	}
	if r := resolveJSON(t, "nodata.example", 0, s.addr.String()); r.Error != ErrNoData {
		t.Fatalf("nodata: %+v", r)
	}
	if r := resolveJSON(t, "servfail.example", 0, s.addr.String()); r.Error != ErrFailed {
		t.Fatalf("servfail: %+v", r)
	}
}

func TestResolveFallsBackToNextServer(t *testing.T) {
	s := newStub(t)
	// A server that never answers: a bound UDP socket nobody reads.
	silent, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	start := time.Now()
	r := resolveJSON(t, "relay.example", 0, silent.LocalAddr().String(), s.addr.String())
	if r.Error != "" || len(r.A) != 2 {
		t.Fatalf("result %+v", r)
	}
	if d := time.Since(start); d < 250*time.Millisecond || d > 3*time.Second {
		t.Fatalf("fallback took %v; want about one 300 ms attempt", d)
	}
}

func TestResolveBoundToLoopbackInterface(t *testing.T) {
	lo, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skip("no lo0")
	}
	s := newStub(t)
	if r := resolveJSON(t, "relay.example", int32(lo.Index), s.addr.String()); r.Error != "" || len(r.A) != 2 {
		t.Fatalf("bound to lo0: %+v", r)
	}
	if r := resolveJSON(t, "relay.example", 999999, s.addr.String()); r.Error != ErrFailed {
		t.Fatalf("bound to a missing interface: %+v", r)
	}
}

func TestResolveLiteralsAndInvalidInput(t *testing.T) {
	s := newStub(t)
	if r := resolveJSON(t, "192.0.2.7", 0, s.addr.String()); strings.Join(r.A, ",") != "192.0.2.7" || s.udpHits.Load() != 0 {
		t.Fatalf("literal: %+v", r)
	}
	if r := resolveJSON(t, "2001:db8::7", 0, s.addr.String()); strings.Join(r.AAAA, ",") != "2001:db8::7" {
		t.Fatalf("literal v6: %+v", r)
	}
	for _, doc := range []string{``, `[]`, `{"servers":[]}`, `["not an ip"]`, `{"servers":["127.0.0.1"],"bogus":1}`, `["127.0.0.1:0"]`} {
		out := ResolveJSON(context.Background(), "relay.example", 0, 0, []byte(doc))
		var r Result
		if err := json.Unmarshal(out, &r); err != nil || r.Error != ErrInvalid || r.A == nil || r.AAAA == nil {
			t.Errorf("resolvers %q: %s", doc, out)
		}
	}
	if r := resolveJSON(t, "", 0, s.addr.String()); r.Error != ErrInvalid {
		t.Fatalf("empty host: %+v", r)
	}
	if r := resolveJSON(t, strings.Repeat("a", 300), 0, s.addr.String()); r.Error != ErrInvalid {
		t.Fatalf("long host: %+v", r)
	}
	out := ResolveJSON(context.Background(), "relay.example", -1, 0, []byte(`["127.0.0.1"]`))
	if !strings.Contains(string(out), `"error":"invalid"`) {
		t.Fatalf("negative index: %s", out)
	}
	servers, _, err := ParseServers([]byte(`["192.0.2.1","[2001:db8::1]:5353","192.0.2.2:53"]`))
	if err != nil || servers[0].Port() != 53 || servers[1].Port() != 5353 {
		t.Fatalf("ParseServers: %v %v", servers, err)
	}
}

// Answers carrying other record types (including SVCB/HTTPS, whose parser
// had GO-2026-5942) are skipped without decoding; garbage never panics.
func TestParseResponseSkipsOtherRecordsAndSurvivesGarbage(t *testing.T) {
	name := dnsmessage.MustNewName("relay.example.")
	q := dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, Response: true})
	_ = b.StartQuestions()
	_ = b.Question(q)
	_ = b.StartAnswers()
	hdr := dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: 50}
	_ = b.CNAMEResource(hdr, dnsmessage.CNAMEResource{CNAME: name})
	// An unknown/opaque record body standing in for a malformed SVCB.
	_ = b.UnknownResource(dnsmessage.ResourceHeader{Name: name, Type: 64, Class: dnsmessage.ClassINET, TTL: 1},
		dnsmessage.UnknownResource{Type: 64, Data: []byte{0xff, 0xff, 0xff}})
	_ = b.AResource(hdr, dnsmessage.AResource{A: [4]byte{192, 0, 2, 9}})
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	r, ok := parseResponse(msg, 7, q)
	if !ok || len(r.addrs) != 1 || r.addrs[0].String() != "192.0.2.9" || r.ttl != 50 {
		t.Fatalf("parse: %+v %v", r, ok)
	}
	if _, ok := parseResponse(msg, 8, q); ok {
		t.Fatal("wrong ID accepted")
	}
	for i := range len(msg) {
		_, _ = parseResponse(msg[:i], 7, q)
		mut := append([]byte(nil), msg...)
		mut[i] ^= 0xff
		_, _ = parseResponse(mut, 7, q)
	}
}

func FuzzParseResponse(f *testing.F) {
	f.Add([]byte{0, 7, 0x80, 0, 0, 1, 0, 1, 0, 0, 0, 0})
	q := dnsmessage.Question{Name: dnsmessage.MustNewName("relay.example."), Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET}
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parseResponse(b, 7, q)
	})
}
