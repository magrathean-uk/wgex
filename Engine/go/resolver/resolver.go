// SPDX-License-Identifier: MIT

// Package resolver is the UnderlayResolver's DNS client (02-architecture
// §7.5): A and AAAA queries over UDP with TCP fallback, sent from sockets bound
// to the underlay interface with IP_BOUND_IF / IPV6_BOUND_IF so resolution
// works while blocking policies are in place and never depends on
// mDNSResponder. Caching and persistence belong to the caller.
package resolver

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

// DefaultAttemptTimeout bounds each query attempt (one server, one protocol).
const DefaultAttemptTimeout = 2 * time.Second

// maxAttemptTimeout caps a caller-supplied attempt timeout.
const maxAttemptTimeout = 10 * time.Second

// maxServers caps the resolver list.
const maxServers = 8

// Options configures one resolution.
type Options struct {
	// Servers are resolver addresses, "ip" or "ip:port" ("[v6]:port").
	Servers []netip.AddrPort
	// IfIndexV4 and IfIndexV6 bind the query sockets (0 = unbound).
	IfIndexV4, IfIndexV6 uint32
	// AttemptTimeout bounds each attempt; 0 means DefaultAttemptTimeout.
	AttemptTimeout time.Duration
}

// Result is the JSON document wgex_resolve returns.
type Result struct {
	A     []string `json:"a"`
	AAAA  []string `json:"aaaa"`
	TTL   uint32   `json:"ttl"`
	Error string   `json:"error,omitempty"`
}

// Error codes in Result.Error.
const (
	ErrInvalid  = "invalid"
	ErrNXDomain = "nxdomain"
	ErrNoData   = "nodata"
	ErrFailed   = "failed"
)

// resolversDoc is the resolvers_json argument: either a JSON array of server
// strings or {"servers":[...],"timeout_ms":n}.
type resolversDoc struct {
	Servers   []string `json:"servers"`
	TimeoutMS int      `json:"timeout_ms"`
}

// ParseServers parses resolvers_json.
func ParseServers(doc []byte) ([]netip.AddrPort, time.Duration, error) {
	var d resolversDoc
	trimmed := strings.TrimSpace(string(doc))
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(doc, &d.Servers); err != nil {
			return nil, 0, err
		}
	} else {
		dec := json.NewDecoder(strings.NewReader(trimmed))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&d); err != nil {
			return nil, 0, err
		}
	}
	if len(d.Servers) == 0 || len(d.Servers) > maxServers {
		return nil, 0, fmt.Errorf("need 1...%d servers, got %d", maxServers, len(d.Servers))
	}
	out := make([]netip.AddrPort, 0, len(d.Servers))
	for _, s := range d.Servers {
		ap, err := parseServer(s)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, ap)
	}
	if d.TimeoutMS < 0 {
		return nil, 0, errors.New("negative timeout_ms")
	}
	t := time.Duration(d.TimeoutMS) * time.Millisecond
	if t > maxAttemptTimeout {
		t = maxAttemptTimeout
	}
	return out, t, nil
}

func parseServer(s string) (netip.AddrPort, error) {
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.AddrPortFrom(a.Unmap(), 53), nil
	}
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolver %q: %w", s, err)
	}
	if ap.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("resolver %q: port 0", s)
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}

// Resolve looks up the A and AAAA records of host. An IP literal is returned
// as-is. Each query tries the servers in order (UDP, then TCP when the UDP
// answer is truncated) and stops at the first server that answers with
// NOERROR or NXDOMAIN; A and AAAA run concurrently. The worst case is
// len(Servers) × 2 attempts × AttemptTimeout.
func Resolve(ctx context.Context, host string, opt Options) Result {
	res := Result{A: []string{}, AAAA: []string{}}
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		if a.Is4() {
			res.A = append(res.A, a.String())
		} else {
			res.AAAA = append(res.AAAA, a.String())
		}
		return res
	}
	name, err := queryName(host)
	if err != nil || len(opt.Servers) == 0 {
		res.Error = ErrInvalid
		return res
	}
	if opt.AttemptTimeout <= 0 {
		opt.AttemptTimeout = DefaultAttemptTimeout
	}

	type answer struct {
		addrs []netip.Addr
		ttl   uint32
		rcode dnsmessage.RCode
		err   error
	}
	var (
		wg      sync.WaitGroup
		answers [2]answer
	)
	for i, qt := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a := &answers[i]
			a.addrs, a.ttl, a.rcode, a.err = query(ctx, name, qt, opt)
		}()
	}
	wg.Wait()

	var ttl uint32
	haveTTL := false
	for i, a := range answers {
		for _, ip := range a.addrs {
			if i == 0 {
				res.A = append(res.A, ip.String())
			} else {
				res.AAAA = append(res.AAAA, ip.String())
			}
		}
		if len(a.addrs) > 0 && (!haveTTL || a.ttl < ttl) {
			ttl, haveTTL = a.ttl, true
		}
	}
	res.TTL = ttl
	if len(res.A)+len(res.AAAA) > 0 {
		return res
	}
	switch {
	case answers[0].rcode == dnsmessage.RCodeNameError || answers[1].rcode == dnsmessage.RCodeNameError:
		res.Error = ErrNXDomain
	case answers[0].err == nil && answers[1].err == nil:
		res.Error = ErrNoData
	default:
		res.Error = ErrFailed
	}
	return res
}

func queryName(host string) (dnsmessage.Name, error) {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " \t\r\n") {
		return dnsmessage.Name{}, errors.New("invalid host name")
	}
	if !strings.HasSuffix(host, ".") {
		host += "."
	}
	return dnsmessage.NewName(host)
}

var errBadResponse = errors.New("malformed or mismatched DNS response")

func query(ctx context.Context, name dnsmessage.Name, qt dnsmessage.Type, opt Options) ([]netip.Addr, uint32, dnsmessage.RCode, error) {
	q := dnsmessage.Question{Name: name, Type: qt, Class: dnsmessage.ClassINET}
	var lastErr error = errors.New("no servers")
	for _, server := range opt.Servers {
		if err := ctx.Err(); err != nil {
			return nil, 0, 0, err
		}
		ifindex := opt.IfIndexV4
		if server.Addr().Is6() {
			ifindex = opt.IfIndexV6
		}
		resp, err := exchange(ctx, "udp", server, ifindex, q, opt.AttemptTimeout)
		if err == nil && resp.header.Truncated {
			resp, err = exchange(ctx, "tcp", server, ifindex, q, opt.AttemptTimeout)
		}
		if err != nil {
			lastErr = err
			continue
		}
		switch resp.header.RCode {
		case dnsmessage.RCodeSuccess:
			return resp.addrs, resp.ttl, dnsmessage.RCodeSuccess, nil
		case dnsmessage.RCodeNameError:
			return nil, 0, dnsmessage.RCodeNameError, nil
		default:
			lastErr = fmt.Errorf("server %s: rcode %v", server, resp.header.RCode)
		}
	}
	return nil, 0, 0, lastErr
}

func newQuery(q dnsmessage.Question) (uint16, []byte, error) {
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return 0, nil, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	b := dnsmessage.NewBuilder(make([]byte, 2, 514), dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return 0, nil, err
	}
	if err := b.Question(q); err != nil {
		return 0, nil, err
	}
	msg, err := b.Finish()
	if err != nil {
		return 0, nil, err
	}
	return id, msg, nil // msg[0:2] is room for the TCP length prefix
}

func dialer(ifindex uint32, timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: func(network, _ string, c syscall.RawConn) error {
			if ifindex == 0 {
				return nil
			}
			var opErr error
			err := c.Control(func(fd uintptr) {
				if strings.HasSuffix(network, "6") {
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

func exchange(ctx context.Context, proto string, server netip.AddrPort, ifindex uint32, q dnsmessage.Question, timeout time.Duration) (*response, error) {
	id, wire, err := newQuery(q)
	if err != nil {
		return nil, err
	}
	family := "4"
	if server.Addr().Is6() {
		family = "6"
	}
	actx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c, err := dialer(ifindex, timeout).DialContext(actx, proto+family, server.String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	deadline, _ := actx.Deadline()
	_ = c.SetDeadline(deadline)
	stop := context.AfterFunc(actx, func() { _ = c.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	if proto == "udp" {
		if _, err := c.Write(wire[2:]); err != nil {
			return nil, err
		}
		buf := make([]byte, 4096)
		for {
			n, err := c.Read(buf)
			if err != nil {
				return nil, err
			}
			// Ignore datagrams that are not the answer to this query.
			if m, ok := parseResponse(buf[:n], id, q); ok {
				return m, nil
			}
		}
	}
	binary.BigEndian.PutUint16(wire[:2], uint16(len(wire)-2))
	if _, err := c.Write(wire); err != nil {
		return nil, err
	}
	var lb [2]byte
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	m, ok := parseResponse(resp, id, q)
	if !ok {
		return nil, errBadResponse
	}
	return m, nil
}

// response is the part of a DNS answer the resolver uses.
type response struct {
	header dnsmessage.Header
	addrs  []netip.Addr
	ttl    uint32
}

// parseResponse checks that b answers q (ID, QR bit, single matching
// question) and collects the A or AAAA records. It parses incrementally and
// skips every other record without decoding its body, so malformed records
// of types WGEX never asks for (for example SVCB/HTTPS, GO-2026-5942 in
// dnsmessage.Message.Unpack) are never parsed; a recover backs that up.
func parseResponse(b []byte, id uint16, q dnsmessage.Question) (resp *response, ok bool) {
	defer func() {
		if recover() != nil {
			resp, ok = nil, false
		}
	}()
	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil || !h.Response || h.ID != id {
		return nil, false
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) != 1 {
		return nil, false
	}
	got := qs[0]
	if got.Type != q.Type || got.Class != q.Class || !strings.EqualFold(got.Name.String(), q.Name.String()) {
		return nil, false
	}
	r := &response{header: h}
	if h.Truncated || h.RCode != dnsmessage.RCodeSuccess {
		return r, true
	}
	for {
		ah, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			return r, true
		}
		if err != nil {
			return nil, false
		}
		var a netip.Addr
		switch {
		case ah.Type == dnsmessage.TypeA && q.Type == dnsmessage.TypeA && ah.Class == dnsmessage.ClassINET:
			rr, err := p.AResource()
			if err != nil {
				return nil, false
			}
			a = netip.AddrFrom4(rr.A)
		case ah.Type == dnsmessage.TypeAAAA && q.Type == dnsmessage.TypeAAAA && ah.Class == dnsmessage.ClassINET:
			rr, err := p.AAAAResource()
			if err != nil {
				return nil, false
			}
			a = netip.AddrFrom16(rr.AAAA)
		default:
			if err := p.SkipAnswer(); err != nil {
				return nil, false
			}
			continue
		}
		if len(r.addrs) == 0 || ah.TTL < r.ttl {
			r.ttl = ah.TTL
		}
		r.addrs = append(r.addrs, a)
	}
}

// ResolveJSON runs Resolve and returns the result document; invalid arguments
// yield {"a":[],"aaaa":[],"ttl":0,"error":"invalid"}.
func ResolveJSON(ctx context.Context, host string, ifindexV4, ifindexV6 int32, resolversJSON []byte) []byte {
	res := Result{A: []string{}, AAAA: []string{}}
	servers, timeout, err := ParseServers(resolversJSON)
	if err != nil || ifindexV4 < 0 || ifindexV6 < 0 {
		res.Error = ErrInvalid
	} else {
		res = Resolve(ctx, host, Options{
			Servers:        servers,
			IfIndexV4:      uint32(ifindexV4),
			IfIndexV6:      uint32(ifindexV6),
			AttemptTimeout: timeout,
		})
	}
	b, err := json.Marshal(res)
	if err != nil {
		return []byte(`{"a":[],"aaaa":[],"ttl":0,"error":"` + ErrFailed + `"}`)
	}
	return b
}
