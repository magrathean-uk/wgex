// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	tunnelHTTPPort   = 80
	tunnelDNSPort    = 53
	tunnelEchoPort   = 7
	tunnelMarkerPort = 8088 // mirrors the default marker listener port
	defaultMTU       = 1420
	// defaultMarkerDNSPort is not 5353: mDNSResponder holds *:5353 on macOS
	// and sharing it would mean SO_REUSEPORT and stealing unicast mDNS.
	defaultMarkerDNSPort = 5354
)

// PeerSpec is one client allowed to connect.
type PeerSpec struct {
	Name      string
	PublicKey Key
	Addrs     []netip.Addr // tunnel addresses (allowed IPs as host routes)
}

// Config is the full server configuration; main builds it from flags and
// the tests build it directly.
type Config struct {
	Listen          []netip.AddrPort
	PrivateKey      Key
	Peers           []PeerSpec
	Server4         netip.Addr
	Server6         netip.Addr // invalid when IPv6 is off
	IPv6            bool
	MTU             int
	MarkerListen    []netip.AddrPort
	MarkerDNSPort   int // 0 = ephemeral, negative = disabled
	Chaos           ChaosConfig
	CounterInterval time.Duration
	PollInterval    time.Duration
	Events          *Events
}

type peerState struct {
	spec      PeerSpec
	endpoint  string
	handshake int64
}

// Server is a running userspace WireGuard test peer.
type Server struct {
	cfg  Config
	ev   *Events
	dev  *device.Device
	tnet *netstack.Net
	bind *chaosBind
	port uint16

	peersByHex map[string]*peerState
	peersByIP  map[netip.Addr]string

	markerHTTP []netip.AddrPort
	markerDNS  []netip.AddrPort

	mu      sync.Mutex
	closers []io.Closer
	stop    chan struct{}
	wg      sync.WaitGroup
	once    sync.Once
}

func isWildcardListen(l []netip.AddrPort) bool {
	return len(l) == 1 && l[0].Addr().IsUnspecified()
}

// StartServer brings the device up and starts every service.
func StartServer(cfg Config) (*Server, error) {
	if cfg.MTU == 0 {
		cfg.MTU = defaultMTU
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = time.Second
	}
	if cfg.CounterInterval == 0 {
		cfg.CounterInterval = 5 * time.Second
	}
	if len(cfg.Listen) == 0 {
		return nil, errors.New("no listen address")
	}
	port := cfg.Listen[0].Port()
	for _, l := range cfg.Listen {
		if l.Port() != port {
			return nil, errors.New("all --listen addresses must share one port")
		}
	}
	s := &Server{
		cfg:        cfg,
		ev:         cfg.Events,
		peersByHex: map[string]*peerState{},
		peersByIP:  map[netip.Addr]string{},
		stop:       make(chan struct{}),
	}

	var inner conn.Bind
	acceptV6 := cfg.IPv6
	if isWildcardListen(cfg.Listen) {
		// The default bind always opens IPv4 and IPv6 wildcard sockets;
		// without --ipv6 the chaos wrapper drops IPv6-sourced datagrams.
		inner = conn.NewDefaultBind()
	} else {
		addrs := append([]netip.AddrPort(nil), cfg.Listen...)
		hasV6 := false
		for _, a := range addrs {
			if a.Addr().Is6() {
				hasV6 = true
			}
		}
		if cfg.IPv6 && !hasV6 {
			addrs = append(addrs, netip.AddrPortFrom(netip.IPv6Unspecified(), port))
			hasV6 = true
		}
		acceptV6 = acceptV6 || hasV6
		inner = newAddrBind(addrs)
	}
	s.bind = newChaosBind(inner, cfg.Chaos, acceptV6, s.ev)

	local := []netip.Addr{cfg.Server4}
	if cfg.Server6.IsValid() {
		local = append(local, cfg.Server6)
	}
	tdev, tnet, err := netstack.CreateNetTUN(local, nil, cfg.MTU)
	if err != nil {
		s.bind.shutdown()
		return nil, fmt.Errorf("netstack: %w", err)
	}
	s.tnet = tnet
	s.dev = device.NewDevice(tdev, s.bind, s.wgLogger())

	var uapi strings.Builder
	fmt.Fprintf(&uapi, "private_key=%s\nlisten_port=%d\n", cfg.PrivateKey.hex(), port)
	for _, p := range cfg.Peers {
		fmt.Fprintf(&uapi, "public_key=%s\n", p.PublicKey.hex())
		for _, a := range p.Addrs {
			fmt.Fprintf(&uapi, "allowed_ip=%s\n", netip.PrefixFrom(a, a.BitLen()))
			s.peersByIP[a] = p.Name
		}
		s.peersByHex[p.PublicKey.hex()] = &peerState{spec: p}
	}
	if err := s.dev.IpcSet(uapi.String()); err != nil {
		s.Close()
		return nil, errors.New("configuring device failed") // never echo the UAPI text
	}
	if err := s.dev.Up(); err != nil {
		s.Close()
		return nil, fmt.Errorf("device up: %w", err)
	}
	s.port = s.readListenPort()

	if err := s.startTunnelServices(); err != nil {
		s.Close()
		return nil, err
	}
	if err := s.startMarkerListeners(); err != nil {
		s.Close()
		return nil, err
	}
	s.wg.Add(1)
	go s.pollLoop()
	return s, nil
}

func (s *Server) wgLogger() *device.Logger {
	return &device.Logger{
		Verbosef: func(format string, args ...any) {
			s.ev.Debug("wireguard", "message", fmt.Sprintf(format, args...))
		},
		Errorf: func(format string, args ...any) {
			s.ev.Warn("wireguard_error", "message", fmt.Sprintf(format, args...))
		},
	}
}

// Port is the bound WireGuard UDP port.
func (s *Server) Port() uint16 { return s.port }

// MarkerAddrs returns the bound marker HTTP/UDP and DNS addresses.
func (s *Server) MarkerAddrs() (httpUDP, dns []netip.AddrPort) { return s.markerHTTP, s.markerDNS }

func (s *Server) addCloser(c io.Closer) {
	s.mu.Lock()
	s.closers = append(s.closers, c)
	s.mu.Unlock()
}

// Close stops all services and the device.
func (s *Server) Close() {
	s.once.Do(func() {
		close(s.stop)
		s.mu.Lock()
		cs := s.closers
		s.closers = nil
		s.mu.Unlock()
		for _, c := range cs {
			c.Close()
		}
		if s.dev != nil {
			s.dev.Close()
		}
		s.bind.shutdown()
		s.wg.Wait()
	})
}

type uapiPeer struct {
	hexKey    string
	endpoint  string
	handshake int64
	rx, tx    uint64
}

// readUAPI parses IpcGet output. The device section contains the private
// key; it is skipped and the raw text is never logged.
func (s *Server) readUAPI() (port uint16, peers []uapiPeer) {
	text, err := s.dev.IpcGet()
	if err != nil {
		return 0, nil
	}
	var cur *uapiPeer
	var sec, nsec int64
	flush := func() {
		if cur != nil {
			cur.handshake = sec*int64(time.Second) + nsec
			peers = append(peers, *cur)
		}
	}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "listen_port":
			p, _ := strconv.ParseUint(v, 10, 16)
			port = uint16(p)
		case "public_key":
			flush()
			cur, sec, nsec = &uapiPeer{hexKey: v}, 0, 0
		case "endpoint":
			if cur != nil {
				cur.endpoint = v
			}
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		case "rx_bytes":
			if cur != nil {
				cur.rx, _ = strconv.ParseUint(v, 10, 64)
			}
		case "tx_bytes":
			if cur != nil {
				cur.tx, _ = strconv.ParseUint(v, 10, 64)
			}
		}
	}
	flush()
	return port, peers
}

func (s *Server) readListenPort() uint16 {
	p, _ := s.readUAPI()
	return p
}

func (s *Server) pollLoop() {
	defer s.wg.Done()
	poll := time.NewTicker(s.cfg.PollInterval)
	defer poll.Stop()
	counters := time.NewTicker(s.cfg.CounterInterval)
	defer counters.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-poll.C:
			s.checkPeers(false)
		case <-counters.C:
			s.checkPeers(true)
		}
	}
}

func (s *Server) checkPeers(emitCounters bool) {
	_, peers := s.readUAPI()
	for _, p := range peers {
		st, ok := s.peersByHex[p.hexKey]
		if !ok {
			continue
		}
		name, pub := st.spec.Name, st.spec.PublicKey.String()
		if p.endpoint != st.endpoint {
			s.ev.Emit("endpoint_change", "peer", name, "public_key", pub, "old", st.endpoint, "new", p.endpoint)
			st.endpoint = p.endpoint
		}
		if p.handshake != 0 && p.handshake != st.handshake {
			s.ev.Emit("handshake", "peer", name, "public_key", pub, "endpoint", p.endpoint,
				"at", time.Unix(0, p.handshake).UTC().Format(time.RFC3339Nano))
			st.handshake = p.handshake
		}
		if emitCounters {
			last := ""
			if p.handshake != 0 {
				last = time.Unix(0, p.handshake).UTC().Format(time.RFC3339Nano)
			}
			s.ev.Emit("counters", "peer", name, "endpoint", p.endpoint, "rx_bytes", p.rx, "tx_bytes", p.tx, "last_handshake", last)
		}
	}
	if emitCounters && (s.cfg.Chaos.active() || s.bind.counters.v6Disabled.Load() > 0) {
		s.ev.Emit("chaos_counters", s.bind.counterAttrs()...)
	}
}

func (s *Server) peerName(a netip.Addr) string {
	if n, ok := s.peersByIP[a.Unmap()]; ok {
		return n
	}
	return ""
}

func addrOf(a net.Addr) netip.Addr {
	if a == nil {
		return netip.Addr{}
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// serveUDP runs handler for each datagram; a non-nil reply is sent back.
func (s *Server) serveUDP(pc net.PacketConn, handler func(p []byte, src net.Addr) []byte) {
	s.addCloser(pc)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		buf := make([]byte, 65535)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				select {
				case <-s.stop:
					return
				default:
				}
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			if reply := handler(buf[:n], src); reply != nil {
				_, _ = pc.WriteTo(reply, src)
			}
		}
	}()
}

func (s *Server) serveHTTP(l net.Listener, h httpHandler) {
	srv := newHTTPServer(h)
	s.addCloser(srv)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		_ = srv.Serve(l)
	}()
}

func (s *Server) startTunnelServices() error {
	addrs := []netip.Addr{s.cfg.Server4}
	if s.cfg.Server6.IsValid() {
		addrs = append(addrs, s.cfg.Server6)
	}
	dnsA := dnsAnswerer{answer4: s.cfg.Server4, answer6: s.cfg.Server6, testZoneOn: true}
	for _, a := range addrs {
		for _, port := range []uint16{tunnelHTTPPort, tunnelMarkerPort} {
			l, err := s.tnet.ListenTCPAddrPort(netip.AddrPortFrom(a, port))
			if err != nil {
				return fmt.Errorf("in-tunnel HTTP %s: %w", netip.AddrPortFrom(a, port), err)
			}
			s.serveHTTP(l, s.tunnelHandler())
		}
		// The in-tunnel resolver also answers on the marker DNS port so the
		// same probe target port works on both homes.
		markerDNS := uint16(defaultMarkerDNSPort)
		if s.cfg.MarkerDNSPort > 0 {
			markerDNS = uint16(s.cfg.MarkerDNSPort)
		}
		dnsPorts := []uint16{tunnelDNSPort}
		if markerDNS != tunnelDNSPort {
			dnsPorts = append(dnsPorts, markerDNS)
		}
		for _, port := range dnsPorts {
			pc, err := s.tnet.ListenUDPAddrPort(netip.AddrPortFrom(a, port))
			if err != nil {
				return fmt.Errorf("in-tunnel DNS: %w", err)
			}
			s.serveUDP(pc, s.dnsHandler("in_tunnel", netip.AddrPortFrom(a, port).String(), dnsA))
		}
		echo, err := s.tnet.ListenUDPAddrPort(netip.AddrPortFrom(a, tunnelEchoPort))
		if err != nil {
			return fmt.Errorf("in-tunnel UDP echo: %w", err)
		}
		s.serveUDP(echo, func(p []byte, src net.Addr) []byte {
			s.udpMarker("in_tunnel", p, src, netip.AddrPortFrom(a, tunnelEchoPort))
			return append([]byte(nil), p...)
		})
		mk, err := s.tnet.ListenUDPAddrPort(netip.AddrPortFrom(a, tunnelMarkerPort))
		if err != nil {
			return fmt.Errorf("in-tunnel UDP marker: %w", err)
		}
		s.serveUDP(mk, func(p []byte, src net.Addr) []byte {
			s.udpMarker("in_tunnel", p, src, netip.AddrPortFrom(a, tunnelMarkerPort))
			return nil
		})
	}
	return nil
}

func (s *Server) marker(scope, proto, nonce string, src netip.Addr, listener string) {
	attrs := []any{"scope", scope, "proto", proto, "nonce", nonce, "src", src.String(), "listener", listener}
	if scope == "in_tunnel" {
		attrs = append(attrs, "peer", s.peerName(src))
		s.ev.Emit("marker", attrs...)
		return
	}
	// Outside-tunnel markers are the leak evidence: logged at warn so they
	// survive --log-level warn.
	s.ev.Warn("marker", attrs...)
}

func (s *Server) udpMarker(scope string, p []byte, src net.Addr, listener netip.AddrPort) {
	if n, ok := udpMarkerNonce(p); ok {
		s.marker(scope, "udp", n, addrOf(src), listener.String())
	}
}

func (s *Server) dnsHandler(scope, listener string, a dnsAnswerer) func([]byte, net.Addr) []byte {
	return func(p []byte, src net.Addr) []byte {
		out, res, ok := a.handle(p)
		if !ok {
			return nil
		}
		ip := addrOf(src)
		attrs := []any{"scope", scope, "name", res.name, "qtype", res.qtype, "rcode", res.rcode, "src", ip.String()}
		if scope == "in_tunnel" {
			attrs = append(attrs, "peer", s.peerName(ip))
		}
		s.ev.Emit("dns_query", attrs...)
		if res.marker {
			s.marker(scope, "dns", res.nonce, ip, listener)
		}
		return out
	}
}

func (s *Server) startMarkerListeners() error {
	for _, ap := range s.cfg.MarkerListen {
		tcpNet, udpNet := "tcp4", "udp4"
		if ap.Addr().Is6() {
			tcpNet, udpNet = "tcp6", "udp6"
		}
		l, err := net.Listen(tcpNet, ap.String())
		if err != nil {
			return fmt.Errorf("marker HTTP %s: %w", ap, err)
		}
		bound := netip.AddrPortFrom(ap.Addr(), uint16(l.Addr().(*net.TCPAddr).Port))
		s.serveHTTP(l, s.markerHandler(bound.String()))
		pc, err := net.ListenPacket(udpNet, bound.String())
		if err != nil {
			return fmt.Errorf("marker UDP %s: %w", bound, err)
		}
		s.serveUDP(pc, func(p []byte, src net.Addr) []byte {
			if n, ok := udpMarkerNonce(p); ok {
				s.marker("outside_tunnel", "udp", n, addrOf(src), bound.String())
			}
			return nil
		})
		s.markerHTTP = append(s.markerHTTP, bound)

		if s.cfg.MarkerDNSPort < 0 {
			continue
		}
		dpc, err := net.ListenPacket(udpNet, netip.AddrPortFrom(ap.Addr(), uint16(s.cfg.MarkerDNSPort)).String())
		if err != nil {
			return fmt.Errorf("marker DNS %s port %d: %w", ap.Addr(), s.cfg.MarkerDNSPort, err)
		}
		dbound := netip.AddrPortFrom(ap.Addr(), uint16(dpc.LocalAddr().(*net.UDPAddr).Port))
		ans := dnsAnswerer{}
		if ap.Addr().Is4() {
			ans.answer4 = ap.Addr()
		} else {
			ans.answer6 = ap.Addr()
		}
		s.serveUDP(dpc, s.dnsHandler("outside_tunnel", dbound.String(), ans))
		s.markerDNS = append(s.markerDNS, dbound)
	}
	return nil
}

// waitStop blocks until ctx is done.
func (s *Server) waitStop(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-s.stop:
	}
}
