// SPDX-License-Identifier: MIT

// Command testpeer is the WGEX userspace WireGuard test peer. It runs
// unprivileged: wireguard-go on a gVisor netstack (no utun, routes or pf),
// ordinary UDP/TCP sockets for WireGuard and the marker listener. See
// README.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*l = append(*l, p)
		}
	}
	return nil
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

type options struct {
	listen, markerListen, dropFrom          listFlag
	clientKeyFiles                          listFlag
	keyFile, publicAddress, outDir          string
	printKeys, ipv6, jsonOut                bool
	peers, mtu, markerDNSPort               int
	innerCIDR, innerCIDR6, clientAllowedIPs string
	allowOnlyFrom, logLevel                 string
	dropAfter, loss                         float64
	latencyMS                               int
	counterInterval                         time.Duration
}

func parseFlags(args []string, stderr io.Writer) (*options, error) {
	o := &options{}
	fs := flag.NewFlagSet("testpeer", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Var(&o.listen, "listen", "WireGuard UDP `addr:port`, repeatable; 0.0.0.0 uses the default dual-stack bind (default 0.0.0.0:51820)")
	fs.StringVar(&o.keyFile, "key-file", "", "server private key file (base64 or a PrivateKey = line); absent: ephemeral key")
	fs.BoolVar(&o.printKeys, "print-keys", false, "print secrets (server private key, client .conf and terminal QR) to stderr")
	fs.IntVar(&o.peers, "peers", 0, "number of client key pairs to generate")
	fs.Var(&o.clientKeyFiles, "client-key-file", "fixed client public key `file` (base64 or a PublicKey = line), repeatable; added before generated peers, no .conf written")
	fs.StringVar(&o.publicAddress, "public-address", "", "server `ip` written into client Endpoint lines (required with --peers > 0)")
	fs.StringVar(&o.outDir, "out-dir", "", "directory for client .conf and .png QR files (mode 0600)")
	fs.StringVar(&o.innerCIDR, "inner-cidr", "10.77.0.0/24", "inner IPv4 range; the server takes the first host")
	fs.StringVar(&o.innerCIDR6, "inner-cidr6", "fd77:6765:7800::/64", "inner IPv6 ULA range used with --ipv6")
	fs.BoolVar(&o.ipv6, "ipv6", false, "add the ULA inner range and accept WireGuard over IPv6")
	fs.IntVar(&o.mtu, "mtu", defaultMTU, "tunnel MTU")
	fs.StringVar(&o.clientAllowedIPs, "client-allowed-ips", "", "AllowedIPs written into client configs (default 0.0.0.0/0, plus ::/0 with --ipv6)")
	fs.Var(&o.markerListen, "marker-listen", "clear-text marker listener `ip:port` (HTTP and UDP), repeatable; off by default")
	fs.IntVar(&o.markerDNSPort, "marker-dns-port", defaultMarkerDNSPort, "UDP port of the marker DNS listener on each --marker-listen ip (5353 is taken by mDNSResponder on macOS); -1 disables")
	fs.Var(&o.dropFrom, "drop-udp-from", "drop inbound WireGuard UDP from this `cidr`, repeatable")
	fs.StringVar(&o.allowOnlyFrom, "allow-udp-only-from", "", "drop inbound WireGuard UDP from every source except this `ip` (or cidr)")
	fs.Float64Var(&o.dropAfter, "drop-udp-after", 0, "DEPRECATED: drop all WireGuard UDP after `seconds`, relay traffic included; use the source-scoped flags")
	fs.Float64Var(&o.loss, "loss", 0, "random loss `pct` applied to WireGuard UDP in each direction")
	fs.IntVar(&o.latencyMS, "latency", 0, "`ms` added to outbound WireGuard UDP")
	fs.DurationVar(&o.counterInterval, "counters-interval", 5*time.Second, "interval of counters events")
	fs.StringVar(&o.logLevel, "log-level", "info", "debug, info, warn or error")
	fs.BoolVar(&o.jsonOut, "json", true, "JSON event log on stdout (false: logfmt text)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	if len(o.listen) == 0 {
		o.listen = listFlag{"0.0.0.0:51820"}
	}
	return o, nil
}

func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// hosts returns the first n+1 host addresses after the network address.
func hosts(p netip.Prefix, n int) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, n+1)
	a := p.Masked().Addr()
	for range n + 1 {
		a = a.Next()
		if !a.IsValid() || !p.Contains(a) {
			return nil, fmt.Errorf("%s is too small for the server and %d peers", p, n)
		}
		out = append(out, a)
	}
	if p.Addr().Is4() && !p.Contains(a.Next()) {
		return nil, fmt.Errorf("%s is too small for the server and %d peers", p, n) // last would be broadcast
	}
	return out, nil
}

func buildConfig(o *options) (Config, error) {
	cfg := Config{IPv6: o.ipv6, MTU: o.mtu, MarkerDNSPort: o.markerDNSPort, CounterInterval: o.counterInterval}
	for _, l := range o.listen {
		ap, err := netip.ParseAddrPort(l)
		if err != nil {
			return cfg, fmt.Errorf("--listen %q: %w", l, err)
		}
		cfg.Listen = append(cfg.Listen, unmapAddrPort(ap))
	}
	for _, l := range o.markerListen {
		ap, err := netip.ParseAddrPort(l)
		if err != nil {
			return cfg, fmt.Errorf("--marker-listen %q: %w", l, err)
		}
		if ap.Addr().IsUnspecified() {
			return cfg, fmt.Errorf("--marker-listen %q: use a specific address (the DNS listener answers with it)", l)
		}
		cfg.MarkerListen = append(cfg.MarkerListen, unmapAddrPort(ap))
	}
	if o.markerDNSPort > 65535 {
		return cfg, errors.New("--marker-dns-port out of range")
	}
	for _, d := range o.dropFrom {
		p, err := parsePrefixOrAddr(d)
		if err != nil {
			return cfg, fmt.Errorf("--drop-udp-from %q: %w", d, err)
		}
		cfg.Chaos.DropFrom = append(cfg.Chaos.DropFrom, p)
	}
	if o.allowOnlyFrom != "" {
		p, err := parsePrefixOrAddr(o.allowOnlyFrom)
		if err != nil {
			return cfg, fmt.Errorf("--allow-udp-only-from: %w", err)
		}
		cfg.Chaos.AllowOnlyFrom = []netip.Prefix{p}
	}
	if o.loss < 0 || o.loss > 100 {
		return cfg, errors.New("--loss must be 0..100")
	}
	if o.dropAfter < 0 || o.latencyMS < 0 || o.mtu < 576 || o.mtu > 65535 || o.counterInterval <= 0 {
		return cfg, errors.New("negative or out-of-range --drop-udp-after, --latency, --mtu or --counters-interval")
	}
	cfg.Chaos.LossPct = o.loss
	cfg.Chaos.Latency = time.Duration(o.latencyMS) * time.Millisecond
	cfg.Chaos.DropAfter = time.Duration(o.dropAfter * float64(time.Second))
	return cfg, nil
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	o, err := parseFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "testpeer:", err)
		return 2
	}
	level, ok := parseLevel(o.logLevel)
	if !ok {
		fmt.Fprintln(stderr, "testpeer: unknown --log-level", o.logLevel)
		return 2
	}
	ev := newEvents(stdout, o.jsonOut, level)
	if err := runServer(ctx, o, ev, stderr); err != nil {
		ev.Error("fatal", "error", err.Error())
		return 1
	}
	return 0
}

func runServer(ctx context.Context, o *options, ev *Events, stderr io.Writer) error {
	cfg, err := buildConfig(o)
	if err != nil {
		return err
	}
	cfg.Events = ev
	if o.peers < 0 {
		return errors.New("--peers must be >= 0")
	}
	var public netip.Addr
	if o.peers > 0 {
		if o.publicAddress == "" {
			return errors.New("--public-address is required to write client configs")
		}
		if public, err = netip.ParseAddr(o.publicAddress); err != nil {
			return fmt.Errorf("--public-address: %w", err)
		}
		if o.outDir == "" && !o.printKeys {
			return errors.New("generated client keys need --out-dir or --print-keys")
		}
	}

	keySource := "file"
	if o.keyFile != "" {
		if cfg.PrivateKey, err = readKeyFile(o.keyFile); err != nil {
			return fmt.Errorf("--key-file: %w", err)
		}
	} else {
		keySource = "ephemeral"
		if cfg.PrivateKey, err = generatePrivateKey(); err != nil {
			return err
		}
	}
	serverPub, err := cfg.PrivateKey.Public()
	if err != nil {
		return err
	}

	in4, err := netip.ParsePrefix(o.innerCIDR)
	if err != nil || !in4.Addr().Is4() {
		return fmt.Errorf("--inner-cidr %q is not an IPv4 prefix", o.innerCIDR)
	}
	h4, err := hosts(in4, len(o.clientKeyFiles)+o.peers)
	if err != nil {
		return err
	}
	cfg.Server4 = h4[0]
	var h6 []netip.Addr
	if o.ipv6 {
		in6, err := netip.ParsePrefix(o.innerCIDR6)
		if err != nil || !in6.Addr().Is6() {
			return fmt.Errorf("--inner-cidr6 %q is not an IPv6 prefix", o.innerCIDR6)
		}
		if h6, err = hosts(in6, len(o.clientKeyFiles)+o.peers); err != nil {
			return err
		}
		cfg.Server6 = h6[0]
	}

	// Fixed clients (--client-key-file) take the first client addresses; the
	// test client holds the matching private key, so no .conf is written.
	fixed := make([]clientConf, len(o.clientKeyFiles))
	for i, path := range o.clientKeyFiles {
		pub, err := readPublicKeyFile(path)
		if err != nil {
			return fmt.Errorf("--client-key-file: %w", err)
		}
		c := clientConf{Name: fmt.Sprintf("fixed-%d", i+1), Public: pub, Addrs: []netip.Addr{h4[i+1]}}
		if o.ipv6 {
			c.Addrs = append(c.Addrs, h6[i+1])
		}
		fixed[i] = c
		cfg.Peers = append(cfg.Peers, PeerSpec{Name: c.Name, PublicKey: pub, Addrs: c.Addrs})
	}
	clients := make([]clientConf, o.peers)
	for i := range clients {
		priv, err := generatePrivateKey()
		if err != nil {
			return err
		}
		pub, err := priv.Public()
		if err != nil {
			return err
		}
		n := len(fixed) + i + 1
		c := clientConf{Name: fmt.Sprintf("client-%d", i+1), Private: priv, Public: pub, Addrs: []netip.Addr{h4[n]}}
		if o.ipv6 {
			c.Addrs = append(c.Addrs, h6[n])
		}
		clients[i] = c
		cfg.Peers = append(cfg.Peers, PeerSpec{Name: c.Name, PublicKey: pub, Addrs: c.Addrs})
	}

	if cfg.Chaos.DropAfter > 0 {
		ev.Warn("deprecated_flag", "flag", "--drop-udp-after", "note", "applies to every source including relay-forwarded traffic; prefer --drop-udp-from or --allow-udp-only-from")
	}

	srv, err := StartServer(cfg)
	if err != nil {
		return err
	}
	defer srv.Close()

	ev.Emit("started", "listen", o.listen.String(), "port", srv.Port(), "public_key", serverPub.String(), "key_source", keySource,
		"server_ipv4", cfg.Server4.String(), "server_ipv6", addrString(cfg.Server6), "mtu", cfg.MTU, "peers", len(cfg.Peers))
	if cfg.Chaos.active() {
		ev.Emit("chaos_config", "drop_udp_from", o.dropFrom.String(), "allow_udp_only_from", o.allowOnlyFrom,
			"drop_udp_after_s", o.dropAfter, "loss_pct", o.loss, "latency_ms", o.latencyMS)
	}
	httpUDP, dns := srv.MarkerAddrs()
	for i, a := range httpUDP {
		attrs := []any{"http_udp", a.String()}
		if i < len(dns) {
			attrs = append(attrs, "dns", dns[i].String())
		}
		ev.Emit("marker_listener", attrs...)
	}
	for _, c := range fixed {
		ev.Emit("client", "peer", c.Name, "public_key", c.Public.String(), "addresses", fmt.Sprint(c.Addrs), "key_source", "file")
	}
	if o.printKeys {
		fmt.Fprintf(stderr, "# SECRET: server private key (%s)\n%s\n", keySource, cfg.PrivateKey)
	}

	if len(clients) > 0 {
		dnsServers := []netip.Addr{cfg.Server4}
		allowed := []string{"0.0.0.0/0"}
		if o.ipv6 {
			dnsServers = append(dnsServers, cfg.Server6)
			allowed = append(allowed, "::/0")
		}
		if o.clientAllowedIPs != "" {
			allowed = strings.Split(o.clientAllowedIPs, ",")
			for i := range allowed {
				allowed[i] = strings.TrimSpace(allowed[i])
				if _, err := netip.ParsePrefix(allowed[i]); err != nil {
					return fmt.Errorf("--client-allowed-ips: %w", err)
				}
			}
		}
		params := confParams{ServerPublic: serverPub, Endpoint: netip.AddrPortFrom(public, srv.Port()), DNS: dnsServers, AllowedIPs: allowed, MTU: cfg.MTU}
		for _, c := range clients {
			conf := c.render(params)
			attrs := []any{"peer", c.Name, "public_key", c.Public.String(), "addresses", fmt.Sprint(c.Addrs)}
			if o.outDir != "" {
				confPath, pngPath, err := writeClientFiles(o.outDir, c.Name, conf)
				if err != nil {
					return fmt.Errorf("writing client files: %w", err)
				}
				attrs = append(attrs, "conf", confPath, "qr_png", pngPath)
			}
			ev.Emit("client", attrs...)
			if o.printKeys {
				qr, err := terminalQR(conf)
				if err != nil {
					return err
				}
				fmt.Fprintf(stderr, "# SECRET: %s.conf\n%s\n%s\n", c.Name, conf, qr)
			}
		}
	}

	srv.waitStop(ctx)
	ev.Emit("stopping")
	return nil
}

func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}
