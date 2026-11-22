// SPDX-License-Identifier: MIT

//go:build wgextest

package testsupport

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	wgtun "golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/magrathean-uk/wgex/engine/cabi"
	"github.com/magrathean-uk/wgex/engine/engine"
	"github.com/magrathean-uk/wgex/engine/internal/testkeys"
)

// PairConfig is the wgex_test_pair_create JSON document. Every field is
// optional.
type PairConfig struct {
	// Addresses are the in-tunnel addresses of side A and B
	// (default 10.99.0.1 and 10.99.0.2).
	Addresses []string `json:"addresses"`
	// MTU of both netstack tuns (default 1420).
	MTU int `json:"mtu"`
	// Keepalive is the persistent keepalive interval in seconds (default 0).
	Keepalive int `json:"keepalive"`
	// Configure applies keys, peers, listen ports and endpoints (default true).
	Configure *bool `json:"configure"`
	// Up brings both engines up after configuring (default true).
	Up *bool `json:"up"`
}

// Pair is two engines over loopback UDP with netstack tuns, each serving
// HTTP on port 80 of its in-tunnel address.
type Pair struct {
	ID        int64     `json:"pair"`
	Handles   [2]int64  `json:"handles"`
	Addresses [2]string `json:"addresses"`
	// PublicKeys are standard base64.
	PublicKeys [2]string `json:"public_keys"`
	// ListenPorts are the loopback UDP ports (0 when not configured).
	ListenPorts [2]uint16 `json:"listen_ports"`
	// UAPI are the full documents applied to each side (throwaway test keys).
	UAPI [2]string `json:"uapi"`

	nets    [2]*netstack.Net
	tuns    [2]*faultTUN
	servers [2]*http.Server
}

var pairs = struct {
	sync.Mutex
	next int64
	m    map[int64]*Pair
}{m: map[int64]*Pair{}}

func boolOr(p *bool, d bool) bool {
	if p == nil {
		return d
	}
	return *p
}

type keyPair struct{ priv, pub [32]byte }

func newKeyPair(index int) (keyPair, error) {
	priv, pub, err := testkeys.Load(index)
	return keyPair{priv: priv, pub: pub}, err
}

type faultTUN struct {
	wgtun.Device
	injected  atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

// Close is idempotent even when fault injection races upstream's error shutdown.
func (t *faultTUN) Close() error {
	t.closeOnce.Do(func() { t.closeErr = t.Device.Close() })
	return t.closeErr
}

func (t *faultTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.Device.Read(bufs, sizes, offset)
	if t.injected.Load() {
		return 0, errors.New("injected tun read failure")
	}
	return n, err
}

// FailTUNRead closes the test-only netstack descriptor, making upstream Read fail.
func (p *Pair) FailTUNRead(side int) bool {
	if side < 0 || side > 1 || p.tuns[side] == nil {
		return false
	}
	p.tuns[side].injected.Store(true)
	_ = p.tuns[side].Close()
	return true
}

func fullDoc(self, peer keyPair, port uint16, peerAddr netip.Addr, endpoint string, keepalive int) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "private_key=%s\nlisten_port=%d\nreplace_peers=true\n", hex.EncodeToString(self.priv[:]), port)
	fmt.Fprintf(&b, "public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s\n", hex.EncodeToString(peer.pub[:]), netip.PrefixFrom(peerAddr, peerAddr.BitLen()))
	if endpoint != "" {
		fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	}
	if keepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", keepalive)
	}
	return b.Bytes()
}

func listenPort(h int64) (uint16, error) {
	b := cabi.PublicStatsJSON(h)
	if b == nil {
		return 0, errors.New("no statistics")
	}
	var st engine.PublicStats
	if err := json.Unmarshal(b, &st); err != nil {
		return 0, err
	}
	return st.ListenPort, nil
}

func codeErr(step string, c int32) error {
	if c == 0 {
		return nil
	}
	return fmt.Errorf("%s: wgex error %d", step, c)
}

// CreatePair builds a pair. pa and pb point to optional wgex_create_params
// (callbacks, bind indexes, transport); their tun fields are ignored.
func CreatePair(cfgJSON []byte, pa, pb unsafe.Pointer) (*Pair, error) {
	var cfg PairConfig
	if len(bytes.TrimSpace(cfgJSON)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(cfgJSON))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil {
			return nil, fmt.Errorf("pair config: %w", err)
		}
	}
	if len(cfg.Addresses) == 0 {
		cfg.Addresses = []string{"10.99.0.1", "10.99.0.2"}
	}
	if len(cfg.Addresses) != 2 {
		return nil, errors.New("pair config: need two addresses")
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1420
	}
	var addrs [2]netip.Addr
	for i, s := range cfg.Addresses {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("pair config: address %d: %w", i, err)
		}
		addrs[i] = a
	}
	keys := [2]keyPair{}
	for i := range keys {
		var err error
		if keys[i], err = newKeyPair(i); err != nil {
			return nil, err
		}
	}

	p := &Pair{}
	params := [2]unsafe.Pointer{pa, pb}
	for i := range 2 {
		t, n, err := netstack.CreateNetTUN([]netip.Addr{addrs[i]}, nil, cfg.MTU)
		if err != nil {
			p.destroy()
			return nil, fmt.Errorf("netstack %d: %w", i, err)
		}
		p.tuns[i] = &faultTUN{Device: t}
		h := cabi.CreateWithTUN(params[i], p.tuns[i])
		if h < 0 {
			p.destroy()
			return nil, fmt.Errorf("create %d: wgex error %d", i, h)
		}
		p.Handles[i], p.nets[i] = h, n
		p.Addresses[i] = addrs[i].String()
		p.PublicKeys[i] = base64.StdEncoding.EncodeToString(keys[i].pub[:])
		if err := p.serve(i, addrs[i]); err != nil {
			p.destroy()
			return nil, err
		}
	}

	if boolOr(cfg.Configure, true) {
		if err := p.configure(keys, addrs, cfg.Keepalive, boolOr(cfg.Up, true)); err != nil {
			p.destroy()
			return nil, err
		}
	}

	pairs.Lock()
	pairs.next++
	p.ID = pairs.next
	pairs.m[p.ID] = p
	pairs.Unlock()
	return p, nil
}

func (p *Pair) configure(keys [2]keyPair, addrs [2]netip.Addr, keepalive int, up bool) error {
	// Bind both sides on kernel-chosen loopback ports first, then apply the
	// final documents with those ports and each other's endpoint.
	for i := range 2 {
		doc := fullDoc(keys[i], keys[1-i], 0, addrs[1-i], "", 0)
		if err := codeErr("set_config", cabi.SetConfig(p.Handles[i], doc)); err != nil {
			return err
		}
		if err := codeErr("up", cabi.Up(p.Handles[i])); err != nil {
			return err
		}
		port, err := listenPort(p.Handles[i])
		if err != nil {
			return err
		}
		p.ListenPorts[i] = port
	}
	for i := range 2 {
		ep := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), p.ListenPorts[1-i]).String()
		doc := fullDoc(keys[i], keys[1-i], p.ListenPorts[i], addrs[1-i], ep, keepalive)
		p.UAPI[i] = string(doc)
		if err := codeErr("set_config", cabi.SetConfig(p.Handles[i], doc)); err != nil {
			return err
		}
		if !up {
			if err := codeErr("down", cabi.Down(p.Handles[i])); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *Pair) serve(i int, addr netip.Addr) error {
	l, err := p.nets[i].ListenTCPAddrPort(netip.AddrPortFrom(addr, 80))
	if err != nil {
		return fmt.Errorf("listen %d: %w", i, err)
	}
	side := string(rune('a' + i))
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "wgex-test "+side+"\n")
	})
	mux.HandleFunc("/ip", func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		_, _ = io.WriteString(w, host+"\n")
	})
	mux.HandleFunc("/bytes", func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(r.URL.Query().Get("n"))
		if err != nil || n < 0 || n > 16<<20 {
			http.Error(w, "n must be 0...16777216", http.StatusBadRequest)
			return
		}
		_, _ = w.Write(bytes.Repeat([]byte{'x'}, n))
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	p.servers[i] = srv
	go func() { _ = srv.Serve(l) }()
	return nil
}

// HTTPResult is the wgex_test_pair_http_get document.
type HTTPResult struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
	Error  string `json:"error,omitempty"`
}

// HTTPGet requests path from the other side through side from's tunnel.
func (p *Pair) HTTPGet(from int, path string, timeout time.Duration) HTTPResult {
	if from != 0 && from != 1 {
		return HTTPResult{Error: "side must be 0 or 1"}
	}
	tnet := p.nets[from]
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:       tnet.DialContext,
			DisableKeepAlives: true,
		},
	}
	resp, err := client.Get("http://" + net.JoinHostPort(p.Addresses[1-from], "80") + path)
	if err != nil {
		return HTTPResult{Error: err.Error()}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	res := HTTPResult{Status: resp.StatusCode, Body: string(body)}
	if err != nil {
		res.Error = err.Error()
	}
	return res
}

func (p *Pair) destroy() {
	for _, s := range p.servers {
		if s != nil {
			_ = s.Close()
		}
	}
	for _, h := range p.Handles {
		if h > 0 {
			cabi.Destroy(h)
		}
	}
}

// LookupPair returns a live pair.
func LookupPair(id int64) (*Pair, bool) {
	pairs.Lock()
	defer pairs.Unlock()
	p, ok := pairs.m[id]
	return p, ok
}

// DestroyPair destroys both engines (if still alive) and the HTTP servers.
func DestroyPair(id int64) bool {
	pairs.Lock()
	p, ok := pairs.m[id]
	delete(pairs.m, id)
	pairs.Unlock()
	if !ok {
		return false
	}
	p.destroy()
	return true
}
