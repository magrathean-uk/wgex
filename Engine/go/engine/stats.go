// SPDX-License-Identifier: MIT

package engine

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"slices"
	"strconv"
	"time"
)

// uapiPeer is one peer of an IpcGetOperation dump, without secrets.
type uapiPeer struct {
	PublicKey [32]byte
	Endpoint  string // literal ip:port, "" if none
	HSSec     int64
	HSNsec    int64
	RxBytes   uint64
	TxBytes   uint64
	Keepalive uint32
}

// uapiState is the secret-free subset of an IpcGetOperation dump.
type uapiState struct {
	ListenPort uint16
	Peers      []uapiPeer
}

// getCollector is the io.Writer given to IpcGetOperation. It parses lines in
// place as they arrive and keeps nothing but the secret-free fields:
// private_key and preshared_key lines are skipped without being copied. A
// line split across two writes is carried over and wiped after use.
type getCollector struct {
	st      uapiState
	cur     *uapiPeer
	partial []byte
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (c *getCollector) Write(p []byte) (int, error) {
	n := len(p)
	if len(c.partial) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			c.partial = append(c.partial, p...)
			return n, nil
		}
		c.partial = append(c.partial, p[:i]...)
		c.line(c.partial)
		wipe(c.partial)
		c.partial = c.partial[:0]
		p = p[i+1:]
	}
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			c.partial = append(c.partial, p...)
			break
		}
		c.line(p[:i])
		p = p[i+1:]
	}
	return n, nil
}

// finish flushes a final unterminated line and returns the state.
func (c *getCollector) finish() uapiState {
	if len(c.partial) > 0 {
		c.line(c.partial)
		wipe(c.partial)
		c.partial = nil
	}
	c.flushPeer()
	return c.st
}

func (c *getCollector) flushPeer() {
	if c.cur != nil {
		c.st.Peers = append(c.st.Peers, *c.cur)
		c.cur = nil
	}
}

func (c *getCollector) line(l []byte) {
	key, value, ok := bytes.Cut(l, []byte{'='})
	if !ok {
		return
	}
	switch string(key) {
	case "private_key", "preshared_key":
		return
	case "public_key":
		c.flushPeer()
		var pk [32]byte
		if len(value) != 64 {
			return
		}
		if _, err := hex.Decode(pk[:], value); err != nil {
			return
		}
		c.cur = &uapiPeer{PublicKey: pk}
		return
	case "listen_port":
		if c.cur == nil {
			if v, err := strconv.ParseUint(string(value), 10, 16); err == nil {
				c.st.ListenPort = uint16(v)
			}
		}
		return
	}
	if c.cur == nil {
		return
	}
	switch string(key) {
	case "endpoint":
		if ap, err := netip.ParseAddrPort(string(value)); err == nil {
			c.cur.Endpoint = ap.String()
		}
	case "last_handshake_time_sec":
		c.cur.HSSec, _ = strconv.ParseInt(string(value), 10, 64)
	case "last_handshake_time_nsec":
		c.cur.HSNsec, _ = strconv.ParseInt(string(value), 10, 64)
	case "rx_bytes":
		c.cur.RxBytes, _ = strconv.ParseUint(string(value), 10, 64)
	case "tx_bytes":
		c.cur.TxBytes, _ = strconv.ParseUint(string(value), 10, 64)
	case "persistent_keepalive_interval":
		v, _ := strconv.ParseUint(string(value), 10, 16)
		c.cur.Keepalive = uint32(v)
	}
}

// parseUAPIGet parses a complete dump (tests and fuzzing).
func parseUAPIGet(b []byte) uapiState {
	var c getCollector
	_, _ = c.Write(b)
	return c.finish()
}

// lastHandshake returns the wall-clock handshake time, or the zero time.
func (p uapiPeer) lastHandshake() time.Time {
	if p.HSSec == 0 && p.HSNsec == 0 {
		return time.Time{}
	}
	return time.Unix(p.HSSec, p.HSNsec).UTC()
}

func (p uapiPeer) publicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(p.PublicKey[:])
}

// PublicStats is the public statistics DTO (02-architecture §3), as JSON.
// It has no field that could carry a private or preshared key.
type PublicStats struct {
	InterfaceName string       `json:"interface_name,omitempty"`
	ListenPort    uint16       `json:"listen_port,omitempty"`
	SampledAt     string       `json:"sampled_at"`
	Peers         []PublicPeer `json:"peers"`
}

// PublicPeer is one peer's public statistics.
type PublicPeer struct {
	// PublicKey is standard base64 (Swift decodes Data as base64).
	PublicKey string `json:"public_key"`
	// Endpoint is the engine-observed (roaming) endpoint.
	Endpoint string `json:"endpoint,omitempty"`
	// LastHandshakeTime is RFC 3339 with nanoseconds, UTC; omitted before the
	// first handshake.
	LastHandshakeTime           string `json:"last_handshake_time,omitempty"`
	RxBytes                     uint64 `json:"rx_bytes"`
	TxBytes                     uint64 `json:"tx_bytes"`
	PersistentKeepaliveInterval uint32 `json:"persistent_keepalive_interval,omitempty"`
}

// publicStatsJSON builds the public statistics document from a dump.
func publicStatsJSON(st uapiState, ifname string, now time.Time) ([]byte, error) {
	out := PublicStats{
		InterfaceName: ifname,
		ListenPort:    st.ListenPort,
		SampledAt:     now.UTC().Format(time.RFC3339Nano),
		Peers:         make([]PublicPeer, 0, len(st.Peers)),
	}
	for _, p := range st.Peers {
		pp := PublicPeer{
			PublicKey:                   p.publicKeyBase64(),
			Endpoint:                    p.Endpoint,
			RxBytes:                     p.RxBytes,
			TxBytes:                     p.TxBytes,
			PersistentKeepaliveInterval: p.Keepalive,
		}
		if t := p.lastHandshake(); !t.IsZero() {
			pp.LastHandshakeTime = t.Format(time.RFC3339Nano)
		}
		out.Peers = append(out.Peers, pp)
	}
	slices.SortFunc(out.Peers, func(a, b PublicPeer) int {
		switch {
		case a.PublicKey < b.PublicKey:
			return -1
		case a.PublicKey > b.PublicKey:
			return 1
		}
		return 0
	})
	return json.Marshal(out)
}
