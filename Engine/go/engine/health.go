// SPDX-License-Identifier: MIT

package engine

import (
	"context"
	"time"
)

// Health timing (02-architecture §4.1). wireguard-go offers no hooks for
// handshakes or traffic, so the engine samples the counters IpcGetOperation
// exposes (tx_bytes, rx_bytes, last_handshake_time_*, endpoint) once per
// HealthPollInterval and derives the events from their deltas.
const (
	// HealthPollInterval is the sampling period.
	HealthPollInterval = time.Second
	// TxWithoutRxWindow is KeepaliveTimeout + RekeyTimeout: a peer that
	// received anything replies within KeepaliveTimeout, and an initiator
	// without a reply retries after RekeyTimeout.
	TxWithoutRxWindow = 15 * time.Second
	// RxEventInterval rate-limits rx events.
	RxEventInterval = 5 * time.Second
)

type peerHealth struct {
	tx, rx   uint64
	hs       time.Time
	endpoint string
	txSince  time.Time // first sample with tx growth and no rx since; zero if none pending
	windows  int       // txWithoutRx windows already reported for txSince
}

type healthTracker struct {
	window   time.Duration
	rxEvery  time.Duration
	peers    map[[32]byte]*peerHealth
	lastRx   time.Time
	lastSeen time.Time // wall time of the previous sample (tracker start before the first)
}

func newHealthTracker(window, rxEvery time.Duration, start time.Time) *healthTracker {
	return &healthTracker{window: window, rxEvery: rxEvery, peers: make(map[[32]byte]*peerHealth), lastSeen: start}
}

type txWithoutRxEvent struct {
	Kind   string `json:"kind"`
	Peer   string `json:"peer"`
	Since  string `json:"since"`
	Window int    `json:"window"`
}

type handshakeEvent struct {
	Kind string `json:"kind"`
	Peer string `json:"peer"`
	At   string `json:"at"`
}

type rxEvent struct {
	Kind string `json:"kind"`
	At   string `json:"at"`
}

type endpointEvent struct {
	Kind     string `json:"kind"`
	Peer     string `json:"peer"`
	Endpoint string `json:"endpoint"`
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// observe consumes one sample and reports events through emit.
//
//   - handshakeCompleted when a peer's last handshake time advances;
//   - txWithoutRx when tx_bytes grew (data, keepalive or handshake
//     initiation) and rx_bytes has not grown for window since the first such
//     sample, then again after every further window while it persists
//     (window 1, 2, ...), so the policy can count consecutive windows;
//   - rx when any peer's rx_bytes grew, at most once per rxEvery;
//   - endpointChanged when a peer's endpoint changes to a new non-empty value.
//
// A peer seen for the first time, or whose counters went backwards (it was
// replaced by a full configuration), starts a new baseline. Its counters all
// accrued since the previous sample, so a handshake newer than that sample is
// reported, rx > 0 counts as rx, and tx > 0 with rx == 0 starts a
// txWithoutRx window.
func (h *healthTracker) observe(now time.Time, st uapiState, emit func(EventKind, any)) {
	seen := make(map[[32]byte]bool, len(st.Peers))
	anyRx := false
	for _, p := range st.Peers {
		seen[p.PublicKey] = true
		hs := p.lastHandshake()
		ph, ok := h.peers[p.PublicKey]
		key := p.publicKeyBase64()
		if !ok || p.TxBytes < ph.tx || p.RxBytes < ph.rx {
			nph := &peerHealth{tx: p.TxBytes, rx: p.RxBytes, hs: hs, endpoint: p.Endpoint}
			h.peers[p.PublicKey] = nph
			if !hs.IsZero() && hs.After(h.lastSeen) {
				emit(EventHandshakeCompleted, handshakeEvent{Kind: "handshakeCompleted", Peer: key, At: rfc3339(hs)})
			}
			switch {
			case p.RxBytes > 0:
				anyRx = true
			case p.TxBytes > 0:
				nph.txSince = now
			}
			continue
		}
		if hs.After(ph.hs) {
			emit(EventHandshakeCompleted, handshakeEvent{Kind: "handshakeCompleted", Peer: key, At: rfc3339(hs)})
		}
		ph.hs = hs
		if p.Endpoint != "" && p.Endpoint != ph.endpoint {
			emit(EventEndpointChanged, endpointEvent{Kind: "endpointChanged", Peer: key, Endpoint: p.Endpoint})
		}
		ph.endpoint = p.Endpoint

		rxGrew, txGrew := p.RxBytes > ph.rx, p.TxBytes > ph.tx
		ph.rx, ph.tx = p.RxBytes, p.TxBytes
		switch {
		case rxGrew:
			anyRx = true
			ph.txSince, ph.windows = time.Time{}, 0
		case txGrew && ph.txSince.IsZero():
			ph.txSince = now
		}
		if !ph.txSince.IsZero() && now.Sub(ph.txSince) >= time.Duration(ph.windows+1)*h.window {
			ph.windows++
			emit(EventTxWithoutRx, txWithoutRxEvent{Kind: "txWithoutRx", Peer: key, Since: rfc3339(ph.txSince), Window: ph.windows})
		}
	}
	for k := range h.peers {
		if !seen[k] {
			delete(h.peers, k)
		}
	}
	if anyRx && (h.lastRx.IsZero() || now.Sub(h.lastRx) >= h.rxEvery) {
		h.lastRx = now
		emit(EventRx, rxEvent{Kind: "rx", At: rfc3339(now)})
	}
	h.lastSeen = now
}

// runHealth samples the device until ctx ends.
func (e *Engine) runHealth(ctx context.Context, interval time.Duration, h *healthTracker) {
	defer e.bg.Done()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			st, err := e.sample()
			if err != nil {
				continue
			}
			// Wall clock, comparable with wireguard-go's handshake times.
			h.observe(time.Now(), st, e.disp.event)
		}
	}
}
