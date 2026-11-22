// SPDX-License-Identifier: MIT

package engine

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestPairTrafficAndHealthEvents(t *testing.T) {
	p := newPair(t, fastOptions(), "")
	mustGet(t, p.a, p.b)
	mustGet(t, p.b, p.a)

	st := p.a.stats(t)
	if len(st.Peers) != 1 || st.Peers[0].LastHandshakeTime == "" || st.Peers[0].RxBytes == 0 || st.Peers[0].TxBytes == 0 {
		t.Fatalf("stats after traffic: %+v", st)
	}
	if st.Peers[0].Endpoint != loopback(p.b.port) {
		t.Fatalf("endpoint %q, want %q", st.Peers[0].Endpoint, loopback(p.b.port))
	}
	waitFor(t, 3*time.Second, "handshakeCompleted and rx events", func() bool {
		return len(p.a.rec.eventsOf(EventHandshakeCompleted)) > 0 && len(p.a.rec.eventsOf(EventRx)) > 0
	})
	hs := p.a.rec.eventsOf(EventHandshakeCompleted)[0]
	if hs["kind"] != "handshakeCompleted" || hs["peer"] != st.Peers[0].PublicKey || hs["at"] == "" {
		t.Fatalf("handshake event %v", hs)
	}
	if n := len(p.a.rec.eventsOf(EventTxWithoutRx)); n != 0 {
		t.Fatalf("%d txWithoutRx events on a healthy pair", n)
	}
}

func TestUpdateEndpointsKeepsSession(t *testing.T) {
	p := newPair(t, fastOptions(), "")
	mustGet(t, p.a, p.b)
	sent, recv := p.a.rec.count(logSentInit)+p.b.rec.count(logSentInit), p.a.rec.count(logRecvInit)+p.b.rec.count(logRecvInit)
	hs := p.a.stats(t).Peers[0].LastHandshakeTime

	doc := fmt.Appendf(nil, "public_key=%s\nupdate_only=true\nendpoint=%s\n", hexKey(p.b.key.pub), loopback(p.b.port))
	if err := p.a.e.UpdateEndpoints(doc); err != nil {
		t.Fatal(err)
	}
	mustGet(t, p.a, p.b)
	mustGet(t, p.b, p.a)
	if s, r := p.a.rec.count(logSentInit)+p.b.rec.count(logSentInit), p.a.rec.count(logRecvInit)+p.b.rec.count(logRecvInit); s != sent || r != recv {
		t.Fatalf("handshakes after update_endpoints: sent %d->%d, received %d->%d", sent, s, recv, r)
	}
	st := p.a.stats(t)
	if st.Peers[0].LastHandshakeTime != hs {
		t.Fatalf("last handshake changed: %s -> %s", hs, st.Peers[0].LastHandshakeTime)
	}

	// An unknown peer is ignored, not created.
	stranger := newKeyPair(t)
	doc = fmt.Appendf(nil, "public_key=%s\nupdate_only=true\nendpoint=127.0.0.1:9\n", hexKey(stranger.pub))
	if err := p.a.e.UpdateEndpoints(doc); err != nil {
		t.Fatal(err)
	}
	if n := len(p.a.stats(t).Peers); n != 1 {
		t.Fatalf("%d peers after update for an unknown key", n)
	}
	for _, bad := range []string{
		fmt.Sprintf("public_key=%s\nendpoint=127.0.0.1:9\n", hexKey(p.b.key.pub)),
		fmt.Sprintf("public_key=%s\nupdate_only=true\nallowed_ip=0.0.0.0/0\n", hexKey(p.b.key.pub)),
		fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=example.com:9\n", hexKey(p.b.key.pub)),
		"replace_peers=true\n",
	} {
		if err := p.a.e.UpdateEndpoints([]byte(bad)); CodeOf(err) != EINVAL {
			t.Errorf("update_endpoints(%q) = %v, want EINVAL", bad, err)
		}
	}
}

func TestForceHandshakeKeepsRoamedEndpoint(t *testing.T) {
	// B is configured with a wrong endpoint for A and learns A's real one by
	// roaming when A initiates.
	p := newPair(t, fastOptions(), "127.0.0.1:9")
	mustGet(t, p.a, p.b)
	roamed := loopback(p.a.port)
	waitFor(t, 2*time.Second, "B to roam to A's endpoint", func() bool {
		return p.b.stats(t).Peers[0].Endpoint == roamed
	})
	before := p.b.stats(t).Peers[0]
	sentB, recvA := p.b.rec.count(logSentInit), p.a.rec.count(logRecvInit)
	time.Sleep(10 * time.Millisecond) // handshake timestamps have wall-clock resolution

	if err := p.b.e.ForceHandshake(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "a new handshake initiated by B", func() bool {
		st := p.b.stats(t).Peers[0]
		return p.b.rec.count(logSentInit) > sentB && p.a.rec.count(logRecvInit) > recvA &&
			st.LastHandshakeTime > before.LastHandshakeTime
	})
	after := p.b.stats(t)
	if len(after.Peers) != 1 || after.Peers[0].Endpoint != roamed {
		t.Fatalf("after force_handshake: %+v, want one peer at %s", after.Peers, roamed)
	}
	if after.Peers[0].RxBytes < before.RxBytes {
		t.Fatalf("peer counters reset (rx %d -> %d): the peer was replaced", before.RxBytes, after.Peers[0].RxBytes)
	}
	mustGet(t, p.b, p.a)
}

func TestSetTransportUDPKeepsSession(t *testing.T) {
	p := newPair(t, fastOptions(), "")
	mustGet(t, p.a, p.b)
	sent := p.a.rec.count(logSentInit) + p.b.rec.count(logSentInit)

	if err := p.a.e.SetTransport([]byte(`{"kind":"udp"}`)); err != nil {
		t.Fatal(err)
	}
	if port := p.a.stats(t).ListenPort; port != p.a.port {
		t.Fatalf("listen port %d after rebind, want %d", port, p.a.port)
	}
	mustGet(t, p.a, p.b)
	mustGet(t, p.b, p.a)
	if s := p.a.rec.count(logSentInit) + p.b.rec.count(logSentInit); s != sent {
		t.Fatalf("handshake initiations %d -> %d after udp->udp", sent, s)
	}
	waitFor(t, time.Second, "transportChanged event", func() bool {
		for _, ev := range p.a.rec.eventsOf(EventEngine) {
			if ev["event"] == "transportChanged" {
				return true
			}
		}
		return false
	})
	for _, bad := range []string{`{"kind":"vless"}`, `{"kind":"udp","x":1}`, `not json`, `{"kind":"udp"} {}`} {
		if err := p.a.e.SetTransport([]byte(bad)); CodeOf(err) != EINVAL {
			t.Errorf("set_transport(%s) = %v, want EINVAL", bad, err)
		}
	}
}

// RT-03 (Go side): a rejected document restores the previous configuration
// and the device keeps running.
func TestSetConfigErrorRestoresPrevious(t *testing.T) {
	p := newPair(t, fastOptions(), "")
	mustGet(t, p.a, p.b)
	good := p.a.stats(t)

	cases := map[string][]byte{
		"invalid allowed_ip": p.a.doc(p.b, p.a.port, loopback(p.b.port), "allowed_ip=10.0.0.0/99\n"),
		"port in use":        p.a.doc(p.b, p.b.port, loopback(p.b.port), ""),
		"invalid keepalive":  p.a.doc(p.b, p.a.port, loopback(p.b.port), "persistent_keepalive_interval=70000\n"),
	}
	for name, doc := range cases {
		err := p.a.e.SetConfig(doc)
		if CodeOf(err) != ECONFIG {
			t.Fatalf("%s: set_config = %v, want ECONFIG", name, err)
		}
		st := p.a.stats(t)
		if st.ListenPort != good.ListenPort || len(st.Peers) != 1 || st.Peers[0].PublicKey != good.Peers[0].PublicKey ||
			st.Peers[0].Endpoint != good.Peers[0].Endpoint {
			t.Fatalf("%s: state after restore %+v, want %+v", name, st, good)
		}
		mustGet(t, p.a, p.b)
		mustGet(t, p.b, p.a)
	}
	waitFor(t, time.Second, "configRestored events", func() bool {
		restored := 0
		for _, ev := range p.a.rec.eventsOf(EventEngine) {
			if ev["event"] == "configRestored" {
				restored++
			}
		}
		return restored == len(cases)
	})

	// Shape errors are rejected before wireguard-go sees the document.
	for _, bad := range [][]byte{
		[]byte("private_key=" + hexKey(p.a.key.priv) + "\npublic_key=" + hexKey(p.b.key.pub) + "\n"), // no replace_peers
		[]byte("replace_peers=true\nupdate_only=true\n"),
		[]byte("replace_peers=true\nprivate_key\n"),
		[]byte("replace_peers=false\n"),
		[]byte("replace_peers=true\n\nlisten_port=1\n"),
		[]byte("replace_peers=true\npublic_key=zz\n"),
		{},
	} {
		if err := p.a.e.SetConfig(bad); CodeOf(err) != EINVAL {
			t.Errorf("set_config(%q) = %v, want EINVAL", bad, err)
		}
	}
	mustGet(t, p.a, p.b)
}

func TestBumpSocketsRebindsToLoopback(t *testing.T) {
	p := newPair(t, fastOptions(), "")
	mustGet(t, p.a, p.b)
	lo, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skip("no lo0")
	}
	if err := p.a.e.BumpSockets(uint32(lo.Index), uint32(lo.Index)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, "socketsBumped ok", func() bool {
		for _, ev := range p.a.rec.eventsOf(EventEngine) {
			if ev["event"] == "socketsBumped" && ev["ok"] == true {
				return true
			}
		}
		return false
	})
	if v4, v6 := p.a.e.udp.Interfaces(); v4 != uint32(lo.Index) || v6 != uint32(lo.Index) {
		t.Fatalf("interfaces %d/%d, want %d", v4, v6, lo.Index)
	}
	if port := p.a.stats(t).ListenPort; port != p.a.port {
		t.Fatalf("listen port %d, want %d", port, p.a.port)
	}
	mustGet(t, p.a, p.b)
	mustGet(t, p.b, p.a)
}

func TestTxWithoutRxWhenPeerVanishes(t *testing.T) {
	o := fastOptions()
	o.txWindow = 600 * time.Millisecond
	p := newPair(t, o, "")
	mustGet(t, p.a, p.b)
	p.b.e.Close()
	// Traffic towards the vanished peer: tx grows, rx does not.
	go func() { _ = get(p.a, p.b, 3*time.Second) }()
	waitFor(t, 5*time.Second, "two txWithoutRx windows", func() bool {
		return len(p.a.rec.eventsOf(EventTxWithoutRx)) >= 2
	})
	evs := p.a.rec.eventsOf(EventTxWithoutRx)
	if evs[0]["window"] != float64(1) || evs[1]["window"] != float64(2) || evs[0]["since"] != evs[1]["since"] || evs[0]["since"] == "" {
		t.Fatalf("txWithoutRx events %v", evs)
	}
}
