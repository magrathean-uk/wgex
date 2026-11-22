// SPDX-License-Identifier: MIT

package engine

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func assertNoSecrets(t testing.TB, out []byte, secrets [][32]byte) {
	t.Helper()
	for _, banned := range []string{"private_key", "preshared_key", "private", "preshared"} {
		if bytes.Contains(out, []byte(banned)) {
			t.Fatalf("stats JSON contains %q: %s", banned, out)
		}
	}
	for _, s := range secrets {
		for _, enc := range []string{hex.EncodeToString(s[:]), strings.ToUpper(hex.EncodeToString(s[:])), base64.StdEncoding.EncodeToString(s[:])} {
			if bytes.Contains(out, []byte(enc)) {
				t.Fatalf("stats JSON contains a secret key: %s", out)
			}
		}
	}
}

func sampleDump(priv, psk, pub [32]byte) []byte {
	return fmt.Appendf(nil, "private_key=%x\nlisten_port=51820\npublic_key=%x\npreshared_key=%x\nprotocol_version=1\nendpoint=192.0.2.1:51820\nlast_handshake_time_sec=1761370000\nlast_handshake_time_nsec=5\ntx_bytes=10\nrx_bytes=20\npersistent_keepalive_interval=25\nallowed_ip=10.0.0.2/32\n",
		priv, pub, psk)
}

func TestPublicStatsFromDump(t *testing.T) {
	priv, psk, pub := newKeyPair(t).priv, newKeyPair(t).priv, newKeyPair(t).pub
	st := parseUAPIGet(sampleDump(priv, psk, pub))
	b, err := publicStatsJSON(st, "utun9", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecrets(t, b, [][32]byte{priv, psk})
	var got PublicStats
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	want := PublicPeer{
		PublicKey: base64.StdEncoding.EncodeToString(pub[:]), Endpoint: "192.0.2.1:51820",
		LastHandshakeTime: "2025-10-25T05:26:40.000000005Z", RxBytes: 20, TxBytes: 10, PersistentKeepaliveInterval: 25,
	}
	if got.InterfaceName != "utun9" || got.ListenPort != 51820 || len(got.Peers) != 1 || got.Peers[0] != want {
		t.Fatalf("stats %+v, want peer %+v", got, want)
	}
}

func TestGetCollectorHandlesSplitWrites(t *testing.T) {
	priv, psk, pub := newKeyPair(t).priv, newKeyPair(t).priv, newKeyPair(t).pub
	dump := sampleDump(priv, psk, pub)
	whole := parseUAPIGet(dump)
	for split := 1; split < len(dump); split += 7 {
		var c getCollector
		_, _ = c.Write(dump[:split])
		_, _ = c.Write(dump[split:])
		if got := c.finish(); fmt.Sprint(got) != fmt.Sprint(whole) {
			t.Fatalf("split at %d: %+v, want %+v", split, got, whole)
		}
	}
}

// RT-07: whatever IpcGet returns, the public statistics never carry a key
// that appeared on a private_key or preshared_key line.
func FuzzPublicStatsNoSecrets(f *testing.F) {
	var a, b, c [32]byte
	for i := range a {
		a[i], b[i], c[i] = byte(i), byte(255-i), byte(i*7)
	}
	f.Add(sampleDump(a, b, c))
	f.Add([]byte("private_key=" + strings.Repeat("ab", 32) + "\npublic_key=" + strings.Repeat("ab", 32) + "\n"))
	f.Add([]byte("public_key=\npreshared_key=00\nendpoint=[::1]:1\n"))
	f.Fuzz(func(t *testing.T, dump []byte) {
		st := parseUAPIGet(dump)
		out, err := publicStatsJSON(st, "", time.Unix(0, 0))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(out, []byte("private_key")) || bytes.Contains(out, []byte("preshared_key")) {
			t.Fatalf("secret field name in %s", out)
		}
		publics := map[string]bool{}
		for _, line := range bytes.Split(dump, []byte{'\n'}) {
			if k, v, ok := bytes.Cut(line, []byte{'='}); ok && string(k) == "public_key" {
				publics[strings.ToLower(string(v))] = true
			}
		}
		for _, line := range bytes.Split(dump, []byte{'\n'}) {
			k, v, ok := bytes.Cut(line, []byte{'='})
			if !ok || (string(k) != "private_key" && string(k) != "preshared_key") || len(v) == 0 {
				continue
			}
			if publics[strings.ToLower(string(v))] {
				continue // the same bytes also appear as a public key
			}
			if len(v) >= 8 && bytes.Contains(out, v) {
				t.Fatalf("secret value leaked: %s", out)
			}
			if raw, err := hex.DecodeString(string(v)); err == nil && len(raw) == 32 &&
				bytes.Contains(out, []byte(base64.StdEncoding.EncodeToString(raw))) {
				t.Fatalf("secret value leaked as base64: %s", out)
			}
		}
	})
}

func TestValidateFullConfig(t *testing.T) {
	k := strings.Repeat("a", 64)
	ok := []string{
		"private_key=" + k + "\nlisten_port=0\nreplace_peers=true\n",
		"private_key=" + k + "\nlisten_port=1\nfwmark=0\nreplace_peers=true\npublic_key=" + k + "\npreshared_key=" + k + "\nendpoint=1.2.3.4:5\npersistent_keepalive_interval=1\nreplace_allowed_ips=true\nallowed_ip=0.0.0.0/0\nprotocol_version=1\n",
		"private_key=" + k + "\r\nlisten_port=0\r\nreplace_peers=true\r\npublic_key=" + k + "\r\n\r\n",
		"private_key=" + k + "\nlisten_port=0\nreplace_peers=true", // no trailing newline
	}
	for _, d := range ok {
		if err := ValidateFullConfig([]byte(d)); err != nil {
			t.Errorf("ValidateFullConfig(%q) = %v", d, err)
		}
	}
	bad := []string{
		"", "listen_port=1\n", "replace_peers=yes\n", "replace_peers=true\nbogus=1\n",
		"replace_peers=true\npublic_key=" + k + "\nlisten_port=1\n", // device key in a peer section
		"replace_peers=true\npublic_key=" + k + "\nupdate_only=true\n",
		"replace_peers=true\npublic_key=" + k + "\nremove=true\n",
		"replace_peers=true\npublic_key=xyz\n",
		"replace_peers=true\n\nlisten_port=1\n",
		"private_key\nreplace_peers=true\n",
		"public_key=" + k + "\nreplace_peers=true\n",
	}
	for _, d := range bad {
		err := ValidateFullConfig([]byte(d))
		if err == nil {
			t.Errorf("ValidateFullConfig(%q) accepted", d)
			continue
		}
		if strings.Contains(err.Error(), k) {
			t.Errorf("error message quotes document content: %v", err)
		}
	}
	if err := ValidateFullConfig(bytes.Repeat([]byte("x"), MaxUAPISize+1)); err == nil {
		t.Error("oversized document accepted")
	}
}

func TestValidateEndpointUpdate(t *testing.T) {
	k := strings.Repeat("b", 64)
	ok := []string{
		"public_key=" + k + "\nupdate_only=true\nendpoint=1.2.3.4:5\n",
		"public_key=" + k + "\nupdate_only=true\n",
		"public_key=" + k + "\nupdate_only=true\nendpoint=[2001:db8::1]:51820\npublic_key=" + k + "\nupdate_only=true\nendpoint=1.2.3.4:5\n",
	}
	for _, d := range ok {
		if err := ValidateEndpointUpdate([]byte(d)); err != nil {
			t.Errorf("ValidateEndpointUpdate(%q) = %v", d, err)
		}
	}
	bad := []string{
		"", "\n",
		"update_only=true\n",
		"public_key=" + k + "\n",
		"public_key=" + k + "\nendpoint=1.2.3.4:5\nupdate_only=true\n",
		"public_key=" + k + "\nupdate_only=false\n",
		"public_key=" + k + "\nupdate_only=true\nendpoint=1.2.3.4:5\nendpoint=1.2.3.4:6\n",
		"public_key=" + k + "\nupdate_only=true\nendpoint=host:5\n",
		"public_key=" + k + "\nupdate_only=true\nendpoint=1.2.3.4:0\n",
		"public_key=" + k + "\nupdate_only=true\nallowed_ip=0.0.0.0/0\n",
		"public_key=" + k + "\nupdate_only=true\nremove=true\n",
		"private_key=" + k + "\n",
		"replace_peers=true\n",
		"public_key=" + k + "\nupdate_only=true\npublic_key=" + k + "\n",
	}
	for _, d := range bad {
		if err := ValidateEndpointUpdate([]byte(d)); err == nil {
			t.Errorf("ValidateEndpointUpdate(%q) accepted", d)
		}
	}
}

func TestHealthTracker(t *testing.T) {
	var pk [32]byte
	pk[0] = 1
	type ev struct {
		kind EventKind
		v    any
	}
	var got []ev
	emit := func(k EventKind, v any) { got = append(got, ev{k, v}) }
	t0 := time.Unix(1000, 0)
	h := newHealthTracker(15*time.Second, 5*time.Second, t0.Add(-time.Second))
	sample := func(sec int, tx, rx uint64, hs int64, endpoint string) {
		h.observe(t0.Add(time.Duration(sec)*time.Second), uapiState{Peers: []uapiPeer{{PublicKey: pk, TxBytes: tx, RxBytes: rx, HSSec: hs, Endpoint: endpoint}}}, emit)
	}
	kinds := func() (out []EventKind) {
		for _, e := range got {
			out = append(out, e.kind)
		}
		got = nil
		return out
	}
	sample(0, 0, 0, 0, "")
	if k := kinds(); len(k) != 0 {
		t.Fatalf("baseline emitted %v", k)
	}
	sample(1, 148, 0, 0, "192.0.2.1:1") // handshake initiation sent
	if k := kinds(); len(k) != 1 || k[0] != EventEndpointChanged {
		t.Fatalf("after first tx: %v", k)
	}
	sample(15, 296, 0, 0, "192.0.2.1:1")
	if k := kinds(); len(k) != 0 {
		t.Fatalf("before the window elapsed: %v", k)
	}
	sample(16, 296, 0, 0, "192.0.2.1:1")
	if k := kinds(); len(k) != 1 || k[0] != EventTxWithoutRx {
		t.Fatalf("window 1: %v", k)
	}
	sample(20, 296, 0, 0, "192.0.2.1:1")
	if k := kinds(); len(k) != 0 {
		t.Fatalf("between windows: %v", k)
	}
	sample(31, 444, 0, 0, "192.0.2.1:1")
	if len(got) != 1 || got[0].v.(txWithoutRxEvent).Window != 2 || got[0].v.(txWithoutRxEvent).Since != rfc3339(t0.Add(time.Second)) {
		t.Fatalf("window 2: %+v", got)
	}
	kinds()
	sample(32, 444, 92, 1032, "192.0.2.1:1") // response received: handshake + rx
	if k := kinds(); len(k) != 2 || k[0] != EventHandshakeCompleted || k[1] != EventRx {
		t.Fatalf("after rx: %v", k)
	}
	sample(33, 600, 200, 1032, "192.0.2.1:1")
	if k := kinds(); len(k) != 0 {
		t.Fatalf("rx within the rate limit: %v", k)
	}
	sample(37, 700, 300, 1032, "192.0.2.1:1")
	if k := kinds(); len(k) != 1 || k[0] != EventRx {
		t.Fatalf("rx after the rate limit: %v", k)
	}
	sample(38, 0, 0, 0, "") // peer replaced: counters reset, baseline only
	if k := kinds(); len(k) != 0 {
		t.Fatalf("after reset: %v", k)
	}
	// A replacement peer that completed its handshake between two samples is
	// still reported, with its rx.
	sample(39, 0, 0, 0, "")
	h.peers = map[[32]byte]*peerHealth{}
	sample(43, 300, 200, 1042, "192.0.2.1:1")
	if k := kinds(); len(k) != 2 || k[0] != EventHandshakeCompleted || k[1] != EventRx {
		t.Fatalf("first sight after a handshake: %v", k)
	}
	// An old handshake seen for the first time is not reported.
	h.peers = map[[32]byte]*peerHealth{}
	sample(44, 300, 200, 1000, "192.0.2.1:1")
	if k := kinds(); len(k) != 0 {
		t.Fatalf("first sight of an old handshake: %v", k)
	}
	// First sight with tx and no rx starts a window.
	h.peers = map[[32]byte]*peerHealth{}
	sample(50, 148, 0, 0, "192.0.2.1:1")
	sample(66, 296, 0, 0, "192.0.2.1:1")
	if k := kinds(); len(k) != 1 || k[0] != EventTxWithoutRx {
		t.Fatalf("first sight tx without rx: %v", k)
	}
}

func TestRedactKeys(t *testing.T) {
	hexKey := strings.Repeat("0123456789abcdef", 4)
	b64 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	for in, want := range map[string]string{
		"peer(AbCd…wxyz) - Sending handshake initiation": "peer(AbCd…wxyz) - Sending handshake initiation",
		"key " + hexKey + " end":                         "key (redacted) end",
		"b64 " + b64 + " end":                            "b64 (redacted) end",
		"peer" + hexKey:                                  "peer(redacted)",
		"prefix" + b64 + "suffix":                        "(redacted)suffix",
		"prefix" + hexKey + "suffix":                     "prefix(redacted)suffix",
		"ordinary alphanumeric words unchanged":          "ordinary alphanumeric words unchanged",
		"short abcdef0123":                               "short abcdef0123",
	} {
		if got := string(redactKeys([]byte(in))); got != want {
			t.Errorf("redactKeys(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseTransport(t *testing.T) {
	for _, ok := range []string{"", "  ", `{"kind":"udp"}`} {
		if k, err := ParseTransport([]byte(ok)); err != nil || k != "udp" {
			t.Errorf("ParseTransport(%q) = %q, %v", ok, k, err)
		}
	}
	for _, bad := range []string{`{"kind":"vless"}`, `{}`, `[]`, `{"kind":"udp","extra":true}`, `{"kind":"udp"}x`} {
		if _, err := ParseTransport([]byte(bad)); CodeOf(err) != EINVAL {
			t.Errorf("ParseTransport(%q) = %v, want EINVAL", bad, err)
		}
	}
}

func TestProcessParamsValidate(t *testing.T) {
	if err := (ProcessParams{MemoryLimitBytes: 24 << 20, GCPercent: 50, QueueProfile: QueueProfileConstrained}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []ProcessParams{{MemoryLimitBytes: -1}, {GCPercent: -2}, {QueueProfile: 2}} {
		if p.Validate() == nil {
			t.Errorf("%+v accepted", p)
		}
	}
	if QueueProfileApplies {
		t.Fatal("queue profile must be a no-op on macOS")
	}
}
