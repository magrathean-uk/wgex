// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixtureKeys is the shared test-key directory (P0-19). Every file there
// starts with a "# WGEX TEST FIXTURE" comment line.
const fixtureKeys = "../../Tests/Fixtures/keys"

func TestKeyFileSkipsBlankAndCommentLines(t *testing.T) {
	want, pub := mustKey(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "commented.key")
	body := "# WGEX TEST FIXTURE - NOT A REAL KEY\n\n   \n; another comment\n# Field = value\n\n" + want.String() + "\n\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readKeyFile(path); err != nil || got != want {
		t.Fatalf("private key with comment header: %v", err)
	}
	pubPath := filepath.Join(dir, "commented.pub")
	if err := os.WriteFile(pubPath, []byte("# header\n\n"+pub.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readPublicKeyFile(pubPath); err != nil || got != pub {
		t.Fatalf("public key with comment header: %v", err)
	}
	conf := filepath.Join(dir, "peer.conf")
	if err := os.WriteFile(conf, []byte("# c\n[Peer]\nAllowedIPs = 10.0.0.2/32\nPublicKey = "+pub.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readPublicKeyFile(conf); err != nil || got != pub {
		t.Fatalf("PublicKey = line: %v", err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("# only a comment\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readKeyFile(empty); err == nil {
		t.Fatal("comment-only file accepted")
	}
}

func TestSharedFixtureKeysParse(t *testing.T) {
	for _, pair := range [][2]string{{"server.key", "server.pub"}, {"client1.key", "client1.pub"}, {"client2.key", "client2.pub"}} {
		priv, err := readKeyFile(filepath.Join(fixtureKeys, pair[0]))
		if err != nil {
			t.Fatalf("%s: %v", pair[0], err)
		}
		pub, err := readPublicKeyFile(filepath.Join(fixtureKeys, pair[1]))
		if err != nil {
			t.Fatalf("%s: %v", pair[1], err)
		}
		if derived, err := priv.Public(); err != nil || derived != pub {
			t.Fatalf("%s is not the public key of %s", pair[1], pair[0])
		}
	}
}

// TestRunWithFixedClientKey starts the peer with the shared server key and a
// fixed client public key, then connects an in-process client holding the
// matching fixture private key.
func TestRunWithFixedClientKey(t *testing.T) {
	t.Parallel()
	serverKey := filepath.Join(fixtureKeys, "server.key")
	clientPubFile := filepath.Join(fixtureKeys, "client1.pub")
	serverPriv, err := readKeyFile(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	serverPub, _ := serverPriv.Public()
	clientPriv, err := readKeyFile(filepath.Join(fixtureKeys, "client1.key"))
	if err != nil {
		t.Fatal(err)
	}
	clientPub, _ := clientPriv.Public()

	sink := &eventSink{}
	var stderr bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"--listen", "127.0.0.1:0", "--key-file", serverKey,
			"--client-key-file", clientPubFile, "--counters-interval", "200ms"}, sink, &stderr)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	started := sink.wait(t, eventWaitTimeout, func(e map[string]any) bool { return e["event"] == "started" })
	if started == nil {
		t.Fatalf("no started event:\n%s", sink.text())
	}
	if started["public_key"] != serverPub.String() || started["key_source"] != "file" {
		t.Fatalf("started event does not carry the fixture server key: %v", started["key_source"])
	}
	port, ok := started["port"].(float64)
	if !ok {
		t.Fatalf("started event has no port")
	}
	client := sink.wait(t, eventWaitTimeout, func(e map[string]any) bool { return e["event"] == "client" && e["peer"] == "fixed-1" })
	if client == nil || client["public_key"] != clientPub.String() || !strings.Contains(fmt.Sprint(client["addresses"]), client4.String()) {
		t.Fatalf("fixed client event missing or wrong:\n%s", sink.text())
	}

	c := newClient(t, clientPriv, serverPub, netip.MustParseAddrPort("127.0.0.1:0"),
		netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)), client4, 0)
	resp, err := c.httpClient().Get("http://" + server4.String() + "/ip")
	if err != nil {
		t.Fatalf("GET /ip through the tunnel: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if got := strings.TrimSpace(string(body)); got != client4.String() {
		t.Fatalf("/ip = %q, want %s", got, client4)
	}

	out := sink.text() + stderr.String()
	for _, secret := range []Key{serverPriv, clientPriv} {
		if strings.Contains(out, secret.String()) {
			t.Fatal("a private key appeared in the output")
		}
	}
}

func TestFixedClientsComeBeforeGeneratedPeers(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	code := run(ctx, []string{"--listen", "127.0.0.1:0", "--client-key-file", filepath.Join(fixtureKeys, "client1.pub"),
		"--client-key-file", filepath.Join(fixtureKeys, "client2.pub"), "--peers", "1",
		"--public-address", "192.0.2.10", "--out-dir", dir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run exit %d: %s", code, stderr.String())
	}
	conf, err := os.ReadFile(filepath.Join(dir, "client-1.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(conf), "Address = 10.77.0.4/32") {
		t.Fatal("generated peer does not follow the two fixed clients")
	}
	for _, n := range []string{"fixed-1", "fixed-2"} {
		if _, err := os.Stat(filepath.Join(dir, n+".conf")); err == nil {
			t.Fatalf("%s.conf written for a fixed client", n)
		}
	}
	var bad bytes.Buffer
	if code := run(context.Background(), []string{"--listen", "127.0.0.1:0", "--client-key-file", filepath.Join(dir, "absent.pub")}, io.Discard, &bad); code == 0 {
		t.Fatal("missing --client-key-file accepted")
	}
}
