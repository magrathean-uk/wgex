// SPDX-License-Identifier: MIT

//go:build wgextest

// Command wgex-engine-test proves the bridge on userspace netstack tuns.
// It opens loopback UDP sockets only; HTTP port 80 belongs to gVisor, not the host.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/magrathean-uk/wgex/engine/cabi"
	"github.com/magrathean-uk/wgex/engine/engine"
	"github.com/magrathean-uk/wgex/engine/testsupport"
)

func check(code int32, step string) error {
	if code != 0 {
		return fmt.Errorf("%s: ABI code %d", step, code)
	}
	return nil
}

func statistics(h int64) (engine.PublicStats, error) {
	var st engine.PublicStats
	b := cabi.PublicStatsJSON(h)
	// Test the exported JSON independently of its Swift decoder; never print it.
	if len(b) == 0 || bytes.Contains(b, []byte("private_key")) || bytes.Contains(b, []byte("preshared_key")) {
		return st, errors.New("statistics missing or contain a secret field")
	}
	if json.Unmarshal(b, &st) != nil || len(st.Peers) != 1 {
		return st, errors.New("statistics schema or peer count invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, st.SampledAt); err != nil {
		return st, errors.New("sample timestamp invalid")
	}
	return st, nil
}

func request(p *testsupport.Pair, from int) error {
	r := p.HTTPGet(from, "/ip", 5*time.Second)
	if r.Error != "" || r.Status != 200 || strings.TrimSpace(r.Body) != p.Addresses[from] {
		return errors.New("in-tunnel HTTP failed")
	}
	return nil
}

func run() error {
	started := time.Now()
	p, err := testsupport.CreatePair(nil, nil, nil)
	if err != nil {
		return errors.New("netstack pair creation failed")
	}
	defer testsupport.DestroyPair(p.ID)
	for from := range 2 {
		if err := request(p, from); err != nil {
			return err
		}
		st, err := statistics(p.Handles[from])
		if err != nil {
			return err
		}
		peer := st.Peers[0]
		if peer.PublicKey != p.PublicKeys[1-from] || peer.RxBytes == 0 || peer.TxBytes == 0 || peer.LastHandshakeTime == "" {
			return errors.New("live peer statistics incomplete")
		}
		// Also prove that secret values from the throwaway document did not escape.
		for line := range strings.SplitSeq(p.UAPI[from], "\n") {
			k, v, _ := strings.Cut(line, "=")
			if (k == "private_key" || k == "preshared_key") && v != "" && bytes.Contains(cabi.PublicStatsJSON(p.Handles[from]), []byte(v)) {
				return errors.New("secret value in statistics")
			}
		}
	}
	before, err := statistics(p.Handles[0])
	if err != nil {
		return err
	}
	peer := before.Peers[0]
	pk, err := base64.StdEncoding.DecodeString(peer.PublicKey)
	if err != nil {
		return errors.New("public key encoding invalid")
	}
	doc := []byte(fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n", hex.EncodeToString(pk), peer.Endpoint))
	if err := check(cabi.UpdateEndpoints(p.Handles[0], doc), "endpoint update"); err != nil {
		return err
	}
	if err := request(p, 0); err != nil {
		return err
	}
	time.Sleep(1200 * time.Millisecond)
	after, err := statistics(p.Handles[0])
	if err != nil {
		return err
	}
	if after.Peers[0].LastHandshakeTime != peer.LastHandshakeTime {
		return errors.New("endpoint update replaced the session")
	}
	if err := check(cabi.ForceHandshake(p.Handles[0]), "force handshake"); err != nil {
		return err
	}
	previous, err := time.Parse(time.RFC3339Nano, peer.LastHandshakeTime)
	if err != nil {
		return errors.New("handshake timestamp invalid")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		after, err = statistics(p.Handles[0])
		if err != nil {
			return err
		}
		latest, parseErr := time.Parse(time.RFC3339Nano, after.Peers[0].LastHandshakeTime)
		if parseErr == nil && latest.After(previous) {
			break
		}
		if time.Now().After(deadline) {
			return errors.New("forced handshake did not complete")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if after.Peers[0].Endpoint != peer.Endpoint {
		return errors.New("forced handshake lost the endpoint")
	}
	if err := request(p, 1); err != nil {
		return err
	}
	if !testsupport.DestroyPair(p.ID) {
		return errors.New("pair destroy failed")
	}
	if live, closing := cabi.Counts(); live != 0 || closing != 0 {
		return errors.New("engine registry not empty after destroy")
	}
	fmt.Printf("engine integration: two netstack engines, HTTP both ways, public stats, endpoint session retained, forced handshake, clean destroy; PASS (%s)\n", time.Since(started).Round(time.Millisecond))
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "engine integration:", err)
		os.Exit(1)
	}
}
