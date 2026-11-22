// SPDX-License-Identifier: MIT

package engine

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
)

// MaxUAPISize bounds a UAPI document passed to wgex_set_config or
// wgex_update_endpoints. 1024 peers with 4096 allowed IPs (ADR-007 caps) fit.
const MaxUAPISize = 4 << 20

var (
	deviceKeys = map[string]bool{"private_key": true, "listen_port": true, "fwmark": true, "replace_peers": true}
	peerKeys   = map[string]bool{
		"preshared_key": true, "endpoint": true, "persistent_keepalive_interval": true,
		"replace_allowed_ips": true, "allowed_ip": true, "protocol_version": true,
	}
)

// forEachLine calls fn for each line of doc with its 1-based number, after
// removing a trailing CR (as bufio.ScanLines does inside IpcSetOperation). A
// blank line ends a UAPI operation, so it is accepted only at the end. No
// line content is ever turned into a string.
func forEachLine(doc []byte, fn func(n int, key, value []byte) error) error {
	n := 0
	for len(doc) > 0 {
		n++
		line := doc
		if i := bytes.IndexByte(doc, '\n'); i >= 0 {
			line, doc = doc[:i], doc[i+1:]
		} else {
			doc = nil
		}
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if len(line) == 0 {
			if len(bytes.TrimSpace(doc)) != 0 {
				return fmt.Errorf("line %d: blank line before the end of the document", n)
			}
			return nil
		}
		key, value, ok := bytes.Cut(line, []byte{'='})
		if !ok {
			return fmt.Errorf("line %d: missing '='", n)
		}
		if err := fn(n, key, value); err != nil {
			return err
		}
	}
	return nil
}

func isHexKey(v []byte) bool {
	if len(v) != 64 {
		return false
	}
	for _, c := range v {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func checkSize(doc []byte) error {
	if len(doc) == 0 {
		return errors.New("empty document")
	}
	if len(doc) > MaxUAPISize {
		return fmt.Errorf("document larger than %d bytes", MaxUAPISize)
	}
	return nil
}

// ValidateFullConfig checks the shape of a wgex_set_config document: known
// keys only, replace_peers=true present in the interface section, well-formed
// public keys. Value semantics are left to IpcSetOperation, whose failures
// trigger the restore path.
func ValidateFullConfig(doc []byte) error {
	if err := checkSize(doc); err != nil {
		return err
	}
	inPeer, replace := false, false
	privateKey, listenPort := false, false
	err := forEachLine(doc, func(n int, key, value []byte) error {
		k := string(key) // keys are protocol vocabulary, never secret
		switch {
		case k == "public_key":
			if !isHexKey(value) {
				return fmt.Errorf("line %d: public_key is not 64 hex digits", n)
			}
			inPeer = true
		case !inPeer && deviceKeys[k]:
			privateKey = privateKey || k == "private_key"
			listenPort = listenPort || k == "listen_port"
			if k == "replace_peers" {
				if !bytes.Equal(value, []byte("true")) {
					return fmt.Errorf("line %d: replace_peers must be true", n)
				}
				replace = true
			}
		case inPeer && peerKeys[k]:
		default:
			return fmt.Errorf("line %d: key not allowed in a full configuration", n)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !privateKey || !listenPort {
		return errors.New("private_key and listen_port required in a full replacement")
	}
	if !replace {
		return errors.New("replace_peers=true missing: wgex_set_config is a full replace")
	}
	return nil
}

// ValidateEndpointUpdate checks a wgex_update_endpoints document: blocks of
// public_key, update_only=true and at most one literal endpoint, nothing else.
func ValidateEndpointUpdate(doc []byte) error {
	if err := checkSize(doc); err != nil {
		return err
	}
	const (
		wantKey = iota
		wantUpdateOnly
		wantEndpointOrKey
		wantKeyAfterEndpoint
	)
	state, blocks := wantKey, 0
	err := forEachLine(doc, func(n int, key, value []byte) error {
		switch string(key) {
		case "public_key":
			if state == wantUpdateOnly {
				return fmt.Errorf("line %d: update_only=true must follow public_key", n)
			}
			if !isHexKey(value) {
				return fmt.Errorf("line %d: public_key is not 64 hex digits", n)
			}
			blocks++
			state = wantUpdateOnly
		case "update_only":
			if state != wantUpdateOnly || !bytes.Equal(value, []byte("true")) {
				return fmt.Errorf("line %d: update_only=true must directly follow public_key", n)
			}
			state = wantEndpointOrKey
		case "endpoint":
			if state != wantEndpointOrKey {
				return fmt.Errorf("line %d: endpoint must follow update_only=true, once per peer", n)
			}
			ap, err := netip.ParseAddrPort(string(value))
			if err != nil || ap.Port() == 0 {
				return fmt.Errorf("line %d: endpoint is not a literal ip:port", n)
			}
			state = wantKeyAfterEndpoint
		default:
			return fmt.Errorf("line %d: only public_key, update_only and endpoint are allowed", n)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if blocks == 0 {
		return errors.New("no peers")
	}
	if state == wantUpdateOnly {
		return errors.New("last peer lacks update_only=true")
	}
	return nil
}
