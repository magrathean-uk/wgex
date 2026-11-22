// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Key is a Curve25519 key in WireGuard's encoding.
type Key [32]byte

func generatePrivateKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return k, err
	}
	// Clamp as wg(8) genkey does so the stored form matches other tools.
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return k, nil
}

func (k Key) Public() (Key, error) {
	priv, err := ecdh.X25519().NewPrivateKey(k[:])
	if err != nil {
		return Key{}, err
	}
	var pub Key
	copy(pub[:], priv.PublicKey().Bytes())
	return pub, nil
}

// String is the base64 form. Only call it on public keys or when the
// operator explicitly asked for secrets (--print-keys, client .conf files).
func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

func (k Key) hex() string { return hex.EncodeToString(k[:]) }

func parseKey(s string) (Key, error) {
	var k Key
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return k, errors.New("key is not valid base64")
	}
	if len(b) != len(k) {
		return k, fmt.Errorf("key is %d bytes, want 32", len(b))
	}
	copy(k[:], b)
	return k, nil
}

// readKeyFile reads a private key from a file holding either the bare base64
// key (wg genkey output) or a wg-quick style "PrivateKey = ..." line.
func readKeyFile(path string) (Key, error) { return readKeyField(path, "PrivateKey") }

// readPublicKeyFile reads a public key from a file holding either the bare
// base64 key (wg pubkey output, as in Tests/Fixtures/keys/*.pub) or a
// "PublicKey = ..." line.
func readPublicKeyFile(path string) (Key, error) { return readKeyField(path, "PublicKey") }

// readKeyField returns the first key in path: a bare base64 line or the value
// of a "<field> = ..." line. Blank lines, comment lines starting with '#' or
// ';' (the fixture header) and section lines are skipped. Errors never quote
// file content.
func readKeyField(path, field string) (Key, error) {
	f, err := os.Open(path)
	if err != nil {
		return Key{}, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "[") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && strings.EqualFold(strings.TrimSpace(k), field) {
			return parseKey(v)
		}
		if strings.Contains(line, " = ") {
			continue // some other wg-quick field
		}
		return parseKey(line)
	}
	if err := sc.Err(); err != nil {
		return Key{}, err
	}
	return Key{}, fmt.Errorf("%s: no key found", path)
}
