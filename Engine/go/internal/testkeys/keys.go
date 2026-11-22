// SPDX-License-Identifier: MIT

// Package testkeys loads repository fixtures only; no key generation or network is used.
// It is imported exclusively by tests and wgextest support, never production bridge code.
package testkeys

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
)

// Load returns one of the dedicated repository fixture identities.
func Load(index int) (priv, pub [32]byte, err error) {
	names := []string{"client1.key", "server.key", "client2.key"}
	cwd, err := os.Getwd()
	if err != nil {
		return priv, pub, err
	}
	for range 10 {
		path := filepath.Join(cwd, "Tests", "Fixtures", "keys", names[index%len(names)])
		data, readErr := os.ReadFile(path)
		if readErr == nil {
			defer clear(data)
			for _, line := range bytes.Split(data, []byte{'\n'}) {
				line = bytes.TrimSpace(line)
				if len(line) == 0 || line[0] == '#' {
					continue
				}
				n, decodeErr := base64.StdEncoding.Strict().Decode(priv[:], line)
				if decodeErr != nil || n != 32 {
					return priv, pub, errors.New("invalid fixture key")
				}
				key, keyErr := ecdh.X25519().NewPrivateKey(priv[:])
				if keyErr != nil {
					return priv, pub, errors.New("invalid fixture identity")
				}
				copy(pub[:], key.PublicKey().Bytes())
				return priv, pub, nil
			}
			return priv, pub, errors.New("empty fixture key")
		}
		cwd = filepath.Dir(cwd)
	}
	return priv, pub, errors.New("repository test keys not found")
}
