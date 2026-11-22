// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

// clientConf is a generated client: its private key is secret and only ever
// written to a 0600 file or printed with --print-keys.
type clientConf struct {
	Name    string
	Private Key
	Public  Key
	Addrs   []netip.Addr
}

type confParams struct {
	ServerPublic Key
	Endpoint     netip.AddrPort
	DNS          []netip.Addr
	AllowedIPs   []string
	MTU          int
}

func (c clientConf) render(p confParams) string {
	var b strings.Builder
	addrs := make([]string, len(c.Addrs))
	for i, a := range c.Addrs {
		addrs[i] = netip.PrefixFrom(a, a.BitLen()).String()
	}
	dns := make([]string, len(p.DNS))
	for i, a := range p.DNS {
		dns[i] = a.String()
	}
	fmt.Fprintf(&b, "# WGEX test peer client %s - test use only; the peer is not a router.\n", c.Name)
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", c.Private)
	fmt.Fprintf(&b, "Address = %s\n", strings.Join(addrs, ", "))
	fmt.Fprintf(&b, "DNS = %s\n", strings.Join(dns, ", "))
	if p.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", p.MTU)
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", p.ServerPublic)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(p.AllowedIPs, ", "))
	fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String()
}

// writeClientFiles writes <name>.conf and <name>.png (QR of the .conf) with
// mode 0600 and returns their paths.
func writeClientFiles(dir, name, conf string) (string, string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	confPath := filepath.Join(dir, name+".conf")
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		return "", "", err
	}
	png, err := qrcode.Encode(conf, qrcode.Medium, 512)
	if err != nil {
		return "", "", err
	}
	pngPath := filepath.Join(dir, name+".png")
	if err := os.WriteFile(pngPath, png, 0o600); err != nil {
		return "", "", err
	}
	return confPath, pngPath, nil
}

// terminalQR renders the .conf as a QR code using half-block characters.
func terminalQR(conf string) (string, error) {
	q, err := qrcode.New(conf, qrcode.Medium)
	if err != nil {
		return "", err
	}
	return q.ToSmallString(false), nil
}
