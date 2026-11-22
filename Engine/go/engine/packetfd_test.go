// SPDX-License-Identifier: MIT

package engine

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func dgramPair(t *testing.T) (engineEnd, appEnd int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 1<<17)
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<17)
	}
	t.Cleanup(func() { unix.Close(fds[0]); unix.Close(fds[1]) })
	return fds[0], fds[1]
}

// udp4Packet builds an IPv4/UDP packet; wireguard-go checks the length and
// the source address against the peer's allowed IPs, not the checksums.
func udp4Packet(src, dst [4]byte, payload []byte) []byte {
	p := make([]byte, 28+len(payload))
	p[0], p[8], p[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	binary.BigEndian.PutUint16(p[20:], 40000)
	binary.BigEndian.PutUint16(p[22:], 9)
	binary.BigEndian.PutUint16(p[24:], uint16(8+len(payload)))
	copy(p[28:], payload)
	return p
}

// P1-19: two engines over loopback whose tuns are packet descriptors (tun_kind
// 1); an IP packet written to A's socketpair comes out of B's.
func TestPacketFDEnginesCarryPackets(t *testing.T) {
	type end struct {
		e   *Engine
		app int
		key keyPair
		ip  [4]byte
	}
	var ends [2]*end
	for i := range ends {
		engFD, appFD := dgramPair(t)
		e, err := New(Params{TunKind: TunPacketFD, TunFD: engFD, MTU: 1420})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(e.Close)
		if e.TunName() != "packetfd" {
			t.Fatalf("tun name %q", e.TunName())
		}
		ends[i] = &end{e: e, app: appFD, key: newKeyPair(t), ip: [4]byte{10, 97, 0, byte(i + 1)}}
	}
	ports := [2]uint16{}
	for i, s := range ends {
		peer := ends[1-i]
		doc := fmt.Sprintf("private_key=%s\nlisten_port=0\nreplace_peers=true\npublic_key=%s\nallowed_ip=10.97.0.%d/32\n", hexKey(s.key.priv), hexKey(peer.key.pub), 2-i)
		if err := s.e.SetConfig([]byte(doc)); err != nil {
			t.Fatal(err)
		}
		if err := s.e.Up(); err != nil {
			t.Fatal(err)
		}
		st, _ := s.e.PublicStatsJSON()
		var parsed struct {
			ListenPort uint16 `json:"listen_port"`
		}
		if err := jsonUnmarshal(st, &parsed); err != nil {
			t.Fatal(err)
		}
		ports[i] = parsed.ListenPort
	}
	for i, s := range ends {
		doc := fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n", hexKey(ends[1-i].key.pub), loopback(ports[1-i]))
		if err := s.e.UpdateEndpoints([]byte(doc)); err != nil {
			t.Fatal(err)
		}
	}
	_ = unix.SetsockoptTimeval(ends[1].app, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 5})
	for i := range 3 {
		pkt := udp4Packet(ends[0].ip, ends[1].ip, []byte(fmt.Sprintf("datagram %d", i)))
		if _, err := unix.Write(ends[0].app, pkt); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 2048)
		deadline := time.Now().Add(5 * time.Second)
		for {
			n, err := unix.Read(ends[1].app, buf)
			if err != nil {
				t.Fatalf("packet %d: %v", i, err)
			}
			if string(buf[:n]) == string(pkt) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("packet %d not delivered", i)
			}
		}
	}
}
