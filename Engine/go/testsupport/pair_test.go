// SPDX-License-Identifier: MIT

//go:build wgextest

package testsupport

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/magrathean-uk/wgex/engine/cabi"
)

func TestPairHTTPBothWays(t *testing.T) {
	p, err := CreatePair([]byte(`{"keepalive":0}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer DestroyPair(p.ID)
	for from := range 2 {
		r := p.HTTPGet(from, "/", 10*time.Second)
		want := "wgex-test " + string(rune('a'+1-from)) + "\n"
		if r.Error != "" || r.Status != 200 || r.Body != want {
			t.Fatalf("GET from %d: %+v", from, r)
		}
		r = p.HTTPGet(from, "/ip", 10*time.Second)
		if strings.TrimSpace(r.Body) != p.Addresses[from] {
			t.Fatalf("/ip from %d = %q", from, r.Body)
		}
	}
	r := p.HTTPGet(0, "/bytes?n=1000000", 20*time.Second)
	if r.Status != 200 || len(r.Body) != 1000000 {
		t.Fatalf("1 MB transfer: status %d, %d bytes, %s", r.Status, len(r.Body), r.Error)
	}
	b, _ := json.Marshal(p)
	for _, k := range []string{`"handles"`, `"public_keys"`, `"listen_ports"`, `"uapi"`} {
		if !strings.Contains(string(b), k) {
			t.Fatalf("info lacks %s: %s", k, b)
		}
	}
	// The handles are ordinary engine handles.
	if st := cabi.PublicStatsJSON(p.Handles[0]); st == nil || !strings.Contains(string(st), p.PublicKeys[1]) {
		t.Fatalf("stats of side a: %s", st)
	}
	// Re-applying side a's document through the normal ABI works.
	if c := cabi.SetConfig(p.Handles[0], []byte(p.UAPI[0])); c != 0 {
		t.Fatalf("set_config with the pair document = %d", c)
	}
	if r := p.HTTPGet(0, "/", 10*time.Second); r.Status != 200 {
		t.Fatalf("GET after re-apply: %+v", r)
	}
}

func TestPairDestroyIsClean(t *testing.T) {
	base := runtime.NumGoroutine()
	for range 3 {
		p, err := CreatePair(nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if r := p.HTTPGet(1, "/", 10*time.Second); r.Status != 200 {
			t.Fatalf("GET: %+v", r)
		}
		// The caller may destroy an engine itself before the pair.
		cabi.Destroy(p.Handles[0])
		if !DestroyPair(p.ID) {
			t.Fatal("pair unknown")
		}
		if DestroyPair(p.ID) {
			t.Fatal("pair destroyed twice")
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for runtime.NumGoroutine() > base+2 {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			t.Fatalf("goroutines %d, base %d\n%s", runtime.NumGoroutine(), base, buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(50 * time.Millisecond)
	}
	if live, closing := cabi.Counts(); live != 0 || closing != 0 {
		t.Fatalf("registry %d live, %d closing", live, closing)
	}
}

func TestPairWithoutConfiguration(t *testing.T) {
	p, err := CreatePair([]byte(`{"configure":false,"addresses":["10.98.1.1","10.98.1.2"]}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer DestroyPair(p.ID)
	if p.ListenPorts != [2]uint16{} || p.UAPI != [2]string{} {
		t.Fatalf("unconfigured pair has state: %+v", p)
	}
	if _, err := CreatePair([]byte(`{"bogus":1}`), nil, nil); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestPacketFDEchoHelper(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	_ = unix.SetsockoptInt(fds[1], unix.SOL_SOCKET, unix.SO_SNDBUF, 1<<16)
	h, err := StartEcho(fds[0], 1420)
	if err != nil {
		t.Fatal(err)
	}
	_ = unix.SetsockoptTimeval(fds[1], unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2})
	for i := range 5 {
		pkt := make([]byte, 100+i*300)
		pkt[0] = 0x45
		pkt[1] = byte(i)
		if _, err := unix.Write(fds[1], pkt); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 2048)
		n, err := unix.Read(fds[1], buf)
		if err != nil || n != len(pkt) || buf[1] != byte(i) {
			t.Fatalf("echo %d: %d bytes, %v", i, n, err)
		}
	}
	if n := StopEcho(h); n != 5 {
		t.Fatalf("echoed %d", n)
	}
	if StopEcho(h) != -1 {
		t.Fatal("second stop")
	}
	if _, err := StartEcho(fds[0], 10); err == nil {
		t.Fatal("bad mtu accepted")
	}
}
