// SPDX-License-Identifier: MIT

//go:build wgextest

// Package testsupport carries the wgex_test_* exports that Swift loopback
// tests link through WGEXEngineTest.xcframework (macOS slice only): netstack
// engine pairs over loopback UDP (P1-18) and a packet-descriptor echo
// (P1-19). It is compiled only with -tags wgextest; production archives must
// not contain it and Engine/scripts/verify-slices.sh fails if they do.
package testsupport

/*
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"encoding/json"
	"time"
	"unsafe"

	"github.com/magrathean-uk/wgex/engine/engine"
)

// Ping returns the constant wgex_test_ping reports, for Go-side tests.
func Ping() int32 { return 1 }

//export wgex_test_ping
func wgex_test_ping() C.int32_t {
	return C.int32_t(Ping())
}

func mallocJSON(v any) *C.char {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	p := C.malloc(C.size_t(len(b) + 1))
	if p == nil {
		return nil
	}
	dst := unsafe.Slice((*byte)(p), len(b)+1)
	copy(dst, b)
	dst[len(b)] = 0
	return (*C.char)(p)
}

//export wgex_test_pair_create
func wgex_test_pair_create(cfg *C.char, pa, pb unsafe.Pointer) C.int64_t {
	var doc []byte
	if cfg != nil {
		doc = C.GoBytes(unsafe.Pointer(cfg), C.int(C.strlen(cfg)))
	}
	p, err := CreatePair(doc, pa, pb)
	if err != nil {
		return C.int64_t(engine.EINVAL)
	}
	return C.int64_t(p.ID)
}

//export wgex_test_pair_engine
func wgex_test_pair_engine(pair C.int64_t, side C.int32_t) C.int64_t {
	p, ok := LookupPair(int64(pair))
	if !ok || (side != 0 && side != 1) {
		return C.int64_t(engine.EHANDLE)
	}
	return C.int64_t(p.Handles[side])
}

//export wgex_test_pair_info
func wgex_test_pair_info(pair C.int64_t) *C.char {
	p, ok := LookupPair(int64(pair))
	if !ok {
		return nil
	}
	return mallocJSON(p)
}

//export wgex_test_pair_http_get
func wgex_test_pair_http_get(pair C.int64_t, from C.int32_t, path *C.char, timeoutMS C.int32_t) *C.char {
	p, ok := LookupPair(int64(pair))
	if !ok {
		return mallocJSON(HTTPResult{Error: "unknown pair"})
	}
	route := "/"
	if path != nil {
		route = C.GoString(path)
	}
	t := time.Duration(timeoutMS) * time.Millisecond
	if t <= 0 {
		t = 5 * time.Second
	}
	return mallocJSON(p.HTTPGet(int(from), route, t))
}

//export wgex_test_pair_destroy
func wgex_test_pair_destroy(pair C.int64_t) C.int32_t {
	if !DestroyPair(int64(pair)) {
		return C.int32_t(engine.EHANDLE)
	}
	return C.int32_t(engine.OK)
}

//export wgex_test_packetfd_echo
func wgex_test_packetfd_echo(fd, mtu C.int32_t) C.int64_t {
	h, err := StartEcho(int(fd), int(mtu))
	if err != nil {
		return C.int64_t(engine.EINVAL)
	}
	return C.int64_t(h)
}

//export wgex_test_packetfd_echo_stop
func wgex_test_packetfd_echo_stop(h C.int64_t) C.int64_t {
	return C.int64_t(StopEcho(int64(h)))
}

//export wgex_test_pair_fail_tun
func wgex_test_pair_fail_tun(pair C.int64_t, side C.int32_t) C.int32_t {
	p, ok := LookupPair(int64(pair))
	if !ok || !p.FailTUNRead(int(side)) {
		return C.int32_t(engine.EINVAL)
	}
	return C.int32_t(engine.OK)
}
