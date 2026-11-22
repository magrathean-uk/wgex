// SPDX-License-Identifier: MIT

package main

// The preamble declares nothing from wgex.h: cgo writes this file's //export
// prototypes into its own header together with the preamble, and pointer
// parameters are unsafe.Pointer here (void * in that header) where wgex.h
// says const T *. The calling convention is identical; wgex.h is the public
// declaration.

/*
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"context"
	"unsafe"

	"github.com/magrathean-uk/wgex/engine/cabi"
	"github.com/magrathean-uk/wgex/engine/engine"
	"github.com/magrathean-uk/wgex/engine/resolver"
	etun "github.com/magrathean-uk/wgex/engine/tun"
)

// cBytes views C memory as a byte slice without copying; nil for NULL or 0.
func cBytes(p unsafe.Pointer, n C.size_t) []byte {
	if p == nil || n == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(p), int(n))
}

// mallocJSON copies b into a NUL-terminated C buffer the caller frees with
// wgex_free.
func mallocJSON(b []byte) *C.char {
	if b == nil {
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

//export wgex_configure_process
func wgex_configure_process(p unsafe.Pointer) C.int32_t {
	return C.int32_t(cabi.ConfigureProcess(p))
}

//export wgex_create
func wgex_create(p unsafe.Pointer) C.int64_t {
	return C.int64_t(cabi.Create(p))
}

//export wgex_set_config
func wgex_set_config(h C.int64_t, uapi unsafe.Pointer, n C.size_t) C.int32_t {
	return C.int32_t(cabi.SetConfig(int64(h), cBytes(uapi, n)))
}

//export wgex_update_endpoints
func wgex_update_endpoints(h C.int64_t, uapi unsafe.Pointer, n C.size_t) C.int32_t {
	return C.int32_t(cabi.UpdateEndpoints(int64(h), cBytes(uapi, n)))
}

//export wgex_up
func wgex_up(h C.int64_t) C.int32_t { return C.int32_t(cabi.Up(int64(h))) }

//export wgex_down
func wgex_down(h C.int64_t) C.int32_t { return C.int32_t(cabi.Down(int64(h))) }

//export wgex_destroy
func wgex_destroy(h C.int64_t) C.int32_t { return C.int32_t(cabi.Destroy(int64(h))) }

//export wgex_bump_sockets
func wgex_bump_sockets(h C.int64_t, v4, v6 C.int32_t) C.int32_t {
	return C.int32_t(cabi.BumpSockets(int64(h), int32(v4), int32(v6)))
}

//export wgex_set_transport
func wgex_set_transport(h C.int64_t, doc unsafe.Pointer, n C.size_t) C.int32_t {
	if doc == nil || n == 0 {
		return C.int32_t(engine.EINVAL)
	}
	return C.int32_t(cabi.SetTransport(int64(h), C.GoBytes(doc, C.int(n))))
}

//export wgex_force_handshake
func wgex_force_handshake(h C.int64_t) C.int32_t {
	return C.int32_t(cabi.ForceHandshake(int64(h)))
}

//export wgex_find_utun_fd
func wgex_find_utun_fd() C.int32_t { return C.int32_t(etun.FindUTunFD()) }

//export wgex_public_stats_json
func wgex_public_stats_json(h C.int64_t) *C.char {
	return mallocJSON(cabi.PublicStatsJSON(int64(h)))
}

//export wgex_tun_name
func wgex_tun_name(h C.int64_t) *C.char { return (*C.char)(cabi.TunName(int64(h))) }

//export wgex_free_os_memory
func wgex_free_os_memory() C.int32_t {
	engine.FreeOSMemory()
	return C.int32_t(engine.OK)
}

//export wgex_resolve
func wgex_resolve(host *C.char, v4, v6 C.int32_t, resolvers *C.char) *C.char {
	if host == nil || resolvers == nil {
		return mallocJSON(resolver.ResolveJSON(context.Background(), "", -1, -1, nil))
	}
	doc := C.GoBytes(unsafe.Pointer(resolvers), C.int(C.strlen(resolvers)))
	return mallocJSON(resolver.ResolveJSON(context.Background(), C.GoString(host), int32(v4), int32(v6), doc))
}

//export wgex_abi_version
func wgex_abi_version() C.int32_t { return C.int32_t(engine.ABIVersion) }
