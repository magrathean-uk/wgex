// SPDX-License-Identifier: MIT

package cabi

/*
#cgo CFLAGS: -I${SRCDIR}/../bridge
#include <stdlib.h>
#include <string.h>
#include "wgex.h"

// Depth of engine callbacks running on this thread. wgex_destroy reads it to
// avoid waiting for the callback it is called from. Every C function that
// touches it lives in this one translation unit.
static __thread int wgex_cb_depth;

static int wgex_in_callback(void) { return wgex_cb_depth > 0; }
static void wgex_cb_enter(void) { wgex_cb_depth++; }
static void wgex_cb_leave(void) { wgex_cb_depth--; }

static void wgex_call_log(wgex_log_fn fn, void *ctx, int32_t level, const char *msg, size_t len) {
	wgex_cb_depth++;
	fn(ctx, level, msg, len);
	wgex_cb_depth--;
}

static void wgex_call_event(wgex_event_fn fn, void *ctx, int32_t kind, const char *json, size_t len) {
	wgex_cb_depth++;
	fn(ctx, kind, json, len);
	wgex_cb_depth--;
}
*/
import "C"

import (
	"runtime"
	"unsafe"

	"github.com/magrathean-uk/wgex/engine/engine"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

func inCallback() bool { return C.wgex_in_callback() != 0 }

func cString(s string) unsafe.Pointer {
	if s == "" {
		return nil
	}
	return unsafe.Pointer(C.CString(s))
}

func freeCString(p unsafe.Pointer) {
	if p != nil {
		C.free(p)
	}
}

// guardLog and guardEvent mark Go callbacks as callbacks for the in-callback
// check: the goroutine is pinned to its thread while the thread-local depth
// is raised, so a nested Destroy on that goroutine sees it.
func guardLog(fn engine.LogFunc) engine.LogFunc {
	if fn == nil {
		return nil
	}
	return func(level int32, msg []byte) {
		runtime.LockOSThread()
		C.wgex_cb_enter()
		defer func() {
			C.wgex_cb_leave()
			runtime.UnlockOSThread()
		}()
		fn(level, msg)
	}
}

func guardEvent(fn engine.EventFunc) engine.EventFunc {
	if fn == nil {
		return nil
	}
	return func(kind engine.EventKind, data []byte) {
		runtime.LockOSThread()
		C.wgex_cb_enter()
		defer func() {
			C.wgex_cb_leave()
			runtime.UnlockOSThread()
		}()
		fn(kind, data)
	}
}

func bytePtr(b []byte) *C.char {
	if len(b) == 0 {
		return nil
	}
	return (*C.char)(unsafe.Pointer(unsafe.SliceData(b)))
}

// ConfigureProcess decodes a wgex_process_params pointer.
func ConfigureProcess(p unsafe.Pointer) int32 {
	if p == nil {
		return code(engine.EINVAL)
	}
	cp := (*C.wgex_process_params)(p)
	return ConfigureProcessParams(engine.ProcessParams{
		MemoryLimitBytes: int64(cp.memory_limit_bytes),
		GCPercent:        int32(cp.gc_percent),
		QueueProfile:     int32(cp.queue_profile),
	})
}

// decodeParams converts wgex_create_params, binding the C callbacks.
func decodeParams(p unsafe.Pointer) (engine.Params, bool) {
	if p == nil {
		return engine.Params{}, false
	}
	cp := (*C.wgex_create_params)(p)
	if cp.log_level < 0 || cp.log_level > 3 || cp.bind_ifindex_v4 < 0 || cp.bind_ifindex_v6 < 0 || cp.mobile_quirks < 0 || cp.mobile_quirks > 1 {
		return engine.Params{}, false
	}
	out := engine.Params{
		TunKind:       engine.TunKind(cp.tun_kind),
		TunFD:         int(cp.tun_fd),
		MTU:           int(cp.mtu),
		BindIfIndexV4: uint32(cp.bind_ifindex_v4),
		BindIfIndexV6: uint32(cp.bind_ifindex_v6),
		MobileQuirks:  cp.mobile_quirks == 1,
		LogLevel:      int32(cp.log_level),
	}
	if cp.tun_name != nil {
		out.TunName = C.GoString(cp.tun_name)
	}
	if cp.transport_json != nil {
		out.TransportJSON = C.GoBytes(unsafe.Pointer(cp.transport_json), C.int(C.strlen(cp.transport_json)))
	}
	if fn, ctx := cp.log, cp.log_ctx; fn != nil {
		out.Log = func(level int32, msg []byte) {
			C.wgex_call_log(fn, ctx, C.int32_t(level), bytePtr(msg), C.size_t(len(msg)))
		}
	}
	if fn, ctx := cp.event, cp.event_ctx; fn != nil {
		out.Event = func(kind engine.EventKind, data []byte) {
			C.wgex_call_event(fn, ctx, C.int32_t(kind), bytePtr(data), C.size_t(len(data)))
		}
	}
	return out, true
}

// Create decodes wgex_create_params and creates an engine.
func Create(p unsafe.Pointer) int64 {
	params, ok := decodeParams(p)
	if !ok {
		return int64(engine.EINVAL)
	}
	markCreated()
	e, err := engine.New(params)
	if err != nil {
		return int64(engine.CodeOf(err))
	}
	return register(e)
}

// CreateWithTUN creates an engine over a ready tun device (test support:
// netstack). p may be nil; its tun_kind, tun_fd, tun_name and mtu are
// ignored. The engine owns t, also on failure.
func CreateWithTUN(p unsafe.Pointer, t wgtun.Device) int64 {
	params := engine.Params{}
	if p != nil {
		var ok bool
		if params, ok = decodeParams(p); !ok {
			t.Close()
			return int64(engine.EINVAL)
		}
	}
	params.TUN = t
	markCreated()
	e, err := engine.New(params)
	if err != nil {
		return int64(engine.CodeOf(err))
	}
	return register(e)
}

// HeaderABIVersion exposes the compiled header constant for the bridge contract check.
func HeaderABIVersion() int32 { return int32(C.WGEX_ABI_VERSION) }

// HeaderDeviceClosedCode exposes the compiled header error for the bridge contract check.
func HeaderDeviceClosedCode() int32 { return int32(C.WGEX_EDEVICECLOSED) }
