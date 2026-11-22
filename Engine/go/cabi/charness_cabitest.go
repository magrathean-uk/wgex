// SPDX-License-Identifier: MIT

//go:build wgexcabitest

package cabi

// C harness for the C-path tests (cpath_test.go): C callbacks that count
// deliveries and can call wgex_destroy's Go implementation from inside an
// event callback, plus builders for wgex_create_params. Go tests
// only (tag wgexcabitest; never in an archive).

/*
#cgo CFLAGS: -I${SRCDIR}/../bridge
#include <stdlib.h>
#include <stdatomic.h>
#include "wgex.h"
extern int wgexHarnessDestroy(int64_t h); // charness_export_cabitest.go

typedef struct {
	int64_t handle;
	int destroy_from_event;
	atomic_int destroy_rc;
	atomic_int destroy_calls;
	atomic_long logs;
	atomic_long events;
} wgex_harness;

static void wgex_harness_log(void *ctx, int32_t level, const char *msg, size_t len) {
	wgex_harness *h = ctx;
	atomic_fetch_add(&h->logs, 1);
}

static void wgex_harness_event(void *ctx, int32_t kind, const char *json, size_t len) {
	wgex_harness *h = ctx;
	atomic_fetch_add(&h->events, 1);
	if (h->destroy_from_event && atomic_fetch_add(&h->destroy_calls, 1) == 0) {
		atomic_store(&h->destroy_rc, wgexHarnessDestroy(h->handle));
	}
}

static wgex_harness *wgex_harness_new(int destroy_from_event) {
	wgex_harness *h = calloc(1, sizeof(wgex_harness));
	h->destroy_from_event = destroy_from_event;
	atomic_store(&h->destroy_rc, 1);
	return h;
}

static wgex_create_params *wgex_harness_params(wgex_harness *h, int32_t kind, int32_t fd, int32_t mtu, const char *transport) {
	wgex_create_params *p = calloc(1, sizeof(wgex_create_params));
	p->tun_kind = kind;
	p->tun_fd = fd;
	p->mtu = mtu;
	p->transport_json = transport;
	p->log_level = 1;
	p->log = wgex_harness_log;
	p->log_ctx = h;
	p->event = wgex_harness_event;
	p->event_ctx = h;
	return p;
}

static wgex_process_params *wgex_harness_process(int64_t limit, int32_t gc, int32_t profile) {
	wgex_process_params *p = calloc(1, sizeof(wgex_process_params));
	p->memory_limit_bytes = limit;
	p->gc_percent = gc;
	p->queue_profile = profile;
	return p;
}

static long wgex_harness_logs(wgex_harness *h) { return atomic_load(&h->logs); }
static long wgex_harness_events(wgex_harness *h) { return atomic_load(&h->events); }
static int wgex_harness_rc(wgex_harness *h) { return atomic_load(&h->destroy_rc); }
static void wgex_harness_set_handle(wgex_harness *h, int64_t v) { h->handle = v; }
*/
import "C"

import "unsafe"

// Harness is a C callback context.
type Harness struct{ h *C.wgex_harness }

// NewHarness allocates a callback context; destroyFromEvent makes the first
// event callback call Destroy on the harness handle.
func NewHarness(destroyFromEvent bool) *Harness {
	v := 0
	if destroyFromEvent {
		v = 1
	}
	return &Harness{h: C.wgex_harness_new(C.int(v))}
}

// Params builds a wgex_create_params bound to the harness callbacks. Free
// the result with FreeC; transport may be "".
func (h *Harness) Params(kind, fd, mtu int32, transport string) unsafe.Pointer {
	var tj *C.char
	if transport != "" {
		tj = C.CString(transport) // leaked deliberately: tests only
	}
	return unsafe.Pointer(C.wgex_harness_params(h.h, C.int32_t(kind), C.int32_t(fd), C.int32_t(mtu), tj))
}

// SetHandle records the handle Destroy is called with.
func (h *Harness) SetHandle(v int64) { C.wgex_harness_set_handle(h.h, C.int64_t(v)) }

// Logs and Events count deliveries; DestroyRC is the in-callback Destroy result (1 = not called).
func (h *Harness) Logs() int64    { return int64(C.wgex_harness_logs(h.h)) }
func (h *Harness) Events() int64  { return int64(C.wgex_harness_events(h.h)) }
func (h *Harness) DestroyRC() int { return int(C.wgex_harness_rc(h.h)) }

// Free releases the harness; call only after the engine is destroyed.
func (h *Harness) Free() { C.free(unsafe.Pointer(h.h)) }

// ProcessParams builds a wgex_process_params.
func ProcessParamsC(limit int64, gc, profile int32) unsafe.Pointer {
	return unsafe.Pointer(C.wgex_harness_process(C.int64_t(limit), C.int32_t(gc), C.int32_t(profile)))
}

// FreeC frees C memory from the builders.
func FreeC(p unsafe.Pointer) { C.free(p) }
