// SPDX-License-Identifier: MIT

// Package cabi is the C-facing layer shared by the bridge (package main) and
// the test-support exports: the handle registry, process settings, C struct
// decoding and the callback trampolines. The bridge's //export functions are
// one-line wrappers around it. The registry is the package's only global
// state (02-architecture §6.2); there is no package-global logger, no init
// function and no signal handling.
package cabi

import (
	"sync"
	"unsafe"

	"github.com/magrathean-uk/wgex/engine/engine"
)

type entry struct {
	e        *engine.Engine
	name     unsafe.Pointer // C string owned by the entry; nil if none
	freeOnce sync.Once
}

func (en *entry) release() {
	en.freeOnce.Do(func() {
		freeCString(en.name)
		en.name = nil
	})
}

type registry struct {
	mu       sync.Mutex
	next     int64
	live     map[int64]*entry
	closing  map[int64]*entry // destroyed, teardown still running
	created  bool             // an engine was created in this process
	procSet  bool
	procArgs engine.ProcessParams
}

// reg is the process-wide registry, the only global of the bridge.
var reg = registry{live: map[int64]*entry{}, closing: map[int64]*entry{}}

func code(c engine.Code) int32 { return int32(c) }

// ConfigureProcessParams applies process-wide settings once, before the
// first engine exists. A repeat with identical values succeeds; different
// values, or any call after an engine was created, return ESTATE.
func ConfigureProcessParams(p engine.ProcessParams) int32 {
	if err := p.Validate(); err != nil {
		return code(engine.EINVAL)
	}
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if reg.procSet {
		if p == reg.procArgs {
			return code(engine.OK)
		}
		return code(engine.ESTATE)
	}
	if reg.created {
		return code(engine.ESTATE)
	}
	engine.ApplyProcessParams(p)
	reg.procSet, reg.procArgs = true, p
	return code(engine.OK)
}

func markCreated() {
	reg.mu.Lock()
	reg.created = true
	reg.mu.Unlock()
}

func register(e *engine.Engine) int64 {
	name := cString(e.TunName())
	reg.mu.Lock()
	defer reg.mu.Unlock()
	reg.next++
	h := reg.next
	reg.live[h] = &entry{e: e, name: name}
	return h
}

// CreateGo creates and registers an engine from Go parameters (tests and
// test support). It returns a handle > 0 or an error code < 0.
func CreateGo(p engine.Params) int64 {
	markCreated()
	p.Log, p.Event = guardLog(p.Log), guardEvent(p.Event)
	e, err := engine.New(p)
	if err != nil {
		return int64(engine.CodeOf(err))
	}
	return register(e)
}

// Lookup returns the live engine for h.
func Lookup(h int64) (*engine.Engine, bool) {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	en, ok := reg.live[h]
	if !ok {
		return nil, false
	}
	return en.e, true
}

func with(h int64, fn func(e *engine.Engine) error) int32 {
	e, ok := Lookup(h)
	if !ok {
		return code(engine.EHANDLE)
	}
	return code(engine.CodeOf(fn(e)))
}

// SetConfig applies a full UAPI document. doc may point into C memory; it is
// only read during the call.
func SetConfig(h int64, doc []byte) int32 {
	if len(doc) == 0 {
		return code(engine.EINVAL)
	}
	return with(h, func(e *engine.Engine) error { return e.SetConfig(doc) })
}

// UpdateEndpoints applies an endpoint-only UAPI document.
func UpdateEndpoints(h int64, doc []byte) int32 {
	if len(doc) == 0 {
		return code(engine.EINVAL)
	}
	return with(h, func(e *engine.Engine) error { return e.UpdateEndpoints(doc) })
}

// Up brings the device up.
func Up(h int64) int32 { return with(h, (*engine.Engine).Up) }

// Down brings the device down.
func Down(h int64) int32 { return with(h, (*engine.Engine).Down) }

// ForceHandshake re-handshakes every peer.
func ForceHandshake(h int64) int32 { return with(h, (*engine.Engine).ForceHandshake) }

// BumpSockets rebinds the UDP transport to new interface indexes.
func BumpSockets(h int64, v4, v6 int32) int32 {
	if v4 < 0 || v6 < 0 {
		return code(engine.EINVAL)
	}
	return with(h, func(e *engine.Engine) error { return e.BumpSockets(uint32(v4), uint32(v6)) })
}

// SetTransport switches the inner transport.
func SetTransport(h int64, doc []byte) int32 {
	return with(h, func(e *engine.Engine) error { return e.SetTransport(doc) })
}

// PublicStatsJSON returns the public statistics document, or nil.
func PublicStatsJSON(h int64) []byte {
	e, ok := Lookup(h)
	if !ok {
		return nil
	}
	b, err := e.PublicStatsJSON()
	if err != nil {
		return nil
	}
	return b
}

// TunName returns the C string of the tun name, valid until wgex_destroy, or
// nil.
func TunName(h int64) unsafe.Pointer {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if en, ok := reg.live[h]; ok {
		return en.name
	}
	return nil
}

// Destroy tears the engine down and returns once no callback of it is in
// flight. It is idempotent: a handle that was already destroyed returns OK
// (after waiting for a teardown still in progress). Called from inside any
// engine callback it cannot wait for that callback, so it starts the
// teardown, returns OK at once, and no further callback of the engine starts
// once the current one returns.
func Destroy(h int64) int32 {
	reg.mu.Lock()
	en, ok := reg.live[h]
	if ok {
		delete(reg.live, h)
		reg.closing[h] = en
	} else if en, ok = reg.closing[h]; !ok {
		known := h > 0 && h <= reg.next
		reg.mu.Unlock()
		if known {
			return code(engine.OK)
		}
		return code(engine.EHANDLE)
	}
	reg.mu.Unlock()

	finish := func() {
		reg.mu.Lock()
		if reg.closing[h] == en {
			delete(reg.closing, h)
		}
		reg.mu.Unlock()
		en.release()
	}
	if inCallback() {
		en.e.CloseAsync()
		go func() {
			<-en.e.Done()
			finish()
		}()
		return code(engine.OK)
	}
	en.e.Close()
	finish()
	return code(engine.OK)
}

// Counts reports live and closing engines (tests).
func Counts() (live, closing int) {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	return len(reg.live), len(reg.closing)
}
