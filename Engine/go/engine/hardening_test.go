// SPDX-License-Identifier: MIT

package engine

import (
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestUnexpectedDeviceCloseIsFatal(t *testing.T) {
	rec := newRecorder()
	tun := newFakeTUN()
	e, err := New(Params{TUN: tun, Event: rec.event})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	start := time.Now()
	_ = tun.Close() // makes the upstream tun Read fail, not an engine shutdown
	waitFor(t, time.Second, "deviceClosed", func() bool {
		for _, event := range rec.eventsOf(EventEngine) {
			if event["event"] == "deviceClosed" && event["reason"] == float64(1) {
				return true
			}
		}
		return false
	})
	if time.Since(start) >= time.Second {
		t.Fatal("device closure exceeded one second")
	}
	for _, call := range []func() error{e.Up, func() error { return e.SetConfig(nil) }} {
		if CodeOf(call()) != Code(-9) {
			t.Fatal("closed device did not return EDEVICECLOSED")
		}
	}
	for range 2 {
		if e.Down() != nil {
			t.Fatal("Down must succeed on an already-closed device")
		}
	}
}

func TestLiveResultRechecksClosureAfterOperationBegins(t *testing.T) {
	e := newFakeEngine(t, defaultOptions(), newRecorder())
	defer e.Close()
	if err := e.beginLive(); err != nil {
		t.Fatal("cannot begin live operation")
	}
	defer e.end()
	e.dev.Close()
	for _, code := range []Code{ECONFIG, EBIND, EINTERNAL} {
		for _, result := range []error{nil, errors.New("fixture operation failure")} {
			if CodeOf(e.liveResult(code, result)) != EDEVICECLOSED {
				t.Fatal("device closure must take precedence over an in-flight operation result")
			}
		}
	}
}

type formatProbe struct{ calls *int }

func (p formatProbe) String() string { *p.calls++; return "fixture" }

func TestDefaultLoggerSkipsDebugFormatting(t *testing.T) {
	calls := 0
	e := newFakeEngine(t, defaultOptions(), newRecorder())
	defer e.Close()
	e.logf(LogDebug, "%s", formatProbe{&calls})
	if calls != 0 {
		t.Fatal("disabled debug log was formatted")
	}
	e.logf(LogError, "%s", formatProbe{&calls})
	if calls != 1 {
		t.Fatalf("enabled error log formatted %d times", calls)
	}
}

func TestNormalCloseDoesNotReportDeviceFailure(t *testing.T) {
	rec := newRecorder()
	e, err := New(Params{TUN: newFakeTUN(), Event: rec.event})
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
	for _, event := range rec.eventsOf(EventEngine) {
		if event["event"] == "deviceClosed" {
			t.Fatal("normal shutdown reported as failure")
		}
	}
}

func TestDeviceClosedSurvivesFullHealthQueue(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var first, released sync.Once
	var closed atomic.Bool
	d := newDispatcher(nil, func(kind EventKind, data []byte) {
		first.Do(func() { close(entered); <-release })
		if kind == EventEngine {
			var event struct {
				Event string `json:"event"`
			}
			if json.Unmarshal(data, &event) == nil && event.Event == "deviceClosed" {
				closed.Store(true)
			}
		}
	})
	defer func() { released.Do(func() { close(release) }); d.stop() }()
	d.event(EventRx, map[string]any{"kind": "rx"})
	<-entered
	for range eventQueue {
		d.event(EventRx, map[string]any{"kind": "rx"})
	}
	e := &Engine{disp: d}
	e.note("deviceClosed", map[string]any{"reason": DeviceClosedTUN})
	released.Do(func() { close(release) })
	waitFor(t, time.Second, "fatal lifecycle event after health saturation", closed.Load)
}
