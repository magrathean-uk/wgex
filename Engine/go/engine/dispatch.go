// SPDX-License-Identifier: MIT

package engine

import (
	"encoding/json"
	"sync"
	"sync/atomic"
)

// EventKind mirrors wgex_event_kind_t.
type EventKind int32

// Event kinds. The JSON payload always carries the same name in "kind".
const (
	// EventEngine: engine lifecycle notes ({"kind":"engine","event":...}).
	EventEngine EventKind = 0
	// EventHandshakeCompleted: {"kind":"handshakeCompleted","peer":b64,"at":rfc3339}.
	EventHandshakeCompleted EventKind = 1
	// EventTxWithoutRx: {"kind":"txWithoutRx","peer":b64,"since":rfc3339,"window":n}.
	EventTxWithoutRx EventKind = 2
	// EventRx: {"kind":"rx","at":rfc3339}, at most one per RxEventInterval.
	EventRx EventKind = 3
	// EventEndpointChanged: {"kind":"endpointChanged","peer":b64,"endpoint":"ip:port"}.
	EventEndpointChanged EventKind = 4
	// EventTransport: carrier events from phase 6 ({"kind":"transport","event":...}).
	EventTransport EventKind = 5
)

// Queue depths between emitters and the dispatcher goroutine. Emitters never
// block: when a queue is full the item is dropped and counted.
const (
	eventQueue = 256
	logQueue   = 1024
	// drainLogs bounds the log lines still delivered by stop, so a slow log
	// callback cannot hold wgex_destroy for the whole queue.
	drainLogs = 16
)

type logItem struct {
	level int32
	msg   []byte
}

type eventItem struct {
	kind EventKind
	data []byte
}

// dispatcher delivers callbacks on one goroutine per engine, so callbacks
// never run on wireguard-go's goroutines or under any engine or device lock,
// and a slow callback can only cost dropped log lines, never stall the data
// path.
type dispatcher struct {
	logFn   LogFunc
	eventFn EventFunc
	logs    chan logItem
	events  chan eventItem
	fatal   chan eventItem
	quit    chan struct{}
	done    chan struct{}
	stopped atomic.Bool
	discard atomic.Bool
	once    sync.Once

	droppedLogs   atomic.Uint64
	droppedEvents atomic.Uint64
}

func newDispatcher(logFn LogFunc, eventFn EventFunc) *dispatcher {
	d := &dispatcher{
		logFn:   logFn,
		eventFn: eventFn,
		logs:    make(chan logItem, logQueue),
		events:  make(chan eventItem, eventQueue),
		fatal:   make(chan eventItem, 1),
		quit:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	if logFn == nil && eventFn == nil {
		d.stopped.Store(true)
		close(d.done)
		return d
	}
	go d.run()
	return d
}

func (d *dispatcher) log(level int32, msg []byte) {
	if d.logFn == nil || d.stopped.Load() {
		return
	}
	select {
	case d.logs <- logItem{level, msg}:
	default:
		d.droppedLogs.Add(1)
	}
}

func (d *dispatcher) event(kind EventKind, v any) {
	d.enqueue(kind, v, d.events)
}

// deviceFailure has a reserved slot: a health burst cannot hide the one fatal
// lifecycle event. Each engine transitions to failed at most once.
func (d *dispatcher) deviceFailure(v any) {
	d.enqueue(EventEngine, v, d.fatal)
}

func (d *dispatcher) enqueue(kind EventKind, v any, queue chan eventItem) {
	if d.eventFn == nil || d.stopped.Load() {
		return
	}
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	select {
	case queue <- eventItem{kind, data}:
	default:
		d.droppedEvents.Add(1)
	}
}

func (d *dispatcher) deliverEvent(it eventItem) {
	if d.eventFn != nil && !d.discard.Load() {
		d.eventFn(it.kind, it.data)
	}
}

func (d *dispatcher) deliverLog(it logItem) {
	if d.logFn != nil && !d.discard.Load() {
		d.logFn(it.level, it.msg)
	}
}

func (d *dispatcher) run() {
	defer close(d.done)
	for {
		// Fatal closure first, independent of health queue saturation.
		select {
		case it := <-d.fatal:
			d.deliverEvent(it)
			continue
		default:
		}
		// Events first: they drive health and are never starved by logs.
		select {
		case it := <-d.events:
			d.deliverEvent(it)
			continue
		default:
		}
		select {
		case it := <-d.fatal:
			d.deliverEvent(it)
		case it := <-d.events:
			d.deliverEvent(it)
		case it := <-d.logs:
			d.deliverLog(it)
		case <-d.quit:
			d.drain()
			return
		}
	}
}

// drain delivers the events queued before stop and up to drainLogs log
// lines, without waiting for more; the remaining lines are counted as dropped.
func (d *dispatcher) drain() {
	logs := 0
	for {
		select {
		case it := <-d.fatal:
			d.deliverEvent(it)
			continue
		default:
		}
		select {
		case it := <-d.events:
			d.deliverEvent(it)
			continue
		default:
		}
		select {
		case it := <-d.logs:
			if logs < drainLogs {
				d.deliverLog(it)
				logs++
			} else {
				d.droppedLogs.Add(1)
			}
		default:
			return
		}
	}
}

// abort stops delivery immediately, including queued items. It never waits, so
// the currently executing callback can call it safely.
func (d *dispatcher) abort() {
	d.discard.Store(true)
	d.once.Do(func() {
		d.stopped.Store(true)
		close(d.quit)
	})
}

// stop refuses new items, delivers the queued ones and waits until no
// callback is in flight. It must not be called from a callback.
func (d *dispatcher) stop() {
	d.once.Do(func() {
		d.stopped.Store(true)
		close(d.quit)
	})
	<-d.done
}
