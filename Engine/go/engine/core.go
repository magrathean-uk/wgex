// SPDX-License-Identifier: MIT

package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/device"
	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/magrathean-uk/wgex/engine/transport"
	etun "github.com/magrathean-uk/wgex/engine/tun"
)

// Socket bump retry policy (wgex_bump_sockets).
const (
	BumpAttempts = 10
	BumpInterval = 500 * time.Millisecond
)

type options struct {
	healthInterval time.Duration
	txWindow       time.Duration
	rxEvery        time.Duration
	bumpInterval   time.Duration
}

func defaultOptions() options {
	return options{
		healthInterval: HealthPollInterval,
		txWindow:       TxWithoutRxWindow,
		rxEvery:        RxEventInterval,
		bumpInterval:   BumpInterval,
	}
}

// Engine is one WireGuard device behind the C ABI: tun, SwitchBind, device,
// health sampler and callback dispatcher. Every method returns without
// waiting on the network.
type Engine struct {
	opts    options
	dev     *device.Device
	bind    *transport.SwitchBind
	udp     *transport.UDP
	tunName string
	quirks  bool
	disp    *dispatcher

	// opMu orders operations against Close: operations hold it shared and
	// re-check closed; Close takes it exclusively once to flip closed, so it
	// never waits on a callback that is itself inside an operation.
	opMu     sync.RWMutex
	closed   bool
	failed   atomic.Bool // the device closed unexpectedly or after a configuration failure
	logLevel int32

	cfgMu      sync.Mutex // serialises set_config / update_endpoints
	rebindPort uint16     // protected by cfgMu; survives upstream clearing its port on failure
	lastGood   []byte     // last applied full document; wiped when replaced

	ctx    context.Context
	cancel context.CancelFunc
	bg     sync.WaitGroup // health sampler and socket bumps

	bumpMu     sync.Mutex
	bumpCancel context.CancelFunc
	bumpDone   chan struct{}

	closeOnce sync.Once
	closedCh  chan struct{}
}

// New creates an engine. The device starts down; wgex_up brings it up.
func New(p Params) (*Engine, error) { return newEngine(p, defaultOptions()) }

func newEngine(p Params, o options) (*Engine, error) {
	if p.LogLevel < LogLevelDefault || p.LogLevel > LogLevelOff {
		if p.TUN != nil {
			_ = p.TUN.Close()
		}
		return nil, errorf(EINVAL, "invalid log level")
	}
	if _, err := ParseTransport(p.TransportJSON); err != nil {
		if p.TUN != nil {
			p.TUN.Close()
		}
		return nil, err
	}
	tdev := p.TUN
	if tdev == nil {
		var err error
		if tdev, err = createTUN(p); err != nil {
			return nil, err
		}
	}
	name, err := tdev.Name()
	if err != nil {
		name = ""
	}
	e := &Engine{
		opts:     o,
		logLevel: p.LogLevel,
		udp:      transport.NewUDP(p.BindIfIndexV4, p.BindIfIndexV6),
		tunName:  name,
		quirks:   p.MobileQuirks,
		disp:     newDispatcher(p.Log, p.Event),
		closedCh: make(chan struct{}),
	}
	e.bind = transport.New(e.udp)
	e.ctx, e.cancel = context.WithCancel(context.Background())
	e.dev = device.NewDevice(tdev, e.bind, &device.Logger{
		Verbosef: func(format string, args ...any) { e.logf(LogDebug, format, args...) },
		Errorf:   func(format string, args ...any) { e.logf(LogError, format, args...) },
	})
	if e.quirks {
		e.dev.DisableSomeRoamingForBrokenMobileSemantics()
	}
	e.bg.Add(2)
	go e.watchDevice()
	go e.runHealth(e.ctx, o.healthInterval, newHealthTracker(o.txWindow, o.rxEvery, time.Now()))
	return e, nil
}

func createTUN(p Params) (wgtun.Device, error) {
	switch p.TunKind {
	case TunNEUTun:
		if p.MTU != 0 {
			return nil, wrap(EINVAL, etun.ErrMTUNotAllowed)
		}
		if p.TunFD < 0 {
			return nil, errorf(EINVAL, "tun_fd %d", p.TunFD)
		}
		d, err := etun.FromUTunFD(p.TunFD, 0)
		return d, wrap(ETUN, err)
	case TunPacketFD:
		if p.TunFD < 0 || p.MTU < etun.MinPacketFDMTU || p.MTU > etun.MaxPacketFDMTU {
			return nil, errorf(EINVAL, "tun_kind 1 needs a descriptor and mtu %d...%d", etun.MinPacketFDMTU, etun.MaxPacketFDMTU)
		}
		d, err := etun.NewPacketFD(p.TunFD, p.MTU)
		return d, wrap(ETUN, err)
	case TunCreateUTun:
		if p.TunName == "" || p.MTU <= 0 {
			return nil, errorf(EINVAL, "tun_kind 2 needs tun_name and mtu")
		}
		d, err := etun.CreateUTun(p.TunName, p.MTU)
		return d, wrap(ETUN, err)
	}
	return nil, errorf(EINVAL, "unknown tun_kind %d", p.TunKind)
}

// logf checks the level before formatting, redacting or queueing a line.
func (e *Engine) logf(level int32, format string, args ...any) {
	if e.disp.logFn == nil || e.logLevel == LogLevelOff ||
		(level == LogDebug && e.logLevel != LogLevelDebug) ||
		(level == LogInfo && e.logLevel == LogLevelError) {
		return
	}
	e.disp.log(level, redactKeys(fmt.Appendf(nil, format, args...)))
}

func (e *Engine) note(event string, fields map[string]any) {
	v := map[string]any{"kind": "engine", "event": event}
	for k, f := range fields {
		v[k] = f
	}
	if event == "deviceClosed" {
		e.disp.deviceFailure(v)
		return
	}
	e.disp.event(EventEngine, v)
}

// begin enters an operation; end must be called when it returns no error.
func (e *Engine) begin() error {
	e.opMu.RLock()
	if e.closed {
		e.opMu.RUnlock()
		return errorf(EHANDLE, "engine destroyed")
	}
	return nil
}

func (e *Engine) end() { e.opMu.RUnlock() }

func (e *Engine) beginLive() error {
	if err := e.begin(); err != nil {
		return err
	}
	if e.deviceClosed() {
		e.end()
		return errorf(EDEVICECLOSED, "device closed; destroy the engine")
	}
	return nil
}

// TunName returns the tun interface name ("" if unknown).
func (e *Engine) TunName() string { return e.tunName }

// SetConfig applies a full configuration (replace_peers=true). doc is read
// as bytes through a bytes.Reader; WGEX never builds a string from it.
// On an IpcSetOperation failure the last good document is re-applied and
// ECONFIG returned with the device running; when there is no good document,
// or re-applying it fails too, EDEVICECLOSED is returned (state "failed") and only
// Close remains useful. The engine keeps its own copy of the last good
// document and wipes superseded copies; the caller may wipe doc on return.
func (e *Engine) SetConfig(doc []byte) error {
	if err := e.beginLive(); err != nil {
		return err
	}
	defer e.end()
	if err := ValidateFullConfig(doc); err != nil {
		return wrap(EINVAL, err)
	}
	e.cfgMu.Lock()
	defer e.cfgMu.Unlock()
	err := e.dev.IpcSetOperation(bytes.NewReader(doc))
	if e.deviceClosed() {
		return errorf(EDEVICECLOSED, "device closed")
	}
	if err == nil {
		e.applyQuirks()
		wipe(e.lastGood)
		e.lastGood = bytes.Clone(doc)
		if st, sampleErr := e.sample(); sampleErr == nil {
			e.rebindPort = st.ListenPort
		}
		return nil
	}
	e.logf(LogError, "set_config failed: %v", ipcCause(err))
	if e.lastGood != nil {
		if rerr := e.dev.IpcSetOperation(bytes.NewReader(e.lastGood)); rerr == nil {
			if e.deviceClosed() {
				return errorf(EDEVICECLOSED, "device closed")
			}
			e.applyQuirks()
			e.note("configRestored", nil)
			return wrap(ECONFIG, errors.New("configuration rejected; previous configuration restored"))
		}
	}
	e.failDevice(DeviceClosedConfiguration)
	return wrap(EDEVICECLOSED, errors.New("configuration rejected; device closed"))
}

// ipcCause keeps only the IPC error code: wireguard-go's messages can quote
// the offending line.
func ipcCause(err error) string {
	var ipcErr *device.IPCError
	if errors.As(err, &ipcErr) {
		return fmt.Sprintf("IPC error %d", ipcErr.ErrorCode())
	}
	return "IPC error"
}

func (e *Engine) failDevice(reason int32) {
	if e.failed.Swap(true) {
		return
	}
	e.cancel()
	e.dev.Close()
	wipe(e.lastGood)
	e.lastGood = nil
	e.note("deviceClosed", map[string]any{"reason": reason})
}

// Fixed reason codes form the public lifecycle contract; no device error text escapes.
const (
	DeviceClosedTUN           int32 = 1
	DeviceClosedConfiguration int32 = 2
)

func (e *Engine) deviceClosed() bool {
	if e.failed.Load() {
		return true
	}
	select {
	case <-e.dev.Wait():
		return true
	default:
		return false
	}
}

func (e *Engine) watchDevice() {
	defer e.bg.Done()
	select {
	case <-e.ctx.Done():
		return
	case <-e.dev.Wait():
	}
	e.opMu.RLock()
	defer e.opMu.RUnlock()
	if e.closed || e.failed.Swap(true) {
		return
	}
	e.cancel()
	e.cfgMu.Lock()
	wipe(e.lastGood)
	e.lastGood = nil
	e.cfgMu.Unlock()
	e.note("deviceClosed", map[string]any{"reason": DeviceClosedTUN})
}

func (e *Engine) liveResult(code Code, err error) error {
	if e.deviceClosed() {
		return errorf(EDEVICECLOSED, "device closed")
	}
	return wrap(code, err)
}

func (e *Engine) applyQuirks() {
	if e.quirks {
		e.dev.DisableSomeRoamingForBrokenMobileSemantics()
	}
}

// UpdateEndpoints applies public_key / update_only=true / endpoint blocks
// without replacing peers, so sessions survive.
func (e *Engine) UpdateEndpoints(doc []byte) error {
	if err := e.beginLive(); err != nil {
		return err
	}
	defer e.end()
	if err := ValidateEndpointUpdate(doc); err != nil {
		return wrap(EINVAL, err)
	}
	e.cfgMu.Lock()
	defer e.cfgMu.Unlock()
	if err := e.dev.IpcSetOperation(bytes.NewReader(doc)); err != nil {
		e.logf(LogError, "update_endpoints failed: %v", ipcCause(err))
		return e.liveResult(ECONFIG, errors.New("endpoint update rejected"))
	}
	e.applyQuirks()
	return e.liveResult(ECONFIG, nil)
}

// Up brings the device up (opens SwitchBind).
func (e *Engine) Up() error {
	if err := e.beginLive(); err != nil {
		return err
	}
	defer e.end()
	return e.liveResult(EUP, e.dev.Up())
}

// Down brings the device down. An already-closed device is already down;
// only a destroyed engine handle is invalid.
func (e *Engine) Down() error {
	if err := e.begin(); err != nil {
		return err
	}
	defer e.end()
	if e.deviceClosed() {
		return nil
	}
	err := e.dev.Down()
	if e.deviceClosed() {
		return nil
	}
	return wrap(EUP, err)
}

// BumpSockets rebinds the UDP transport to new interface indexes. It returns
// at once; a background attempt calls BindUpdate up to BumpAttempts times,
// BumpInterval apart, then sends keepalives to peers with a current keypair.
// A new call cancels the previous attempt; Close cancels it too.
func (e *Engine) BumpSockets(ifV4, ifV6 uint32) error {
	if err := e.beginLive(); err != nil {
		return err
	}
	defer e.end()
	e.bumpMu.Lock()
	if e.bumpCancel != nil {
		e.bumpCancel()
	}
	prev := e.bumpDone
	ctx, cancel := context.WithCancel(e.ctx)
	done := make(chan struct{})
	e.bumpCancel, e.bumpDone = cancel, done
	e.bumpMu.Unlock()

	e.bg.Add(1) // safe: Close cannot be waiting while we hold opMu shared
	go func() {
		defer e.bg.Done()
		defer close(done)
		defer cancel()
		if prev != nil {
			select {
			case <-prev:
			case <-ctx.Done():
				return
			}
		}
		e.bump(ctx, ifV4, ifV6)
	}()
	return nil
}

func (e *Engine) bump(ctx context.Context, ifV4, ifV6 uint32) {
	e.udp.SetInterfaces(ifV4, ifV6)
	var err error
	for attempt := 1; attempt <= BumpAttempts; attempt++ {
		if ctx.Err() != nil {
			return
		}
		if err = e.rebindUDP(); err == nil {
			e.dev.SendKeepalivesToPeersWithCurrentKeypair()
			e.note("socketsBumped", map[string]any{"ok": true, "attempts": attempt})
			return
		}
		e.logf(LogError, "bump_sockets attempt %d: %v", attempt, err)
		t := time.NewTimer(e.opts.bumpInterval)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
	e.note("socketsBumped", map[string]any{"ok": false, "attempts": BumpAttempts})
}

// rebindUDP preserves the selected port across failed opens. IpcSetOperation
// reopens the bind when restoring a port cleared by upstream BindUpdate.
func (e *Engine) rebindUDP() error {
	e.cfgMu.Lock()
	defer e.cfgMu.Unlock()
	st, err := e.sample()
	if err != nil {
		return err
	}
	if st.ListenPort != 0 {
		e.rebindPort = st.ListenPort
	}
	if st.ListenPort != e.rebindPort {
		return e.dev.IpcSetOperation(bytes.NewReader(fmt.Appendf(nil, "listen_port=%d\n", e.rebindPort)))
	}
	return e.dev.BindUpdate()
}

// SetTransport switches SwitchBind's inner transport. Until the carrier
// transports land only udp→udp exists, which rebinds the UDP sockets on the
// same port (BindUpdate) and keeps sessions.
func (e *Engine) SetTransport(doc []byte) error {
	if err := e.beginLive(); err != nil {
		return err
	}
	defer e.end()
	kind, err := ParseTransport(doc)
	if err != nil {
		return err
	}
	if kind != TransportUDP || e.bind.Inner().Kind() != TransportUDP {
		return errorf(EINVAL, "transport switch not supported")
	}
	if err := e.rebindUDP(); err != nil {
		return e.liveResult(EBIND, err)
	}
	e.note("transportChanged", map[string]any{"transport": kind})
	return e.liveResult(EBIND, nil)
}

// ForceHandshake expires every peer's current keypairs and sends a fresh
// handshake initiation, keeping peers and their (possibly roamed) endpoints.
func (e *Engine) ForceHandshake() error {
	if err := e.beginLive(); err != nil {
		return err
	}
	defer e.end()
	st, err := e.sample()
	if err != nil {
		return e.liveResult(EINTERNAL, err)
	}
	for _, p := range st.Peers {
		peer := e.dev.LookupPeer(device.NoisePublicKey(p.PublicKey))
		if peer == nil {
			continue
		}
		peer.ExpireCurrentKeypairs()
		if err := peer.SendHandshakeInitiation(false); err != nil {
			e.logf(LogError, "%v - force_handshake: %v", peer, err)
		}
	}
	return e.liveResult(EINTERNAL, nil)
}

// sample reads the secret-free device state.
func (e *Engine) sample() (uapiState, error) {
	var c getCollector
	if err := e.dev.IpcGetOperation(&c); err != nil {
		c.finish()
		return uapiState{}, err
	}
	return c.finish(), nil
}

// PublicStatsJSON returns the public statistics document.
func (e *Engine) PublicStatsJSON() ([]byte, error) {
	if err := e.beginLive(); err != nil {
		return nil, err
	}
	defer e.end()
	st, err := e.sample()
	if err != nil {
		return nil, wrap(EINTERNAL, err)
	}
	b, err := publicStatsJSON(st, e.tunName, time.Now())
	return b, wrap(EINTERNAL, err)
}

// Close tears the engine down and returns when no callback is in flight. It
// is idempotent. It must not be called from one of this engine's callbacks
// (use CloseAsync there).
func (e *Engine) Close() {
	e.startClose()
	<-e.closedCh
}

// CloseAsync starts the teardown and returns at once; no callback starts
// after the one currently running (if any) returns. Done reports completion.
func (e *Engine) CloseAsync() {
	e.disp.abort()
	e.startClose()
}

// Done is closed when the teardown has finished.
func (e *Engine) Done() <-chan struct{} { return e.closedCh }

func (e *Engine) startClose() {
	e.closeOnce.Do(func() {
		e.opMu.Lock()
		e.closed = true
		e.opMu.Unlock()
		// Always launch outside closeOnce: a concurrent callback may itself
		// request CloseAsync while a synchronous Close waits for delivery.
		go e.teardown()
	})
}

func (e *Engine) teardown() {
	e.cancel()
	e.bg.Wait()
	e.dev.Close()
	e.cfgMu.Lock()
	wipe(e.lastGood)
	e.lastGood = nil
	e.cfgMu.Unlock()
	e.disp.stop()
	close(e.closedCh)
}

// DroppedCallbacks reports log lines and events dropped because a queue was
// full.
func (e *Engine) DroppedCallbacks() (logs, events uint64) {
	return e.disp.droppedLogs.Load(), e.disp.droppedEvents.Load()
}
