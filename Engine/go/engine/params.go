// SPDX-License-Identifier: MIT

package engine

import (
	"bytes"
	"encoding/json"
	"errors"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// TunKind selects how wgex_create obtains its tun device.
type TunKind int32

// Tun kinds (wgex_create_params.tun_kind).
const (
	// TunNEUTun wraps the utun descriptor NetworkExtension opened; mtu must be 0.
	TunNEUTun TunKind = 0
	// TunPacketFD wraps one end of a SOCK_DGRAM socketpair.
	TunPacketFD TunKind = 1
	// TunCreateUTun creates a utun interface (root only).
	TunCreateUTun TunKind = 2
)

// Log levels passed to LogFunc (EngineLogLine.Level in Swift).
const (
	LogDebug int32 = 0
	LogInfo  int32 = 1
	LogError int32 = 2
)

// Configured minimum log levels. Zero defaults to info, never debug.
const (
	LogLevelDefault int32 = iota
	LogLevelDebug
	LogLevelError
	LogLevelOff
)

// LogFunc receives one log line. msg is valid only for the call.
type LogFunc func(level int32, msg []byte)

// EventFunc receives one event. data is a JSON object valid only for the call.
type EventFunc func(kind EventKind, data []byte)

// Params configures New. It mirrors wgex_create_params.
type Params struct {
	TunKind       TunKind
	TunFD         int
	TunName       string
	MTU           int
	BindIfIndexV4 uint32
	BindIfIndexV6 uint32
	// TransportJSON is a TransportSpec; empty means {"kind":"udp"}.
	TransportJSON []byte
	MobileQuirks  bool
	LogLevel      int32
	Log           LogFunc
	Event         EventFunc
	// TUN, when set, is used instead of creating a device from TunKind. Test
	// support (netstack pairs) and tests use it; it takes ownership.
	TUN wgtun.Device
}

// TransportUDP is the only transport kind before phase 6.
const TransportUDP = "udp"

type transportSpec struct {
	Kind string `json:"kind"`
}

// ParseTransport validates a TransportSpec document and returns its kind.
// Only {"kind":"udp"} is accepted until the carrier transports land.
func ParseTransport(doc []byte) (string, error) {
	if len(bytes.TrimSpace(doc)) == 0 {
		return TransportUDP, nil
	}
	var spec transportSpec
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&spec); err != nil {
		return "", errorf(EINVAL, "transport spec: %w", err)
	}
	if dec.More() {
		return "", errorf(EINVAL, "transport spec: trailing data")
	}
	if spec.Kind != TransportUDP {
		return "", &Error{Code: EINVAL, Err: errors.New("transport kind not supported")}
	}
	return spec.Kind, nil
}
