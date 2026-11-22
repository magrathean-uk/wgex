// SPDX-License-Identifier: MIT

package engine

import (
	"errors"
	"runtime/debug"
)

// Queue profiles (wgex_process_params.queue_profile).
const (
	QueueProfileDefault     int32 = 0
	QueueProfileConstrained int32 = 1
)

// ConstrainedQueueSize is the wireguard-go queue depth and pool preallocation
// of the constrained profile (02-architecture §6.3; tuned by P1-13).
const ConstrainedQueueSize = 256

// ProcessParams mirrors wgex_process_params.
type ProcessParams struct {
	// MemoryLimitBytes sets debug.SetMemoryLimit; 0 leaves the runtime default.
	MemoryLimitBytes int64
	// GCPercent sets debug.SetGCPercent; 0 leaves the default, -1 disables GC.
	GCPercent int32
	// QueueProfile is QueueProfileDefault or QueueProfileConstrained. It
	// changes wireguard-go's queue variables under GOOS=ios only; on macOS
	// they are constants.
	QueueProfile int32
}

// Validate checks the ranges.
func (p ProcessParams) Validate() error {
	if p.MemoryLimitBytes < 0 {
		return errors.New("memory_limit_bytes is negative")
	}
	if p.GCPercent < -1 {
		return errors.New("gc_percent below -1")
	}
	if p.QueueProfile != QueueProfileDefault && p.QueueProfile != QueueProfileConstrained {
		return errors.New("unknown queue_profile")
	}
	return nil
}

// ApplyProcessParams applies p. The caller (the registry) guarantees it runs
// at most once and before any device exists, because the iOS queue variables
// are read when a device is created.
func ApplyProcessParams(p ProcessParams) {
	if p.MemoryLimitBytes > 0 {
		debug.SetMemoryLimit(p.MemoryLimitBytes)
	}
	if p.GCPercent != 0 {
		debug.SetGCPercent(int(p.GCPercent))
	}
	applyQueueProfile(p.QueueProfile)
}

// FreeOSMemory returns as much memory to the OS as possible (memory-pressure
// handler).
func FreeOSMemory() { debug.FreeOSMemory() }
