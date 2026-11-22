// SPDX-License-Identifier: MIT

package engine

import "golang.zx2c4.com/wireguard/device"

// QueueProfileApplies reports whether the queue profile changes anything on
// this GOOS.
const QueueProfileApplies = true

func applyQueueProfile(profile int32) {
	if profile != QueueProfileConstrained {
		return
	}
	device.QueueOutboundSize = ConstrainedQueueSize
	device.QueueInboundSize = ConstrainedQueueSize
	device.QueueHandshakeSize = ConstrainedQueueSize
	device.PreallocatedBuffersPerPool = ConstrainedQueueSize
}
