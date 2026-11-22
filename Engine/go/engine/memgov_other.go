// SPDX-License-Identifier: MIT

//go:build !ios

package engine

// QueueProfileApplies reports whether the queue profile changes anything on
// this GOOS: wireguard-go's queue sizes are constants outside GOOS=ios.
const QueueProfileApplies = false

func applyQueueProfile(int32) {}
