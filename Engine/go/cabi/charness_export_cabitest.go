// SPDX-License-Identifier: MIT

//go:build wgexcabitest

package cabi

/*
#include <stdint.h>
*/
import "C"

//export wgexHarnessDestroy
func wgexHarnessDestroy(h C.int64_t) C.int {
	return C.int(Destroy(int64(h)))
}
