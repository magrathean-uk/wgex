// SPDX-License-Identifier: MIT

// Command bridge is the C ABI of the WGEX engine. It is built with
// -buildmode=c-archive, which requires package main; the exported functions
// are declared by hand in wgex.h (module CWGEXEngine) and the header cgo
// generates is discarded by Engine/scripts/build-xcframework.sh.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"runtime"
	"sync"
	"unsafe"

	"github.com/magrathean-uk/wgex/engine/engine"
)

// Set at link time by build-xcframework.sh with -X main.<name>=<value>.
var (
	appVersion = "0.0.0"
	build      = "0"
	scriptSHA  = "unknown"
)

type buildInfo struct {
	AppVersion   string `json:"app_version"`
	Build        string `json:"build"`
	EngineCommit string `json:"engine_commit"`
	Go           string `json:"go"`
	ScriptSHA    string `json:"script_sha"`
}

func buildInfoJSON() string {
	b, err := json.Marshal(buildInfo{
		AppVersion:   appVersion,
		Build:        build,
		EngineCommit: engine.WireGuardCommit,
		Go:           runtime.Version(),
		ScriptSHA:    scriptSHA,
	})
	if err != nil {
		// Marshalling a struct of strings cannot fail; keep the ABI total anyway.
		return "{}"
	}
	return string(b)
}

// staticBuildInfo is allocated once and never freed, so callers may keep the
// pointer for the life of the process and must not pass it to wgex_free.
var staticBuildInfo = sync.OnceValue(func() *C.char {
	return C.CString(buildInfoJSON())
})

//export wgex_build_info
func wgex_build_info() *C.char {
	return staticBuildInfo()
}

//export wgex_free
func wgex_free(p unsafe.Pointer) {
	C.free(p)
}

func main() {}
