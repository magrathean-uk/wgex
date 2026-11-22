// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"runtime"
	"testing"

	"github.com/magrathean-uk/wgex/engine/engine"
)

func TestBuildInfoJSON(t *testing.T) {
	var got map[string]string
	if err := json.Unmarshal([]byte(buildInfoJSON()), &got); err != nil {
		t.Fatalf("build info is not JSON: %v", err)
	}
	want := map[string]string{
		"app_version":   appVersion,
		"build":         build,
		"engine_commit": engine.WireGuardCommit,
		"go":            runtime.Version(),
		"script_sha":    scriptSHA,
	}
	if len(got) != len(want) {
		t.Fatalf("build info has %d keys, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("build info %s = %q, want %q", k, got[k], v)
		}
	}
}
