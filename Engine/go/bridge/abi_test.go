// SPDX-License-Identifier: MIT

package main

import (
	"slices"
	"testing"

	"github.com/magrathean-uk/wgex/engine/cabi"
	"github.com/magrathean-uk/wgex/engine/engine"
	"github.com/magrathean-uk/wgex/engine/internal/abicheck"
)

// The hand-written header declares exactly the functions the bridge exports.
func TestHeaderMatchesExports(t *testing.T) {
	decl, err := abicheck.HeaderFunctions("wgex.h")
	if err != nil {
		t.Fatal(err)
	}
	exp, err := abicheck.Exports(".")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(decl, exp) {
		t.Fatalf("wgex.h declares %v\nbridge exports %v", decl, exp)
	}
	want := []string{
		"wgex_abi_version", "wgex_build_info", "wgex_bump_sockets", "wgex_configure_process", "wgex_create", "wgex_destroy",
		"wgex_find_utun_fd", "wgex_force_handshake", "wgex_free", "wgex_free_os_memory", "wgex_public_stats_json",
		"wgex_resolve", "wgex_set_config", "wgex_set_transport", "wgex_tun_name", "wgex_up", "wgex_down",
		"wgex_update_endpoints",
	}
	slices.Sort(want)
	if !slices.Equal(exp, want) {
		t.Fatalf("exports %v, want the 02 §6.2 set plus wgex_resolve: %v", exp, want)
	}
}

func TestHeaderVersionAndDeviceClosedCode(t *testing.T) {
	if cabi.HeaderABIVersion() != engine.ABIVersion || engine.ABIVersion != 2 {
		t.Fatal("header ABI version mismatch")
	}
	if cabi.HeaderDeviceClosedCode() != int32(engine.EDEVICECLOSED) {
		t.Fatal("header device-closed code mismatch")
	}
}
