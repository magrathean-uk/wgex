// SPDX-License-Identifier: MIT

//go:build wgextest

package testsupport

import (
	"slices"
	"testing"

	"github.com/magrathean-uk/wgex/engine/internal/abicheck"
)

func TestTestHeaderMatchesExports(t *testing.T) {
	decl, err := abicheck.HeaderFunctions("wgex_test.h")
	if err != nil {
		t.Fatal(err)
	}
	exp, err := abicheck.Exports(".")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(decl, exp) {
		t.Fatalf("wgex_test.h declares %v\ntestsupport exports %v", decl, exp)
	}
}
