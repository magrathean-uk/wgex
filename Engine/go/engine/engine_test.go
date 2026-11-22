// SPDX-License-Identifier: MIT

package engine

import (
	"strings"
	"testing"
)

func TestWireGuardCommitIsFullSHA(t *testing.T) {
	if len(WireGuardCommit) != 40 || strings.Trim(WireGuardCommit, "0123456789abcdef") != "" {
		t.Fatalf("WireGuardCommit %q is not a 40-character lowercase hex SHA", WireGuardCommit)
	}
}

func TestVersionDoesNotPanic(t *testing.T) {
	if Version() == "" {
		t.Fatal("Version returned an empty string")
	}
}
