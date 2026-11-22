// SPDX-License-Identifier: MIT

//go:build wgextest

package main

// Links the wgex_test_* exports into the test-support archive only.
import _ "github.com/magrathean-uk/wgex/engine/testsupport"
