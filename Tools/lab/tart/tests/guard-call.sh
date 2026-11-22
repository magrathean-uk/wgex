#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Test driver for tart/tests/run.sh: sources the tracked guest guard and runs the one argument as code, so a test calls a
# guard function in a fresh shell without a wrapped `bash -c 'source ...'` line. Never run outside the offline harness.
# shellcheck source=Tools/lab/tart/guest/guard.sh
source "$(dirname "$0")/../guest/guard.sh"
eval "$1"
