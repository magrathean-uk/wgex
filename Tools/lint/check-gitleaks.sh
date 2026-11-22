#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Whole-tree gitleaks scan behind `just lint` (M00-T01). Unlike the typos, public-prose and secret-string steps it
# covers .plan/: every file under the repository root is read, tracked or not, the same scope as the pre-commit
# gitleaks hook. Findings are named (file, rule, line) with the secret redacted, and any finding fails the step.
# gitleaks is a local binary and makes no network calls, so the step runs offline. The house .gitleaks.toml must
# exist (a missing allowlist fails closed); accepted fingerprints come from .gitleaksignore.
set -euo pipefail
# shellcheck source=Tools/lint/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$LINT_ROOT"
if [[ ! -f .gitleaks.toml ]]; then
  echo 'check-gitleaks: .gitleaks.toml is missing at the repository root' >&2
  exit 1
fi
if ! command -v gitleaks >/dev/null 2>&1; then
  echo 'check-gitleaks: gitleaks is not installed (see Toolchain.lock)' >&2
  exit 1
fi
exec gitleaks dir --redact --verbose --no-banner --no-color --exit-code 1 \
  --config .gitleaks.toml --gitleaks-ignore-path .gitleaksignore .
