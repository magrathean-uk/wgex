# SPDX-License-Identifier: MIT
"""Canonical, checkout-scoped build output resolver for shell and Python tools."""
import os
from pathlib import Path
import sys


def build_root(repository=None, environment=None):
    """Return <base>/<tree>, rejecting relative or source-tree output paths."""
    repository = Path(repository) if repository is not None else Path(__file__).resolve().parents[2]
    environment = os.environ if environment is None else environment
    fallback = Path(environment.get("TMPDIR") or "/tmp") / "wgex-build"
    base = Path(environment.get("WGEX_BUILD_ROOT") or environment.get("CLEAN_DEV_BUILDS") or fallback)
    output = base / repository.name
    resolved = repository.resolve()
    if not base.is_absolute() or base.resolve().is_relative_to(resolved) or output.resolve().is_relative_to(resolved):
        raise ValueError("build_root: WGEX_BUILD_ROOT/build base must be absolute and outside the repository")
    return output


if __name__ == "__main__":
    try:
        sys.stdout.write(str(build_root(Path(sys.argv[1]) if len(sys.argv) > 1 else None)))
    except ValueError as error:
        sys.exit(str(error))
