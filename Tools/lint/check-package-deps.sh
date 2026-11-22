#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Package dependency rules (plan 02 §2, ADR-002; ticket P0-04). For every
# Package.swift (parsed with `swift package dump-package`) it checks:
#   - package, product and target names against the table below;
#   - platforms are exactly macOS 26, iOS 27, tvOS 27;
#   - each regular target's dependency closure equals the table's;
#   - client products (WGEXDaemonClient, WGEXNEClient) never reach WGEXEngine;
#   - no SwiftUI import outside WGEXUI and WGEXUITesting, and WGEXCore imports
#     only Foundation, CryptoKit, Network and Synchronization;
#   - Swift 6 mode with the four upcoming features; MainActor default
#     isolation only in WGEXUI and WGEXUITesting; strict memory safety in
#     the WGEXEngine package;
#   - SMAppService appears in code only in WGEXDaemonClient's
#     ServiceController.swift (P0-18 host guard); comments are ignored.
# Usage: check-package-deps.sh [packages-dir]
#        check-package-deps.sh --release-imports <Swift-file-or-directory>
# Default repository mode also checks that app imports exclude WGEXTesting and WGEXDaemonCoreTesting in Release.
#   With no argument it checks Packages/ and also requires every package to
#   exist; with a directory (a fixture) it checks only what is there.
set -euo pipefail
# shellcheck source=Tools/lint/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# M1-01: evaluate conditional imports for Release before package manifest checks.
if [[ "${1:-}" == --release-imports ]]; then
  shift
  python3 -I - "$@" <<'PYIMPORT'
import ast
import pathlib
import re
import sys


def possible(expression):
    expression = re.sub(r"\b(?:os|arch|targetEnvironment|canImport|swift|compiler)\([^)]*\)", "UNKNOWN", expression)
    expression = expression.replace("&&", " and ").replace("||", " or ")
    expression = re.sub(r"!(?!=)", " not ", expression).strip()

    def evaluate(node):
        if isinstance(node, ast.Name):
            return {False} if node.id in {"DEBUG", "WGEX_LAB_BUILD"} else {False, True}
        if isinstance(node, ast.Constant) and isinstance(node.value, bool):
            return {node.value}
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return {not v for v in evaluate(node.operand)}
        if isinstance(node, ast.BoolOp):
            values = {isinstance(node.op, ast.And)}
            for child in node.values:
                values = {a and b if isinstance(node.op, ast.And) else a or b for a in values for b in evaluate(child)}
            return values
        return {False, True}

    try:
        return evaluate(ast.parse(expression, mode="eval").body)
    except SyntaxError:
        return {False, True}


failed = False
for root in sys.argv[1:]:
    root = pathlib.Path(root)
    paths = [root] if root.is_file() else root.rglob("*.swift")
    for path in paths:
        active = True
        stack = []
        for number, line in enumerate(path.read_text().splitlines(), 1):
            text = line.strip()
            if text.startswith("#if "):
                values = possible(text[4:])
                stack.append((active, False in values))
                active = active and True in values
            elif text.startswith("#elseif ") and stack:
                parent, remaining = stack[-1]
                values = possible(text[8:])
                active = parent and remaining and True in values
                stack[-1] = (parent, remaining and False in values)
            elif text == "#else" and stack:
                parent, remaining = stack[-1]
                active = parent and remaining
                stack[-1] = (parent, False)
            elif text == "#endif" and stack:
                active = stack.pop()[0]
            elif active and (found := re.search(r"\bimport\s+(?:(?:class|struct|func|enum|protocol|var|let|typealias)\s+)?(WGEXTesting|WGEXDaemonCoreTesting)\b", text.split("//")[0])):
                sys.stderr.write(f"{path}:{number}: Release imports {found.group(1)} (M1-01, M1-15)\n")
                failed = True
sys.exit(1 if failed else 0)
PYIMPORT
  exit "$?"
fi
if (($# == 0)); then
  bash "$0" --release-imports "$LINT_ROOT/Apps" "$LINT_ROOT/Daemon" "$LINT_ROOT/Extensions"
fi

manifests=()
if (($#)); then
  mode=fixture
  while IFS= read -r -d '' f; do
    manifests+=("$f")
  done < <(find "$1" -mindepth 2 -maxdepth 2 -name Package.swift -type f -print0 | sort -z)
else
  mode=repository
  # Fails closed (M1-32): git must list the files and a repository always has package manifests.
  load_repo_files 'Packages/*/Package.swift' || exit 1
  if ((${#REPO_FILES[@]} == 0)); then
    echo 'check-package-deps: no Packages/*/Package.swift manifests in the repository listing (a broken index or listing)' >&2
    exit 1
  fi
  manifests=("${REPO_FILES[@]}")
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/wgex-package-deps.XXXXXX")"
# The trap fails closed: bash 3.2 hands an EXIT trap status 0 after a shell error under set -e (unbound variable, ${x:?},
# readonly, bad substitution, failed source), so the script sets finished=1 just before each intended successful end.
# finished=0 first: an exported finished=1 in the caller must not mark an erroring script as finished.
finished=0
trap 'rc=$?; ((rc != 0)) || ((${finished:-0})) || rc=1; rm -rf "$work"; exit "$rc"' EXIT

# dump-package compiles each manifest; run them in parallel, each with its own
# scratch directory so nothing is written inside the source tree.
i=0
for manifest in ${manifests[@]+"${manifests[@]}"}; do
  dir="$(dirname "$manifest")"
  printf '%s\n' "$dir" >"$work/$i.dir"
  (
    if swift package --package-path "$dir" --scratch-path "$work/scratch-$i" dump-package >"$work/$i.json" 2>"$work/$i.err"; then
      : >"$work/$i.ok"
    fi
  ) &
  i=$((i + 1))
done
wait

if [[ "$mode" == repository ]]; then
  swift_roots=("$LINT_ROOT/Packages" "$LINT_ROOT/Apps" "$LINT_ROOT/Daemon" "$LINT_ROOT/Extensions")
else
  swift_roots=("$1")
fi

finished=1
python3 -I - "$work" "$mode" "$i" "${swift_roots[@]}" <<'PY'
import json
import os
import re
import sys

work, mode, count = sys.argv[1], sys.argv[2], int(sys.argv[3])
swift_roots = sys.argv[4:]

# target -> (package, required dependencies, optional dependencies)
# Optional edges are pending tickets: WGEXEngineBinary and the daemon's
# WGEXEngine edge arrive with the engine integration ticket (P0-05).
TABLE = {
    "WGEXCore": ("WGEXCore", [], []),
    "WGEXProfileStore": ("WGEXProfileStore", ["WGEXCore"], []),
    "WGEXAppComposition": ("WGEXAppComposition", ["WGEXCore", "WGEXProfileStore"], []),
    "WGEXPolicy": ("WGEXPolicy", ["WGEXCore"], []),
    "WGEXEngineInterface": ("WGEXEngineInterface", ["WGEXCore"], []),
    "WGEXEngine": ("WGEXEngine", ["WGEXEngineInterface"], ["WGEXEngineBinary"]),
    "WGEXDaemonProtocol": ("WGEXBackendMac", ["WGEXCore"], []),
    "WGEXDaemonClient": ("WGEXBackendMac", ["WGEXDaemonProtocol", "WGEXProfileStore"], []),
    "WGEXDaemonCore": ("WGEXBackendMac",
                       ["WGEXDaemonProtocol", "WGEXEngineInterface", "WGEXProfileStore", "WGEXPolicy", "CWGEXSysShim"],
                       ["WGEXEngine"]),
    "WGEXDaemonCoreTesting": ("WGEXBackendMac", ["WGEXDaemonCore"], []),
    "WGEXNEClient": ("WGEXBackendNE", ["WGEXCore", "WGEXPolicy", "WGEXProfileStore"], []),
    "WGEXNEProvider": ("WGEXBackendNE", ["WGEXCore", "WGEXPolicy", "WGEXProfileStore", "WGEXEngineInterface"], []),
    "WGEXPairing": ("WGEXPairing", ["WGEXCore"], []),
    "WGEXUI": ("WGEXUI", ["WGEXCore", "WGEXPolicy"], []),
    "WGEXActivityShared": ("WGEXActivityShared", ["WGEXCore"], []),
    "WGEXDiagnostics": ("WGEXDiagnostics", ["WGEXCore"], []),
    "WGEXTesting": ("WGEXTesting", ["WGEXCore", "WGEXPolicy", "WGEXEngineInterface"], []),
    "WGEXUITesting": ("WGEXUITesting", ["WGEXUI", "WGEXTesting"], []),
    "CWGEXSysShim": ("CWGEXSysShim", [], []),
}
BINARY_TARGETS = {"WGEXEngineBinary": "WGEXEngine"}
PRODUCTS = {
    "WGEXEngine": {"WGEXEngine"},
    "WGEXBackendMac": {"WGEXDaemonProtocol", "WGEXDaemonClient", "WGEXDaemonCore", "WGEXDaemonCoreTesting"},
    "WGEXBackendNE": {"WGEXNEClient", "WGEXNEProvider"},
}
PACKAGES = sorted({package for package, _, _ in TABLE.values()})
CLIENT_PRODUCTS = {"WGEXDaemonClient", "WGEXNEClient"}
ENGINE_MODULES = {"WGEXEngine", "WGEXEngineBinary"}
SWIFTUI_ALLOWED = {"WGEXUI", "WGEXUITesting"}
MAIN_ACTOR_TARGETS = {"WGEXUI", "WGEXUITesting"}
STRICT_MEMORY_PACKAGES = {"WGEXEngine"}
CORE_IMPORTS = {"Foundation", "CryptoKit", "Network", "Synchronization"}
UPCOMING = {"NonisolatedNonsendingByDefault", "InferIsolatedConformances", "MemberImportVisibility", "ExistentialAny"}
PLATFORMS = [("macos", "26.0"), ("ios", "27.0"), ("tvos", "27.0")]
IMPORT = re.compile(r"^\s*(?:@[\w()]+\s+)*import\s+(?:(?:struct|class|enum|protocol|typealias|func|let|var)\s+)?([A-Za-z_][\w]*)", re.M)

violations = []


def fail(where, message):
    violations.append(f"{where}: {message}")


def closure(name, include_optional, seen=None):
    seen = set() if seen is None else seen
    if name not in TABLE:
        return seen
    _, required, optional = TABLE[name]
    for dep in required + (optional if include_optional else []):
        if dep not in seen:
            seen.add(dep)
            closure(dep, include_optional, seen)
    return seen


def reach(deps):
    result = set()
    for dep in deps:
        result.add(dep)
        result |= closure(dep, False)
    return result


def swift_files(directory):
    for root, _, files in os.walk(directory):
        for name in files:
            if name.endswith(".swift"):
                yield os.path.join(root, name)


def target_dir(package_dir, target):
    path = target.get("path") or os.path.join("Sources" if target["type"] != "test" else "Tests", target["name"])
    return os.path.join(package_dir, path)


def check_settings(where, package, target, has_swift):
    if not has_swift:
        return
    kinds = {}
    for setting in target.get("settings", []):
        if setting.get("tool") != "swift":
            continue
        for kind, value in setting["kind"].items():
            kinds.setdefault(kind, []).append(value.get("_0") if isinstance(value, dict) else value)
    if kinds.get("swiftLanguageMode") != ["6"]:
        fail(where, "Swift language mode must be 6")
    missing = UPCOMING - set(kinds.get("enableUpcomingFeature", []))
    if missing:
        fail(where, "missing upcoming features " + ", ".join(sorted(missing)))
    main_actor = kinds.get("defaultIsolation") == ["MainActor"]
    if main_actor != (target["name"].removesuffix("Tests") in MAIN_ACTOR_TARGETS):
        fail(where, "MainActor default isolation is allowed only in WGEXUI and WGEXUITesting (and required there)")
    if package in STRICT_MEMORY_PACKAGES and "strictMemorySafety" not in kinds:
        fail(where, "strict memory safety is required in the WGEXEngine package")


def check_imports(where, name, directory):
    for path in swift_files(directory):
        with open(path, encoding="utf-8") as handle:
            modules = IMPORT.findall(handle.read())
        relative = os.path.relpath(path, directory)
        if "SwiftUI" in modules and name not in SWIFTUI_ALLOWED:
            fail(where, f"imports SwiftUI ({relative}); only WGEXUI and WGEXUITesting may")
        if name == "WGEXCore":
            extra = sorted(set(modules) - CORE_IMPORTS)
            if extra:
                fail(where, f"WGEXCore imports {', '.join(extra)} ({relative}); allowed: {', '.join(sorted(CORE_IMPORTS))}")


seen_packages = set()
for index in range(count):
    with open(os.path.join(work, f"{index}.dir"), encoding="utf-8") as handle:
        package_dir = handle.read().strip()
    label = os.path.basename(package_dir)
    if not os.path.exists(os.path.join(work, f"{index}.ok")):
        fail(label, "swift package dump-package failed (manifest does not evaluate)")
        continue
    with open(os.path.join(work, f"{index}.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
    package = manifest["name"]
    seen_packages.add(package)
    if package not in PACKAGES:
        fail(package, "unknown package; not in the plan 02 §2 table")
        continue
    if package != label:
        fail(package, f"package name differs from its directory {label}")
    platforms = [(p["platformName"], p["version"]) for p in manifest.get("platforms", [])]
    if sorted(platforms) != sorted(PLATFORMS):
        fail(package, f"platforms {platforms} differ from macOS 26, iOS 27, tvOS 27")
    expected_products = PRODUCTS.get(package, {package})
    products = {p["name"]: p["targets"] for p in manifest["products"]}
    if set(products) != expected_products:
        fail(package, f"products {sorted(products)} differ from {sorted(expected_products)}")
    for product, targets in products.items():
        if targets != [product]:
            fail(package, f"product {product} must contain exactly the target {product}")
    expected_targets = {t for t, (p, _, _) in TABLE.items() if p == package}
    for target in manifest["targets"]:
        name = target["name"]
        where = f"{package}/{name}"
        if target["type"] == "binary":
            if BINARY_TARGETS.get(name) != package:
                fail(where, "unexpected binary target")
            continue
        directory = target_dir(package_dir, target)
        has_swift = any(True for _ in swift_files(directory))
        check_settings(where, package, target, has_swift)
        if target["type"] == "test":
            continue
        if target["type"] != "regular" or name not in expected_targets:
            fail(where, "target is not in the plan 02 §2 table")
            continue
        expected_targets.discard(name)
        direct = set()
        for dependency in target["dependencies"]:
            kind, value = next(iter(dependency.items()))
            direct.add(value[0])
        unknown = sorted(d for d in direct if d not in TABLE and d not in BINARY_TARGETS)
        if unknown:
            fail(where, f"unknown dependencies {unknown}")
        actual = reach(direct)
        required = closure(name, False)
        allowed = closure(name, True) | {d for d in TABLE[name][2]}
        if name in CLIENT_PRODUCTS and actual & ENGINE_MODULES:
            fail(where, f"client product depends on {sorted(actual & ENGINE_MODULES)}; apps and the CLI link client products only")
        if not required <= actual:
            fail(where, f"missing dependencies {sorted(required - actual)}")
        if not actual <= allowed:
            fail(where, f"dependencies outside the table {sorted(actual - allowed)}")
        check_imports(where, name, directory)
    for missing in sorted(expected_targets):
        fail(package, f"missing target {missing}")

SERVICE_CONTROLLER = os.path.join("WGEXDaemonClient", "ServiceController.swift")
SM_APP_SERVICE = re.compile(r"\bSMAppService\b")
for swift_root in swift_roots:
    for path in swift_files(swift_root):
        if path.endswith(os.sep + SERVICE_CONTROLLER) or f"{os.sep}.build{os.sep}" in path:
            continue
        with open(path, encoding="utf-8") as handle:
            for number, line in enumerate(handle, 1):
                if not line.lstrip().startswith("//") and SM_APP_SERVICE.search(line):
                    fail(os.path.relpath(path, os.path.dirname(swift_root)), f"line {number} references SMAppService outside {SERVICE_CONTROLLER}")

if mode == "repository":
    for missing in sorted(set(PACKAGES) - seen_packages):
        fail(missing, "package missing from Packages/")

for line in violations:
    print(f"check-package-deps: {line}", file=sys.stderr)
if violations:
    print(f"check-package-deps: FAIL ({len(violations)} violation(s); rules: plan 02 §2, P0-04)", file=sys.stderr)
    sys.exit(1)
print(f"check-package-deps: ok ({len(seen_packages)} package(s))")
PY
